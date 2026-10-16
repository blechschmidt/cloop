package remote

// Unit tests for the device channel's frames and its stream (Task 20430).

import (
	"errors"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor"
)

func TestDeviceOpenValidation(t *testing.T) {
	good := []DeviceOpenPayload{
		{ChannelID: "c1", Kind: executor.ForwardedUSB, Name: "fwd-tablet", BusID: "1-1"},
		{ChannelID: "c2", Kind: executor.ForwardedL2, Name: "fwd-lab", Interface: &executor.HostInterface{Target: "fwd0", Address: "10.77.0.2/24"}},
	}
	for _, p := range good {
		if err := p.Validate(); err != nil {
			t.Errorf("%+v refused: %v", p, err)
		}
	}
	bad := map[string]DeviceOpenPayload{
		"no channel":       {Kind: executor.ForwardedUSB, BusID: "1-1"},
		"usb, no bus id":   {ChannelID: "c", Kind: executor.ForwardedUSB},
		"usb, long bus id": {ChannelID: "c", Kind: executor.ForwardedUSB, BusID: strings.Repeat("1", 40)},
		"l2, no interface": {ChannelID: "c", Kind: executor.ForwardedL2, Name: "x"},
		"l2, bad target":   {ChannelID: "c", Kind: executor.ForwardedL2, Name: "x", Interface: &executor.HostInterface{Target: "lo"}},
		"unknown kind":     {ChannelID: "c", Kind: "pci"},
	}
	for name, p := range bad {
		if err := p.Validate(); !errors.Is(err, ErrProtocol) {
			t.Errorf("%s: Validate = %v, want a protocol error", name, err)
		}
	}
	f, _ := NewFrame(TypeDeviceOpen, "id", "", good[0])
	if _, err := DecodeDeviceOpen(f); err == nil {
		t.Error("a device_open naming no workload was accepted")
	}
	big, _ := NewFrame(TypeDeviceData, "", "h", DeviceDataPayload{ChannelID: "c", Data: make([]byte, MaxDeviceChunk+1)})
	if _, err := DecodeDeviceData(big); !errors.Is(err, ErrProtocol) {
		t.Errorf("an oversized device_data chunk = %v, want refused", err)
	}
}

// TestDeviceStreamCarriesAndEnds: writes are chunked into frames, delivered
// bytes are read in order, and the peer's close lets the reader drain what
// already arrived before it sees why the stream ended.
func TestDeviceStreamCarriesAndEnds(t *testing.T) {
	var mu sync.Mutex
	var sent []DeviceDataPayload
	var closes int
	ds := NewDeviceStream("c1", func(ty FrameType, p any) error {
		mu.Lock()
		defer mu.Unlock()
		switch ty {
		case TypeDeviceData:
			sent = append(sent, p.(DeviceDataPayload))
		case TypeDeviceClose:
			closes++
		}
		return nil
	}, nil)
	payload := make([]byte, MaxDeviceChunk*2+5)
	if n, err := ds.Write(payload); err != nil || n != len(payload) {
		t.Fatalf("Write = %d, %v", n, err)
	}
	mu.Lock()
	if len(sent) != 3 || len(sent[2].Data) != 5 {
		t.Fatalf("a %d-byte write went out as %d frames", len(payload), len(sent))
	}
	mu.Unlock()

	ds.Deliver([]byte("hello "))
	ds.Deliver([]byte("world"))
	ds.Finish("the agent detached the device")
	got, err := io.ReadAll(ds)
	if string(got) != "hello world" || err == nil || !strings.Contains(err.Error(), "detached") {
		t.Fatalf("read %q, %v; want the delivered bytes, then the peer's reason", got, err)
	}
	mu.Lock()
	if closes != 0 {
		t.Fatal("a stream the peer closed sent a close back")
	}
	mu.Unlock()
}

// TestDeviceStreamOverflowEndsTheChannel: a consumer that stops reading ends
// its channel — it never blocks the session's shared read loop, and never
// buffers without bound.
func TestDeviceStreamOverflowEndsTheChannel(t *testing.T) {
	closed := make(chan string, 1)
	ds := NewDeviceStream("c2", func(ty FrameType, p any) error {
		if ty == TypeDeviceClose {
			closed <- p.(DeviceClosePayload).Reason
		}
		return nil
	}, nil)
	chunk := make([]byte, MaxDeviceChunk)
	start := time.Now()
	for i := 0; i < deviceInboxDepth*4; i++ {
		ds.Deliver(chunk)
	}
	if time.Since(start) > 2*time.Second {
		t.Fatal("Deliver blocked on a consumer that is not reading")
	}
	select {
	case reason := <-closed:
		if !strings.Contains(reason, "behind") {
			t.Fatalf("the channel ended for %q", reason)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("a channel whose consumer stopped reading was never ended")
	}
}
