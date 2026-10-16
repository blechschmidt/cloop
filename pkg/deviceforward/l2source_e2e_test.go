//go:build linux

package deviceforward

// Real layer-2 forward over a veth pair: a forwarder captures one end, a
// consumer bridges the hub's stream to a TAP, and a frame sent on the far end of
// the veth arrives on the TAP — the same path a cloud sandbox would share an
// on-prem segment over.
//
// Opt-in, because it needs root and creates network interfaces:
//
//	CLOOP_FORWARD_L2_E2E=1 go test ./pkg/deviceforward -run TestL2ForwardEndToEnd -v

import (
	"context"
	"net"
	"os"
	"os/exec"
	"syscall"
	"testing"
	"time"
)

func TestL2ForwardEndToEnd(t *testing.T) {
	if os.Getenv("CLOOP_FORWARD_L2_E2E") == "" {
		t.Skip("set CLOOP_FORWARD_L2_E2E=1 (needs root) to run")
	}
	if os.Geteuid() != 0 {
		t.Skip("needs root to create veth and TAP interfaces")
	}
	if _, err := exec.LookPath("ip"); err != nil {
		t.Skip("ip(8) not installed")
	}
	a, b := "cloopfwdA", "cloopfwdB"
	run := func(args ...string) {
		if out, err := exec.Command("ip", args...).CombinedOutput(); err != nil {
			t.Logf("ip %v: %v: %s", args, err, out)
		}
	}
	run("link", "del", a)
	run("link", "add", a, "type", "veth", "peer", "name", b)
	run("link", "set", a, "up")
	run("link", "set", b, "up")
	t.Cleanup(func() { run("link", "del", a) })

	store := newMemStore()
	dev := ForwardedDevice{Kind: KindL2, Interface: a}
	token, _, err := Mint(store, MintOptions{Name: "lab", Device: dev})
	if err != nil {
		t.Fatal(err)
	}
	hub, url := startHub(t, store)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	src, err := NewL2Source(a, L2SourceOptions{Logf: t.Logf})
	if err != nil {
		t.Fatal(err)
	}
	runForwarder(t, ctx, ForwarderConfig{
		Server: url, Token: token, CredentialPath: t.TempDir() + "/c.json",
		Source: src, Logf: t.Logf,
	})
	ids := waitConnected(t, hub, 1)

	stream, err := hub.OpenDevice(ctx, ids[0], "test")
	if err != nil {
		t.Fatalf("OpenDevice: %v", err)
	}
	bridge, err := BridgeTAP(stream, "cloopfwdtap")
	if err != nil {
		t.Fatalf("BridgeTAP: %v", err)
	}
	defer bridge.Close()
	run("link", "set", bridge.Name(), "up")

	// Open a raw socket on the TAP to read what arrives, and send a unique
	// frame out veth B; it should traverse B→A→forwarder→tunnel→TAP.
	tapIfi, err := netInterfaceByName(bridge.Name())
	if err != nil {
		t.Fatal(err)
	}
	tapFD, err := openRawSocket(tapIfi)
	if err != nil {
		t.Fatalf("raw socket on TAP: %v", err)
	}
	defer syscall.Close(tapFD)

	bIfi, err := netInterfaceByName(b)
	if err != nil {
		t.Fatal(err)
	}
	bFD, err := openRawSocket(bIfi)
	if err != nil {
		t.Fatalf("raw socket on %s: %v", b, err)
	}
	defer syscall.Close(bFD)

	// A frame with a recognisable payload and an unusual ethertype.
	frame := make([]byte, 60)
	copy(frame[0:6], []byte{0x02, 0, 0, 0, 0, 0x01})  // dst
	copy(frame[6:12], []byte{0x02, 0, 0, 0, 0, 0x02}) // src
	frame[12], frame[13] = 0x12, 0x34                 // ethertype
	copy(frame[14:], []byte("CLOOP-L2-FORWARD-TEST"))

	got := make(chan bool, 1)
	go func() {
		buf := make([]byte, 2048)
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) {
			_ = syscall.SetNonblock(tapFD, true)
			n, _, err := syscall.Recvfrom(tapFD, buf, 0)
			if err == nil && n >= 14 && buf[12] == 0x12 && buf[13] == 0x34 {
				got <- true
				return
			}
			time.Sleep(20 * time.Millisecond)
		}
		got <- false
	}()

	// Send the frame a few times from B.
	for i := 0; i < 10; i++ {
		_ = syscall.Sendto(bFD, frame, 0, &syscall.SockaddrLinklayer{Ifindex: bIfi, Halen: 6})
		time.Sleep(50 * time.Millisecond)
	}

	if !<-got {
		t.Fatal("frame sent on the far veth end did not arrive on the TAP through the forwarder")
	}
	t.Log("L2 frame traversed the forwarder from the on-prem interface to the TAP")
}

func netInterfaceByName(name string) (int, error) {
	ifi, err := net.InterfaceByName(name)
	if err != nil {
		return 0, err
	}
	return ifi.Index, nil
}

// TestTAPReadsBlockUntilAFrameArrives is the regression test for a bridge that
// ended the moment it started: the TAP's descriptor was registered with Go's
// poller before it was attached to an interface, the poller recorded the
// unattached descriptor's error, and every read failed "not pollable" (Task
// 20430). A TAP's read must wait for a frame. Needs root, for the TAP; the TAP
// is not persistent and goes with the descriptor.
func TestTAPReadsBlockUntilAFrameArrives(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to create a TAP")
	}
	for i := 0; i < 3; i++ {
		f, name, err := openTAP("")
		if err != nil {
			t.Skipf("cannot create a TAP here: %v", err)
		}
		done := make(chan error, 1)
		go func() {
			_, err := f.Read(make([]byte, 2048))
			done <- err
		}()
		select {
		case err := <-done:
			f.Close()
			t.Fatalf("a read on the fresh TAP %s returned at once: %v", name, err)
		case <-time.After(300 * time.Millisecond):
		}
		f.Close()
		<-done
	}
}
