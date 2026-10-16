package deviceforward

import (
	"bytes"
	"testing"

	"github.com/blechschmidt/cloop/pkg/executor"
)

func TestFrameMarshalParse(t *testing.T) {
	f := Frame{Type: TypeData, Channel: 42, Payload: []byte("hello world")}
	b, err := f.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	got, err := parseFrame(b)
	if err != nil {
		t.Fatal(err)
	}
	if got.Type != f.Type || got.Channel != f.Channel || !bytes.Equal(got.Payload, f.Payload) {
		t.Fatalf("round trip mismatch: %+v", got)
	}
}

func TestParseFrameRejectsBadLength(t *testing.T) {
	// Short header.
	if _, err := parseFrame([]byte{1, 2, 3}); err == nil {
		t.Fatal("expected error for a short frame")
	}
	// Declares more payload than present.
	b, _ := Frame{Type: TypeData, Channel: 1, Payload: []byte("abc")}.Marshal()
	b[8] = 0xff // length low byte way over actual
	if _, err := parseFrame(b); err == nil {
		t.Fatal("expected error for length mismatch")
	}
}

func TestMarshalRejectsOversizePayload(t *testing.T) {
	if _, err := (Frame{Type: TypeData, Payload: make([]byte, MaxFramePayload+1)}).Marshal(); err == nil {
		t.Fatal("expected oversize payload to be refused")
	}
}

func TestStreamFrameRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	frames := []Frame{
		{Type: TypeHello, Payload: []byte(`{"version":1}`)},
		{Type: TypeData, Channel: 7, Payload: []byte("xyz")},
		{Type: TypeClose, Channel: 7},
	}
	for _, f := range frames {
		b, _ := f.Marshal()
		buf.Write(b)
	}
	for i, want := range frames {
		got, err := readStreamFrame(&buf)
		if err != nil {
			t.Fatalf("frame %d: %v", i, err)
		}
		if got.Type != want.Type || got.Channel != want.Channel || !bytes.Equal(got.Payload, want.Payload) {
			t.Fatalf("frame %d mismatch: %+v vs %+v", i, got, want)
		}
	}
}

func TestDeviceNormalizeAndDescribe(t *testing.T) {
	d, err := (ForwardedDevice{Kind: "USB", USB: usbMatch()}).Normalize()
	if err != nil {
		t.Fatal(err)
	}
	if d.Kind != KindUSB {
		t.Fatalf("kind not lowercased: %q", d.Kind)
	}
	l2, err := (ForwardedDevice{Kind: KindL2, Interface: "eth1"}).Normalize()
	if err != nil {
		t.Fatal(err)
	}
	if l2.Interface != "eth1" {
		t.Fatalf("interface lost")
	}
	if (ForwardedDevice{Kind: KindL2}).Validate() == nil {
		t.Fatal("l2 with no interface must fail")
	}
	if (ForwardedDevice{Kind: KindUSB, USB: usbMatch(), Interface: "eth0"}).Validate() == nil {
		t.Fatal("usb with an interface must fail")
	}
}

func usbMatch() *executor.USBMatch {
	return &executor.USBMatch{VendorID: "1050", ProductID: "0030"}
}
