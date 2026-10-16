package deviceforward

import (
	"bytes"
	"io"
	"testing"
)

// fakePacketIO is a packetIO backed by in-memory frame queues.
type fakePacketIO struct {
	in      [][]byte // frames ReadPacket will return, in order
	written [][]byte // frames WritePacket received
}

func (f *fakePacketIO) ReadPacket(p []byte) (int, error) {
	if len(f.in) == 0 {
		return 0, io.EOF
	}
	frame := f.in[0]
	f.in = f.in[1:]
	return copy(p, frame), nil
}

func (f *fakePacketIO) WritePacket(p []byte) error {
	f.written = append(f.written, append([]byte(nil), p...))
	return nil
}

func (f *fakePacketIO) Close() error { return nil }

func TestPktStreamFramesOutbound(t *testing.T) {
	frames := [][]byte{[]byte("frame-one"), bytes.Repeat([]byte{0xab}, 1500)}
	p := &fakePacketIO{in: frames}
	s := newPktStream(p)

	// Read the whole stream; it should be each frame, length-prefixed.
	var got []byte
	buf := make([]byte, 7) // small reads, to exercise partial draining
	for {
		n, err := s.Read(buf)
		got = append(got, buf[:n]...)
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	// Rebuild expected: 2-byte length + frame for each.
	var want []byte
	for _, f := range frames {
		want = append(want, byte(len(f)>>8), byte(len(f)))
		want = append(want, f...)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("outbound framing mismatch: got %d bytes, want %d", len(got), len(want))
	}
}

func TestPktStreamParsesInbound(t *testing.T) {
	p := &fakePacketIO{}
	s := newPktStream(p)
	frames := [][]byte{[]byte("hello"), []byte("a much longer ethernet frame payload")}
	var wire []byte
	for _, f := range frames {
		wire = append(wire, byte(len(f)>>8), byte(len(f)))
		wire = append(wire, f...)
	}
	// Feed the wire in awkward chunks to exercise buffering across writes.
	for i := 0; i < len(wire); i += 3 {
		end := i + 3
		if end > len(wire) {
			end = len(wire)
		}
		if _, err := s.Write(wire[i:end]); err != nil {
			t.Fatal(err)
		}
	}
	if len(p.written) != len(frames) {
		t.Fatalf("wrote %d frames, want %d", len(p.written), len(frames))
	}
	for i := range frames {
		if !bytes.Equal(p.written[i], frames[i]) {
			t.Fatalf("frame %d mismatch: %q vs %q", i, p.written[i], frames[i])
		}
	}
}

func TestPktStreamRejectsOversizeFrame(t *testing.T) {
	s := newPktStream(&fakePacketIO{})
	// A length prefix over the cap must be refused.
	_, err := s.Write([]byte{0xff, 0xff, 0x00})
	if err == nil {
		t.Fatal("expected an oversize-frame error")
	}
}
