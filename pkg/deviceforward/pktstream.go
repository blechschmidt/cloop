package deviceforward

// pktstream.go frames an L2 device's packets onto the byte stream the mux
// carries.
//
// A USB forward is a transparent byte stream — the kernel's usbip traffic has
// its own framing, so the relay copies bytes and looks at nothing. An L2
// forward cannot: it moves whole Ethernet frames, and the mux's Data chunks do
// not preserve a packet's boundaries. So both ends wrap their packet handle
// (an AF_PACKET socket on the forwarder, a TAP on the consumer) in a pktStream,
// which length-prefixes each frame on the wire and hands each received frame to
// the kernel whole. Because both ends use the same codec, the relay between
// them stays the same dumb byte copy.

import (
	"encoding/binary"
	"fmt"
	"io"
	"sync"
)

// maxEthFrame bounds one L2 frame. 9216 covers jumbo frames; a length prefix
// claiming more than this is refused rather than allocated.
const maxEthFrame = 9216

// packetIO is a handle that reads and writes one whole frame at a time.
type packetIO interface {
	// ReadPacket reads one frame into p and returns its length.
	ReadPacket(p []byte) (int, error)
	// WritePacket writes one whole frame.
	WritePacket(p []byte) error
	// Close releases the handle.
	Close() error
}

// pktStream presents a packetIO as a byte stream of length-prefixed frames, so
// it can be spliced to a mux channel like any other stream.
type pktStream struct {
	p packetIO

	readMu  sync.Mutex
	readBuf []byte // the unread tail of the current prefixed frame

	writeMu  sync.Mutex
	writeBuf []byte // partial inbound frame awaiting its full length
	scratch  []byte
}

func newPktStream(p packetIO) *pktStream {
	return &pktStream{p: p, scratch: make([]byte, maxEthFrame)}
}

// Read fills p from the current prefixed frame, reading the next frame from the
// device when the current one is drained.
func (s *pktStream) Read(p []byte) (int, error) {
	s.readMu.Lock()
	defer s.readMu.Unlock()
	if len(s.readBuf) == 0 {
		n, err := s.p.ReadPacket(s.scratch)
		if err != nil {
			return 0, err
		}
		frame := s.scratch[:n]
		out := make([]byte, 2+n)
		binary.BigEndian.PutUint16(out[0:2], uint16(n))
		copy(out[2:], frame)
		s.readBuf = out
	}
	n := copy(p, s.readBuf)
	s.readBuf = s.readBuf[n:]
	return n, nil
}

// Write accumulates bytes and emits each complete length-prefixed frame to the
// device.
func (s *pktStream) Write(p []byte) (int, error) {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	s.writeBuf = append(s.writeBuf, p...)
	for {
		if len(s.writeBuf) < 2 {
			break
		}
		fl := int(binary.BigEndian.Uint16(s.writeBuf[0:2]))
		if fl > maxEthFrame {
			return 0, fmt.Errorf("%w: L2 frame length %d exceeds %d", ErrProtocol, fl, maxEthFrame)
		}
		if len(s.writeBuf) < 2+fl {
			break
		}
		frame := s.writeBuf[2 : 2+fl]
		if err := s.p.WritePacket(frame); err != nil {
			return 0, err
		}
		s.writeBuf = s.writeBuf[2+fl:]
	}
	return len(p), nil
}

// Close releases the device handle.
func (s *pktStream) Close() error { return s.p.Close() }

var _ io.ReadWriteCloser = (*pktStream)(nil)
