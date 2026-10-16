package deviceforward

// proto.go is the wire format between a forwarder (on-prem) and the hub.
//
// # The shape, and why it is multiplexed
//
// The forwarder dials the hub and holds one long-lived, authenticated,
// TLS-protected WebSocket open — the same inverted direction the executor
// agent uses, and for the same reason: an on-prem device sits behind NAT that
// permits outbound connections and nothing inbound, so the control plane can
// never dial it. Everything travels down that one connection.
//
// A forwarder carries exactly one device, but a consumer opens and closes the
// device many times over the forwarder's life: a USB device is attached and
// detached by vhci, an L2 segment is bridged and unbridged. Each of those is a
// fresh byte stream to the on-prem endpoint, and they must not share a buffer
// or a lifetime. So frames carry a channel number and the connection is a
// multiplexer: channel 0 is the session (hello, heartbeat, bye) and every
// positive channel is one open stream to the device.
//
// # The frame
//
//	type(1) | channel(4, big-endian) | length(4, big-endian) | payload(length)
//
// One frame is one WebSocket binary message, so the message boundary already
// delimits it; the length prefix is kept so the same frames can run over a raw
// stream in a test without a WebSocket. Payloads are JSON for the control
// frames (open, hello, …) and raw bytes for Data, which is the device's own
// protocol and must pass through untouched.
//
// # Versioning
//
// Every hello carries a version. The hub replies in the welcome with the
// version the session settled on — the lower of the two — and both sides speak
// it. Adding a control-frame field is backward compatible; changing a frame's
// meaning requires a bump. There is only one version so far, so the machinery
// is deliberately minimal.

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"

	"github.com/blechschmidt/cloop/pkg/executor"
)

// ProtocolVersion is the newest forwarder protocol this build speaks.
const ProtocolVersion = 1

// MinProtocolVersion is the oldest a connecting forwarder may speak.
const MinProtocolVersion = 1

// FrameType is the one-byte discriminator at the head of every frame.
type FrameType byte

const (
	// TypeHello (forwarder→hub, channel 0) opens the session and advertises
	// the one device the forwarder carries.
	TypeHello FrameType = 1
	// TypeWelcome (hub→forwarder, channel 0) accepts the session and names the
	// negotiated version.
	TypeWelcome FrameType = 2
	// TypeOpen (hub→forwarder) asks the forwarder to open a new stream to its
	// device on the named channel.
	TypeOpen FrameType = 3
	// TypeOpenAck (forwarder→hub) reports whether the open succeeded.
	TypeOpenAck FrameType = 4
	// TypeData (both directions) carries one chunk of a stream's bytes on its
	// channel. The payload is opaque — it is the device's own protocol.
	TypeData FrameType = 5
	// TypeClose (both directions) ends a stream's channel. After it, the
	// channel number must not be reused.
	TypeClose FrameType = 6
	// TypePing / TypePong (channel 0) are the heartbeat.
	TypePing FrameType = 7
	TypePong FrameType = 8
	// TypeBye (hub→forwarder, channel 0) ends the session and says whether to
	// reconnect.
	TypeBye FrameType = 9
	// TypeError (both, any channel) reports a non-fatal problem. On channel 0
	// it is about the session; on a positive channel it is about that stream.
	TypeError FrameType = 10
)

// frameHeaderLen is type(1) + channel(4) + length(4).
const frameHeaderLen = 9

// MaxFramePayload bounds one frame's payload. A Data chunk larger than this is
// a bug or an attack, not a legitimate stream write; USB/IP URBs and Ethernet
// frames are far smaller, and the relay chunks its reads well under it.
const MaxFramePayload = 1 << 20 // 1 MiB

// Frame is one unit on the wire.
type Frame struct {
	Type    FrameType
	Channel uint32
	Payload []byte
}

// Marshal renders the frame to its wire bytes.
func (f Frame) Marshal() ([]byte, error) {
	if len(f.Payload) > MaxFramePayload {
		return nil, fmt.Errorf("%w: frame payload %d exceeds %d", ErrProtocol, len(f.Payload), MaxFramePayload)
	}
	buf := make([]byte, frameHeaderLen+len(f.Payload))
	buf[0] = byte(f.Type)
	binary.BigEndian.PutUint32(buf[1:5], f.Channel)
	binary.BigEndian.PutUint32(buf[5:9], uint32(len(f.Payload)))
	copy(buf[frameHeaderLen:], f.Payload)
	return buf, nil
}

// parseFrame decodes a whole frame from its wire bytes (one WebSocket message).
func parseFrame(b []byte) (Frame, error) {
	if len(b) < frameHeaderLen {
		return Frame{}, fmt.Errorf("%w: frame is %d bytes, shorter than its %d-byte header",
			ErrProtocol, len(b), frameHeaderLen)
	}
	length := binary.BigEndian.Uint32(b[5:9])
	if length > MaxFramePayload {
		return Frame{}, fmt.Errorf("%w: frame declares %d payload bytes, over the %d limit",
			ErrProtocol, length, MaxFramePayload)
	}
	if int(length) != len(b)-frameHeaderLen {
		return Frame{}, fmt.Errorf("%w: frame declares %d payload bytes but carries %d",
			ErrProtocol, length, len(b)-frameHeaderLen)
	}
	f := Frame{
		Type:    FrameType(b[0]),
		Channel: binary.BigEndian.Uint32(b[1:5]),
	}
	if length > 0 {
		f.Payload = make([]byte, length)
		copy(f.Payload, b[frameHeaderLen:])
	}
	return f, nil
}

// readStreamFrame reads one length-prefixed frame from r, for the raw-stream
// transport used in tests. The WebSocket transport does not use it: a message
// is already one frame.
func readStreamFrame(r io.Reader) (Frame, error) {
	hdr := make([]byte, frameHeaderLen)
	if _, err := io.ReadFull(r, hdr); err != nil {
		return Frame{}, err
	}
	length := binary.BigEndian.Uint32(hdr[5:9])
	if length > MaxFramePayload {
		return Frame{}, fmt.Errorf("%w: frame declares %d payload bytes, over the %d limit",
			ErrProtocol, length, MaxFramePayload)
	}
	buf := make([]byte, frameHeaderLen+int(length))
	copy(buf, hdr)
	if _, err := io.ReadFull(r, buf[frameHeaderLen:]); err != nil {
		return Frame{}, err
	}
	return parseFrame(buf)
}

// HelloPayload is the forwarder's opening frame.
type HelloPayload struct {
	Version int             `json:"version"`
	Device  ForwardedDevice `json:"device"`
	// AgentVersion is the forwarder build string, for the fleet view.
	AgentVersion string `json:"agent_version,omitempty"`
	// Available reports whether the forwarder can currently reach its device
	// (the USB device is plugged in, the interface exists). A forwarder that
	// connects with its device missing is still useful to see in the UI, so
	// this is advisory, not a refusal.
	Available bool `json:"available"`
	// Detail explains a false Available, for the operator.
	Detail string `json:"detail,omitempty"`
	// Resolved, for a USB device, is what the forwarder found the configured
	// identity resolving to on its host right now — the concrete device, with
	// its current bus/port, so the dashboard can show the real hardware.
	Resolved *executor.USBDevice `json:"resolved,omitempty"`
}

// WelcomePayload is the hub's acceptance.
type WelcomePayload struct {
	Version int `json:"version"`
	// ForwarderID is the hub's durable ID for this forwarder, echoed so the
	// device can log which identity it is serving as.
	ForwarderID string `json:"forwarder_id"`
	// Credential is the long-lived forwarder credential, non-empty only on the
	// connection that redeemed an enrollment token. The forwarder persists it
	// and reconnects with it; it is shown once and never again.
	Credential string `json:"credential,omitempty"`
}

// OpenPayload asks the forwarder to open a stream to its device.
type OpenPayload struct {
	// Purpose is a short free-form note for the forwarder's log and the audit
	// trail: "attach", "devlist". Advisory only.
	Purpose string `json:"purpose,omitempty"`
}

// OpenAckPayload reports the outcome of an Open.
type OpenAckPayload struct {
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
}

// ErrorPayload carries a non-fatal error.
type ErrorPayload struct {
	Message string `json:"message"`
}

// ByePayload ends a session.
type ByePayload struct {
	Reason    string `json:"reason,omitempty"`
	Reconnect bool   `json:"reconnect"`
}

func marshalJSON(v any) []byte {
	b, _ := json.Marshal(v)
	return b
}
