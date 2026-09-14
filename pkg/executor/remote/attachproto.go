package remote

// attachproto.go is the wire half of interactive attach (Task 20265): the
// frames that carry an operator's terminal to a workload running on an edge
// device, and its output back.
//
// # Why new frames rather than a second connection
//
// The agent dials out. That is the whole premise of this transport — edge
// devices sit behind NAT, the hub cannot reach them, and everything the hub
// wants to say travels down a session the device opened. A second connection
// for attach would need its own enrollment, its own authentication, and a way
// for the hub to reach a host it demonstrably cannot reach. So attach is
// multiplexed onto the session that already exists, like logs and signals.
//
// # Why a session ID and not just the handle
//
// Frame.Handle scopes a frame to one workload, which is almost enough: two
// operators can attach to the same workload at once, and a stdin frame carrying
// only a handle would be delivered to both terminals. AttachSessionID
// distinguishes them. It is minted by the hub — the agent never invents one —
// so that a stale frame from a session the hub has forgotten is refused rather
// than silently opening a new one.

import (
	"fmt"
	"strings"
)

// Attach frame types. Direction is fixed for each and is not negotiable: the
// agent never opens a session, only answers one.
const (
	// TypeAttachOpen (hub → agent) asks the device to start an interactive
	// command inside a running workload. Correlated by Frame.ID.
	TypeAttachOpen FrameType = "attach_open"

	// TypeAttachOpened (agent → hub) answers TypeAttachOpen.
	TypeAttachOpened FrameType = "attach_opened"

	// TypeAttachData carries bytes in both directions: keystrokes from the hub,
	// output from the device. One type rather than two, because the payload and
	// the routing are identical and the direction is already implied by which
	// end received it.
	TypeAttachData FrameType = "attach_data"

	// TypeAttachResize (hub → agent) reports new terminal geometry.
	TypeAttachResize FrameType = "attach_resize"

	// TypeAttachClose ends a session from either end: the operator closing a
	// terminal, or the device reporting that the command exited.
	TypeAttachClose FrameType = "attach_close"
)

// MinAttachVersion is the first protocol version whose agents understand the
// attach frames. An older device runs work perfectly well and simply cannot be
// entered; the hub refuses the session rather than sending frames that would be
// logged as "unexpected" and dropped.
const MinAttachVersion = 7

// SupportsAttach reports whether an agent at this negotiated version can host
// an interactive session.
func SupportsAttach(version int) bool { return version >= MinAttachVersion }

// MaxAttachChunk bounds one data frame's payload.
//
// Well under MaxFrameBytes, because the payload is base64-encoded by the JSON
// marshaller (a []byte field) and therefore grows by a third on the wire, and
// because a terminal is latency-sensitive: a 1 MiB frame is a quarter-second of
// head-of-line blocking on a slow uplink for output nobody can read that fast.
const MaxAttachChunk = 32 << 10

// AttachOpenPayload asks the device to start an interactive command.
type AttachOpenPayload struct {
	// SessionID is minted by the hub and scopes every later frame.
	SessionID string `json:"session_id"`
	// Command is the argv to run. Empty means the agent's default shell.
	Command []string `json:"command,omitempty"`
	// TTY requests a pseudo-terminal on the device.
	TTY bool `json:"tty,omitempty"`
	// Stdin reports that this session may deliver input. When false the agent
	// must give the command no input descriptor at all — the read-only
	// guarantee is enforced on the device, not by the hub declining to send.
	Stdin bool `json:"stdin,omitempty"`
	// Rows and Cols are the initial geometry; ignored without a TTY.
	Rows uint16 `json:"rows,omitempty"`
	Cols uint16 `json:"cols,omitempty"`
	// Env carries extra "K=V" entries for the command (TERM, in practice).
	Env []string `json:"env,omitempty"`
}

// AttachOpenedPayload answers an open request.
type AttachOpenedPayload struct {
	SessionID string `json:"session_id"`
	// TTY reports whether the device actually allocated a terminal. It can be
	// false on a request that asked for one — a device without a pty
	// implementation degrades to pipes rather than refusing — and the hub tells
	// the operator instead of letting them wonder why there is no prompt.
	TTY bool `json:"tty"`
}

// AttachDataPayload carries one chunk in either direction.
type AttachDataPayload struct {
	SessionID string `json:"session_id"`
	Data      []byte `json:"data"`
}

// AttachResizePayload reports terminal geometry.
type AttachResizePayload struct {
	SessionID string `json:"session_id"`
	Rows      uint16 `json:"rows"`
	Cols      uint16 `json:"cols"`
}

// AttachClosePayload ends a session.
type AttachClosePayload struct {
	SessionID string `json:"session_id"`
	// Reason is a short human-readable cause, shown to the operator.
	Reason string `json:"reason,omitempty"`
	// ExitCode is the command's status when the device observed one. -1 means
	// it did not (killed, or the session was closed from the hub end).
	ExitCode int `json:"exit_code,omitempty"`
}

// DecodeAttachOpen decodes and validates an open request.
func DecodeAttachOpen(f Frame) (AttachOpenPayload, error) {
	var p AttachOpenPayload
	if err := decodePayload(f, &p); err != nil {
		return p, err
	}
	if strings.TrimSpace(p.SessionID) == "" {
		return p, fmt.Errorf("%w: attach_open has no session id", ErrProtocol)
	}
	return p, nil
}

// DecodeAttachOpened decodes an open acknowledgement.
func DecodeAttachOpened(f Frame) (AttachOpenedPayload, error) {
	var p AttachOpenedPayload
	if err := decodePayload(f, &p); err != nil {
		return p, err
	}
	if strings.TrimSpace(p.SessionID) == "" {
		return p, fmt.Errorf("%w: attach_opened has no session id", ErrProtocol)
	}
	return p, nil
}

// DecodeAttachData decodes one chunk, refusing an oversized one.
//
// The check is here rather than at the sender because the sender is the party
// that might be malicious: an agent that streamed unbounded frames at a hub
// would be turning a debugging session into a memory-exhaustion primitive
// against the control plane.
func DecodeAttachData(f Frame) (AttachDataPayload, error) {
	var p AttachDataPayload
	if err := decodePayload(f, &p); err != nil {
		return p, err
	}
	if strings.TrimSpace(p.SessionID) == "" {
		return p, fmt.Errorf("%w: attach_data has no session id", ErrProtocol)
	}
	if len(p.Data) > MaxAttachChunk {
		return p, fmt.Errorf("%w: attach_data chunk %d bytes exceeds %d",
			ErrProtocol, len(p.Data), MaxAttachChunk)
	}
	return p, nil
}

// DecodeAttachResize decodes a geometry report.
func DecodeAttachResize(f Frame) (AttachResizePayload, error) {
	var p AttachResizePayload
	if err := decodePayload(f, &p); err != nil {
		return p, err
	}
	if strings.TrimSpace(p.SessionID) == "" {
		return p, fmt.Errorf("%w: attach_resize has no session id", ErrProtocol)
	}
	return p, nil
}

// DecodeAttachClose decodes a close notice.
func DecodeAttachClose(f Frame) (AttachClosePayload, error) {
	var p AttachClosePayload
	if err := decodePayload(f, &p); err != nil {
		return p, err
	}
	if strings.TrimSpace(p.SessionID) == "" {
		return p, fmt.Errorf("%w: attach_close has no session id", ErrProtocol)
	}
	return p, nil
}
