package remote

// conn.go isolates frame transport from protocol logic.
//
// The session state machine — heartbeat accounting, log-offset reconciliation,
// request correlation — is the part with interesting failure modes, and it is
// the part worth testing without a network. So it talks to a Conn, and the
// WebSocket implementation is one small adapter behind that interface. The
// loopback end-to-end test still uses the real WebSocket adapter, so the seam
// buys testability without letting the production path go unexercised.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"nhooyr.io/websocket"
)

// Conn is a bidirectional, ordered, message-framed connection.
//
// Ordering is load-bearing: the log-resume design assumes that a chunk sent
// before a terminal status frame arrives before it, which is what lets the
// control plane close a log stream on terminal status without worrying about
// output still in flight. A transport that reorders would break that, so any
// future implementation must preserve message order.
//
// Implementations must be safe for one concurrent reader and one concurrent
// writer. They are not required to tolerate concurrent readers or concurrent
// writers; the session serialises both.
type Conn interface {
	// ReadFrame blocks until a frame arrives, ctx is cancelled, or the peer
	// goes away (io.EOF / net.ErrClosed).
	ReadFrame(ctx context.Context) (Frame, error)
	// WriteFrame sends one frame.
	WriteFrame(ctx context.Context, f Frame) error
	// Close terminates the connection. Idempotent.
	Close(reason string) error
}

// wsConn adapts a nhooyr.io/websocket connection to Conn.
type wsConn struct {
	c *websocket.Conn

	// writeMu serialises writes. websocket.Conn permits only one concurrent
	// writer, and the session's dispatch path plus its heartbeat-ack path can
	// both write, so the lock lives here rather than being every caller's
	// problem.
	writeMu sync.Mutex

	closeOnce sync.Once
}

// NewWSConn wraps an established WebSocket as a Conn and applies the protocol
// read limit, so a peer cannot force a large allocation with one message.
func NewWSConn(c *websocket.Conn) Conn {
	c.SetReadLimit(MaxFrameBytes)
	return &wsConn{c: c}
}

func (w *wsConn) ReadFrame(ctx context.Context) (Frame, error) {
	typ, data, err := w.c.Read(ctx)
	if err != nil {
		return Frame{}, normalizeConnError(err)
	}
	if typ != websocket.MessageText {
		return Frame{}, fmt.Errorf("%w: expected a text frame, got %v", ErrProtocol, typ)
	}
	var f Frame
	if err := json.Unmarshal(data, &f); err != nil {
		return Frame{}, fmt.Errorf("%w: decode frame: %v", ErrProtocol, err)
	}
	if err := f.Validate(); err != nil {
		return Frame{}, err
	}
	return f, nil
}

func (w *wsConn) WriteFrame(ctx context.Context, f Frame) error {
	data, err := json.Marshal(f)
	if err != nil {
		return fmt.Errorf("remote: encode %s frame: %w", f.Type, err)
	}
	// A write that cannot drain must not block the caller forever: an edge
	// device on a dead LTE link accepts no bytes but also sends no FIN, so
	// without this bound the dispatch goroutine would wedge until TCP gave up
	// minutes later.
	ctx, cancel := context.WithTimeout(ctx, WriteTimeout)
	defer cancel()

	w.writeMu.Lock()
	defer w.writeMu.Unlock()
	if err := w.c.Write(ctx, websocket.MessageText, data); err != nil {
		return normalizeConnError(err)
	}
	return nil
}

func (w *wsConn) Close(reason string) error {
	var err error
	w.closeOnce.Do(func() {
		// Close reasons are capped at 125 bytes by RFC 6455; oversizing makes
		// the library error instead of closing, which would leak the conn.
		if len(reason) > 120 {
			reason = reason[:120]
		}
		err = w.c.Close(websocket.StatusNormalClosure, reason)
	})
	return err
}

// normalizeConnError maps transport-specific disconnect errors onto
// ErrSessionClosed so the session state machine has one condition to test for
// instead of a growing list of library and syscall errors.
func normalizeConnError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
		return fmt.Errorf("%w: %v", ErrSessionClosed, err)
	}
	if websocket.CloseStatus(err) != -1 {
		return fmt.Errorf("%w: %v", ErrSessionClosed, err)
	}
	return err
}

// pipeConn is an in-memory Conn pair used by tests to drive the session state
// machine without a network. It lives in the non-test build because the agent
// package's tests need it too, and duplicating it there would let the two
// copies drift.
type pipeConn struct {
	in     chan Frame
	out    chan Frame
	shared *pipeShared
}

// pipeShared is the close state both ends of a pipe share. It is a separate
// struct rather than duplicated fields because closing is a property of the
// *link*, not of either endpoint: with a sync.Once per endpoint, closing both
// ends would close the same channel twice and panic.
type pipeShared struct {
	once   sync.Once
	closed chan struct{}
	mu     sync.Mutex
	reason string
}

// NewPipe returns two Conns wired to each other. Frames written to one are
// readable from the other. Closing either closes both, matching how a real
// socket behaves.
func NewPipe(buffer int) (Conn, Conn) {
	if buffer <= 0 {
		buffer = 16
	}
	a2b := make(chan Frame, buffer)
	b2a := make(chan Frame, buffer)
	shared := &pipeShared{closed: make(chan struct{})}
	a := &pipeConn{in: b2a, out: a2b, shared: shared}
	b := &pipeConn{in: a2b, out: b2a, shared: shared}
	return a, b
}

func (p *pipeConn) ReadFrame(ctx context.Context) (Frame, error) {
	select {
	case f, ok := <-p.in:
		if !ok {
			return Frame{}, fmt.Errorf("%w: pipe drained", ErrSessionClosed)
		}
		if err := f.Validate(); err != nil {
			return Frame{}, err
		}
		return f, nil
	case <-p.shared.closed:
		return Frame{}, fmt.Errorf("%w: %s", ErrSessionClosed, p.closeReason())
	case <-ctx.Done():
		return Frame{}, ctx.Err()
	}
}

func (p *pipeConn) WriteFrame(ctx context.Context, f Frame) error {
	// Round-trip through JSON so tests exercise the same marshalling the
	// WebSocket path does — a payload that only works because both sides
	// share a pointer would otherwise pass here and fail in production.
	data, err := json.Marshal(f)
	if err != nil {
		return fmt.Errorf("remote: encode %s frame: %w", f.Type, err)
	}
	var decoded Frame
	if err := json.Unmarshal(data, &decoded); err != nil {
		return fmt.Errorf("remote: re-decode %s frame: %w", f.Type, err)
	}
	select {
	case p.out <- decoded:
		return nil
	case <-p.shared.closed:
		return fmt.Errorf("%w: %s", ErrSessionClosed, p.closeReason())
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(WriteTimeout):
		return fmt.Errorf("remote: pipe write timed out")
	}
}

func (p *pipeConn) Close(reason string) error {
	p.shared.once.Do(func() {
		p.shared.mu.Lock()
		p.shared.reason = reason
		p.shared.mu.Unlock()
		close(p.shared.closed)
	})
	return nil
}

func (p *pipeConn) closeReason() string {
	p.shared.mu.Lock()
	defer p.shared.mu.Unlock()
	if p.shared.reason == "" {
		return "pipe closed"
	}
	return p.shared.reason
}
