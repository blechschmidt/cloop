package remote

// attach.go is the hub half of interactive attach for edge devices
// (Task 20265): executor.Attacher, implemented over the frames in
// attachproto.go and multiplexed onto the session the agent already holds.
//
// # The shape of a session here
//
// Unlike the container and Kubernetes drivers, nothing on this side holds a
// file descriptor connected to the workload. The conn returned by Attach is a
// mailbox: Write encodes a frame and hands it to the session; incoming data
// frames are pushed into a pipe by the session's read loop. So this file owns a
// registry keyed by session ID, and the session's dispatcher looks the session
// up there — the same pattern as handleState, one level finer because a handle
// can carry several terminals.
//
// # What happens when the device drops
//
// Everything open is closed with a reason. An attach session is not resumable:
// the process on the far side is gone with the connection, and offering the
// operator a terminal that reconnects into a different shell would be worse
// than telling them it ended.

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"

	"github.com/blechschmidt/cloop/pkg/executor"
)

// attachSession is the hub's end of one live terminal.
type attachSession struct {
	id       string
	handleID string
	sess     *Session
	writable bool

	pw  *io.PipeWriter // written only by pump
	out io.Reader      // redacted view handed to the caller

	// inbox decouples the session read loop from the operator's transport.
	//
	// This is not an optimisation. The read loop is shared by every workload on
	// this agent — heartbeats, log chunks, status replies — and writing an
	// attach chunk straight into the pipe would block it for as long as the
	// terminal's consumer took to drain. A browser tab that stopped reading
	// would stall the heartbeat, the watchdog would declare the device
	// unreachable, and one slow terminal would take down every task on that
	// edge device. Observed exactly that way before this buffer existed:
	// "session closed: no heartbeat for 52s (limit 45s)".
	inbox chan []byte

	closeOnce sync.Once
	closed    chan struct{}
}

// Attach implements executor.Attacher.
func (e *Executor) Attach(ctx context.Context, req executor.AttachRequest) (executor.AttachConn, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	hs, err := e.lookup(req.HandleID)
	if err != nil {
		return nil, err
	}
	if hs.snapshotStatus().State.Terminal() {
		return nil, fmt.Errorf("%w: handle %s has finished on agent %s",
			executor.ErrAttachClosed, req.HandleID, e.id)
	}

	sess := e.currentSession()
	if sess == nil {
		return nil, fmt.Errorf("%w: cannot attach to %s: agent %s is not connected",
			ErrAgentUnreachable, req.HandleID, e.id)
	}
	if !SupportsAttach(sess.Version()) {
		return nil, fmt.Errorf("%w: agent %s speaks protocol v%d; interactive attach needs v%d "+
			"(press Upgrade on the device's row in the Executors panel, or run `sudo cloop executor agent install --upgrade` on it)",
			executor.ErrAttachUnsupported, e.id, sess.Version(), MinAttachVersion)
	}

	sessionID := newCorrelationID()
	pr, pw := io.Pipe()
	as := &attachSession{
		id:       sessionID,
		handleID: req.HandleID,
		sess:     sess,
		writable: req.Stdin,
		pw:       pw,
		inbox:    make(chan []byte, attachInboxDepth),
		closed:   make(chan struct{}),
	}
	go as.pump()
	// The same redaction the log stream applies to this handle's output. The
	// remote driver installs its set on the handle's bus at Start; reusing it
	// keeps a credential that never reaches the live-log room from reaching a
	// terminal on the same workload.
	as.out = executor.RedactAttachOutput(pr, hs.redactor())

	// Register before asking, so a device that answers faster than this
	// goroutine resumes still finds somewhere to deliver the first chunk.
	//
	// The refusal here is the structural backstop, not the policy ceiling: the
	// hub's AttachLimiter is what an operator sees and can widen, while this
	// one is enforced where the frames are actually routed, so a future call
	// site that forgets the limiter still cannot turn one agent connection into
	// an unbounded fan-out of pipes.
	if !sess.registerAttach(as) {
		return nil, fmt.Errorf("%w: agent %s is already carrying %d interactive sessions",
			executor.ErrAttachBusy, e.id, maxAttachSessionsPerConnection)
	}

	frame, err := sess.frame(TypeAttachOpen, newCorrelationID(), req.HandleID, AttachOpenPayload{
		SessionID: sessionID,
		Command:   req.Command,
		TTY:       req.TTY,
		Stdin:     req.Stdin,
		Rows:      req.Rows,
		Cols:      req.Cols,
		Env:       req.Env,
	})
	if err != nil {
		sess.unregisterAttach(sessionID)
		return nil, err
	}
	reply, err := sess.request(ctx, frame, TypeAttachOpened)
	if err != nil {
		sess.unregisterAttach(sessionID)
		return nil, fmt.Errorf("remote: attach to %s on agent %s: %w", req.HandleID, e.id, err)
	}
	if _, derr := DecodeAttachOpened(reply); derr != nil {
		sess.unregisterAttach(sessionID)
		return nil, derr
	}
	return as, nil
}

func (a *attachSession) Read(p []byte) (int, error) { return a.out.Read(p) }

func (a *attachSession) Write(p []byte) (int, error) {
	if !a.writable {
		return 0, executor.ErrAttachReadOnly
	}
	select {
	case <-a.closed:
		return 0, executor.ErrAttachClosed
	default:
	}
	// Chunked, because a paste is one Write of arbitrary size and the frame
	// decoder refuses an oversized payload. Splitting here rather than failing
	// keeps "paste a script into the terminal" working.
	total := 0
	for len(p) > 0 {
		n := len(p)
		if n > MaxAttachChunk {
			n = MaxAttachChunk
		}
		if err := a.send(TypeAttachData, AttachDataPayload{SessionID: a.id, Data: p[:n]}); err != nil {
			return total, err
		}
		total += n
		p = p[n:]
	}
	return total, nil
}

func (a *attachSession) Resize(rows, cols uint16) error {
	if rows == 0 || cols == 0 {
		return nil
	}
	select {
	case <-a.closed:
		return nil
	default:
	}
	return a.send(TypeAttachResize, AttachResizePayload{SessionID: a.id, Rows: rows, Cols: cols})
}

func (a *attachSession) Close() error {
	a.closeOnce.Do(func() {
		close(a.closed)
		// Best effort: tell the device to kill the command. A failure here is
		// not worth surfacing — the operator has already left — but it is worth
		// attempting, because the alternative is a shell running unattended
		// inside a sandbox that still holds the project's credentials.
		_ = a.send(TypeAttachClose, AttachClosePayload{SessionID: a.id, Reason: "closed by operator"})
		a.sess.unregisterAttach(a.id)
		_ = a.pw.Close()
	})
	return nil
}

// send writes one frame on the shared session.
func (a *attachSession) send(t FrameType, payload any) error {
	frame, err := a.sess.frame(t, newCorrelationID(), a.handleID, payload)
	if err != nil {
		return err
	}
	// A short bound rather than the caller's context: a wedged uplink must not
	// pin a keystroke forever, and the operator would rather see the session
	// fail than watch a terminal stop echoing with no explanation.
	ctx, cancel := context.WithTimeout(context.Background(), attachWriteTimeout)
	defer cancel()
	return a.sess.write(ctx, frame)
}

// deliver hands one inbound chunk to this terminal's pump. It must never
// block: it runs on the session read loop that every workload on this agent
// shares.
func (a *attachSession) deliver(data []byte) {
	if len(data) == 0 {
		return
	}
	select {
	case a.inbox <- data:
	case <-a.closed:
	default:
		// The buffer is full, so this terminal's consumer has fallen a megabyte
		// behind. Ending one session is the only outcome that is bounded: the
		// alternatives are to block the shared read loop (which kills every
		// task on the device) or to keep buffering (which makes a slow reader a
		// memory-exhaustion primitive against the hub).
		a.finish("terminal fell too far behind and was disconnected")
	}
}

// pump is the only writer to the pipe, so the read loop never touches it.
func (a *attachSession) pump() {
	for {
		select {
		case <-a.closed:
			return
		case chunk := <-a.inbox:
			if _, err := a.pw.Write(chunk); err != nil {
				return
			}
		}
	}
}

// finish ends the session because the far side said so.
//
// The reason travels as the pipe's close error rather than as bytes written
// into it. Writing it would block whenever the consumer is not reading — which
// is precisely the situation that calls finish from deliver — and that write
// happens on the shared session read loop. CloseWithError never blocks, and the
// reader gets the same sentence either way.
func (a *attachSession) finish(reason string) {
	a.closeOnce.Do(func() {
		close(a.closed)
		a.sess.unregisterAttach(a.id)
		if strings.TrimSpace(reason) == "" {
			reason = "session ended"
		}
		_ = a.pw.CloseWithError(errors.New(reason))
	})
}
