package remote

// session.go is the control-plane side of one agent connection: the handshake,
// the read loop, request/response correlation, and the heartbeat watchdog.
//
// A Session is deliberately cheap to lose. Every method that can fail assumes
// the link may vanish mid-call, and nothing durable lives here — handles,
// their logs, and their statuses belong to the Executor. Losing a session
// costs a reconnect and a resume, not a run.

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"
)

// LogAckBytes is how much output may accumulate before the control plane
// acknowledges it. Acking every chunk would double the frame count on a
// chatty run; acking too rarely would make the agent retain more unacked
// output than necessary. 32 KiB matches MaxLogChunkBytes, so a busy stream
// acks roughly every chunk while a trickle of small chunks is batched.
const LogAckBytes = 32 << 10

// Session is one live connection to an enrolled agent.
type Session struct {
	conn    Conn
	ex      *Executor
	agentID string
	version int

	nowFn func() time.Time
	// poll is how often watchHeartbeat checks for silence.
	poll time.Duration

	mu       sync.Mutex
	caps     AgentCapabilities
	pending  map[string]chan Frame
	lastSeen time.Time
	// ackedOffset tracks, per handle, the offset most recently acked to the
	// agent, so acks are only sent when they would actually release buffer.
	ackedOffset map[string]int64
	closed      bool
	// unreachable records that this session ended because the agent stopped
	// answering, rather than because either side closed it deliberately. It
	// is set before the close so the read loop — which owns detaching — can
	// report the right status without racing the watchdog for it.
	unreachable bool

	done      chan struct{}
	closeOnce sync.Once
	closeMsg  string
}

// AcceptOptions parameterises the server-side handshake.
type AcceptOptions struct {
	// Agent is the already-authenticated identity of the peer. The hello
	// frame's AgentID is checked against it; a mismatch is fatal.
	Agent AgentRecord
	// Executor is the durable driver this session attaches to.
	Executor *Executor
	// IssuedCredential is non-empty when this connection redeemed an
	// enrollment token, in which case the credential is handed to the agent
	// in the welcome frame. A freshly enrolling agent does not yet know its
	// own ID, so the hello identity check is relaxed for exactly this case.
	IssuedCredential string
	// Now overrides the clock for tests.
	Now func() time.Time
	// HeartbeatPoll overrides how often the watchdog checks for silence.
	// Zero uses half the heartbeat interval, which keeps detection latency a
	// fraction of the deadline. Tests set it small so a timeout transition
	// can be exercised in milliseconds against a synthetic clock instead of
	// waiting out a real 45-second deadline.
	HeartbeatPoll time.Duration
}

func (o AcceptOptions) now() time.Time {
	if o.Now != nil {
		return o.Now()
	}
	return time.Now()
}

// Accept performs the server side of the handshake on an already-authenticated
// connection and returns a running Session.
//
// Authentication happened at the HTTP upgrade; what remains here is
// *authorization* and version negotiation. The hello frame's AgentID is
// compared against the authenticated identity and a mismatch closes the
// connection, so a valid credential for edge-1 cannot be used to impersonate
// edge-2 and steal its work or forge its status.
//
// On success the session's read loop is already running in its own goroutine.
func Accept(ctx context.Context, conn Conn, opts AcceptOptions) (*Session, error) {
	if conn == nil {
		return nil, fmt.Errorf("remote: accept: nil conn")
	}
	if opts.Executor == nil {
		return nil, fmt.Errorf("remote: accept: nil executor")
	}

	// Bound the handshake: a peer that completes the TCP and TLS handshake
	// and then says nothing must not hold a goroutine and a connection slot
	// indefinitely. This is the cheapest denial-of-service to mount and the
	// cheapest to defend against.
	hsCtx, cancel := context.WithTimeout(ctx, HeartbeatInterval)
	defer cancel()

	frame, err := conn.ReadFrame(hsCtx)
	if err != nil {
		_ = conn.Close("handshake read failed")
		return nil, fmt.Errorf("remote: accept: read hello: %w", err)
	}
	if frame.Type != TypeHello {
		writeError(hsCtx, conn, "", CodeProtocol, "expected a hello frame")
		_ = conn.Close("expected hello")
		return nil, fmt.Errorf("%w: first frame was %q, expected hello", ErrProtocol, frame.Type)
	}
	hello, err := DecodeHello(frame)
	if err != nil {
		writeError(hsCtx, conn, frame.ID, CodeProtocol, err.Error())
		_ = conn.Close("malformed hello")
		return nil, err
	}

	// An agent enrolling for the first time has no ID to claim yet, so an
	// empty AgentID is accepted on exactly that connection. Every other
	// connection must claim the identity its credential was issued to.
	freshEnrollment := opts.IssuedCredential != "" && hello.AgentID == ""
	if !freshEnrollment && hello.AgentID != opts.Agent.AgentID {
		// The credential is valid but claims a different identity. Treat it
		// as hostile rather than as a mistake: report nothing specific to the
		// peer and close.
		writeError(hsCtx, conn, frame.ID, CodeUnauthorized, "identity mismatch")
		_ = conn.Close("identity mismatch")
		return nil, fmt.Errorf("%w: credential is for agent %s but hello claims %s",
			ErrCredentialInvalid, opts.Agent.AgentID, hello.AgentID)
	}

	version, err := NegotiateVersion(hello.ProtocolVersion)
	if err != nil {
		writeError(hsCtx, conn, frame.ID, CodeVersionUnsupported, err.Error())
		_ = conn.Close("unsupported protocol version")
		return nil, err
	}

	now := opts.now()
	poll := opts.HeartbeatPoll
	if poll <= 0 {
		poll = HeartbeatInterval / 2
	}
	sess := &Session{
		conn:        conn,
		ex:          opts.Executor,
		agentID:     opts.Agent.AgentID,
		version:     version,
		nowFn:       opts.now,
		poll:        poll,
		caps:        hello.Capabilities,
		pending:     make(map[string]chan Frame),
		ackedOffset: make(map[string]int64),
		lastSeen:    now,
		done:        make(chan struct{}),
	}

	// Reconcile resume offers before sending welcome: the welcome carries the
	// answer, and the agent blocks on it before resending anything.
	acks := opts.Executor.reconcileResume(hello.Resume)

	welcome, err := NewFrameAt(version, TypeWelcome, frame.ID, "", WelcomePayload{
		ProtocolVersion:  version,
		ExecutorID:       opts.Executor.ID(),
		Credential:       opts.IssuedCredential,
		HeartbeatSeconds: int(HeartbeatInterval / time.Second),
		ResumeAccepted:   acks,
	})
	if err != nil {
		_ = conn.Close("welcome encode failed")
		return nil, err
	}
	if err := conn.WriteFrame(hsCtx, welcome); err != nil {
		_ = conn.Close("welcome write failed")
		return nil, fmt.Errorf("remote: accept: write welcome: %w", err)
	}

	opts.Executor.attach(sess)
	go sess.serve()
	go sess.watchHeartbeat()
	return sess, nil
}

// frame builds a frame stamped with the version this session negotiated.
//
// Every outbound frame goes through here rather than through NewFrame. A v2
// control plane talking to a v1 agent must speak v1 on the wire, or the
// agent's envelope check rejects every frame as out of range and the
// negotiation the handshake performed becomes decorative.
func (s *Session) frame(t FrameType, id, handle string, payload any) (Frame, error) {
	return NewFrameAt(s.version, t, id, handle, payload)
}

// Capabilities returns what the agent advertised at hello.
func (s *Session) Capabilities() AgentCapabilities {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.caps
}

// AgentID returns the authenticated identity of the peer.
func (s *Session) AgentID() string { return s.agentID }

// Version returns the negotiated protocol version.
func (s *Session) Version() int { return s.version }

// LastSeen returns when a frame last arrived from the agent.
func (s *Session) LastSeen() time.Time {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lastSeen
}

// Done returns a channel closed when the session ends.
func (s *Session) Done() <-chan struct{} { return s.done }

// Close ends the session and detaches it from its executor.
func (s *Session) Close() error { return s.closeWithReason("closed by control plane") }

func (s *Session) closeWithReason(reason string) error {
	s.closeOnce.Do(func() {
		s.mu.Lock()
		s.closed = true
		s.closeMsg = reason
		waiters := make([]chan Frame, 0, len(s.pending))
		for id, ch := range s.pending {
			waiters = append(waiters, ch)
			delete(s.pending, id)
		}
		s.mu.Unlock()

		// Closing every pending channel releases in-flight requests with
		// ErrSessionClosed instead of leaving them blocked until their own
		// context expires. A Start that hangs for its full timeout because
		// the link dropped is exactly the "fails slow" behaviour this driver
		// is supposed to avoid.
		for _, ch := range waiters {
			close(ch)
		}
		close(s.done)
		_ = s.conn.Close(reason)
	})
	return nil
}

// serve is the read loop. It runs until the connection fails or the session is
// closed, then detaches from the executor.
// The read loop is the single owner of detach. The heartbeat watchdog closes
// the session and lets this defer do the detaching, so the two cannot race to
// report contradictory statuses for the same disconnect.
func (s *Session) serve() {
	unreachable := false
	defer func() {
		// A panic in frame handling must take down this session, not the
		// whole control plane: one malformed agent should never be able to
		// crash the process serving every other agent.
		if r := recover(); r != nil {
			unreachable = true
			s.closeWithReason(fmt.Sprintf("panic in session read loop: %v", r))
		}
		status := StatusOffline
		s.mu.Lock()
		if s.unreachable || unreachable {
			status = StatusUnreachable
		}
		s.mu.Unlock()
		s.ex.detach(s, status)
	}()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		<-s.done
		cancel()
	}()

	for {
		frame, err := s.conn.ReadFrame(ctx)
		if err != nil {
			// A read error that is not an orderly shutdown means the link
			// broke under us — the agent is unreachable, not offline.
			if !errors.Is(err, context.Canceled) && !errors.Is(err, ErrSessionClosed) {
				unreachable = true
			}
			s.closeWithReason(fmt.Sprintf("read: %v", err))
			return
		}
		s.touch()
		if stop := s.handleFrame(ctx, frame); stop {
			return
		}
	}
}

// handleFrame dispatches one inbound frame. It returns true when the session
// should end.
func (s *Session) handleFrame(ctx context.Context, f Frame) (stop bool) {
	switch f.Type {
	case TypeHeartbeat:
		hb, err := DecodeHeartbeat(f)
		if err != nil {
			return false
		}
		// Reconciling here is what resolves workloads the device forgot: the
		// heartbeat's handle list is the only evidence a control plane gets
		// that a process died with its machine.
		s.ex.reconcileActive(hb.ActiveHandles)
		s.flushAcks(ctx)
		ack, err := s.frame(TypeHeartbeatAck, f.ID, "", HeartbeatAckPayload{
			Seq:        hb.Seq,
			ServerTime: s.nowFn(),
		})
		if err == nil {
			_ = s.write(ctx, ack)
		}
		return false

	case TypeLogChunk:
		chunk, err := DecodeLogChunk(f)
		if err != nil {
			return false
		}
		offset, err := s.ex.appendLog(f.Handle, chunk)
		if err != nil {
			// A chunk for a handle we do not know is not fatal: it is the
			// normal result of the control plane restarting while the agent
			// kept streaming. Tell the agent so it can stop.
			writeError(ctx, s.conn, f.ID, CodeUnknownHandle, err.Error())
			return false
		}
		// Register the handle so the heartbeat's ack flush covers it. A
		// resumed handle never issues a start on this session, so without
		// this a workload producing less than LogAckBytes after a reconnect
		// would never be acked and the agent would retain those bytes until
		// it exited.
		s.trackHandle(f.Handle)
		s.maybeAck(ctx, f.Handle, offset)
		return false

	case TypeStatus:
		payload, err := DecodeStatus(f)
		if err != nil {
			return false
		}
		s.ex.applyStatus(f.Handle, payload)
		// A status frame is both an unsolicited terminal notification and the
		// reply to status_req and signal, so it is applied first and then
		// routed to any waiter.
		s.deliver(f)
		return false

	case TypeStarted, TypeRevoked, TypeError:
		s.deliver(f)
		return false

	case TypeBye:
		bye, _ := DecodeBye(f)
		reason := bye.Reason
		if reason == "" {
			reason = "agent said goodbye"
		}
		s.closeWithReason(reason)
		return true

	case TypeHello:
		// A second hello on an established session means the agent's state
		// machine is confused; the safe response is to reset the link.
		writeError(ctx, s.conn, f.ID, CodeProtocol, "hello on an established session")
		s.closeWithReason("duplicate hello")
		return true

	default:
		writeError(ctx, s.conn, f.ID, CodeProtocol, fmt.Sprintf("unexpected frame type %q", f.Type))
		return false
	}
}

// touch records that the agent is alive.
func (s *Session) touch() {
	s.mu.Lock()
	s.lastSeen = s.nowFn()
	s.mu.Unlock()
}

// watchHeartbeat closes the session once the agent has been silent for
// MissedHeartbeatLimit intervals.
//
// This is the only liveness signal available: the control plane cannot dial a
// NAT'd device to check on it. A half-open TCP connection — the router
// forgot the flow, no FIN was ever sent — reads as perfectly healthy at the
// socket layer and would otherwise keep an offline agent marked online
// forever, with the UI happily dispatching work into a black hole.
func (s *Session) watchHeartbeat() {
	// Check several times per deadline so detection latency is a fraction of
	// the deadline rather than up to a full extra interval.
	tick := s.poll
	if tick <= 0 {
		tick = time.Second
	}
	ticker := time.NewTicker(tick)
	defer ticker.Stop()

	deadline := HeartbeatDeadline()
	for {
		select {
		case <-s.done:
			return
		case <-ticker.C:
			if silent := s.nowFn().Sub(s.LastSeen()); silent > deadline {
				// Flag the reason, then close. Closing unblocks the read loop,
				// which owns detaching and will report StatusUnreachable
				// because of the flag — the agent did not say goodbye, it
				// stopped answering.
				s.mu.Lock()
				s.unreachable = true
				s.mu.Unlock()
				s.closeWithReason(fmt.Sprintf(
					"no heartbeat for %s (limit %s)", silent.Round(time.Second), deadline))
				return
			}
		}
	}
}

// maybeAck sends a log ack once enough new output has accumulated.
func (s *Session) maybeAck(ctx context.Context, handleID string, offset int64) {
	s.mu.Lock()
	last := s.ackedOffset[handleID]
	if offset-last < LogAckBytes {
		s.mu.Unlock()
		return
	}
	s.ackedOffset[handleID] = offset
	s.mu.Unlock()
	s.sendAck(ctx, handleID, offset)
}

// flushAcks emits any acks held below the byte threshold. Called on every
// heartbeat so a workload that stops producing output still has its final
// bytes acknowledged and the agent's retained buffer released.
func (s *Session) flushAcks(ctx context.Context) {
	// Snapshot under s.mu, then do the executor lookups with it released.
	// Calling into the executor while holding s.mu would invert the
	// Executor.mu → Session.mu order that attach relies on.
	s.mu.Lock()
	acked := make(map[string]int64, len(s.ackedOffset))
	for handleID, offset := range s.ackedOffset {
		acked[handleID] = offset
	}
	s.mu.Unlock()

	type pendingAck struct {
		handle string
		offset int64
	}
	var flush []pendingAck
	for handleID, was := range acked {
		hs, err := s.ex.lookup(handleID)
		if err != nil {
			continue
		}
		hs.mu.Lock()
		received := hs.receivedOffset
		hs.mu.Unlock()
		if received > was {
			flush = append(flush, pendingAck{handleID, received})
		}
	}
	if len(flush) == 0 {
		return
	}

	s.mu.Lock()
	for _, a := range flush {
		// Re-check against the live value: maybeAck may have advanced this
		// handle while the lock was released, and an ack must never move
		// backwards or the agent would re-send output already delivered.
		if a.offset > s.ackedOffset[a.handle] {
			s.ackedOffset[a.handle] = a.offset
		}
	}
	s.mu.Unlock()

	for _, a := range flush {
		s.sendAck(ctx, a.handle, a.offset)
	}
}

func (s *Session) sendAck(ctx context.Context, handleID string, offset int64) {
	frame, err := s.frame(TypeLogAck, "", handleID, LogAckPayload{Offset: offset})
	if err != nil {
		return
	}
	_ = s.write(ctx, frame)
}

// trackHandle registers a handle so flushAcks knows to consider it.
func (s *Session) trackHandle(handleID string) {
	s.mu.Lock()
	if _, ok := s.ackedOffset[handleID]; !ok {
		s.ackedOffset[handleID] = 0
	}
	s.mu.Unlock()
}

// write sends a frame, failing fast if the session is already closed.
func (s *Session) write(ctx context.Context, f Frame) error {
	s.mu.Lock()
	closed := s.closed
	s.mu.Unlock()
	if closed {
		return fmt.Errorf("%w: %s", ErrSessionClosed, s.closeMsg)
	}
	return s.conn.WriteFrame(ctx, f)
}

// request sends f and waits for a reply correlated by f.ID.
//
// It returns as soon as any of four things happens: the reply arrives, the
// agent reports an error, ctx expires, or the session dies. The last is the
// important one — without it a Start issued microseconds before an LTE modem
// dropped would block for its full context timeout rather than failing
// immediately with a comprehensible reason.
func (s *Session) request(ctx context.Context, f Frame, want FrameType) (Frame, error) {
	if f.ID == "" {
		return Frame{}, fmt.Errorf("remote: request frame has no correlation ID")
	}
	ch := make(chan Frame, 1)

	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return Frame{}, fmt.Errorf("%w: %s", ErrSessionClosed, s.closeMsg)
	}
	s.pending[f.ID] = ch
	s.mu.Unlock()

	defer func() {
		s.mu.Lock()
		delete(s.pending, f.ID)
		s.mu.Unlock()
	}()

	if f.Handle != "" {
		s.trackHandle(f.Handle)
	}
	if err := s.write(ctx, f); err != nil {
		return Frame{}, err
	}

	select {
	case reply, ok := <-ch:
		if !ok {
			return Frame{}, fmt.Errorf("%w: %s", ErrSessionClosed, s.closeMsg)
		}
		if reply.Type == TypeError {
			payload, decodeErr := DecodeError(reply)
			if decodeErr != nil {
				return Frame{}, decodeErr
			}
			return Frame{}, errorFromPayload(payload)
		}
		if reply.Type != want {
			return Frame{}, fmt.Errorf("%w: expected %s in reply to %s, got %s",
				ErrProtocol, want, f.Type, reply.Type)
		}
		return reply, nil
	case <-s.done:
		return Frame{}, fmt.Errorf("%w: %s", ErrSessionClosed, s.closeMsg)
	case <-ctx.Done():
		return Frame{}, ctx.Err()
	}
}

// deliver routes a reply to its waiting request, if any.
func (s *Session) deliver(f Frame) {
	if f.ID == "" {
		return
	}
	s.mu.Lock()
	ch, ok := s.pending[f.ID]
	if ok {
		delete(s.pending, f.ID)
	}
	s.mu.Unlock()
	if !ok {
		// No waiter: an unsolicited status, or a reply that arrived after its
		// request gave up. Both are normal and neither is an error.
		return
	}
	// Buffered with capacity 1 and removed from the map above, so exactly one
	// send can ever reach it and this cannot block or race with close.
	ch <- f
	close(ch)
}

// errorFromPayload maps a protocol error code onto the package's sentinels so
// callers can errors.Is against them instead of string-matching messages.
func errorFromPayload(p ErrorPayload) error {
	base := errors.New(p.Message)
	switch p.Code {
	case CodeUnauthorized:
		return fmt.Errorf("%w: %s", ErrCredentialInvalid, p.Message)
	case CodeVersionUnsupported:
		return fmt.Errorf("%w: %s", ErrVersionUnsupported, p.Message)
	case CodeUnknownHandle:
		return fmt.Errorf("%w: %s", ErrProtocol, p.Message)
	case CodeForbiddenPath:
		return fmt.Errorf("%w: %s", ErrPathOutsideRoot, p.Message)
	case CodeBusy:
		return fmt.Errorf("%w: %s", ErrAgentBusy, p.Message)
	case CodeProtocol:
		return fmt.Errorf("%w: %s", ErrProtocol, p.Message)
	default:
		return base
	}
}

// writeError sends an error frame on a best-effort basis. Failures are ignored
// because every caller is already on a path that closes the connection.
//
// It is stamped at MinProtocolVersion rather than at this build's maximum
// because every caller is on a pre-negotiation or failed-negotiation path: an
// error frame's entire job is to be legible to the peer that could not agree
// with us, and a peer stuck at the floor rejects anything above it as an
// out-of-range envelope. Reporting "unsupported version" in a frame the peer
// cannot parse would tell it only that the link broke.
func writeError(ctx context.Context, conn Conn, id, code, msg string) {
	frame, err := NewFrameAt(MinProtocolVersion, TypeError, id, "", ErrorPayload{Code: code, Message: msg})
	if err != nil {
		return
	}
	_ = conn.WriteFrame(ctx, frame)
}
