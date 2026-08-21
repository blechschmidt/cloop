package remote_test

// Session tests: handshake authorization, heartbeat-timeout transition, and
// reconnect-with-resume.
//
// These drive the control-plane state machine over an in-memory pipe with a
// hand-written peer, so the exact frame sequence — including the ones a real
// agent would never send, like a hello claiming someone else's identity — is
// under the test's control.

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/executor/remote"
)

// fakeClock is a manually advanced clock, so heartbeat-deadline behaviour can
// be exercised in milliseconds instead of waiting out a real 45s deadline.
type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func newFakeClock() *fakeClock {
	return &fakeClock{now: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(d)
	c.mu.Unlock()
}

// peer is the test's hand-written agent side of a connection.
type peer struct {
	t    *testing.T
	conn remote.Conn
}

func (p *peer) write(f remote.Frame) {
	p.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := p.conn.WriteFrame(ctx, f); err != nil {
		p.t.Fatalf("peer write %s: %v", f.Type, err)
	}
}

func (p *peer) read() (remote.Frame, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	return p.conn.ReadFrame(ctx)
}

// readUntil returns the first frame of the given type, ignoring others. Log
// acks and heartbeat acks arrive interleaved with replies, so a test looking
// for a specific frame cannot assume it is next.
func (p *peer) readUntil(want remote.FrameType) remote.Frame {
	p.t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		f, err := p.read()
		if err != nil {
			p.t.Fatalf("peer read waiting for %s: %v", want, err)
		}
		if f.Type == want {
			return f
		}
	}
	p.t.Fatalf("timed out waiting for a %s frame", want)
	return remote.Frame{}
}

// connect performs the agent side of the handshake and returns the peer plus
// the control plane's session.
func connect(t *testing.T, ex *remote.Executor, agent remote.AgentRecord, hello remote.HelloPayload, clock *fakeClock) (*peer, *remote.Session) {
	t.Helper()
	cpConn, agentConn := remote.NewPipe(64)

	type result struct {
		sess *remote.Session
		err  error
	}
	resCh := make(chan result, 1)
	go func() {
		opts := remote.AcceptOptions{
			Agent:         agent,
			Executor:      ex,
			HeartbeatPoll: 5 * time.Millisecond,
		}
		if clock != nil {
			opts.Now = clock.Now
		}
		sess, err := remote.Accept(context.Background(), cpConn, opts)
		resCh <- result{sess, err}
	}()

	p := &peer{t: t, conn: agentConn}
	frame, err := remote.NewFrame(remote.TypeHello, "hello", "", hello)
	if err != nil {
		t.Fatalf("build hello: %v", err)
	}
	p.write(frame)

	select {
	case res := <-resCh:
		if res.err != nil {
			t.Fatalf("Accept: %v", res.err)
		}
		// Drain the welcome so the caller starts from a clean stream.
		p.readUntil(remote.TypeWelcome)
		return p, res.sess
	case <-time.After(3 * time.Second):
		t.Fatal("Accept did not complete")
		return nil, nil
	}
}

func newTestExecutor(t *testing.T, clock *fakeClock) *remote.Executor {
	t.Helper()
	opts := remote.Options{ID: "agent-1", Name: "edge-1"}
	if clock != nil {
		opts.Now = clock.Now
	}
	ex, err := remote.NewExecutor(opts)
	if err != nil {
		t.Fatalf("NewExecutor: %v", err)
	}
	return ex
}

func defaultHello() remote.HelloPayload {
	return remote.HelloPayload{
		ProtocolVersion: remote.ProtocolVersion,
		AgentID:         "agent-1",
		Name:            "edge-1",
		Capabilities: remote.AgentCapabilities{
			OS: "linux", Arch: "arm64", CPUs: 4, MemoryMB: 2048,
			Harnesses: []string{"claude"},
		},
	}
}

// TestHeartbeatTimeoutMarksUnreachable is the liveness assertion. A NAT'd
// device cannot be probed, so silence is the only evidence available that it
// is gone — and a half-open TCP connection reads as perfectly healthy at the
// socket layer. Without this transition the control plane would keep
// dispatching work into a black hole.
func TestHeartbeatTimeoutMarksUnreachable(t *testing.T) {
	clock := newFakeClock()
	ex := newTestExecutor(t, clock)
	_, sess := connect(t, ex, remote.AgentRecord{AgentID: "agent-1", Name: "edge-1"}, defaultHello(), clock)

	if !ex.Connected() {
		t.Fatal("executor should be connected right after the handshake")
	}
	if got := ex.ConnStatus(); got != remote.StatusOnline {
		t.Fatalf("status = %q, want online", got)
	}

	// Go silent for longer than MissedHeartbeatLimit intervals.
	clock.Advance(remote.HeartbeatDeadline() + time.Second)

	select {
	case <-sess.Done():
	case <-time.After(3 * time.Second):
		t.Fatal("session should have been closed by the heartbeat watchdog")
	}

	// The detach happens in the read loop after the close, so allow it to run.
	waitFor(t, 2*time.Second, func() bool {
		return !ex.Connected() && ex.ConnStatus() == remote.StatusUnreachable
	}, "executor should become unreachable")

	// Start must now fail fast with the typed error rather than hanging.
	_, err := ex.Start(context.Background(), executor.Spec{
		WorkDir: t.TempDir(),
		Argv:    []string{"echo", "hi"},
	})
	if !errors.Is(err, remote.ErrAgentUnreachable) {
		t.Fatalf("Start on an unreachable agent must return ErrAgentUnreachable, got %v", err)
	}
}

// TestHeartbeatKeepsSessionAlive is the converse: an agent that keeps beating
// must not be reaped. A watchdog that evicts healthy agents is worse than none.
func TestHeartbeatKeepsSessionAlive(t *testing.T) {
	clock := newFakeClock()
	ex := newTestExecutor(t, clock)
	p, sess := connect(t, ex, remote.AgentRecord{AgentID: "agent-1"}, defaultHello(), clock)

	// Beat several times, advancing just under the deadline between each.
	for i := 0; i < 4; i++ {
		clock.Advance(remote.HeartbeatInterval)
		f, err := remote.NewFrame(remote.TypeHeartbeat, "", "", remote.HeartbeatPayload{Seq: uint64(i + 1)})
		if err != nil {
			t.Fatalf("build heartbeat: %v", err)
		}
		p.write(f)
		p.readUntil(remote.TypeHeartbeatAck)
	}

	select {
	case <-sess.Done():
		t.Fatal("a heartbeating session must not be closed")
	default:
	}
	if !ex.Connected() {
		t.Error("executor should still be connected")
	}
}

// TestHelloIdentityMismatchRejected is the frame-authorization assertion: a
// valid credential for one agent must not let it claim another's identity and
// thereby forge status or steal logs for that agent's handles.
func TestHelloIdentityMismatchRejected(t *testing.T) {
	ex := newTestExecutor(t, nil)
	cpConn, agentConn := remote.NewPipe(8)

	errCh := make(chan error, 1)
	go func() {
		_, err := remote.Accept(context.Background(), cpConn, remote.AcceptOptions{
			Agent:    remote.AgentRecord{AgentID: "agent-1"},
			Executor: ex,
		})
		errCh <- err
	}()

	p := &peer{t: t, conn: agentConn}
	hello := defaultHello()
	hello.AgentID = "agent-2-someone-else"
	f, err := remote.NewFrame(remote.TypeHello, "hello", "", hello)
	if err != nil {
		t.Fatalf("build hello: %v", err)
	}
	p.write(f)

	select {
	case err := <-errCh:
		if !errors.Is(err, remote.ErrCredentialInvalid) {
			t.Fatalf("expected ErrCredentialInvalid for an identity mismatch, got %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Accept did not reject the mismatched hello")
	}
	if ex.Connected() {
		t.Error("a rejected handshake must not attach a session")
	}
}

func TestHelloVersionNegotiationRejectsAncientAgent(t *testing.T) {
	ex := newTestExecutor(t, nil)
	cpConn, agentConn := remote.NewPipe(8)

	errCh := make(chan error, 1)
	go func() {
		_, err := remote.Accept(context.Background(), cpConn, remote.AcceptOptions{
			Agent:    remote.AgentRecord{AgentID: "agent-1"},
			Executor: ex,
		})
		errCh <- err
	}()

	p := &peer{t: t, conn: agentConn}
	hello := defaultHello()
	hello.ProtocolVersion = remote.MinProtocolVersion - 1
	f, err := remote.NewFrame(remote.TypeHello, "hello", "", hello)
	if err != nil {
		t.Fatalf("build hello: %v", err)
	}
	p.write(f)

	select {
	case err := <-errCh:
		if !errors.Is(err, remote.ErrVersionUnsupported) {
			t.Fatalf("expected ErrVersionUnsupported, got %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Accept did not reject the old protocol version")
	}
}

// TestStartSignalStatusRoundTrip exercises the request/response correlation
// for the three control operations.
func TestStartSignalStatusRoundTrip(t *testing.T) {
	ex := newTestExecutor(t, nil)
	p, _ := connect(t, ex, remote.AgentRecord{AgentID: "agent-1"}, defaultHello(), nil)

	// Answer the start frame as a real agent would.
	var handleID string
	startDone := make(chan struct{})
	go func() {
		defer close(startDone)
		f := p.readUntil(remote.TypeStart)
		handleID = f.Handle
		reply, err := remote.NewFrame(remote.TypeStarted, f.ID, f.Handle, remote.StartedPayload{
			HandleID:  f.Handle,
			PID:       4242,
			StartedAt: time.Now(),
		})
		if err != nil {
			return
		}
		p.write(reply)
	}()

	handle, err := ex.Start(context.Background(), executor.Spec{
		WorkDir: t.TempDir(),
		Argv:    []string{"echo", "hello"},
	})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	<-startDone
	if handle.PID != 4242 {
		t.Errorf("PID = %d, want 4242 (the device-side PID must be reported)", handle.PID)
	}
	if handle.ID != handleID {
		t.Errorf("handle ID mismatch: %q vs frame %q", handle.ID, handleID)
	}
	if handle.ExecutorID != "agent-1" {
		t.Errorf("ExecutorID = %q, want agent-1", handle.ExecutorID)
	}

	// Signal: the agent answers with a status, which doubles as the delivery
	// acknowledgement.
	sigDone := make(chan struct{})
	go func() {
		defer close(sigDone)
		f := p.readUntil(remote.TypeSignal)
		payload, err := remote.DecodeSignal(f)
		if err != nil {
			t.Errorf("DecodeSignal: %v", err)
			return
		}
		if payload.Signal != executor.SignalInterrupt {
			t.Errorf("signal = %q, want interrupt", payload.Signal)
		}
		reply, err := remote.NewFrame(remote.TypeStatus, f.ID, f.Handle, remote.StatusPayload{
			Status: executor.Status{HandleID: f.Handle, State: executor.StateRunning},
		})
		if err != nil {
			return
		}
		p.write(reply)
	}()

	if err := ex.Signal(context.Background(), handle.ID, executor.SignalInterrupt); err != nil {
		t.Fatalf("Signal: %v", err)
	}
	<-sigDone
}

// TestStatusUnknownWhenDisconnected pins the documented meaning of
// StateUnknown: a run whose device dropped off must render as "state unknown,
// last seen running" rather than disappearing behind an error.
func TestStatusUnknownWhenDisconnected(t *testing.T) {
	ex := newTestExecutor(t, nil)
	p, sess := connect(t, ex, remote.AgentRecord{AgentID: "agent-1"}, defaultHello(), nil)

	handle := startHandle(t, ex, p)

	sess.Close()
	waitFor(t, 2*time.Second, func() bool { return !ex.Connected() }, "session should detach")

	st, err := ex.Status(context.Background(), handle.ID)
	if err != nil {
		t.Fatalf("Status after disconnect should not error: %v", err)
	}
	if st.State != executor.StateUnknown {
		t.Errorf("state = %q, want unknown", st.State)
	}
	if !strings.Contains(st.Error, "not connected") {
		t.Errorf("status error should explain the agent is offline, got %q", st.Error)
	}
}

// startHandle drives a Start through a scripted peer and returns the handle.
func startHandle(t *testing.T, ex *remote.Executor, p *peer) executor.Handle {
	t.Helper()
	done := make(chan struct{})
	go func() {
		defer close(done)
		f := p.readUntil(remote.TypeStart)
		reply, err := remote.NewFrame(remote.TypeStarted, f.ID, f.Handle, remote.StartedPayload{
			HandleID:  f.Handle,
			PID:       111,
			StartedAt: time.Now(),
		})
		if err != nil {
			return
		}
		p.write(reply)
	}()
	handle, err := ex.Start(context.Background(), executor.Spec{
		WorkDir: t.TempDir(),
		Argv:    []string{"sleep", "60"},
	})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	<-done
	return handle
}

// waitFor polls cond until it holds or the timeout expires.
func waitFor(t *testing.T, timeout time.Duration, cond func() bool, msg string) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("timed out: %s", msg)
}
