package remote_test

// Reconnect-with-resume tests.
//
// Reconnection is the normal case for an edge device, not an exceptional one,
// so the log stream has to survive it. The property under test: after a
// disconnect, the control plane tells the reconnecting agent the exact byte
// offset it needs next, and the reassembled stream is byte-for-byte what the
// workload actually produced — no duplicated prefix, no silent hole.

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/executor/remote"
)

// sendLog writes one log chunk from the peer at the given byte offset.
func (p *peer) sendLog(handleID string, offset int64, text string) {
	p.t.Helper()
	f, err := remote.NewFrame(remote.TypeLogChunk, "", handleID, remote.LogChunkPayload{
		Stream: executor.StreamCombined,
		Offset: offset,
		Text:   text,
		Time:   time.Now(),
	})
	if err != nil {
		p.t.Fatalf("build log chunk: %v", err)
	}
	p.write(f)
}

// collect drains a stream channel until it closes or goes quiet.
func collect(t *testing.T, lines <-chan executor.LogLine, quiet time.Duration) string {
	t.Helper()
	var sb strings.Builder
	timer := time.NewTimer(quiet)
	defer timer.Stop()
	for {
		select {
		case line, ok := <-lines:
			if !ok {
				return sb.String()
			}
			sb.WriteString(line.Text)
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			timer.Reset(quiet)
		case <-timer.C:
			return sb.String()
		}
	}
}

// TestReconnectResumesFromAckedOffset is the core resume assertion.
func TestReconnectResumesFromAckedOffset(t *testing.T) {
	ex := newTestExecutor(t, nil)
	agentRec := remote.AgentRecord{AgentID: "agent-1", Name: "edge-1"}
	p, sess := connect(t, ex, agentRec, defaultHello(), nil)

	handle := startHandle(t, ex, p)

	// Subscribe before any output is sent, and drain in the background, so
	// the assertion at the end sees the whole reassembled stream rather than
	// racing the chunks as they arrive.
	lines, err := ex.Stream(context.Background(), handle.ID)
	if err != nil {
		t.Fatalf("Stream: %v", err)
	}
	sink := newStreamSink(lines)

	// The workload produces its first output.
	const first = "building step 1\n"
	p.sendLog(handle.ID, 0, first)

	// Wait until the control plane has actually applied that chunk: the
	// resume offset it reports later is only meaningful once it has.
	waitFor(t, 2*time.Second, func() bool { return sink.text() == first },
		"control plane should receive the first chunk")

	// The link drops mid-run. The device keeps working; the control plane
	// keeps the handle.
	sess.Close()
	waitFor(t, 2*time.Second, func() bool { return !ex.Connected() }, "session should detach")

	// The device produced more output while offline. It reconnects and offers
	// the handle with its true total byte count.
	const second = "building step 2\n"
	totalProduced := int64(len(first) + len(second))

	hello := defaultHello()
	hello.Resume = []remote.ResumeHandle{{
		HandleID:  handle.ID,
		StartedAt: handle.StartedAt,
		LogOffset: totalProduced,
	}}

	cpConn, agentConn := remote.NewPipe(64)
	type result struct {
		sess *remote.Session
		err  error
	}
	resCh := make(chan result, 1)
	go func() {
		s, err := remote.Accept(context.Background(), cpConn, remote.AcceptOptions{
			Agent:         agentRec,
			Executor:      ex,
			HeartbeatPoll: 5 * time.Millisecond,
		})
		resCh <- result{s, err}
	}()

	p2 := &peer{t: t, conn: agentConn}
	helloFrame, err := remote.NewFrame(remote.TypeHello, "hello", "", hello)
	if err != nil {
		t.Fatalf("build hello: %v", err)
	}
	p2.write(helloFrame)

	res := <-resCh
	if res.err != nil {
		t.Fatalf("Accept on reconnect: %v", res.err)
	}
	welcomeFrame := p2.readUntil(remote.TypeWelcome)
	welcome, err := remote.DecodeWelcome(welcomeFrame)
	if err != nil {
		t.Fatalf("DecodeWelcome: %v", err)
	}

	if len(welcome.ResumeAccepted) != 1 {
		t.Fatalf("expected 1 accepted resume, got %d", len(welcome.ResumeAccepted))
	}
	ack := welcome.ResumeAccepted[0]
	if ack.HandleID != handle.ID {
		t.Errorf("resumed handle = %q, want %q", ack.HandleID, handle.ID)
	}
	// The critical number: the control plane must ask for exactly the bytes
	// it is missing — not 0 (which would duplicate the prefix) and not
	// totalProduced (which would skip the gap).
	if ack.FromOffset != int64(len(first)) {
		t.Fatalf("resume offset = %d, want %d (the bytes already received)", ack.FromOffset, len(first))
	}

	// The agent resends from the requested offset.
	p2.sendLog(handle.ID, ack.FromOffset, second)

	// Terminating the workload closes the stream so collection is bounded.
	statusFrame, err := remote.NewFrame(remote.TypeStatus, "", handle.ID, remote.StatusPayload{
		Status: executor.Status{
			HandleID: handle.ID,
			State:    executor.StateExited,
			ExitCode: 0,
		},
		FinalOffset: totalProduced,
	})
	if err != nil {
		t.Fatalf("build status: %v", err)
	}
	p2.write(statusFrame)

	// The terminal status closes the stream, which is also the signal that
	// the status has been recorded — so waiting here makes the assertions
	// below deterministic rather than racing frame processing.
	sink.waitClosed(t, 3*time.Second)

	want := first + second
	if got := sink.text(); got != want {
		t.Fatalf("reassembled log mismatch:\n got: %q\nwant: %q", got, want)
	}
	if ex.LogGapped(handle.ID) {
		t.Error("a clean resume must not be reported as gapped")
	}

	st, err := ex.Status(context.Background(), handle.ID)
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if st.State != executor.StateExited {
		t.Errorf("final state = %q, want exited", st.State)
	}
}

// streamSink drains a log stream in the background into a buffer, so a test
// can assert on the accumulated text without racing delivery or consuming
// chunks it still needs.
type streamSink struct {
	mu sync.Mutex
	sb strings.Builder
	// closed fires when the driver closes the stream, which the Executor
	// contract guarantees happens only after the terminal status has been
	// recorded. Waiting on it is therefore the race-free way to ask "has the
	// workload finished?" — polling Status instead would block on a round
	// trip to a peer that is no longer answering.
	closed chan struct{}
}

func newStreamSink(lines <-chan executor.LogLine) *streamSink {
	s := &streamSink{closed: make(chan struct{})}
	go func() {
		defer close(s.closed)
		for line := range lines {
			s.mu.Lock()
			s.sb.WriteString(line.Text)
			s.mu.Unlock()
		}
	}()
	return s
}

// waitClosed blocks until the stream closes.
func (s *streamSink) waitClosed(t *testing.T, timeout time.Duration) {
	t.Helper()
	select {
	case <-s.closed:
	case <-time.After(timeout):
		t.Fatalf("stream did not close within %s; a terminal status should end it", timeout)
	}
}

func (s *streamSink) text() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.sb.String()
}

// TestDuplicateChunksAreIdempotent covers the other half of resume: an agent
// that re-sends bytes the control plane already has (because an ack was lost)
// must not have them appear twice in the log.
func TestDuplicateChunksAreIdempotent(t *testing.T) {
	ex := newTestExecutor(t, nil)
	p, _ := connect(t, ex, remote.AgentRecord{AgentID: "agent-1"}, defaultHello(), nil)
	handle := startHandle(t, ex, p)

	lines, err := ex.Stream(context.Background(), handle.ID)
	if err != nil {
		t.Fatalf("Stream: %v", err)
	}

	const text = "hello world\n"
	p.sendLog(handle.ID, 0, text)
	// Exact duplicate, then an overlapping resend that straddles the boundary.
	p.sendLog(handle.ID, 0, text)
	p.sendLog(handle.ID, int64(len(text)-6), "world\nmore\n")

	statusFrame, err := remote.NewFrame(remote.TypeStatus, "", handle.ID, remote.StatusPayload{
		Status: executor.Status{HandleID: handle.ID, State: executor.StateExited},
	})
	if err != nil {
		t.Fatalf("build status: %v", err)
	}
	p.write(statusFrame)

	got := collect(t, lines, 2*time.Second)
	want := text + "more\n"
	if got != want {
		t.Fatalf("duplicate and overlapping chunks were not deduplicated:\n got: %q\nwant: %q", got, want)
	}
}

// TestGapIsReportedNotHidden checks that unrecoverable loss is surfaced. If
// the agent's retained buffer evicted bytes before the control plane got
// them, the log is genuinely incomplete and a consumer must be able to say so
// rather than presenting a truncated log as whole.
func TestGapIsReportedNotHidden(t *testing.T) {
	ex := newTestExecutor(t, nil)
	p, _ := connect(t, ex, remote.AgentRecord{AgentID: "agent-1"}, defaultHello(), nil)
	handle := startHandle(t, ex, p)

	lines, err := ex.Stream(context.Background(), handle.ID)
	if err != nil {
		t.Fatalf("Stream: %v", err)
	}

	p.sendLog(handle.ID, 0, "start\n")
	// Jump forward: bytes 6..1000 were evicted on the device and are gone.
	p.sendLog(handle.ID, 1000, "end\n")

	statusFrame, err := remote.NewFrame(remote.TypeStatus, "", handle.ID, remote.StatusPayload{
		Status: executor.Status{HandleID: handle.ID, State: executor.StateExited},
	})
	if err != nil {
		t.Fatalf("build status: %v", err)
	}
	p.write(statusFrame)

	got := collect(t, lines, 2*time.Second)
	if got != "start\nend\n" {
		t.Errorf("both received chunks should be delivered, got %q", got)
	}
	if !ex.LogGapped(handle.ID) {
		t.Error("a discontinuity in offsets must be reported as a gap, not silently absorbed")
	}
}

// TestHeartbeatReconcilesForgottenHandles covers the device-reboot case: a
// workload the control plane thinks is running but the agent no longer knows
// about must be resolved rather than left "running" forever, because no
// terminal status will ever arrive for a process the device forgot.
func TestHeartbeatReconcilesForgottenHandles(t *testing.T) {
	ex := newTestExecutor(t, nil)
	p, _ := connect(t, ex, remote.AgentRecord{AgentID: "agent-1"}, defaultHello(), nil)
	handle := startHandle(t, ex, p)

	// Heartbeat reporting no active handles: the device restarted.
	f, err := remote.NewFrame(remote.TypeHeartbeat, "hb", "", remote.HeartbeatPayload{
		Seq:           1,
		ActiveHandles: nil,
	})
	if err != nil {
		t.Fatalf("build heartbeat: %v", err)
	}
	p.write(f)
	p.readUntil(remote.TypeHeartbeatAck)

	waitFor(t, 2*time.Second, func() bool {
		st, err := ex.Status(context.Background(), handle.ID)
		return err == nil && st.State == executor.StateFailed
	}, "a handle the agent no longer reports must be resolved as failed")

	st, _ := ex.Status(context.Background(), handle.ID)
	if !strings.Contains(st.Error, "no longer reports") {
		t.Errorf("failure reason should explain the device lost the process, got %q", st.Error)
	}
}

// TestSmallOutputIsAckedOnHeartbeat pins the buffer-release path for output
// below the byte threshold. Acks are what let the agent drop retained bytes;
// a workload that prints a few lines and then goes quiet would otherwise hold
// them for its entire lifetime, which on a long-running job means the
// retention cap is spent on data the control plane already has.
func TestSmallOutputIsAckedOnHeartbeat(t *testing.T) {
	ex := newTestExecutor(t, nil)
	p, _ := connect(t, ex, remote.AgentRecord{AgentID: "agent-1"}, defaultHello(), nil)
	handle := startHandle(t, ex, p)

	const text = "a few bytes\n"
	p.sendLog(handle.ID, 0, text)

	// A heartbeat flushes acks held below the byte threshold.
	hb, err := remote.NewFrame(remote.TypeHeartbeat, "hb-1", "", remote.HeartbeatPayload{
		Seq:           1,
		ActiveHandles: []string{handle.ID},
	})
	if err != nil {
		t.Fatalf("build heartbeat: %v", err)
	}
	p.write(hb)

	ack := p.readUntil(remote.TypeLogAck)
	if ack.Handle != handle.ID {
		t.Errorf("ack handle = %q, want %q", ack.Handle, handle.ID)
	}
	payload, err := remote.DecodeLogAck(ack)
	if err != nil {
		t.Fatalf("DecodeLogAck: %v", err)
	}
	if payload.Offset != int64(len(text)) {
		t.Errorf("ack offset = %d, want %d", payload.Offset, len(text))
	}
}
