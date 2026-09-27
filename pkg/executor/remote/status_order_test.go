package remote_test

// A terminal status is final. Frames about one handle can reach the control
// plane out of the order the workload lived them in — the agent answers a
// signal from its frame loop while the output pump reports the exit, and a
// start's reply races the exit of a workload that ends at once — and a
// non-terminal status that arrives after the terminal one describes a moment
// that has passed. Applying it anyway reopened a finished handle: Status then
// asked the device about a workload it had already forgotten and reported
// "unknown" for a run that had been stopped (CI, 15f55c9).

import (
	"context"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/executor/remote"
)

// statusFrame builds a status frame from the peer; an empty id makes it an
// unsolicited notification rather than a reply.
func statusFrame(t *testing.T, id, handleID string, state executor.State) remote.Frame {
	t.Helper()
	st := executor.Status{HandleID: handleID, State: state}
	if state.Terminal() {
		st.FinishedAt = time.Now()
	}
	f, err := remote.NewFrame(remote.TypeStatus, id, handleID, remote.StatusPayload{Status: st})
	if err != nil {
		t.Fatalf("build status frame: %v", err)
	}
	return f
}

// statusWithin asks for a handle's status with a bound, so a regression
// shows as the wrong state rather than as a hung test: a reopened handle
// makes Status wait on a device that will never answer.
func statusWithin(t *testing.T, ex *remote.Executor, handleID string) executor.Status {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	st, err := ex.Status(ctx, handleID)
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	return st
}

// TestALateSignalReplyDoesNotReopenAKilledWorkload is the order the agent
// produces when a killed process exits before the signal is answered: the
// pump's terminal status goes out first, then the reply, which the agent
// computed while the output was still draining and so still says "running"
// (workload.draining).
func TestALateSignalReplyDoesNotReopenAKilledWorkload(t *testing.T) {
	ex := newTestExecutor(t, nil)
	p, _ := connect(t, ex, remote.AgentRecord{AgentID: "agent-1"}, defaultHello(), nil)
	handle := startHandle(t, ex, p)

	lines, err := ex.Stream(context.Background(), handle.ID)
	if err != nil {
		t.Fatalf("Stream: %v", err)
	}
	sink := newStreamSink(lines)

	go func() {
		f := p.readUntil(remote.TypeSignal)
		p.write(statusFrame(t, "", f.Handle, executor.StateKilled))
		p.write(statusFrame(t, f.ID, f.Handle, executor.StateRunning))
	}()
	if err := ex.Signal(context.Background(), handle.ID, executor.SignalKill); err != nil {
		t.Fatalf("Signal: %v", err)
	}
	sink.waitClosed(t, 5*time.Second)

	if st := statusWithin(t, ex, handle.ID); st.State != executor.StateKilled {
		t.Errorf("state = %q (%s), want killed: the reply that arrived after the exit reopened the handle",
			st.State, st.Error)
	}
}

// TestAWorkloadThatEndsBeforeStartReturnsStaysEnded: a workload that exits
// at once can report its exit before the start's reply is handled, and the
// start must not then mark it running.
func TestAWorkloadThatEndsBeforeStartReturnsStaysEnded(t *testing.T) {
	ex := newTestExecutor(t, nil)
	p, _ := connect(t, ex, remote.AgentRecord{AgentID: "agent-1"}, defaultHello(), nil)

	go func() {
		f := p.readUntil(remote.TypeStart)
		p.write(statusFrame(t, "", f.Handle, executor.StateExited))
		reply, err := remote.NewFrame(remote.TypeStarted, f.ID, f.Handle, remote.StartedPayload{
			HandleID:  f.Handle,
			PID:       111,
			StartedAt: time.Now(),
		})
		if err != nil {
			t.Errorf("build started frame: %v", err)
			return
		}
		p.write(reply)
	}()
	handle, err := ex.Start(context.Background(), executor.Spec{
		WorkDir: t.TempDir(),
		Argv:    []string{"true"},
	})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}

	if st := statusWithin(t, ex, handle.ID); st.State != executor.StateExited {
		t.Errorf("state = %q (%s), want exited: the start reply marked a finished workload running",
			st.State, st.Error)
	}
}
