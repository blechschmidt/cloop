package remote_test

// Abandon (Task 20396): the hub failed a workload's session over to another
// executor while its device was out of reach. The workload is no longer its
// project's run, and must not come back as one.

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/executor/remote"
)

// TestAbandonedWorkloadIsTerminatedWhenItsDeviceComesBack: a device drops off
// mid-run and the hub gives the workload up. Its stream closes at once, so
// every watcher on the hub lets go of it; its status names why; its durable
// row is forgotten, so a restarted hub does not rehydrate it; and when the
// device reconnects offering to resume it, it is told to terminate it rather
// than run on beside its replacement.
func TestAbandonedWorkloadIsTerminatedWhenItsDeviceComesBack(t *testing.T) {
	store := executor.NewMemoryHandleStore()
	ex := newStoredExecutor(t, store)
	agent := remote.AgentRecord{AgentID: "agent-1"}
	p, sess := connect(t, ex, agent, defaultHello(), nil)
	handle := startHandle(t, ex, p)
	lines, err := ex.Stream(context.Background(), handle.ID)
	if err != nil {
		t.Fatal(err)
	}
	sink := newStreamSink(lines)
	if store.Len() != 1 {
		t.Fatalf("the running workload has %d durable rows, want 1", store.Len())
	}

	// The device drops off; the hub cannot tell whether it is dead.
	sess.Close()
	waitFor(t, 2*time.Second, func() bool { return !ex.Connected() }, "the session should detach")
	if st, err := ex.Status(context.Background(), handle.ID); err != nil || st.State != executor.StateUnknown {
		t.Fatalf("a run whose device dropped off = %q, %v; want unknown", st.State, err)
	}

	// The supervisor failed its session over; the hub gives it up.
	const why = "its executor agent-1 stopped answering; the run failed over to edge-2"
	if err := ex.Abandon(context.Background(), handle.ID, why); err != nil {
		t.Fatalf("Abandon with the device away: %v", err)
	}
	sink.waitClosed(t, 2*time.Second)
	st, err := ex.Status(context.Background(), handle.ID)
	if err != nil || st.State != executor.StateFailed || !strings.Contains(st.Error, why) {
		t.Fatalf("the abandoned workload = %+v, %v; want failed, saying why", st, err)
	}
	waitFor(t, 2*time.Second, func() bool { return store.Len() == 0 },
		"an abandoned workload's durable row must be forgotten")
	// A second word changes nothing.
	if err := ex.Abandon(context.Background(), handle.ID, "again"); err != nil {
		t.Fatalf("a second Abandon: %v", err)
	}

	// The device comes back offering the workload.
	connectWithWelcome(t, ex, agent, helloOffering(remote.ProtocolVersion, handle.ID, 0), func(w remote.WelcomePayload) {
		if len(w.ResumeAccepted) != 1 {
			t.Fatalf("the offer got %d verdicts, want 1", len(w.ResumeAccepted))
		}
		ack := w.ResumeAccepted[0]
		if ack.HandleID != handle.ID || ack.Effective() != remote.ResumeTerminate {
			t.Fatalf("the abandoned workload was answered %+v, want terminate", ack)
		}
		if !strings.Contains(ack.Reason, "failed over to edge-2") {
			t.Errorf("the device is told %q; it should be told why", ack.Reason)
		}
	})
}

// TestAbandonKillsAWorkloadTheAgentCanStillHear: a device whose session is
// still up — failed over all the same, say because its probes timed out —
// is told to kill the workload before the handle is given up.
func TestAbandonKillsAWorkloadTheAgentCanStillHear(t *testing.T) {
	ex := newTestExecutor(t, nil)
	p, _ := connect(t, ex, remote.AgentRecord{AgentID: "agent-1"}, defaultHello(), nil)
	handle := startHandle(t, ex, p)

	killed := make(chan executor.Signal, 1)
	go func() {
		f := p.readUntil(remote.TypeSignal)
		payload, err := remote.DecodeSignal(f)
		if err != nil {
			t.Errorf("DecodeSignal: %v", err)
			return
		}
		killed <- payload.Signal
		reply, err := remote.NewFrame(remote.TypeStatus, f.ID, f.Handle, remote.StatusPayload{
			Status: executor.Status{HandleID: f.Handle, State: executor.StateRunning},
		})
		if err != nil {
			return
		}
		p.write(reply)
	}()

	if err := ex.Abandon(context.Background(), handle.ID, "failed over"); err != nil {
		t.Fatalf("Abandon: %v", err)
	}
	select {
	case sig := <-killed:
		if sig != executor.SignalKill {
			t.Fatalf("the agent was sent %q, want kill", sig)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the agent was never told to kill the workload")
	}
	if st, err := ex.Status(context.Background(), handle.ID); err != nil || st.State != executor.StateFailed {
		t.Fatalf("the abandoned workload = %+v, %v; want failed", st, err)
	}
}
