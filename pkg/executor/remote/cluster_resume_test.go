package remote_test

// An agent moving between hub processes (Task 20354).
//
// Several `cloop ui` processes may serve one control plane, each building an
// executor for every enrolled agent at startup. An agent is connected to one
// of them at a time, and a reconnect — a network blip, a load balancer
// rebalancing, the member it was on restarting — often lands it on another.
// That member rehydrated its handle map when *it* started, before the run in
// question existed, and used to answer the agent's resume offer from that
// snapshot: ResumeTerminate. The device then killed a healthy run.

import (
	"testing"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/executor/remote"
)

func TestAgentMovingToAnotherHubMemberKeepsItsRun(t *testing.T) {
	store := executor.NewMemoryHandleStore()
	// Both members are up before the run starts, as in a live cluster.
	memberA := newStoredExecutor(t, store)
	memberB := newStoredExecutor(t, store)

	// The agent is connected to A, and A dispatches.
	p, sess := connect(t, memberA, remote.AgentRecord{AgentID: "agent-1"}, defaultHello(), nil)
	handle := startHandle(t, memberA, p)
	if store.Len() != 1 {
		t.Fatalf("the dispatch persisted %d rows, want 1", store.Len())
	}

	// The link to A drops; the agent reconnects — to B — still running it.
	sess.Close()
	connectWithWelcome(t, memberB, remote.AgentRecord{AgentID: "agent-1"},
		helloOffering(remote.ProtocolVersion, handle.ID, 1024), func(w remote.WelcomePayload) {
			if len(w.ResumeAccepted) != 1 {
				t.Fatalf("expected 1 resume verdict, got %d", len(w.ResumeAccepted))
			}
			if got := w.ResumeAccepted[0].Effective(); got != remote.ResumeContinue {
				t.Fatalf("B answered %q to a run another member dispatched; the device "+
					"would terminate a healthy run", got)
			}
		})
	tracked := false
	for _, id := range memberB.Handles() {
		if id == handle.ID {
			tracked = true
		}
	}
	if !tracked {
		t.Fatal("B does not track the run it just accepted")
	}
}
