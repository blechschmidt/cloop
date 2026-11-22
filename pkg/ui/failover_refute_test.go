package ui

// A failover claim the member following the run can disprove does not end the
// run (Task 20512).
//
// On the host that found this, an older hub build served the same database
// outside the cluster. Holding no session to the edge agent, its supervisor
// found the agent unreachable whenever its probes ran out and claimed the
// session of the run on it; the member that held the agent's session read the
// claim from the store five minutes later and gave the run up — it killed a
// healthy workload and paused its project, four times in three hours on one
// device. These tests make that claim the way that process did, straight into
// the session store, and sweep.

import (
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/executorstore"
	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// claimFromOutside claims the session of the workload handle on node as a
// supervisor in another process would, at at: the session store is all such a
// process shares with this one.
func claimFromOutside(t *testing.T, r *trackRig, node *seedNode, handle string, at time.Time) statedb.ExecutorSessionRow {
	t.Helper()
	row, ok, err := r.db.ExecutorSessionForHandle(node.id, handle)
	if err != nil || !ok {
		t.Fatalf("no session recorded for %s on %s: %v", handle, node.id, err)
	}
	if _, _, err := r.sched.ClaimRequeue(row.ID, row.ClaimToken, 2, at); err != nil {
		t.Fatalf("claim %s: %v", row.ID, err)
	}
	return row
}

// TestAClaimTheAgentContradictsDoesNotEndTheRun: the agent holding the run is
// connected to this member and says the workload is running, so a claim
// nothing replaced is undone — the run is still followed and never signalled,
// its session is running again, the refutation is on the audit trail, and the
// project is not paused. The run then ends as any run does.
func TestAClaimTheAgentContradictsDoesNotEndTheRun(t *testing.T) {
	r := newTrackRig(t, 1, []*pm.Task{{ID: 1, Title: "long", Status: pm.TaskPending}})
	node := r.nodes[0]
	node.setKind(executor.KindRemoteAgent)
	h := r.dispatch(t)
	node.say(t, h, "━━━ Task 1/1: long ━━━")

	// Claimed long enough ago that no replacement is on its way: the moment
	// the member used to give the run up.
	sess := claimFromOutside(t, r, node, h, time.Now().Add(-2*failoverReplacementWindow))

	// The liveness question already asks the agent: the project executes.
	if !r.srv.projectExecuting(r.dir) {
		t.Fatal("a run whose agent says it is running reads as not executing after an outside claim")
	}
	r.srv.sweepLostRuns(time.Now())

	if exID, got, ok := r.tracked(); !ok || exID != node.id || got != h {
		t.Fatalf("the hub follows %s/%s (%v) after the sweep, want the run it was following", exID, got, ok)
	}
	w, _ := node.workload(h)
	if w == nil || w.abandoned != "" || len(w.signals) != 0 || w.ended {
		t.Fatalf("the workload was disturbed: %+v", w)
	}
	row, ok, err := r.db.ExecutorSessionForHandle(node.id, h)
	if err != nil || !ok || row.State != statedb.ExecutorSessionRunning || !row.EndedAt.IsZero() {
		t.Fatalf("the session = %+v, %v, %v; want running again", row, ok, err)
	}
	rows, _, err := r.db.ListAuditEvents(statedb.AuditFilter{EventType: "executor.failover_refuted", EntityID: sess.ID})
	if err != nil || len(rows) != 1 {
		t.Fatalf("refutation rows for %s = %d, %v; want one", sess.ID, len(rows), err)
	}
	if !strings.Contains(rows[0].Payload, `"claimed":"requeued"`) || !strings.Contains(rows[0].Payload, node.id) {
		t.Errorf("the refutation row does not say what was claimed on which executor: %s", rows[0].Payload)
	}
	st, err := state.LoadLite(r.dir)
	if err != nil {
		t.Fatal(err)
	}
	if st.PauseReason != nil && st.PauseReason.Code == "executor_lost" {
		t.Fatalf("the project was paused executor_lost under a run its agent says is running: %+v", st.PauseReason)
	}
	if r.journalSays(t, state.EventSessionFailed, "stopped answering") {
		t.Fatal("the event history says the executor stopped answering")
	}

	// A second sweep finds nothing to do: the session is not claimed.
	r.srv.sweepLostRuns(time.Now())
	if rows, _, _ := r.db.ListAuditEvents(statedb.AuditFilter{EventType: "executor.failover_refuted"}); len(rows) != 1 {
		t.Fatalf("a sweep over an unclaimed session refuted again (%d rows)", len(rows))
	}

	// And the run ends as runs do: what the device did is merged.
	node.complete(t, h, func(st *state.ProjectState) {
		st.Plan.TaskByID(1).Status = pm.TaskDone
		st.Status = "complete"
	})
	r.waitUntil(t, "the run to be settled", func() bool {
		_, _, ok := r.tracked()
		return !ok
	})
	if task := r.task(t, 1); task.Status != pm.TaskDone {
		t.Fatalf("task 1 is %s after the run finished it", task.Status)
	}
}

// TestConcurrentRefutationsAgree: the sweep and the liveness question can
// refute the same claim at once. Every one of them sees the run kept — the
// one that loses the restore must not read that as the claim standing and
// give the run up — and the session is restored and audited once.
func TestConcurrentRefutationsAgree(t *testing.T) {
	r := newTrackRig(t, 1, []*pm.Task{{ID: 1, Title: "long", Status: pm.TaskPending}})
	node := r.nodes[0]
	node.setKind(executor.KindRemoteAgent)
	h := r.dispatch(t)
	node.say(t, h, "━━━ Task 1/1: long ━━━")
	run := mustTracked(t, r)
	sess := claimFromOutside(t, r, node, h, time.Now().Add(-2*failoverReplacementWindow))
	loss := mustLoss(t, r, node, h)

	results := make([]bool, 8)
	var wg sync.WaitGroup
	for i := range results {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			results[i] = r.srv.refuteLostRunClaim(run, loss)
		}(i)
	}
	wg.Wait()
	for i, kept := range results {
		if !kept {
			t.Fatalf("refutation %d of %d read the claim as standing", i+1, len(results))
		}
	}
	rows, _, err := r.db.ListAuditEvents(statedb.AuditFilter{EventType: "executor.failover_refuted", EntityID: sess.ID})
	if err != nil || len(rows) != 1 {
		t.Fatalf("refutation rows = %d, %v; want exactly one", len(rows), err)
	}
	if row, _, _ := r.db.ExecutorSessionForHandle(node.id, h); row.State != statedb.ExecutorSessionRunning {
		t.Fatalf("the session is %q, want running", row.State)
	}
}

// TestAClaimStandsWithoutTheAgentsWord: the claim is undone only on the
// agent's own word. A device that is not answering, an executor whose
// liveness any member can probe, a workload the device no longer runs, or a
// claim a replacement followed — each leaves the claim standing, and the run
// is given up as before.
func TestAClaimStandsWithoutTheAgentsWord(t *testing.T) {
	for _, tc := range []struct {
		name  string
		kind  string
		setup func(t *testing.T, r *trackRig, h string)
	}{
		{
			name:  "the device is not answering",
			kind:  executor.KindRemoteAgent,
			setup: func(t *testing.T, r *trackRig, h string) { r.nodes[0].kill() },
		},
		{
			name: "not an edge agent",
			kind: executor.KindContainer,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newTrackRig(t, 1, []*pm.Task{{ID: 1, Title: "long", Status: pm.TaskPending}})
			node := r.nodes[0]
			node.setKind(tc.kind)
			h := r.dispatch(t)
			node.say(t, h, "━━━ Task 1/1: long ━━━")
			if tc.setup != nil {
				tc.setup(t, r, h)
			}
			sess := claimFromOutside(t, r, node, h, time.Now().Add(-2*failoverReplacementWindow))

			r.srv.sweepLostRuns(time.Now())

			if _, _, ok := r.tracked(); ok {
				t.Fatal("the hub still follows a run whose claim nothing contradicts")
			}
			if w, _ := node.workload(h); w == nil || w.abandoned == "" {
				t.Fatal("the claimed run was not given up")
			}
			row, _, err := r.db.ExecutorSessionForHandle(node.id, h)
			if err != nil || row.State != statedb.ExecutorSessionRequeued {
				t.Fatalf("the session = %+v, %v; want the claim standing", row, err)
			}
			if rows, _, _ := r.db.ListAuditEvents(statedb.AuditFilter{EventType: "executor.failover_refuted", EntityID: sess.ID}); len(rows) != 0 {
				t.Fatalf("a claim nothing contradicts was refuted: %+v", rows)
			}
			st, err := state.LoadLite(r.dir)
			if err != nil {
				t.Fatal(err)
			}
			if st.PauseReason == nil || st.PauseReason.Code != "executor_lost" {
				t.Fatalf("the project is %q with reason %+v, want paused executor_lost", st.Status, st.PauseReason)
			}
		})
	}

	t.Run("a replacement followed the claim", func(t *testing.T) {
		r := newTrackRig(t, 1, []*pm.Task{{ID: 1, Title: "long", Status: pm.TaskPending}})
		node := r.nodes[0]
		node.setKind(executor.KindRemoteAgent)
		h := r.dispatch(t)
		node.say(t, h, "━━━ Task 1/1: long ━━━")
		sess := claimFromOutside(t, r, node, h, time.Now().Add(-2*failoverReplacementWindow))
		// The replacement the claimer recorded, on an executor this member
		// does not follow.
		next := executor.Session{ID: sess.ID + "-next", ExecutorID: "elsewhere", HandleID: "h-elsewhere",
			ProjectPath: r.dir, ClaimToken: "tok-next", Attempt: 2, StartedAt: time.Now(),
			Spec: executor.Spec{WorkDir: r.dir, Argv: []string{"cloop", "run"}}}
		if err := r.sched.OpenRequeuedSession(next, sess.ID); err != nil {
			t.Fatal(err)
		}

		if r.srv.refuteLostRunClaim(mustTracked(t, r), mustLoss(t, r, node, h)) {
			t.Fatal("a claim a replacement followed was refuted")
		}
		row, _, err := r.db.ExecutorSessionForHandle(node.id, h)
		if err != nil || row.State != statedb.ExecutorSessionRequeued {
			t.Fatalf("the replaced session = %+v, %v; want the claim standing", row, err)
		}
		// The member lets go once the replacement's member has had its
		// window to take the run over, as before.
		r.srv.sweepLostRuns(time.Now().Add(2 * failoverReplacementWindow))
		if _, _, ok := r.tracked(); ok {
			t.Fatal("the hub still follows a run a failover replaced")
		}
	})

	t.Run("the device no longer runs the workload", func(t *testing.T) {
		r := newTrackRig(t, 1, []*pm.Task{{ID: 1, Title: "long", Status: pm.TaskPending}})
		node := r.nodes[0]
		node.setKind(executor.KindRemoteAgent)
		h := r.dispatch(t)
		node.say(t, h, "━━━ Task 1/1: long ━━━")
		run := mustTracked(t, r)
		claimFromOutside(t, r, node, h, time.Now().Add(-2*failoverReplacementWindow))
		// Ended on the device; its stream's end has not been acted on yet.
		node.mu.Lock()
		w := node.workloads[h]
		w.state, w.exitCode = executor.StateFailed, 1
		node.mu.Unlock()
		if r.srv.refuteLostRunClaim(run, mustLoss(t, r, node, h)) {
			t.Fatal("a claim on a workload the device says ended was refuted")
		}
		node.finish(h, executor.StateFailed, 1, "", nil)
	})
}

// mustTracked is the run r's hub follows.
func mustTracked(t *testing.T, r *trackRig) dispatchedRun {
	t.Helper()
	run, ok := r.srv.trackedRun(r.dir)
	if !ok {
		t.Fatal("the hub follows no run")
	}
	return run
}

// mustLoss is what the session store says about handle on node.
func mustLoss(t *testing.T, r *trackRig, node *seedNode, handle string) executorstore.HandleLoss {
	t.Helper()
	loss, ok := lossOfHandle(r.dir, node.id, handle)
	if !ok {
		t.Fatalf("the session store has no answer for %s on %s", handle, node.id)
	}
	return loss
}
