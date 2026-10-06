package orchestrator

// A task quarantined as a suspected node killer (Task 20391) runs again only
// after an explicit reset: --retry-failed leaves it failed, and the gate holds
// it even when something else set it pending.

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/provider"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

func nodeKillerMark() *pm.TaskQuarantine {
	at := time.Date(2026, 10, 6, 12, 0, 0, 0, time.UTC)
	return &pm.TaskQuarantine{Kind: pm.QuarantineNodeKiller, MarkedAt: at, Nodes: []pm.NodeLoss{
		{ExecutorID: "sgx", LostAt: at, SessionID: "s1"},
		{ExecutorID: "edge-2", LostAt: at.Add(time.Minute), SessionID: "s2"},
	}}
}

func TestGateTasks_HoldsAQuarantinedTask(t *testing.T) {
	killer := &pm.Task{ID: 1, Priority: 1, Status: pm.TaskPending, Quarantine: nodeKillerMark()}
	other := &pm.Task{ID: 2, Priority: 2, Status: pm.TaskPending}
	plan := &pm.Plan{Tasks: []*pm.Task{killer, other}}

	for _, parallel := range []bool{false, true} {
		d := GateTasks(context.Background(), plan, GateConfig{Parallel: parallel, EvalCondition: proceedAlways})
		if ids := taskIDs(d.Runnable); len(ids) != 1 || ids[0] != 2 {
			t.Fatalf("parallel=%v: runnable %v, want only task 2 — the quarantined task 1 outranks it and must still not run", parallel, ids)
		}
		var held bool
		for _, e := range d.Events {
			if e.Kind == GateHoldQuarantined && e.Task.ID == 1 {
				held = true
				if !strings.Contains(e.Line, "sgx") || !strings.Contains(e.Line, "cloop task reset 1") {
					t.Errorf("the hold line %q does not name the nodes and the way out", e.Line)
				}
			}
		}
		if !held {
			t.Errorf("parallel=%v: no hold event for the quarantined task", parallel)
		}
		if killer.Status != pm.TaskPending {
			t.Fatalf("the gate changed the held task's status to %s", killer.Status)
		}
	}

	// With nothing else left, the gate reports the plan exhausted: a held
	// task must end the loop, not spin it.
	other.Status = pm.TaskDone
	d := GateTasks(context.Background(), plan, GateConfig{EvalCondition: proceedAlways})
	if len(d.Runnable) != 0 || !d.Exhausted {
		t.Fatalf("runnable %v, exhausted %v; want nothing to run and the loop to end", taskIDs(d.Runnable), d.Exhausted)
	}
}

// TestRunPM_RetryFailedLeavesASuspectedNodeKillerFailed: --retry-failed is the
// automatic reset that must not release a suspected node killer.
func TestRunPM_RetryFailedLeavesASuspectedNodeKillerFailed(t *testing.T) {
	for _, parallel := range []bool{false, true} {
		dir := tempDir(t)
		s := initState(t, dir, "goal", 0)
		s.PMMode = true
		s.Plan = &pm.Plan{Goal: "goal", Tasks: []*pm.Task{
			{ID: 1, Title: "fork bomb", Priority: 1, Status: pm.TaskFailed},
			{ID: 2, Title: "flaky", Priority: 2, Status: pm.TaskFailed},
		}}
		if err := s.Save(); err != nil {
			t.Fatal(err)
		}
		db, err := statedb.Open(state.DBPath(dir))
		if err != nil {
			t.Fatal(err)
		}
		if err := db.PutTaskQuarantine(1, *nodeKillerMark()); err != nil {
			t.Fatal(err)
		}
		db.Close()

		prov := &mockProvider{name: "mock", results: []*provider.Result{
			{Output: "retried and done\nTASK_DONE", Provider: "mock"},
			{Output: "must not run\nTASK_DONE", Provider: "mock"},
		}}
		o := newOrchestrator(t, dir, Config{WorkDir: dir, PMMode: true, RetryFailed: true, Parallel: parallel, MaxParallel: 2}, prov)
		o.runPM(context.Background())

		killer, flaky := o.state.Plan.TaskByID(1), o.state.Plan.TaskByID(2)
		if flaky.Status != pm.TaskDone {
			t.Errorf("parallel=%v: the ordinary failed task is %s, want retried and done", parallel, flaky.Status)
		}
		if killer.Status != pm.TaskFailed {
			t.Errorf("parallel=%v: the suspected node killer is %s, want still failed", parallel, killer.Status)
		}
		if prov.calls != 1 {
			t.Errorf("parallel=%v: %d provider calls, want 1 — the quarantined task was run", parallel, prov.calls)
		}
	}
}
