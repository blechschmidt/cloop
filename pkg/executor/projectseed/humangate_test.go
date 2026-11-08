package projectseed

import (
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/state"
)

// A human review gate is opened by a person, never by a run (Task 20477). A
// device whose cloop predates gates runs one as a task and reports it done; a
// compromised one could report any gate it liked passed. Either way the hub
// keeps its own copy closed. The one outcome a run may report is passing a gate
// the hub's copy says was approved.
func TestMergeNeverOpensAGateTheHubDidNotApprove(t *testing.T) {
	now := time.Now().UTC()
	gate := func(approved bool) *pm.Task {
		g := pm.NewHumanGate("Check the parser", "")
		g.ID, g.Priority, g.Approved = 3, 3, approved
		return g
	}
	passed := func() TaskChange {
		before := gate(false)
		after := gate(false)
		after.Status, after.Result, after.CompletedAt = pm.TaskDone, "reviewed it myself", ptrTime(now)
		return TaskChange{Before: before, After: after}
	}

	st := &state.ProjectState{Plan: &pm.Plan{Tasks: []*pm.Task{gate(false)}}}
	rep, _ := Merge(st, &Result{Format: 1, Tasks: []TaskChange{passed()}}, Provenance{}, nil, now)
	if g := st.Plan.TaskByID(3); g.Status != pm.TaskPending || g.Result != "" || !g.GateClosed() {
		t.Fatalf("a run opened a gate nobody approved: %+v", g)
	}
	if len(rep.Kept) != 1 || !strings.Contains(rep.Kept[0], "human review gate") {
		t.Errorf("kept = %v, want the refusal named", rep.Kept)
	}

	for _, s := range []pm.TaskStatus{pm.TaskFailed, pm.TaskSkipped, pm.TaskInProgress} {
		tc := passed()
		tc.After.Status = s
		st := &state.ProjectState{Plan: &pm.Plan{Tasks: []*pm.Task{gate(true)}}}
		Merge(st, &Result{Format: 1, Tasks: []TaskChange{tc}}, Provenance{}, nil, now)
		if g := st.Plan.TaskByID(3); g.Status != pm.TaskPending {
			t.Errorf("a run's %s reached an approved gate: %s", s, g.Status)
		}
	}

	// Approved on the hub: the run recorded going past it, and that stands.
	st = &state.ProjectState{Plan: &pm.Plan{Tasks: []*pm.Task{gate(true)}}}
	rep, _ = Merge(st, &Result{Format: 1, Tasks: []TaskChange{passed()}}, Provenance{}, nil, now)
	if g := st.Plan.TaskByID(3); g.Status != pm.TaskDone {
		t.Fatalf("an approved gate the run passed = %s, want done", g.Status)
	}
	if len(rep.Kept) != 0 {
		t.Errorf("kept = %v", rep.Kept)
	}
}
