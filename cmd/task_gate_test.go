package cmd

// `cloop task gate` and the gate-aware task commands (Task 20477).

import (
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

func cliQueue(t *testing.T, dir string) []int {
	t.Helper()
	ps, err := state.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	var out []int
	for _, task := range ps.Plan.Queue() {
		out = append(out, task.ID)
	}
	return out
}

func cliTask(t *testing.T, dir string, id int) *pm.Task {
	t.Helper()
	ps, err := state.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	return ps.Plan.TaskByID(id)
}

func sameInts(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestTaskGateCommands(t *testing.T) {
	// This suite may itself run inside a cloop task, whose environment names
	// the task: the approvals below are a person's.
	t.Setenv("CLOOP_TASK_ID", "")
	exe := cliSelfExe(t)
	dir := reqTestProject(t)
	ps, err := state.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	ps.PMMode = true
	ps.Plan = &pm.Plan{Goal: ps.Goal, Tasks: []*pm.Task{
		{ID: 1, Title: "one", Priority: 2, Status: pm.TaskPending},
		{ID: 2, Title: "two", Priority: 2, Status: pm.TaskPending},
		{ID: 3, Title: "three", Priority: 2, Status: pm.TaskPending},
	}}
	if err := ps.Save(); err != nil {
		t.Fatal(err)
	}

	out := mustRun(t, exe, dir, "task", "gate", "add", "--after", "1", "--title", "Check the parser", "--note", "grammar first")
	if !strings.Contains(out, "Added review gate #4") || !strings.Contains(out, "2 queued task(s) wait behind it") {
		t.Errorf("gate add said:\n%s", out)
	}
	if got := cliQueue(t, dir); !sameInts(got, []int{1, 4, 2, 3}) {
		t.Fatalf("queue = %v, want [1 4 2 3]", got)
	}
	if out := mustRun(t, exe, dir, "task", "list"); !strings.Contains(out, "#4 [P2] Check the parser — the run stops here (review gate)") {
		t.Errorf("task list does not show the gate where it stands:\n%s", out)
	}

	// Moved like any task, past a task of equal priority.
	mustRun(t, exe, dir, "task", "move", "4", "down")
	if got := cliQueue(t, dir); !sameInts(got, []int{1, 2, 4, 3}) {
		t.Fatalf("queue after moving the gate down = %v, want [1 2 4 3]", got)
	}

	if out, err := runHelper(t, exe, dir, "task", "fail", "4"); err == nil || !strings.Contains(string(out), "never failed") {
		t.Errorf("task fail on a gate: %v\n%s", err, out)
	}
	mustRun(t, exe, dir, "task", "done", "1")
	mustRun(t, exe, dir, "task", "done", "2")
	if out := mustRun(t, exe, dir, "task", "next"); !strings.Contains(out, "Waiting for review at gate #4") {
		t.Errorf("task next with the gate reached:\n%s", out)
	}

	// Not from inside a task's run.
	t.Setenv("CLOOP_TASK_ID", "7")
	for _, args := range [][]string{{"task", "gate", "approve", "4"}, {"task", "approve", "4"}, {"task", "done", "4"}} {
		if out, err := runHelper(t, exe, dir, args...); err == nil || !strings.Contains(string(out), "inside a task's run") {
			t.Errorf("cloop %s inside a run: %v\n%s", strings.Join(args, " "), err, out)
		}
	}
	if g := cliTask(t, dir, 4); !g.GateClosed() {
		t.Fatal("a refused approval opened the gate")
	}
	t.Setenv("CLOOP_TASK_ID", "")

	if out := mustRun(t, exe, dir, "task", "gate", "approve", "4"); !strings.Contains(out, "Review gate #4 approved") {
		t.Errorf("gate approve said:\n%s", out)
	}
	if g := cliTask(t, dir, 4); !g.Approved || g.Status != pm.TaskDone {
		t.Fatalf("approved gate = %+v", g)
	}
	if out := mustRun(t, exe, dir, "task", "next"); !strings.Contains(out, "Next task: #3") {
		t.Errorf("task next after the approval:\n%s", out)
	}
	db, err := statedb.Open(state.DBPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	evs, _, err := db.ListAuditEvents(statedb.AuditFilter{EventType: "task.gate_approve"})
	db.Close()
	if err != nil || len(evs) != 1 || !strings.Contains(evs[0].Payload, "cloop task gate approve") {
		t.Errorf("audit rows = %+v, %v", evs, err)
	}

	mustRun(t, exe, dir, "task", "gate", "reopen", "4")
	if g := cliTask(t, dir, 4); !g.GateClosed() || g.Approved {
		t.Fatalf("reopened gate = %+v", g)
	}
	// The older verbs work on a gate too.
	mustRun(t, exe, dir, "task", "approve", "4")
	if g := cliTask(t, dir, 4); !g.Approved {
		t.Fatalf("task approve did not approve the gate: %+v", g)
	}
	mustRun(t, exe, dir, "task", "approve", "4", "--revoke")
	if g := cliTask(t, dir, 4); !g.GateClosed() {
		t.Fatalf("task approve --revoke did not close the gate: %+v", g)
	}
	if out, err := runHelper(t, exe, dir, "task", "gate", "approve", "3"); err == nil || !strings.Contains(string(out), "not a review gate") {
		t.Errorf("gate approve on a task: %v\n%s", err, out)
	}
	if out, err := runHelper(t, exe, dir, "task", "gate", "add", "--before", "1"); err == nil || !strings.Contains(string(out), "nothing can be placed before it") {
		t.Errorf("a gate before a finished task: %v\n%s", err, out)
	}

	// Bulk edits follow the same rules: a status no gate takes refuses the
	// whole command before anything changes, and done approves the gate.
	if out, err := runHelper(t, exe, dir, "task", "bulk", "fail", "3", "4"); err == nil || !strings.Contains(string(out), "human review gate") {
		t.Errorf("bulk fail over a gate: %v\n%s", err, out)
	}
	if task := cliTask(t, dir, 3); task.Status != pm.TaskPending {
		t.Fatalf("a refused bulk edit changed task 3 to %s", task.Status)
	}
	mustRun(t, exe, dir, "task", "bulk", "done", "4")
	if g := cliTask(t, dir, 4); !g.Approved || g.Status != pm.TaskDone {
		t.Fatalf("bulk done did not approve the gate: %+v", g)
	}
}
