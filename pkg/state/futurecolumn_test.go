package state

// Every save path keeps the columns this binary does not know (Task 20388).
//
// statedb.SaveState used to empty plan_tasks and insert the plan again, so a
// binary one migration behind reset that migration's columns on every save:
// the long-lived run on this deployment, a build that knows migrations up to
// 0053, erased the thirteen task columns 0054 added each time it saved. The
// tests below add a column no build knows, set it in every task, and save the
// way each caller in this package does — an edit and a deletion through
// SaveDirect, a run's save through Save, which first merges what another
// process added — and check the column is still there, and that a deleted
// task is still gone.

import (
	"strconv"
	"testing"

	"github.com/blechschmidt/cloop/internal/statedbtest"
	"github.com/blechschmidt/cloop/pkg/pm"
)

// futureProject is planProject with four tasks, each holding "kept by <id>"
// in a column a newer build added.
func futureProject(t *testing.T) (dir, dbPath string) {
	t.Helper()
	dir = statedbtest.Dir(t)
	s, err := Init(dir, "goal", 0)
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	s.PMMode = true
	s.Plan = &pm.Plan{Goal: "goal", Tasks: []*pm.Task{
		{ID: 1, Title: "build", Priority: 1, Status: pm.TaskPending},
		{ID: 2, Title: "test", Priority: 2, Status: pm.TaskPending},
		{ID: 3, Title: "ship", Priority: 3, Status: pm.TaskPending},
		{ID: 4, Title: "announce", Priority: 4, Status: pm.TaskPending},
	}}
	if err := s.Save(); err != nil {
		t.Fatalf("Save: %v", err)
	}
	dbPath = DBPath(dir)
	statedbtest.AddFutureColumn(t, dbPath, "plan_tasks", `'kept by ' || id`)
	return dir, dbPath
}

func keptBy(ids ...int) map[string]string {
	out := map[string]string{}
	for _, id := range ids {
		out[strconv.Itoa(id)] = "kept by " + strconv.Itoa(id)
	}
	return out
}

func wantTaskFutureValues(t *testing.T, dbPath, after string, want map[string]string) {
	t.Helper()
	statedbtest.WantFutureValues(t, dbPath, "plan_tasks", "id", after, want)
}

func TestSaveDirectEditKeepsColumnsItDoesNotKnow(t *testing.T) {
	dir, dbPath := futureProject(t)

	ui := mustLoad(t, dir)
	ui.Plan.TaskByID(2).Description = "with the race detector"
	ui.Plan.TaskByID(2).Priority = 9
	if err := ui.SaveDirect(); err != nil {
		t.Fatalf("SaveDirect: %v", err)
	}
	wantTaskFutureValues(t, dbPath, "an edit", keptBy(1, 2, 3, 4))
	if got := mustLoad(t, dir).Plan.TaskByID(2); got.Description != "with the race detector" || got.Priority != 9 {
		t.Errorf("task 2 = %q priority %d; the edit itself was not stored", got.Description, got.Priority)
	}
}

func TestSaveDirectDeletionKeepsColumnsItDoesNotKnow(t *testing.T) {
	dir, dbPath := futureProject(t)

	ui := mustLoad(t, dir)
	tasks := ui.Plan.Tasks[:0]
	for _, task := range ui.Plan.Tasks {
		if task.ID != 3 {
			tasks = append(tasks, task)
		}
	}
	ui.Plan.Tasks = tasks
	if err := ui.SaveDirect(); err != nil {
		t.Fatalf("SaveDirect: %v", err)
	}
	wantTaskFutureValues(t, dbPath, "a deletion", keptBy(1, 2, 4))
	if mustLoad(t, dir).Plan.TaskByID(3) != nil {
		t.Error("task 3 came back after it was deleted")
	}
}

// TestSaveMergeKeepsColumnsItDoesNotKnow is a run's save while another process
// adds a task: the run holds tasks 1–4, the dashboard adds task 5, and a newer
// build sets its column. The run's Save merges task 5 in and writes the plan.
func TestSaveMergeKeepsColumnsItDoesNotKnow(t *testing.T) {
	dir, dbPath := futureProject(t)
	run := mustLoad(t, dir)

	ui := mustLoad(t, dir)
	ui.Plan.Tasks = append(ui.Plan.Tasks, &pm.Task{ID: 5, Title: "added from the dashboard", Priority: 5, Status: pm.TaskPending})
	if err := ui.SaveDirect(); err != nil {
		t.Fatalf("the dashboard's SaveDirect: %v", err)
	}
	statedbtest.SetFutureValue(t, dbPath, "plan_tasks", `'kept by ' || id`, `id = 5`)

	run.Plan.TaskByID(1).Status = pm.TaskDone
	run.Plan.TaskByID(1).Result = "built"
	if err := run.Save(); err != nil {
		t.Fatalf("the run's Save: %v", err)
	}
	wantTaskFutureValues(t, dbPath, "a merging save", keptBy(1, 2, 3, 4, 5))

	after := mustLoad(t, dir)
	if got := after.Plan.TaskByID(1); got.Status != pm.TaskDone || got.Result != "built" {
		t.Errorf("task 1 = %s %q; the run's own change was not stored", got.Status, got.Result)
	}
	if after.Plan.TaskByID(5) == nil {
		t.Error("the externally added task 5 was lost by the run's save")
	}
}

// TestSyncThenSaveKeepsColumnsItDoesNotKnow is the read side followed by the
// write side, as the orchestrator does between tasks: a reorder from the
// dashboard is adopted at the sync and written back by the next save.
func TestSyncThenSaveKeepsColumnsItDoesNotKnow(t *testing.T) {
	dir, dbPath := futureProject(t)
	run := mustLoad(t, dir)

	ui := mustLoad(t, dir)
	ui.Plan.TaskByID(4).Priority = 0
	if err := ui.SaveDirect(); err != nil {
		t.Fatalf("SaveDirect: %v", err)
	}

	run.SyncFromDisk()
	run.Plan.TaskByID(4).Status = pm.TaskInProgress
	if err := run.Save(); err != nil {
		t.Fatalf("Save: %v", err)
	}
	wantTaskFutureValues(t, dbPath, "a sync and a save", keptBy(1, 2, 3, 4))
	if got := mustLoad(t, dir).Plan.TaskByID(4); got.Priority != 0 || got.Status != pm.TaskInProgress {
		t.Errorf("task 4 = priority %d, %s; want the reorder and the run's status both kept", got.Priority, got.Status)
	}
}
