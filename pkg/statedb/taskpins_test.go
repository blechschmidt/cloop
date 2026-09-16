package statedb

import (
	"path/filepath"
	"testing"

	"github.com/blechschmidt/cloop/pkg/pm"
)

// TestTaskPinsMigrationIsAdditive is the compatibility gate, and the reason
// this feature is a side table instead of a column.
//
// :8080 and :8888 run from the same directory and therefore share one control
// plane, and dev builds migrate every registered project's state.db. A
// migration classified breaking makes the older binary refuse to open them,
// which blanks its dashboard until the nightly rebuild — the 2026-09-14 outage
// recorded in schema_compat.go.
//
// The obvious shape for a boolean on a task is `ALTER TABLE plan_tasks ADD
// COLUMN pinned`, and the classifier treats every ALTER as breaking. This test
// is what stops a later edit from quietly reaching for one.
func TestTaskPinsMigrationIsAdditive(t *testing.T) {
	migrations, err := loadMigrations()
	if err != nil {
		t.Fatalf("load migrations: %v", err)
	}
	var found bool
	for _, m := range migrations {
		if m.Version != 42 {
			continue
		}
		found = true
		if got := classifyMigration(string(m.SQL)); got != CompatAdditive {
			t.Errorf("0042_task_pinned classified %q, want %q — an older hub "+
				"sharing this control plane would refuse to open every project "+
				"database until it was rebuilt", got, CompatAdditive)
		}
	}
	if !found {
		t.Fatal("migration 42 is not in the embedded set")
	}
}

// The defect itself: pm.Task.Pinned had no column, so `cloop task pin` set a
// field that the next save discarded. Nothing observed the loss because the
// only thing that read the flag was the rendering of the flag.
func TestTaskPin_SurvivesASaveRoundTrip(t *testing.T) {
	db := openTestDB(t)

	plan := &pm.Plan{Goal: "g", Tasks: []*pm.Task{
		{ID: 1, Title: "one", Priority: 1, Status: pm.TaskPending},
		{ID: 2, Title: "two", Priority: 2, Status: pm.TaskPending, Pinned: true},
	}}
	if err := db.SaveState(&State{Goal: "g", PMMode: true, Plan: plan}); err != nil {
		t.Fatalf("save: %v", err)
	}

	got, err := db.LoadState()
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if got.Plan.TaskByID(1).Pinned {
		t.Error("task 1 came back pinned and was never pinned")
	}
	if !got.Plan.TaskByID(2).Pinned {
		t.Error("task 2 was pinned and came back unpinned — the flag is being dropped")
	}
}

// Unpinning has to clear the row, or a pin is a one-way door.
func TestTaskPin_UnpinClearsIt(t *testing.T) {
	db := openTestDB(t)

	task := &pm.Task{ID: 1, Title: "one", Priority: 1, Status: pm.TaskPending, Pinned: true}
	plan := &pm.Plan{Goal: "g", Tasks: []*pm.Task{task}}
	if err := db.SaveState(&State{Goal: "g", PMMode: true, Plan: plan}); err != nil {
		t.Fatalf("save pinned: %v", err)
	}

	task.Pinned = false
	if err := db.SaveState(&State{Goal: "g", PMMode: true, Plan: plan}); err != nil {
		t.Fatalf("save unpinned: %v", err)
	}

	got, err := db.LoadState()
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if got.Plan.TaskByID(1).Pinned {
		t.Error("the task is still pinned after being unpinned and saved")
	}
}

// A pin must not outlive its task. SaveState rewrites the plan by deleting
// plan_tasks and re-inserting it, so without the cascade a removed task would
// leave an orphan row — and task ids are reused by later plans, which would
// hand the pin to an unrelated task.
func TestTaskPin_DoesNotSurviveItsTask(t *testing.T) {
	db := openTestDB(t)

	if err := db.SaveState(&State{Goal: "g", PMMode: true, Plan: &pm.Plan{
		Goal:  "g",
		Tasks: []*pm.Task{{ID: 7, Title: "pinned", Status: pm.TaskPending, Pinned: true}},
	}}); err != nil {
		t.Fatalf("save: %v", err)
	}

	// The task is deleted and id 7 is later reused by a different task.
	if err := db.SaveState(&State{Goal: "g", PMMode: true, Plan: &pm.Plan{
		Goal:  "g",
		Tasks: []*pm.Task{{ID: 7, Title: "a different task", Status: pm.TaskPending}},
	}}); err != nil {
		t.Fatalf("resave: %v", err)
	}

	got, err := db.LoadState()
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if got.Plan.TaskByID(7).Pinned {
		t.Error("a new task inherited the pin of the task that used to hold its id")
	}

	var orphans int
	if err := db.conn.QueryRow(
		`SELECT COUNT(*) FROM plan_task_pins
		 WHERE task_id NOT IN (SELECT id FROM plan_tasks)`).Scan(&orphans); err != nil {
		t.Fatalf("count orphans: %v", err)
	}
	if orphans != 0 {
		t.Errorf("%d pin rows have no task", orphans)
	}
}

// plan_tasks has two readers — the whole-plan load and the single-task load —
// and each spells out its own column list. A side table has to be joined in
// both, and a reader that forgets it does not fail: it silently answers
// "unpinned", which reads as a task that was never pinned.
func TestTaskPin_BothReadersAgree(t *testing.T) {
	db := openTestDB(t)

	if err := db.SaveState(&State{Goal: "g", PMMode: true, Plan: &pm.Plan{
		Goal: "g",
		Tasks: []*pm.Task{
			{ID: 1, Title: "plain", Status: pm.TaskPending},
			{ID: 2, Title: "pinned", Status: pm.TaskPending, Pinned: true},
		},
	}}); err != nil {
		t.Fatalf("save: %v", err)
	}

	plan, err := db.LoadState()
	if err != nil {
		t.Fatalf("load state: %v", err)
	}
	for _, id := range []int{1, 2} {
		one, err := db.LoadTask(id)
		if err != nil {
			t.Fatalf("load task %d: %v", id, err)
		}
		if want := plan.Plan.TaskByID(id).Pinned; one.Pinned != want {
			t.Errorf("task %d: LoadTask says pinned=%v, LoadState says %v — the "+
				"two readers disagree about the same row", id, one.Pinned, want)
		}
	}
}

// An older database has no plan_task_pins rows at all, which must read as "no
// task is pinned" rather than as an error.
func TestTaskPin_AbsentRowsReadAsUnpinned(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	if err := db.SaveState(&State{Goal: "g", PMMode: true, Plan: &pm.Plan{
		Goal:  "g",
		Tasks: []*pm.Task{{ID: 1, Title: "one", Status: pm.TaskPending}},
	}}); err != nil {
		t.Fatalf("save: %v", err)
	}
	if _, err := db.conn.Exec(`DELETE FROM plan_task_pins`); err != nil {
		t.Fatalf("clear pins: %v", err)
	}

	got, err := db.LoadState()
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if got.Plan.TaskByID(1).Pinned {
		t.Error("a task with no pin row came back pinned")
	}
}
