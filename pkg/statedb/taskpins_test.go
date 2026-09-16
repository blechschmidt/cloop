package statedb

import (
	"path/filepath"
	"testing"

	"github.com/blechschmidt/cloop/pkg/pm"
)

// TestTaskPinsMigrationIsAdditive is the compatibility gate.
//
// :8080 and :8888 run from the same directory and therefore share one control
// plane, and dev builds migrate every registered project's state.db. A
// migration classified breaking makes the older binary refuse to open them,
// which blanks its dashboard until the nightly rebuild — the 2026-09-14 outage
// recorded in schema_compat.go.
//
// ADD COLUMN is admitted only in a narrow form: with a DEFAULT (or nullable)
// and carrying no UNIQUE, PRIMARY KEY, REFERENCES or CHECK. This migration is
// inside that form, but the margin is one word wide — adding a constraint, or
// dropping the default from the NOT NULL, flips the verdict silently. Asserting
// it here is what makes that edit fail in CI instead of in production.
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
// plan_tasks and re-inserting it, and task ids are reused by later plans — so a
// pin that survived its row would be handed to an unrelated task.
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
}

// plan_tasks has two readers — the whole-plan load and the single-task load —
// and each spells out its own column list. A new column has to be added to
// both, and a reader that misses it does not fail loudly: it answers "not
// pinned", which is indistinguishable from a task nobody ever pinned. That is
// the same silence that hid the missing column for as long as it did.
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

// Rows written before this column existed carry its DEFAULT, which must read as
// "not pinned" rather than as an error or a true. This is what an older hub's
// rows look like after the migration runs.
func TestTaskPin_PreExistingRowsReadAsUnpinned(t *testing.T) {
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
	// Exactly what an old binary's INSERT leaves behind: the column unmentioned,
	// so the default fills it in.
	if _, err := db.conn.Exec(
		`INSERT INTO plan_tasks(id, title, status) VALUES (2, 'legacy', 'pending')`); err != nil {
		t.Fatalf("insert legacy row: %v", err)
	}

	got, err := db.LoadState()
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	for _, id := range []int{1, 2} {
		if got.Plan.TaskByID(id).Pinned {
			t.Errorf("task %d came back pinned and was never pinned", id)
		}
	}
}
