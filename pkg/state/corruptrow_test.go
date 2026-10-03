package state

// A damaged task row must stop a merging save rather than be written over
// (Tasks 20297, 20361).

import (
	"database/sql"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// TestSaveRefusesToReplaceAPlanItCannotRead: Save replaces every stored task
// with the plan in memory, and relies on its merge to have brought in what was
// added on disk first. A row whose depends_on cannot be read fails that merge.
// Saving anyway would delete a task the run never saw — the one the error
// names — so the save has to stop until the row is repaired, and then go
// through with the task intact.
func TestSaveRefusesToReplaceAPlanItCannotRead(t *testing.T) {
	dir := planProject(t)
	run := mustLoad(t, dir)

	// Another process adds task 3, and its row is then damaged.
	ui := mustLoad(t, dir)
	ui.Plan.Tasks = append(ui.Plan.Tasks, &pm.Task{
		ID: 3, Title: "added from the dashboard", Status: pm.TaskPending, DependsOn: []int{2},
	})
	if err := ui.SaveDirect(); err != nil {
		t.Fatalf("SaveDirect: %v", err)
	}
	setDependsOn(t, dir, 3, `[2`)

	run.Plan.TaskByID(1).Status = pm.TaskDone
	err := run.Save()
	if !errors.Is(err, statedb.ErrCorruptTaskColumn) {
		t.Fatalf("Save over an unreadable row: err = %v, want ErrCorruptTaskColumn", err)
	}
	if !strings.Contains(err.Error(), "task 3") {
		t.Errorf("the error does not name the row to repair: %v", err)
	}
	if raw := dependsOn(t, dir, 3); raw != `[2` {
		t.Fatalf("task 3's row is now %q: the refused save still wrote over it", raw)
	}

	// Repaired, the same save goes through and keeps task 3.
	setDependsOn(t, dir, 3, `[2]`)
	if err := run.Save(); err != nil {
		t.Fatalf("Save after the repair: %v", err)
	}
	after := mustLoad(t, dir)
	if got := after.Plan.TaskByID(3); got == nil || !reflect.DeepEqual(got.DependsOn, []int{2}) {
		t.Errorf("task 3 after the save = %+v, want it kept with its dependency", got)
	}
	if s := after.Plan.TaskByID(1).Status; s != pm.TaskDone {
		t.Errorf("task 1 = %q; the run's own change did not land once the save could proceed", s)
	}
}

// TestSyncFromDiskSurvivesAnUnreadableRow: the read side loses nothing by
// skipping a merge, so it neither fails nor touches the plan in memory.
func TestSyncFromDiskSurvivesAnUnreadableRow(t *testing.T) {
	dir := planProject(t)
	run := mustLoad(t, dir)
	setDependsOn(t, dir, 2, `not json`)

	run.SyncFromDisk()
	if got := run.Plan.TaskByID(2); got == nil || got.Title != "ship" {
		t.Errorf("the in-memory plan changed after a failed sync: %+v", got)
	}
}

func setDependsOn(t *testing.T, dir string, id int, raw string) {
	t.Helper()
	db := openRawState(t, dir)
	if _, err := db.Exec(`UPDATE plan_tasks SET depends_on = ? WHERE id = ?`, raw, id); err != nil {
		t.Fatalf("damage task %d: %v", id, err)
	}
}

func dependsOn(t *testing.T, dir string, id int) string {
	t.Helper()
	db := openRawState(t, dir)
	var raw string
	if err := db.QueryRow(`SELECT depends_on FROM plan_tasks WHERE id = ?`, id).Scan(&raw); err != nil {
		t.Fatalf("read task %d: %v", id, err)
	}
	return raw
}

// openRawState opens the project's database with no decoding in between,
// which is the only way to stage a row the writer would never produce.
func openRawState(t *testing.T, dir string) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", DBPath(dir)+"?_pragma=busy_timeout(5000)")
	if err != nil {
		t.Fatalf("open %s: %v", DBPath(dir), err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}
