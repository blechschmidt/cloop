package janitor

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/internal/statedbtest"
	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/statedb"
	"github.com/blechschmidt/cloop/pkg/taskrecover"
)

// writeVerdictAged writes a verdict sidecar for taskID and backdates it.
func writeVerdictAged(t *testing.T, workDir string, taskID int, age time.Duration) {
	t.Helper()
	if err := taskrecover.WriteVerdict(workDir, taskrecover.Verdict{TaskID: taskID, Status: pm.TaskDone}); err != nil {
		t.Fatal(err)
	}
	when := time.Now().Add(-age)
	if err := os.Chtimes(taskrecover.VerdictPath(workDir, taskID), when, when); err != nil {
		t.Fatal(err)
	}
}

// Task verdicts (Task 20365) are bounded like everything else in .cloop, except
// the one a stale-task recovery needs: an in-progress task's.
func TestRunOnce_PrunesTaskVerdictsRecoveryNoLongerNeeds(t *testing.T) {
	dir := newProject(t)
	statedbtest.SeedDir(t, dir)
	db, err := statedb.Open(filepath.Join(dir, ".cloop", "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	for _, task := range []*pm.Task{
		{ID: 1, Title: "done long ago", Status: pm.TaskDone},
		{ID: 2, Title: "left in progress by a dead run", Status: pm.TaskInProgress},
		{ID: 3, Title: "done just now", Status: pm.TaskDone},
	} {
		if err := db.UpsertTask(task); err != nil {
			t.Fatal(err)
		}
	}
	_ = db.Close()
	old := VerdictMaxAge + time.Hour
	writeVerdictAged(t, dir, 1, old)
	writeVerdictAged(t, dir, 2, old)
	writeVerdictAged(t, dir, 3, time.Minute)
	writeVerdictAged(t, dir, 4, old) // its task was deleted

	dry, err := RunOnce(Options{WorkDir: dir, Policy: DefaultPolicy(), DryRun: true})
	if err != nil {
		t.Fatal(err)
	}
	if dry.Verdicts.Deleted != 2 {
		t.Fatalf("dry run would delete %d verdicts, want 2", dry.Verdicts.Deleted)
	}
	if _, err := os.Stat(taskrecover.VerdictPath(dir, 1)); err != nil {
		t.Fatal("a dry run deleted a verdict")
	}

	rep, err := RunOnce(Options{WorkDir: dir, Policy: DefaultPolicy()})
	if err != nil {
		t.Fatal(err)
	}
	if rep.Verdicts.Err != nil || !rep.Verdicts.Ran || rep.Verdicts.Deleted != 2 {
		t.Fatalf("verdict step = %+v", rep.Verdicts)
	}
	for id, want := range map[int]bool{1: false, 2: true, 3: true, 4: false} {
		_, err := os.Stat(taskrecover.VerdictPath(dir, id))
		if got := err == nil; got != want {
			t.Errorf("task %d's verdict present = %v, want %v", id, got, want)
		}
	}
}

// Without a readable database nothing says which tasks are in progress, so
// nothing is pruned.
func TestRunOnce_KeepsTaskVerdictsWithoutADatabase(t *testing.T) {
	dir := newProject(t)
	writeVerdictAged(t, dir, 1, VerdictMaxAge+time.Hour)
	rep, err := RunOnce(Options{WorkDir: dir, Policy: DefaultPolicy()})
	if err != nil {
		t.Fatal(err)
	}
	if rep.Verdicts.Ran || rep.Verdicts.Deleted != 0 {
		t.Fatalf("verdict step = %+v, want it skipped", rep.Verdicts)
	}
	if _, err := os.Stat(taskrecover.VerdictPath(dir, 1)); err != nil {
		t.Fatal("a verdict was pruned without knowing its task's status")
	}
}
