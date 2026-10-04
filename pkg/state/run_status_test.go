package state

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/blechschmidt/cloop/internal/statedbtest"
	"github.com/blechschmidt/cloop/pkg/pausereason"
	"github.com/blechschmidt/cloop/pkg/pm"
)

// Task 20362. The last write of a run that stops because a full save failed:
// the status and why, and nothing it did not manage to store.
func TestSaveRunStatusWritesOnlyTheStatus(t *testing.T) {
	dir := statedbtest.Dir(t)
	s, err := Init(dir, "goal", 0)
	if err != nil {
		t.Fatal(err)
	}
	s.Plan = &pm.Plan{Goal: "goal", Tasks: []*pm.Task{{ID: 1, Title: "t", Status: pm.TaskInProgress}}}
	s.Status = "running"
	if err := s.Save(); err != nil {
		t.Fatal(err)
	}

	// In memory the task finished, but that write is the one that failed.
	s.Plan.Tasks[0].Status = pm.TaskDone
	s.SetPaused(pausereason.New(pausereason.CodeStateNotPersisted, "could not save task #1's completion"))
	if err := s.SaveRunStatus(); err != nil {
		t.Fatalf("SaveRunStatus: %v", err)
	}

	got, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !got.PausedFor(pausereason.CodeStateNotPersisted) {
		t.Fatalf("stored status = %q, reason = %+v", got.Status, got.PauseReason)
	}
	if st := got.Plan.TaskByID(1).Status; st != pm.TaskInProgress {
		t.Errorf("stored task = %q: the status write stored the outcome that was lost", st)
	}
}

// It never creates a database: a project without one has nowhere to record a
// status, and an empty database would read as a project that is not there.
func TestSaveRunStatusNeedsADatabase(t *testing.T) {
	dir := tempDir(t)
	s := &ProjectState{WorkDir: dir}
	s.SetPaused(pausereason.New(pausereason.CodeStateNotPersisted, "x"))
	if err := s.SaveRunStatus(); err == nil {
		t.Fatal("SaveRunStatus succeeded without a project database")
	}
	if _, err := os.Stat(filepath.Join(dir, ".cloop")); !os.IsNotExist(err) {
		t.Errorf("SaveRunStatus created %s/.cloop (stat err %v)", dir, err)
	}
}
