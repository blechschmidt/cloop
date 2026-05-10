package statedb_test

import (
	"errors"
	"testing"

	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// TestLoadTask_Found exercises the happy path: a single task is persisted
// then read back through LoadTask. Verifies all surface fields round-trip.
func TestLoadTask_Found(t *testing.T) {
	db, _ := tempDB(t)
	s := baseState()
	s.PMMode = true
	s.Plan = &pm.Plan{
		Goal: "g",
		Tasks: []*pm.Task{
			{ID: 1, Title: "first", Description: "d1", Priority: 2, Status: pm.TaskPending, Role: pm.RoleBackend},
			{ID: 7, Title: "seventh", Description: "d7", Priority: 1, Status: pm.TaskInProgress},
		},
	}
	if err := db.SaveState(s); err != nil {
		t.Fatalf("SaveState: %v", err)
	}

	got, err := db.LoadTask(7)
	if err != nil {
		t.Fatalf("LoadTask(7): %v", err)
	}
	if got.ID != 7 || got.Title != "seventh" {
		t.Errorf("LoadTask returned wrong row: %+v", got)
	}
	if got.Status != pm.TaskInProgress {
		t.Errorf("status round-trip: got %v, want in_progress", got.Status)
	}
}

// TestLoadTask_NotFound is the load-bearing test for the new sentinel:
// HTTP handlers in pkg/ui and pkg/apiserver use errors.Is on this exact
// error to map to 404 instead of 500. If the error ever stops wrapping
// ErrTaskNotFound, every "task X not found" path in the API surface
// regresses to a generic 500.
func TestLoadTask_NotFound(t *testing.T) {
	db, _ := tempDB(t)
	if err := db.SaveState(baseState()); err != nil {
		t.Fatalf("SaveState: %v", err)
	}

	_, err := db.LoadTask(999)
	if err == nil {
		t.Fatal("LoadTask(999): want error, got nil")
	}
	if !errors.Is(err, statedb.ErrTaskNotFound) {
		t.Errorf("LoadTask(999): err does not wrap ErrTaskNotFound: %v", err)
	}
	if statedb.HTTPStatus(err) != 404 {
		t.Errorf("HTTPStatus for not-found = %d, want 404", statedb.HTTPStatus(err))
	}
}

// TestLoadTask_EmptyDB verifies that LoadTask against a freshly-opened DB
// (no SaveState yet) still returns the typed sentinel rather than a raw
// "no such table" or similar driver-level error.
func TestLoadTask_EmptyDB(t *testing.T) {
	db, _ := tempDB(t)
	_, err := db.LoadTask(1)
	if err == nil {
		t.Fatal("LoadTask on empty DB: want error, got nil")
	}
	if !errors.Is(err, statedb.ErrTaskNotFound) {
		t.Errorf("LoadTask on empty DB: err does not wrap ErrTaskNotFound: %v", err)
	}
}
