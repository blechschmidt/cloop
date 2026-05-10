package state

import (
	"errors"
	"net/http"
	"testing"

	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// TestLoad_NoProject_WrapsErrProjectNotFound is the load-bearing test for
// the apiserver loadState helper: an empty workdir must produce an error
// that errors.Is matches against statedb.ErrProjectNotFound, otherwise the
// HTTP layer can't tell "missing project" (404) from "broken DB" (503).
func TestLoad_NoProject_WrapsErrProjectNotFound(t *testing.T) {
	dir := tempDir(t)
	_, err := Load(dir)
	if err == nil {
		t.Fatal("Load(empty dir): want error, got nil")
	}
	if !errors.Is(err, statedb.ErrProjectNotFound) {
		t.Errorf("Load(empty dir): err does not wrap ErrProjectNotFound: %v", err)
	}
	if got := statedb.HTTPStatus(err); got != http.StatusNotFound {
		t.Errorf("HTTPStatus(load err) = %d, want 404", got)
	}
}

// TestRequireTask_NotFound covers the path UI handlers use for "task X
// not found" 404s.
func TestRequireTask_NotFound(t *testing.T) {
	cases := []struct {
		name string
		ps   *ProjectState
	}{
		{"nil receiver", nil},
		{"nil plan", &ProjectState{}},
		{"empty plan", &ProjectState{Plan: &pm.Plan{Tasks: []*pm.Task{}}}},
		{
			"missing id",
			&ProjectState{Plan: &pm.Plan{Tasks: []*pm.Task{
				{ID: 1, Title: "x"},
				{ID: 2, Title: "y"},
			}}},
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			_, err := tc.ps.RequireTask(99)
			if err == nil {
				t.Fatal("RequireTask: want error, got nil")
			}
			if !errors.Is(err, statedb.ErrTaskNotFound) {
				t.Errorf("RequireTask: err does not wrap ErrTaskNotFound: %v", err)
			}
		})
	}
}

// TestRequireTask_Found verifies the happy path returns the same pointer
// the plan slice holds — callers mutate the task via this returned pointer.
func TestRequireTask_Found(t *testing.T) {
	want := &pm.Task{ID: 42, Title: "answer"}
	ps := &ProjectState{Plan: &pm.Plan{Tasks: []*pm.Task{
		{ID: 1, Title: "one"},
		want,
		{ID: 100, Title: "hundred"},
	}}}
	got, err := ps.RequireTask(42)
	if err != nil {
		t.Fatalf("RequireTask(42): %v", err)
	}
	if got != want {
		t.Errorf("RequireTask returned %p, want %p", got, want)
	}
}
