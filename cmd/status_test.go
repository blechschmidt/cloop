package cmd

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/pkg/orchestrator"
	"github.com/blechschmidt/cloop/pkg/pausereason"
	"github.com/blechschmidt/cloop/pkg/state"
)

// Task 20362. A paused run's reason was stored, shown on the dashboard and in
// --json, and left out of the one view an operator at a terminal reads.
func TestStatusSaysWhyTheRunPaused(t *testing.T) {
	dir := t.TempDir()
	s, err := state.Init(dir, "goal", 0)
	if err != nil {
		t.Fatal(err)
	}
	s.SetPaused(pausereason.New(pausereason.CodeStateNotPersisted,
		"could not save task #3's completion (status done): database or disk is full"))
	if err := s.Save(); err != nil {
		t.Fatal(err)
	}
	t.Chdir(dir)

	out, err := captureStdout(t, func() error { return statusCmd.RunE(statusCmd, nil) })
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	for _, want := range []string{
		"Status:   paused",
		"Reason:   could not save task #3's completion (status done): database or disk is full",
		"the next run recovers the tasks this one left in progress",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("status output lacks %q:\n%s", want, out)
		}
	}
}

// A run that is not paused has no reason line to print.
func TestStatusPrintsNoReasonWhenNotPaused(t *testing.T) {
	dir := t.TempDir()
	if _, err := state.Init(dir, "goal", 0); err != nil {
		t.Fatal(err)
	}
	t.Chdir(dir)
	out, err := captureStdout(t, func() error { return statusCmd.RunE(statusCmd, nil) })
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	if strings.Contains(out, "Reason:") {
		t.Errorf("an initialized project printed a pause reason:\n%s", out)
	}
}

// The exit status is the account of a stopped run that survives a database
// that took nothing; the hub reads it.
func TestExitCodeForARunThatCouldNotSave(t *testing.T) {
	stopped := fmt.Errorf("run: %w", errors.Join(errors.New("3 consecutive errors"), orchestrator.ErrStateNotPersisted))
	if got := exitCodeFor(stopped); got != pausereason.ExitStateNotPersisted {
		t.Errorf("exitCodeFor(stopped run) = %d, want %d", got, pausereason.ExitStateNotPersisted)
	}
	if got := exitCodeFor(errors.New("provider unreachable")); got != 1 {
		t.Errorf("exitCodeFor(other error) = %d, want 1", got)
	}
}
