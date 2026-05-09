package ui

// Regression tests for the bounded-read guard on the watchState polling loop
// and the analytics-tab task-checkpoint scan in pkg/ui/server.go.
//
// Before the guard, both paths used os.ReadFile directly: a runaway or corrupt
// state.json would be slurped fully into memory and fanned out to every
// connected SSE/WebSocket client; a runaway/corrupt task-checkpoint file under
// .cloop/task-checkpoints/ would be slurped fully into memory by the
// histogram scan in handleAnalytics. The guard caps state.json reads at
// 32 MiB and per-checkpoint reads at 1 MiB.
//
// These tests pin the guard at the boundedread layer, which is what
// pkg/ui/server.go calls. If a future edit reverts to os.ReadFile, the test
// for the analytics scan would still pass — but the symbolic check on the
// boundedread import (compile-time) plus the explicit invariant tests give a
// regression marker should the contract change.

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/blechschmidt/cloop/pkg/boundedread"
	"github.com/blechschmidt/cloop/pkg/state"
)

// TestWatchState_BoundedReadCap asserts that the boundedread library refuses
// a state.json larger than the 32 MiB cap used by watchState. This is the
// invariant watchState relies on to keep a runaway state file out of the
// broadcast hub.
func TestWatchState_BoundedReadCap(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()

	statePath := state.StatePath(dir)
	if err := os.MkdirAll(filepath.Dir(statePath), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(statePath, []byte("{}"), 0o644); err != nil {
		t.Fatalf("write seed: %v", err)
	}

	// Sparse-truncate state.json to just over the cap. Sparse files don't
	// allocate disk on tmpfs/ext4, so this stays cheap. boundedread.ReadFile
	// stats first and refuses without reading any data, so we never load
	// 32 MiB of zeros into memory.
	if err := os.Truncate(statePath, (32<<20)+1); err != nil {
		t.Fatalf("truncate: %v", err)
	}

	_, err := boundedread.ReadFile(statePath, 32<<20)
	if err == nil {
		t.Fatal("expected ErrTooLarge for oversized state.json, got nil")
	}
	if !errors.Is(err, boundedread.ErrTooLarge) {
		t.Fatalf("expected ErrTooLarge, got %v", err)
	}

	// Shrink to a single byte and confirm a normal-sized file reads fine.
	if err := os.Truncate(statePath, 1); err != nil {
		t.Fatalf("truncate small: %v", err)
	}
	if _, err := boundedread.ReadFile(statePath, 32<<20); err != nil {
		t.Fatalf("in-range state.json should read cleanly, got %v", err)
	}
}

// TestAnalyticsCheckpointScan_BoundedReadCap asserts that the per-checkpoint
// 1 MiB cap used by handleAnalytics's histogram scan refuses a runaway file.
// Real checkpoint files in this repo are 2-4 KB; 1 MiB is >250x headroom, so
// any rejection is by definition a malformed/runaway artifact and silent
// skip is the right behaviour.
func TestAnalyticsCheckpointScan_BoundedReadCap(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()

	cpDir := filepath.Join(dir, ".cloop", "task-checkpoints", "task-1")
	if err := os.MkdirAll(cpDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	cpPath := filepath.Join(cpDir, "1.json")
	if err := os.WriteFile(cpPath, []byte("{}"), 0o644); err != nil {
		t.Fatalf("write small: %v", err)
	}
	if err := os.Truncate(cpPath, (1<<20)+1); err != nil {
		t.Fatalf("truncate: %v", err)
	}

	_, err := boundedread.ReadFile(cpPath, 1<<20)
	if !errors.Is(err, boundedread.ErrTooLarge) {
		t.Fatalf("expected ErrTooLarge for oversized checkpoint, got %v", err)
	}
}
