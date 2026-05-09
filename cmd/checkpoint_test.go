package cmd

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/blechschmidt/cloop/pkg/boundedread"
)

// TestCheckpointSave_RefusesOversizedStateFile verifies that the bounded read
// in checkpointSaveCmd refuses to load a state.json larger than the cap. A
// runaway state.json (or one a malicious peer has planted in .cloop/) should
// not be slurped into memory in one go.
func TestCheckpointSave_RefusesOversizedStateFile(t *testing.T) {
	tmp := t.TempDir()
	if err := os.Chdir(tmp); err != nil {
		t.Fatalf("chdir: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(tmp, ".cloop"), 0o755); err != nil {
		t.Fatalf("mkdir .cloop: %v", err)
	}

	// Shrink the cap so we don't have to write a 64 MiB fixture.
	prev := maxCheckpointStateBytes
	maxCheckpointStateBytes = 64
	t.Cleanup(func() { maxCheckpointStateBytes = prev })

	// Write a state.json that exceeds the (test-shrunk) cap.
	statePath := filepath.Join(tmp, ".cloop", "state.json")
	big := make([]byte, 256)
	for i := range big {
		big[i] = 'x'
	}
	if err := os.WriteFile(statePath, big, 0o644); err != nil {
		t.Fatalf("write state.json: %v", err)
	}

	err := checkpointSaveCmd.RunE(checkpointSaveCmd, []string{"oversized"})
	if err == nil {
		t.Fatalf("expected save to fail on oversized state.json, got nil")
	}
	if !errors.Is(err, boundedread.ErrTooLarge) {
		t.Errorf("expected boundedread.ErrTooLarge, got %v", err)
	}

	// And no checkpoint file should have been written.
	cp := filepath.Join(tmp, checkpointDir, "oversized.json")
	if _, statErr := os.Stat(cp); !os.IsNotExist(statErr) {
		t.Errorf("checkpoint file should not exist after refused save: stat=%v", statErr)
	}
}

// TestCheckpointSave_AcceptsBoundedStateFile verifies the happy path still
// works when the state file is well under the cap.
func TestCheckpointSave_AcceptsBoundedStateFile(t *testing.T) {
	tmp := t.TempDir()
	if err := os.Chdir(tmp); err != nil {
		t.Fatalf("chdir: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(tmp, ".cloop"), 0o755); err != nil {
		t.Fatalf("mkdir .cloop: %v", err)
	}

	statePath := filepath.Join(tmp, ".cloop", "state.json")
	if err := os.WriteFile(statePath, []byte(`{"goal":"test"}`), 0o644); err != nil {
		t.Fatalf("write state.json: %v", err)
	}

	if err := checkpointSaveCmd.RunE(checkpointSaveCmd, []string{"happy"}); err != nil {
		t.Fatalf("save returned error on small state file: %v", err)
	}
	cp := filepath.Join(tmp, checkpointDir, "happy.json")
	if _, statErr := os.Stat(cp); statErr != nil {
		t.Errorf("checkpoint file missing after successful save: %v", statErr)
	}
}

// TestCheckpointRestore_RefusesOversizedCheckpoint verifies the cap also
// applies on the restore path so a planted oversized .cloop/checkpoints/*.json
// cannot be loaded into memory wholesale.
func TestCheckpointRestore_RefusesOversizedCheckpoint(t *testing.T) {
	tmp := t.TempDir()
	if err := os.Chdir(tmp); err != nil {
		t.Fatalf("chdir: %v", err)
	}
	dir := filepath.Join(tmp, checkpointDir)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir checkpoints: %v", err)
	}

	prev := maxCheckpointStateBytes
	maxCheckpointStateBytes = 64
	t.Cleanup(func() { maxCheckpointStateBytes = prev })

	cp := filepath.Join(dir, "oversized.json")
	big := make([]byte, 256)
	if err := os.WriteFile(cp, big, 0o644); err != nil {
		t.Fatalf("write checkpoint: %v", err)
	}

	err := checkpointRestoreCmd.RunE(checkpointRestoreCmd, []string{"oversized"})
	if err == nil {
		t.Fatalf("expected restore to fail on oversized checkpoint, got nil")
	}
	if !errors.Is(err, boundedread.ErrTooLarge) {
		t.Errorf("expected boundedread.ErrTooLarge, got %v", err)
	}
}
