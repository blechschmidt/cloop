package cmd

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
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

// TestCheckpointSave_WritesAtomically pins the contract that a successful
// checkpoint save lands the file via atomicfile.Write — i.e. the directory
// contains exactly the renamed file and no leftover `.<name>.*.tmp` siblings.
// Catches regressions where someone re-introduces a direct os.WriteFile on
// the save path, which would (a) not flush the parent directory inode and
// (b) expose a torn-write window where readers could observe a half-written
// file via a partial fsync. The ".tmp" check is the externally observable
// proxy for "atomicfile.Write was used."
func TestCheckpointSave_WritesAtomically(t *testing.T) {
	tmp := t.TempDir()
	if err := os.Chdir(tmp); err != nil {
		t.Fatalf("chdir: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(tmp, ".cloop"), 0o755); err != nil {
		t.Fatalf("mkdir .cloop: %v", err)
	}

	body := []byte(`{"goal":"atomic-save","tasks":[]}`)
	if err := os.WriteFile(filepath.Join(tmp, ".cloop", "state.json"), body, 0o644); err != nil {
		t.Fatalf("write state.json: %v", err)
	}

	if err := checkpointSaveCmd.RunE(checkpointSaveCmd, []string{"atomic"}); err != nil {
		t.Fatalf("save: %v", err)
	}

	dir := filepath.Join(tmp, checkpointDir)
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read checkpoint dir: %v", err)
	}
	var sawTarget bool
	for _, e := range entries {
		name := e.Name()
		if strings.HasSuffix(name, ".tmp") {
			t.Errorf("leftover atomicfile staging file in %s: %s", dir, name)
		}
		if name == "atomic.json" {
			sawTarget = true
		}
	}
	if !sawTarget {
		t.Fatalf("expected checkpoint atomic.json in %s, entries=%v", dir, entries)
	}

	got, err := os.ReadFile(filepath.Join(dir, "atomic.json"))
	if err != nil {
		t.Fatalf("read checkpoint: %v", err)
	}
	if string(got) != string(body) {
		t.Errorf("checkpoint contents mismatch: got %q, want %q", got, body)
	}
}

// TestCheckpointRestore_WritesAtomically verifies that restoring a checkpoint
// (a) overwrites .cloop/state.json atomically and (b) writes the pre-restore
// backup atomically — i.e. neither leaves a `.<name>.*.tmp` sibling in its
// target directory. Restoring is the most failure-sensitive checkpoint path:
// a torn write to state.json corrupts project state and a torn write to the
// pre-restore backup defeats the safety net the user is relying on.
func TestCheckpointRestore_WritesAtomically(t *testing.T) {
	tmp := t.TempDir()
	if err := os.Chdir(tmp); err != nil {
		t.Fatalf("chdir: %v", err)
	}
	cloopDir := filepath.Join(tmp, ".cloop")
	if err := os.MkdirAll(cloopDir, 0o755); err != nil {
		t.Fatalf("mkdir .cloop: %v", err)
	}
	dir := filepath.Join(tmp, checkpointDir)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir checkpoints: %v", err)
	}

	current := []byte(`{"goal":"current"}`)
	if err := os.WriteFile(filepath.Join(cloopDir, "state.json"), current, 0o644); err != nil {
		t.Fatalf("write current state.json: %v", err)
	}
	saved := []byte(`{"goal":"restored","tasks":[]}`)
	if err := os.WriteFile(filepath.Join(dir, "good.json"), saved, 0o644); err != nil {
		t.Fatalf("seed checkpoint: %v", err)
	}

	if err := checkpointRestoreCmd.RunE(checkpointRestoreCmd, []string{"good"}); err != nil {
		t.Fatalf("restore: %v", err)
	}

	// state.json now matches the checkpoint.
	got, err := os.ReadFile(filepath.Join(cloopDir, "state.json"))
	if err != nil {
		t.Fatalf("read state.json: %v", err)
	}
	if string(got) != string(saved) {
		t.Errorf("state.json after restore: got %q, want %q", got, saved)
	}

	// No .tmp leftovers in either target directory.
	for _, d := range []string{cloopDir, dir} {
		entries, err := os.ReadDir(d)
		if err != nil {
			t.Fatalf("read %s: %v", d, err)
		}
		for _, e := range entries {
			if strings.HasSuffix(e.Name(), ".tmp") {
				t.Errorf("leftover atomicfile staging file in %s: %s", d, e.Name())
			}
		}
	}

	// Pre-restore backup of the original state was created.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read checkpoint dir: %v", err)
	}
	var foundBackup bool
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "pre-restore-") && strings.HasSuffix(e.Name(), ".json") {
			b, err := os.ReadFile(filepath.Join(dir, e.Name()))
			if err != nil {
				t.Fatalf("read backup: %v", err)
			}
			if string(b) != string(current) {
				t.Errorf("pre-restore backup mismatch: got %q, want %q", b, current)
			}
			foundBackup = true
		}
	}
	if !foundBackup {
		t.Errorf("expected a pre-restore-*.json backup in %s, entries=%v", dir, entries)
	}
}
