package dbbackup

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/internal/statedbtest"
)

// The preflight checks one file and the restore copies it a moment later.
// Whoever can write the backup could swap it in between; the copy is hashed as
// it is made and must be the file that was checked, or nothing is restored.
func TestABackupChangedAfterItsCheckIsNotRestored(t *testing.T) {
	const key = "dbbackup-stage-test-key-0123456789abcdefghijk"
	src := filepath.Join(t.TempDir(), "state.db")
	statedbtest.Template().Seed(t, src)
	backup := filepath.Join(t.TempDir(), "backup.db")
	if _, err := BackupWithOptions(src, backup, BackupOptions{Key: key}); err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(t.TempDir(), "state.db")
	if err := os.WriteFile(dst, []byte("the live database"), 0o600); err != nil {
		t.Fatal(err)
	}

	afterPreflight = func(path string) {
		f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = f.Write([]byte("swapped after the check"))
		_ = f.Close()
	}
	t.Cleanup(func() { afterPreflight = nil })

	_, err := Restore(backup, dst, RestoreOptions{Key: key, Force: true, Reason: "test"})
	if err == nil || !strings.Contains(err.Error(), "changed between its check and its copy") {
		t.Fatalf("a backup changed after its check: %v", err)
	}
	if got, _ := os.ReadFile(dst); string(got) != "the live database" {
		t.Fatal("the destination was replaced")
	}
	if left, _ := filepath.Glob(dst + ".*"); len(left) != 0 {
		t.Fatalf("left behind: %v", left)
	}
}

// The file swapped in hashed to what the preflight checked, so its chain ends
// where the backup's did; a chain that ends elsewhere was written in between,
// and the restore must not seal it as "restored to".
func TestARestoredChainThatChangedIsNotSealed(t *testing.T) {
	const key = "dbbackup-stage-test-key-0123456789abcdefghijk"
	dst := filepath.Join(t.TempDir(), "state.db")
	statedbtest.Template().Seed(t, dst)
	pre := &Preflight{Backup: "b.db", SHA256: strings.Repeat("ab", 32), Sidecar: SidecarSealed}
	pre.Chain.LastID, pre.Chain.LastRowHash = 41, strings.Repeat("cd", 32)
	cps := filepath.Join(t.TempDir(), "checkpoints.jsonl")

	rec, err := record(dst, pre, RestoreOptions{Key: key, Reason: "test", CheckpointFile: cps})
	var unrecorded *UnrecordedError
	if !errors.As(err, &unrecorded) || !strings.Contains(err.Error(), "written between the swap and the record") {
		t.Fatalf("%v", err)
	}
	if rec.Row.ID != 0 {
		t.Fatal("an audit.restored row was appended")
	}
	if _, err := os.Stat(cps); !os.IsNotExist(err) {
		t.Fatal("a restore record was written")
	}
}
