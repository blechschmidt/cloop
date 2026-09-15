package reconcile

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/pkg/state"
)

// Handle persistence is best-effort, so its failures are warnings rather than
// errors. That makes it important that the warning still means something: it
// fired on every `cloop` command run outside a project, where there is no
// database because there is no project and nothing to persist because the
// command dispatches nothing (Task 20294).
//
// The pair below pins the distinction from both sides. Suppressing the first
// case is only safe if the second still speaks up.

// captureLogs runs handleStore against dir and returns whatever it logged.
//
// handleStoreCache is process-global and deliberately never evicted, so each
// test uses a fresh temp directory as its key rather than trying to reset it.
func captureLogs(t *testing.T, dir string) (string, bool) {
	t.Helper()
	var logged []string
	opts := Options{Logf: func(format string, args ...any) {
		logged = append(logged, format)
	}}
	store := opts.handleStore(dir)
	return strings.Join(logged, "\n"), store != nil
}

// TestHandleStoreIsSilentOutsideAProject: the common path says nothing.
func TestHandleStoreIsSilentOutsideAProject(t *testing.T) {
	dir := t.TempDir() // no .cloop, exactly like a user's empty directory

	logs, gotStore := captureLogs(t, dir)

	if logs != "" {
		t.Errorf("a directory with no project must produce no diagnostics, got:\n%s", logs)
	}
	if gotStore {
		t.Error("want a nil store when there is no database")
	}
	// And it must not have created one as a side effect: a read-only command
	// like `cloop --help` has no business writing a database into the user's
	// current directory.
	if _, err := os.Stat(state.DBPath(dir)); err == nil {
		t.Error("probing for a store must not create a state database")
	}
}

// TestHandleStoreCreatesADatabaseUnderAnExistingCloopDir guards what the quiet
// path must NOT cost. Open creates the database when .cloop already exists, and
// a hub bootstrapped into a directory holding only a config.yaml depends on
// that to get handle persistence at all.
//
// Suppressing the warning by skipping the Open would have passed every other
// test here while silently returning a nil store to exactly that hub.
func TestHandleStoreCreatesADatabaseUnderAnExistingCloopDir(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Dir(state.DBPath(dir)), 0o755); err != nil {
		t.Fatalf("mkdir .cloop: %v", err)
	}

	logs, gotStore := captureLogs(t, dir)

	if !gotStore {
		t.Error("an existing .cloop directory must still yield a handle store")
	}
	if logs != "" {
		t.Errorf("a successful open must be silent, got:\n%s", logs)
	}
	if _, err := os.Stat(state.DBPath(dir)); err != nil {
		t.Errorf("the database must have been created: %v", err)
	}
}

// TestHandleStoreStillWarnsOnAnUnusableDatabase: the diagnostic survives where
// it is genuinely diagnostic. A database that exists and cannot be opened is
// corruption, a permissions problem or a lock — all worth saying out loud,
// because they do cost this process the ability to survive its own restart.
func TestHandleStoreStillWarnsOnAnUnusableDatabase(t *testing.T) {
	dir := t.TempDir()
	dbPath := state.DBPath(dir)
	if err := os.MkdirAll(filepath.Dir(dbPath), 0o755); err != nil {
		t.Fatalf("mkdir .cloop: %v", err)
	}
	if err := os.WriteFile(dbPath, []byte("this is not a database"), 0o600); err != nil {
		t.Fatalf("write junk database: %v", err)
	}

	logs, gotStore := captureLogs(t, dir)

	if !strings.Contains(logs, "handle persistence unavailable") {
		t.Errorf("a database that exists but cannot be opened must still warn, got:\n%s", logs)
	}
	if gotStore {
		t.Error("want a nil store when the database cannot be opened")
	}
}
