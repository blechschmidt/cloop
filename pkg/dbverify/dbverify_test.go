package dbverify_test

import (
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"testing"

	_ "modernc.org/sqlite"

	"github.com/blechschmidt/cloop/pkg/dbverify"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// TestVerify_CleanDatabase verifies a freshly-opened state.db reports OK.
func TestVerify_CleanDatabase(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "state.db")

	db, err := statedb.Open(dbPath)
	if err != nil {
		t.Fatalf("statedb.Open: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	for _, quick := range []bool{false, true} {
		t.Run(quickName(quick), func(t *testing.T) {
			rep, err := dbverify.Verify(dbPath, quick)
			if err != nil {
				t.Fatalf("Verify: %v", err)
			}
			if !rep.OK() {
				t.Fatalf("expected clean DB to be OK, got integrity=%v fk=%v",
					rep.IntegrityIssues, rep.ForeignKeyViolations)
			}
			if rep.QuickCheck != quick {
				t.Errorf("QuickCheck = %v, want %v", rep.QuickCheck, quick)
			}
			if rep.DBPath != dbPath {
				t.Errorf("DBPath = %q, want %q", rep.DBPath, dbPath)
			}
		})
	}
}

// TestVerify_MissingFile returns an explicit error rather than a Report.
func TestVerify_MissingFile(t *testing.T) {
	rep, err := dbverify.Verify(filepath.Join(t.TempDir(), "does-not-exist.db"), false)
	if err == nil {
		t.Fatalf("expected error for missing file, got report %+v", rep)
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("error %q does not mention not found", err.Error())
	}
}

// TestVerify_EmptyPath returns an explicit error.
func TestVerify_EmptyPath(t *testing.T) {
	_, err := dbverify.Verify("", false)
	if err == nil {
		t.Fatal("expected error for empty path")
	}
}

// TestVerify_CorruptedFile detects garbage written into the DB file.
//
// We copy a short, definitely-not-SQLite payload over the start of the file —
// SQLite recognises this as a corrupt header and Verify must surface it
// either as an integrity issue or as a hard error from the driver. Either
// outcome counts as "not silently ignored", which is what the test checks.
func TestVerify_CorruptedFile(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "state.db")
	db, err := statedb.Open(dbPath)
	if err != nil {
		t.Fatalf("statedb.Open: %v", err)
	}
	db.Close()

	// Overwrite the SQLite magic header with garbage so the file is no
	// longer a valid SQLite database.
	if err := os.WriteFile(dbPath, []byte("THIS IS NOT A SQLITE DATABASE FILE"), 0o644); err != nil {
		t.Fatalf("write garbage: %v", err)
	}

	rep, err := dbverify.Verify(dbPath, false)
	if err != nil {
		// Driver refused to open the corrupted file → that *is* the failure
		// signal the user needs. Acceptable outcome.
		return
	}
	if rep.OK() {
		t.Fatalf("expected corruption to be detected, but report is clean: %+v", rep)
	}
}

// TestVerify_ForeignKeyViolation detects a row whose parent does not exist.
//
// We intentionally insert violating rows with foreign_keys=OFF so SQLite
// does not block the INSERT itself — a real-world corruption scenario where
// a sibling process inserted bad rows or an in-place migration broke FKs.
func TestVerify_ForeignKeyViolation(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "fk.db")

	conn, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	if _, err := conn.Exec(`PRAGMA foreign_keys=OFF`); err != nil {
		t.Fatalf("disable FK: %v", err)
	}
	if _, err := conn.Exec(`
		CREATE TABLE parent (id INTEGER PRIMARY KEY);
		CREATE TABLE child  (id INTEGER PRIMARY KEY, parent_id INTEGER REFERENCES parent(id));
		INSERT INTO child(id, parent_id) VALUES (1, 99);  -- 99 does not exist
	`); err != nil {
		t.Fatalf("seed: %v", err)
	}
	conn.Close()

	rep, err := dbverify.Verify(dbPath, false)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if len(rep.ForeignKeyViolations) == 0 {
		t.Fatalf("expected a foreign-key violation, got none. report=%+v", rep)
	}
	v := rep.ForeignKeyViolations[0]
	if v.Table != "child" {
		t.Errorf("violation.Table = %q, want %q", v.Table, "child")
	}
	if v.Parent != "parent" {
		t.Errorf("violation.Parent = %q, want %q", v.Parent, "parent")
	}
	if rep.OK() {
		t.Errorf("OK() should be false when FK violations are present")
	}
}

// TestVerify_DoesNotMutateDB confirms we open the DB read-only:
// the file's mtime and size must not change as a result of Verify.
func TestVerify_DoesNotMutateDB(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "state.db")
	db, err := statedb.Open(dbPath)
	if err != nil {
		t.Fatalf("statedb.Open: %v", err)
	}
	db.Close()

	before, err := os.Stat(dbPath)
	if err != nil {
		t.Fatalf("stat before: %v", err)
	}

	if _, err := dbverify.Verify(dbPath, true); err != nil {
		t.Fatalf("Verify: %v", err)
	}

	after, err := os.Stat(dbPath)
	if err != nil {
		t.Fatalf("stat after: %v", err)
	}
	if before.Size() != after.Size() {
		t.Errorf("Verify changed file size: %d → %d", before.Size(), after.Size())
	}
	if !before.ModTime().Equal(after.ModTime()) {
		t.Errorf("Verify changed mtime: %v → %v", before.ModTime(), after.ModTime())
	}
}

func quickName(q bool) string {
	if q {
		return "quick_check"
	}
	return "integrity_check"
}
