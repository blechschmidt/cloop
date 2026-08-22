package hubdoctor

// Helpers that need a real state database.
//
// They are here rather than inline because both build one through statedb's own
// Open (which migrates), so the schema under test is the schema the hub gets
// rather than a hand-written approximation that would drift.

import (
	"database/sql"
	"os"
	"path/filepath"
	"testing"

	"github.com/blechschmidt/cloop/pkg/statedb"

	_ "modernc.org/sqlite"
)

// mustInitStateDB creates .cloop/state.db and migrates it to this binary's
// latest schema.
func mustInitStateDB(t *testing.T, dir string) string {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(dir, ".cloop"), 0o755); err != nil {
		t.Fatalf("mkdir .cloop: %v", err)
	}
	path := filepath.Join(dir, ".cloop", "state.db")
	db, err := statedb.Open(path)
	if err != nil {
		t.Fatalf("statedb.Open: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("statedb.Close: %v", err)
	}
	return path
}

// recordFutureMigration stamps a version higher than any this binary carries,
// simulating a database written by a newer cloop and then rolled back onto this
// one. Writing the row directly is the point: there is no migration to run,
// only a claim in schema_migrations that this binary must notice.
func recordFutureMigration(t *testing.T, dir string) {
	t.Helper()
	latest, err := statedb.LatestSchemaVersion()
	if err != nil {
		t.Fatalf("LatestSchemaVersion: %v", err)
	}
	path := filepath.Join(dir, ".cloop", "state.db")
	raw, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("open sqlite directly: %v", err)
	}
	defer func() { _ = raw.Close() }()

	if _, err := raw.Exec(
		`INSERT INTO schema_migrations (version, name, applied_at) VALUES (?, ?, datetime('now'))`,
		latest+1, "9999_from_the_future.sql"); err != nil {
		t.Fatalf("stamp future migration: %v", err)
	}
}
