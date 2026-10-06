package hubdoctor

// Helpers that need a real state database.
//
// They are here rather than inline because both build one through statedb's own
// Open (which migrates), so the schema under test is the schema the hub gets
// rather than a hand-written approximation that would drift.

import (
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/internal/statedbtest"
	"github.com/blechschmidt/cloop/pkg/statedb"
	"github.com/blechschmidt/cloop/pkg/tlsconf"

	_ "modernc.org/sqlite"
)

// mustInitStateDB creates .cloop/state.db and migrates it to this binary's
// latest schema — by copying internal/statedbtest's template, which statedb.Open
// built, rather than migrating again; the Open below then finds nothing to do.
func mustInitStateDB(t *testing.T, dir string) string {
	t.Helper()
	statedbtest.SeedDir(t, dir)
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

// futureBuild is the build identifier recordFutureMigration attributes the
// newer schema to — what an operator would have to go and re-deploy.
const futureBuild = "v9.9.9-from-the-future"

// recordFutureMigration stamps a version higher than any this binary carries,
// simulating a database written by a newer cloop and then rolled back onto this
// one. Writing the row directly is the point: there is no migration to run,
// only a claim in schema_migrations that this binary must notice.
//
// applied_by is filled in because the useful half of the finding is naming the
// build that moved the schema; a test that only asserted the version numbers
// would not notice that half going missing.
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
		`INSERT INTO schema_migrations (version, name, applied_at, applied_by)
		 VALUES (?, ?, datetime('now'), ?)`,
		latest+1, "9999_from_the_future.sql", futureBuild); err != nil {
		t.Fatalf("stamp future migration: %v", err)
	}
}

// tlsPair writes a real self-signed certificate and key under a fresh
// directory and returns their paths. Real material, because the proxy checks
// load the pair the way the hub's listeners do (tlsconf.LoadServerConfig);
// they used to stat the files, and a fixture of placeholder bytes passed.
func tlsPair(t *testing.T, name string) (cert, key string) {
	t.Helper()
	dir := t.TempDir()
	cert = filepath.Join(dir, name+".crt")
	key = filepath.Join(dir, name+".key")
	if _, err := tlsconf.GenerateSelfSigned(cert, key, tlsconf.SelfSignedOptions{
		Hosts: []string{"hub.internal"}, ValidFor: time.Hour,
	}); err != nil {
		t.Fatalf("generate %s pair: %v", name, err)
	}
	return cert, key
}

// recordFutureAdditiveMigration stamps a version past this binary's, recorded
// as additive — the shape of database an older hub's guard opens anyway.
func recordFutureAdditiveMigration(t *testing.T, dir string) {
	t.Helper()
	latest, err := statedb.LatestSchemaVersion()
	if err != nil {
		t.Fatalf("LatestSchemaVersion: %v", err)
	}
	raw, err := sql.Open("sqlite", filepath.Join(dir, ".cloop", "state.db"))
	if err != nil {
		t.Fatalf("open sqlite directly: %v", err)
	}
	defer func() { _ = raw.Close() }()
	if _, err := raw.Exec(
		`INSERT INTO schema_migrations (version, name, applied_at, applied_by, compat)
		 VALUES (?, ?, datetime('now'), ?, ?)`,
		latest+1, "9999_a_new_table.sql", futureBuild, string(statedb.CompatAdditive)); err != nil {
		t.Fatalf("stamp future additive migration: %v", err)
	}
}
