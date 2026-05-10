package statedb

// White-box tests for the migration framework. Lives in package statedb
// (not statedb_test) so it can exercise applyOne, splitStatements, and the
// helpers that simulate partial-migration recovery without spinning up a
// full *DB.

import (
	"database/sql"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	_ "modernc.org/sqlite"
)

// openRaw opens a SQLite file directly without going through statedb.Open.
// Tests use this when they need to inspect or mutate the DB before the
// migration runner gets a chance to touch it.
func openRaw(t *testing.T, path string) *sql.DB {
	t.Helper()
	conn, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("openRaw: %v", err)
	}
	conn.SetMaxOpenConns(1)
	if err := applyPragmas(conn); err != nil {
		t.Fatalf("openRaw applyPragmas: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	return conn
}

// ── splitStatements ──────────────────────────────────────────────────────────

func TestSplitStatements_DropsCommentsAndEmptyStatements(t *testing.T) {
	in := `
-- comment line
CREATE TABLE foo (x INT); -- trailing comment
;
INSERT INTO foo VALUES (1);
`
	got := splitStatements(in)
	if len(got) != 2 {
		t.Fatalf("want 2 statements, got %d: %v", len(got), got)
	}
	if !strings.Contains(got[0], "CREATE TABLE foo") {
		t.Errorf("first stmt unexpected: %q", got[0])
	}
	if !strings.Contains(got[1], "INSERT INTO foo") {
		t.Errorf("second stmt unexpected: %q", got[1])
	}
}

func TestSplitStatements_RespectsQuotedSemicolons(t *testing.T) {
	in := `INSERT INTO m VALUES ('a;b', "c;d"); SELECT 1;`
	got := splitStatements(in)
	if len(got) != 2 {
		t.Fatalf("want 2 statements, got %d: %v", len(got), got)
	}
	if !strings.Contains(got[0], "'a;b'") {
		t.Errorf("first stmt lost the quoted semicolon: %q", got[0])
	}
}

// ── parseVersion ─────────────────────────────────────────────────────────────

func TestParseVersion(t *testing.T) {
	cases := []struct {
		in      string
		want    int
		wantErr bool
	}{
		{"0001_init.sql", 1, false},
		{"0002_add_pinned.sql", 2, false},
		{"42_foo.sql", 42, false},
		{"noprefix.sql", 0, true},
		{"abc_bar.sql", 0, true},
		{"_underscore.sql", 0, true},
		{"0_zero.sql", 0, true},
	}
	for _, tc := range cases {
		got, err := parseVersion(tc.in)
		if tc.wantErr {
			if err == nil {
				t.Errorf("parseVersion(%q): expected error, got nil", tc.in)
			}
			continue
		}
		if err != nil {
			t.Errorf("parseVersion(%q): unexpected error %v", tc.in, err)
		}
		if got != tc.want {
			t.Errorf("parseVersion(%q) = %d, want %d", tc.in, got, tc.want)
		}
	}
}

// ── loadMigrations ───────────────────────────────────────────────────────────

func TestLoadMigrations_EmbeddedFilesAreDenseAndSorted(t *testing.T) {
	got, err := loadMigrations()
	if err != nil {
		t.Fatalf("loadMigrations: %v", err)
	}
	if len(got) == 0 {
		t.Fatal("expected at least one embedded migration")
	}
	for i, m := range got {
		if m.Version != i+1 {
			t.Errorf("migrations[%d].Version = %d, want %d (file %s)", i, m.Version, i+1, m.Name)
		}
		if m.SQL == "" {
			t.Errorf("migrations[%d] (%s) is empty", i, m.Name)
		}
	}
}

// ── Migrate on a fresh DB ────────────────────────────────────────────────────

func TestMigrate_FreshDB_AppliesAllMigrations(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.db")
	conn := openRaw(t, path)

	report, err := Migrate(conn)
	if err != nil {
		t.Fatalf("Migrate: %v", err)
	}

	embedded, _ := loadMigrations()
	wantEnd := embedded[len(embedded)-1].Version

	if report.StartVersion != 0 {
		t.Errorf("StartVersion = %d, want 0 (fresh DB)", report.StartVersion)
	}
	if report.EndVersion != wantEnd {
		t.Errorf("EndVersion = %d, want %d", report.EndVersion, wantEnd)
	}
	if len(report.Applied) != len(embedded) {
		t.Errorf("Applied count = %d, want %d", len(report.Applied), len(embedded))
	}
	if report.BaselineApplied {
		t.Error("BaselineApplied = true on fresh DB; expected false")
	}

	// schema_migrations rows recorded.
	var count int
	if err := conn.QueryRow(`SELECT COUNT(*) FROM schema_migrations`).Scan(&count); err != nil {
		t.Fatalf("count schema_migrations: %v", err)
	}
	if count != len(embedded) {
		t.Errorf("schema_migrations rows = %d, want %d", count, len(embedded))
	}

	// All baseline tables exist.
	for _, table := range []string{
		"metadata", "plan_tasks", "steps", "costs", "queue", "stuck_tasks",
	} {
		var name string
		err := conn.QueryRow(
			`SELECT name FROM sqlite_master WHERE type='table' AND name=?`,
			table,
		).Scan(&name)
		if err != nil {
			t.Errorf("table %q missing after migrate: %v", table, err)
		}
	}
}

// ── Migrate on an already-migrated DB is a no-op ─────────────────────────────

func TestMigrate_AlreadyMigrated_IsNoOp(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.db")

	// First migration run.
	conn := openRaw(t, path)
	if _, err := Migrate(conn); err != nil {
		t.Fatalf("first Migrate: %v", err)
	}
	conn.Close()

	// Second run on the same file.
	conn2 := openRaw(t, path)
	report, err := Migrate(conn2)
	if err != nil {
		t.Fatalf("second Migrate: %v", err)
	}
	if len(report.Applied) != 0 {
		t.Errorf("Applied = %v on already-migrated DB; want empty", report.Applied)
	}
	if report.BaselineApplied {
		t.Error("BaselineApplied = true on already-migrated DB")
	}

	embedded, _ := loadMigrations()
	wantVersion := embedded[len(embedded)-1].Version
	if report.StartVersion != wantVersion || report.EndVersion != wantVersion {
		t.Errorf("Start/End = %d/%d, want both %d",
			report.StartVersion, report.EndVersion, wantVersion)
	}
}

// ── Pre-framework DB is adopted at v1 without re-running 0001 ────────────────

func TestMigrate_BaselineAdoption_FromPreFrameworkDB(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.db")

	// Simulate a database written by an older binary: it has the user-facing
	// tables but no schema_migrations row.
	conn := openRaw(t, path)

	// Apply 0001 directly without inserting into schema_migrations, then
	// drop schema_migrations entirely so the new code thinks this is a
	// pre-framework database.
	embedded, err := loadMigrations()
	if err != nil {
		t.Fatalf("loadMigrations: %v", err)
	}
	v1 := embedded[0]
	for _, stmt := range splitStatements(v1.SQL) {
		if _, err := conn.Exec(stmt); err != nil {
			t.Fatalf("seed v1 statement: %v", err)
		}
	}
	// Insert a sentinel row so we can verify the baseline path didn't
	// re-run the migration and clobber the table.
	if _, err := conn.Exec(
		`INSERT INTO metadata(key, value) VALUES('marker', 'preserved')`,
	); err != nil {
		t.Fatalf("insert marker: %v", err)
	}

	// Now run the migration framework. It should detect the baseline and
	// record version 1 without re-applying it.
	report, err := Migrate(conn)
	if err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	if !report.BaselineApplied {
		t.Error("BaselineApplied = false; expected true for pre-framework DB")
	}

	// Marker row must still be present — proves 0001 wasn't re-run as a
	// destructive CREATE/DROP.
	var marker string
	if err := conn.QueryRow(
		`SELECT value FROM metadata WHERE key='marker'`,
	).Scan(&marker); err != nil {
		t.Fatalf("marker disappeared: %v", err)
	}
	if marker != "preserved" {
		t.Errorf("marker = %q, want 'preserved'", marker)
	}

	// schema_migrations should now have exactly one row at version 1
	// (or more if there are higher-numbered migrations, which would have
	// run normally on top of the baseline).
	var v1Count int
	if err := conn.QueryRow(
		`SELECT COUNT(*) FROM schema_migrations WHERE version=1`,
	).Scan(&v1Count); err != nil {
		t.Fatalf("count v1: %v", err)
	}
	if v1Count != 1 {
		t.Errorf("schema_migrations v1 rows = %d, want 1", v1Count)
	}
}

// ── Partial migration: failing migration rolls back cleanly ──────────────────

// TestMigrate_PartialFailureRecovery simulates a buggy migration by
// invoking applyOne directly with a SQL script that errors on the second
// statement. Verifies that the first statement's effect AND the
// schema_migrations row are both rolled back, leaving the database
// unchanged. Then a follow-up successful migration succeeds.
func TestMigrate_PartialFailureRecovery(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.db")
	conn := openRaw(t, path)

	if _, err := Migrate(conn); err != nil {
		t.Fatalf("initial Migrate: %v", err)
	}
	embedded, _ := loadMigrations()
	baselineVersion := embedded[len(embedded)-1].Version

	bogus := migration{
		Version: baselineVersion + 1,
		Name:    "9999_bogus.sql",
		SQL: `
CREATE TABLE partial_test (x INTEGER);
INSERT INTO non_existent_table VALUES (1);
`,
	}
	err := applyOne(conn, bogus)
	if err == nil {
		t.Fatal("applyOne: expected error from bogus migration, got nil")
	}

	// partial_test must NOT exist — the transaction rolled back.
	var name string
	row := conn.QueryRow(
		`SELECT name FROM sqlite_master WHERE type='table' AND name='partial_test'`,
	)
	if err := row.Scan(&name); !errors.Is(err, sql.ErrNoRows) {
		t.Errorf("partial_test table leaked through failed migration: scan err=%v name=%q", err, name)
	}

	// schema_migrations must NOT contain the bogus version.
	var bogusCount int
	if err := conn.QueryRow(
		`SELECT COUNT(*) FROM schema_migrations WHERE version=?`,
		bogus.Version,
	).Scan(&bogusCount); err != nil {
		t.Fatalf("count bogus version: %v", err)
	}
	if bogusCount != 0 {
		t.Errorf("schema_migrations recorded a failed migration: %d rows for version %d", bogusCount, bogus.Version)
	}

	// Recovery: the next successful migration on top of the same connection
	// should apply normally, proving the DB is in a usable state.
	good := migration{
		Version: baselineVersion + 1,
		Name:    "9999_good.sql",
		SQL:     `CREATE TABLE recovered (y INTEGER);`,
	}
	if err := applyOne(conn, good); err != nil {
		t.Fatalf("applyOne after rollback: %v", err)
	}

	var recovered string
	if err := conn.QueryRow(
		`SELECT name FROM sqlite_master WHERE type='table' AND name='recovered'`,
	).Scan(&recovered); err != nil {
		t.Errorf("recovered table missing after follow-up migration: %v", err)
	}
}

// ── End-to-end: Open() runs Migrate ──────────────────────────────────────────

func TestOpen_RunsMigrations(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.db")

	db, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer db.Close()

	v, err := db.CurrentSchemaVersion()
	if err != nil {
		t.Fatalf("CurrentSchemaVersion: %v", err)
	}
	embedded, _ := loadMigrations()
	want := embedded[len(embedded)-1].Version
	if v != want {
		t.Errorf("CurrentSchemaVersion() = %d, want %d", v, want)
	}
}

// TestOpen_TwiceIsIdempotent verifies that opening the same database file
// twice produces no migration churn — important because every cloop
// process opens its own *DB pointing at the same .cloop/state.db.
func TestOpen_TwiceIsIdempotent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.db")

	db1, err := Open(path)
	if err != nil {
		t.Fatalf("first Open: %v", err)
	}
	v1, _ := db1.CurrentSchemaVersion()
	db1.Close()

	db2, err := Open(path)
	if err != nil {
		t.Fatalf("second Open: %v", err)
	}
	defer db2.Close()
	v2, _ := db2.CurrentSchemaVersion()

	if v1 != v2 || v1 == 0 {
		t.Errorf("schema version drift across Opens: v1=%d v2=%d", v1, v2)
	}
}
