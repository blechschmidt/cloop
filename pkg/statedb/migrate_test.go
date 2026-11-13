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
	"time"

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

// TestMigrateNamesADivergentVersion is the regression for a migration that was
// applied never and reported nowhere.
//
// Two changes developed in parallel both take the next free number, because the
// contiguity check only ever sees one tree. Whichever lands second is skipped
// against every database the first one already touched — its column is missing,
// the code that selects it fails at runtime, and schema_migrations says the
// database is current. Nothing said otherwise until this check existed.
func TestMigrateNamesADivergentVersion(t *testing.T) {
	db := openRaw(t, filepath.Join(t.TempDir(), "state.db"))
	if _, err := Migrate(db); err != nil {
		t.Fatalf("Migrate: %v", err)
	}

	// Rewrite one recorded name to something no file has, which is exactly the
	// state a same-numbered sibling migration leaves behind.
	migs, err := loadMigrations()
	if err != nil {
		t.Fatalf("loadMigrations: %v", err)
	}
	victim := migs[len(migs)-1]
	if _, err := db.Exec(
		`UPDATE schema_migrations SET name = ? WHERE version = ?`,
		"0999_somebody_elses_change.sql", victim.Version,
	); err != nil {
		t.Fatalf("stage the divergence: %v", err)
	}

	report, err := Migrate(db)
	if err != nil {
		t.Fatalf("Migrate must not refuse a divergent name — that would turn a fixable "+
			"skew into an outage: %v", err)
	}
	// Since Task 48 the finding is repaired as well as named, so it arrives in
	// Recovered. Divergent keeps its meaning — a migration still missing — and
	// is therefore empty here.
	if len(report.Recovered) != 1 {
		t.Fatalf("Recovered = %+v, want exactly the one version whose name was rewritten",
			report.Recovered)
	}
	got := report.Recovered[0]
	if got.Version != victim.Version || got.Embedded != victim.Name {
		t.Errorf("Recovered[0] = %+v, want version %d embedded as %q",
			got, victim.Version, victim.Name)
	}
	if got.Recorded != "0999_somebody_elses_change.sql" {
		t.Errorf("Recovered[0].Recorded = %q, want the name the database actually holds",
			got.Recorded)
	}
	if len(report.Divergent) != 0 {
		t.Errorf("Divergent = %+v, want nothing: the skipped migration has been applied",
			report.Divergent)
	}

	// The recorded name is history and must survive the repair: version N
	// really was applied from the other file. Overwriting it would destroy the
	// only evidence of what happened.
	var recorded string
	if err := db.QueryRow(`SELECT name FROM schema_migrations WHERE version = ?`,
		victim.Version).Scan(&recorded); err != nil {
		t.Fatalf("read back the recorded name: %v", err)
	}
	if recorded != "0999_somebody_elses_change.sql" {
		t.Errorf("schema_migrations.name = %q after repair, want the name the database "+
			"actually applied", recorded)
	}

	// And the repair is not repeated: a second open finds the bookkeeping row
	// and reports nothing at all, which is what stops the warning recurring on
	// every start for the life of the database.
	again, err := Migrate(db)
	if err != nil {
		t.Fatalf("Migrate (second): %v", err)
	}
	if len(again.Recovered) != 0 || len(again.Divergent) != 0 {
		t.Errorf("second Migrate reported Recovered=%+v Divergent=%+v, want both empty",
			again.Recovered, again.Divergent)
	}
}

// TestMigrateRepairsASkippedMigrationsEffects is the half of the repair that
// matters to the running hub: not the bookkeeping, but the table that was
// missing.
//
// It stages the real failure — the version number is recorded, so the apply
// loop skips the file, and the object the binary expects is simply not there
// — and asserts that opening the database puts it back.
func TestMigrateRepairsASkippedMigrationsEffects(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	db := openRaw(t, path)

	migs, err := loadMigrations()
	if err != nil {
		t.Fatalf("loadMigrations: %v", err)
	}
	// 0048_autoupdate_policy.sql is the migration this deployment actually
	// lost, to a sibling that took version 48 first; it creates one table,
	// which makes "was it applied" a question with a yes/no answer.
	var victim migration
	for _, m := range migs {
		if m.Name == "0048_autoupdate_policy.sql" {
			victim = m
		}
	}
	if victim.Name == "" {
		t.Skip("0048_autoupdate_policy.sql is no longer embedded")
	}

	// Migrate to just before it, then record its version under the name of the
	// file that beat it to the number. That is precisely the state a
	// duplicate-numbered pair leaves behind.
	if _, err := MigrateTo(db, victim.Version-1); err != nil {
		t.Fatalf("MigrateTo(%d): %v", victim.Version-1, err)
	}
	if _, err := db.Exec(
		`INSERT INTO schema_migrations(version, applied_at, name, applied_by, compat)
		 VALUES (?, ?, ?, ?, ?)`,
		victim.Version, time.Now().UTC().Format(time.RFC3339Nano),
		"0048_egress_firewall_rules.sql", "test", "additive",
	); err != nil {
		t.Fatalf("stage the skipped migration: %v", err)
	}

	if mustHaveTable(t, db, "autoupdate_policy") {
		t.Fatal("staging is wrong: the table the skipped migration creates is already there")
	}

	report, err := Migrate(db)
	if err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	if !mustHaveTable(t, db, "autoupdate_policy") {
		t.Fatalf("the skipped migration's table is still missing after Migrate; "+
			"Recovered=%+v Divergent=%+v", report.Recovered, report.Divergent)
	}
	if len(report.Divergent) != 0 {
		t.Errorf("Divergent = %+v, want nothing left missing", report.Divergent)
	}
}

// TestRepairAdoptsAColumnTheDisplacingSiblingAlreadyAdded covers the collision
// the repair exists to survive.
//
// A migration that lost its number to a near-twin is replayed against a
// database the twin already changed, so its ALTER TABLE ... ADD COLUMN meets
// its own column. SQLite has no idempotent spelling for that statement and
// fails the whole transaction with "duplicate column name"; the repair runs it
// through addcolumn.go instead, which adopts a column of the declared shape.
func TestRepairAdoptsAColumnTheDisplacingSiblingAlreadyAdded(t *testing.T) {
	db := openRaw(t, filepath.Join(t.TempDir(), "state.db"))
	if _, err := Migrate(db); err != nil {
		t.Fatalf("Migrate: %v", err)
	}

	// sessions.claims_as_of is added by 0038_session_claim_freshness.sql, and
	// on the hub's own database that file lost version 38 while its columns
	// arrived anyway under 39. Reproduce both halves: the column is present,
	// and the migration that declares it is recorded under someone else's name.
	if _, err := db.Exec(
		`UPDATE schema_migrations SET name = ? WHERE version = ?`,
		"0038_somebody_elses_change.sql", 38,
	); err != nil {
		t.Fatalf("stage the divergence: %v", err)
	}

	report, err := Migrate(db)
	if err != nil {
		t.Fatalf("Migrate must not fail on a column that is already there: %v", err)
	}
	if len(report.Divergent) != 0 {
		t.Errorf("Divergent = %+v, want the repair to have adopted the existing column",
			report.Divergent)
	}
	if len(report.Recovered) != 1 || report.Recovered[0].Version != 38 {
		t.Errorf("Recovered = %+v, want version 38 repaired", report.Recovered)
	}
}

// TestARepairThatCannotBeMadeIsNotFatal is the safety net under the whole
// repair path, and the reason it is allowed to run unattended on every open.
//
// Migrate is called by Open, which every cloop process does before it does
// anything else. If a repair that fails took the database down with it, a
// divergence — today a warning an operator can act on at their leisure —
// would become every hub refusing to start. So a repair that cannot be made
// must leave exactly the state that existed before repairs did: the database
// open, the divergence reported, the warning printed.
func TestARepairThatCannotBeMadeIsNotFatal(t *testing.T) {
	db := openRaw(t, filepath.Join(t.TempDir(), "state.db"))
	if _, err := Migrate(db); err != nil {
		t.Fatalf("Migrate: %v", err)
	}

	// 0047_executor_sandbox_network.sql adds a column to executor_sandbox.
	// Take the table away and the statement cannot run at all — no adoption,
	// no idempotent reading of it, just SQLite refusing.
	if _, err := db.Exec(`DROP TABLE executor_sandbox`); err != nil {
		t.Fatalf("stage the unrepairable divergence: %v", err)
	}
	if _, err := db.Exec(
		`UPDATE schema_migrations SET name = ? WHERE version = ?`,
		"0047_somebody_elses_change.sql", 47,
	); err != nil {
		t.Fatalf("stage the divergence: %v", err)
	}

	report, err := Migrate(db)
	if err != nil {
		t.Fatalf("a failed repair must not refuse the database — that would turn a warning "+
			"into an outage for every process that opens it: %v", err)
	}
	if len(report.Recovered) != 0 {
		t.Errorf("Recovered = %+v, want nothing: the repair could not be made", report.Recovered)
	}
	if len(report.Divergent) != 1 || report.Divergent[0].Version != 47 {
		t.Fatalf("Divergent = %+v, want the unrepaired version 47 still reported",
			report.Divergent)
	}

	// And it is not recorded as repaired, so the next open tries again rather
	// than believing a repair that never happened.
	var n int
	if err := db.QueryRow(
		`SELECT COUNT(*) FROM schema_migration_repairs WHERE name = ?`,
		"0047_executor_sandbox_network.sql").Scan(&n); err != nil {
		t.Fatalf("read schema_migration_repairs: %v", err)
	}
	if n != 0 {
		t.Errorf("the failed repair was recorded as done (%d rows); the next open would "+
			"skip it and the migration would stay missing for good", n)
	}
}

// mustHaveTable reports whether the database holds a table of that name,
// failing the test if the question itself cannot be asked.
func mustHaveTable(t *testing.T, db *sql.DB, name string) bool {
	t.Helper()
	ok, err := tableExists(db, name)
	if err != nil {
		t.Fatalf("look for table %s: %v", name, err)
	}
	return ok
}

// TestMigrateReportsNoDivergenceOnACleanDatabase keeps the check from warning
// about the v1 baseline row or about a database that is simply up to date.
func TestMigrateReportsNoDivergenceOnACleanDatabase(t *testing.T) {
	db := openRaw(t, filepath.Join(t.TempDir(), "state.db"))
	report, err := Migrate(db)
	if err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	if len(report.Divergent) != 0 {
		t.Errorf("a freshly migrated database reported divergence: %+v", report.Divergent)
	}
	again, err := Migrate(db)
	if err != nil {
		t.Fatalf("Migrate (second): %v", err)
	}
	if len(again.Divergent) != 0 {
		t.Errorf("a re-migrated database reported divergence: %+v", again.Divergent)
	}
}

// TestDivergenceWarningIsPrintedOnce covers the dedup added in Task 20325.
//
// A single command opens statedb more than once, so an unconditional warn
// printed the same finding several times. That noise is what displaced the
// JSON payload the Web UI's suggest panel parses; the panel is now framed
// against it either way, but one finding should still read as one finding.
func TestDivergenceWarningIsPrintedOnce(t *testing.T) {
	divergenceWarnedMu.Lock()
	saved := divergenceWarned
	divergenceWarned = map[string]struct{}{}
	divergenceWarnedMu.Unlock()
	t.Cleanup(func() {
		divergenceWarnedMu.Lock()
		divergenceWarned = saved
		divergenceWarnedMu.Unlock()
	})

	d := VersionDivergence{Version: 37, Recorded: "0037_a.sql", Embedded: "0037_b.sql"}
	if divergenceAlreadyWarned(d) {
		t.Fatal("first sighting must not be suppressed")
	}
	if !divergenceAlreadyWarned(d) {
		t.Fatal("second sighting of the same finding must be suppressed")
	}

	// A different finding at the same version is a new finding, not the one
	// already shown — suppressing it would hide a real change.
	other := VersionDivergence{Version: 37, Recorded: "0037_a.sql", Embedded: "0037_c.sql"}
	if divergenceAlreadyWarned(other) {
		t.Fatal("a different divergence at the same version must still be reported")
	}
}
