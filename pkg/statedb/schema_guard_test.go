package statedb

// Tests for the version-skew guard (Task 20226).
//
// The bug these cover is one of omission: the migration loop skipped everything
// at or below the recorded version and never asked whether the recorded version
// was above anything it knew. So the assertions come in pairs — the new refusal
// fires, and the two paths that must NOT trip over it (an ordinary forward
// migration, and the pre-framework baseline adoption) still behave.

import (
	"database/sql"
	"errors"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

// stampFutureVersion records a schema_migrations row above anything this binary
// embeds, which is exactly what a database migrated by a newer cloop looks like
// to this one. Writing the row directly is the point: there is no migration to
// run, only a claim the older binary has to notice.
func stampFutureVersion(t *testing.T, conn *sql.DB, ahead int, appliedBy string) int {
	t.Helper()
	latest, err := LatestSchemaVersion()
	if err != nil {
		t.Fatalf("LatestSchemaVersion: %v", err)
	}
	v := latest + ahead
	if _, err := conn.Exec(
		`INSERT INTO schema_migrations(version, applied_at, name, applied_by) VALUES (?, ?, ?, ?)`,
		v, time.Now().UTC().Format(time.RFC3339Nano),
		"0"+strconv.Itoa(v)+"_from_the_future.sql", appliedBy,
	); err != nil {
		t.Fatalf("stamp future version %d: %v", v, err)
	}
	return v
}

// migratedDB returns a path to a fully migrated database and a raw connection
// to it, so a test can tamper with schema_migrations before reopening.
func migratedDB(t *testing.T) (string, *sql.DB) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "state.db")
	conn := openRaw(t, path)
	if _, err := Migrate(conn); err != nil {
		t.Fatalf("initial Migrate: %v", err)
	}
	return path, conn
}

// ── The refusal ──────────────────────────────────────────────────────────────

// TestMigrate_RefusesSchemaOneVersionAhead is the core case from the task: a
// database stamped a single version past this binary must be refused, not
// silently accepted as "nothing pending".
func TestMigrate_RefusesSchemaOneVersionAhead(t *testing.T) {
	_, conn := migratedDB(t)
	future := stampFutureVersion(t, conn, 1, "v9.9.9")

	_, err := Migrate(conn)
	if err == nil {
		t.Fatal("Migrate accepted a database newer than this binary")
	}

	if !errors.Is(err, ErrSchemaTooNew) {
		t.Errorf("error does not carry ErrSchemaTooNew: %v", err)
	}
	// Callers that only know about the general case must keep working.
	if !errors.Is(err, ErrSchemaMismatch) {
		t.Errorf("error does not also carry ErrSchemaMismatch: %v", err)
	}

	var detail *SchemaTooNewError
	if !errors.As(err, &detail) {
		t.Fatalf("error is not a *SchemaTooNewError: %T", err)
	}
	latest, _ := LatestSchemaVersion()
	if detail.DBVersion != future || detail.BinaryVersion != latest {
		t.Errorf("versions = db %d / binary %d, want %d / %d",
			detail.DBVersion, detail.BinaryVersion, future, latest)
	}

	// The message has to name both numbers — "schema mismatch" alone sends an
	// operator to the wrong place.
	msg := err.Error()
	for _, want := range []string{strconv.Itoa(future), strconv.Itoa(latest)} {
		if !strings.Contains(msg, want) {
			t.Errorf("message does not name version %s: %q", want, msg)
		}
	}
	// …and the build that moved the schema forward, which is the thing an
	// operator actually has to go and re-deploy.
	if !strings.Contains(msg, "v9.9.9") {
		t.Errorf("message does not name the build that applied the newer schema: %q", msg)
	}
	// …and the way out.
	if !strings.Contains(msg, EnvAllowSchemaDowngrade) {
		t.Errorf("message does not name the opt-out: %q", msg)
	}
}

// TestMigrate_RefusalLeavesDatabaseUntouched: a guard that writes to the
// database it just declared unsafe to touch is not a guard. Checked against the
// provenance column in particular, because it is added a few lines after the
// refusal and would be the easy thing to get wrong.
func TestMigrate_RefusalLeavesDatabaseUntouched(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	conn := openRaw(t, path)

	// A pre-provenance schema_migrations, as an older binary would have left
	// it, holding a version from the future.
	if _, err := conn.Exec(`
		CREATE TABLE schema_migrations (
			version    INTEGER PRIMARY KEY,
			applied_at TEXT    NOT NULL,
			name       TEXT    NOT NULL DEFAULT ''
		)`); err != nil {
		t.Fatalf("create legacy schema_migrations: %v", err)
	}
	latest, _ := LatestSchemaVersion()
	if _, err := conn.Exec(
		`INSERT INTO schema_migrations(version, applied_at, name) VALUES (?, ?, ?)`,
		latest+1, time.Now().UTC().Format(time.RFC3339Nano), "9999_future.sql",
	); err != nil {
		t.Fatalf("seed future row: %v", err)
	}

	if _, err := Migrate(conn); !errors.Is(err, ErrSchemaTooNew) {
		t.Fatalf("Migrate: want ErrSchemaTooNew, got %v", err)
	}

	has, err := hasColumn(conn, "schema_migrations", "applied_by")
	if err != nil {
		t.Fatalf("hasColumn: %v", err)
	}
	if has {
		t.Error("the refusal altered schema_migrations on a database it declined to open")
	}
	// The refusal still reported what it could, without the build name.
	var count int
	if err := conn.QueryRow(`SELECT COUNT(*) FROM schema_migrations`).Scan(&count); err != nil {
		t.Fatalf("count rows: %v", err)
	}
	if count != 1 {
		t.Errorf("schema_migrations rows = %d, want 1 (nothing added)", count)
	}
}

// TestMigrate_RefusalWithoutProvenance covers a database whose newer binary
// never stamped itself: the refusal must still fire, just without naming a
// build.
func TestMigrate_RefusalWithoutProvenance(t *testing.T) {
	_, conn := migratedDB(t)
	stampFutureVersion(t, conn, 3, "")

	_, err := Migrate(conn)
	if !errors.Is(err, ErrSchemaTooNew) {
		t.Fatalf("Migrate: want ErrSchemaTooNew, got %v", err)
	}
	if !strings.Contains(err.Error(), "unidentified build") {
		t.Errorf("message should admit the build is unknown: %q", err.Error())
	}
}

// TestOpen_RefusesFutureSchema checks the guard at the boundary that matters:
// Open is what every command, the orchestrator and the hub go through, and the
// refusal has to arrive as a startup error rather than a handle that fails
// later on a column it does not know.
func TestOpen_RefusesFutureSchema(t *testing.T) {
	path, conn := migratedDB(t)
	stampFutureVersion(t, conn, 1, "v2.0.0")
	conn.Close()

	db, err := Open(path)
	if err == nil {
		db.Close()
		t.Fatal("Open returned a handle to a database newer than this binary")
	}
	if !errors.Is(err, ErrSchemaTooNew) {
		t.Fatalf("Open: want ErrSchemaTooNew, got %v", err)
	}
	// Open must not bury the refusal under its own generic prefix.
	if strings.HasPrefix(err.Error(), "statedb migrate:") {
		t.Errorf("refusal was wrapped in a generic prefix: %q", err.Error())
	}
	// It maps to a 500 like any other schema fault, via the ErrSchemaMismatch
	// alias — the point of that alias is that no existing caller had to change.
	if got := HTTPStatus(err); got != 500 {
		t.Errorf("HTTPStatus = %d, want 500", got)
	}
}

// ── The opt-out ──────────────────────────────────────────────────────────────

func TestOpen_FutureSchemaOptOutViaEnv(t *testing.T) {
	path, conn := migratedDB(t)
	future := stampFutureVersion(t, conn, 1, "v2.0.0")
	conn.Close()

	t.Setenv(EnvAllowSchemaDowngrade, "1")

	db, err := Open(path)
	if err != nil {
		t.Fatalf("Open with the opt-out set: %v", err)
	}
	defer db.Close()

	v, err := db.CurrentSchemaVersion()
	if err != nil {
		t.Fatalf("CurrentSchemaVersion: %v", err)
	}
	if v != future {
		t.Errorf("CurrentSchemaVersion = %d, want %d", v, future)
	}
}

func TestAllowSchemaDowngradeFromEnv(t *testing.T) {
	for _, tc := range []struct {
		set  string
		want bool
	}{
		{"1", true}, {"true", true}, {"TRUE", true}, {"yes", true}, {"on", true},
		{"", false}, {"0", false}, {"false", false}, {"no", false}, {"maybe", false},
	} {
		t.Setenv(EnvAllowSchemaDowngrade, tc.set)
		if got := AllowSchemaDowngradeFromEnv(); got != tc.want {
			t.Errorf("%s=%q: got %v, want %v", EnvAllowSchemaDowngrade, tc.set, got, tc.want)
		}
	}
}

// TestOpenWithOptions_FutureSchemaOptOut: the programmatic opt-out, which is
// how `cloop hub doctor` reads a database the hub would refuse.
func TestOpenWithOptions_FutureSchemaOptOut(t *testing.T) {
	path, conn := migratedDB(t)
	stampFutureVersion(t, conn, 2, "v3.1.4")
	conn.Close()

	db, err := OpenWithOptions(path, OpenOptions{AllowSchemaDowngrade: true})
	if err != nil {
		t.Fatalf("OpenWithOptions: %v", err)
	}
	defer db.Close()

	stamp, err := db.SchemaStamp()
	if err != nil {
		t.Fatalf("SchemaStamp: %v", err)
	}
	if stamp.AppliedBy != "v3.1.4" {
		t.Errorf("SchemaStamp.AppliedBy = %q, want v3.1.4", stamp.AppliedBy)
	}
}

// ── The paths that must not regress ──────────────────────────────────────────

// TestMigrate_ForwardPathStillApplies: the ordinary case. An older database
// opened by a newer binary migrates forward exactly as before — the guard only
// looks in the other direction.
func TestMigrate_ForwardPathStillApplies(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	conn := openRaw(t, path)

	latest, err := LatestSchemaVersion()
	if err != nil {
		t.Fatalf("LatestSchemaVersion: %v", err)
	}
	if latest < 2 {
		t.Skip("need at least two migrations to build a partially-migrated database")
	}

	// Stop short, the way a release from N-1 versions ago left it.
	partial, err := MigrateTo(conn, latest-1)
	if err != nil {
		t.Fatalf("MigrateTo(%d): %v", latest-1, err)
	}
	if partial.EndVersion != latest-1 {
		t.Fatalf("partial EndVersion = %d, want %d", partial.EndVersion, latest-1)
	}

	// Now the current binary opens it.
	report, err := Migrate(conn)
	if err != nil {
		t.Fatalf("forward Migrate: %v", err)
	}
	if report.StartVersion != latest-1 || report.EndVersion != latest {
		t.Errorf("Start/End = %d/%d, want %d/%d",
			report.StartVersion, report.EndVersion, latest-1, latest)
	}
	if len(report.Applied) != 1 || report.Applied[0] != latest {
		t.Errorf("Applied = %v, want [%d]", report.Applied, latest)
	}
}

// TestMigrate_BaselineAdoptionSurvivesTheGuard: detectBaseline runs on a
// database whose recorded version is 0, and 0 is below every embedded
// migration — but the guard sits between currentVersion and the adoption, so
// "still works" is worth asserting rather than assuming.
func TestMigrate_BaselineAdoptionSurvivesTheGuard(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	conn := openRaw(t, path)

	// A pre-framework database: 0001's tables, no schema_migrations at all.
	embedded, err := loadMigrations()
	if err != nil {
		t.Fatalf("loadMigrations: %v", err)
	}
	for _, stmt := range splitStatements(embedded[0].SQL) {
		if _, err := conn.Exec(stmt); err != nil {
			t.Fatalf("seed v1: %v", err)
		}
	}
	if _, err := conn.Exec(`INSERT INTO metadata(key, value) VALUES('marker','preserved')`); err != nil {
		t.Fatalf("insert marker: %v", err)
	}

	report, err := Migrate(conn)
	if err != nil {
		t.Fatalf("Migrate on a pre-framework DB: %v", err)
	}
	if !report.BaselineApplied {
		t.Error("BaselineApplied = false; the guard must not have displaced the adoption")
	}
	if report.StartVersion != 0 {
		t.Errorf("StartVersion = %d, want 0", report.StartVersion)
	}
	latest, _ := LatestSchemaVersion()
	if report.EndVersion != latest {
		t.Errorf("EndVersion = %d, want %d", report.EndVersion, latest)
	}

	var marker string
	if err := conn.QueryRow(`SELECT value FROM metadata WHERE key='marker'`).Scan(&marker); err != nil {
		t.Fatalf("marker disappeared: %v", err)
	}
	if marker != "preserved" {
		t.Errorf("marker = %q, want preserved — 0001 was re-run", marker)
	}
}

// TestMigrate_AdoptsLegacySchemaMigrationsTable: a database whose
// schema_migrations predates applied_by must gain the column and keep every row
// it already had, rather than being mistaken for a skew or re-migrated.
func TestMigrate_AdoptsLegacySchemaMigrationsTable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	conn := openRaw(t, path)

	if _, err := conn.Exec(`
		CREATE TABLE schema_migrations (
			version    INTEGER PRIMARY KEY,
			applied_at TEXT    NOT NULL,
			name       TEXT    NOT NULL DEFAULT ''
		)`); err != nil {
		t.Fatalf("create legacy schema_migrations: %v", err)
	}

	report, err := Migrate(conn)
	if err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	latest, _ := LatestSchemaVersion()
	if report.EndVersion != latest {
		t.Errorf("EndVersion = %d, want %d", report.EndVersion, latest)
	}

	has, err := hasColumn(conn, "schema_migrations", "applied_by")
	if err != nil {
		t.Fatalf("hasColumn: %v", err)
	}
	if !has {
		t.Fatal("applied_by was not added to a legacy schema_migrations table")
	}

	// Second open must not try to add it again.
	if _, err := Migrate(conn); err != nil {
		t.Fatalf("second Migrate over the adopted table: %v", err)
	}
}

// ── Provenance ───────────────────────────────────────────────────────────────

// TestMigrate_StampsBinaryVersion: without this, the refusal can name two
// numbers but not the build an operator has to go and re-deploy.
func TestMigrate_StampsBinaryVersion(t *testing.T) {
	prev := binaryVersion()
	t.Cleanup(func() { SetBinaryVersion(prev) })
	SetBinaryVersion("v1.2.3-test")

	path := filepath.Join(t.TempDir(), "state.db")
	db, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer db.Close()

	stamp, err := db.SchemaStamp()
	if err != nil {
		t.Fatalf("SchemaStamp: %v", err)
	}
	latest, _ := LatestSchemaVersion()
	if stamp.Version != latest {
		t.Errorf("stamp.Version = %d, want %d", stamp.Version, latest)
	}
	if stamp.AppliedBy != "v1.2.3-test" {
		t.Errorf("stamp.AppliedBy = %q, want v1.2.3-test", stamp.AppliedBy)
	}
	if stamp.AppliedAt.IsZero() {
		t.Error("stamp.AppliedAt is zero; the applied_at row was not parsed")
	}
	if !strings.HasSuffix(stamp.Name, ".sql") {
		t.Errorf("stamp.Name = %q, want the migration filename", stamp.Name)
	}
}

// TestSchemaStamp_EmptyDatabase: no recorded migrations is not a fault.
func TestSchemaStamp_EmptyDatabase(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	conn := openRaw(t, path)
	if err := ensureMigrationsTable(conn); err != nil {
		t.Fatalf("ensureMigrationsTable: %v", err)
	}
	db := &DB{conn: conn}

	stamp, err := db.SchemaStamp()
	if err != nil {
		t.Fatalf("SchemaStamp on an empty database: %v", err)
	}
	if stamp != (SchemaStamp{}) {
		t.Errorf("SchemaStamp = %+v, want zero", stamp)
	}
}

func TestParseStampTime(t *testing.T) {
	for _, tc := range []struct {
		in       string
		wantZero bool
	}{
		{"2026-09-12T10:04:11.123456789Z", false},
		{"2026-09-12T10:04:11Z", false},
		{"2026-09-12 10:04:11", false}, // datetime('now'), written by hand
		{"", true},
		{"not a time", true},
	} {
		got := parseStampTime(tc.in)
		if got.IsZero() != tc.wantZero {
			t.Errorf("parseStampTime(%q).IsZero() = %v, want %v", tc.in, got.IsZero(), tc.wantZero)
		}
	}
}
