package statedb

// Adopting a pre-framework database completes migration 0001's schema before
// recording version 1 (Task 20374).

import (
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// oldMigrateSchema is the schema `cloop migrate` created when it converted a
// state.json, as it shipped until Task 20374: three of 0001's six tables, with
// plan_tasks carrying the three columns migration 0054 later adopted.
const oldMigrateSchema = `
CREATE TABLE IF NOT EXISTS metadata (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS plan_tasks (
    id                INTEGER PRIMARY KEY,
    title             TEXT    NOT NULL DEFAULT '',
    description       TEXT    NOT NULL DEFAULT '',
    priority          INTEGER NOT NULL DEFAULT 5,
    status            TEXT    NOT NULL DEFAULT 'pending',
    role              TEXT    NOT NULL DEFAULT '',
    depends_on        TEXT    NOT NULL DEFAULT '[]',
    result            TEXT    NOT NULL DEFAULT '',
    started_at        TEXT,
    completed_at      TEXT,
    deadline          TEXT,
    verify_retries    INTEGER NOT NULL DEFAULT 0,
    github_issue      INTEGER NOT NULL DEFAULT 0,
    estimated_minutes INTEGER NOT NULL DEFAULT 0,
    actual_minutes    INTEGER NOT NULL DEFAULT 0,
    artifact_path     TEXT    NOT NULL DEFAULT '',
    failure_diagnosis TEXT    NOT NULL DEFAULT '',
    tags              TEXT    NOT NULL DEFAULT '[]',
    fail_count        INTEGER NOT NULL DEFAULT 0,
    heal_attempts     INTEGER NOT NULL DEFAULT 0,
    annotations       TEXT    NOT NULL DEFAULT '[]',
    condition_expr    TEXT    NOT NULL DEFAULT '',
    recurrence        TEXT    NOT NULL DEFAULT '',
    next_run_at       TEXT,
    requires_approval INTEGER NOT NULL DEFAULT 0,
    approved          INTEGER NOT NULL DEFAULT 0,
    max_minutes       INTEGER NOT NULL DEFAULT 0,
    assignee          TEXT    NOT NULL DEFAULT '',
    external_url      TEXT    NOT NULL DEFAULT '',
    links             TEXT    NOT NULL DEFAULT '[]'
);
CREATE TABLE IF NOT EXISTS steps (
    step          INTEGER PRIMARY KEY,
    task          TEXT    NOT NULL DEFAULT '',
    output        TEXT    NOT NULL DEFAULT '',
    exit_code     INTEGER NOT NULL DEFAULT 0,
    duration      TEXT    NOT NULL DEFAULT '',
    time          TEXT    NOT NULL DEFAULT '',
    input_tokens  INTEGER NOT NULL DEFAULT 0,
    output_tokens INTEGER NOT NULL DEFAULT 0
);
INSERT INTO metadata(key, value) VALUES ('goal', 'ship it'), ('schema_version', '2'), ('status', 'paused');
INSERT INTO plan_tasks(id, title, status, assignee) VALUES (1, 'first', 'done', 'ada'), (2, 'second', 'pending', '');
INSERT INTO steps(step, task, output) VALUES (1, 'first', 'it worked');
`

// Before Task 20374 this database was adopted at version 1 and migration 0009
// failed on the stuck_tasks table it never had — and so did every command that
// opened the project afterwards.
func TestOpenAdoptsADatabaseTheOldMigrateCommandMade(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	raw, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := raw.Exec(oldMigrateSchema); err != nil {
		t.Fatalf("build the old schema: %v", err)
	}
	raw.Close()

	db, err := Open(path)
	if err != nil {
		t.Fatalf("Open could not adopt the database `cloop migrate` made: %v", err)
	}
	defer db.Close()

	st, err := db.LoadState()
	if err != nil {
		t.Fatalf("LoadState: %v", err)
	}
	if st.Goal != "ship it" || st.Plan == nil || len(st.Plan.Tasks) != 2 || len(st.Steps) != 1 {
		t.Fatalf("adopted state lost data: goal=%q tasks=%v steps=%d", st.Goal, st.Plan, len(st.Steps))
	}
	if got := st.Plan.Tasks[0]; got.Title != "first" || string(got.Status) != "done" || got.Assignee != "ada" {
		t.Errorf("task 1 = %+v", got)
	}
	latest, err := LatestSchemaVersion()
	if err != nil {
		t.Fatal(err)
	}
	if v, err := db.CurrentSchemaVersion(); err != nil || v != latest {
		t.Errorf("schema version after adoption = %d (%v), want %d", v, err, latest)
	}
}

// completeBaseline runs 0001 against a populated database, which is only safe
// while every statement in it changes nothing that already exists. 0001 is
// shipped and must never be edited; this pins that it stays that way.
func TestMigration0001IsIdempotentDDLThroughout(t *testing.T) {
	migrations, err := loadMigrations()
	if err != nil {
		t.Fatal(err)
	}
	for i, stmt := range splitStatements(migrations[0].SQL) {
		if !isIdempotentDDL(stmt) {
			t.Errorf("statement %d of %s is not idempotent DDL:\n%s", i+1, migrations[0].Name, stmt)
		}
	}
	for _, s := range []string{
		"ALTER TABLE t ADD COLUMN c TEXT",
		"CREATE TABLE t (n INTEGER)",
		"DELETE FROM t",
		"INSERT INTO t VALUES (1)",
	} {
		if isIdempotentDDL(s) {
			t.Errorf("isIdempotentDDL(%q) = true", s)
		}
	}
}

// InspectSchema answers by the rules Open applies: a database it calls
// pre-framework is one Open adopts as its baseline, and afterwards it reports
// the version Open migrated it to. Asking writes nothing and creates nothing.
func TestInspectSchemaPredictsWhatOpenDoes(t *testing.T) {
	latest, err := LatestSchemaVersion()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "state.db")
	raw, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := raw.Exec(oldMigrateSchema); err != nil {
		t.Fatal(err)
	}
	raw.Close()

	before, err := InspectSchema(path)
	if err != nil {
		t.Fatal(err)
	}
	if !before.PreFramework || !before.HoldsProject || before.Version != 0 {
		t.Fatalf("before Open: %+v, want a pre-framework database holding a project", before)
	}

	conn, err := sql.Open("sqlite", connString(path))
	if err != nil {
		t.Fatal(err)
	}
	report, err := Migrate(conn)
	conn.Close()
	if err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	if !report.BaselineApplied {
		t.Fatal("InspectSchema called the database pre-framework, but Open did not adopt it as a baseline")
	}
	after, err := InspectSchema(path)
	if err != nil {
		t.Fatal(err)
	}
	if after.PreFramework || after.Version != latest || !after.HoldsProject {
		t.Fatalf("after Open: %+v, want v%d, holding the project", after, latest)
	}

	fresh := filepath.Join(t.TempDir(), "state.db")
	db, err := Open(fresh)
	if err != nil {
		t.Fatal(err)
	}
	db.Close()
	if st, err := InspectSchema(fresh); err != nil || st.PreFramework || st.HoldsProject || st.Version != latest {
		t.Fatalf("a new database: %+v, %v; want v%d holding no project", st, err, latest)
	}

	missing := filepath.Join(t.TempDir(), "state.db")
	if _, err := InspectSchema(missing); err == nil {
		t.Fatal("InspectSchema of a missing file returned no error")
	}
	if _, err := os.Stat(missing); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("InspectSchema created %s", missing)
	}
}
