package statedb

// Migration 0054 against the databases it will really meet (Task 20361).

import (
	"database/sql"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// taskFieldColumns are the columns 0054 declares.
var taskFieldColumns = []string{
	"assignee", "external_url", "links", "tdd_status", "tdd_score", "sprint_id",
	"complexity_size", "story_points", "on_success", "on_failure", "risk_score",
	"impact_score", "retry_budget",
}

// cloopMigrateColumns is what `cloop migrate` (pkg/migrate, stepV1toV2) runs
// against plan_tasks, copied rather than imported: it is the shape already on
// disk wherever that tool ran, and a test of today's pkg/migrate would stop
// describing those databases the day the tool changed.
var cloopMigrateColumns = []string{
	`ALTER TABLE plan_tasks ADD COLUMN assignee TEXT NOT NULL DEFAULT ''`,
	`ALTER TABLE plan_tasks ADD COLUMN external_url TEXT NOT NULL DEFAULT ''`,
	`ALTER TABLE plan_tasks ADD COLUMN links TEXT NOT NULL DEFAULT '[]'`,
}

// TestTaskFieldsMigrationIsAdditive asks the verdict this build records for
// 0054. Its SQL appends to plan_tasks, which classifyMigration now reads as
// additive-columns, but 0054 shipped before that verdict existed and keeps the
// additive every database holding it already records (Task 20388).
func TestTaskFieldsMigrationIsAdditive(t *testing.T) {
	m := embeddedMigration(t, 54)
	if got := migrationVerdict(m); got != CompatAdditive {
		t.Fatalf("%s is recorded %q, want %q: an older hub sharing the control plane "+
			"would refuse every database it is applied to", m.Name, got, CompatAdditive)
	}
}

// TestTaskFieldsMigrationAdoptsColumnsCloopMigrateAdded reproduces the hub's
// own control plane: `cloop migrate` added three of 0054's columns before
// 0018 existed, and a stranded build recorded 49 and 50 under other names. A
// plain ADD COLUMN fails there with "duplicate column name", and the nightly
// deploy would leave the hub unable to start.
func TestTaskFieldsMigrationAdoptsColumnsCloopMigrateAdded(t *testing.T) {
	for name, at := range map[string]int{
		"before 0018, as on the hub": 17,
		"just before 0054":           53,
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "state.db")
			conn := openRaw(t, path)
			if _, err := MigrateTo(conn, at); err != nil {
				t.Fatalf("MigrateTo(%d): %v", at, err)
			}
			for _, stmt := range cloopMigrateColumns {
				if _, err := conn.Exec(stmt); err != nil {
					t.Fatalf("%s: %v", stmt, err)
				}
			}
			// A value already sitting in an adopted column must be readable
			// afterwards, not reset.
			if _, err := conn.Exec(`INSERT INTO plan_tasks(id, title, status, assignee, links)
				VALUES (1, 'carried over', 'pending', 'alice', '[{"url":"https://t/1","kind":"ticket"}]')`); err != nil {
				t.Fatalf("seed a task: %v", err)
			}
			if at < 49 {
				if _, err := MigrateTo(conn, 48); err != nil {
					t.Fatalf("MigrateTo(48): %v", err)
				}
				recordCollided(t, conn, map[int]string{
					49: "0049_project_members.sql", 50: "0050_project_members.sql",
				})
			}

			rep, err := Migrate(conn)
			if err != nil {
				t.Fatalf("Migrate over the columns cloop migrate added: %v", err)
			}
			if !containsInt(rep.Applied, 54) {
				t.Fatalf("0054 not applied: %+v", rep)
			}
			assertTaskFieldColumns(t, conn)

			db, err := Open(path)
			if err != nil {
				t.Fatalf("Open: %v", err)
			}
			defer db.Close()
			task, err := db.LoadTask(1)
			if err != nil {
				t.Fatalf("LoadTask: %v", err)
			}
			if task.Assignee != "alice" || len(task.Links) != 1 || task.Links[0].URL != "https://t/1" {
				t.Errorf("the adopted columns' values were lost: assignee %q, links %+v", task.Assignee, task.Links)
			}
			if len(task.OnSuccess) != 0 || task.RetryBudget != 0 {
				t.Errorf("a column 0054 added does not read as unset on an existing row: %+v", task)
			}
		})
	}
}

// TestTaskFieldsMigrationAddsEveryColumnToAFreshDatabase is the ordinary case,
// where IF NOT EXISTS finds nothing and every column is added.
func TestTaskFieldsMigrationAddsEveryColumnToAFreshDatabase(t *testing.T) {
	conn := openRaw(t, filepath.Join(t.TempDir(), "state.db"))
	if _, err := MigrateTo(conn, 53); err != nil {
		t.Fatalf("MigrateTo(53): %v", err)
	}
	if _, err := conn.Exec(`INSERT INTO plan_tasks(id, title) VALUES (1, 'old row')`); err != nil {
		t.Fatal(err)
	}
	if _, err := Migrate(conn); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	assertTaskFieldColumns(t, conn)
	var links, onSuccess string
	var budget int
	if err := conn.QueryRow(`SELECT links, on_success, retry_budget FROM plan_tasks WHERE id = 1`).
		Scan(&links, &onSuccess, &budget); err != nil {
		t.Fatal(err)
	}
	if links != "[]" || onSuccess != "[]" || budget != 0 {
		t.Errorf("an existing row read links=%q on_success=%q retry_budget=%d, want the defaults", links, onSuccess, budget)
	}
}

// TestTaskFieldsMigrationRefusesAColumnOfAnotherShape: adopting a column that
// is not the one declared would move the failure from the deploy, where it is
// named, to every load afterwards.
func TestTaskFieldsMigrationRefusesAColumnOfAnotherShape(t *testing.T) {
	for name, stmt := range map[string]string{
		"another type":    `ALTER TABLE plan_tasks ADD COLUMN links BLOB NOT NULL DEFAULT '[]'`,
		"nullable":        `ALTER TABLE plan_tasks ADD COLUMN on_success TEXT`,
		"another default": `ALTER TABLE plan_tasks ADD COLUMN on_failure TEXT NOT NULL DEFAULT ''`,
	} {
		t.Run(name, func(t *testing.T) {
			conn := openRaw(t, filepath.Join(t.TempDir(), "state.db"))
			if _, err := MigrateTo(conn, 53); err != nil {
				t.Fatalf("MigrateTo(53): %v", err)
			}
			if _, err := conn.Exec(stmt); err != nil {
				t.Fatalf("%s: %v", stmt, err)
			}
			column := strings.Fields(stmt)[5]

			_, err := Migrate(conn)
			if err == nil {
				t.Fatalf("Migrate adopted plan_tasks.%s of another shape", column)
			}
			msg := err.Error()
			if !strings.Contains(msg, "plan_tasks."+column+" already exists as") ||
				!strings.Contains(msg, "DROP COLUMN "+column) {
				t.Errorf("the error does not name the column and the way out: %v", err)
			}
			// The migration's transaction rolled back: the version did not
			// move and none of the other columns were left half-added.
			if v, _ := currentVersion(conn); v != 53 {
				t.Errorf("schema version = %d after a failed 0054, want 53", v)
			}
			if has, _ := hasColumn(conn, "plan_tasks", "retry_budget"); has {
				t.Error("a failed 0054 left retry_budget behind")
			}
		})
	}
}

// TestTaskFieldsMigrationCanBeAssertedAgain: a database that recorded 54 from
// some other file — the collision that already happened to 37, 38 and 47–50 —
// is repaired by re-running these statements in a later migration, and that
// only works if they are harmless where they have already run.
func TestTaskFieldsMigrationCanBeAssertedAgain(t *testing.T) {
	conn := openRaw(t, filepath.Join(t.TempDir(), "state.db"))
	if _, err := Migrate(conn); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	m := embeddedMigration(t, 54)
	tx, err := conn.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback() //nolint:errcheck
	for i, stmt := range splitStatements(m.SQL) {
		add, ok := parseAddColumnIfNotExists(stmt)
		if !ok {
			t.Fatalf("statement %d of %s is not the idempotent form: %s", i+1, m.Name, stmt)
		}
		if err := add.apply(tx); err != nil {
			t.Errorf("re-running statement %d: %v", i+1, err)
		}
	}
}

func TestParseAddColumnIfNotExists(t *testing.T) {
	for stmt, want := range map[string]addColumnIfNotExists{
		`ALTER TABLE plan_tasks ADD COLUMN IF NOT EXISTS links TEXT NOT NULL DEFAULT '[]'`: {
			"plan_tasks", "links", `TEXT NOT NULL DEFAULT '[]'`},
		"alter table t\n  add if not exists c   INTEGER": {"t", "c", "INTEGER"},
	} {
		got, ok := parseAddColumnIfNotExists(stmt)
		if !ok || got != want {
			t.Errorf("parse(%q) = %+v, %v; want %+v", stmt, got, ok, want)
		}
	}
	for _, stmt := range []string{
		`ALTER TABLE t ADD COLUMN c TEXT`, // SQLite's own form is SQLite's to run
		`ALTER TABLE "t" ADD COLUMN IF NOT EXISTS c TEXT`,
		`ALTER TABLE t ADD COLUMN IF NOT EXISTS c`, // no declaration
		`CREATE TABLE IF NOT EXISTS t (c TEXT)`,
	} {
		if got, ok := parseAddColumnIfNotExists(stmt); ok {
			t.Errorf("parse(%q) = %+v, want no match", stmt, got)
		}
	}
}

func embeddedMigration(t *testing.T, version int) migration {
	t.Helper()
	all, err := loadMigrations()
	if err != nil {
		t.Fatalf("loadMigrations: %v", err)
	}
	for _, m := range all {
		if m.Version == version {
			return m
		}
	}
	t.Fatalf("migration %04d is not embedded", version)
	return migration{}
}

func recordCollided(t *testing.T, conn *sql.DB, collided map[int]string) {
	t.Helper()
	now := time.Now().UTC().Format(time.RFC3339Nano)
	for v, file := range collided {
		if _, err := conn.Exec(`INSERT INTO schema_migrations(version, applied_at, name, applied_by, compat)
			VALUES (?, ?, ?, 'stranded', 'additive')`, v, now, file); err != nil {
			t.Fatalf("record collided version %d: %v", v, err)
		}
	}
}

func assertTaskFieldColumns(t *testing.T, conn *sql.DB) {
	t.Helper()
	for _, c := range taskFieldColumns {
		if has, err := hasColumn(conn, "plan_tasks", c); err != nil || !has {
			t.Errorf("plan_tasks.%s missing after 0054 (%v)", c, err)
		}
	}
}

func containsInt(xs []int, x int) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}
