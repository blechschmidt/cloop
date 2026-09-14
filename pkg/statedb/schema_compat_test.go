package statedb

// Tests for compatibility-aware version skew (Task 20254).
//
// The outage these exist to prevent: a development build applied
// 0034_telemetry.sql — a CREATE TABLE and two CREATE INDEX, touching nothing
// that already existed — to 18 project databases at 08:44, and the hub
// deployed at 04:43 refused every one of them until the next nightly rebuild.
// The dashboard stayed up and served 18 projects with no goal, no tasks and no
// steps, because "the database will not open" and "this directory is not a
// project" were the same answer.
//
// Two properties are load-bearing and both are asserted below:
//
//	An additive migration ahead of the binary no longer refuses. That is the
//	fix.
//
//	Everything else still refuses — breaking migrations, migrations nothing
//	classified, gaps with no row at all, and databases whose bookkeeping
//	predates the compat column entirely. The fix must be a narrow relaxation
//	for a positively-identified case, not a general loosening, so the negative
//	cases outnumber the positive one on purpose.

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

// stampFutureVersionCompat is stampFutureVersion with an explicit compat
// verdict, which is what a newer build records when it applies a migration.
func stampFutureVersionCompat(t *testing.T, conn *sql.DB, ahead int, compat MigrationCompat) int {
	t.Helper()
	latest, err := LatestSchemaVersion()
	if err != nil {
		t.Fatalf("LatestSchemaVersion: %v", err)
	}
	v := latest + ahead
	if _, err := conn.Exec(
		`INSERT INTO schema_migrations(version, applied_at, name, applied_by, compat) VALUES (?, ?, ?, ?, ?)`,
		v, time.Now().UTC().Format(time.RFC3339Nano),
		"0"+strconv.Itoa(v)+"_from_the_future.sql", "dev+gfuture", string(compat),
	); err != nil {
		t.Fatalf("stamp future version %d: %v", v, err)
	}
	return v
}

// ── The classifier ───────────────────────────────────────────────────────────

func TestClassifyMigration(t *testing.T) {
	cases := []struct {
		name string
		sql  string
		want MigrationCompat
	}{{
		name: "the migration that caused the outage",
		sql: `CREATE TABLE IF NOT EXISTS telemetry_events (
			      id INTEGER PRIMARY KEY AUTOINCREMENT,
			      source TEXT NOT NULL DEFAULT ''
			  );
			  CREATE INDEX IF NOT EXISTS idx_t_source ON telemetry_events(source, id DESC);`,
		want: CompatAdditive,
	}, {
		name: "comments and blank lines do not count as statements",
		sql: `-- a leading essay about why this table exists
			  CREATE TABLE new_thing (id INTEGER PRIMARY KEY);`,
		want: CompatAdditive,
	}, {
		name: "table name jammed against its column list",
		sql:  `CREATE TABLE IF NOT EXISTS packed(id INTEGER PRIMARY KEY);`,
		want: CompatAdditive,
	}, {
		name: "a plain index on a pre-existing table only adds a query plan",
		sql:  `CREATE INDEX IF NOT EXISTS idx_tasks_status ON tasks(status);`,
		want: CompatAdditive,
	}, {
		name: "a view cannot be named by a binary that never heard of it",
		sql:  `CREATE VIEW open_tasks AS SELECT * FROM tasks WHERE status = 'pending';`,
		want: CompatAdditive,
	}, {
		// The subtle one. A unique index is a rule the old binary's INSERTs
		// must now satisfy, and it has no idea the rule exists.
		name: "a unique index on a pre-existing table is a new constraint",
		sql:  `CREATE UNIQUE INDEX idx_tasks_slug ON tasks(slug);`,
		want: CompatBreaking,
	}, {
		name: "a unique index on a table from this same migration is invisible",
		sql: `CREATE TABLE fresh (id INTEGER PRIMARY KEY, slug TEXT);
			  CREATE UNIQUE INDEX idx_fresh_slug ON fresh(slug);`,
		want: CompatAdditive,
	}, {
		name: "a trigger on a pre-existing table can reject its writes",
		sql:  `CREATE TRIGGER t_guard BEFORE INSERT ON tasks BEGIN SELECT 1; END;`,
		want: CompatBreaking,
	}, {
		name: "adding a column changes a table the old binary writes",
		sql:  `ALTER TABLE tasks ADD COLUMN executor TEXT NOT NULL DEFAULT '';`,
		want: CompatBreaking,
	}, {
		name: "dropping anything is breaking",
		sql:  `DROP TABLE obsolete;`,
		want: CompatBreaking,
	}, {
		name: "a data backfill is breaking",
		sql:  `UPDATE tasks SET status = 'pending' WHERE status = '';`,
		want: CompatBreaking,
	}, {
		name: "one breaking statement poisons an otherwise additive migration",
		sql: `CREATE TABLE fine (id INTEGER PRIMARY KEY);
			  ALTER TABLE tasks ADD COLUMN oops TEXT NOT NULL DEFAULT '';`,
		want: CompatBreaking,
	}, {
		name: "a migration with no statements is not blessed",
		sql:  "-- nothing but a comment\n",
		want: CompatBreaking,
	}, {
		name: "an unrecognised statement is not assumed safe",
		sql:  `PRAGMA journal_mode=WAL;`,
		want: CompatBreaking,
	}, {
		name: "a temporary object has no business in a migration",
		sql:  `CREATE TEMP TABLE scratch (id INTEGER);`,
		want: CompatBreaking,
	}}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := classifyMigration(tc.sql); got != tc.want {
				t.Errorf("classifyMigration = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestEmbeddedMigrationsClassifyDeterministically runs the classifier over
// every migration this binary actually ships.
//
// The assertion is not "they are all additive" — plenty are not, and saying so
// is the point of the mechanism. It is that the classifier produces a definite
// verdict for each one without panicking on real SQL, and that the specific
// migration behind the outage comes out additive.
func TestEmbeddedMigrationsClassifyDeterministically(t *testing.T) {
	migrations, err := loadMigrations()
	if err != nil {
		t.Fatalf("loadMigrations: %v", err)
	}

	var additive, breaking int
	for _, m := range migrations {
		got := classifyMigration(m.SQL)
		if got != CompatAdditive && got != CompatBreaking {
			t.Errorf("%s: classifier returned %q, want a definite verdict", m.Name, got)
		}
		// Deterministic: the verdict is recorded once and read back by another
		// build, so two evaluations disagreeing would be a latent corruption.
		if again := classifyMigration(m.SQL); again != got {
			t.Errorf("%s: classifier is not deterministic (%q then %q)", m.Name, got, again)
		}
		if got == CompatAdditive {
			additive++
		} else {
			breaking++
		}
		if strings.Contains(m.Name, "telemetry") && got != CompatAdditive {
			t.Errorf("%s is the migration that caused the outage and must classify "+
				"as additive, got %q", m.Name, got)
		}
	}
	t.Logf("%d embedded migrations: %d additive, %d breaking", len(migrations), additive, breaking)
	if additive == 0 {
		t.Error("no migration classified additive — the classifier is rejecting everything")
	}
}

// ── The guard ────────────────────────────────────────────────────────────────

// TestAdditiveMigrationAheadDoesNotRefuse is the outage, reproduced and fixed:
// a database one version ahead, whose extra migration only added tables, must
// open in a binary that predates it.
func TestAdditiveMigrationAheadDoesNotRefuse(t *testing.T) {
	path, conn := migratedDB(t)
	future := stampFutureVersionCompat(t, conn, 1, CompatAdditive)

	if _, err := Migrate(conn); err != nil {
		t.Fatalf("Migrate refused a database whose only newer migration was additive: %v", err)
	}
	if err := conn.Close(); err != nil {
		t.Fatalf("close raw conn: %v", err)
	}

	// Refusing to refuse is only useful if the database is then actually
	// usable — the hub has to be able to read and write a project from it,
	// which is the whole point of not taking the dashboard down.
	db, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer db.Close()

	// LoadStateLite is the exact call the dashboard makes per project on every
	// tick, and the exact call whose failure rendered 18 empty project cards.
	if err := db.SaveState(&State{Goal: "still serving", Status: "idle", PMMode: true}); err != nil {
		t.Fatalf("write to a forward-compatible database: %v", err)
	}
	st, err := db.LoadStateLite()
	if err != nil {
		t.Fatalf("LoadStateLite: %v", err)
	}
	if st.Goal != "still serving" {
		t.Fatalf("goal read back = %q, want %q", st.Goal, "still serving")
	}

	v, err := db.CurrentSchemaVersion()
	if err != nil {
		t.Fatalf("CurrentSchemaVersion: %v", err)
	}
	if v != future {
		t.Errorf("schema version = %d, want %d — opening must not rewrite the version", v, future)
	}
}

// TestBreakingMigrationAheadStillRefuses keeps the guard's original job intact,
// and checks the refusal now names the migration responsible.
func TestBreakingMigrationAheadStillRefuses(t *testing.T) {
	_, conn := migratedDB(t)
	stampFutureVersionCompat(t, conn, 1, CompatBreaking)

	_, err := Migrate(conn)
	if err == nil {
		t.Fatal("Migrate accepted a database with a breaking migration ahead of it")
	}
	if !errors.Is(err, ErrSchemaTooNew) {
		t.Errorf("error does not carry ErrSchemaTooNew: %v", err)
	}

	var detail *SchemaTooNewError
	if !errors.As(err, &detail) {
		t.Fatalf("error is not a *SchemaTooNewError: %T", err)
	}
	if len(detail.Blocking) != 1 {
		t.Fatalf("Blocking = %+v, want exactly the one breaking migration", detail.Blocking)
	}
	if !strings.Contains(err.Error(), "from_the_future.sql") {
		t.Errorf("refusal does not name the migration that caused it: %v", err)
	}
}

// TestUnclassifiedMigrationAheadStillRefuses is the back-compatibility case: a
// row written by a build with no notion of compat must be treated as unsafe,
// not as "no objection recorded".
func TestUnclassifiedMigrationAheadStillRefuses(t *testing.T) {
	_, conn := migratedDB(t)
	stampFutureVersionCompat(t, conn, 1, CompatUnknown)

	_, err := Migrate(conn)
	if err == nil {
		t.Fatal("an unclassified migration ahead was treated as compatible")
	}
	if !errors.Is(err, ErrSchemaTooNew) {
		t.Errorf("error does not carry ErrSchemaTooNew: %v", err)
	}
	if !strings.Contains(err.Error(), "unclassified") {
		t.Errorf("refusal does not say the migration was unclassified: %v", err)
	}
}

// TestAdditiveRunMustBeUnbroken guards the gap case. currentVersion is a MAX,
// so a database can be at v+3 while only v+1 and v+3 have rows. The missing
// one is not an absence of objection.
func TestAdditiveRunMustBeUnbroken(t *testing.T) {
	_, conn := migratedDB(t)
	stampFutureVersionCompat(t, conn, 1, CompatAdditive)
	stampFutureVersionCompat(t, conn, 3, CompatAdditive) // ahead+2 deliberately absent

	_, err := Migrate(conn)
	if err == nil {
		t.Fatal("a gap in the recorded migrations was treated as compatible")
	}
	var detail *SchemaTooNewError
	if !errors.As(err, &detail) {
		t.Fatalf("error is not a *SchemaTooNewError: %T", err)
	}
	if len(detail.Blocking) != 1 {
		t.Fatalf("Blocking = %+v, want only the unrecorded version", detail.Blocking)
	}
	if !strings.Contains(err.Error(), "unrecorded") {
		t.Errorf("refusal does not flag the unrecorded version: %v", err)
	}
}

// TestMixedRunAheadRefusesAndNamesOnlyTheBreakingOne: several versions ahead,
// only one of them a problem. The operator should be pointed at that one rather
// than left to diff the whole range.
func TestMixedRunAheadRefusesAndNamesOnlyTheBreakingOne(t *testing.T) {
	_, conn := migratedDB(t)
	stampFutureVersionCompat(t, conn, 1, CompatAdditive)
	breaking := stampFutureVersionCompat(t, conn, 2, CompatBreaking)
	stampFutureVersionCompat(t, conn, 3, CompatAdditive)

	_, err := Migrate(conn)
	if err == nil {
		t.Fatal("a breaking migration in the middle of the range was tolerated")
	}
	var detail *SchemaTooNewError
	if !errors.As(err, &detail) {
		t.Fatalf("error is not a *SchemaTooNewError: %T", err)
	}
	if len(detail.Blocking) != 1 || detail.Blocking[0].Version != breaking {
		t.Fatalf("Blocking = %+v, want only v%d", detail.Blocking, breaking)
	}
}

// TestSchemaMigrationsWithoutCompatColumnStillRefuses covers bookkeeping older
// than the column itself: nothing can be known about what is ahead, so nothing
// may be assumed.
func TestSchemaMigrationsWithoutCompatColumnStillRefuses(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	conn := openRaw(t, path)

	// The schema_migrations table as an older cloop created it.
	if _, err := conn.Exec(`
		CREATE TABLE schema_migrations (
			version    INTEGER PRIMARY KEY,
			applied_at TEXT NOT NULL,
			name       TEXT NOT NULL DEFAULT '',
			applied_by TEXT NOT NULL DEFAULT ''
		)`); err != nil {
		t.Fatalf("create legacy schema_migrations: %v", err)
	}
	latest, err := LatestSchemaVersion()
	if err != nil {
		t.Fatalf("LatestSchemaVersion: %v", err)
	}
	if _, err := conn.Exec(
		`INSERT INTO schema_migrations(version, applied_at, name) VALUES (?, ?, ?)`,
		latest+1, time.Now().UTC().Format(time.RFC3339Nano), "0999_future.sql",
	); err != nil {
		t.Fatalf("stamp future version: %v", err)
	}

	if _, err := Migrate(conn); !errors.Is(err, ErrSchemaTooNew) {
		t.Fatalf("bookkeeping without a compat column: err = %v, want ErrSchemaTooNew", err)
	}
}

// TestAllowSchemaDowngradeStillOverridesABreakingMigration keeps the operator
// escape hatch working — the new check narrows what needs it, it does not
// replace it.
func TestAllowSchemaDowngradeStillOverridesABreakingMigration(t *testing.T) {
	_, conn := migratedDB(t)
	stampFutureVersionCompat(t, conn, 1, CompatBreaking)

	t.Setenv(EnvAllowSchemaDowngrade, "1")
	if _, err := Migrate(conn); err != nil {
		t.Fatalf("the operator opt-out did not override a breaking migration: %v", err)
	}
}

// ── Recording and back-fill ──────────────────────────────────────────────────

// TestMigrateRecordsCompatForEveryMigrationItApplies: the verdict has to reach
// the database, because the binary that needs it is a different one that cannot
// see the SQL.
func TestMigrateRecordsCompatForEveryMigrationItApplies(t *testing.T) {
	_, conn := migratedDB(t)

	rows, err := conn.Query(`SELECT version, name, compat FROM schema_migrations ORDER BY version`)
	if err != nil {
		t.Fatalf("query schema_migrations: %v", err)
	}
	defer rows.Close()

	seen := 0
	for rows.Next() {
		var (
			version      int
			name, compat string
		)
		if err := rows.Scan(&version, &name, &compat); err != nil {
			t.Fatalf("scan: %v", err)
		}
		seen++
		if MigrationCompat(compat) != CompatAdditive && MigrationCompat(compat) != CompatBreaking {
			t.Errorf("v%d (%s): compat = %q, want a recorded verdict", version, name, compat)
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate: %v", err)
	}
	if seen == 0 {
		t.Fatal("no migrations recorded")
	}
}

// TestBackfillClassifiesRowsWrittenBeforeTheColumnExisted. Without this the
// mechanism would only help databases migrated after it shipped — which on a
// running deployment means no database at all until the schema next moves.
func TestBackfillClassifiesRowsWrittenBeforeTheColumnExisted(t *testing.T) {
	_, conn := migratedDB(t)

	// Simulate bookkeeping from a build that never recorded a verdict.
	if _, err := conn.Exec(`UPDATE schema_migrations SET compat = ''`); err != nil {
		t.Fatalf("blank compat: %v", err)
	}

	if _, err := Migrate(conn); err != nil {
		t.Fatalf("Migrate: %v", err)
	}

	var blank int
	if err := conn.QueryRow(
		`SELECT COUNT(*) FROM schema_migrations WHERE compat = ''`).Scan(&blank); err != nil {
		t.Fatalf("count unclassified: %v", err)
	}
	if blank != 0 {
		t.Errorf("%d migrations still unclassified after a reopen — back-fill did not run", blank)
	}
}

// TestBackfillNeverRevisesARecordedVerdict. Two builds disagreeing about a
// migration is a corruption risk; the stricter reading already in the database
// wins.
func TestBackfillNeverRevisesARecordedVerdict(t *testing.T) {
	_, conn := migratedDB(t)

	if _, err := conn.Exec(
		`UPDATE schema_migrations SET compat = ? WHERE version = 1`, string(CompatBreaking),
	); err != nil {
		t.Fatalf("force verdict: %v", err)
	}

	if _, err := Migrate(conn); err != nil {
		t.Fatalf("Migrate: %v", err)
	}

	var compat string
	if err := conn.QueryRow(
		`SELECT compat FROM schema_migrations WHERE version = 1`).Scan(&compat); err != nil {
		t.Fatalf("read back: %v", err)
	}
	if MigrationCompat(compat) != CompatBreaking {
		t.Errorf("compat = %q, want the recorded verdict to survive back-fill", compat)
	}
}
