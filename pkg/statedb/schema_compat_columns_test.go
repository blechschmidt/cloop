package statedb

// The additive-columns verdict (Task 20388).
//
// Builds before Task 20388 replace whole rows of plan_tasks, quota_counters
// and ci_exchanges on every write, resetting any column they do not know. A
// column appended to one of those tables is therefore additive only for the
// builds that came after: they write those rows in place. The verdict says
// exactly that — tolerable to this build and later ones, and, being a word no
// earlier build knows, a refusal for every build before.

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/pkg/pm"
)

// preColumnsTolerable is how every build from Task 20254 to Task 20387 read a
// verdict: MigrationCompat.Tolerable was `return c == CompatAdditive`. It is
// the guard of the builds this verdict exists to stop.
func preColumnsTolerable(c MigrationCompat) bool { return c == CompatAdditive }

// TestOnlyARewrittenTableGetsTheColumnsVerdict appends a column to every table
// a migrated database has. The verdict is additive-columns for the tables
// earlier builds rewrite, and additive for every other.
func TestOnlyARewrittenTableGetsTheColumnsVerdict(t *testing.T) {
	_, conn := migratedDB(t)
	rows, err := conn.Query(`SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'`)
	if err != nil {
		t.Fatalf("list tables: %v", err)
	}
	var tables []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			t.Fatalf("scan: %v", err)
		}
		tables = append(tables, name)
	}
	rows.Close()
	sort.Strings(tables)
	if len(tables) < 40 {
		t.Fatalf("only %d tables in a migrated database; this is not the schema the test is about", len(tables))
	}

	have := map[string]bool{}
	var columns []string
	for _, table := range tables {
		have[table] = true
		got := classifyMigration(`ALTER TABLE ` + table + ` ADD COLUMN later_column TEXT NOT NULL DEFAULT '';`)
		want := CompatAdditive
		if _, ok := rewrittenTables[table]; ok {
			want = CompatAdditiveColumns
			columns = append(columns, table)
		}
		if got != want {
			t.Errorf("appending to %s classifies %q, want %q", table, got, want)
		}
	}
	// A name in the list that is not a table would protect nothing.
	for table := range rewrittenTables {
		if !have[table] {
			t.Errorf("rewrittenTables names %q, which a migrated database does not have", table)
		}
	}
	if strings.Join(columns, " ") != "ci_exchanges plan_tasks quota_counters" {
		t.Errorf("the tables appended to as additive-columns are %v", columns)
	}
}

func TestColumnsVerdictShapes(t *testing.T) {
	cases := []struct {
		name string
		sql  string
		want MigrationCompat
	}{{
		name: "the COLUMN-less form",
		sql:  `ALTER TABLE plan_tasks ADD later TEXT NOT NULL DEFAULT '';`,
		want: CompatAdditiveColumns,
	}, {
		name: "a nullable column",
		sql:  `ALTER TABLE ci_exchanges ADD COLUMN later TEXT;`,
		want: CompatAdditiveColumns,
	}, {
		name: "quoted table name",
		sql:  `ALTER TABLE "quota_counters" ADD COLUMN later REAL NOT NULL DEFAULT 0;`,
		want: CompatAdditiveColumns,
	}, {
		// A rule an older binary's writes must satisfy is breaking wherever it
		// lands; the new verdict only ever replaces additive.
		name: "a constraint is still breaking",
		sql:  `ALTER TABLE plan_tasks ADD COLUMN later TEXT UNIQUE DEFAULT '';`,
		want: CompatBreaking,
	}, {
		name: "NOT NULL with no default is still breaking",
		sql:  `ALTER TABLE plan_tasks ADD COLUMN later TEXT NOT NULL;`,
		want: CompatBreaking,
	}, {
		name: "the strictest statement decides: additive-columns over additive",
		sql: `CREATE TABLE IF NOT EXISTS fresh (id INTEGER PRIMARY KEY);
		      ALTER TABLE costs ADD COLUMN note TEXT;
		      ALTER TABLE plan_tasks ADD COLUMN later TEXT NOT NULL DEFAULT '';`,
		want: CompatAdditiveColumns,
	}, {
		name: "and breaking over additive-columns",
		sql: `ALTER TABLE plan_tasks ADD COLUMN later TEXT NOT NULL DEFAULT '';
		      UPDATE plan_tasks SET later = title;`,
		want: CompatBreaking,
	}, {
		// The rewrite is of rows; an index changes none of them.
		name: "an index on a rewritten table is additive",
		sql:  `CREATE INDEX IF NOT EXISTS idx_plan_tasks_later ON plan_tasks(status, id);`,
		want: CompatAdditive,
	}, {
		// Every database has had plan_tasks since 0001, so CREATE TABLE IF NOT
		// EXISTS of it creates nothing and cannot make the append invisible.
		name: "re-declaring a rewritten table does not make it new",
		sql: `CREATE TABLE IF NOT EXISTS plan_tasks (id INTEGER PRIMARY KEY);
		      ALTER TABLE plan_tasks ADD COLUMN later TEXT NOT NULL DEFAULT '';`,
		want: CompatAdditiveColumns,
	}, {
		name: "a table of the same migration is still invisible",
		sql: `CREATE TABLE IF NOT EXISTS plan_task_notes (id INTEGER PRIMARY KEY);
		      ALTER TABLE plan_task_notes ADD COLUMN later TEXT NOT NULL;`,
		want: CompatAdditive,
	}}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := classifyMigration(tc.sql); got != tc.want {
				t.Errorf("classifyMigration = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestShippedVerdictsAreLeftAsTheyWere: 0001–0059 shipped before the verdict
// existed. Every database holding them records additive or breaking, and this
// build records the same on a database it creates, so no two disagree.
func TestShippedVerdictsAreLeftAsTheyWere(t *testing.T) {
	migrations, err := loadMigrations()
	if err != nil {
		t.Fatalf("loadMigrations: %v", err)
	}
	var appended []int
	for _, m := range migrations {
		if m.Version >= firstColumnsVerdict {
			continue
		}
		want := CompatAdditive
		if _, ok := breakingMigrations[m.Version]; ok {
			want = CompatBreaking
		}
		if got := migrationVerdict(m); got != want {
			t.Errorf("%s is recorded %q, want %q — the verdict it shipped with", m.Name, got, want)
		}
		if classifyMigration(m.SQL) == CompatAdditiveColumns {
			appended = append(appended, m.Version)
		}
	}
	// The shipped migrations whose columns builds before them erase: the ones
	// the cutoff speaks for. The list is closed — these files are never edited.
	if got := fmt.Sprint(appended); got != "[18 25 29 32 42 53 54]" {
		t.Errorf("shipped migrations appending to a rewritten table: %s, want [18 25 29 32 42 53 54]", got)
	}
	if firstColumnsVerdict-1 > len(migrations) {
		t.Errorf("firstColumnsVerdict is %d but only %d migrations are embedded", firstColumnsVerdict, len(migrations))
	}

	// From firstColumnsVerdict on, the SQL decides.
	next := migration{Version: firstColumnsVerdict, Name: "0060_later.sql",
		SQL: `ALTER TABLE plan_tasks ADD COLUMN later TEXT NOT NULL DEFAULT '';`}
	if got := migrationVerdict(next); got != CompatAdditiveColumns {
		t.Errorf("a migration %d appending to plan_tasks is recorded %q, want %q", next.Version, got, CompatAdditiveColumns)
	}
	next.Version = firstColumnsVerdict - 6
	if got := migrationVerdict(next); got != CompatAdditive {
		t.Errorf("the same SQL as migration %d is recorded %q, want %q", next.Version, got, CompatAdditive)
	}
}

// TestAColumnsVerdictAheadOpensAndItsColumnSurvives is the case the verdict is
// for: a newer build applied a migration appending to plan_tasks. This build
// opens the database, and a save through it keeps the new column.
func TestAColumnsVerdictAheadOpensAndItsColumnSurvives(t *testing.T) {
	path, conn := migratedDB(t)
	future := stampFutureVersionCompat(t, conn, 1, CompatAdditiveColumns)

	blocking, err := breakingVersionsAhead(conn, future-1, future)
	if err != nil {
		t.Fatalf("breakingVersionsAhead: %v", err)
	}
	if len(blocking) != 0 {
		t.Fatalf("this build refuses a migration recorded %q: %+v", CompatAdditiveColumns, blocking)
	}
	if _, err := Migrate(conn); err != nil {
		t.Fatalf("Migrate refused a database whose only newer migration is %q: %v", CompatAdditiveColumns, err)
	}
	if _, err := conn.Exec(`ALTER TABLE plan_tasks ADD COLUMN ` + futureColumn + ` TEXT NOT NULL DEFAULT ''`); err != nil {
		t.Fatalf("the newer build's column: %v", err)
	}
	if err := conn.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	db, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer db.Close()
	plan := &pm.Plan{Goal: "g", Tasks: []*pm.Task{futureTask(1, "one", pm.TaskPending), futureTask(2, "two", pm.TaskPending)}}
	if err := db.SaveState(&State{Goal: "g", Plan: plan}); err != nil {
		t.Fatalf("SaveState: %v", err)
	}
	if _, err := db.conn.Exec(`UPDATE plan_tasks SET ` + futureColumn + ` = 'kept by ' || id`); err != nil {
		t.Fatalf("set: %v", err)
	}
	plan.Tasks[0].Status = pm.TaskDone
	if err := db.SaveState(&State{Goal: "g", Plan: plan}); err != nil {
		t.Fatalf("SaveState: %v", err)
	}
	wantFutureValues(t, db, "a save by the build the verdict admits", map[int]string{1: "kept by 1", 2: "kept by 2"})
}

// TestABuildBeforeTheVerdictRefusesIt is the other half: the same database,
// asked the question the way every earlier build with a compat-aware guard
// asks it, is refused — which is what keeps that build's row replacement
// away from the column.
func TestABuildBeforeTheVerdictRefusesIt(t *testing.T) {
	_, conn := migratedDB(t)
	future := stampFutureVersionCompat(t, conn, 1, CompatAdditiveColumns)

	blocking, err := versionsAheadNotTolerated(conn, future-1, future, preColumnsTolerable)
	if err != nil {
		t.Fatalf("versionsAheadNotTolerated: %v", err)
	}
	if len(blocking) != 1 || blocking[0].Version != future {
		t.Fatalf("an earlier build's guard blocks %+v, want exactly v%d", blocking, future)
	}
	// And it would have refused the database for an additive migration no
	// more than this build does: the verdict is the only difference.
	_, conn2 := migratedDB(t)
	additive := stampFutureVersionCompat(t, conn2, 1, CompatAdditive)
	if blocking, err := versionsAheadNotTolerated(conn2, additive-1, additive, preColumnsTolerable); err != nil || len(blocking) != 0 {
		t.Fatalf("an earlier build's guard blocks an additive migration: %+v, %v", blocking, err)
	}
}

// TestAVerdictThisBuildDoesNotKnowIsRefusedByName: the mechanism that makes
// additive-columns a refusal for older builds does the same for this one,
// against whatever verdict a later build introduces — and says so.
func TestAVerdictThisBuildDoesNotKnowIsRefusedByName(t *testing.T) {
	_, conn := migratedDB(t)
	stampFutureVersionCompat(t, conn, 1, MigrationCompat("additive-something-later"))

	_, err := Migrate(conn)
	var detail *SchemaTooNewError
	if !errors.As(err, &detail) {
		t.Fatalf("Migrate = %v, want a *SchemaTooNewError", err)
	}
	if !strings.Contains(err.Error(), `recorded "additive-something-later", a verdict this build does not know`) {
		t.Errorf("the refusal does not name the unknown verdict: %v", err)
	}
}

// TestAColumnsVerdictDoesNotHideABreakingOne: a run of migrations ahead with
// additive-columns among them refuses for the breaking one, and names only it.
func TestAColumnsVerdictDoesNotHideABreakingOne(t *testing.T) {
	_, conn := migratedDB(t)
	stampFutureVersionCompat(t, conn, 1, CompatAdditiveColumns)
	breaking := stampFutureVersionCompat(t, conn, 2, CompatBreaking)

	_, err := Migrate(conn)
	var detail *SchemaTooNewError
	if !errors.As(err, &detail) {
		t.Fatalf("Migrate = %v, want a *SchemaTooNewError", err)
	}
	if len(detail.Blocking) != 1 || detail.Blocking[0].Version != breaking {
		t.Fatalf("Blocking = %+v, want only v%d", detail.Blocking, breaking)
	}
}
