package statedb

// The project_readers table (Task 20498): its migration is additive for every
// older hub sharing the control plane, guarded against a table that is
// already there, and its accessors keep one row per pair.

import (
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// readersMigration is 0103 as embedded.
func readersMigration(t *testing.T) migration {
	t.Helper()
	all, err := loadMigrations()
	if err != nil {
		t.Fatalf("loadMigrations: %v", err)
	}
	for _, m := range all {
		if m.Name == "0103_project_readers.sql" {
			return m
		}
	}
	t.Fatal("0103_project_readers.sql is not embedded")
	return migration{}
}

// TestProjectReadersMigrationIsAdditive: 0103 only adds objects no older
// binary names, every CREATE in it is guarded, and the verdict it is recorded
// with lets each older kind of hub keep opening the database: a build from
// before this migration, and one from before the additive-columns verdict.
func TestProjectReadersMigrationIsAdditive(t *testing.T) {
	m := readersMigration(t)
	if got := classifyMigration(m.SQL); got != CompatAdditive {
		t.Fatalf("0103 classifies as %q, want %q", got, CompatAdditive)
	}
	if got := migrationVerdict(m); got != CompatAdditive {
		t.Fatalf("0103 is recorded %q, want %q", got, CompatAdditive)
	}
	stmts := splitStatements(m.SQL)
	if len(stmts) != 3 {
		t.Fatalf("0103 has %d statements, want the table and its two indexes: %q", len(stmts), stmts)
	}
	guarded := regexp.MustCompile(`(?i)^CREATE\s+(UNIQUE\s+)?(TABLE|INDEX)\s+IF\s+NOT\s+EXISTS\s`)
	for _, s := range stmts {
		if !guarded.MatchString(s) {
			t.Errorf("an unguarded statement in 0103 — the stable UI shares this database: %q", s)
		}
		if f := strings.Fields(s); len(f) > 0 && !strings.EqualFold(f[0], "CREATE") {
			t.Errorf("0103 does more than create: %q", s)
		}
	}
	if strings.Contains(strings.ToLower(m.SQL), "plan_tasks") && strings.Contains(strings.ToUpper(m.SQL), "ALTER") {
		t.Error("0103 alters plan_tasks")
	}

	// What a fresh database records, and what older hubs make of it.
	_, conn := migratedDB(t)
	var compat string
	if err := conn.QueryRow(`SELECT compat FROM schema_migrations WHERE version = ?`, m.Version).Scan(&compat); err != nil {
		t.Fatalf("read the recorded verdict: %v", err)
	}
	if compat != string(CompatAdditive) {
		t.Fatalf("0103 is recorded %q in schema_migrations, want %q", compat, CompatAdditive)
	}
	latest, err := LatestSchemaVersion()
	if err != nil {
		t.Fatal(err)
	}
	for name, tolerable := range map[string]func(MigrationCompat) bool{
		"a hub built before 0103":                     MigrationCompat.Tolerable,
		"a hub built before the additive-columns cut": preColumnsTolerable,
	} {
		blocking, err := versionsAheadNotTolerated(conn, m.Version-1, latest, tolerable)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		for _, b := range blocking {
			if b.Version == m.Version {
				t.Errorf("%s refuses the database because of 0103", name)
			}
		}
	}
}

// TestProjectReadersAdoptAnExistingTable: a database where the table and its
// indexes already exist — a stranded build, or a hand-made table — migrates
// through 0103 instead of failing on it.
func TestProjectReadersAdoptAnExistingTable(t *testing.T) {
	m := readersMigration(t)
	path := filepath.Join(t.TempDir(), "state.db")
	conn := openRaw(t, path)
	if _, err := MigrateTo(conn, m.Version-1); err != nil {
		t.Fatalf("MigrateTo(%d): %v", m.Version-1, err)
	}
	// The migration's own statements, run once ahead of it.
	for _, s := range splitStatements(m.SQL) {
		if _, err := conn.Exec(s); err != nil {
			t.Fatalf("pre-create: %v", err)
		}
	}
	if _, err := conn.Exec(`INSERT INTO project_readers (id, project_path, reader_path, added_by, added_at)
		VALUES ('prd_before', '/srv/a', '/srv/b', 'stranded', '')`); err != nil {
		t.Fatal(err)
	}
	rep, err := Migrate(conn)
	if err != nil {
		t.Fatalf("Migrate over an existing project_readers: %v", err)
	}
	if !containsInt(rep.Applied, m.Version) {
		t.Fatalf("0103 was not applied: %+v", rep)
	}
	conn.Close()

	db, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer db.Close()
	rows, err := db.ListProjectReaders()
	if err != nil || len(rows) != 1 || rows[0].ID != "prd_before" {
		t.Fatalf("the existing row did not survive: %+v %v", rows, err)
	}
}

// TestProjectReaderRowsArePairs: one row per pair whatever writes it, never a
// project listing itself, and every change committed with its audit row.
func TestProjectReaderRowsArePairs(t *testing.T) {
	path, raw := migratedDB(t)
	raw.Close()
	db, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer db.Close()
	conn := db.conn

	for _, bad := range []ProjectReaderRow{
		{ProjectPath: "", ReaderPath: "/srv/b"},
		{ProjectPath: "/srv/a", ReaderPath: ""},
		{ProjectPath: "/srv/a", ReaderPath: "/srv/a"},
	} {
		if _, _, err := db.AddProjectReader(bad, nil); err == nil {
			t.Errorf("AddProjectReader(%+v) was stored", bad)
		}
	}
	first, added, err := db.AddProjectReader(ProjectReaderRow{ProjectPath: "/srv/a", ReaderPath: "/srv/b", AddedBy: "alice"}, nil)
	if err != nil || !added || !strings.HasPrefix(first.ID, "prd_") || len(first.ID) != len("prd_")+24 {
		t.Fatalf("add = %+v %v %v", first, added, err)
	}
	second, added, err := db.AddProjectReader(ProjectReaderRow{ProjectPath: "/srv/a", ReaderPath: "/srv/b", AddedBy: "bob"}, nil)
	if err != nil || added || second.ID != first.ID || second.AddedBy != "alice" {
		t.Fatalf("a second add of the pair = %+v %v %v, want the first row", second, added, err)
	}
	// The pair index refuses a writer that skips the lookup.
	if _, err := conn.Exec(`INSERT INTO project_readers (id, project_path, reader_path) VALUES ('prd_dup', '/srv/a', '/srv/b')`); err == nil {
		t.Error("a second row for one pair was inserted")
	}
	// An id names a row only on its own project's list.
	if got, err := db.RemoveProjectReaderByID("/srv/b", first.ID, nil); err != nil || got != nil {
		t.Errorf("removed through another project's list: %+v %v", got, err)
	}
	var n int
	if err := conn.QueryRow(`SELECT count(*) FROM project_readers`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("rows = %d %v", n, err)
	}
	if got, err := db.RemoveProjectReaderByID("/srv/a", first.ID, nil); err != nil || got == nil || got.ReaderPath != "/srv/b" {
		t.Fatalf("RemoveProjectReaderByID = %+v %v", got, err)
	}
}
