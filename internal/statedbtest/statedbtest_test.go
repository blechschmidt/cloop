package statedbtest

import (
	"database/sql"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/internal/hometest"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

func TestMain(m *testing.M) {
	os.Exit(hometest.Isolate(m))
}

// schemaOf is everything about a database's shape that statedb.Open decides:
// every object SQLite holds and the migration bookkeeping, minus applied_at,
// which is a clock reading and differs between any two databases.
func schemaOf(t *testing.T, path string) (objects, migrations []string) {
	t.Helper()
	conn, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	collect := func(query string) []string {
		rows, err := conn.Query(query)
		if err != nil {
			t.Fatalf("%s: %v", query, err)
		}
		defer func() { _ = rows.Close() }()
		cols, _ := rows.Columns()
		var out []string
		for rows.Next() {
			vals := make([]sql.NullString, len(cols))
			ptrs := make([]any, len(cols))
			for i := range vals {
				ptrs[i] = &vals[i]
			}
			if err := rows.Scan(ptrs...); err != nil {
				t.Fatal(err)
			}
			parts := make([]string, len(vals))
			for i, v := range vals {
				parts[i] = v.String
			}
			out = append(out, strings.Join(parts, " | "))
		}
		if err := rows.Err(); err != nil {
			t.Fatal(err)
		}
		return out
	}
	objects = collect(`SELECT type, name, tbl_name, sql FROM sqlite_master ORDER BY type, name`)
	migrations = collect(`SELECT version, name, applied_by, compat FROM schema_migrations ORDER BY version`)
	return objects, migrations
}

// The guarantee everything else rests on: a seeded database is the database
// statedb.Open would have built from scratch. Asserted object by object rather
// than inferred from the rest of the suite passing, because a template that
// differed would surface as an unrelated failure in whichever test first
// touched the difference.
func TestSeededDatabaseIsWhatAFreshOpenBuilds(t *testing.T) {
	fresh := filepath.Join(t.TempDir(), "state.db")
	db, err := statedb.Open(fresh)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	seeded := Path(t)

	freshObjects, freshMigrations := schemaOf(t, fresh)
	seededObjects, seededMigrations := schemaOf(t, seeded)
	if !reflect.DeepEqual(freshObjects, seededObjects) {
		t.Errorf("schema objects differ between a fresh and a seeded database:\nfresh:  %d objects\nseeded: %d objects",
			len(freshObjects), len(seededObjects))
		for i := 0; i < len(freshObjects) && i < len(seededObjects); i++ {
			if freshObjects[i] != seededObjects[i] {
				t.Errorf("first difference:\nfresh:  %s\nseeded: %s", freshObjects[i], seededObjects[i])
				break
			}
		}
	}
	if !reflect.DeepEqual(freshMigrations, seededMigrations) {
		t.Errorf("schema_migrations differ:\nfresh:  %q\nseeded: %q", freshMigrations, seededMigrations)
	}

	fi, err := os.Stat(fresh)
	if err != nil {
		t.Fatal(err)
	}
	si, err := os.Stat(seeded)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != si.Mode().Perm() {
		t.Errorf("a fresh database has mode %v, a seeded one %v", fi.Mode().Perm(), si.Mode().Perm())
	}
}

// What the template is for: opening a seeded database applies nothing.
func TestSeededDatabaseNeedsNoMigration(t *testing.T) {
	conn, err := sql.Open("sqlite", Path(t))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	report, err := statedb.Migrate(conn)
	if err != nil {
		t.Fatal(err)
	}
	latest, err := statedb.LatestSchemaVersion()
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Applied) != 0 || report.StartVersion != latest {
		t.Fatalf("a seeded database started at version %d and had %v applied; want version %d and nothing",
			report.StartVersion, report.Applied, latest)
	}
}

// A seeded database is a working one, not just a matching schema: the two
// tables this repository's tests lean on hardest accept writes and read back.
func TestSeededDatabaseIsUsable(t *testing.T) {
	db := Open(t)
	if err := db.AppendAuditEvent(&statedb.AuditEvent{
		Actor: "statedbtest", EventType: "template.check", EntityType: "test", EntityID: "1",
	}); err != nil {
		t.Fatalf("a seeded database refused an audit append: %v", err)
	}
	rep, err := db.VerifyAuditChain()
	if err != nil {
		t.Fatal(err)
	}
	if !rep.OK || rep.Total != 1 {
		t.Fatalf("audit chain on a seeded database: ok=%v total=%d, want ok and exactly the one event",
			rep.OK, rep.Total)
	}

	dir := Dir(t)
	s, err := state.Init(dir, "a goal", 3)
	if err != nil {
		t.Fatalf("state.Init over a seeded project: %v", err)
	}
	if err := s.Save(); err != nil {
		t.Fatal(err)
	}
	loaded, err := state.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Goal != "a goal" || loaded.MaxSteps != 3 {
		t.Fatalf("a project initialised over a seeded database loaded back as goal=%q maxSteps=%d",
			loaded.Goal, loaded.MaxSteps)
	}
}

// SeedDir must put the file where the state package looks for it, or every
// caller would seed a database nothing opens and migrate a second one.
func TestSeedDirIsWhereTheStatePackageLooks(t *testing.T) {
	dir := t.TempDir()
	SeedDir(t, dir)
	if _, err := os.Stat(state.DBPath(dir)); err != nil {
		t.Fatalf("SeedDir did not create state.DBPath(dir): %v", err)
	}
}

// The key is the migration files: any change to any of them is a new key.
func TestKeyIsADigestOfTheMigrationFiles(t *testing.T) {
	files, err := readMigrationFiles()
	if err != nil {
		t.Fatalf("reading pkg/statedb/migrations from the source tree: %v", err)
	}
	latest, err := statedb.LatestSchemaVersion()
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != latest {
		t.Fatalf("found %d migration files, the binary embeds %d", len(files), latest)
	}
	if got, want := Template().Key(), digest(files); got != want {
		t.Fatalf("Template().Key() = %q, want the digest of the files, %q", got, want)
	}

	base := digest(files)
	edited := append([]migrationFile(nil), files...)
	edited[len(edited)-1] = migrationFile{name: files[len(files)-1].name,
		body: append(append([]byte(nil), files[len(files)-1].body...), '\n')}
	if digest(edited) == base {
		t.Error("editing a migration's contents left the key unchanged")
	}
	added := append(append([]migrationFile(nil), files...), migrationFile{name: "9999_next.sql", body: []byte("SELECT 1;")})
	if digest(added) == base {
		t.Error("adding a migration left the key unchanged")
	}
	renamed := append([]migrationFile(nil), files...)
	renamed[0] = migrationFile{name: "0001_renamed.sql", body: files[0].body}
	if digest(renamed) == base {
		t.Error("renaming a migration left the key unchanged")
	}
}

// verify is what makes "cannot go stale" a checked claim. A database that
// stops short of the binary's migrations, or that recorded a version under a
// different file, must be refused.
func TestVerifyRefusesADatabaseThatIsNotTheMigrationFiles(t *testing.T) {
	Template() // reads the migration files verify compares against
	latest, err := statedb.LatestSchemaVersion()
	if err != nil {
		t.Fatal(err)
	}

	short := filepath.Join(t.TempDir(), "short.db")
	conn, err := sql.Open("sqlite", short)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := statedb.MigrateTo(conn, latest-1); err != nil {
		t.Fatal(err)
	}
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	if err := verify(short); err == nil {
		t.Error("verify accepted a database one migration short of the binary's")
	}

	renamed := Path(t)
	conn, err = sql.Open("sqlite", renamed)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Exec(`UPDATE schema_migrations SET name = 'collided.sql' WHERE version = ?`, latest); err != nil {
		t.Fatal(err)
	}
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	if err := verify(renamed); err == nil || !strings.Contains(err.Error(), "collided.sql") {
		t.Errorf("verify(%s) = %v, want a refusal naming the mismatched file", renamed, err)
	}

	if err := verify(Path(t)); err != nil {
		t.Errorf("verify refused the template it built: %v", err)
	}
}
