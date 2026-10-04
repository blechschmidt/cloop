package dbtemplate

import (
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	_ "modernc.org/sqlite"
)

// buildWAL is a builder shaped like statedb.Open's: a WAL-mode database with
// one table and one row, closed so the WAL is checkpointed into the main file.
func buildWAL(path string) error {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return err
	}
	for _, stmt := range []string{
		`PRAGMA journal_mode=WAL`,
		`CREATE TABLE t (v TEXT)`,
		`INSERT INTO t (v) VALUES ('from-the-template')`,
	} {
		if _, err := db.Exec(stmt); err != nil {
			_ = db.Close()
			return err
		}
	}
	return db.Close()
}

func readRows(t *testing.T, path string) []string {
	t.Helper()
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	rows, err := db.Query(`SELECT v FROM t ORDER BY rowid`)
	if err != nil {
		t.Fatalf("querying a seeded copy: %v", err)
	}
	defer func() { _ = rows.Close() }()
	var out []string
	for rows.Next() {
		var v string
		if err := rows.Scan(&v); err != nil {
			t.Fatal(err)
		}
		out = append(out, v)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

// The point of the package: one build, however many seeds, including seeds
// that race each other for the first build.
func TestBuildsOncePerBinary(t *testing.T) {
	var builds atomic.Int32
	tmpl := New("once", "k", func(path string) error {
		builds.Add(1)
		return buildWAL(path)
	}, nil)

	root := t.TempDir()
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if _, _, err := tmpl.Image(); err != nil {
				t.Error(err)
			}
		}(i)
	}
	wg.Wait()
	for i := 0; i < 5; i++ {
		tmpl.Seed(t, filepath.Join(root, strings.Repeat("d", i+1), "state.db"))
	}
	if n := builds.Load(); n != 1 {
		t.Fatalf("the builder ran %d times; a template is built once per binary", n)
	}
}

func TestSeedWritesAnIndependentUsableCopy(t *testing.T) {
	tmpl := New("copy", "k", buildWAL, nil)
	a := filepath.Join(t.TempDir(), "a", ".cloop", "state.db")
	b := filepath.Join(t.TempDir(), "b", "state.db")
	if !tmpl.Seed(t, a) || !tmpl.Seed(t, b) {
		t.Fatal("Seed reported it wrote nothing into fresh directories")
	}
	if got := readRows(t, a); len(got) != 1 || got[0] != "from-the-template" {
		t.Fatalf("seeded copy holds %q, want the template's one row", got)
	}

	// A write to one copy is that copy's alone.
	db, err := sql.Open("sqlite", a)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO t (v) VALUES ('only-in-a')`); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	if got := readRows(t, b); len(got) != 1 {
		t.Fatalf("a write to one seeded copy reached another: %q", got)
	}
	image, _, err := tmpl.Image()
	if err != nil {
		t.Fatal(err)
	}
	c := filepath.Join(t.TempDir(), "c.db")
	if err := os.WriteFile(c, image, 0o600); err != nil {
		t.Fatal(err)
	}
	if got := readRows(t, c); len(got) != 1 {
		t.Fatalf("a write to a seeded copy changed the template itself: %q", got)
	}
}

// A database a test already wrote to is its setup; seeding must not erase it.
func TestSeedNeverReplacesAnExistingFile(t *testing.T) {
	tmpl := New("noclobber", "k", buildWAL, nil)
	path := filepath.Join(t.TempDir(), "state.db")
	if err := os.WriteFile(path, []byte("a test's own setup"), 0o600); err != nil {
		t.Fatal(err)
	}
	if tmpl.Seed(t, path) {
		t.Fatal("Seed reported writing over an existing file")
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "a test's own setup" {
		t.Fatalf("Seed replaced an existing file's contents with %d bytes", len(got))
	}
}

// A seeded file must look like the one the builder made, mode included, or a
// test asserting on permissions would see something production never makes.
func TestSeedKeepsTheBuildersFileMode(t *testing.T) {
	tmpl := New("mode", "k", func(path string) error {
		if err := buildWAL(path); err != nil {
			return err
		}
		return os.Chmod(path, 0o640)
	}, nil)
	path := filepath.Join(t.TempDir(), "state.db")
	tmpl.Seed(t, path)
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o640 {
		t.Fatalf("seeded file has mode %v, the builder's had 0640", info.Mode().Perm())
	}
}

// A builder that leaves its connection open leaves the schema in the -wal,
// and copying the main file alone would hand out an empty database.
func TestRefusesAnImageWithAWALBesideIt(t *testing.T) {
	var leaked *sql.DB
	tmpl := New("leaky", "k", func(path string) error {
		db, err := sql.Open("sqlite", path)
		if err != nil {
			return err
		}
		leaked = db
		for _, stmt := range []string{`PRAGMA journal_mode=WAL`, `CREATE TABLE t (v TEXT)`} {
			if _, err := db.Exec(stmt); err != nil {
				return err
			}
		}
		return nil // deliberately not closed
	}, nil)
	defer func() {
		if leaked != nil {
			_ = leaked.Close()
		}
	}()
	_, _, err := tmpl.Image()
	if err == nil || !strings.Contains(err.Error(), "-wal") {
		t.Fatalf("Image() = %v, want a refusal naming the -wal left behind", err)
	}
}

func TestVerifyFailureNamesTheKey(t *testing.T) {
	tmpl := New("verified", "digest-123", buildWAL, func(string) error {
		return errors.New("the image records migrations the files do not")
	})
	_, _, err := tmpl.Image()
	if err == nil || !strings.Contains(err.Error(), "digest-123") ||
		!strings.Contains(err.Error(), "the files do not") {
		t.Fatalf("Image() = %v, want the verification error with the key it was checked against", err)
	}
}

// The image is held in memory; the directory it was built in is gone.
func TestBuildLeavesNothingOnDisk(t *testing.T) {
	var built string
	tmpl := New("tidy", "k", func(path string) error {
		built = path
		return buildWAL(path)
	}, nil)
	if _, _, err := tmpl.Image(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Dir(built)); !os.IsNotExist(err) {
		t.Fatalf("the template's build directory %s survived: %v", filepath.Dir(built), err)
	}
}
