// Package statedbtest gives tests a fully migrated, empty state.db without
// migrating one.
//
// It binds internal/dbtemplate to statedb.Open: the first test in a binary
// that asks for a database pays for one migration from scratch, and every test
// after it gets a copy of the result. A copy is the file statedb.Open would
// have produced — same schema, same schema_migrations rows, same file mode —
// so the code under test takes the path a hub takes when it opens an existing
// project, and none of the 56 migrations run again. Why that matters, in
// numbers, is in internal/dbtemplate's package comment.
//
// Use it wherever a test needs a project or a database to exist and is not
// about how one comes to exist:
//
//	dir := statedbtest.Dir(t)              // a project directory, database migrated
//	statedbtest.SeedDir(t, dir)            // the same for a directory you already have
//	db := statedbtest.Open(t)              // a migrated *statedb.DB, closed at cleanup
//
// Do not use it in a test about migrations, schema adoption, version skew or a
// first open racing another: those must build their database from scratch, or
// they stop testing what they are named for. pkg/statedb's in-package tests
// cannot import this package (it imports statedb); they bind dbtemplate
// themselves, in template_test.go. Its external statedb_test files use this
// package like everyone else.
//
// The template is keyed on a SHA-256 of the migration files, and a freshly
// built template is checked against those files before it is ever copied: its
// schema_migrations must record exactly them, in order, and nothing else. It is
// built in memory, once per test binary, from the migrations that binary
// embeds, and is never written anywhere that outlives the binary — so it cannot
// go stale, and the check is what proves it rather than assumes it.
package statedbtest

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/blechschmidt/cloop/internal/dbtemplate"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// migrationFile is one file of pkg/statedb/migrations as found in the source
// tree beside this package.
type migrationFile struct {
	name string
	body []byte
}

var (
	setupOnce sync.Once
	tmpl      *dbtemplate.Template
	files     []migrationFile
	filesErr  error
)

// Template returns the state.db template, creating it on first use.
func Template() *dbtemplate.Template {
	setupOnce.Do(func() {
		files, filesErr = readMigrationFiles()
		key := "unavailable"
		if filesErr == nil {
			key = digest(files)
		}
		tmpl = dbtemplate.New("state.db", key, build, verify)
	})
	return tmpl
}

// build is statedb.Open on an empty path — the migration from scratch a test
// would otherwise run itself — followed by the Close that checkpoints the WAL
// into the main file.
func build(path string) error {
	db, err := statedb.Open(path)
	if err != nil {
		return err
	}
	return db.Close()
}

// verify checks that the image records exactly the migrations it is keyed on.
func verify(path string) error {
	latest, err := statedb.LatestSchemaVersion()
	if err != nil {
		return err
	}
	conn, err := sql.Open("sqlite", path)
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()
	rows, err := conn.Query(`SELECT version, name FROM schema_migrations ORDER BY version`)
	if err != nil {
		return fmt.Errorf("reading schema_migrations: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var recorded []string
	for rows.Next() {
		var (
			v    int
			name string
		)
		if err := rows.Scan(&v, &name); err != nil {
			return err
		}
		recorded = append(recorded, name)
		if v != len(recorded) {
			return fmt.Errorf("schema_migrations is not the dense sequence a fresh database records: "+
				"version %d is row %d", v, len(recorded))
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if len(recorded) != latest {
		return fmt.Errorf("the template records %d migrations, but this binary embeds %d",
			len(recorded), latest)
	}
	if filesErr != nil {
		// Without the source tree (a -trimpath build, say) there is nothing
		// to compare names against; the count above still holds the template
		// to the binary's own migrations.
		return nil
	}
	if len(files) != len(recorded) {
		return fmt.Errorf("the template records %d migrations, but pkg/statedb/migrations holds %d files",
			len(recorded), len(files))
	}
	for i, f := range files {
		if recorded[i] != f.name {
			return fmt.Errorf("schema version %d was recorded as %q, but the file is %q",
				i+1, recorded[i], f.name)
		}
	}
	return nil
}

// readMigrationFiles reads pkg/statedb/migrations from the source tree this
// package was compiled from.
func readMigrationFiles() ([]migrationFile, error) {
	_, self, _, ok := runtime.Caller(0)
	if !ok {
		return nil, fmt.Errorf("cannot locate the source tree")
	}
	dir := filepath.Join(filepath.Dir(self), "..", "..", "pkg", "statedb", "migrations")
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var out []migrationFile
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".sql") {
			continue
		}
		body, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			return nil, err
		}
		out = append(out, migrationFile{name: e.Name(), body: body})
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no migration files in %s", dir)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].name < out[j].name })
	return out, nil
}

// digest is the template's key: every file's name and contents, in order.
func digest(files []migrationFile) string {
	h := sha256.New()
	for _, f := range files {
		fmt.Fprintf(h, "%s\x00%d\x00", f.name, len(f.body))
		h.Write(f.body)
	}
	return hex.EncodeToString(h.Sum(nil))[:16]
}

// Seed puts a fully migrated, empty state.db at dbPath unless a file is
// already there, and reports whether it wrote one.
func Seed(tb testing.TB, dbPath string) bool {
	tb.Helper()
	return Template().Seed(tb, dbPath)
}

// SeedDir seeds the database of the project at dir: dir/.cloop/state.db,
// which is where state.Init, state.Save, state.Load and
// statedb.Open(state.DBPath(dir)) find it for a project outside a session.
// Call it before anything opens a database there.
func SeedDir(tb testing.TB, dir string) {
	tb.Helper()
	Seed(tb, filepath.Join(dir, ".cloop", "state.db"))
}

// Dir returns a new temporary directory whose project database is already
// migrated.
func Dir(tb testing.TB) string {
	tb.Helper()
	dir := tb.TempDir()
	SeedDir(tb, dir)
	return dir
}

// Path returns the path of a fully migrated, empty database in a new
// temporary directory.
func Path(tb testing.TB) string {
	tb.Helper()
	path := filepath.Join(tb.TempDir(), "state.db")
	Seed(tb, path)
	return path
}

// Open opens a fully migrated, empty database at a new temporary path and
// closes it when the test ends.
func Open(tb testing.TB) *statedb.DB {
	tb.Helper()
	db, err := statedb.Open(Path(tb))
	if err != nil {
		tb.Fatalf("opening a seeded state.db: %v", err)
	}
	tb.Cleanup(func() { _ = db.Close() })
	return db
}
