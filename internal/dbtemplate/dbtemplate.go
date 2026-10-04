// Package dbtemplate builds a database file once per test binary and hands
// each test its own copy, so that a suite does not pay to build the same
// database over and over.
//
// The database it exists for is cloop's state.db. statedb.Open migrates a new
// file from scratch — 56 migrations at the time of writing — and that is cheap
// in production, about 17 ms once per project at hub start. It is not cheap in
// a test: modernc.org/sqlite is pure Go, so under -race the detector
// instruments the whole SQL engine, and every ALTER TABLE ... ADD COLUMN makes
// SQLite re-parse the entire schema. A fresh database measured 1.47 s under
// -race after migration 0054 added thirteen columns. Nearly every test that
// touches project state starts from a fresh temporary directory, so packages
// that do so hundreds of times — pkg/statedb, pkg/orchestrator, pkg/state,
// cmd, tests/security — spent most of their wall clock replaying identical
// DDL, and the CI race step that waits on them ran 35 minutes.
//
// statedb.Open only applies the migrations a database is missing, so a test
// whose directory already holds a fully migrated file skips all of them and
// takes the path a hub takes when it opens an existing project. That is the
// whole trick, and it changes nothing outside tests.
//
// This package is the generic half: it knows how to capture a database a
// builder produced and how to put copies of it in place, and nothing about
// cloop. It imports nothing from this module on purpose, because pkg/statedb's
// own tests — which live inside package statedb — need it too, and they cannot
// import anything that imports statedb. Every other package uses
// internal/statedbtest, which binds a Template to statedb.Open.
//
// Tests that are about building a database — migrations, adopting an older
// schema, a first open racing another — must not use a template. They are the
// tests that would notice if the template were wrong, and a copied file would
// skip the very code they exist to exercise.
package dbtemplate

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

// Template is a database image built at most once per test binary.
type Template struct {
	name   string
	key    string
	build  func(path string) error
	verify func(path string) error

	once  sync.Once
	image []byte
	mode  fs.FileMode
	err   error
}

// New returns a Template that build produces on first use.
//
// build must leave a complete database at path: closed, and in WAL mode
// checkpointed, so that no -wal or -journal file remains beside it. Anything
// left beside it means the main file alone is an incomplete database, and the
// template refuses to be used rather than hand out a truncated schema that
// would fail somewhere unrelated.
//
// key names what the image depends on — for state.db, a digest of the
// migration files — and verify, if not nil, checks a freshly built image
// against it before the image is ever copied. The image never outlives the
// test binary that built it, so the binary's own migrations are the only ones
// it can contain; verify is what proves that rather than assuming it.
func New(name, key string, build, verify func(path string) error) *Template {
	return &Template{name: name, key: key, build: build, verify: verify}
}

// Name returns the name the Template was created with.
func (t *Template) Name() string { return t.name }

// Key returns the key the Template was created with.
func (t *Template) Key() string { return t.key }

// Image returns the template's bytes and the file mode the builder created the
// database with, building it on the first call. The returned slice is shared:
// callers must not modify it.
func (t *Template) Image() ([]byte, fs.FileMode, error) {
	t.once.Do(t.load)
	return t.image, t.mode, t.err
}

func (t *Template) load() {
	dir, err := os.MkdirTemp("", "cloop-dbtemplate-*")
	if err != nil {
		t.err = fmt.Errorf("dbtemplate %s: %w", t.name, err)
		return
	}
	// The image lives in memory; nothing of it is left on disk.
	defer func() { _ = os.RemoveAll(dir) }()

	path := filepath.Join(dir, "template.db")
	if err := t.build(path); err != nil {
		t.err = fmt.Errorf("dbtemplate %s: building the template: %w", t.name, err)
		return
	}
	if t.verify != nil {
		if err := t.verify(path); err != nil {
			t.err = fmt.Errorf("dbtemplate %s (key %s): %w", t.name, t.key, err)
			return
		}
	}
	// Checked after verify, so that a verifier which left a connection open
	// is caught as surely as a builder that did.
	for _, sidecar := range []string{"-wal", "-journal"} {
		if _, err := os.Stat(path + sidecar); err == nil {
			t.err = fmt.Errorf("dbtemplate %s: %s was left behind, so the main file alone "+
				"is not the whole database; every connection must be closed first",
				t.name, filepath.Base(path+sidecar))
			return
		}
	}
	info, err := os.Stat(path)
	if err != nil {
		t.err = fmt.Errorf("dbtemplate %s: %w", t.name, err)
		return
	}
	image, err := os.ReadFile(path)
	if err != nil {
		t.err = fmt.Errorf("dbtemplate %s: %w", t.name, err)
		return
	}
	t.image, t.mode = image, info.Mode().Perm()
}

// Seed writes a copy of the template at path, creating its parent
// directories, and reports whether it did.
//
// It never replaces an existing file: a database a test has already written
// to is that test's setup, and overwriting it would discard the setup without
// a word. The copy gets the mode the builder's database was created with, so
// a seeded file is indistinguishable from one the code under test would have
// created — permission checks see what they would have seen.
//
// A template that cannot be built fails the test. Every test that seeds would
// otherwise go on to build the database itself and fail the same way, or pass
// slowly with nothing saying why the suite got slower again.
func (t *Template) Seed(tb testing.TB, path string) bool {
	tb.Helper()
	image, mode, err := t.Image()
	if err != nil {
		tb.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		tb.Fatalf("dbtemplate %s: %v", t.name, err)
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if errors.Is(err, fs.ErrExist) {
		return false
	}
	if err != nil {
		tb.Fatalf("dbtemplate %s: %v", t.name, err)
	}
	_, werr := f.Write(image)
	cerr := f.Close()
	if err := errors.Join(werr, cerr); err != nil {
		// Leave nothing half-written for the code under test to choke on.
		_ = os.Remove(path)
		tb.Fatalf("dbtemplate %s: writing %s: %v", t.name, path, err)
	}
	return true
}
