package ui

// A pre-migrated state.db, so that this package's tests stop paying to build
// one 400 times over.
//
// statedb.Open applies the 29 files in pkg/statedb/migrations to a new
// database. That is cheap in production — 35ms, once per project, at hub
// start — and it is not cheap here: modernc.org/sqlite is pure Go, so the
// race detector instruments the entire engine, and the same work measures at
// 457ms under -race. Nearly every test in this package creates a project
// directory, and the suite ran to 365 seconds with roughly half of that spent
// replaying identical DDL.
//
// Open only applies migrations the database is *missing*, so a test whose
// directory already holds a fully-migrated file skips all 29 and takes the
// same path as a hub opening an existing project — arguably the more
// representative one, since a fresh database is the rare case in production
// and the universal case here.
//
// This is a test-only optimisation. Nothing in the production path changes,
// and the fallback is to do nothing: if the template cannot be built, the
// caller simply pays the old cost and still passes.

import (
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/blechschmidt/cloop/pkg/statedb"
)

var (
	migratedTemplateOnce sync.Once
	migratedTemplate     []byte
)

// migratedDBTemplate returns the bytes of a fully-migrated, empty state.db,
// building it once per test binary. Returns nil if it could not be built, which
// callers treat as "skip the optimisation".
func migratedDBTemplate() []byte {
	migratedTemplateOnce.Do(func() {
		dir, err := os.MkdirTemp("", "cloop-ui-db-template-*")
		if err != nil {
			return
		}
		// Removed before returning: the template lives in memory, so the
		// suite leaves nothing behind on disk. CI asserts exactly that.
		defer func() { _ = os.RemoveAll(dir) }()

		path := filepath.Join(dir, "state.db")
		db, err := statedb.Open(path)
		if err != nil {
			return
		}
		// Close before reading. Open runs in WAL mode, so the migrations
		// are in state.db-wal until a checkpoint; Close performs it and
		// removes the sidecar, which is what makes the main file
		// self-contained and safe to copy.
		if err := db.Close(); err != nil {
			return
		}
		if _, err := os.Stat(path + "-wal"); err == nil {
			// A surviving WAL would mean the bytes below are an
			// incomplete database. Refuse rather than seed a truncated
			// schema that would fail in a way pointing nowhere near here.
			return
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return
		}
		migratedTemplate = b
	})
	return migratedTemplate
}

// seedMigratedDB drops a pre-migrated state.db into dir so the next
// statedb.Open or state.Init there has no migrations left to apply.
//
// Call it on a fresh directory, before anything opens a database in it. It is
// a no-op if one already exists — overwriting a database a test has already
// written to would silently discard that test's setup.
func seedMigratedDB(tb testing.TB, dir string) {
	tb.Helper()
	tmpl := migratedDBTemplate()
	if tmpl == nil {
		return // fall back to migrating from scratch
	}
	cloop := filepath.Join(dir, ".cloop")
	if err := os.MkdirAll(cloop, 0o755); err != nil {
		return
	}
	path := filepath.Join(cloop, "state.db")
	if _, err := os.Stat(path); err == nil {
		return
	}
	// 0600: the same mode statedb.Open creates it with. A seeded database
	// that is world-readable would quietly weaken pkg/audit's permission
	// assertions.
	if err := os.WriteFile(path, tmpl, 0o600); err != nil {
		// Leave no partial file behind for statedb.Open to choke on.
		_ = os.Remove(path)
	}
}

// TestMigratedTemplateIsUsable is the check that keeps the optimisation
// honest. The template is only ever a speed-up if a database seeded from it is
// indistinguishable from one migrated in place — so assert that the schema
// really is fully applied, rather than inferring it from the suite passing.
//
// Without this, a template truncated by a surviving WAL, or one built from a
// stale migration set, would present as an unrelated failure in whichever test
// happened to touch the missing table first.
func TestMigratedTemplateIsUsable(t *testing.T) {
	t.Parallel()

	if migratedDBTemplate() == nil {
		t.Skip("template could not be built; tests fall back to migrating in place")
	}

	dir := t.TempDir()
	seedMigratedDB(t, dir)

	db, err := statedb.Open(filepath.Join(dir, ".cloop", "state.db"))
	if err != nil {
		t.Fatalf("opening a seeded database: %v", err)
	}
	defer func() { _ = db.Close() }()

	// Exercise the two schemas this package leans on hardest, one of which
	// (audit_events) arrived in migration 0004 and the other (quotas) in
	// 0020 — so a template stuck at an early version fails here.
	if err := db.AppendAuditEvent(&statedb.AuditEvent{
		Actor: "template-test", EventType: "template.check",
		EntityType: "test", EntityID: "1",
	}); err != nil {
		t.Fatalf("seeded database rejected an audit append: %v", err)
	}
	rep, err := db.VerifyAuditChain()
	if err != nil {
		t.Fatalf("seeded database could not verify its audit chain: %v", err)
	}
	if !rep.OK || rep.Total != 1 {
		t.Fatalf("audit chain on a seeded database: ok=%v total=%d, want ok=true total=1",
			rep.OK, rep.Total)
	}

	// And that it really is at the head of the migration set: a second Open
	// against the same file must find nothing left to apply. MigrateTo
	// reports the version it settled on.
	if _, err := statedb.Open(filepath.Join(dir, ".cloop", "state.db")); err != nil {
		t.Fatalf("reopening a seeded database: %v", err)
	}
}
