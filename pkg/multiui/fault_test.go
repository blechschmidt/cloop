package multiui

// A project that will not load must say so (Task 20254).
//
// GetStatusUsing discarded the error from state.LoadLite and returned a
// zero-valued status, which made "this database was refused" indistinguishable
// from "this directory is not a cloop project". On 2026-09-14 a schema skew
// refused 18 databases at once and the dashboard showed 18 projects with no
// goal and no tasks, so the fault was reported as missing tasks rather than as
// a database that would not open.

import (
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/statedb"
	_ "modernc.org/sqlite"
)

// projectAtFutureSchema creates a real project database and stamps a migration
// beyond what this binary embeds, recorded as breaking so the guard refuses it.
// That is precisely the shape of the database the deployed hub met.
func projectAtFutureSchema(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	cloopDir := filepath.Join(dir, ".cloop")
	if err := os.MkdirAll(cloopDir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	dbPath := filepath.Join(cloopDir, "state.db")

	db, err := statedb.Open(dbPath)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := db.SaveState(&statedb.State{Goal: "before the skew", Status: "idle", PMMode: true}); err != nil {
		t.Fatalf("seed state: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	latest, err := statedb.LatestSchemaVersion()
	if err != nil {
		t.Fatalf("LatestSchemaVersion: %v", err)
	}
	conn, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("raw open: %v", err)
	}
	defer conn.Close()
	if _, err := conn.Exec(
		`INSERT INTO schema_migrations(version, applied_at, name, applied_by, compat) VALUES (?, ?, ?, ?, ?)`,
		latest+1, time.Now().UTC().Format(time.RFC3339Nano),
		"0999_breaking.sql", "dev+gfuture", string(statedb.CompatBreaking),
	); err != nil {
		t.Fatalf("stamp future version: %v", err)
	}
	return dir
}

// TestGetStatus_ReportsADatabaseItCannotOpen is the server half of the
// dashboard's fault banner: without a message on the wire the page has nothing
// to display.
func TestGetStatus_ReportsADatabaseItCannotOpen(t *testing.T) {
	dir := projectAtFutureSchema(t)

	ps := GetStatusUsing(ProjectEntry{Name: "skewed", Path: dir}, false)

	if ps.Error == "" {
		t.Fatal("a project whose database was refused reported no error")
	}
	if !strings.Contains(ps.Error, "schema") {
		t.Errorf("error does not name the cause: %q", ps.Error)
	}
	// HasProject stays false — callers branch on it and the project genuinely
	// could not be loaded. Error is what distinguishes why.
	if ps.HasProject {
		t.Error("HasProject is true for a project that failed to load")
	}
	if ps.Health != HealthUnknown {
		t.Errorf("health = %q, want %q", ps.Health, HealthUnknown)
	}
}

// TestGetStatus_UninitialisedDirectoryIsNotAFault. Registering a path before
// running `cloop init` is ordinary, and reporting it as an error would make the
// banner meaningless.
func TestGetStatus_UninitialisedDirectoryIsNotAFault(t *testing.T) {
	ps := GetStatusUsing(ProjectEntry{Name: "fresh", Path: t.TempDir()}, false)

	if ps.Error != "" {
		t.Errorf("an uninitialised directory reported a fault: %q", ps.Error)
	}
	if ps.HasProject {
		t.Error("HasProject is true for an uninitialised directory")
	}
}

// TestGetStatus_HealthyProjectReportsNoError guards the third case: loading
// fine must leave the field empty, or every project carries a fault forever.
func TestGetStatus_HealthyProjectReportsNoError(t *testing.T) {
	dir := t.TempDir()
	cloopDir := filepath.Join(dir, ".cloop")
	if err := os.MkdirAll(cloopDir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	db, err := statedb.Open(filepath.Join(cloopDir, "state.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := db.SaveState(&statedb.State{Goal: "healthy", Status: "idle", PMMode: true}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	ps := GetStatusUsing(ProjectEntry{Name: "ok", Path: dir}, false)

	if ps.Error != "" {
		t.Errorf("a healthy project reported a fault: %q", ps.Error)
	}
	if !ps.HasProject {
		t.Error("HasProject is false for a project that loaded")
	}
	if ps.Goal != "healthy" {
		t.Errorf("goal = %q, want %q", ps.Goal, "healthy")
	}
}
