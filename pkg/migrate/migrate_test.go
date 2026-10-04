package migrate

// pkg/migrate answers from statedb and delegates to it (Task 20374).

import (
	"database/sql"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/internal/statedbtest"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

func latest(t *testing.T) int {
	t.Helper()
	v, err := statedb.LatestSchemaVersion()
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// currentProject is a project as `cloop init` makes one today.
func currentProject(t *testing.T) string {
	t.Helper()
	dir := statedbtest.Dir(t)
	if _, err := state.Init(dir, "a current project", 0); err != nil {
		t.Fatal(err)
	}
	return dir
}

// legacyProject has its state only in state.json, as the e2e fixtures write it.
func legacyProject(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	writeJSON(t, filepath.Join(dir, ".cloop", "state.json"), map[string]any{
		"goal":    "a legacy project",
		"workdir": dir,
		"status":  "paused",
		"plan": map[string]any{
			"goal": "a legacy project",
			"tasks": []map[string]any{
				{"id": 1, "title": "first", "status": "done"},
				{"id": 2, "title": "second", "status": "pending", "depends_on": []int{1}},
			},
		},
		"steps":      []map[string]any{{"step": 1, "task": "first", "output": "ok"}},
		"created_at": time.Date(2026, 1, 15, 10, 0, 0, 0, time.UTC),
	})
	return dir
}

func writeJSON(t *testing.T, path string, v any) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

// preStatedbProject has a state.db with no schema_migrations: the shape the old
// `cloop migrate` wrote when it converted a state.json — three tables of its
// own, plan_tasks with the three columns migration 0054 later adopted.
func preStatedbProject(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, ".cloop", "state.db")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	raw, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	if _, err := raw.Exec(`
		CREATE TABLE metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL DEFAULT '');
		CREATE TABLE plan_tasks (
			id INTEGER PRIMARY KEY, title TEXT NOT NULL DEFAULT '', description TEXT NOT NULL DEFAULT '',
			priority INTEGER NOT NULL DEFAULT 5, status TEXT NOT NULL DEFAULT 'pending',
			role TEXT NOT NULL DEFAULT '', depends_on TEXT NOT NULL DEFAULT '[]',
			result TEXT NOT NULL DEFAULT '', started_at TEXT, completed_at TEXT, deadline TEXT,
			verify_retries INTEGER NOT NULL DEFAULT 0, github_issue INTEGER NOT NULL DEFAULT 0,
			estimated_minutes INTEGER NOT NULL DEFAULT 0, actual_minutes INTEGER NOT NULL DEFAULT 0,
			artifact_path TEXT NOT NULL DEFAULT '', failure_diagnosis TEXT NOT NULL DEFAULT '',
			tags TEXT NOT NULL DEFAULT '[]', fail_count INTEGER NOT NULL DEFAULT 0,
			heal_attempts INTEGER NOT NULL DEFAULT 0, annotations TEXT NOT NULL DEFAULT '[]',
			condition_expr TEXT NOT NULL DEFAULT '', recurrence TEXT NOT NULL DEFAULT '', next_run_at TEXT,
			requires_approval INTEGER NOT NULL DEFAULT 0, approved INTEGER NOT NULL DEFAULT 0,
			max_minutes INTEGER NOT NULL DEFAULT 0, assignee TEXT NOT NULL DEFAULT '',
			external_url TEXT NOT NULL DEFAULT '', links TEXT NOT NULL DEFAULT '[]');
		CREATE TABLE steps (
			step INTEGER PRIMARY KEY, task TEXT NOT NULL DEFAULT '', output TEXT NOT NULL DEFAULT '',
			exit_code INTEGER NOT NULL DEFAULT 0, duration TEXT NOT NULL DEFAULT '', time TEXT NOT NULL DEFAULT '',
			input_tokens INTEGER NOT NULL DEFAULT 0, output_tokens INTEGER NOT NULL DEFAULT 0);
		INSERT INTO metadata(key, value) VALUES ('goal', 'an old project'), ('schema_version', '2'),
			('workdir', '` + dir + `');
		INSERT INTO plan_tasks(id, title, status) VALUES (1, 'kept', 'done');`); err != nil {
		t.Fatal(err)
	}
	return dir
}

// The defect: every project a current binary creates read as out of date,
// because the answer came from a key statedb never writes.
func TestNeedsUpgradeIsFalseForAProjectCloopCreatesToday(t *testing.T) {
	dir := currentProject(t)
	if NeedsUpgrade(dir) {
		t.Fatal("NeedsUpgrade = true for a project current cloop created")
	}
	st, err := Inspect(dir)
	if err != nil {
		t.Fatal(err)
	}
	if st.Kind != KindStatedb || st.SchemaVersion != latest(t) || st.Pending() != 0 {
		t.Fatalf("Inspect = %+v, want statedb's database at v%d", st, latest(t))
	}
}

func TestNeedsUpgradeForALegacyStateJSON(t *testing.T) {
	dir := legacyProject(t)
	if !NeedsUpgrade(dir) {
		t.Fatal("NeedsUpgrade = false for a project whose state is only in state.json")
	}
	if _, err := os.Stat(filepath.Join(dir, ".cloop", "state.db")); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("asking created state.db (stat: %v)", err)
	}

	// A database something opened for an unrelated reason holds no project, and
	// the project is still the state.json — what every command finds after
	// PersistentPreRunE's executor reconciliation has created that database.
	db, err := statedb.Open(filepath.Join(dir, ".cloop", "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	db.Close()
	if st, err := Inspect(dir); err != nil || st.Kind != KindLegacyJSON {
		t.Fatalf("Inspect beside an empty database = %+v, %v; want legacy-json", st, err)
	}
}

func TestNeedsUpgradeForADatabaseFromBeforeStatedbsMigrations(t *testing.T) {
	dir := preStatedbProject(t)
	if !NeedsUpgrade(dir) {
		t.Fatal("NeedsUpgrade = false for a database without schema_migrations")
	}
	if st, _ := Inspect(dir); st.Kind != KindPreStatedb {
		t.Fatalf("Kind = %q, want pre-statedb", st.Kind)
	}
}

func TestNeedsUpgradeOutsideAProject(t *testing.T) {
	if NeedsUpgrade(t.TempDir()) {
		t.Fatal("NeedsUpgrade = true with no .cloop directory")
	}
}

// Converting a legacy project goes through statedb, so the result is a
// database every other command can open — which the old conversion's was not.
func TestRunConvertsALegacyProjectThroughStatedb(t *testing.T) {
	dir := legacyProject(t)
	rep, _, err := Run(Options{WorkDir: dir})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if rep.Before.Kind != KindLegacyJSON || rep.After.Kind != KindStatedb || rep.After.SchemaVersion != latest(t) {
		t.Fatalf("report = %+v", rep)
	}
	if len(rep.Steps) != 1 || !strings.Contains(rep.Steps[0].Note, "(2 tasks, 1 steps)") {
		t.Fatalf("steps = %+v", rep.Steps)
	}

	st, err := state.Load(dir)
	if err != nil {
		t.Fatalf("the converted project does not load: %v", err)
	}
	if st.Goal != "a legacy project" || st.Plan == nil || len(st.Plan.Tasks) != 2 || len(st.Steps) != 1 {
		t.Fatalf("converted state = goal %q, plan %+v, %d steps", st.Goal, st.Plan, len(st.Steps))
	}
	assertNoSchemaVersionKey(t, dir)
	if NeedsUpgrade(dir) {
		t.Fatal("still NeedsUpgrade after Run")
	}
}

func TestRunAdoptsADatabaseFromBeforeStatedbsMigrations(t *testing.T) {
	dir := preStatedbProject(t)
	rep, _, err := Run(Options{WorkDir: dir})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if rep.After.Kind != KindStatedb || rep.After.SchemaVersion != latest(t) || len(rep.Steps) != 1 {
		t.Fatalf("report = %+v", rep)
	}
	st, err := state.Load(dir)
	if err != nil {
		t.Fatalf("the adopted project does not load: %v", err)
	}
	if st.Goal != "an old project" || len(st.Plan.Tasks) != 1 || st.Plan.Tasks[0].Title != "kept" {
		t.Fatalf("adopted state = goal %q, plan %+v", st.Goal, st.Plan)
	}
}

func TestRunDryRunWritesNothing(t *testing.T) {
	dir := legacyProject(t)
	rep, _, err := Run(Options{WorkDir: dir, DryRun: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Steps) != 1 || !strings.HasPrefix(rep.Steps[0].Note, "would convert") {
		t.Fatalf("steps = %+v", rep.Steps)
	}
	if _, err := os.Stat(filepath.Join(dir, ".cloop", "state.db")); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("a dry run created state.db (stat: %v)", err)
	}

	dir = preStatedbProject(t)
	if _, _, err := Run(Options{WorkDir: dir, DryRun: true}); err != nil {
		t.Fatal(err)
	}
	if st, _ := Inspect(dir); st.Kind != KindPreStatedb {
		t.Fatalf("a dry run adopted the database: %+v", st)
	}
}

// A database statedb owns is migrated by statedb, and Run adds nothing of its
// own: no schema_version key, no column statedb does not declare.
func TestRunOnACurrentProjectChangesNothing(t *testing.T) {
	dir := currentProject(t)
	rep, _, err := Run(Options{WorkDir: dir})
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Steps) != 0 || rep.After.SchemaVersion != rep.Before.SchemaVersion {
		t.Fatalf("report = %+v, want nothing done", rep)
	}
	assertNoSchemaVersionKey(t, dir)
}

func assertNoSchemaVersionKey(t *testing.T, dir string) {
	t.Helper()
	conn, err := statedb.OpenConn(state.DBPath(dir), statedb.ReadOnly)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	var n int
	if err := conn.QueryRow(`SELECT COUNT(*) FROM metadata WHERE key = 'schema_version'`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatal("metadata.schema_version was written: pkg/migrate keeps no version of its own")
	}
}
