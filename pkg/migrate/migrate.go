// Package migrate provides versioned schema upgrade and repair for .cloop directories.
// It detects the current schema version, runs idempotent migration steps, and
// repairs common corruption such as orphaned snapshot files and missing columns.
package migrate

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	_ "modernc.org/sqlite" // pure-Go driver

	"github.com/blechschmidt/cloop/pkg/pm"
)

// CurrentVersion is the highest schema version this binary understands.
const CurrentVersion = 2

// Report summarises what was (or would be) done during a migration run.
type Report struct {
	FromVersion   int
	ToVersion     int
	DryRun        bool
	Steps         []StepReport
	Warnings      []string
	RowsMigrated  int
	FilesConverted int
}

// StepReport is the outcome of a single versioned migration step.
type StepReport struct {
	From    int
	To      int
	Applied bool   // false when already up-to-date
	Note    string // human-readable summary
}

// RepairReport describes a single repair action.
type RepairReport struct {
	Kind    string // "orphan_snapshot", "missing_column", "invalid_config_key"
	Detail  string
	Fixed   bool
}

// Options controls migration behaviour.
type Options struct {
	WorkDir     string
	DryRun      bool
	FromVersion int // -1 = auto-detect
}

// Run detects the schema version, applies all pending migrations, and repairs
// common corruption. It returns a Report describing what happened.
func Run(opts Options) (*Report, []RepairReport, error) {
	workDir := opts.WorkDir
	dotcloop := filepath.Join(workDir, ".cloop")

	report := &Report{DryRun: opts.DryRun}

	// ── Detect current version ───────────────────────────────────────────────
	currentVersion, err := detectVersion(dotcloop, opts.FromVersion)
	if err != nil {
		return nil, nil, fmt.Errorf("detect version: %w", err)
	}
	report.FromVersion = currentVersion
	report.ToVersion = currentVersion // updated below as migrations succeed

	if currentVersion == CurrentVersion {
		// Nothing to migrate; run repairs only.
		repairs, err := repairExisting(dotcloop, opts.DryRun)
		return report, repairs, err
	}

	// ── Run versioned steps ──────────────────────────────────────────────────
	for from := currentVersion; from < CurrentVersion; from++ {
		to := from + 1
		step, rowsMigrated, filesConverted, err := runStep(dotcloop, from, to, opts.DryRun)
		if err != nil {
			return report, nil, fmt.Errorf("migration v%d→v%d: %w", from, to, err)
		}
		report.Steps = append(report.Steps, step)
		report.RowsMigrated += rowsMigrated
		report.FilesConverted += filesConverted
		if step.Applied {
			report.ToVersion = to
		}
	}

	// ── Repairs ─────────────────────────────────────────────────────────────
	repairs, err := repairExisting(dotcloop, opts.DryRun)
	return report, repairs, err
}

// NeedsUpgrade returns true when the .cloop directory exists but the schema
// version is behind CurrentVersion. It never returns an error on missing dirs.
func NeedsUpgrade(workDir string) bool {
	dotcloop := filepath.Join(workDir, ".cloop")
	if _, err := os.Stat(dotcloop); err != nil {
		return false // no project
	}
	v, err := detectVersion(dotcloop, -1)
	if err != nil {
		return false // can't determine — don't spam warnings
	}
	return v < CurrentVersion
}

// ─────────────────────────────────────────────────────────────────────────────
// Version detection
// ─────────────────────────────────────────────────────────────────────────────

func detectVersion(dotcloop string, override int) (int, error) {
	if override >= 0 {
		return override, nil
	}

	dbPath := filepath.Join(dotcloop, "state.db")
	jsonPath := filepath.Join(dotcloop, "state.json")

	// No state at all → v0 (empty project; nothing to migrate).
	dbExists := fileExists(dbPath)
	jsonExists := fileExists(jsonPath)
	if !dbExists && !jsonExists {
		return CurrentVersion, nil // pristine; migrations not needed
	}

	// Legacy JSON only → v0 (needs v0→v1 migration).
	if !dbExists && jsonExists {
		return 0, nil
	}

	// state.db exists: read schema_version from metadata table.
	conn, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return 0, fmt.Errorf("open state.db: %w", err)
	}
	defer conn.Close()

	// Ensure the metadata table exists (very old databases may lack it).
	var v string
	err = conn.QueryRow(`SELECT value FROM metadata WHERE key='schema_version'`).Scan(&v)
	if err == sql.ErrNoRows || err != nil {
		// DB exists but no schema_version → v1.
		return 1, nil
	}
	n, _ := strconv.Atoi(v)
	return n, nil
}

// ─────────────────────────────────────────────────────────────────────────────
// Versioned migration steps
// ─────────────────────────────────────────────────────────────────────────────

func runStep(dotcloop string, from, to int, dryRun bool) (StepReport, int, int, error) {
	switch {
	case from == 0 && to == 1:
		return stepV0toV1(dotcloop, dryRun)
	case from == 1 && to == 2:
		return stepV1toV2(dotcloop, dryRun)
	default:
		return StepReport{From: from, To: to, Note: "unknown step"}, 0, 0,
			fmt.Errorf("no migration step defined for v%d→v%d", from, to)
	}
}

// stepV0toV1 converts .cloop/state.json to .cloop/state.db.
func stepV0toV1(dotcloop string, dryRun bool) (StepReport, int, int, error) {
	step := StepReport{From: 0, To: 1}
	jsonPath := filepath.Join(dotcloop, "state.json")
	dbPath := filepath.Join(dotcloop, "state.db")

	if !fileExists(jsonPath) {
		step.Note = "state.json not found; skipping"
		return step, 0, 0, nil
	}

	raw, err := os.ReadFile(jsonPath)
	if err != nil {
		return step, 0, 0, fmt.Errorf("read state.json: %w", err)
	}

	// Parse the legacy JSON state.
	var legacy legacyState
	if err := json.Unmarshal(raw, &legacy); err != nil {
		return step, 0, 0, fmt.Errorf("parse state.json: %w", err)
	}

	rowsMigrated := 0
	filesConverted := 0

	if dryRun {
		n := 0
		if legacy.Plan != nil {
			n = len(legacy.Plan.Tasks)
		}
		step.Applied = true
		step.Note = fmt.Sprintf("dry-run: would convert state.json → state.db (%d tasks, %d steps)",
			n, len(legacy.Steps))
		return step, n + len(legacy.Steps), 1, nil
	}

	// Open (or create) the target database.
	conn, err := openDB(dbPath)
	if err != nil {
		return step, 0, 0, err
	}
	defer conn.Close()

	tx, err := conn.Begin()
	if err != nil {
		return step, 0, 0, err
	}
	defer tx.Rollback() //nolint:errcheck

	// ── scalar metadata ──
	meta := buildMetaFromLegacy(&legacy)
	for k, v := range meta {
		if err := upsertMeta(tx, k, v); err != nil {
			return step, 0, 0, fmt.Errorf("upsert meta %q: %w", k, err)
		}
	}

	// ── plan tasks ──
	if legacy.Plan != nil {
		for _, t := range legacy.Plan.Tasks {
			if err := upsertTask(tx, t); err != nil {
				return step, 0, 0, fmt.Errorf("insert task %d: %w", t.ID, err)
			}
			rowsMigrated++
		}
	}

	// ── steps ──
	for i, s := range legacy.Steps {
		if err := upsertStep(tx, i+1, s); err != nil {
			return step, 0, 0, fmt.Errorf("insert step %d: %w", i+1, err)
		}
		rowsMigrated++
	}

	// ── set schema_version = 1 ──
	if err := upsertMeta(tx, "schema_version", "1"); err != nil {
		return step, 0, 0, err
	}

	if err := tx.Commit(); err != nil {
		return step, 0, 0, err
	}

	filesConverted = 1
	step.Applied = true
	step.Note = fmt.Sprintf("converted state.json → state.db (%d tasks, %d steps)", rowsMigrated-len(legacy.Steps), len(legacy.Steps))
	return step, rowsMigrated, filesConverted, nil
}

// stepV1toV2 adds columns introduced after the initial SQLite migration:
// assignee, external_url, links (all in plan_tasks).
func stepV1toV2(dotcloop string, dryRun bool) (StepReport, int, int, error) {
	step := StepReport{From: 1, To: 2}
	dbPath := filepath.Join(dotcloop, "state.db")

	if !fileExists(dbPath) {
		step.Note = "state.db not found; skipping"
		return step, 0, 0, nil
	}

	conn, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return step, 0, 0, fmt.Errorf("open state.db: %w", err)
	}
	defer conn.Close()

	// Determine which columns are missing.
	existing, err := columnSet(conn, "plan_tasks")
	if err != nil {
		return step, 0, 0, err
	}

	type colDef struct {
		name string
		ddl  string
	}
	needed := []colDef{
		{"assignee", "TEXT NOT NULL DEFAULT ''"},
		{"external_url", "TEXT NOT NULL DEFAULT ''"},
		{"links", "TEXT NOT NULL DEFAULT '[]'"},
	}

	var missing []colDef
	for _, c := range needed {
		if !existing[c.name] {
			missing = append(missing, c)
		}
	}

	if len(missing) == 0 {
		// Bump schema_version and return.
		if !dryRun {
			if _, err := conn.Exec(`INSERT INTO metadata(key,value) VALUES('schema_version','2') ON CONFLICT(key) DO UPDATE SET value='2'`); err != nil {
				return step, 0, 0, err
			}
		}
		step.Note = "all columns present; schema_version bumped to 2"
		step.Applied = true
		return step, 0, 0, nil
	}

	if dryRun {
		names := make([]string, len(missing))
		for i, c := range missing {
			names[i] = c.name
		}
		step.Applied = true
		step.Note = fmt.Sprintf("dry-run: would add columns: %s", strings.Join(names, ", "))
		return step, 0, 0, nil
	}

	for _, c := range missing {
		sql := fmt.Sprintf("ALTER TABLE plan_tasks ADD COLUMN %s %s", c.name, c.ddl)
		if _, err := conn.Exec(sql); err != nil {
			return step, 0, 0, fmt.Errorf("ALTER TABLE add %s: %w", c.name, err)
		}
	}

	if _, err := conn.Exec(`INSERT INTO metadata(key,value) VALUES('schema_version','2') ON CONFLICT(key) DO UPDATE SET value='2'`); err != nil {
		return step, 0, 0, err
	}

	names := make([]string, len(missing))
	for i, c := range missing {
		names[i] = c.name
	}
	step.Applied = true
	step.Note = fmt.Sprintf("added columns: %s", strings.Join(names, ", "))
	return step, 0, 0, nil
}

// ─────────────────────────────────────────────────────────────────────────────
// Repair
// ─────────────────────────────────────────────────────────────────────────────

func repairExisting(dotcloop string, dryRun bool) ([]RepairReport, error) {
	var repairs []RepairReport

	r, err := repairOrphanSnapshots(dotcloop, dryRun)
	repairs = append(repairs, r...)
	if err != nil {
		return repairs, err
	}

	r2, err := repairConfigTypes(dotcloop, dryRun)
	repairs = append(repairs, r2...)
	return repairs, err
}

// repairOrphanSnapshots removes plan-history snapshot files whose task IDs
// no longer exist in the current plan_tasks table.
func repairOrphanSnapshots(dotcloop string, dryRun bool) ([]RepairReport, error) {
	histDir := filepath.Join(dotcloop, "plan-history")
	if _, err := os.Stat(histDir); err != nil {
		return nil, nil // no snapshots dir
	}

	dbPath := filepath.Join(dotcloop, "state.db")
	if !fileExists(dbPath) {
		return nil, nil
	}

	conn, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	// Collect known task IDs.
	rows, err := conn.Query(`SELECT id FROM plan_tasks`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	knownIDs := map[int]bool{}
	for rows.Next() {
		var id int
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		knownIDs[id] = true
	}

	var repairs []RepairReport
	_ = filepath.WalkDir(histDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".json") {
			return nil
		}
		// Quick parse: check if file references task IDs that no longer exist.
		raw, e := os.ReadFile(path)
		if e != nil {
			return nil
		}
		var snap snapshotFile
		if e := json.Unmarshal(raw, &snap); e != nil {
			return nil
		}
		orphaned := false
		for _, t := range snap.Tasks {
			if !knownIDs[t.ID] && len(snap.Tasks) == 1 {
				orphaned = true
				break
			}
		}
		if orphaned {
			rep := RepairReport{
				Kind:   "orphan_snapshot",
				Detail: fmt.Sprintf("%s references non-existent task IDs", filepath.Base(path)),
			}
			if !dryRun {
				if e := os.Remove(path); e == nil {
					rep.Fixed = true
				}
			}
			repairs = append(repairs, rep)
		}
		return nil
	})

	return repairs, nil
}

// repairConfigTypes checks config.yaml for keys with obviously wrong types
// (e.g. numeric strings for boolean fields).
func repairConfigTypes(dotcloop string, dryRun bool) ([]RepairReport, error) {
	cfgPath := filepath.Join(dotcloop, "config.yaml")
	raw, err := os.ReadFile(cfgPath)
	if err != nil {
		return nil, nil // no config; nothing to repair
	}

	var repairs []RepairReport
	lines := strings.Split(string(raw), "\n")
	boolKeys := map[string]bool{
		"auto_evolve": true,
		"pm_mode":     true,
		"skip_clarify": true,
	}
	for i, line := range lines {
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		val := strings.TrimSpace(parts[1])
		if !boolKeys[key] {
			continue
		}
		// Accept "true", "false", "yes", "no", "1", "0" — flag anything else.
		switch strings.ToLower(val) {
		case "true", "false", "yes", "no", "1", "0", "":
			continue
		default:
			rep := RepairReport{
				Kind:   "invalid_config_key",
				Detail: fmt.Sprintf("config.yaml line %d: key %q has unexpected value %q (expected bool)", i+1, key, val),
			}
			repairs = append(repairs, rep)
		}
	}
	return repairs, nil
}

// ─────────────────────────────────────────────────────────────────────────────
// SQLite helpers
// ─────────────────────────────────────────────────────────────────────────────

const createSchema = `
PRAGMA journal_mode=WAL;
PRAGMA busy_timeout=5000;
PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS metadata (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS plan_tasks (
    id                INTEGER PRIMARY KEY,
    title             TEXT    NOT NULL DEFAULT '',
    description       TEXT    NOT NULL DEFAULT '',
    priority          INTEGER NOT NULL DEFAULT 5,
    status            TEXT    NOT NULL DEFAULT 'pending',
    role              TEXT    NOT NULL DEFAULT '',
    depends_on        TEXT    NOT NULL DEFAULT '[]',
    result            TEXT    NOT NULL DEFAULT '',
    started_at        TEXT,
    completed_at      TEXT,
    deadline          TEXT,
    verify_retries    INTEGER NOT NULL DEFAULT 0,
    github_issue      INTEGER NOT NULL DEFAULT 0,
    estimated_minutes INTEGER NOT NULL DEFAULT 0,
    actual_minutes    INTEGER NOT NULL DEFAULT 0,
    artifact_path     TEXT    NOT NULL DEFAULT '',
    failure_diagnosis TEXT    NOT NULL DEFAULT '',
    tags              TEXT    NOT NULL DEFAULT '[]',
    fail_count        INTEGER NOT NULL DEFAULT 0,
    heal_attempts     INTEGER NOT NULL DEFAULT 0,
    annotations       TEXT    NOT NULL DEFAULT '[]',
    condition_expr    TEXT    NOT NULL DEFAULT '',
    recurrence        TEXT    NOT NULL DEFAULT '',
    next_run_at       TEXT,
    requires_approval INTEGER NOT NULL DEFAULT 0,
    approved          INTEGER NOT NULL DEFAULT 0,
    max_minutes       INTEGER NOT NULL DEFAULT 0,
    assignee          TEXT    NOT NULL DEFAULT '',
    external_url      TEXT    NOT NULL DEFAULT '',
    links             TEXT    NOT NULL DEFAULT '[]'
);

CREATE TABLE IF NOT EXISTS steps (
    step          INTEGER PRIMARY KEY,
    task          TEXT    NOT NULL DEFAULT '',
    output        TEXT    NOT NULL DEFAULT '',
    exit_code     INTEGER NOT NULL DEFAULT 0,
    duration      TEXT    NOT NULL DEFAULT '',
    time          TEXT    NOT NULL DEFAULT '',
    input_tokens  INTEGER NOT NULL DEFAULT 0,
    output_tokens INTEGER NOT NULL DEFAULT 0
);
`

func openDB(path string) (*sql.DB, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	conn, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	conn.SetMaxOpenConns(1)
	if _, err := conn.Exec(createSchema); err != nil {
		conn.Close()
		return nil, err
	}
	return conn, nil
}

func upsertMeta(tx *sql.Tx, key, value string) error {
	_, err := tx.Exec(
		`INSERT INTO metadata(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value`,
		key, value,
	)
	return err
}

func upsertTask(tx *sql.Tx, t *pm.Task) error {
	depsJSON, _ := json.Marshal(t.DependsOn)
	tagsJSON, _ := json.Marshal(t.Tags)
	annJSON, _ := json.Marshal(t.Annotations)
	linksJSON, _ := json.Marshal(t.Links)

	boolInt := func(b bool) int {
		if b {
			return 1
		}
		return 0
	}
	nullStr := func(tp *time.Time) sql.NullString {
		if tp == nil {
			return sql.NullString{}
		}
		return sql.NullString{String: tp.Format(time.RFC3339Nano), Valid: true}
	}

	_, err := tx.Exec(`
		INSERT INTO plan_tasks(
			id, title, description, priority, status, role, depends_on, result,
			started_at, completed_at, deadline, verify_retries, github_issue,
			estimated_minutes, actual_minutes, artifact_path, failure_diagnosis,
			tags, fail_count, heal_attempts, annotations, condition_expr,
			recurrence, next_run_at, requires_approval, approved, max_minutes,
			assignee, external_url, links
		) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
		ON CONFLICT(id) DO UPDATE SET
			title=excluded.title, description=excluded.description,
			priority=excluded.priority, status=excluded.status, role=excluded.role,
			depends_on=excluded.depends_on, result=excluded.result,
			started_at=excluded.started_at, completed_at=excluded.completed_at,
			deadline=excluded.deadline, verify_retries=excluded.verify_retries,
			github_issue=excluded.github_issue,
			estimated_minutes=excluded.estimated_minutes,
			actual_minutes=excluded.actual_minutes,
			artifact_path=excluded.artifact_path,
			failure_diagnosis=excluded.failure_diagnosis,
			tags=excluded.tags, fail_count=excluded.fail_count,
			heal_attempts=excluded.heal_attempts, annotations=excluded.annotations,
			condition_expr=excluded.condition_expr, recurrence=excluded.recurrence,
			next_run_at=excluded.next_run_at,
			requires_approval=excluded.requires_approval,
			approved=excluded.approved, max_minutes=excluded.max_minutes,
			assignee=excluded.assignee, external_url=excluded.external_url,
			links=excluded.links`,
		t.ID, t.Title, t.Description, t.Priority, string(t.Status), string(t.Role),
		string(depsJSON), t.Result,
		nullStr(t.StartedAt), nullStr(t.CompletedAt), nullStr(t.Deadline),
		t.VerifyRetries, t.GitHubIssue,
		t.EstimatedMinutes, t.ActualMinutes,
		t.ArtifactPath, t.FailureDiagnosis,
		string(tagsJSON), t.FailCount, t.HealAttempts,
		string(annJSON), t.Condition, t.Recurrence,
		nullStr(t.NextRunAt),
		boolInt(t.RequiresApproval), boolInt(t.Approved),
		t.MaxMinutes,
		t.Assignee, t.ExternalURL, string(linksJSON),
	)
	return err
}

func upsertStep(tx *sql.Tx, step int, s legacyStep) error {
	ts := ""
	if !s.Time.IsZero() {
		ts = s.Time.Format(time.RFC3339Nano)
	}
	_, err := tx.Exec(`
		INSERT INTO steps(step, task, output, exit_code, duration, time, input_tokens, output_tokens)
		VALUES(?,?,?,?,?,?,?,?)
		ON CONFLICT(step) DO UPDATE SET
			task=excluded.task, output=excluded.output, exit_code=excluded.exit_code,
			duration=excluded.duration, time=excluded.time,
			input_tokens=excluded.input_tokens, output_tokens=excluded.output_tokens`,
		step, s.Task, s.Output, s.ExitCode, s.Duration, ts, s.InputTokens, s.OutputTokens,
	)
	return err
}

func columnSet(conn *sql.DB, table string) (map[string]bool, error) {
	rows, err := conn.Query(fmt.Sprintf("PRAGMA table_info(%s)", table))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	cols := map[string]bool{}
	for rows.Next() {
		var cid int
		var name, typ string
		var notNull, pk int
		var dflt sql.NullString
		if err := rows.Scan(&cid, &name, &typ, &notNull, &dflt, &pk); err != nil {
			return nil, err
		}
		cols[name] = true
	}
	return cols, rows.Err()
}

// ─────────────────────────────────────────────────────────────────────────────
// Legacy JSON state structures
// ─────────────────────────────────────────────────────────────────────────────

type legacyState struct {
	Goal              string        `json:"goal"`
	WorkDir           string        `json:"workdir"`
	MaxSteps          int           `json:"max_steps"`
	CurrentStep       int           `json:"current_step"`
	Status            string        `json:"status"`
	Steps             []legacyStep  `json:"steps"`
	CreatedAt         time.Time     `json:"created_at"`
	UpdatedAt         time.Time     `json:"updated_at"`
	Model             string        `json:"model,omitempty"`
	Instructions      string        `json:"instructions,omitempty"`
	AutoEvolve        bool          `json:"auto_evolve"`
	EvolveStep        int           `json:"evolve_step"`
	Provider          string        `json:"provider,omitempty"`
	PMMode            bool          `json:"pm_mode,omitempty"`
	Plan              *pm.Plan      `json:"plan,omitempty"`
	TotalInputTokens  int           `json:"total_input_tokens,omitempty"`
	TotalOutputTokens int           `json:"total_output_tokens,omitempty"`
	DefaultMaxMinutes int           `json:"default_max_minutes,omitempty"`
	SkipClarify       bool          `json:"skip_clarify,omitempty"`
}

type legacyStep struct {
	Step         int       `json:"step"`
	Task         string    `json:"task"`
	Output       string    `json:"output"`
	ExitCode     int       `json:"exit_code"`
	Duration     string    `json:"duration"`
	Time         time.Time `json:"time"`
	InputTokens  int       `json:"input_tokens,omitempty"`
	OutputTokens int       `json:"output_tokens,omitempty"`
}

// snapshotFile is the shape of a plan-history JSON snapshot (partial parse).
type snapshotFile struct {
	Tasks []*pm.Task `json:"tasks"`
}

func buildMetaFromLegacy(s *legacyState) map[string]string {
	boolStr := func(b bool) string {
		if b {
			return "1"
		}
		return "0"
	}
	m := map[string]string{
		"goal":                s.Goal,
		"workdir":             s.WorkDir,
		"max_steps":           strconv.Itoa(s.MaxSteps),
		"current_step":        strconv.Itoa(s.CurrentStep),
		"status":              s.Status,
		"model":               s.Model,
		"instructions":        s.Instructions,
		"auto_evolve":         boolStr(s.AutoEvolve),
		"evolve_step":         strconv.Itoa(s.EvolveStep),
		"provider":            s.Provider,
		"pm_mode":             boolStr(s.PMMode),
		"total_input_tokens":  strconv.Itoa(s.TotalInputTokens),
		"total_output_tokens": strconv.Itoa(s.TotalOutputTokens),
		"default_max_minutes": strconv.Itoa(s.DefaultMaxMinutes),
		"skip_clarify":        boolStr(s.SkipClarify),
		"created_at":          s.CreatedAt.Format(time.RFC3339Nano),
		"updated_at":          s.UpdatedAt.Format(time.RFC3339Nano),
	}
	if s.Plan != nil {
		m["plan_goal"] = s.Plan.Goal
		m["plan_version"] = strconv.Itoa(s.Plan.Version)
	}
	return m
}

// ─────────────────────────────────────────────────────────────────────────────
// Util
// ─────────────────────────────────────────────────────────────────────────────

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
