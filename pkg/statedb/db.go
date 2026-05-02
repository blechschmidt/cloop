// Package statedb provides a SQLite-backed persistent store for cloop project state.
// It replaces the JSON flat-file store with a normalized schema that allows
// concurrent-safe writes, real SQL queries for reporting, and historical task rows.
package statedb

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"strconv"
	"sync"
	"time"

	_ "modernc.org/sqlite" // pure-Go SQLite driver, no CGo

	"github.com/blechschmidt/cloop/pkg/health"
	"github.com/blechschmidt/cloop/pkg/milestone"
	"github.com/blechschmidt/cloop/pkg/pm"
)

// State mirrors pkg/state.ProjectState but is owned by this package to avoid
// import cycles. pkg/state converts between the two representations.
type State struct {
	Goal              string
	WorkDir           string
	MaxSteps          int
	CurrentStep       int
	Status            string
	Steps             []StepRow
	CreatedAt         time.Time
	UpdatedAt         time.Time
	Model             string
	Instructions      string
	AutoEvolve        bool
	EvolveStep        int
	Provider          string
	PMMode            bool
	Plan              *pm.Plan
	Milestones        []*milestone.Milestone
	TotalInputTokens  int
	TotalOutputTokens int
	HealthReport      *health.HealthReport
	DefaultMaxMinutes int
	SkipClarify       bool
}

// StepRow represents one recorded step result.
type StepRow struct {
	Step         int
	Task         string
	Output       string
	ExitCode     int
	Duration     string
	Time         time.Time
	InputTokens  int
	OutputTokens int
}

// DB is a thread-safe handle to the SQLite state database.
// Open one DB per workdir; Close it when done.
type DB struct {
	mu   sync.Mutex
	conn *sql.DB
}

const schema = `
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
    max_minutes       INTEGER NOT NULL DEFAULT 0
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

// Open opens (or creates) the SQLite database at dbPath and applies the schema.
func Open(dbPath string) (*DB, error) {
	conn, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("statedb open %s: %w", dbPath, err)
	}
	// Single writer connection; WAL mode allows concurrent readers.
	conn.SetMaxOpenConns(1)

	if _, err := conn.Exec(schema); err != nil {
		conn.Close()
		return nil, fmt.Errorf("statedb schema: %w", err)
	}
	return &DB{conn: conn}, nil
}

// Close releases the database connection.
func (d *DB) Close() error {
	return d.conn.Close()
}

// ────────────────────────────────────────────────────────────
// Metadata helpers
// ────────────────────────────────────────────────────────────

func (d *DB) setMeta(tx *sql.Tx, key, value string) error {
	_, err := tx.Exec(
		`INSERT INTO metadata(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value`,
		key, value,
	)
	return err
}

func (d *DB) getMeta(key string) (string, error) {
	var v string
	err := d.conn.QueryRow(`SELECT value FROM metadata WHERE key=?`, key).Scan(&v)
	if err == sql.ErrNoRows {
		return "", nil
	}
	return v, err
}

// ────────────────────────────────────────────────────────────
// SaveState persists the full project state atomically.
// ────────────────────────────────────────────────────────────

func (d *DB) SaveState(s *State) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	tx, err := d.conn.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck

	// ── scalar metadata ──
	meta := map[string]string{
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

	// plan-level fields
	if s.Plan != nil {
		meta["plan_goal"] = s.Plan.Goal
		meta["plan_version"] = strconv.Itoa(s.Plan.Version)
	} else {
		meta["plan_goal"] = ""
		meta["plan_version"] = "0"
	}

	// JSON blob fields
	if s.HealthReport != nil {
		b, _ := json.Marshal(s.HealthReport)
		meta["health_report"] = string(b)
	} else {
		meta["health_report"] = ""
	}
	if len(s.Milestones) > 0 {
		b, _ := json.Marshal(s.Milestones)
		meta["milestones"] = string(b)
	} else {
		meta["milestones"] = ""
	}

	for k, v := range meta {
		if err := d.setMeta(tx, k, v); err != nil {
			return fmt.Errorf("set metadata %q: %w", k, err)
		}
	}

	// ── plan tasks ──
	if _, err := tx.Exec(`DELETE FROM plan_tasks`); err != nil {
		return err
	}
	if s.Plan != nil {
		for _, t := range s.Plan.Tasks {
			if err := insertTask(tx, t); err != nil {
				return fmt.Errorf("insert task %d: %w", t.ID, err)
			}
		}
	}

	// ── steps (upsert, never delete) ──
	for _, row := range s.Steps {
		if err := upsertStep(tx, row); err != nil {
			return fmt.Errorf("upsert step %d: %w", row.Step, err)
		}
	}

	return tx.Commit()
}

// ────────────────────────────────────────────────────────────
// LoadState reads the full project state from the database.
// ────────────────────────────────────────────────────────────

func (d *DB) LoadState() (*State, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	s := &State{}

	// ── scalar metadata ──
	rows, err := d.conn.Query(`SELECT key, value FROM metadata`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	metaMap := make(map[string]string)
	for rows.Next() {
		var k, v string
		if err := rows.Scan(&k, &v); err != nil {
			return nil, err
		}
		metaMap[k] = v
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	s.Goal = metaMap["goal"]
	s.WorkDir = metaMap["workdir"]
	s.MaxSteps = atoi(metaMap["max_steps"])
	s.CurrentStep = atoi(metaMap["current_step"])
	s.Status = metaMap["status"]
	s.Model = metaMap["model"]
	s.Instructions = metaMap["instructions"]
	s.AutoEvolve = metaMap["auto_evolve"] == "1"
	s.EvolveStep = atoi(metaMap["evolve_step"])
	s.Provider = metaMap["provider"]
	s.PMMode = metaMap["pm_mode"] == "1"
	s.TotalInputTokens = atoi(metaMap["total_input_tokens"])
	s.TotalOutputTokens = atoi(metaMap["total_output_tokens"])
	s.DefaultMaxMinutes = atoi(metaMap["default_max_minutes"])
	s.SkipClarify = metaMap["skip_clarify"] == "1"

	if v := metaMap["created_at"]; v != "" {
		s.CreatedAt, _ = time.Parse(time.RFC3339Nano, v)
	}
	if v := metaMap["updated_at"]; v != "" {
		s.UpdatedAt, _ = time.Parse(time.RFC3339Nano, v)
	}

	if v := metaMap["health_report"]; v != "" {
		s.HealthReport = &health.HealthReport{}
		if err := json.Unmarshal([]byte(v), s.HealthReport); err != nil {
			s.HealthReport = nil
		}
	}
	if v := metaMap["milestones"]; v != "" {
		if err := json.Unmarshal([]byte(v), &s.Milestones); err != nil {
			s.Milestones = nil
		}
	}

	// ── plan tasks ──
	tasks, err := loadTasks(d.conn)
	if err != nil {
		return nil, err
	}
	planGoal := metaMap["plan_goal"]
	planVersion := atoi(metaMap["plan_version"])
	if planGoal != "" || len(tasks) > 0 {
		s.Plan = &pm.Plan{
			Goal:    planGoal,
			Tasks:   tasks,
			Version: planVersion,
		}
	}

	// ── steps ──
	s.Steps, err = loadSteps(d.conn)
	if err != nil {
		return nil, err
	}

	return s, nil
}

// ────────────────────────────────────────────────────────────
// UpsertTask upserts a single task (for incremental updates).
// ────────────────────────────────────────────────────────────

func (d *DB) UpsertTask(t *pm.Task) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	tx, err := d.conn.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck

	if err := upsertTaskTx(tx, t); err != nil {
		return err
	}
	return tx.Commit()
}

// AppendStep inserts a step row (idempotent on step number).
func (d *DB) AppendStep(row StepRow) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	tx, err := d.conn.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck

	if err := upsertStep(tx, row); err != nil {
		return err
	}
	return tx.Commit()
}

// ────────────────────────────────────────────────────────────
// Internal helpers
// ────────────────────────────────────────────────────────────

func insertTask(tx *sql.Tx, t *pm.Task) error {
	return upsertTaskTx(tx, t)
}

func upsertTaskTx(tx *sql.Tx, t *pm.Task) error {
	depsJSON, _ := json.Marshal(t.DependsOn)
	tagsJSON, _ := json.Marshal(t.Tags)
	annJSON, _ := json.Marshal(t.Annotations)

	var startedAt, completedAt, deadline, nextRunAt sql.NullString
	if t.StartedAt != nil {
		startedAt = sql.NullString{String: t.StartedAt.Format(time.RFC3339Nano), Valid: true}
	}
	if t.CompletedAt != nil {
		completedAt = sql.NullString{String: t.CompletedAt.Format(time.RFC3339Nano), Valid: true}
	}
	if t.Deadline != nil {
		deadline = sql.NullString{String: t.Deadline.Format(time.RFC3339Nano), Valid: true}
	}
	if t.NextRunAt != nil {
		nextRunAt = sql.NullString{String: t.NextRunAt.Format(time.RFC3339Nano), Valid: true}
	}

	_, err := tx.Exec(`
		INSERT INTO plan_tasks(
			id, title, description, priority, status, role, depends_on, result,
			started_at, completed_at, deadline, verify_retries, github_issue,
			estimated_minutes, actual_minutes, artifact_path, failure_diagnosis,
			tags, fail_count, heal_attempts, annotations, condition_expr,
			recurrence, next_run_at, requires_approval, approved, max_minutes
		) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
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
			approved=excluded.approved, max_minutes=excluded.max_minutes`,
		t.ID, t.Title, t.Description, t.Priority, string(t.Status), string(t.Role),
		string(depsJSON), t.Result,
		startedAt, completedAt, deadline,
		t.VerifyRetries, t.GitHubIssue,
		t.EstimatedMinutes, t.ActualMinutes,
		t.ArtifactPath, t.FailureDiagnosis,
		string(tagsJSON), t.FailCount, t.HealAttempts,
		string(annJSON), t.Condition, t.Recurrence,
		nextRunAt,
		boolInt(t.RequiresApproval), boolInt(t.Approved),
		t.MaxMinutes,
	)
	return err
}

func loadTasks(conn *sql.DB) ([]*pm.Task, error) {
	rows, err := conn.Query(`
		SELECT id, title, description, priority, status, role, depends_on, result,
			started_at, completed_at, deadline, verify_retries, github_issue,
			estimated_minutes, actual_minutes, artifact_path, failure_diagnosis,
			tags, fail_count, heal_attempts, annotations, condition_expr,
			recurrence, next_run_at, requires_approval, approved, max_minutes
		FROM plan_tasks ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var tasks []*pm.Task
	for rows.Next() {
		t := &pm.Task{}
		var (
			status, role, depsJSON, tagsJSON, annJSON string
			startedAt, completedAt, deadline, nextRunAt sql.NullString
			reqApproval, approved                     int
		)
		if err := rows.Scan(
			&t.ID, &t.Title, &t.Description, &t.Priority, &status, &role,
			&depsJSON, &t.Result,
			&startedAt, &completedAt, &deadline,
			&t.VerifyRetries, &t.GitHubIssue,
			&t.EstimatedMinutes, &t.ActualMinutes,
			&t.ArtifactPath, &t.FailureDiagnosis,
			&tagsJSON, &t.FailCount, &t.HealAttempts,
			&annJSON, &t.Condition, &t.Recurrence,
			&nextRunAt, &reqApproval, &approved, &t.MaxMinutes,
		); err != nil {
			return nil, err
		}
		t.Status = pm.TaskStatus(status)
		t.Role = pm.AgentRole(role)
		_ = json.Unmarshal([]byte(depsJSON), &t.DependsOn)
		_ = json.Unmarshal([]byte(tagsJSON), &t.Tags)
		_ = json.Unmarshal([]byte(annJSON), &t.Annotations)
		t.RequiresApproval = reqApproval == 1
		t.Approved = approved == 1
		if startedAt.Valid {
			ts, _ := time.Parse(time.RFC3339Nano, startedAt.String)
			t.StartedAt = &ts
		}
		if completedAt.Valid {
			ts, _ := time.Parse(time.RFC3339Nano, completedAt.String)
			t.CompletedAt = &ts
		}
		if deadline.Valid {
			ts, _ := time.Parse(time.RFC3339Nano, deadline.String)
			t.Deadline = &ts
		}
		if nextRunAt.Valid {
			ts, _ := time.Parse(time.RFC3339Nano, nextRunAt.String)
			t.NextRunAt = &ts
		}
		tasks = append(tasks, t)
	}
	return tasks, rows.Err()
}

func upsertStep(tx *sql.Tx, row StepRow) error {
	_, err := tx.Exec(`
		INSERT INTO steps(step, task, output, exit_code, duration, time, input_tokens, output_tokens)
		VALUES(?,?,?,?,?,?,?,?)
		ON CONFLICT(step) DO UPDATE SET
			task=excluded.task, output=excluded.output, exit_code=excluded.exit_code,
			duration=excluded.duration, time=excluded.time,
			input_tokens=excluded.input_tokens, output_tokens=excluded.output_tokens`,
		row.Step, row.Task, row.Output, row.ExitCode, row.Duration,
		row.Time.Format(time.RFC3339Nano),
		row.InputTokens, row.OutputTokens,
	)
	return err
}

func loadSteps(conn *sql.DB) ([]StepRow, error) {
	rows, err := conn.Query(`SELECT step, task, output, exit_code, duration, time, input_tokens, output_tokens FROM steps ORDER BY step`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []StepRow
	for rows.Next() {
		var r StepRow
		var ts string
		if err := rows.Scan(&r.Step, &r.Task, &r.Output, &r.ExitCode, &r.Duration, &ts, &r.InputTokens, &r.OutputTokens); err != nil {
			return nil, err
		}
		r.Time, _ = time.Parse(time.RFC3339Nano, ts)
		out = append(out, r)
	}
	return out, rows.Err()
}

// ────────────────────────────────────────────────────────────
// Utility
// ────────────────────────────────────────────────────────────

func boolStr(b bool) string {
	if b {
		return "1"
	}
	return "0"
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func atoi(s string) int {
	n, _ := strconv.Atoi(s)
	return n
}
