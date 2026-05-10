// Package statedb provides a SQLite-backed persistent store for cloop project state.
// It replaces the JSON flat-file store with a normalized schema that allows
// concurrent-safe writes, real SQL queries for reporting, and historical task rows.
package statedb

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	_ "modernc.org/sqlite" // pure-Go SQLite driver, no CGo

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
	DefaultMaxMinutes int
	SkipClarify       bool
	InnovateMode      bool
	Parallel          bool
	MaxParallel       int
	PlanOnly          bool
	RetryFailed       bool
	DryRun            bool
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

// Open opens (or creates) the SQLite database at dbPath, applies tuning
// pragmas, and runs any pending schema migrations.
//
// Concurrency model: every cloop process (Web UI, orchestrator, CLI commands)
// opens its own *DB handle pointing at the same .cloop/state.db file. WAL
// mode + busy_timeout coordinate them at the SQLite file level, so writes
// from one process do not return SQLITE_BUSY to readers in another.
//
// Errors returned by this function may wrap the typed sentinels
// ErrDBLocked or ErrSchemaMismatch — callers should use errors.Is to
// distinguish them from generic open failures.
func Open(dbPath string) (*DB, error) {
	conn, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("statedb open %s: %w", dbPath, classifyDriverErr(err))
	}
	// One physical connection per *DB handle. Within a single process this
	// serialises all reads and writes through Go's connection pool so we
	// never hit intra-process lock contention; cross-process contention is
	// handled by the pragmas below. Bumping this above 1 is possible with
	// WAL but would require re-applying connection-scoped pragmas
	// (busy_timeout, synchronous) on every new connection.
	conn.SetMaxOpenConns(1)

	if err := applyPragmas(conn); err != nil {
		conn.Close()
		return nil, err
	}

	if _, err := Migrate(conn); err != nil {
		conn.Close()
		return nil, fmt.Errorf("statedb migrate: %w", err)
	}
	return &DB{conn: conn}, nil
}

// applyPragmas configures the SQLite connection for safe multi-process use.
//
//   - journal_mode=WAL: persistent file-level setting. Lets one writer and
//     many readers proceed without blocking each other. Required since
//     state.db is now shared by the Web UI, orchestrator, and CLI commands
//     (Task 20079 merged the queue and state DBs into a single file).
//   - busy_timeout=5000: when a connection encounters a lock, retry for up
//     to 5 seconds before returning SQLITE_BUSY. Prevents intermittent
//     "database is locked" errors under realistic load (Task 20084).
//   - synchronous=NORMAL: safe under WAL — a sudden power loss may lose
//     the very last commit but cannot corrupt the database — and is
//     several times faster than the FULL default for our write pattern.
func applyPragmas(conn *sql.DB) error {
	var mode string
	if err := conn.QueryRow(`PRAGMA journal_mode=WAL`).Scan(&mode); err != nil {
		return fmt.Errorf("statedb: enable WAL mode: %w", err)
	}
	if !strings.EqualFold(mode, "wal") {
		return fmt.Errorf("statedb: WAL mode rejected (got journal_mode=%q); filesystem may not support it", mode)
	}
	if _, err := conn.Exec(`PRAGMA busy_timeout=5000`); err != nil {
		return fmt.Errorf("statedb: set busy_timeout: %w", err)
	}
	if _, err := conn.Exec(`PRAGMA synchronous=NORMAL`); err != nil {
		return fmt.Errorf("statedb: set synchronous=NORMAL: %w", err)
	}
	// Connection-scoped: must be re-issued on every open. Migration files
	// can no longer rely on PRAGMA foreign_keys being part of their script
	// because each migration runs once, then never again.
	if _, err := conn.Exec(`PRAGMA foreign_keys=ON`); err != nil {
		return fmt.Errorf("statedb: enable foreign_keys: %w", err)
	}
	return nil
}

// Close releases the database connection.
func (d *DB) Close() error {
	return d.conn.Close()
}

// PingContext runs a `SELECT 1` against the underlying connection, honouring
// ctx for cancellation/deadline. Used by readiness probes (e.g. /readyz) to
// verify the SQLite store is reachable.
//
// Intentionally does NOT acquire d.mu: *sql.DB is concurrency-safe, and the
// mutex is reserved for transactional read-modify-write ops in this package.
// Holding it here would block readiness on whichever long-running write
// happens to own the lock — exactly what a probe must NOT do. The ctx
// timeout bounds wait time on the single underlying connection (we set
// MaxOpenConns(1)) when it is busy.
func (d *DB) PingContext(ctx context.Context) error {
	var one int
	if err := d.conn.QueryRowContext(ctx, "SELECT 1").Scan(&one); err != nil {
		return fmt.Errorf("statedb ping: %w", err)
	}
	if one != 1 {
		return fmt.Errorf("statedb ping: unexpected result %d", one)
	}
	return nil
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
	if err := d.saveStateLocked(s); err != nil {
		return err
	}
	// Audit emission must happen after the write commits and after the
	// caller-facing mutex is released. We snapshot the relevant fields here
	// so the audit row records the post-commit state.
	auditStateSave(d, s)
	auditPlanTasks(d, s)
	return nil
}

func (d *DB) saveStateLocked(s *State) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	tx, err := d.conn.Begin()
	if err != nil {
		return classifyDriverErr(err)
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
		"innovate_mode":       boolStr(s.InnovateMode),
		"parallel":            boolStr(s.Parallel),
		"max_parallel":        strconv.Itoa(s.MaxParallel),
		"plan_only":           boolStr(s.PlanOnly),
		"retry_failed":        boolStr(s.RetryFailed),
		"dry_run":             boolStr(s.DryRun),
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
	if len(s.Milestones) > 0 {
		b, _ := json.Marshal(s.Milestones)
		meta["milestones"] = string(b)
	} else {
		meta["milestones"] = ""
	}

	for k, v := range meta {
		if err := d.setMeta(tx, k, v); err != nil {
			return fmt.Errorf("set metadata %q: %w", k, classifyDriverErr(err))
		}
	}

	// ── plan tasks ──
	if _, err := tx.Exec(`DELETE FROM plan_tasks`); err != nil {
		return classifyDriverErr(err)
	}
	if s.Plan != nil {
		for _, t := range s.Plan.Tasks {
			if err := insertTask(tx, t); err != nil {
				return fmt.Errorf("insert task %d: %w", t.ID, classifyDriverErr(err))
			}
		}
	}

	// ── steps (upsert, never delete) ──
	for _, row := range s.Steps {
		if err := upsertStep(tx, row); err != nil {
			return fmt.Errorf("upsert step %d: %w", row.Step, classifyDriverErr(err))
		}
	}

	if err := tx.Commit(); err != nil {
		return classifyDriverErr(err)
	}
	return nil
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
		return nil, classifyDriverErr(err)
	}
	defer rows.Close()
	metaMap := make(map[string]string)
	for rows.Next() {
		var k, v string
		if err := rows.Scan(&k, &v); err != nil {
			return nil, classifyDriverErr(err)
		}
		metaMap[k] = v
	}
	if err := rows.Err(); err != nil {
		return nil, classifyDriverErr(err)
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
	s.InnovateMode = metaMap["innovate_mode"] == "1"
	s.Parallel = metaMap["parallel"] == "1"
	s.MaxParallel = atoi(metaMap["max_parallel"])
	s.PlanOnly = metaMap["plan_only"] == "1"
	s.RetryFailed = metaMap["retry_failed"] == "1"
	s.DryRun = metaMap["dry_run"] == "1"

	if v := metaMap["created_at"]; v != "" {
		s.CreatedAt, _ = time.Parse(time.RFC3339Nano, v)
	}
	if v := metaMap["updated_at"]; v != "" {
		s.UpdatedAt, _ = time.Parse(time.RFC3339Nano, v)
	}

	if v := metaMap["milestones"]; v != "" {
		if err := json.Unmarshal([]byte(v), &s.Milestones); err != nil {
			s.Milestones = nil
		}
	}

	// ── plan tasks ──
	tasks, err := loadTasks(d.conn)
	if err != nil {
		return nil, classifyDriverErr(err)
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
		return nil, classifyDriverErr(err)
	}

	return s, nil
}

// ────────────────────────────────────────────────────────────
// UpsertTask upserts a single task (for incremental updates).
// ────────────────────────────────────────────────────────────

func (d *DB) UpsertTask(t *pm.Task) error {
	d.mu.Lock()
	tx, err := d.conn.Begin()
	if err != nil {
		d.mu.Unlock()
		return classifyDriverErr(err)
	}
	if err := upsertTaskTx(tx, t); err != nil {
		_ = tx.Rollback()
		d.mu.Unlock()
		return classifyDriverErr(err)
	}
	if err := tx.Commit(); err != nil {
		d.mu.Unlock()
		return classifyDriverErr(err)
	}
	d.mu.Unlock()

	// Audit emission happens after commit so it cannot abort the user write.
	// AppendAuditEvent re-acquires d.mu internally; we released it above.
	auditTaskUpsert(d, t, "")
	return nil
}

// ────────────────────────────────────────────────────────────
// Config blob storage (Task 20075)
//
// Per-project config (.cloop/config.yaml) is mirrored into the metadata
// table under a single key. Keeping it as an opaque blob means future
// Config field additions don't require schema migrations — and SQLite
// remains the canonical queryable store next to state, costs, and steps.
// ────────────────────────────────────────────────────────────

const configMetaKey = "config_yaml"

// SetConfigBlob persists the YAML-serialised project config into the metadata
// table. The write is wrapped in a transaction so a crash mid-write leaves
// either the previous value or the new one — never a partial row.
func (d *DB) SetConfigBlob(yamlBlob string) error {
	d.mu.Lock()
	tx, err := d.conn.Begin()
	if err != nil {
		d.mu.Unlock()
		return fmt.Errorf("statedb: begin config tx: %w", err)
	}
	if err := d.setMeta(tx, configMetaKey, yamlBlob); err != nil {
		_ = tx.Rollback()
		d.mu.Unlock()
		return fmt.Errorf("statedb: set config blob: %w", err)
	}
	if err := tx.Commit(); err != nil {
		d.mu.Unlock()
		return err
	}
	d.mu.Unlock()

	// Audit emission. We log the *YAML content* directly so replay can rewrite
	// the config. Secrets in config.yaml are masked at the layer above (by
	// pkg/config) before the blob ever reaches us, so this is safe.
	auditConfigSet(d, yamlBlob, "")
	return nil
}

// GetConfigBlob returns the YAML-serialised project config previously stored
// via SetConfigBlob. Returns ("", nil) when no blob has been written yet
// (fresh project, or DB created before this column existed).
func (d *DB) GetConfigBlob() (string, error) {
	v, err := d.getMeta(configMetaKey)
	if err != nil {
		return "", fmt.Errorf("statedb: get config blob: %w", err)
	}
	return v, nil
}

// LoadTask returns a single task by ID. Returns ErrTaskNotFound if the task
// does not exist. Useful from HTTP handlers where the typical 404 path is
// "the requested task does not exist".
func (d *DB) LoadTask(id int) (*pm.Task, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	rows, err := d.conn.Query(`
		SELECT id, title, description, priority, status, role, depends_on, result,
			started_at, completed_at, deadline, verify_retries, github_issue,
			estimated_minutes, actual_minutes, artifact_path, failure_diagnosis,
			tags, fail_count, heal_attempts, annotations, condition_expr,
			recurrence, next_run_at, requires_approval, approved, max_minutes
		FROM plan_tasks WHERE id = ? LIMIT 1`, id)
	if err != nil {
		return nil, classifyDriverErr(err)
	}
	defer rows.Close()
	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return nil, classifyDriverErr(err)
		}
		return nil, fmt.Errorf("task %d: %w", id, ErrTaskNotFound)
	}
	t := &pm.Task{}
	var (
		status, role, depsJSON, tagsJSON, annJSON   string
		startedAt, completedAt, deadline, nextRunAt sql.NullString
		reqApproval, approved                       int
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
		return nil, classifyDriverErr(err)
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
	return t, nil
}

// DeleteTask removes a single task by id. Returns nil even if the row did
// not exist — the post-condition (task absent) is satisfied either way.
func (d *DB) DeleteTask(id int) error {
	d.mu.Lock()
	tx, err := d.conn.Begin()
	if err != nil {
		d.mu.Unlock()
		return classifyDriverErr(err)
	}
	if _, err := tx.Exec(`DELETE FROM plan_tasks WHERE id = ?`, id); err != nil {
		_ = tx.Rollback()
		d.mu.Unlock()
		return classifyDriverErr(err)
	}
	if err := tx.Commit(); err != nil {
		d.mu.Unlock()
		return classifyDriverErr(err)
	}
	d.mu.Unlock()

	AuditTaskDelete(d, id, "")
	return nil
}

// AppendStep inserts a step row (idempotent on step number).
func (d *DB) AppendStep(row StepRow) error {
	d.mu.Lock()
	tx, err := d.conn.Begin()
	if err != nil {
		d.mu.Unlock()
		return classifyDriverErr(err)
	}
	if err := upsertStep(tx, row); err != nil {
		_ = tx.Rollback()
		d.mu.Unlock()
		return classifyDriverErr(err)
	}
	if err := tx.Commit(); err != nil {
		d.mu.Unlock()
		return classifyDriverErr(err)
	}
	d.mu.Unlock()

	auditStepAppend(d, row, "")
	return nil
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
// CostEntry represents one API call cost record.
// ────────────────────────────────────────────────────────────

// CostEntry records the cost of one task execution in the costs table.
type CostEntry struct {
	Timestamp      time.Time
	TaskID         int
	TaskTitle      string
	Provider       string
	Model          string
	InputTokens    int
	OutputTokens   int
	ThinkingTokens int
	EstimatedUSD   float64
}

// AppendCost inserts a cost entry into the costs table.
func (d *DB) AppendCost(entry CostEntry) error {
	if entry.Timestamp.IsZero() {
		entry.Timestamp = time.Now().UTC()
	}
	d.mu.Lock()
	defer d.mu.Unlock()

	_, err := d.conn.Exec(`
		INSERT INTO costs(timestamp, task_id, task_title, provider, model,
			input_tokens, output_tokens, thinking_tokens, estimated_usd)
		VALUES(?,?,?,?,?,?,?,?,?)`,
		entry.Timestamp.UTC().Format(time.RFC3339Nano),
		entry.TaskID, entry.TaskTitle, entry.Provider, entry.Model,
		entry.InputTokens, entry.OutputTokens, entry.ThinkingTokens,
		entry.EstimatedUSD,
	)
	return classifyDriverErr(err)
}

// ReadCosts returns all cost entries ordered by timestamp ascending.
func (d *DB) ReadCosts() ([]CostEntry, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	rows, err := d.conn.Query(`
		SELECT timestamp, task_id, task_title, provider, model,
			input_tokens, output_tokens, thinking_tokens, estimated_usd
		FROM costs ORDER BY timestamp ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanCostRows(rows)
}

// ReadCostsSince returns cost entries with timestamp >= since, ordered ascending.
func (d *DB) ReadCostsSince(since time.Time) ([]CostEntry, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	rows, err := d.conn.Query(`
		SELECT timestamp, task_id, task_title, provider, model,
			input_tokens, output_tokens, thinking_tokens, estimated_usd
		FROM costs WHERE timestamp >= ? ORDER BY timestamp ASC`,
		since.UTC().Format(time.RFC3339Nano),
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanCostRows(rows)
}

// MonthlyCosts returns cost entries for the given UTC year/month.
func (d *DB) MonthlyCosts(year, month int) ([]CostEntry, error) {
	// Build inclusive date range: YYYY-MM-01 00:00:00 → YYYY-MM-01 of next month.
	start := time.Date(year, time.Month(month), 1, 0, 0, 0, 0, time.UTC)
	end := start.AddDate(0, 1, 0)
	d.mu.Lock()
	defer d.mu.Unlock()

	rows, err := d.conn.Query(`
		SELECT timestamp, task_id, task_title, provider, model,
			input_tokens, output_tokens, thinking_tokens, estimated_usd
		FROM costs WHERE timestamp >= ? AND timestamp < ? ORDER BY timestamp ASC`,
		start.Format(time.RFC3339Nano), end.Format(time.RFC3339Nano),
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanCostRows(rows)
}

func scanCostRows(rows *sql.Rows) ([]CostEntry, error) {
	var out []CostEntry
	for rows.Next() {
		var e CostEntry
		var ts string
		if err := rows.Scan(&ts, &e.TaskID, &e.TaskTitle, &e.Provider, &e.Model,
			&e.InputTokens, &e.OutputTokens, &e.ThinkingTokens, &e.EstimatedUSD); err != nil {
			return nil, err
		}
		e.Timestamp, _ = time.Parse(time.RFC3339Nano, ts)
		out = append(out, e)
	}
	return out, rows.Err()
}

// ────────────────────────────────────────────────────────────
// Stuck-task forensics (Task 20088)
// ────────────────────────────────────────────────────────────

// StuckEvent records one watchdog detection of a stuck in-flight task.
type StuckEvent struct {
	ID                int64
	TaskID            int
	TaskTitle         string
	StartedAt         time.Time
	DetectedAt        time.Time
	StuckForSeconds   int
	ArtifactIdleSecs  int
	ArtifactPath      string
	AutoKilled        bool
	Note              string
}

// AppendStuck inserts a stuck-task event row. The watchdog calls this once
// per detection per tick (a single task may produce many rows over its
// stuck lifetime, by design).
func (d *DB) AppendStuck(e StuckEvent) (int64, error) {
	if e.DetectedAt.IsZero() {
		e.DetectedAt = time.Now().UTC()
	}
	d.mu.Lock()
	defer d.mu.Unlock()

	res, err := d.conn.Exec(`
		INSERT INTO stuck_tasks(task_id, task_title, started_at, detected_at,
			stuck_for_seconds, artifact_idle_secs, artifact_path,
			auto_killed, note)
		VALUES(?,?,?,?,?,?,?,?,?)`,
		e.TaskID, e.TaskTitle,
		e.StartedAt.UTC().Format(time.RFC3339Nano),
		e.DetectedAt.UTC().Format(time.RFC3339Nano),
		e.StuckForSeconds, e.ArtifactIdleSecs, e.ArtifactPath,
		boolInt(e.AutoKilled), e.Note,
	)
	if err != nil {
		return 0, fmt.Errorf("statedb: append stuck event: %w", classifyDriverErr(err))
	}
	id, err := res.LastInsertId()
	if err != nil {
		return 0, fmt.Errorf("statedb: append stuck event: %w", classifyDriverErr(err))
	}
	return id, nil
}

// ReadStuck returns the most recent N stuck-task events, ordered most
// recent first. Pass 0 for an unbounded read.
func (d *DB) ReadStuck(limit int) ([]StuckEvent, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	q := `SELECT id, task_id, task_title, started_at, detected_at,
		stuck_for_seconds, artifact_idle_secs, artifact_path,
		auto_killed, note
		FROM stuck_tasks ORDER BY detected_at DESC, id DESC`
	if limit > 0 {
		q += fmt.Sprintf(" LIMIT %d", limit)
	}
	rows, err := d.conn.Query(q)
	if err != nil {
		return nil, fmt.Errorf("statedb: read stuck events: %w", classifyDriverErr(err))
	}
	defer rows.Close()

	var out []StuckEvent
	for rows.Next() {
		var e StuckEvent
		var startedAt, detectedAt string
		var autoKilled int
		if err := rows.Scan(&e.ID, &e.TaskID, &e.TaskTitle,
			&startedAt, &detectedAt,
			&e.StuckForSeconds, &e.ArtifactIdleSecs, &e.ArtifactPath,
			&autoKilled, &e.Note); err != nil {
			return nil, classifyDriverErr(err)
		}
		e.StartedAt, _ = time.Parse(time.RFC3339Nano, startedAt)
		e.DetectedAt, _ = time.Parse(time.RFC3339Nano, detectedAt)
		e.AutoKilled = autoKilled == 1
		out = append(out, e)
	}
	return out, classifyDriverErr(rows.Err())
}

// ReadStuckSince returns stuck events with detected_at >= since, ordered
// most recent first. Used by the UI's poll loop to surface only events
// the client has not yet seen.
func (d *DB) ReadStuckSince(since time.Time) ([]StuckEvent, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	rows, err := d.conn.Query(`
		SELECT id, task_id, task_title, started_at, detected_at,
			stuck_for_seconds, artifact_idle_secs, artifact_path,
			auto_killed, note
		FROM stuck_tasks
		WHERE detected_at >= ?
		ORDER BY detected_at DESC, id DESC`,
		since.UTC().Format(time.RFC3339Nano),
	)
	if err != nil {
		return nil, fmt.Errorf("statedb: read stuck events: %w", classifyDriverErr(err))
	}
	defer rows.Close()

	var out []StuckEvent
	for rows.Next() {
		var e StuckEvent
		var startedAt, detectedAt string
		var autoKilled int
		if err := rows.Scan(&e.ID, &e.TaskID, &e.TaskTitle,
			&startedAt, &detectedAt,
			&e.StuckForSeconds, &e.ArtifactIdleSecs, &e.ArtifactPath,
			&autoKilled, &e.Note); err != nil {
			return nil, err
		}
		e.StartedAt, _ = time.Parse(time.RFC3339Nano, startedAt)
		e.DetectedAt, _ = time.Parse(time.RFC3339Nano, detectedAt)
		e.AutoKilled = autoKilled == 1
		out = append(out, e)
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
