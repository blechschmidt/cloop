// Package statedb provides a SQLite-backed persistent store for cloop project state.
// It replaces the JSON flat-file store with a normalized schema that allows
// concurrent-safe writes, real SQL queries for reporting, and historical task rows.
package statedb

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	_ "modernc.org/sqlite" // pure-Go SQLite driver, no CGo

	"github.com/blechschmidt/cloop/pkg/milestone"
	"github.com/blechschmidt/cloop/pkg/pausereason"
	"github.com/blechschmidt/cloop/pkg/pm"
)

// State mirrors pkg/state.ProjectState but is owned by this package to avoid
// import cycles. pkg/state converts between the two representations.
type State struct {
	Goal        string
	WorkDir     string
	MaxSteps    int
	CurrentStep int
	Status      string
	// PauseReason explains a "paused" Status. Stored as JSON in the
	// schemaless metadata table rather than as a column, so adding it needed
	// no migration — and an older binary reading this DB just ignores the key
	// instead of being locked out by a schema it does not know.
	PauseReason *pausereason.Reason
	Steps       []StepRow
	// StepCount mirrors len(Steps) on full loads but is also populated by
	// LoadStateLite — where Steps is nil — so callers that only need a
	// count don't have to materialize every row's Output (Task 20125).
	StepCount int
	// LastStepTime is the timestamp of the newest step row. Populated by
	// both LoadState (last element of Steps) and LoadStateLite (cheap
	// lookup of the highest step number); used by health probes to detect
	// stalled runs without scanning the full Steps slice.
	LastStepTime      time.Time
	CreatedAt         time.Time
	UpdatedAt         time.Time
	Model             string
	Instructions      string
	AutoEvolve        bool
	EvolveStep        int
	Provider          string
	Effort            string
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
	WorktreeParallel  bool
	PlanOnly          bool
	RetryFailed       bool
	DryRun            bool
	// ReviewGate is the project's review-gate configuration (Task 20357),
	// stored as JSON under the review_gate meta key. Nil when never set.
	ReviewGate *pm.ReviewGate
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

	// role is which of the two audit chains this handle may write to, set by
	// AsControlPlane or AsProject. Zero means unclassified, which asserts
	// nothing. See audit_home.go.
	role roleField
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
// distinguish them from generic open failures. A database migrated past this
// binary's schema is refused with ErrSchemaTooNew rather than opened; see
// schema_guard.go.
func Open(dbPath string) (*DB, error) {
	return OpenWithOptions(dbPath, OpenOptions{
		AllowSchemaDowngrade: AllowSchemaDowngradeFromEnv(),
	})
}

// OpenOptions configures OpenWithOptions.
type OpenOptions struct {
	// AllowSchemaDowngrade opens a database whose schema is ahead of this
	// binary's instead of refusing it. Open sets this from
	// CLOOP_ALLOW_SCHEMA_DOWNGRADE; diagnostics that must read a skewed
	// database in order to report on it set it directly.
	AllowSchemaDowngrade bool
}

// OpenWithOptions is Open with the version-skew opt-out under the caller's
// control rather than the environment's.
func OpenWithOptions(dbPath string, opts OpenOptions) (*DB, error) {
	conn, err := sql.Open("sqlite", connString(dbPath))
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

	if _, err := MigrateWithOptions(conn, MigrateOptions{
		AllowSchemaDowngrade: opts.AllowSchemaDowngrade,
	}); err != nil {
		conn.Close()
		// A version-skew refusal is already a complete, operator-facing
		// sentence naming both versions, the build that moved the schema and
		// the way out. Prefixing it with "statedb migrate:" only buries the
		// lede in what is, for a rolled-back hub, the first thing printed at
		// startup.
		var tooNew *SchemaTooNewError
		if errors.As(err, &tooNew) {
			return nil, err
		}
		return nil, fmt.Errorf("statedb migrate: %w", err)
	}
	return &DB{conn: conn}, nil
}

// connString is dbPath plus the settings the driver applies to every
// connection it opens, before the first statement runs (Task 20349).
//
// They used to be issued by applyPragmas after the connection existed, with
// `PRAGMA journal_mode=WAL` first. So the open itself had no busy handler: a
// hub opening a project's database just as a `cloop run` closed it — the last
// close of a WAL database checkpoints under an exclusive lock — failed at once
// with "enable WAL mode: database is locked". The driver applies busy_timeout
// ahead of every other pragma, so it now covers the WAL pragma, the migration
// check and everything after; and a connection the pool reopens gets the same
// settings, where one issued once by applyPragmas would have lost them.
//
// _txlock=immediate makes every transaction take the write lock at BEGIN
// rather than at its first write. Every transaction statedb opens reads and
// then writes, and a deferred one fails instantly with SQLITE_BUSY_SNAPSHOT
// (517) — no busy handler, no retry — whenever another handle commits between
// its read and its write: two handles appending audit rows concurrently lost
// half of them that way. An immediate transaction waits on busy_timeout
// instead, and in WAL mode readers are not blocked by it.
func connString(dbPath string) string {
	return dbPath + "?" + url.Values{
		"_pragma": {"busy_timeout(5000)", "foreign_keys(1)", "synchronous(NORMAL)"},
		"_txlock": {"immediate"},
	}.Encode()
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
//
// connString already applies busy_timeout, synchronous and foreign_keys when
// the driver opens the connection, busy_timeout before anything else; they are
// repeated here, busy_timeout first, so a connection string built elsewhere
// cannot quietly lose them.
func applyPragmas(conn *sql.DB) error {
	if _, err := conn.Exec(`PRAGMA busy_timeout=5000`); err != nil {
		return fmt.Errorf("statedb: set busy_timeout: %w", err)
	}
	var mode string
	if err := conn.QueryRow(`PRAGMA journal_mode=WAL`).Scan(&mode); err != nil {
		return fmt.Errorf("statedb: enable WAL mode: %w", err)
	}
	if !strings.EqualFold(mode, "wal") {
		return fmt.Errorf("statedb: WAL mode rejected (got journal_mode=%q); filesystem may not support it", mode)
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

// getMeta reads one metadata value inside an open transaction. It is separate
// from the (*DB).getMeta below because that one queries d.conn directly, and
// issuing a read on the same connection while a write transaction is open on
// it is a different question than the caller means to ask.
func getMeta(tx *sql.Tx, key string) (string, error) {
	var v string
	err := tx.QueryRow(`SELECT value FROM metadata WHERE key=?`, key).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	return v, err
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
	changed, deleted, edges, err := d.saveStateLocked(s)
	if err != nil {
		return err
	}
	// Audit emission must happen after the write commits and after the
	// caller-facing mutex is released. We snapshot the relevant fields here
	// so the audit row records the post-commit state.
	//
	// Only genuinely changed tasks are emitted: saveStateLocked diffed them
	// against their stored fingerprints inside its own transaction, before the
	// wholesale rewrite destroyed the previous values. See audit_fingerprint.go
	// for why that diff cannot be done here.
	auditStateSave(d, s)
	auditPlanTasks(d, changed, deleted)
	auditTaskLifecycle(d, edges, s.WorkDir)
	return nil
}

// saveStateLocked writes the state and returns the task-audit delta the write
// produced: tasks whose audit payload changed, ids that disappeared, and the
// tasks that crossed the execution boundary in either direction.
func (d *DB) saveStateLocked(s *State) (changed []taskAuditChange, deleted []int, edges []taskLifecycleEdge, err error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	tx, err := d.conn.Begin()
	if err != nil {
		return nil, nil, nil, classifyDriverErr(err)
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
		"effort":              s.Effort,
		"pm_mode":             boolStr(s.PMMode),
		"total_input_tokens":  strconv.Itoa(s.TotalInputTokens),
		"total_output_tokens": strconv.Itoa(s.TotalOutputTokens),
		"default_max_minutes": strconv.Itoa(s.DefaultMaxMinutes),
		"skip_clarify":        boolStr(s.SkipClarify),
		"innovate_mode":       boolStr(s.InnovateMode),
		"parallel":            boolStr(s.Parallel),
		"max_parallel":        strconv.Itoa(s.MaxParallel),
		"worktree_parallel":   boolStr(s.WorktreeParallel),
		"plan_only":           boolStr(s.PlanOnly),
		"retry_failed":        boolStr(s.RetryFailed),
		"dry_run":             boolStr(s.DryRun),
		"created_at":          s.CreatedAt.Format(time.RFC3339Nano),
		"updated_at":          s.UpdatedAt.Format(time.RFC3339Nano),
	}

	// plan-level fields. A nil Plan means "no plan loaded" (e.g. saving
	// before decomposition), NOT "plan intentionally emptied" — leave the
	// stored plan metadata untouched so externally-added tasks and their
	// goal survive. An intentionally emptied plan is a non-nil Plan with
	// zero tasks, which still replaces the stored rows below.
	if s.Plan != nil {
		meta["plan_goal"] = s.Plan.Goal
		meta["plan_version"] = strconv.Itoa(s.Plan.Version)
	}

	// JSON blob fields
	if len(s.Milestones) > 0 {
		b, _ := json.Marshal(s.Milestones)
		meta["milestones"] = string(b)
	} else {
		meta["milestones"] = ""
	}

	// Written unconditionally — including the empty string — because clearing
	// matters as much as setting: a run that resumes must not leave last
	// week's cap pause behind for the dashboard to keep reporting.
	if pr := pausereason.Normalize(s.Status, s.PauseReason); pr != nil {
		b, _ := json.Marshal(pr)
		meta["pause_reason"] = string(b)
	} else {
		meta["pause_reason"] = ""
	}

	// The review gate (Task 20357) is written only when this state carries
	// one. A process holding an older copy without it must not be able to
	// switch a project's gate off by saving; the gate is changed through
	// SaveReviewGate, and switched off by storing it disabled.
	if s.ReviewGate != nil {
		b, _ := json.Marshal(s.ReviewGate)
		meta["review_gate"] = string(b)
	}

	// workdir is write-once: it records where the project was created, and the
	// process saving is not always in a position to know that. An isolating
	// executor bind-mounts the project somewhere of its own — the container
	// driver uses /workspace — so a task running in a sandbox would otherwise
	// overwrite the hub's own path with one that exists only inside a mount
	// namespace that has since been torn down. state.Load already tolerates a
	// stored path that does not resolve (see resolveWorkDir there), but a
	// record the hub cannot act on is still worse than the one it wrote, and
	// pkg/ui's stale-run recovery refuses to repair a project whose state
	// points somewhere else.
	if existing, err := getMeta(tx, "workdir"); err != nil {
		return nil, nil, nil, fmt.Errorf("read metadata %q: %w", "workdir", classifyDriverErr(err))
	} else if existing != "" {
		delete(meta, "workdir")
	}

	for k, v := range meta {
		if err := d.setMeta(tx, k, v); err != nil {
			return nil, nil, nil, fmt.Errorf("set metadata %q: %w", k, classifyDriverErr(err))
		}
	}

	// ── plan tasks ──
	// Only replace the stored task rows when the incoming state actually
	// carries a plan. When s.Plan is nil the caller never loaded (or never
	// had) a plan, and deleting here would destroy tasks added externally
	// (e.g. via the UI) before decomposition ran.
	if s.Plan != nil {
		// Diff before the rewrite: after the DELETE the previous payloads are
		// gone, and "what changed" is unanswerable. The fingerprint table is
		// updated in this same transaction, so a rollback below leaves the
		// audit bookkeeping exactly as consistent as the tasks.
		changed, deleted, err = diffPlanTaskFingerprints(tx, s.Plan.Tasks)
		if err != nil {
			return nil, nil, nil, err
		}
		// Execution-boundary detection, in the same transaction and for the
		// same reason: the cursor it advances must commit or roll back with
		// the statuses it describes (Task 20282).
		edges, err = diffTaskLifecycle(tx, s.Plan.Tasks)
		if err != nil {
			return nil, nil, nil, err
		}
		if _, err := tx.Exec(`DELETE FROM plan_tasks`); err != nil {
			return nil, nil, nil, classifyDriverErr(err)
		}
		if err := insertTasks(tx, s.Plan.Tasks); err != nil {
			return nil, nil, nil, err
		}
	}

	// ── steps (upsert, never delete) ──
	for _, row := range s.Steps {
		if err := upsertStep(tx, row); err != nil {
			return nil, nil, nil, fmt.Errorf("upsert step %d: %w", row.Step, classifyDriverErr(err))
		}
	}

	if err := tx.Commit(); err != nil {
		return nil, nil, nil, classifyDriverErr(err)
	}
	return changed, deleted, edges, nil
}

// HasProjectState reports whether any project state has ever been written to
// this database — that is, whether the metadata table holds a row.
//
// It distinguishes a database that merely *exists* from one that holds a
// project. Opening a state.db creates the file and every table in it, so file
// existence alone says nothing: several code paths open a project's database
// for reasons unrelated to its state (executor reconciliation does it on every
// CLI invocation), and each of them leaves behind a complete but empty
// database. Callers that need "is there a project here" must ask this.
func (d *DB) HasProjectState() (bool, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	var one int
	err := d.conn.QueryRow(`SELECT 1 FROM metadata LIMIT 1`).Scan(&one)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, classifyDriverErr(err)
	}
	return true, nil
}

// ────────────────────────────────────────────────────────────
// LoadState reads the full project state from the database.
// ────────────────────────────────────────────────────────────

func (d *DB) LoadState() (*State, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	s, err := d.loadStateMetaTx()
	if err != nil {
		return nil, err
	}
	s.Steps, err = loadSteps(d.conn)
	if err != nil {
		return nil, classifyDriverErr(err)
	}
	s.StepCount = len(s.Steps)
	if n := len(s.Steps); n > 0 {
		s.LastStepTime = s.Steps[n-1].Time
	}
	return s, nil
}

// LoadStateLite is like LoadState but skips loading the per-step rows
// (which on long-running projects can be megabytes of Output strings). The
// returned State has Steps == nil; StepCount and LastStepTime are filled
// from cheap aggregate SQL so handlers that only render counts or check
// last-activity for health don't pay for decoding every Output (Task 20125).
func (d *DB) LoadStateLite() (*State, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	s, err := d.loadStateMetaTx()
	if err != nil {
		return nil, err
	}
	// The newest step is the one with the highest step number (the monotonic
	// primary key) — NOT MAX(time), which compares RFC3339 strings
	// lexicographically and breaks across timezone offsets and trimmed
	// trailing zeros.
	var ts string
	if err := d.conn.QueryRow(
		`SELECT COUNT(*), IFNULL((SELECT time FROM steps ORDER BY step DESC LIMIT 1), '') FROM steps`,
	).Scan(&s.StepCount, &ts); err != nil {
		return nil, classifyDriverErr(err)
	}
	if ts != "" {
		s.LastStepTime, _ = time.Parse(time.RFC3339Nano, ts)
	}
	return s, nil
}

// loadStateMetaTx loads metadata + plan tasks (never steps). Caller must
// hold d.mu. Shared by LoadState and LoadStateLite.
func (d *DB) loadStateMetaTx() (*State, error) {
	s := &State{}

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
	s.Effort = metaMap["effort"]
	s.PMMode = metaMap["pm_mode"] == "1"
	s.TotalInputTokens = atoi(metaMap["total_input_tokens"])
	s.TotalOutputTokens = atoi(metaMap["total_output_tokens"])
	s.DefaultMaxMinutes = atoi(metaMap["default_max_minutes"])
	s.SkipClarify = metaMap["skip_clarify"] == "1"
	s.InnovateMode = metaMap["innovate_mode"] == "1"
	s.Parallel = metaMap["parallel"] == "1"
	s.MaxParallel = atoi(metaMap["max_parallel"])
	s.WorktreeParallel = metaMap["worktree_parallel"] == "1"
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

	if v := metaMap["pause_reason"]; v != "" {
		var pr pausereason.Reason
		if err := json.Unmarshal([]byte(v), &pr); err == nil {
			// Normalize drops a reason whose code this binary does not know,
			// so a row written by a newer cloop degrades to a bare "paused"
			// rather than rendering a code the UI has no label for.
			s.PauseReason = pausereason.Normalize(s.Status, &pr)
		}
	}

	if v := metaMap["review_gate"]; v != "" {
		var g pm.ReviewGate
		if err := json.Unmarshal([]byte(v), &g); err == nil {
			s.ReviewGate = &g
		}
	}

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
	// Keep the audit fingerprint in step with the row, in the same transaction
	// as the row. A single-task write that skipped this would leave SaveState's
	// diff comparing against a stale value — harmlessly re-emitting in one
	// direction, and silently swallowing a real change in the other.
	payload := MarshalAuditPayload(t)
	if err := recordTaskFingerprintTx(tx, t.ID, payload); err != nil {
		_ = tx.Rollback()
		d.mu.Unlock()
		return err
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

	rows, err := d.conn.Query(taskSelect+` WHERE id = ? LIMIT 1`, id)
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
	t, err := newTaskScanner().scan(rows)
	if err != nil {
		return nil, classifyDriverErr(err)
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
	// Drop the audit fingerprint with the row. Task ids are reused (see the
	// merge logic in pkg/state), and a fingerprint outliving its task would
	// make the next task to claim that id look unchanged against a predecessor
	// it has nothing to do with — an unrelated task's creation going unaudited.
	if err := forgetTaskFingerprintTx(tx, id); err != nil {
		_ = tx.Rollback()
		d.mu.Unlock()
		return err
	}
	// Same reasoning for the run correlation: an id reused later must start
	// from "never dispatched" rather than inheriting the run and lifecycle
	// cursor of an unrelated task, which would suppress its first dispatch row.
	if err := forgetTaskRunTx(tx, id); err != nil {
		_ = tx.Rollback()
		d.mu.Unlock()
		return err
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

// insertTasks writes every task of a plan through one prepared statement.
//
// Preparing it once rather than per row is most of the cost of a save: the
// statement names every column, and an unprepared Exec has SQLite compile it
// afresh for each task — 70% of SaveState's time for a 400-task plan, measured
// when 0054 made the statement a third longer (Task 20361).
func insertTasks(tx *sql.Tx, tasks []*pm.Task) error {
	stmt, err := tx.Prepare(upsertTaskSQL)
	if err != nil {
		return fmt.Errorf("prepare task insert: %w", classifyDriverErr(err))
	}
	defer stmt.Close()
	for _, t := range tasks {
		if _, err := stmt.Exec(taskValues(t)...); err != nil {
			return fmt.Errorf("insert task %d: %w", t.ID, classifyDriverErr(err))
		}
	}
	return nil
}

// taskColumns are plan_tasks' columns in the order upsertTaskTx writes them and
// taskScanner reads them back.
//
// One list for both directions, from which the INSERT, its ON CONFLICT update
// and the SELECT are all built. The writer and the two readers used to carry a
// hand-written copy each, and all three had missed the same fourteen pm.Task
// fields since the move from state.json to SQLite (Task 20361): an assignee, a
// sprint, a plan's on_success branches all read back as zero after the next
// load. TestEveryTaskFieldSurvivesTheDatabase in taskroundtrip_test.go is what
// keeps this list complete; the order here has to match taskValues and
// newTaskScanner, which the same test checks by giving every field its own value.
var taskColumns = []string{
	"id", "title", "description", "priority", "status", "role", "depends_on", "result",
	"started_at", "completed_at", "deadline", "verify_retries", "github_issue",
	"estimated_minutes", "actual_minutes", "artifact_path", "failure_diagnosis",
	"tags", "fail_count", "heal_attempts", "annotations", "condition_expr",
	"recurrence", "next_run_at", "requires_approval", "approved", "max_minutes",
	"write_back_branch", "write_back_commit", "background", "abort",
	"executor_id", "executor_kind", "isolation", "pinned", "review",
	// 0054_task_fields (Task 20361).
	"assignee", "external_url", "links", "tdd_status", "tdd_score",
	"sprint_id", "complexity_size", "story_points", "on_success", "on_failure",
	"risk_score", "impact_score", "retry_budget",
}

// taskSelect reads every task column, then the task's run id. The run id is not
// a plan_tasks column: it lives in task_runs, which SaveState's lifecycle diff
// maintains (Task 20282).
var taskSelect = `SELECT ` + strings.Join(taskColumns, ", ") + `,
		COALESCE((SELECT run_id FROM task_runs WHERE task_runs.task_id = plan_tasks.id), '')
	FROM plan_tasks`

// upsertTaskSQL writes every column of taskColumns, replacing all but the id
// on conflict.
var upsertTaskSQL = func() string {
	updates := make([]string, 0, len(taskColumns)-1)
	for _, c := range taskColumns[1:] {
		updates = append(updates, c+"=excluded."+c)
	}
	return `INSERT INTO plan_tasks(` + strings.Join(taskColumns, ", ") + `) VALUES (` +
		strings.TrimSuffix(strings.Repeat("?,", len(taskColumns)), ",") + `)
		ON CONFLICT(id) DO UPDATE SET ` + strings.Join(updates, ", ")
}()

// taskValues returns t's values in taskColumns order.
func taskValues(t *pm.Task) []any {
	return []any{
		t.ID, t.Title, t.Description, t.Priority, string(t.Status), string(t.Role),
		listText(t.DependsOn), t.Result,
		timeText(t.StartedAt), timeText(t.CompletedAt), timeText(t.Deadline),
		t.VerifyRetries, t.GitHubIssue,
		t.EstimatedMinutes, t.ActualMinutes,
		t.ArtifactPath, t.FailureDiagnosis,
		listText(t.Tags), t.FailCount, t.HealAttempts,
		listText(t.Annotations), t.Condition, t.Recurrence,
		timeText(t.NextRunAt),
		boolInt(t.RequiresApproval), boolInt(t.Approved),
		t.MaxMinutes,
		t.WriteBackBranch, t.WriteBackCommit, encodeBackground(t.Background),
		encodeAbort(t.Abort),
		t.ExecutorID, t.ExecutorKind, t.Isolation, boolInt(t.Pinned),
		encodeReview(t.Review),
		t.Assignee, t.ExternalURL, listText(t.Links), t.TDDStatus, t.TDDScore,
		t.SprintID, t.ComplexitySize, t.StoryPoints, listText(t.OnSuccess), listText(t.OnFailure),
		t.RiskScore, t.ImpactScore, t.RetryBudget,
	}
}

func upsertTaskTx(tx *sql.Tx, t *pm.Task) error {
	_, err := tx.Exec(upsertTaskSQL, taskValues(t)...)
	return err
}

// taskScanner reads rows selected by taskSelect. It is the only reader of a
// task row, so LoadTask and loadTasks cannot disagree about what one holds.
//
// Rows are scanned into one reusable set of destinations and then copied out,
// so a load does not allocate Scan's argument list — one pointer per column,
// some fifty of them — once for every task. The plan is read on every
// dashboard request.
type taskScanner struct {
	row                                         pm.Task
	status, role                                string
	lists                                       taskListColumns
	bgJSON, abortJSON, reviewJSON               string
	startedAt, completedAt, deadline, nextRunAt sql.NullString
	reqApproval, approved, pinned               int
	dest                                        []any
}

func newTaskScanner() *taskScanner {
	sc := &taskScanner{}
	t := &sc.row
	sc.dest = []any{
		&t.ID, &t.Title, &t.Description, &t.Priority, &sc.status, &sc.role,
		&sc.lists.DependsOn, &t.Result,
		&sc.startedAt, &sc.completedAt, &sc.deadline,
		&t.VerifyRetries, &t.GitHubIssue,
		&t.EstimatedMinutes, &t.ActualMinutes,
		&t.ArtifactPath, &t.FailureDiagnosis,
		&sc.lists.Tags, &t.FailCount, &t.HealAttempts,
		&sc.lists.Annotations, &t.Condition, &t.Recurrence,
		&sc.nextRunAt, &sc.reqApproval, &sc.approved, &t.MaxMinutes,
		&t.WriteBackBranch, &t.WriteBackCommit, &sc.bgJSON, &sc.abortJSON,
		&t.ExecutorID, &t.ExecutorKind, &t.Isolation, &sc.pinned, &sc.reviewJSON,
		&t.Assignee, &t.ExternalURL, &sc.lists.Links, &t.TDDStatus, &t.TDDScore,
		&t.SprintID, &t.ComplexitySize, &t.StoryPoints, &sc.lists.OnSuccess, &sc.lists.OnFailure,
		&t.RiskScore, &t.ImpactScore, &t.RetryBudget,
		&t.RunID,
	}
	return sc
}

// scan reads the current row into a new task.
//
// A list column that is damaged in a way that would change what runs fails
// the read with ErrCorruptTaskColumn; see decodeTaskColumns.
func (sc *taskScanner) scan(rows rowScanner) (*pm.Task, error) {
	sc.row = pm.Task{}
	if err := rows.Scan(sc.dest...); err != nil {
		return nil, err
	}
	t := new(pm.Task)
	*t = sc.row
	t.Status = pm.TaskStatus(sc.status)
	t.Role = pm.AgentRole(sc.role)
	if err := decodeTaskColumns(t, sc.lists); err != nil {
		return nil, err
	}
	t.Background = decodeBackground(sc.bgJSON)
	t.Abort = decodeAbort(sc.abortJSON)
	t.Review = decodeReview(sc.reviewJSON)
	t.RequiresApproval = sc.reqApproval == 1
	t.Approved = sc.approved == 1
	t.Pinned = sc.pinned == 1
	t.StartedAt = parseTimeText(sc.startedAt)
	t.CompletedAt = parseTimeText(sc.completedAt)
	t.Deadline = parseTimeText(sc.deadline)
	t.NextRunAt = parseTimeText(sc.nextRunAt)
	return t, nil
}

func loadTasks(conn *sql.DB) ([]*pm.Task, error) {
	rows, err := conn.Query(taskSelect + ` ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var tasks []*pm.Task
	sc := newTaskScanner()
	for rows.Next() {
		t, err := sc.scan(rows)
		if err != nil {
			return nil, err
		}
		tasks = append(tasks, t)
	}
	return tasks, rows.Err()
}

// listText encodes a list column exactly as json.Marshal does — a nil list as
// the literal null, an empty one as [] — without calling it for those two,
// which is what nearly every list of nearly every task is on every save.
func listText[T any](v []T) string {
	switch {
	case v == nil:
		return "null"
	case len(v) == 0:
		return "[]"
	}
	b, _ := json.Marshal(v)
	return string(b)
}

// timeText encodes an optional timestamp column; nil is SQL NULL.
func timeText(t *time.Time) sql.NullString {
	if t == nil {
		return sql.NullString{}
	}
	return sql.NullString{String: t.Format(time.RFC3339Nano), Valid: true}
}

// parseTimeText decodes an optional timestamp column. A value that does not
// parse reads as the zero time, as it always has.
func parseTimeText(v sql.NullString) *time.Time {
	if !v.Valid {
		return nil
	}
	ts, _ := time.Parse(time.RFC3339Nano, v.String)
	return &ts
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
		row.Time.UTC().Format(time.RFC3339Nano),
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

	// Identity is who this spend is attributed to — an oidcauth OwnerKey, or
	// the "local" sentinel for an unauthenticated run (Task 20264). Empty on
	// rows written before migration 0035, which means *unattributed* rather
	// than unowned. Self-reported by the orchestrator; see 0035 for why quota
	// enforcement deliberately does not read it.
	Identity string

	// RowID is the costs.id of this row. Set by the readers that select it,
	// zero elsewhere (AppendCost does not read it back).
	//
	// It exists for the hub's spend drain, which needs a watermark it can
	// resume from without double-booking. A timestamp cannot serve: two tasks
	// finishing in the same nanosecond collide, and a clock adjustment moves
	// one backwards — either would book a tenant twice or not at all. The
	// autoincrement id is monotonic in insertion order, which is the order the
	// drain actually walks.
	RowID int64
}

// costColumns is the select list every cost reader shares, so a column added
// to the table is added to all of them at once. It is paired with
// scanCostRows, which must scan exactly these, in this order.
const costColumns = `id, timestamp, task_id, task_title, provider, model,
	input_tokens, output_tokens, thinking_tokens, estimated_usd, identity`

// AppendCost inserts a cost entry into the costs table.
func (d *DB) AppendCost(entry CostEntry) error {
	if entry.Timestamp.IsZero() {
		entry.Timestamp = time.Now().UTC()
	}
	d.mu.Lock()
	defer d.mu.Unlock()

	_, err := d.conn.Exec(`
		INSERT INTO costs(timestamp, task_id, task_title, provider, model,
			input_tokens, output_tokens, thinking_tokens, estimated_usd, identity)
		VALUES(?,?,?,?,?,?,?,?,?,?)`,
		entry.Timestamp.UTC().Format(time.RFC3339Nano),
		entry.TaskID, entry.TaskTitle, entry.Provider, entry.Model,
		entry.InputTokens, entry.OutputTokens, entry.ThinkingTokens,
		entry.EstimatedUSD, entry.Identity,
	)
	return classifyDriverErr(err)
}

// ReadCosts returns all cost entries ordered by timestamp ascending.
func (d *DB) ReadCosts() ([]CostEntry, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	rows, err := d.conn.Query(`SELECT ` + costColumns + `
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

	rows, err := d.conn.Query(`SELECT `+costColumns+`
		FROM costs WHERE timestamp >= ? ORDER BY timestamp ASC`,
		since.UTC().Format(time.RFC3339Nano),
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanCostRows(rows)
}

// ReadCostsAfterID returns cost entries with id > afterID, oldest first.
//
// This is the hub's spend drain (Task 20264): it books everything it has not
// booked before and remembers the highest id it saw. Ordering by id rather
// than timestamp is what makes the watermark sound — see CostEntry.RowID.
//
// limit bounds one drain so a project whose ledger grew while the hub was down
// cannot pull an unbounded result set into memory; the caller advances its
// watermark and comes back for the rest.
func (d *DB) ReadCostsAfterID(afterID int64, limit int) ([]CostEntry, error) {
	if limit <= 0 {
		limit = 1000
	}
	d.mu.Lock()
	defer d.mu.Unlock()

	rows, err := d.conn.Query(`SELECT `+costColumns+`
		FROM costs WHERE id > ? ORDER BY id ASC LIMIT ?`, afterID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanCostRows(rows)
}

// MaxCostRowID returns the highest costs.id present, or 0 when the table is
// empty. It seeds a drain watermark at a point that means "everything already
// here is somebody else's business", so a hub adopting an existing project
// does not retroactively bill a tenant for spend that predates it.
func (d *DB) MaxCostRowID() (int64, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	var id sql.NullInt64
	if err := d.conn.QueryRow(`SELECT MAX(id) FROM costs`).Scan(&id); err != nil {
		return 0, err
	}
	if !id.Valid {
		return 0, nil
	}
	return id.Int64, nil
}

// IdentitySpend is one identity's total spend over a window.
type IdentitySpend struct {
	Identity       string
	InputTokens    int
	OutputTokens   int
	ThinkingTokens int
	EstimatedUSD   float64
	Entries        int
}

// SpendByIdentity aggregates costs per identity over [from, to).
//
// A zero `from` or `to` leaves that side of the window open, so the caller can
// ask for "today", "since Monday" or "everything" through one query. Rows with
// no identity aggregate under the empty string: they are reported as
// unattributed rather than dropped, because spend that happened is spend that
// happened and a total that silently omits it would not reconcile against the
// project ledger.
func (d *DB) SpendByIdentity(from, to time.Time) ([]IdentitySpend, error) {
	query := `SELECT identity,
			COALESCE(SUM(input_tokens),0), COALESCE(SUM(output_tokens),0),
			COALESCE(SUM(thinking_tokens),0), COALESCE(SUM(estimated_usd),0),
			COUNT(*)
		FROM costs`
	var (
		where []string
		args  []interface{}
	)
	if !from.IsZero() {
		where = append(where, "timestamp >= ?")
		args = append(args, from.UTC().Format(time.RFC3339Nano))
	}
	if !to.IsZero() {
		where = append(where, "timestamp < ?")
		args = append(args, to.UTC().Format(time.RFC3339Nano))
	}
	if len(where) > 0 {
		query += " WHERE " + strings.Join(where, " AND ")
	}
	query += " GROUP BY identity ORDER BY identity ASC"

	d.mu.Lock()
	defer d.mu.Unlock()

	rows, err := d.conn.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []IdentitySpend
	for rows.Next() {
		var s IdentitySpend
		if err := rows.Scan(&s.Identity, &s.InputTokens, &s.OutputTokens,
			&s.ThinkingTokens, &s.EstimatedUSD, &s.Entries); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// MonthlyCosts returns cost entries for the given UTC year/month.
func (d *DB) MonthlyCosts(year, month int) ([]CostEntry, error) {
	// Build inclusive date range: YYYY-MM-01 00:00:00 → YYYY-MM-01 of next month.
	start := time.Date(year, time.Month(month), 1, 0, 0, 0, 0, time.UTC)
	end := start.AddDate(0, 1, 0)
	d.mu.Lock()
	defer d.mu.Unlock()

	rows, err := d.conn.Query(`SELECT `+costColumns+`
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
		if err := rows.Scan(&e.RowID, &ts, &e.TaskID, &e.TaskTitle, &e.Provider, &e.Model,
			&e.InputTokens, &e.OutputTokens, &e.ThinkingTokens, &e.EstimatedUSD,
			&e.Identity); err != nil {
			return nil, err
		}
		e.Timestamp, _ = time.Parse(time.RFC3339Nano, ts)
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

// encodeBackground serialises a task's background-work record for the
// plan_tasks.background column (Task 20205).
//
// Absent work is stored as the empty string rather than the JSON literal
// "null", so a row written by this build is indistinguishable from one that
// predates the column's migration. That keeps the "no background work" case a
// single value instead of three that all have to be handled.
func encodeBackground(b *pm.BackgroundWork) string {
	if b == nil {
		return ""
	}
	raw, err := json.Marshal(b)
	if err != nil {
		// A record that cannot be encoded must not take the task's whole save
		// down with it: the status, result and diagnosis matter more than the
		// annotation of why it failed.
		return ""
	}
	return string(raw)
}

// decodeBackground parses the background column, treating anything
// unreadable as "no background work".
//
// Tolerating a bad value rather than failing the load is deliberate: this
// field is diagnostic, and refusing to open a project because one task's
// diagnostic annotation is malformed would trade a cosmetic loss for a total
// one.
func decodeBackground(raw string) *pm.BackgroundWork {
	if raw == "" || raw == "null" {
		return nil
	}
	var b pm.BackgroundWork
	if err := json.Unmarshal([]byte(raw), &b); err != nil || b.State == "" {
		return nil
	}
	return &b
}

// encodeAbort serialises a task's refusal record for the plan_tasks.abort
// column (Task 20224). Same shape as encodeBackground above: absent is the
// empty string, not the JSON literal "null", so a row written by this build is
// indistinguishable from one predating migration 0029.
func encodeAbort(a *pm.TaskAbort) string {
	if a == nil {
		return ""
	}
	raw, err := json.Marshal(a)
	if err != nil {
		return ""
	}
	return string(raw)
}

// decodeAbort parses the abort column, treating anything unreadable as "no
// record".
//
// A record without a class is discarded rather than kept: the class is what the
// sweep and the UI key off, and a classless record would block plan completion
// while being unable to say why. Losing it costs one reclassification on the
// next sweep — the summary it describes is still on the task.
func decodeAbort(raw string) *pm.TaskAbort {
	if raw == "" || raw == "null" {
		return nil
	}
	var a pm.TaskAbort
	if err := json.Unmarshal([]byte(raw), &a); err != nil || a.Class == "" {
		return nil
	}
	return &a
}

// SaveReviewGate stores the project's review gate settings and nothing else
// (Task 20357). The dashboard and `cloop review gate` change them while a run
// may be saving its tasks; a full SaveState from their copy would write stale
// tasks back over the run's.
func (d *DB) SaveReviewGate(g *pm.ReviewGate) error {
	value := ""
	if g != nil {
		b, err := json.Marshal(g)
		if err != nil {
			return fmt.Errorf("statedb: encode review gate: %w", err)
		}
		value = string(b)
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if _, err := d.conn.Exec(
		`INSERT INTO metadata(key,value) VALUES('review_gate',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value`,
		value,
	); err != nil {
		return fmt.Errorf("statedb: save review gate: %w", classifyDriverErr(err))
	}
	return nil
}

// SaveRunStatus stores the run's status and pause reason and nothing else
// (Task 20362).
//
// It exists for the one write that has to land after a full SaveState has just
// failed: an orchestrator that could not record a task's outcome stops, and
// says why it stopped. A full save rewrites every task row and merges the plan
// first — which is the very write that was refused when, say, a damaged row
// makes the merge give up — while three metadata keys in one transaction are
// the smallest change that tells the dashboard the run is no longer running.
// It leaves the plan exactly as the last successful save left it, so the
// outcome that was lost stays lost rather than half-written.
func (d *DB) SaveRunStatus(status string, reason *pausereason.Reason, updatedAt time.Time) error {
	pr := pausereason.Normalize(status, reason)
	encoded := ""
	if pr != nil {
		b, err := json.Marshal(pr)
		if err != nil {
			return fmt.Errorf("statedb: encode pause reason: %w", err)
		}
		encoded = string(b)
	}
	if err := d.saveRunStatusLocked(status, encoded, updatedAt); err != nil {
		return fmt.Errorf("statedb: save run status: %w", err)
	}
	// After the commit and outside the lock, as SaveState audits.
	auditRunStatus(d, status, pr)
	return nil
}

func (d *DB) saveRunStatusLocked(status, pauseReason string, updatedAt time.Time) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	tx, err := d.conn.Begin()
	if err != nil {
		return classifyDriverErr(err)
	}
	defer tx.Rollback() //nolint:errcheck

	for _, kv := range [][2]string{
		{"status", status},
		{"pause_reason", pauseReason},
		{"updated_at", updatedAt.Format(time.RFC3339Nano)},
	} {
		if err := d.setMeta(tx, kv[0], kv[1]); err != nil {
			return fmt.Errorf("set metadata %q: %w", kv[0], classifyDriverErr(err))
		}
	}
	return classifyDriverErr(tx.Commit())
}

// encodeReview serialises a task's review-gate record for the
// plan_tasks.review column (Task 20357). Same shape as encodeBackground:
// absent is the empty string, so a row written by this build reads the same
// as one predating migration 0053.
func encodeReview(r *pm.TaskReview) string {
	if r == nil {
		return ""
	}
	raw, err := json.Marshal(r)
	if err != nil {
		return ""
	}
	return string(raw)
}

// decodeReview parses the review column, treating anything unreadable — or a
// record without a verdict, which could not say what it decided — as "not
// reviewed".
func decodeReview(raw string) *pm.TaskReview {
	if raw == "" || raw == "null" {
		return nil
	}
	var r pm.TaskReview
	if err := json.Unmarshal([]byte(raw), &r); err != nil || r.Verdict == "" {
		return nil
	}
	return &r
}
