// Package taskqueue implements a central SQLite-backed queue that records every
// unit of work cloop performs — PM task executions, auto-heal retries, evolve
// discoveries, and externally-added tasks. The queue is the single source of
// truth for "what is cloop doing right now and what did it just do," giving
// the UI full auditability and ensuring no work runs anonymously.
//
// The queue is intentionally append-mostly: rows are inserted when work begins
// and updated only with terminal status. List() returns rows newest-first.
//
// As of Task 20079 the queue table lives inside the project state database
// (.cloop/state.db) so a project has exactly one SQLite file. Existing
// .cloop/queue.db files are migrated transparently on first Open and removed.
package taskqueue

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

// sessionMetaFile is the sentinel that identifies a session directory. When
// present in dir, state.db lives directly under dir (not under dir/.cloop/).
// Mirrored from pkg/state to avoid the import cycle that would arise from
// pulling pkg/state into a low-level storage package.
const sessionMetaFile = "session.json"

// Kind identifies what type of work the queue entry represents.
type Kind string

const (
	KindTask     Kind = "task"     // PM task execution
	KindHeal     Kind = "heal"     // auto-heal retry attempt
	KindEvolve   Kind = "evolve"   // evolve discovery cycle
	KindExternal Kind = "external" // externally-added task merged in
	KindSession  Kind = "session"  // session-level work (decompose, optimize, etc.)
)

// Status enumerates queue entry lifecycle states.
type Status string

const (
	StatusQueued  Status = "queued"
	StatusRunning Status = "running"
	StatusDone    Status = "done"
	StatusFailed  Status = "failed"
	StatusSkipped Status = "skipped"
)

// Entry is a single queue row.
type Entry struct {
	ID            int64     `json:"id"`
	Kind          Kind      `json:"kind"`
	TaskID        int       `json:"task_id,omitempty"`     // 0 if not linked to a plan task
	Attempt       int       `json:"attempt,omitempty"`     // 1-based attempt counter (heal retries)
	ParentID      int64     `json:"parent_id,omitempty"`   // queue id of the parent entry, if any
	Title         string    `json:"title"`
	Description   string    `json:"description,omitempty"`
	Status        Status    `json:"status"`
	Source        string    `json:"source,omitempty"`      // "orchestrator" | "evolve" | "external" | "api" | "cli"
	CreatedAt     time.Time `json:"created_at"`
	StartedAt     *time.Time `json:"started_at,omitempty"`
	CompletedAt   *time.Time `json:"completed_at,omitempty"`
	OutputSummary string    `json:"output_summary,omitempty"`
	ErrorMessage  string    `json:"error_message,omitempty"`
}

// Queue is a thread-safe handle to the queue database.
type Queue struct {
	mu   sync.Mutex
	conn *sql.DB
	path string
}

const schema = `
PRAGMA journal_mode=WAL;
PRAGMA busy_timeout=5000;

CREATE TABLE IF NOT EXISTS queue (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    kind            TEXT    NOT NULL DEFAULT 'task',
    task_id         INTEGER NOT NULL DEFAULT 0,
    attempt         INTEGER NOT NULL DEFAULT 0,
    parent_id       INTEGER NOT NULL DEFAULT 0,
    title           TEXT    NOT NULL DEFAULT '',
    description     TEXT    NOT NULL DEFAULT '',
    status          TEXT    NOT NULL DEFAULT 'queued',
    source          TEXT    NOT NULL DEFAULT '',
    created_at      TEXT    NOT NULL DEFAULT '',
    started_at      TEXT,
    completed_at    TEXT,
    output_summary  TEXT    NOT NULL DEFAULT '',
    error_message   TEXT    NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS queue_task_id ON queue(task_id);
CREATE INDEX IF NOT EXISTS queue_status ON queue(status);
CREATE INDEX IF NOT EXISTS queue_created_at ON queue(created_at);
`

// QueuePath returns the on-disk path of the database that backs the queue
// for a project working directory. As of Task 20079 this is the project's
// state.db — the queue table is co-located with project state so there is
// exactly one SQLite file per project.
func QueuePath(workDir string) string {
	if workDir == "" {
		return ""
	}
	if _, err := os.Stat(filepath.Join(workDir, sessionMetaFile)); err == nil {
		// Session directories store state.db flat (no .cloop/ subdir).
		return filepath.Join(workDir, "state.db")
	}
	return filepath.Join(workDir, ".cloop", "state.db")
}

// legacyQueuePath returns the historical .cloop/queue.db location used before
// Task 20079. Migration on Open() reads from here and removes the file.
func legacyQueuePath(workDir string) string {
	if workDir == "" {
		return ""
	}
	if _, err := os.Stat(filepath.Join(workDir, sessionMetaFile)); err == nil {
		return filepath.Join(workDir, "queue.db")
	}
	return filepath.Join(workDir, ".cloop", "queue.db")
}

// Open opens (or creates) the queue database. The caller must Close() it.
//
// Storage is the project's state.db (the queue table is part of that file's
// schema, see pkg/statedb). On first call, any rows in a legacy
// .cloop/queue.db are migrated into state.db and the legacy file is removed.
func Open(workDir string) (*Queue, error) {
	if workDir == "" {
		return nil, fmt.Errorf("taskqueue.Open: empty workDir")
	}
	path := QueuePath(workDir)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, fmt.Errorf("taskqueue mkdir %s: %w", filepath.Dir(path), err)
	}
	conn, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("taskqueue open %s: %w", path, err)
	}
	conn.SetMaxOpenConns(1)
	if _, err := conn.Exec(schema); err != nil {
		conn.Close()
		return nil, fmt.Errorf("taskqueue schema: %w", err)
	}

	q := &Queue{conn: conn, path: path}

	// Best-effort migration of any pre-Task-20079 .cloop/queue.db. Failures are
	// logged via the returned error path only when the legacy file existed AND
	// could not be merged; otherwise we silently continue with the new store.
	if legacy := legacyQueuePath(workDir); legacy != "" && legacy != path {
		if _, statErr := os.Stat(legacy); statErr == nil {
			if migrateErr := migrateLegacyQueue(conn, legacy); migrateErr != nil {
				conn.Close()
				return nil, fmt.Errorf("taskqueue migrate %s: %w", legacy, migrateErr)
			}
		}
	}

	return q, nil
}

// migrateLegacyQueue copies all rows from the legacy queue.db into the
// destination connection's queue table, preserving the original IDs, then
// removes the legacy file (including its WAL/SHM siblings).
func migrateLegacyQueue(dst *sql.DB, legacyPath string) error {
	src, err := sql.Open("sqlite", legacyPath)
	if err != nil {
		return fmt.Errorf("open legacy: %w", err)
	}
	defer src.Close()
	src.SetMaxOpenConns(1)

	// Discover table existence — a torn or empty file might have no schema.
	var tableName string
	if err := src.QueryRow(
		`SELECT name FROM sqlite_master WHERE type='table' AND name='queue'`,
	).Scan(&tableName); err != nil {
		if err == sql.ErrNoRows {
			// Empty legacy file — nothing to migrate, just clean up.
			return removeLegacyQueueFiles(legacyPath)
		}
		return fmt.Errorf("inspect legacy: %w", err)
	}

	rows, err := src.Query(`
		SELECT id, kind, task_id, attempt, parent_id, title, description,
		       status, source, created_at, started_at, completed_at,
		       output_summary, error_message
		FROM queue ORDER BY id`)
	if err != nil {
		return fmt.Errorf("read legacy rows: %w", err)
	}
	defer rows.Close()

	tx, err := dst.Begin()
	if err != nil {
		return fmt.Errorf("dst begin: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck

	stmt, err := tx.Prepare(`
		INSERT OR IGNORE INTO queue
		(id, kind, task_id, attempt, parent_id, title, description, status,
		 source, created_at, started_at, completed_at, output_summary, error_message)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return fmt.Errorf("prepare insert: %w", err)
	}
	defer stmt.Close()

	for rows.Next() {
		var (
			id, taskID, attempt, parentID                int64
			kind, title, desc, status, source, createdAt string
			outSummary, errMsg                           string
			startedAt, completedAt                       sql.NullString
		)
		if err := rows.Scan(
			&id, &kind, &taskID, &attempt, &parentID, &title, &desc,
			&status, &source, &createdAt, &startedAt, &completedAt,
			&outSummary, &errMsg,
		); err != nil {
			return fmt.Errorf("scan legacy row: %w", err)
		}
		if _, err := stmt.Exec(
			id, kind, taskID, attempt, parentID, title, desc,
			status, source, createdAt, startedAt, completedAt,
			outSummary, errMsg,
		); err != nil {
			return fmt.Errorf("insert row %d: %w", id, err)
		}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate legacy rows: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit migration: %w", err)
	}
	rows.Close()
	src.Close()

	return removeLegacyQueueFiles(legacyPath)
}

// removeLegacyQueueFiles deletes queue.db and its WAL/SHM siblings if present.
// Errors on the WAL/SHM files are tolerated — they're checkpointed automatically
// by SQLite and not removing them is harmless (just clutter).
func removeLegacyQueueFiles(path string) error {
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove %s: %w", path, err)
	}
	for _, suffix := range []string{"-wal", "-shm"} {
		_ = os.Remove(path + suffix)
	}
	return nil
}

// Close releases the queue database connection.
func (q *Queue) Close() error {
	if q == nil || q.conn == nil {
		return nil
	}
	return q.conn.Close()
}

// Path returns the on-disk path of the queue database.
func (q *Queue) Path() string {
	if q == nil {
		return ""
	}
	return q.path
}

// Enqueue inserts a new queue entry and returns its assigned id. The Status,
// CreatedAt, ID, StartedAt, and CompletedAt fields of the input are ignored —
// Enqueue assigns its own values.
func (q *Queue) Enqueue(e Entry) (int64, error) {
	if q == nil || q.conn == nil {
		return 0, fmt.Errorf("queue closed")
	}
	q.mu.Lock()
	defer q.mu.Unlock()

	now := time.Now()
	res, err := q.conn.Exec(
		`INSERT INTO queue (kind, task_id, attempt, parent_id, title, description, status, source, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		string(e.Kind),
		e.TaskID,
		e.Attempt,
		e.ParentID,
		truncateString(e.Title, 500),
		truncateString(e.Description, 4000),
		string(StatusQueued),
		e.Source,
		now.Format(time.RFC3339Nano),
	)
	if err != nil {
		return 0, fmt.Errorf("queue insert: %w", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return 0, fmt.Errorf("queue last insert id: %w", err)
	}
	return id, nil
}

// MarkRunning transitions an entry to the running state and stamps started_at.
// No-op if id is zero.
func (q *Queue) MarkRunning(id int64) error {
	if q == nil || id == 0 {
		return nil
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	now := time.Now().Format(time.RFC3339Nano)
	_, err := q.conn.Exec(
		`UPDATE queue SET status=?, started_at=? WHERE id=?`,
		string(StatusRunning), now, id,
	)
	if err != nil {
		return fmt.Errorf("queue mark_running %d: %w", id, err)
	}
	return nil
}

// MarkDone sets the entry status to "done" and records a brief output summary.
func (q *Queue) MarkDone(id int64, summary string) error {
	return q.complete(id, StatusDone, summary, "")
}

// MarkFailed sets the entry status to "failed" and records an error message.
func (q *Queue) MarkFailed(id int64, errMsg string) error {
	return q.complete(id, StatusFailed, "", errMsg)
}

// MarkSkipped sets the entry status to "skipped" and records a reason.
func (q *Queue) MarkSkipped(id int64, reason string) error {
	return q.complete(id, StatusSkipped, reason, "")
}

func (q *Queue) complete(id int64, status Status, summary, errMsg string) error {
	if q == nil || id == 0 {
		return nil
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	now := time.Now().Format(time.RFC3339Nano)
	_, err := q.conn.Exec(
		`UPDATE queue
		 SET status=?, completed_at=?, output_summary=?, error_message=?,
		     started_at = COALESCE(started_at, ?)
		 WHERE id=?`,
		string(status), now,
		truncateString(summary, 2000),
		truncateString(errMsg, 1000),
		now, id,
	)
	if err != nil {
		return fmt.Errorf("queue complete %d: %w", id, err)
	}
	return nil
}

// ListOptions filters and paginates List results.
type ListOptions struct {
	// Limit caps the number of returned rows. 0 = default 200.
	Limit int
	// Offset for pagination. 0 = from newest.
	Offset int
	// Status filter. Empty = all statuses.
	Status Status
	// Kind filter. Empty = all kinds.
	Kind Kind
	// TaskID filter. 0 = all tasks.
	TaskID int
}

// List returns queue entries matching opts, newest first.
func (q *Queue) List(opts ListOptions) ([]Entry, error) {
	if q == nil || q.conn == nil {
		return nil, fmt.Errorf("queue closed")
	}
	q.mu.Lock()
	defer q.mu.Unlock()

	limit := opts.Limit
	if limit <= 0 {
		limit = 200
	}
	if limit > 5000 {
		limit = 5000
	}

	query := `SELECT id, kind, task_id, attempt, parent_id, title, description,
	          status, source, created_at, started_at, completed_at,
	          output_summary, error_message
	          FROM queue WHERE 1=1`
	var args []interface{}
	if opts.Status != "" {
		query += ` AND status=?`
		args = append(args, string(opts.Status))
	}
	if opts.Kind != "" {
		query += ` AND kind=?`
		args = append(args, string(opts.Kind))
	}
	if opts.TaskID != 0 {
		query += ` AND task_id=?`
		args = append(args, opts.TaskID)
	}
	query += ` ORDER BY id DESC LIMIT ? OFFSET ?`
	args = append(args, limit, opts.Offset)

	rows, err := q.conn.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("queue list: %w", err)
	}
	defer rows.Close()

	var out []Entry
	for rows.Next() {
		var (
			e                                      Entry
			kind, status, createdAt                string
			startedAt, completedAt                 sql.NullString
		)
		if err := rows.Scan(
			&e.ID, &kind, &e.TaskID, &e.Attempt, &e.ParentID,
			&e.Title, &e.Description, &status, &e.Source,
			&createdAt, &startedAt, &completedAt,
			&e.OutputSummary, &e.ErrorMessage,
		); err != nil {
			return nil, fmt.Errorf("queue scan: %w", err)
		}
		e.Kind = Kind(kind)
		e.Status = Status(status)
		if t, err := time.Parse(time.RFC3339Nano, createdAt); err == nil {
			e.CreatedAt = t
		}
		if startedAt.Valid && startedAt.String != "" {
			if t, err := time.Parse(time.RFC3339Nano, startedAt.String); err == nil {
				e.StartedAt = &t
			}
		}
		if completedAt.Valid && completedAt.String != "" {
			if t, err := time.Parse(time.RFC3339Nano, completedAt.String); err == nil {
				e.CompletedAt = &t
			}
		}
		out = append(out, e)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("queue rows: %w", err)
	}
	return out, nil
}

// Stats returns counts grouped by status.
func (q *Queue) Stats() (map[Status]int, error) {
	if q == nil || q.conn == nil {
		return nil, fmt.Errorf("queue closed")
	}
	q.mu.Lock()
	defer q.mu.Unlock()

	rows, err := q.conn.Query(`SELECT status, COUNT(*) FROM queue GROUP BY status`)
	if err != nil {
		return nil, fmt.Errorf("queue stats: %w", err)
	}
	defer rows.Close()
	out := make(map[Status]int)
	for rows.Next() {
		var s string
		var n int
		if err := rows.Scan(&s, &n); err != nil {
			return nil, fmt.Errorf("queue stats scan: %w", err)
		}
		out[Status(s)] = n
	}
	return out, rows.Err()
}

// Truncate removes all queue entries. Used by tests and `cloop reset`.
func (q *Queue) Truncate() error {
	if q == nil || q.conn == nil {
		return nil
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	_, err := q.conn.Exec(`DELETE FROM queue`)
	return err
}

func truncateString(s string, max int) string {
	if max <= 0 || len(s) <= max {
		return s
	}
	return s[:max] + "…"
}
