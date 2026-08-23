// Durable handle identity (Task 20191).
//
// Rows for migrations/0021_executor_handles.sql. See that file for why this is
// a separate table from executor_sessions: this is the *driver's* ledger of
// what the runtime is holding, keyed by the external name the runtime knows,
// while executor_sessions is the *control plane's* ledger of dispatched work.
//
// This file owns the SQL only. What counts as an orphan, how long a grace
// period runs and which driver adopts which row is policy, and lives in
// pkg/executor and its sub-packages.

package statedb

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// ErrExecutorHandleNotFound is returned when no row exists for a handle id.
var ErrExecutorHandleNotFound = errors.New("statedb: executor handle not found")

// ExecutorHandleRow is the durable identity of one dispatched workload.
type ExecutorHandleRow struct {
	HandleID   string
	ExecutorID string
	Driver     string
	// ExternalID is the name the runtime knows the workload by. Its shape is
	// driver-specific and nothing outside the owning driver interprets it.
	ExternalID  string
	ProjectPath string
	TaskID      int
	PID         int
	Image       string
	// MetaJSON is a marshalled map[string]string of driver-specific extras.
	// '' and '{}' both mean "none"; readers must tolerate both because the
	// column default is '{}' and a caller may write ''.
	MetaJSON  string
	StartedAt time.Time
	// Deadline is when the workload's timeout expires; the zero time means
	// unbounded. Absolute, so a hub that was down does not restart the clock.
	Deadline  time.Time
	UpdatedAt time.Time
}

// PutExecutorHandle inserts or replaces the row for row.HandleID.
//
// Unlike OpenExecutorSession this *is* an upsert. A driver may re-record a
// handle it already owns — rehydration re-writes rows so updated_at reflects
// the adopting control plane, and a Start that retries against the same
// handle id must not fail on a duplicate key. There is no claim token here to
// clobber: the row carries identity, not ownership.
func (d *DB) PutExecutorHandle(row ExecutorHandleRow) error {
	if strings.TrimSpace(row.HandleID) == "" {
		return errors.New("statedb: executor handle id is required")
	}
	if strings.TrimSpace(row.ExecutorID) == "" {
		return fmt.Errorf("statedb: executor handle %q needs an executor id", row.HandleID)
	}
	// An empty external id is the one failure mode this table cannot tolerate:
	// the row would be visible to a sweep that could never act on it, which is
	// worse than no row at all because it looks like coverage.
	if strings.TrimSpace(row.ExternalID) == "" {
		return fmt.Errorf("statedb: executor handle %q needs an external id", row.HandleID)
	}
	if strings.TrimSpace(row.MetaJSON) == "" {
		row.MetaJSON = "{}"
	}
	if row.UpdatedAt.IsZero() {
		row.UpdatedAt = time.Now().UTC()
	}

	d.mu.Lock()
	defer d.mu.Unlock()
	_, err := d.conn.Exec(
		`INSERT INTO executor_handles(handle_id, executor_id, driver, external_id,
		                              project_path, task_id, pid, image, meta_json,
		                              started_at, deadline, updated_at)
		 VALUES(?,?,?,?,?,?,?,?,?,?,?,?)
		 ON CONFLICT(handle_id) DO UPDATE SET
		   executor_id  = excluded.executor_id,
		   driver       = excluded.driver,
		   external_id  = excluded.external_id,
		   project_path = excluded.project_path,
		   task_id      = excluded.task_id,
		   pid          = excluded.pid,
		   image        = excluded.image,
		   meta_json    = excluded.meta_json,
		   started_at   = excluded.started_at,
		   deadline     = excluded.deadline,
		   updated_at   = excluded.updated_at`,
		row.HandleID, row.ExecutorID, row.Driver, row.ExternalID,
		row.ProjectPath, row.TaskID, row.PID, row.Image, row.MetaJSON,
		formatOptionalTime(row.StartedAt), formatOptionalTime(row.Deadline),
		formatOptionalTime(row.UpdatedAt),
	)
	if err != nil {
		return fmt.Errorf("statedb: put executor handle %q: %w", row.HandleID, classifyDriverErr(err))
	}
	return nil
}

// GetExecutorHandle returns one row, or ErrExecutorHandleNotFound.
func (d *DB) GetExecutorHandle(handleID string) (ExecutorHandleRow, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	row := d.conn.QueryRow(
		`SELECT handle_id, executor_id, driver, external_id, project_path, task_id,
		        pid, image, meta_json, started_at, deadline, updated_at
		 FROM executor_handles WHERE handle_id = ?`, handleID)
	out, err := scanExecutorHandleRow(row)
	if errors.Is(err, sql.ErrNoRows) {
		return ExecutorHandleRow{}, fmt.Errorf("%w: %q", ErrExecutorHandleNotFound, handleID)
	}
	if err != nil {
		return ExecutorHandleRow{}, fmt.Errorf("statedb: get executor handle %q: %w", handleID, classifyDriverErr(err))
	}
	return out, nil
}

// ListExecutorHandles returns rows owned by executorID, oldest first. Passing
// "" returns every row, which is what a cross-driver sweep wants.
//
// Oldest-first matters: an orphan sweep applies a grace period to
// started_at, and processing in dispatch order means the first row it
// examines is the one most likely to have aged past it.
func (d *DB) ListExecutorHandles(executorID string) ([]ExecutorHandleRow, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	query := `SELECT handle_id, executor_id, driver, external_id, project_path, task_id,
	                 pid, image, meta_json, started_at, deadline, updated_at
	          FROM executor_handles`
	var args []any
	if strings.TrimSpace(executorID) != "" {
		query += ` WHERE executor_id = ?`
		args = append(args, executorID)
	}
	// started_at is RFC3339 text, which sorts lexicographically in the same
	// order as chronologically for a fixed offset — and every write goes
	// through formatOptionalTime, which normalises to UTC.
	query += ` ORDER BY started_at ASC, handle_id ASC`

	rows, err := d.conn.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("statedb: list executor handles: %w", classifyDriverErr(err))
	}
	defer rows.Close()

	var out []ExecutorHandleRow
	for rows.Next() {
		rec, err := scanExecutorHandleRow(rows)
		if err != nil {
			return nil, fmt.Errorf("statedb: scan executor handle: %w", classifyDriverErr(err))
		}
		out = append(out, rec)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("statedb: list executor handles: %w", classifyDriverErr(err))
	}
	return out, nil
}

// DeleteExecutorHandle forgets one row. Deleting a row that is not there is
// not an error: a terminal transition can be recorded twice (once by the log
// pump, once by an explicit reap) and neither call should fail.
func (d *DB) DeleteExecutorHandle(handleID string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if _, err := d.conn.Exec(`DELETE FROM executor_handles WHERE handle_id = ?`, handleID); err != nil {
		return fmt.Errorf("statedb: delete executor handle %q: %w", handleID, classifyDriverErr(err))
	}
	return nil
}

// scanExecutorHandleRow maps one result row onto the struct.
func scanExecutorHandleRow(sc rowScanner) (ExecutorHandleRow, error) {
	var (
		rec                            ExecutorHandleRow
		startedAt, deadline, updatedAt string
	)
	if err := sc.Scan(&rec.HandleID, &rec.ExecutorID, &rec.Driver, &rec.ExternalID,
		&rec.ProjectPath, &rec.TaskID, &rec.PID, &rec.Image, &rec.MetaJSON,
		&startedAt, &deadline, &updatedAt); err != nil {
		return ExecutorHandleRow{}, err
	}
	rec.StartedAt = parseOptionalTime(startedAt)
	rec.Deadline = parseOptionalTime(deadline)
	rec.UpdatedAt = parseOptionalTime(updatedAt)
	return rec, nil
}

// MarshalHandleMeta renders a driver's extras for the meta_json column.
// A nil or empty map becomes "{}" rather than "", so the column always holds
// valid JSON and a reader never has to special-case the empty string.
func MarshalHandleMeta(meta map[string]string) string {
	if len(meta) == 0 {
		return "{}"
	}
	b, err := json.Marshal(meta)
	if err != nil {
		// map[string]string cannot fail to marshal; treat a future change
		// that makes it possible as "no metadata" rather than losing the row.
		return "{}"
	}
	return string(b)
}

// UnmarshalHandleMeta parses the meta_json column. Unparsable metadata is
// dropped rather than propagated: the extras are advisory, and refusing to
// rehydrate a workload because a hint field is corrupt would strand a running
// container to protect a label.
func UnmarshalHandleMeta(s string) map[string]string {
	s = strings.TrimSpace(s)
	if s == "" || s == "{}" {
		return nil
	}
	var out map[string]string
	if err := json.Unmarshal([]byte(s), &out); err != nil {
		return nil
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
