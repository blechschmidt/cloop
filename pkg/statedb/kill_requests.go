// Manual abort requests (Task 20140).
//
// When an operator manually changes an in_progress task's status via the Web
// UI, the UI inserts one row here and the orchestrator's fast-tick poller
// fires the task's registered context.CancelFunc. After the worker exits,
// the orchestrator re-applies target_status so the user-selected status
// wins over the worker's normal "canceled → failed" handling.
//
// Rows are short-lived: the orchestrator removes them immediately after
// firing the cancel. Stale rows surviving a crash are processed at the next
// orchestrator startup; an unknown task ID is a no-op.

package statedb

import (
	"database/sql"
	"errors"
	"time"
)

// KillRequest is one pending manual-abort request keyed by task ID.
type KillRequest struct {
	TaskID       int
	TargetStatus string // empty when the operator did not pick a final status
	RequestedAt  time.Time
	RequestedBy  string // free-form (UI client ID, "ui", etc.) — informational only
}

// RequestKill upserts one abort request. Repeated calls for the same task ID
// overwrite target_status / requested_at — the latest request wins. Returns
// nil when the row was written.
func (d *DB) RequestKill(req KillRequest) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if req.TaskID <= 0 {
		return errors.New("kill request: task_id must be > 0")
	}
	if req.RequestedAt.IsZero() {
		req.RequestedAt = time.Now()
	}
	_, err := d.conn.Exec(
		`INSERT INTO kill_requests(task_id, target_status, requested_at, requested_by)
		 VALUES(?,?,?,?)
		 ON CONFLICT(task_id) DO UPDATE SET
		   target_status = excluded.target_status,
		   requested_at  = excluded.requested_at,
		   requested_by  = excluded.requested_by`,
		req.TaskID,
		req.TargetStatus,
		req.RequestedAt.Format(time.RFC3339Nano),
		req.RequestedBy,
	)
	if err != nil {
		return classifyDriverErr(err)
	}
	return nil
}

// PendingKills returns all currently-pending abort requests, oldest first.
// The orchestrator's poller calls this every fast tick.
func (d *DB) PendingKills() ([]KillRequest, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	rows, err := d.conn.Query(
		`SELECT task_id, target_status, requested_at, requested_by
		 FROM kill_requests ORDER BY requested_at ASC`,
	)
	if err != nil {
		return nil, classifyDriverErr(err)
	}
	defer rows.Close()
	var out []KillRequest
	for rows.Next() {
		var (
			r     KillRequest
			tsRaw string
		)
		if err := rows.Scan(&r.TaskID, &r.TargetStatus, &tsRaw, &r.RequestedBy); err != nil {
			return nil, err
		}
		if t, parseErr := time.Parse(time.RFC3339Nano, tsRaw); parseErr == nil {
			r.RequestedAt = t
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// LookupKill returns the pending kill for taskID and whether a row exists.
// Used by the orchestrator after a worker exits to recover the operator's
// chosen target_status. Returns (KillRequest{}, false, nil) when no row.
func (d *DB) LookupKill(taskID int) (KillRequest, bool, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	row := d.conn.QueryRow(
		`SELECT task_id, target_status, requested_at, requested_by
		 FROM kill_requests WHERE task_id = ?`,
		taskID,
	)
	var (
		r     KillRequest
		tsRaw string
	)
	if err := row.Scan(&r.TaskID, &r.TargetStatus, &tsRaw, &r.RequestedBy); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return KillRequest{}, false, nil
		}
		return KillRequest{}, false, classifyDriverErr(err)
	}
	if t, parseErr := time.Parse(time.RFC3339Nano, tsRaw); parseErr == nil {
		r.RequestedAt = t
	}
	return r, true, nil
}

// ClearKill removes the kill row for taskID. Idempotent — clearing a row
// that does not exist returns nil.
func (d *DB) ClearKill(taskID int) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	_, err := d.conn.Exec(`DELETE FROM kill_requests WHERE task_id = ?`, taskID)
	if err != nil {
		return classifyDriverErr(err)
	}
	return nil
}
