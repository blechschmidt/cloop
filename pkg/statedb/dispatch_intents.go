// Dispatch intents (Task 20419).
//
// Rows for migrations/0069_run_supervision.sql's dispatch_intents. See that
// file for why a dispatch is recorded before its workload exists. This file
// owns the SQL; which intent names an unsupervised workload, and what is done
// about it, is pkg/ui's.

package statedb

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Dispatch intent states.
const (
	// DispatchIntentDispatching: the executor has been, or is about to be,
	// asked to start the workload, and has not answered.
	DispatchIntentDispatching = "dispatching"
	// DispatchIntentStarted: the executor answered with a handle.
	DispatchIntentStarted = "started"
)

// ErrDispatchIntentNotFound is returned when no row names a run.
var ErrDispatchIntentNotFound = errors.New("statedb: dispatch intent not found")

// DispatchIntentRow is one workload a hub process is starting.
type DispatchIntentRow struct {
	RunID       string
	InstanceID  string
	ExecutorID  string
	Driver      string
	ProjectPath string
	HandleID    string
	LeaseIDs    []string
	EgressIDs   []string
	State       string
	CreatedAt   time.Time
	UpdatedAt   time.Time
	Detail      string
}

const dispatchIntentColumns = `run_id, instance_id, executor_id, driver, project_path, handle_id,
	lease_ids, egress_ids, state, created_at, updated_at, detail`

// PutDispatchIntent records a workload about to be started. A run id is
// minted once per dispatch, so a conflict is the same dispatch writing again,
// and its row is brought up to date.
func (d *DB) PutDispatchIntent(row DispatchIntentRow) error {
	if strings.TrimSpace(row.RunID) == "" {
		return errors.New("statedb: dispatch intent needs a run id")
	}
	if strings.TrimSpace(row.State) == "" {
		row.State = DispatchIntentDispatching
	}
	now := time.Now().UTC()
	if row.CreatedAt.IsZero() {
		row.CreatedAt = now
	}
	if row.UpdatedAt.IsZero() {
		row.UpdatedAt = now
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	_, err := d.conn.Exec(
		`INSERT INTO dispatch_intents(`+dispatchIntentColumns+`)
		 VALUES(?,?,?,?,?,?,?,?,?,?,?,?)
		 ON CONFLICT(run_id) DO UPDATE SET
		   instance_id  = excluded.instance_id,
		   executor_id  = excluded.executor_id,
		   driver       = excluded.driver,
		   project_path = excluded.project_path,
		   handle_id    = excluded.handle_id,
		   lease_ids    = excluded.lease_ids,
		   egress_ids   = excluded.egress_ids,
		   state        = excluded.state,
		   updated_at   = excluded.updated_at,
		   detail       = excluded.detail`,
		row.RunID, row.InstanceID, row.ExecutorID, row.Driver, row.ProjectPath, row.HandleID,
		marshalIDList(row.LeaseIDs), marshalIDList(row.EgressIDs), row.State,
		formatOptionalTime(row.CreatedAt), formatOptionalTime(row.UpdatedAt), row.Detail,
	)
	if err != nil {
		return fmt.Errorf("statedb: record dispatch intent %q: %w", row.RunID, classifyDriverErr(err))
	}
	return nil
}

// MarkDispatchStarted completes an intent with the workload's handle and the
// egress sessions bound to it, and reports whether the intent was there.
func (d *DB) MarkDispatchStarted(runID, handleID string, egressIDs []string) (bool, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	res, err := d.conn.Exec(
		`UPDATE dispatch_intents SET handle_id = ?, egress_ids = ?, state = ?, updated_at = ?
		  WHERE run_id = ?`,
		handleID, marshalIDList(egressIDs), DispatchIntentStarted, formatOptionalTime(time.Now().UTC()), runID)
	if err != nil {
		return false, fmt.Errorf("statedb: complete dispatch intent %q: %w", runID, classifyDriverErr(err))
	}
	n, _ := res.RowsAffected()
	return n == 1, nil
}

// NoteDispatchIntent records why an intent is still outstanding.
func (d *DB) NoteDispatchIntent(runID, detail string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if _, err := d.conn.Exec(`UPDATE dispatch_intents SET detail = ?, updated_at = ? WHERE run_id = ?`,
		detail, formatOptionalTime(time.Now().UTC()), runID); err != nil {
		return fmt.Errorf("statedb: note dispatch intent %q: %w", runID, classifyDriverErr(err))
	}
	return nil
}

// GetDispatchIntent returns one intent, or a wrapped ErrDispatchIntentNotFound.
func (d *DB) GetDispatchIntent(runID string) (DispatchIntentRow, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	r, err := scanDispatchIntent(d.conn.QueryRow(
		`SELECT `+dispatchIntentColumns+` FROM dispatch_intents WHERE run_id = ?`, runID))
	if errors.Is(err, sql.ErrNoRows) {
		return DispatchIntentRow{}, fmt.Errorf("%w: %s", ErrDispatchIntentNotFound, runID)
	}
	if err != nil {
		return DispatchIntentRow{}, fmt.Errorf("statedb: get dispatch intent %q: %w", runID, classifyDriverErr(err))
	}
	return r, nil
}

// ListDispatchIntents returns every outstanding intent, oldest first.
func (d *DB) ListDispatchIntents() ([]DispatchIntentRow, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	rows, err := d.conn.Query(`SELECT ` + dispatchIntentColumns + ` FROM dispatch_intents ORDER BY created_at, run_id`)
	if err != nil {
		return nil, fmt.Errorf("statedb: list dispatch intents: %w", classifyDriverErr(err))
	}
	defer rows.Close()
	var out []DispatchIntentRow
	for rows.Next() {
		r, err := scanDispatchIntent(rows)
		if err != nil {
			return nil, fmt.Errorf("statedb: scan dispatch intent: %w", classifyDriverErr(err))
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("statedb: list dispatch intents: %w", classifyDriverErr(err))
	}
	return out, nil
}

// DeleteDispatchIntent forgets one intent. A missing row is not an error: the
// run's record and its end both retire it, and either may come second.
func (d *DB) DeleteDispatchIntent(runID string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if _, err := d.conn.Exec(`DELETE FROM dispatch_intents WHERE run_id = ?`, runID); err != nil {
		return fmt.Errorf("statedb: delete dispatch intent %q: %w", runID, classifyDriverErr(err))
	}
	return nil
}

// DeleteDispatchIntentForHandle forgets the intent naming handleID on
// executorID, and reports whether one went: what recording the run does, which
// knows the workload by its handle rather than by the run id.
func (d *DB) DeleteDispatchIntentForHandle(executorID, handleID string) (bool, error) {
	if strings.TrimSpace(executorID) == "" || strings.TrimSpace(handleID) == "" {
		return false, nil
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	res, err := d.conn.Exec(`DELETE FROM dispatch_intents WHERE executor_id = ? AND handle_id = ?`,
		executorID, handleID)
	if err != nil {
		return false, fmt.Errorf("statedb: delete dispatch intent for %s/%s: %w", executorID, handleID, classifyDriverErr(err))
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

func scanDispatchIntent(s interface{ Scan(dest ...any) error }) (DispatchIntentRow, error) {
	var (
		r                    DispatchIntentRow
		leases, egress       string
		createdAt, updatedAt string
	)
	if err := s.Scan(&r.RunID, &r.InstanceID, &r.ExecutorID, &r.Driver, &r.ProjectPath, &r.HandleID,
		&leases, &egress, &r.State, &createdAt, &updatedAt, &r.Detail); err != nil {
		return DispatchIntentRow{}, err
	}
	r.LeaseIDs = unmarshalIDList(leases)
	r.EgressIDs = unmarshalIDList(egress)
	r.CreatedAt = parseOptionalTime(createdAt)
	r.UpdatedAt = parseOptionalTime(updatedAt)
	return r, nil
}

// marshalIDList renders a list of ids for a JSON text column; nil is "[]".
func marshalIDList(ids []string) string {
	if len(ids) == 0 {
		return "[]"
	}
	b, err := json.Marshal(ids)
	if err != nil {
		return "[]"
	}
	return string(b)
}

// unmarshalIDList parses a JSON text column of ids. Unreadable text is no ids:
// the column is written only by marshalIDList.
func unmarshalIDList(s string) []string {
	s = strings.TrimSpace(s)
	if s == "" || s == "[]" {
		return nil
	}
	var out []string
	if err := json.Unmarshal([]byte(s), &out); err != nil {
		return nil
	}
	return out
}
