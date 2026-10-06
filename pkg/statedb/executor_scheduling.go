// Executor liveness and failover persistence (Task 20162).
//
// Rows for the two tables described in
// migrations/0013_executor_scheduling.sql. This file owns the SQL; the
// scheduler owns the policy — how many probe failures demote a node, how long
// a degraded node waits before it is drained — so none of that appears here.
//
// executor_health is the control plane's own observation of a backend, kept
// apart from the enrollment registry in `executors` so that in-process drivers
// (localprocess, container) which never enroll can still be marked unhealthy
// or cordoned. Health rows therefore stand alone: writing one does not require
// an executors row, and there is no foreign key.
//
// executor_sessions is the in-flight ledger failover requeues from, and
// ClaimExecutorSessionRequeue below is the exactly-once latch that makes
// requeueing safe. Everything else in this file is bookkeeping around it.

package statedb

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Executor session states as persisted in the state column.
const (
	// ExecutorSessionRunning: work is in flight on the executor.
	ExecutorSessionRunning = "running"
	// ExecutorSessionRequeued: a supervisor claimed the session for failover
	// and the work has been handed to another executor.
	ExecutorSessionRequeued = "requeued"
	// ExecutorSessionFinished: the work completed on this executor.
	ExecutorSessionFinished = "finished"
	// ExecutorSessionFailed: the work ended in failure and was not requeued.
	ExecutorSessionFailed = "failed"
	// ExecutorSessionFailoverExhausted: the executor went unreachable after
	// the session had already been re-dispatched as often as
	// executors.failover.max_attempts allows (Task 20391). The claim closed
	// it in this state instead of requeued, and nothing re-dispatches it.
	ExecutorSessionFailoverExhausted = "failover_exhausted"
)

// maxSessionChain bounds ExecutorSessionChain's walk. A chain is at most
// executors.failover.max_attempts + 1 long (ten re-dispatches at most), so
// anything near this is a cycle written by hand, not history.
const maxSessionChain = 64

// ExecutorHealthRow is the scheduler's probe-driven view of one executor.
// ExecutorID shares the identifier space with ExecutorRow.ID but is not a
// foreign key — see the file comment.
type ExecutorHealthRow struct {
	ExecutorID          string
	State               string
	Reason              string
	ConsecutiveFailures int
	LastSeen            time.Time
	LastProbe           time.Time
	StateChangedAt      time.Time
}

// ExecutorSessionRow is one unit of work in flight on an executor.
type ExecutorSessionRow struct {
	ID          string
	ExecutorID  string
	HandleID    string
	ProjectPath string
	TaskID      int
	// ClaimToken gates the requeue latch. It is a concurrency token, not a
	// secret: it is stored and compared in plaintext because it authorises
	// nothing beyond winning one race.
	ClaimToken   string
	State        string
	Attempt      int
	StartedAt    time.Time
	UpdatedAt    time.Time
	EndedAt      time.Time
	RequeuedFrom string
	// SpecJSON is the marshalled executor.Spec the session was dispatched
	// with. Failover re-dispatches from it, so it must survive a
	// control-plane restart: a session whose spec lived only in the memory
	// of the process that started it could not be requeued by the process
	// that replaces it, which is exactly when requeueing matters most.
	SpecJSON string
	// RunningTasks are the tasks the workload last announced it was working
	// on (Task 20391), kept so a failover can say which tasks a lost node
	// was running even when the hub's own copy of the project cannot: a run
	// on a device works on a copy. Written by SetExecutorSessionRunningTasks
	// while the session runs; empty when nothing was observed.
	RunningTasks []int
}

// PutExecutorHealth inserts or updates the health row for row.ExecutorID.
//
// The row is written wholesale rather than merged field-by-field: the prober
// computes the complete verdict (state, reason, failure count, transition
// time) in one place, and a partial update would let a stale field outlive the
// observation that produced it.
func (d *DB) PutExecutorHealth(row ExecutorHealthRow) error {
	if strings.TrimSpace(row.ExecutorID) == "" {
		return errors.New("statedb: executor health executor id is required")
	}
	// Default to the same value as the column default, so a caller that only
	// wants to record a probe timestamp does not write a blank state that
	// would render as an empty health column in the UI.
	if row.State == "" {
		row.State = "ready"
	}
	if row.ConsecutiveFailures < 0 {
		row.ConsecutiveFailures = 0
	}

	d.mu.Lock()
	defer d.mu.Unlock()
	_, err := d.conn.Exec(
		`INSERT INTO executor_health(executor_id, state, reason, consecutive_failures,
		                             last_seen, last_probe, state_changed_at)
		 VALUES(?,?,?,?,?,?,?)
		 ON CONFLICT(executor_id) DO UPDATE SET
		   state                = excluded.state,
		   reason               = excluded.reason,
		   consecutive_failures = excluded.consecutive_failures,
		   last_seen            = excluded.last_seen,
		   last_probe           = excluded.last_probe,
		   state_changed_at     = excluded.state_changed_at`,
		row.ExecutorID, row.State, row.Reason, row.ConsecutiveFailures,
		formatOptionalTime(row.LastSeen),
		formatOptionalTime(row.LastProbe),
		formatOptionalTime(row.StateChangedAt),
	)
	if err != nil {
		return fmt.Errorf("statedb: put executor health %q: %w", row.ExecutorID, classifyDriverErr(err))
	}
	return nil
}

// GetExecutorHealth returns one health row, or ErrExecutorHealthNotFound.
//
// "Never probed" is deliberately an error rather than a zero-valued ready row:
// a caller that cannot tell the two apart would treat an unobserved executor
// as healthy, which is the failure mode this table exists to prevent.
func (d *DB) GetExecutorHealth(executorID string) (ExecutorHealthRow, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	row := d.conn.QueryRow(
		`SELECT executor_id, state, reason, consecutive_failures,
		        last_seen, last_probe, state_changed_at
		 FROM executor_health WHERE executor_id = ?`, executorID)
	out, err := scanExecutorHealthRow(row)
	if errors.Is(err, sql.ErrNoRows) {
		return ExecutorHealthRow{}, fmt.Errorf("%w: %q", ErrExecutorHealthNotFound, executorID)
	}
	if err != nil {
		return ExecutorHealthRow{}, fmt.Errorf("statedb: get executor health %q: %w", executorID, classifyDriverErr(err))
	}
	return out, nil
}

// ListExecutorHealth returns every health row ordered by executor ID.
func (d *DB) ListExecutorHealth() ([]ExecutorHealthRow, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	rows, err := d.conn.Query(
		`SELECT executor_id, state, reason, consecutive_failures,
		        last_seen, last_probe, state_changed_at
		 FROM executor_health ORDER BY executor_id ASC`)
	if err != nil {
		return nil, fmt.Errorf("statedb: list executor health: %w", classifyDriverErr(err))
	}
	defer rows.Close()

	var out []ExecutorHealthRow
	for rows.Next() {
		rec, err := scanExecutorHealthRow(rows)
		if err != nil {
			return nil, fmt.Errorf("statedb: scan executor health: %w", classifyDriverErr(err))
		}
		out = append(out, rec)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("statedb: list executor health: %w", classifyDriverErr(err))
	}
	return out, nil
}

// DeleteExecutorHealth forgets the health record for executorID. Deleting a
// row that was never written is not an error: de-enrolling an executor that
// was never probed must not fail.
func (d *DB) DeleteExecutorHealth(executorID string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if _, err := d.conn.Exec(`DELETE FROM executor_health WHERE executor_id = ?`, executorID); err != nil {
		return fmt.Errorf("statedb: delete executor health %q: %w", executorID, classifyDriverErr(err))
	}
	return nil
}

// OpenExecutorSession records work starting on an executor.
//
// This is a plain INSERT, not an upsert: a session id identifies one attempt,
// and silently overwriting an existing row would erase the claim token a
// supervisor may already be holding for the in-flight attempt.
func (d *DB) OpenExecutorSession(row ExecutorSessionRow) error {
	if strings.TrimSpace(row.ID) == "" {
		return errors.New("statedb: executor session id is required")
	}
	// A blank claim token would make the requeue latch's WHERE clause match
	// any other blank-token holder, collapsing the exactly-once guarantee into
	// "whoever asks". Refuse the row rather than persist an unclaimable one.
	if strings.TrimSpace(row.ClaimToken) == "" {
		return fmt.Errorf("statedb: executor session %q has an empty claim token", row.ID)
	}
	if strings.TrimSpace(row.ExecutorID) == "" {
		return fmt.Errorf("statedb: executor session %q has no executor id", row.ID)
	}
	if row.State == "" {
		row.State = ExecutorSessionRunning
	}
	if row.Attempt <= 0 {
		row.Attempt = 1
	}
	if row.StartedAt.IsZero() {
		row.StartedAt = time.Now()
	}
	if row.UpdatedAt.IsZero() {
		row.UpdatedAt = row.StartedAt
	}

	d.mu.Lock()
	defer d.mu.Unlock()
	_, err := d.conn.Exec(
		`INSERT INTO executor_sessions(id, executor_id, handle_id, project_path, task_id,
		                               claim_token, state, attempt, started_at, updated_at,
		                               ended_at, requeued_from, spec_json, running_tasks)
		 VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		row.ID, row.ExecutorID, row.HandleID, row.ProjectPath, row.TaskID,
		row.ClaimToken, row.State, row.Attempt,
		row.StartedAt.UTC().Format(time.RFC3339Nano),
		row.UpdatedAt.UTC().Format(time.RFC3339Nano),
		formatOptionalTime(row.EndedAt), row.RequeuedFrom, row.SpecJSON,
		encodeRunningTasks(row.RunningTasks),
	)
	if err != nil {
		return fmt.Errorf("statedb: open executor session %q: %w", row.ID, classifyDriverErr(err))
	}
	return nil
}

// GetExecutorSession returns one session by ID, or ErrExecutorSessionNotFound.
func (d *DB) GetExecutorSession(id string) (ExecutorSessionRow, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	out, err := d.getExecutorSessionLocked(id)
	if errors.Is(err, sql.ErrNoRows) {
		return ExecutorSessionRow{}, fmt.Errorf("%w: %q", ErrExecutorSessionNotFound, id)
	}
	if err != nil {
		return ExecutorSessionRow{}, fmt.Errorf("statedb: get executor session %q: %w", id, classifyDriverErr(err))
	}
	return out, nil
}

// ListExecutorSessions returns sessions ordered by start time then ID. An
// empty executorID lists every executor's sessions; onlyRunning restricts the
// result to work that is still in flight, which is what failover and capacity
// checks ask for.
func (d *DB) ListExecutorSessions(executorID string, onlyRunning bool) ([]ExecutorSessionRow, error) {
	query := `SELECT ` + executorSessionColumns + `
	          FROM executor_sessions`
	var (
		clauses []string
		args    []any
	)
	if executorID != "" {
		clauses = append(clauses, "executor_id = ?")
		args = append(args, executorID)
	}
	if onlyRunning {
		clauses = append(clauses, "state = ?")
		args = append(args, ExecutorSessionRunning)
	}
	if len(clauses) > 0 {
		query += " WHERE " + strings.Join(clauses, " AND ")
	}
	// Ordering by id after started_at keeps the listing stable when several
	// sessions share a timestamp, so tests and UI paging do not shuffle.
	query += " ORDER BY started_at ASC, id ASC"

	d.mu.Lock()
	defer d.mu.Unlock()
	rows, err := d.conn.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("statedb: list executor sessions: %w", classifyDriverErr(err))
	}
	defer rows.Close()

	var out []ExecutorSessionRow
	for rows.Next() {
		rec, err := scanExecutorSessionRow(rows)
		if err != nil {
			return nil, fmt.Errorf("statedb: scan executor session: %w", classifyDriverErr(err))
		}
		out = append(out, rec)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("statedb: list executor sessions: %w", classifyDriverErr(err))
	}
	return out, nil
}

// CountRunningExecutorSessions returns how many sessions are still in flight.
// An empty executorID counts across the whole fleet.
func (d *DB) CountRunningExecutorSessions(executorID string) (int, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	var (
		n   int
		err error
	)
	if executorID == "" {
		err = d.conn.QueryRow(
			`SELECT COUNT(1) FROM executor_sessions WHERE state = ?`,
			ExecutorSessionRunning).Scan(&n)
	} else {
		err = d.conn.QueryRow(
			`SELECT COUNT(1) FROM executor_sessions WHERE executor_id = ? AND state = ?`,
			executorID, ExecutorSessionRunning).Scan(&n)
	}
	if err != nil {
		return 0, fmt.Errorf("statedb: count running executor sessions: %w", classifyDriverErr(err))
	}
	return n, nil
}

// CloseExecutorSession moves a running session to a terminal state. Returns
// ErrExecutorSessionNotFound when the ID is unknown, so a driver reporting
// completion for a session the control plane never opened surfaces loudly
// instead of being silently dropped.
//
// A session that is no longer running is left as it is and the call succeeds:
// its end is already recorded. That matters for the one writer that gets
// there first on purpose — a failover's claim, which records requeued or
// failover_exhausted (Task 20391). The workload's own watcher notices the end
// much later, often only when the dead node's stream finally closes, and
// before this condition its close overwrote the claim's verdict with
// "failed": the exhausted session vanished from the record, and with it what
// stops a re-dispatch.
func (d *DB) CloseExecutorSession(id, state string, at time.Time) error {
	if state == "" {
		state = ExecutorSessionFinished
	}
	if at.IsZero() {
		at = time.Now()
	}
	stamp := at.UTC().Format(time.RFC3339Nano)

	d.mu.Lock()
	defer d.mu.Unlock()
	res, err := d.conn.Exec(
		`UPDATE executor_sessions SET state = ?, updated_at = ?, ended_at = ? WHERE id = ? AND state = ?`,
		state, stamp, stamp, id, ExecutorSessionRunning)
	if err != nil {
		return fmt.Errorf("statedb: close executor session %q: %w", id, classifyDriverErr(err))
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("statedb: close executor session %q: %w", id, classifyDriverErr(err))
	}
	if n == 0 {
		if _, readErr := d.getExecutorSessionLocked(id); errors.Is(readErr, sql.ErrNoRows) {
			return fmt.Errorf("%w: %q", ErrExecutorSessionNotFound, id)
		} else if readErr != nil {
			return fmt.Errorf("statedb: close executor session %q: %w", id, classifyDriverErr(readErr))
		}
	}
	return nil
}

// ClaimExecutorSessionRequeue atomically claims a running session for failover
// and rotates its claim token.
//
// The exactly-once guarantee lives entirely in this statement's WHERE clause.
// SQLite serialises writers, so of N supervisors racing to fail over the same
// dead executor exactly one finds state = 'running' with the claim token it
// read and updates a row; every other supervisor matches nothing and gets
// ErrExecutorSessionClaimLost. Rotating claim_token in the same statement also
// makes a retry by the winner idempotent-safe: the old token can never match
// again.
//
// A read-then-write implementation would let two supervisors both decide the
// session is running and both requeue the work — which here means two AI
// agents editing the same repository concurrently. That is the failure this
// function exists to make impossible, so the read and the write must not be
// separable.
//
// The failover cap is decided in the same statement (Task 20391). A session
// whose attempt is at most maxAttempts — re-dispatched fewer times than the
// cap — becomes requeued; one past it becomes failover_exhausted, and the
// returned row's State says which. Deciding it here rather than in the caller
// is what makes every supervisor and every hub member agree: whoever wins the
// claim also fixes the session's fate, and a loser has nothing left to decide
// differently. maxAttempts below zero is read as zero — no re-dispatch —
// because no reading of a bad cap may be "no cap".
//
// The follow-up read on a zero-row update is only to tell the operator which
// of two situations they are in; it never grants a claim, so a row appearing
// or vanishing between the two statements cannot turn a loss into a win.
func (d *DB) ClaimExecutorSessionRequeue(id, claimToken, newClaimToken string, maxAttempts int, at time.Time) (ExecutorSessionRow, error) {
	if strings.TrimSpace(claimToken) == "" {
		return ExecutorSessionRow{}, errors.New("statedb: executor session claim token is required")
	}
	if strings.TrimSpace(newClaimToken) == "" {
		return ExecutorSessionRow{}, errors.New("statedb: executor session replacement claim token is required")
	}
	if maxAttempts < 0 {
		maxAttempts = 0
	}
	if at.IsZero() {
		at = time.Now()
	}
	stamp := at.UTC().Format(time.RFC3339Nano)

	d.mu.Lock()
	defer d.mu.Unlock()
	res, err := d.conn.Exec(
		`UPDATE executor_sessions
		 SET state = CASE WHEN attempt <= ? THEN ? ELSE ? END,
		     claim_token = ?, updated_at = ?, ended_at = ?
		 WHERE id = ? AND claim_token = ? AND state = ?`,
		maxAttempts, ExecutorSessionRequeued, ExecutorSessionFailoverExhausted,
		newClaimToken, stamp, stamp,
		id, claimToken, ExecutorSessionRunning)
	if err != nil {
		return ExecutorSessionRow{}, fmt.Errorf("statedb: claim executor session %q: %w", id, classifyDriverErr(err))
	}
	n, err := res.RowsAffected()
	if err != nil {
		return ExecutorSessionRow{}, fmt.Errorf("statedb: claim executor session %q: %w", id, classifyDriverErr(err))
	}
	if n == 0 {
		// Losing the race is the common case and the default answer. Report
		// "not found" only when a follow-up read shows there is genuinely no
		// such session, because an operator debugging a stale session id needs
		// that distinction and it costs nothing to give.
		if _, readErr := d.getExecutorSessionLocked(id); errors.Is(readErr, sql.ErrNoRows) {
			return ExecutorSessionRow{}, fmt.Errorf("%w: %q", ErrExecutorSessionNotFound, id)
		}
		return ExecutorSessionRow{}, fmt.Errorf("%w: %q", ErrExecutorSessionClaimLost, id)
	}

	out, err := d.getExecutorSessionLocked(id)
	if err != nil {
		return ExecutorSessionRow{}, fmt.Errorf("statedb: reload claimed executor session %q: %w", id, classifyDriverErr(err))
	}
	return out, nil
}

// getExecutorSessionLocked reads one session. The caller must hold d.mu; it
// returns the raw sql.ErrNoRows so callers can decide which sentinel that
// means in their context.
func (d *DB) getExecutorSessionLocked(id string) (ExecutorSessionRow, error) {
	row := d.conn.QueryRow(
		`SELECT `+executorSessionColumns+`
		 FROM executor_sessions WHERE id = ?`, id)
	return scanExecutorSessionRow(row)
}

// executorSessionColumns is what every session read selects, in the order
// scanExecutorSessionRow scans it.
const executorSessionColumns = `id, executor_id, handle_id, project_path, task_id, claim_token,
	state, attempt, started_at, updated_at, ended_at, requeued_from,
	spec_json, running_tasks`

func scanExecutorHealthRow(sc rowScanner) (ExecutorHealthRow, error) {
	var (
		rec                                 ExecutorHealthRow
		lastSeen, lastProbe, stateChangedAt string
	)
	if err := sc.Scan(&rec.ExecutorID, &rec.State, &rec.Reason, &rec.ConsecutiveFailures,
		&lastSeen, &lastProbe, &stateChangedAt); err != nil {
		return ExecutorHealthRow{}, err
	}
	rec.LastSeen = parseOptionalTime(lastSeen)
	rec.LastProbe = parseOptionalTime(lastProbe)
	rec.StateChangedAt = parseOptionalTime(stateChangedAt)
	return rec, nil
}

func scanExecutorSessionRow(sc rowScanner) (ExecutorSessionRow, error) {
	var (
		rec                           ExecutorSessionRow
		startedAt, updatedAt, endedAt string
		running                       string
	)
	if err := sc.Scan(&rec.ID, &rec.ExecutorID, &rec.HandleID, &rec.ProjectPath, &rec.TaskID,
		&rec.ClaimToken, &rec.State, &rec.Attempt,
		&startedAt, &updatedAt, &endedAt, &rec.RequeuedFrom, &rec.SpecJSON, &running); err != nil {
		return ExecutorSessionRow{}, err
	}
	rec.StartedAt = parseOptionalTime(startedAt)
	rec.UpdatedAt = parseOptionalTime(updatedAt)
	rec.EndedAt = parseOptionalTime(endedAt)
	rec.RunningTasks = decodeRunningTasks(running)
	return rec, nil
}

// maxRunningTasks bounds the running-tasks record. It is written from what a
// workload printed, and a workload is hostile by assumption: a run announcing
// ten thousand tasks must not turn one row into a megabyte.
const maxRunningTasks = 64

// encodeRunningTasks renders a running-tasks record for its column: positive
// ids only, deduplicated, at most maxRunningTasks of them.
func encodeRunningTasks(ids []int) string {
	ids = normalizeRunningTasks(ids)
	if len(ids) == 0 {
		return ""
	}
	data, err := json.Marshal(ids)
	if err != nil {
		return ""
	}
	return string(data)
}

// decodeRunningTasks reads the column back. Damage reads as "nothing
// observed": the record attributes a lost node to tasks, and a guess is worse
// than an honest blank.
func decodeRunningTasks(s string) []int {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	var ids []int
	if err := json.Unmarshal([]byte(s), &ids); err != nil {
		return nil
	}
	return normalizeRunningTasks(ids)
}

func normalizeRunningTasks(ids []int) []int {
	if len(ids) == 0 {
		return nil
	}
	seen := make(map[int]bool, len(ids))
	out := make([]int, 0, len(ids))
	for _, id := range ids {
		if id <= 0 || seen[id] {
			continue
		}
		seen[id] = true
		out = append(out, id)
		if len(out) == maxRunningTasks {
			break
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// SetExecutorSessionRunningTasks records which tasks a running session's
// workload is working on (Task 20391). Only a session still running is
// written: once a claim has taken it, what it was running is history the
// failover already read, and a late write from a stream that had not caught
// up must not change it.
//
// It reports whether a row was written.
func (d *DB) SetExecutorSessionRunningTasks(id string, tasks []int) (bool, error) {
	if strings.TrimSpace(id) == "" {
		return false, errors.New("statedb: executor session id is required")
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	res, err := d.conn.Exec(
		`UPDATE executor_sessions SET running_tasks = ? WHERE id = ? AND state = ?`,
		encodeRunningTasks(tasks), id, ExecutorSessionRunning)
	if err != nil {
		return false, fmt.Errorf("statedb: record running tasks of session %q: %w", id, classifyDriverErr(err))
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("statedb: record running tasks of session %q: %w", id, classifyDriverErr(err))
	}
	return n > 0, nil
}

// ExecutorSessionChain returns the failover chain that ends at id, oldest
// first: the session the run was first dispatched as, then each replacement a
// failover opened (requeued_from), down to id itself (Task 20391). It is how a
// failover names every node a run has lost so far.
//
// The walk is bounded (maxSessionChain) and refuses to revisit a session, so a
// cycle written into the table by hand ends the walk rather than the process.
// A predecessor that is gone — pruned by retention — ends it too: the chain is
// then what is left of it.
func (d *DB) ExecutorSessionChain(id string) ([]ExecutorSessionRow, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	var (
		chain []ExecutorSessionRow
		seen  = make(map[string]bool)
	)
	for cur := id; cur != "" && !seen[cur] && len(chain) < maxSessionChain; {
		seen[cur] = true
		row, err := d.getExecutorSessionLocked(cur)
		if errors.Is(err, sql.ErrNoRows) {
			if len(chain) == 0 {
				return nil, fmt.Errorf("%w: %q", ErrExecutorSessionNotFound, id)
			}
			break
		}
		if err != nil {
			return nil, fmt.Errorf("statedb: read executor session %q: %w", cur, classifyDriverErr(err))
		}
		chain = append(chain, row)
		cur = row.RequeuedFrom
	}
	for i, j := 0, len(chain)-1; i < j; i, j = i+1, j-1 {
		chain[i], chain[j] = chain[j], chain[i]
	}
	return chain, nil
}

// ExecutorSessionSuccessor returns the session a failover opened to replace
// id, if there is one.
func (d *DB) ExecutorSessionSuccessor(id string) (string, bool, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	var next string
	err := d.conn.QueryRow(
		`SELECT id FROM executor_sessions WHERE requeued_from = ? ORDER BY started_at ASC, id ASC LIMIT 1`,
		id).Scan(&next)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, fmt.Errorf("statedb: find the successor of executor session %q: %w", id, classifyDriverErr(err))
	}
	return next, true, nil
}
