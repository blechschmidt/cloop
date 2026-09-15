// Task execution correlation and lifecycle-transition detection (Task 20282).
//
// Two questions were unanswerable from audit_events, and they share a cause.
//
// "How did task 63 end?" had to be *inferred* from the task.upsert rows
// SaveState emits incidentally, by noticing that one payload said in_progress
// and the next said failed. That is inference, not a record: the two rows are
// indistinguishable from any other pair of field edits, there is no outcome, no
// duration, no reason, and a reader has to know the plan's shape to spot them
// at all.
//
// "Under which secret leases?" had nothing to join on. The broker writes
// secret.lease rows naming an executor and a project; the task rows name a
// task. Correlating them meant reconstructing a time window and hoping no other
// run overlapped it — and on a hub running a fleet, one always does.
//
// # Why the emitter lives here and not in the orchestrator
//
// A terminal audit row has to be written on *every* exit path, and the
// orchestrator has many: the three signal paths, an unsignalled run judged by
// its repository diff, a manual kill, a step timeout, a per-task deadline, a
// provider abort applied live, a provider abort found later by the sweep, an
// executor failover, and a hub crash whose tasks are reconciled by a different
// process entirely. Asking each of those to remember to emit is how coverage
// rots: the next exit path added is the one that forgets, and the gap is
// invisible because a missing audit row looks exactly like a task that never
// ran.
//
// They do all have one thing in common. Every one of them must *persist* the
// status it decided, or the decision is lost — so every one of them passes
// through SaveState. Detecting the transition at the write is therefore
// complete by construction, and stays complete for exit paths nobody has
// written yet.
//
// The cursor is what makes a transition visible at a write that only sees the
// new value. audited_status holds the status for which a lifecycle row was last
// emitted; comparing it against the incoming status yields the edge:
//
//	→ in_progress      task.dispatch
//	in_progress → any  task.finish
//
// Both are recorded inside the same transaction as the tasks, so a rollback
// leaves the audit bookkeeping exactly as consistent as the plan, and a task
// whose save failed does not get a dispatch row for work that never started.

package statedb

import (
	"database/sql"
	"fmt"

	"github.com/blechschmidt/cloop/pkg/pm"
)

// taskRunRow is the persisted correlation state for one task.
type taskRunRow struct {
	RunID string
	// AuditedStatus is the status for which a lifecycle row was last emitted,
	// empty when none ever was.
	AuditedStatus string
}

// taskLifecycleEdge is one task crossing into or out of execution, carried from
// inside the write transaction out to the post-commit emitter.
//
// PrevStatus is the status the trail last recorded, not necessarily the status
// stored on the previous save: a save that changed only a task's description
// does not move the cursor, so the edge that eventually fires still names the
// status the last *lifecycle* row described.
type taskLifecycleEdge struct {
	Task       *pm.Task
	RunID      string
	PrevStatus string
	NewStatus  string
}

// Dispatch reports whether this edge is a task entering execution.
func (e taskLifecycleEdge) Dispatch() bool {
	return e.NewStatus == string(pm.TaskInProgress)
}

// loadTaskRuns reads the correlation table into a map.
func loadTaskRuns(tx *sql.Tx) (map[int]taskRunRow, error) {
	out := make(map[int]taskRunRow)
	rows, err := tx.Query(`SELECT task_id, run_id, audited_status FROM task_runs`)
	if err != nil {
		return nil, fmt.Errorf("read task runs: %w", classifyDriverErr(err))
	}
	defer rows.Close()
	for rows.Next() {
		var (
			id  int
			row taskRunRow
		)
		if err := rows.Scan(&id, &row.RunID, &row.AuditedStatus); err != nil {
			return nil, fmt.Errorf("scan task run: %w", classifyDriverErr(err))
		}
		out[id] = row
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("task run rows: %w", classifyDriverErr(err))
	}
	return out, nil
}

// putTaskRun writes one task's correlation row.
func putTaskRun(tx *sql.Tx, taskID int, row taskRunRow) error {
	if _, err := tx.Exec(
		`INSERT INTO task_runs(task_id, run_id, audited_status) VALUES (?,?,?)
		 ON CONFLICT(task_id) DO UPDATE SET run_id = excluded.run_id, audited_status = excluded.audited_status`,
		taskID, row.RunID, row.AuditedStatus,
	); err != nil {
		return fmt.Errorf("write task run %d: %w", taskID, classifyDriverErr(err))
	}
	return nil
}

// forgetTaskRunTx drops a deleted task's correlation row, so an id reused later
// starts from "never dispatched" rather than inheriting an unrelated task's run
// and cursor — the same reason forgetTaskFingerprintTx exists.
func forgetTaskRunTx(tx *sql.Tx, taskID int) error {
	if _, err := tx.Exec(`DELETE FROM task_runs WHERE task_id = ?`, taskID); err != nil {
		return fmt.Errorf("drop task run %d: %w", taskID, classifyDriverErr(err))
	}
	return nil
}

// diffTaskLifecycle detects execution-boundary crossings for the incoming plan
// and advances the stored cursor to match, all inside tx.
//
// It returns the edges to emit once the transaction commits. Callers must not
// emit before the commit: an audit row that describes a write which rolled back
// is worse than no row, because it is a false statement in a table whose value
// is that its statements are true.
//
// A task whose RunID is empty inherits the stored one. That is what lets the
// terminal row for a crash-recovered task name the run that actually spent the
// leases: the process writing that row is a *different* process, which never
// dispatched the task and has no run id of its own to stamp.
func diffTaskLifecycle(tx *sql.Tx, tasks []*pm.Task) ([]taskLifecycleEdge, error) {
	stored, err := loadTaskRuns(tx)
	if err != nil {
		return nil, err
	}

	var edges []taskLifecycleEdge
	seen := make(map[int]bool, len(tasks))
	for _, t := range tasks {
		if t == nil {
			continue
		}
		seen[t.ID] = true
		prev := stored[t.ID]

		runID := t.RunID
		if runID == "" {
			runID = prev.RunID
		}

		status := string(t.Status)
		inFlight := status == string(pm.TaskInProgress)
		wasInFlight := prev.AuditedStatus == string(pm.TaskInProgress)

		// No edge: the task is not crossing the execution boundary. Note that a
		// pending task whose cursor is also pending produces nothing, which is
		// what keeps the ordinary "saved for an unrelated field change" case
		// free of lifecycle rows.
		if inFlight == wasInFlight {
			// The run id can still move under a task that stays in flight —
			// nothing does that today, but persisting it unconditionally keeps
			// the stored value equal to the task's rather than merely usually
			// equal to it.
			if runID != prev.RunID {
				if err := putTaskRun(tx, t.ID, taskRunRow{RunID: runID, AuditedStatus: prev.AuditedStatus}); err != nil {
					return nil, err
				}
			}
			continue
		}

		edges = append(edges, taskLifecycleEdge{
			Task:       t,
			RunID:      runID,
			PrevStatus: prev.AuditedStatus,
			NewStatus:  status,
		})
		if err := putTaskRun(tx, t.ID, taskRunRow{RunID: runID, AuditedStatus: status}); err != nil {
			return nil, err
		}
	}

	// A task that disappeared mid-flight is deliberately not given a terminal
	// row here. Its row is dropped by DeleteTask, which emits task.delete — and
	// a plan that merely stopped listing a task has not ended its execution, it
	// has lost track of it. Inventing a finish would assert an outcome nobody
	// observed.
	for id := range stored {
		if !seen[id] {
			if err := forgetTaskRunTx(tx, id); err != nil {
				return nil, err
			}
		}
	}
	return edges, nil
}

// TaskRunID reports the execution a task's latest attempt was dispatched into,
// and whether one was recorded.
//
// Exported for the reconstruction in `cloop audit-log --task`, which needs the
// run id to pull the lease rows that belong to the same execution.
func (d *DB) TaskRunID(taskID int) (string, bool, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	var runID string
	err := d.conn.QueryRow(`SELECT run_id FROM task_runs WHERE task_id = ?`, taskID).Scan(&runID)
	if err == sql.ErrNoRows {
		return "", false, nil
	}
	if err != nil {
		return "", false, classifyDriverErr(err)
	}
	return runID, runID != "", nil
}
