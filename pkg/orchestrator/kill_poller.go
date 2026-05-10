// Manual abort poller (Task 20140).
//
// Polls the kill_requests table on a fast tick. For each pending request:
//
//  1. If the watchdog still has a registered cancel for the task ID, fire it.
//     The worker's provider call returns ctx.Err(); the worker writes its
//     terminal status (typically TaskFailed via the canceled-error path).
//  2. If the in-memory task is no longer in_progress (the worker has exited
//     and persisted), apply the operator's chosen target_status — overriding
//     the worker's "canceled → failed" default — and clear the kill row.
//
// Step (1) and step (2) usually happen on different ticks: the worker needs
// a moment to drain after the cancel fires. Until step (2) clears the row,
// the poller harmlessly retries — Watchdog.Cancel is idempotent (no cancel
// registered after step (1) → no-op).
//
// All work runs in a single goroutine bound to the run context, so there is
// no fan-out concurrency to coordinate.

package orchestrator

import (
	"context"
	"fmt"
	"time"

	"github.com/blechschmidt/cloop/pkg/logger"
	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/state"
)

// eventManualKill is the structured-log Event used by the kill-request poller
// for both the "fired cancel" and "applied target_status" log lines.
const eventManualKill logger.Event = "manual_kill"

// killPollInterval is the cadence of the kill-request poller. 1s strikes a
// balance between responsiveness (operator clicks "mark done" → cancel
// fires within a second) and load on the SQLite handle (~60 reads/min).
const killPollInterval = 1 * time.Second

// startKillPoller launches the manual-abort poller goroutine. Bound to ctx;
// the goroutine exits when ctx is cancelled. Safe to call when statedb is
// nil — the poller exits immediately in that case.
func (o *Orchestrator) startKillPoller(ctx context.Context) {
	if o == nil || o.statedb == nil {
		return
	}
	o.killWG.Add(1)
	go func() {
		defer o.killWG.Done()
		t := time.NewTicker(killPollInterval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				o.processPendingKills()
			}
		}
	}()
}

// processPendingKills handles one tick of the manual-abort poller. Exposed
// for tests; production callers go through startKillPoller.
func (o *Orchestrator) processPendingKills() {
	if o == nil || o.statedb == nil {
		return
	}
	rows, err := o.statedb.PendingKills()
	if err != nil {
		// Best-effort: a flapping DB must not crash the orchestrator. Surface
		// at warn level and try again next tick.
		if o.log != nil {
			o.log.Warn(eventManualKill, 0, fmt.Sprintf("read kill_requests: %v", err), nil)
		}
		return
	}
	if len(rows) == 0 {
		return
	}
	for _, req := range rows {
		o.handleKillRequest(req)
	}
}

// handleKillRequest processes a single pending kill row. Two-phase: fire the
// cancel if the worker is still running, otherwise apply the operator's
// chosen target_status and clear the row.
func (o *Orchestrator) handleKillRequest(req state.KillRequest) {
	task := o.findTaskByID(req.TaskID)
	if task == nil {
		// Stale row for a task we don't know about (e.g. deleted, or merged
		// from a sibling project). Drop the row so the poller doesn't spin
		// on it forever.
		_ = o.statedb.ClearKill(req.TaskID)
		return
	}

	// Phase 1: worker still running — fire the cancel, leave the row in
	// place so phase 2 runs once the worker drains.
	if task.Status == pm.TaskInProgress {
		fired := o.watchdog.Cancel(req.TaskID)
		if fired && o.log != nil {
			o.log.Info(eventManualKill, req.TaskID,
				fmt.Sprintf("Task #%d: manual kill from %q (target=%q)", req.TaskID, req.RequestedBy, req.TargetStatus),
				map[string]interface{}{
					"task_id":       req.TaskID,
					"target_status": req.TargetStatus,
					"requested_by":  req.RequestedBy,
				})
		}
		// If no cancel was registered (watchdog disabled, race with task
		// completion), let phase 2 handle it on the next tick — the worker
		// will eventually exit on its own and Status will leave in_progress.
		return
	}

	// Phase 2: worker has exited (status is terminal). Override with the
	// operator's chosen target_status, persist, and clear the row.
	o.applyKillTargetStatus(task, req.TargetStatus)
	if err := o.state.Save(); err != nil && o.log != nil {
		o.log.Warn(eventManualKill, req.TaskID,
			fmt.Sprintf("Task #%d: persist target status failed: %v", req.TaskID, err), nil)
	}
	if err := o.statedb.ClearKill(req.TaskID); err != nil && o.log != nil {
		o.log.Warn(eventManualKill, req.TaskID,
			fmt.Sprintf("Task #%d: clear kill row failed: %v", req.TaskID, err), nil)
	}
}

// findTaskByID returns the in-memory task pointer or nil. Read-only access
// to o.state.Plan is safe because the slice header is stable across the
// orchestrator's lifetime; concurrent writes to individual *pm.Task fields
// are tolerated (we only read .ID and .Status here).
func (o *Orchestrator) findTaskByID(id int) *pm.Task {
	if o == nil || o.state == nil || o.state.Plan == nil {
		return nil
	}
	for _, t := range o.state.Plan.Tasks {
		if t != nil && t.ID == id {
			return t
		}
	}
	return nil
}

// applyKillTargetStatus mutates task.Status based on the operator's chosen
// target. Unknown values fall through to TaskSkipped — preserving the user's
// intent ("stop running this") even when the chosen label is malformed.
func (o *Orchestrator) applyKillTargetStatus(task *pm.Task, target string) {
	switch target {
	case "pending":
		task.Status = pm.TaskPending
	case "in_progress":
		// Operator picked in_progress as target — they want the task to
		// resume. Leave the worker's terminal status in place; the
		// orchestrator's pending-task loop will pick it up on its next
		// iteration (status is already non-running).
		task.Status = pm.TaskPending
	case "done":
		task.Status = pm.TaskDone
	case "skipped":
		task.Status = pm.TaskSkipped
	case "failed":
		task.Status = pm.TaskFailed
	default:
		// Empty / unknown target: keep whatever the worker set. The cancel
		// already fired in phase 1, so the task is no longer running.
	}
}
