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
// # Staleness (Task 20203)
//
// A row survives whatever ends the run that would have consumed it: a crash, a
// stop, or simply the plan finishing before the drained worker's next tick. It
// also gets written when nothing is running at all, because an operator
// unsticking a task left in_progress by a dead run is, on disk, a transition
// out of in_progress. Replaying such a row against the next run is what made
// reset tasks die a second after starting, or land straight back in the
// terminal status the operator had just cleared.
//
// Two independent guards, because each covers a case the other cannot:
//
//   - The row names the attempt it was filed against (task.StartedAt at the
//     time). A row naming a different attempt refers to an execution that is
//     already over. This is what stops a row from cancelling the *fresh*
//     attempt of a task the operator reset.
//   - A row is only acted on once this process has seen that attempt running.
//     Resetting a task does not advance StartedAt, so a leftover row still
//     names a matching attempt — but a process that never started that task
//     has nothing to abort and no worker whose status it may overwrite. This
//     is what stops "skipped" from being re-applied to a task just reset to
//     pending.
//
// Either way the row is deleted, so a stale request is resolved on the first
// tick rather than lingering to fire again.
//
// The poller runs in a single goroutine bound to the run context; observedRuns
// is mutex-guarded only because tests drive processPendingKills directly.

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
// chosen target_status and clear the row. Rows that do not describe an
// execution this process is running are discarded — see the staleness notes
// at the top of the file.
func (o *Orchestrator) handleKillRequest(req state.KillRequest) {
	task := o.findTaskByID(req.TaskID)
	if task == nil {
		// Stale row for a task we don't know about (e.g. deleted, or merged
		// from a sibling project). Drop the row so the poller doesn't spin
		// on it forever.
		o.discardKillRequest(req, "task not in plan")
		return
	}

	// Guard 1: does the row still name the running attempt? A mismatch means
	// the execution the operator aborted has ended; anything running now is a
	// later attempt that they never asked to stop.
	if !attemptMatches(req.Attempt, task) {
		o.discardKillRequest(req, "request names a finished attempt")
		return
	}

	// Phase 1: worker still running — fire the cancel, leave the row in
	// place so phase 2 runs once the worker drains.
	if task.Status == pm.TaskInProgress {
		o.markKillObserved(req.TaskID, req.Attempt)
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
		// The observation above is what makes that phase 2 legitimate.
		return
	}

	// Guard 2: the task is not running and never ran here while this row was
	// pending, so there is no cancelled worker whose status we are correcting.
	// Applying target_status now would overwrite a status the operator set
	// deliberately — the reset-then-rerun case that made tasks reappear as
	// skipped.
	if !o.killObservedRunning(req.TaskID, req.Attempt) {
		o.discardKillRequest(req, "no execution of this attempt in this run")
		return
	}

	// Phase 2: worker has exited (status is terminal). Override with the
	// operator's chosen target_status, persist, and clear the row.
	o.applyKillTargetStatus(task, req.TargetStatus)
	if err := o.state.Save(); err != nil && o.log != nil {
		o.log.Warn(eventManualKill, req.TaskID,
			fmt.Sprintf("Task #%d: persist target status failed: %v", req.TaskID, err), nil)
	}
	o.forgetKillObserved(req.TaskID)
	if err := o.statedb.ClearKill(req.TaskID); err != nil && o.log != nil {
		o.log.Warn(eventManualKill, req.TaskID,
			fmt.Sprintf("Task #%d: clear kill row failed: %v", req.TaskID, err), nil)
	}
}

// discardKillRequest drops a row that does not describe a live execution,
// leaving the task untouched. Logged at info: an operator whose abort silently
// did nothing deserves a line saying why.
func (o *Orchestrator) discardKillRequest(req state.KillRequest, reason string) {
	if o.log != nil {
		o.log.Info(eventManualKill, req.TaskID,
			fmt.Sprintf("Task #%d: discarding stale kill request (%s)", req.TaskID, reason),
			map[string]interface{}{
				"task_id":       req.TaskID,
				"target_status": req.TargetStatus,
				"requested_by":  req.RequestedBy,
				"attempt":       req.Attempt,
				"reason":        reason,
			})
	}
	o.forgetKillObserved(req.TaskID)
	if err := o.statedb.ClearKill(req.TaskID); err != nil && o.log != nil {
		o.log.Warn(eventManualKill, req.TaskID,
			fmt.Sprintf("Task #%d: clear stale kill row failed: %v", req.TaskID, err), nil)
	}
}

// attemptMatches reports whether req's attempt token still names the task's
// current execution. An empty token names no execution: it comes from a row
// written before Task 20203 added the column, or from a task that had never
// been started, and in both cases there is nothing to match it against.
//
// Instants are compared rather than strings so a client that formats the
// timestamp differently still matches; the string compare is the fallback for
// tokens that do not parse.
func attemptMatches(attempt string, task *pm.Task) bool {
	if attempt == "" {
		return false
	}
	current := state.AttemptToken(task)
	if current == "" {
		return false
	}
	if current == attempt {
		return true
	}
	want, wantErr := time.Parse(time.RFC3339Nano, attempt)
	got, gotErr := time.Parse(time.RFC3339Nano, current)
	if wantErr != nil || gotErr != nil {
		return false
	}
	return want.Equal(got)
}

// markKillObserved records that this process has seen the named attempt of a
// task running while its kill row was pending, which is what makes a later
// phase 2 for that row legitimate.
func (o *Orchestrator) markKillObserved(taskID int, attempt string) {
	o.killMu.Lock()
	defer o.killMu.Unlock()
	if o.killObserved == nil {
		o.killObserved = make(map[int]string)
	}
	o.killObserved[taskID] = attempt
}

// killObservedRunning reports whether markKillObserved recorded this exact
// attempt. Matching on the attempt as well as the ID keeps an observation from
// one execution from authorising a status overwrite on the next.
func (o *Orchestrator) killObservedRunning(taskID int, attempt string) bool {
	o.killMu.Lock()
	defer o.killMu.Unlock()
	seen, ok := o.killObserved[taskID]
	return ok && seen == attempt
}

// forgetKillObserved drops the observation for taskID once its row is gone, so
// a later request for the same task starts from no assumptions.
func (o *Orchestrator) forgetKillObserved(taskID int) {
	o.killMu.Lock()
	defer o.killMu.Unlock()
	delete(o.killObserved, taskID)
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
