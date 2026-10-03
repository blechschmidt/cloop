package taskrecover

// events.go records reconciliation in the project's event journal.
//
// It lives apart from taskrecover.go so that Reconcile stays a pure function
// over a plan and a directory: the decision logic is testable with nothing but
// a temp dir, while the persistence that has to import pkg/state is confined
// here. Both callers — the orchestrator before it schedules, and the hub when
// it notices a run has died — funnel through this so a recovered task reads the
// same way in the timeline no matter who noticed.

import (
	"fmt"

	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/state"
)

// LogOutcome appends one reconciliation to the project's event journal.
//
// An adopted task is recorded as its real outcome — task_done, task_failed,
// task_skipped — rather than as some recovery-specific event type, because
// that is what it is: the completion the dying run failed to write. Recording
// it as anything else would leave the timeline showing a task that never
// finished. The message carries the provenance so nobody reads it as work this
// run performed, and the timestamp is when the agent actually stopped, not when
// we got around to noticing.
//
// Best-effort, like every other event write: observability must never be the
// reason a repair fails.
func LogOutcome(workDir string, oc Outcome) {
	if workDir == "" {
		return
	}
	row, details, ok := EventFor(oc)
	if !ok {
		return
	}
	if details == nil {
		state.LogEvent(workDir, row)
		return
	}
	state.LogEventDetails(workDir, row, details)
}

// EventFor renders one reconciliation as the journal row LogOutcome writes,
// with its structured details — nil when the recovery followed the agent's
// report rather than a verdict. ok is false for an outcome that is not
// journalled. A remote device uses it to send the row back with the run's own
// (pkg/executor/projectseed), so a recovery reads the same on the hub whether
// it happened there or on the device.
func EventFor(oc Outcome) (row state.EventRow, details map[string]any, ok bool) {
	if oc.Verdict != nil {
		details = map[string]any{
			"recovered_from": "verdict",
			"verdict_status": string(oc.Verdict.Status),
			"verdict_source": oc.Verdict.Source,
			"verdict_reason": oc.Verdict.Reason,
		}
	}
	switch oc.Action {
	case ActionAdopted:
		msg := fmt.Sprintf(
			"Task #%d recovered as %s: the agent had finished and reported it, but the run process "+
				"died before the outcome was persisted. Adopted from the live artifact instead of re-running.",
			oc.TaskID, oc.Status)
		if oc.Verdict != nil {
			// The orchestrator's decision, not the agent's report (Task
			// 20365). Saying which matters most when they differ: a task the
			// review gate rejected reads as failed here, and the agent's
			// TASK_DONE is not what the timeline claims.
			msg = fmt.Sprintf(
				"Task #%d recovered as %s: cloop had decided it (%s), but the run ended before the "+
					"outcome was persisted. Its decision was applied instead of re-running the task.",
				oc.TaskID, oc.Status, oc.Verdict.Describe())
		}
		return state.EventRow{
			Timestamp: oc.CompletedAt,
			Type:      adoptedEventType(oc.Status),
			TaskID:    oc.TaskID,
			TaskTitle: oc.Title,
			Step:      state.NoStep,
			Message:   msg,
		}, details, true
	case ActionRequeued:
		return state.EventRow{
			Type:      state.EventTaskStatusChange,
			TaskID:    oc.TaskID,
			TaskTitle: oc.Title,
			Step:      state.NoStep,
			Message: fmt.Sprintf("Task #%d reset to pending after an interrupted run: %s.",
				oc.TaskID, oc.Reason),
		}, details, true
	}
	return state.EventRow{}, nil, false
}

// adoptedEventType maps an adopted status onto the event the live path would
// have recorded for it.
func adoptedEventType(status pm.TaskStatus) state.EventType {
	switch status {
	case pm.TaskDone:
		return state.EventTaskDone
	case pm.TaskFailed, pm.TaskTimedOut:
		return state.EventTaskFailed
	default:
		return state.EventTaskSkipped
	}
}
