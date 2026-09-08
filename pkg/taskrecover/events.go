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
	switch oc.Action {
	case ActionAdopted:
		state.LogEvent(workDir, state.EventRow{
			Timestamp: oc.CompletedAt,
			Type:      adoptedEventType(oc.Status),
			TaskID:    oc.TaskID,
			TaskTitle: oc.Title,
			Step:      state.NoStep,
			Message: fmt.Sprintf(
				"Task #%d recovered as %s: the agent had finished and reported it, but the run process "+
					"died before the outcome was persisted. Adopted from the live artifact instead of re-running.",
				oc.TaskID, oc.Status),
		})
	case ActionRequeued:
		state.LogEvent(workDir, state.EventRow{
			Type:      state.EventTaskStatusChange,
			TaskID:    oc.TaskID,
			TaskTitle: oc.Title,
			Step:      state.NoStep,
			Message: fmt.Sprintf("Task #%d reset to pending after an interrupted run: %s.",
				oc.TaskID, oc.Reason),
		})
	}
}

// adoptedEventType maps an adopted status onto the event the live path would
// have recorded for it.
func adoptedEventType(status pm.TaskStatus) state.EventType {
	switch status {
	case pm.TaskDone:
		return state.EventTaskDone
	case pm.TaskFailed:
		return state.EventTaskFailed
	default:
		return state.EventTaskSkipped
	}
}
