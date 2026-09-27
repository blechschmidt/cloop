package statedb

import (
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/pm"
)

// TestTaskFinishNamesWhyAnExecutionWasReturnedToPending: when the orchestrator
// takes an execution back — the run was stopped under it, or the provider
// aborted it — the terminal row gives the reason it wrote on the task, not
// just "returned to pending" (Task 20348). A pending reset that left no such
// note keeps the generic reason: a note from an earlier stage of the task is
// not an explanation of this reset.
func TestTaskFinishNamesWhyAnExecutionWasReturnedToPending(t *testing.T) {
	const interrupted = "Interrupted while the agent was working on it: the run stopped before the task finished. " +
		"Returned to pending, so the next run starts it again."

	for _, tc := range []struct {
		name string
		note *pm.Annotation
		want string
	}{
		{"interrupted by a stop", &pm.Annotation{Author: "cloop", Text: interrupted}, interrupted},
		{"reset with no note of its own", nil, "returned to pending without a recorded outcome"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db := newAuditDB(t)
			started := time.Now().UTC().Add(-time.Minute)
			task := &pm.Task{ID: 7, Title: "Build the widget", Status: pm.TaskInProgress, StartedAt: &started,
				Annotations: []pm.Annotation{{Author: "ai", Text: "Task started on executor local"}}}
			st := &State{Goal: "g", WorkDir: t.TempDir(), Plan: &pm.Plan{Tasks: []*pm.Task{task}}}
			if err := db.SaveState(st); err != nil {
				t.Fatalf("save in_progress: %v", err)
			}

			task.Status = pm.TaskPending
			if tc.note != nil {
				task.Annotations = append(task.Annotations, *tc.note)
			}
			if err := db.SaveState(st); err != nil {
				t.Fatalf("save pending: %v", err)
			}

			rows, _, err := db.ListAuditEvents(AuditFilter{EntityType: "task", EntityID: "7", EventType: "task.finish"})
			if err != nil {
				t.Fatalf("list: %v", err)
			}
			if len(rows) != 1 {
				t.Fatalf("got %d task.finish rows, want 1", len(rows))
			}
			p := decodeAuditPayload(rows[0].Payload)
			if got := payloadString(p, "outcome"); got != string(pm.TaskPending) {
				t.Errorf("outcome = %q, want pending", got)
			}
			if got := payloadString(p, "reason"); got != tc.want {
				t.Errorf("reason = %q, want %q", got, tc.want)
			}
		})
	}
}
