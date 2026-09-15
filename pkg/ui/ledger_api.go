package ui

// ledger_api.go exposes the two verdicts an operator can record against a task
// whose stored summary is a provider or harness refusal (Task 20224).
//
// The finding itself already rides to the browser on the task: pm.Task.Abort is
// part of the plan payload, so the list and the detail modal can render it
// without asking for anything extra. What was missing is a way to *act* on it.
// Before this, the only interface was `cloop task audit-ledger --reopen` on the
// CLI, which nobody ran — which is precisely why fourteen corrupted entries sat
// in this project's own plan for about a hundred iterations.
//
// There are exactly two honest answers to "this task is recorded as done but
// its whole summary is 'You've hit your limit'":
//
//   reopen — the work never happened. Reset to pending so it actually runs.
//   clear  — the work exists anyway, because a later task re-landed it. Record
//            who checked and what they found, and stop flagging it.
//
// Both are `task` permission rather than `read`: they change what the plan
// believes about itself, and clearing one is what allows a plan to be counted
// complete. Neither is `start`, since neither spends a provider call.

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// maxClearNoteBytes bounds the free-text justification. Generous enough for a
// sentence naming the task that re-landed the work, short enough that the field
// cannot be used to stuff the plan payload every client downloads.
const maxClearNoteBytes = 500

// ledgerTaskFromRequest resolves the {id} path value to a task that actually
// carries an abort record, so both handlers fail the same way on the same
// inputs.
func (s *Server) ledgerTaskFromRequest(w http.ResponseWriter, r *http.Request) (*state.ProjectState, *pm.Task, bool) {
	id, err := strconv.Atoi(r.PathValue("id"))
	if err != nil {
		jsonErr(w, "invalid task id", http.StatusBadRequest)
		return nil, nil, false
	}
	ps, err := state.Load(s.resolveWorkDir(r))
	if err != nil {
		jsonErr(w, err.Error(), statedb.HTTPStatus(err))
		return nil, nil, false
	}
	task, err := ps.RequireTask(id)
	if err != nil {
		jsonErr(w, err.Error(), statedb.HTTPStatus(err))
		return nil, nil, false
	}
	if task.Abort == nil {
		// Not an error in the plan's sense, but the caller is acting on a
		// finding that is not there — most likely a stale page whose task has
		// since been re-run. Saying so beats silently succeeding.
		jsonErr(w, fmt.Sprintf("task %d carries no aborted-outcome record", id), http.StatusConflict)
		return nil, nil, false
	}
	return ps, task, true
}

// handleTaskReopenAborted resets a task recorded as done on a refusal back to
// pending, so the work it was supposed to do actually runs.
func (s *Server) handleTaskReopenAborted(w http.ResponseWriter, r *http.Request) {
	if !requirePOST(w, r) {
		return
	}
	ps, task, ok := s.ledgerTaskFromRequest(w, r)
	if !ok {
		return
	}

	rec := task.Abort
	oldStatus := string(task.Status)
	task.Status = pm.TaskPending
	// A run that produced nothing has no completion instant and no elapsed
	// work; leaving these set would keep rendering the task as finished.
	task.CompletedAt = nil
	task.ActualMinutes = 0
	// A clearance and a reopen are opposite verdicts. Reopening one that was
	// previously cleared must retract the clearance, or the sweep would read
	// "checked, fine" off a task the operator just said had never run.
	rec.Cleared = false
	rec.ClearedBy = ""
	rec.ClearedNote = ""
	rec.ClearedAt = nil
	pm.AddAnnotation(task, "cloop", fmt.Sprintf(
		"Reopened from the dashboard: recorded done, but the stored summary is a %s (%s), not a description of work.",
		rec.Class, rec.Reason))

	if err := ps.SaveDirect(); err != nil {
		jsonErr(w, "save failed: "+err.Error(), statedb.HTTPStatus(err))
		return
	}

	workDir := s.resolveWorkDir(r)
	state.LogEventDetails(workDir, state.EventRow{
		Type:      state.EventTaskAborted,
		TaskID:    task.ID,
		TaskTitle: task.Title,
		Step:      state.NoStep,
		Message: fmt.Sprintf("Task #%d reopened via UI (%s): %s — recorded done but never ran",
			task.ID, rec.Class, rec.Reason),
	}, map[string]any{
		"abort_class": rec.Class,
		"reason":      rec.Reason,
		"evidence":    rec.Evidence,
		"old_status":  oldStatus,
		"source":      "ui",
	})
	// Reopening is a manual status flip like any other, and the one most worth
	// attributing: it overrides a recorded outcome (Task 20282).
	s.auditTaskStatus(r, workDir, task.ID, oldStatus, string(pm.TaskPending))
	s.broadcastStateDiff(workDir, ps)
	jsonOK(w, map[string]interface{}{"ok": true, "id": task.ID, "status": string(pm.TaskPending)})
}

// handleTaskClearAborted records that the work exists despite the refusal
// summary, so the finding stops blocking plan completion.
//
// The note is required. A clearance without a reason is indistinguishable from
// giving up on the audit, and this whole mechanism exists because the previous
// one had no way to say "checked, it is fine" and so got ignored instead.
func (s *Server) handleTaskClearAborted(w http.ResponseWriter, r *http.Request) {
	if !requirePOST(w, r) {
		return
	}
	var req struct {
		Note string `json:"note"`
	}
	limitJSONBody(w, r, maxJSONBodyBytes)
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondToBodyError(w, err)
		return
	}
	note := strings.TrimSpace(req.Note)
	if note == "" {
		jsonErr(w, "a note is required: say where the work actually landed", http.StatusBadRequest)
		return
	}
	if len(note) > maxClearNoteBytes {
		jsonErr(w, fmt.Sprintf("note is too long (%d bytes, max %d)", len(note), maxClearNoteBytes),
			http.StatusRequestEntityTooLarge)
		return
	}

	ps, task, ok := s.ledgerTaskFromRequest(w, r)
	if !ok {
		return
	}

	by := s.auditActor(r)
	task.Abort.Clear(by, note)
	pm.AddAnnotation(task, "cloop", fmt.Sprintf(
		"Aborted-outcome finding cleared by %s: %s", by, note))

	if err := ps.SaveDirect(); err != nil {
		jsonErr(w, "save failed: "+err.Error(), statedb.HTTPStatus(err))
		return
	}

	workDir := s.resolveWorkDir(r)
	state.LogEventDetails(workDir, state.EventRow{
		Type:      state.EventTaskStatusChange,
		TaskID:    task.ID,
		TaskTitle: task.Title,
		Step:      state.NoStep,
		Message: fmt.Sprintf("Task #%d aborted-outcome finding cleared by %s: %s",
			task.ID, by, note),
	}, map[string]any{
		"abort_class": task.Abort.Class,
		"cleared_by":  by,
		"note":        note,
		"source":      "ui",
	})
	s.broadcastStateDiff(workDir, ps)
	jsonOK(w, map[string]interface{}{"ok": true, "id": task.ID, "cleared": true, "cleared_by": by})
}
