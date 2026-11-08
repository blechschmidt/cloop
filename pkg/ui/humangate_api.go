package ui

// Human review gates in the task list (Task 20477):
//
//	POST /api/tasks/gate           add a gate at a position in the run queue
//	POST /api/tasks/{id}/approve   approve a gate, or pre-approve a task
//
// A gate is a task (see pkg/pm/humangate.go), so everything else about one —
// listing it, dragging it, editing its title or note, removing it — goes
// through the ordinary task routes. The status routes are gate-aware: a gate
// is pending (closed), done (approved) or skipped (bypassed), so "done" on a
// gate is its approval and "pending" closes it again.

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// Bounds on what a gate carries. A gate's title is a row in the task list and
// its note is what the reviewer is asked to look at; neither is a document.
const (
	maxGateTitleRunes = 200
	maxGateNoteRunes  = 4000
)

// handleTaskGateCreate adds a human review gate (POST /api/tasks/gate).
//
// Body: {"title": "", "description": "", "after": 0, "before": 0}. Every field
// is optional: an untitled gate is called "Human review", and with no position
// it goes to the end of the run queue — the run then stops once everything
// already queued has finished. "after" puts it right after a task (at the head
// of the queue when that task has already run), "before" right before a task
// still in the queue.
func (s *Server) handleTaskGateCreate(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Title       string `json:"title"`
		Description string `json:"description"`
		After       int    `json:"after"`
		Before      int    `json:"before"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	req.Title = strings.TrimSpace(req.Title)
	req.Description = strings.TrimSpace(req.Description)
	switch {
	case utf8.RuneCountInString(req.Title) > maxGateTitleRunes:
		jsonErr(w, fmt.Sprintf("title is longer than %d characters", maxGateTitleRunes), http.StatusBadRequest)
		return
	case utf8.RuneCountInString(req.Description) > maxGateNoteRunes:
		jsonErr(w, fmt.Sprintf("description is longer than %d characters", maxGateNoteRunes), http.StatusBadRequest)
		return
	case req.After < 0 || req.Before < 0:
		jsonErr(w, "after and before are task ids", http.StatusBadRequest)
		return
	}

	workDir := s.resolveWorkDir(r)
	// LoadLite, as handleTaskAdd: placing a gate needs the plan, not its steps.
	ps, err := state.LoadLite(workDir)
	if err != nil {
		jsonErr(w, err.Error(), statedb.HTTPStatus(err))
		return
	}
	if ps.Plan == nil {
		ps.Plan = pm.NewPlan(ps.Goal)
		ps.PMMode = true
	}
	gate := pm.NewHumanGate(req.Title, req.Description)
	gate.ID = ps.Plan.NextTaskID()
	if err := ps.Plan.InsertInQueue(gate, req.After, req.Before); err != nil {
		code := http.StatusBadRequest
		if errors.Is(err, pm.ErrNotQueued) {
			code = http.StatusConflict
		}
		jsonErr(w, err.Error(), code)
		return
	}
	if err := ps.SaveDirect(); err != nil {
		jsonErr(w, "save failed: "+err.Error(), statedb.HTTPStatus(err))
		return
	}

	s.broadcastStateDiff(workDir, ps)
	raw, _ := json.Marshal(map[string]interface{}{"task": gate})
	s.broadcastToProject(workDir, wsMessage{Type: "task_added", Data: raw})
	state.LogEvent(workDir, state.EventRow{
		Type:      state.EventTaskAdded,
		TaskID:    gate.ID,
		TaskTitle: gate.Title,
		Step:      state.NoStep,
		Message:   fmt.Sprintf("Review gate #%d added via UI: %s", gate.ID, gate.Title),
	})
	jsonOK(w, map[string]interface{}{"ok": true, "id": gate.ID, "task": gate})
}

// handleTaskApprove approves a human review gate, or pre-approves a task that
// requires approval (POST /api/tasks/{id}/approve).
//
// Approving a gate opens it: the gate is recorded as passed and the tasks it
// held may run. The run that stopped at it does not restart here — starting a
// run is a separate permission (`start`), and the dashboard's "Approve &
// continue" makes that second call itself. An approval made while a run is
// going reaches it through its next sync: Approved is a definition field, so
// the run's own saves keep it.
func (s *Server) handleTaskApprove(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.Atoi(r.PathValue("id"))
	if err != nil || id <= 0 {
		jsonErr(w, "invalid task id", http.StatusBadRequest)
		return
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(r.Body, 1<<16))

	workDir := s.resolveWorkDir(r)
	ps, err := state.Load(workDir)
	if err != nil {
		jsonErr(w, err.Error(), statedb.HTTPStatus(err))
		return
	}
	task, err := ps.RequireTask(id)
	if err != nil {
		jsonErr(w, err.Error(), statedb.HTTPStatus(err))
		return
	}
	if task.IsWork() && task.Approved {
		jsonOK(w, map[string]interface{}{"ok": true, "id": id, "already": true})
		return
	}
	if !task.IsWork() && !task.GateClosed() {
		jsonOK(w, map[string]interface{}{"ok": true, "id": id, "already": true, "kind": string(task.Kind)})
		return
	}
	waiting := s.approveTask(r, workDir, ps, task)
	if err := ps.SaveDirect(); err != nil {
		jsonErr(w, "save failed: "+err.Error(), statedb.HTTPStatus(err))
		return
	}
	s.recordApproval(r, workDir, task, waiting, "dashboard")
	s.broadcastStateDiff(workDir, ps)
	jsonOK(w, map[string]interface{}{"ok": true, "id": id, "kind": string(task.Kind), "waiting": waiting})
}

// approveTask applies an approval to task in ps, in memory, and reports
// whether a run had stopped at it. A gate is opened and recorded as passed; a
// task that requires approval is pre-approved, so the run's approval gate lets
// it through.
func (s *Server) approveTask(r *http.Request, workDir string, ps *state.ProjectState, task *pm.Task) bool {
	waiting := ps.Status == "paused" && ps.PauseReason != nil && ps.PauseReason.TaskID == task.ID
	if task.IsWork() {
		task.Approved = true
		return waiting
	}
	pm.ApproveGate(task, s.auditActor(r), time.Now())
	return waiting
}

// recordApproval writes an approval's audit row and journal entry, once it is
// saved. Best-effort, like every other emitter: the approval stands either way.
func (s *Server) recordApproval(r *http.Request, workDir string, task *pm.Task, waiting bool, via string) {
	if db, err := statedb.Open(state.DBPath(workDir)); err == nil {
		statedb.AuditTaskGateApprove(db, task, waiting, s.auditActor(r), via)
		db.Close()
	}
	what := "Task"
	if !task.IsWork() {
		what = "Review gate"
	}
	state.LogEventDetails(workDir, state.EventRow{
		Type:      state.EventReviewGate,
		TaskID:    task.ID,
		TaskTitle: task.Title,
		Step:      state.NoStep,
		Message:   fmt.Sprintf("%s #%d approved by %s: %s", what, task.ID, s.auditActor(r), task.Title),
	}, map[string]any{"action": "approved", "by": s.auditActor(r), "waiting": waiting, "kind": string(task.Kind)})
}

// gateStatusChange applies a hand-made status change to a gate, as
// pm.SetStatusByHand does: "done" is its approval, "pending" closes it again,
// "skipped" bypasses it. It reports false after answering 400 for a status no
// gate takes. approved says the change was an approval, which the caller
// records once it is saved; waiting, that a run had stopped at the gate.
func (s *Server) gateStatusChange(w http.ResponseWriter, r *http.Request, ps *state.ProjectState,
	task *pm.Task, to pm.TaskStatus) (ok, approved, waiting bool) {
	waiting = ps.Status == "paused" && ps.PauseReason != nil && ps.PauseReason.TaskID == task.ID
	approved, err := pm.SetStatusByHand(task, to, s.auditActor(r), time.Now())
	if err != nil {
		jsonErr(w, err.Error(), http.StatusBadRequest)
		return false, false, false
	}
	return true, approved, waiting && approved
}

// refuseIfGate answers 409 for an action that needs work to act on, when the
// task is a human review gate, and reports whether it did.
func refuseIfGate(w http.ResponseWriter, task *pm.Task, action string) bool {
	if task == nil || task.IsWork() {
		return false
	}
	jsonErr(w, fmt.Sprintf("task %d is a human review gate, which holds no work to %s", task.ID, action), http.StatusConflict)
	return true
}

// refuseRunAtGate answers 409 when the project's run would stop at a review
// gate before doing anything (Task 20477): the gate is closed and no work
// ahead of it is left to run. Starting a run there would only dispatch a
// harness — on a remote executor, a whole sandbox — to pause again at once.
// It reports whether it answered.
func refuseRunAtGate(w http.ResponseWriter, workDir string) bool {
	ps, err := state.LoadLite(workDir)
	if err != nil || ps == nil || ps.Plan == nil {
		return false
	}
	g := ps.Plan.WaitingGate()
	if g == nil {
		return false
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusConflict)
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"error": fmt.Sprintf("the run is waiting at review gate #%d (%s): every task ahead of it has finished. "+
			"Approve the gate to continue, or put tasks ahead of it first", g.ID, g.Title),
		"waiting_gate": g.ID,
	})
	return true
}
