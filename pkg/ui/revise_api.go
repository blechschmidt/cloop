package ui

// Revising a task's details from a spoken instruction (Task 20302).
//
// The Dictate button in the edit modal has to answer a question the one beside
// the Add Task field never does: the field it is speaking into already has
// words in it. Overwriting them is sometimes exactly right ("scrap that — this
// task is really about the migration") and sometimes destructive ("...and make
// sure it works on mobile"), and nothing in the audio distinguishes the two. So
// the front end asks, and this endpoint serves the answer the user cannot give
// themselves in the two seconds they have: treat what was said as an
// instruction, and apply it to the text that is already there.
//
// Replacing and appending happen entirely in the browser. Only this one costs a
// provider call, which is why it is a route of its own rather than a flag on
// /api/transcribe — a button that sometimes spends the project's budget and
// sometimes does not should not be one endpoint.
//
// # It proposes, it does not save
//
// The revised text lands in the textarea the editor is already looking at, and
// nothing reaches the plan until they press Save Changes. That is the whole
// safety argument for letting a model rewrite someone's task description: a
// misheard instruction is a visible paragraph they can undo with Cancel, not a
// silent edit. This handler accordingly writes nothing — it loads the task only
// to confirm it exists and to give the model its title as context.
//
// # Why the draft comes from the client
//
// The description sent up is the one in the open textarea, which is deliberately
// *not* re-read from the plan. The user may have typed into it since the modal
// opened, and revising the stored copy would throw those edits away — the exact
// destruction this whole dialog exists to avoid.

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// reviseTimeout bounds the model call. Someone is holding an open modal
// waiting for this, so it is far shorter than the decomposition preview's:
// past this the answer is no longer useful even if it arrives, and the dialog
// still offers Replace and Append, which cost nothing. The bounds on what is
// sent and accepted, and the prompt, are pm's (pm/revise.go), shared with
// `cloop task revise`, which makes the call (Task 20442).
const reviseTimeout = 90 * time.Second

// reviseRequest is the open editor's state, not the stored task.
type reviseRequest struct {
	// Instruction is what the user said.
	Instruction string `json:"instruction"`

	// Description is the draft currently in the textarea.
	Description string `json:"description"`

	// Title is context only; the model is told not to rewrite it.
	Title string `json:"title"`
}

// handleTaskRevise applies a spoken instruction to a task's description and
// returns the result for review (POST /api/tasks/{id}/revise). It does not
// mutate the plan.
func (s *Server) handleTaskRevise(w http.ResponseWriter, r *http.Request) {
	// Dispatched like a run, so it goes where a run would (Task 20354).
	if s.routeDispatch(w, r, s.resolveWorkDir(r)) {
		return
	}
	id, err := strconv.Atoi(r.PathValue("id"))
	if err != nil || id <= 0 {
		jsonErr(w, "invalid task id", http.StatusBadRequest)
		return
	}

	var req reviseRequest
	if !decodeJSON(w, r, &req) {
		return
	}

	instruction := truncateRunes(strings.TrimSpace(req.Instruction), pm.MaxReviseInstructionRunes)
	if instruction == "" {
		jsonErr(w, "nothing was said to apply", http.StatusBadRequest)
		return
	}
	current := truncateRunes(strings.TrimSpace(req.Description), pm.MaxReviseDescriptionRunes)
	if current == "" {
		// The dialog only offers this option when there is something to revise,
		// so an empty draft means the client and the plan have diverged. Say so
		// rather than spending a provider call to have a model invent a
		// description from an instruction that assumes one.
		jsonErr(w, "this task has no details to revise — use Replace instead", http.StatusBadRequest)
		return
	}

	workDir := s.resolveWorkDir(r)
	ps, err := state.Load(workDir)
	if err != nil {
		jsonErr(w, err.Error(), statedb.HTTPStatus(err))
		return
	}
	if ps.Plan == nil || len(ps.Plan.Tasks) == 0 {
		jsonErr(w, "no task plan found — run cloop init first", http.StatusNotFound)
		return
	}
	task, err := ps.RequireTask(id)
	if err != nil {
		jsonErr(w, err.Error(), statedb.HTTPStatus(err))
		return
	}

	// The stored title is the fallback, not the override: an editor who has
	// retitled the task but not yet saved is describing the task they mean, and
	// the model should read that one.
	title := truncateRunes(strings.TrimSpace(req.Title), pm.MaxReviseInstructionRunes)
	if title == "" {
		title = task.Title
	}

	// The model call is `cloop task revise` on the project's executor, with the
	// caller's Claude account (Task 20442; see model_calls.go). The draft and
	// the instruction travel joined to their flags, so text that starts with
	// "-" is never read as a flag of its own.
	clear := s.harnessClearanceFor(r, workDir)
	if s.refuseWithoutHarnessCredential(w, clear) {
		return
	}
	out, err := runCloopSubcommandFor(r.Context(), s.selfExe(), workDir, reviseDispatchTimeout,
		s.claudeEnvResolver(r), clear, "task", "revise", strconv.Itoa(id),
		"--instruction="+instruction, "--description="+current, "--title="+title,
		"--timeout", reviseTimeout.String(), "--json")
	var res struct {
		Description string `json:"description"`
		Provider    string `json:"provider"`
		Model       string `json:"model"`
	}
	// 502, not 500, when the model fails: the hub is fine, the model it
	// depends on is not — and the dialog's other two options still work, which
	// is what the client tells the user when it sees this.
	if !readModelCall(w, out, err, "revising the details failed: ", &res) {
		return
	}
	// Cleaned again here: the answer came from whatever cloop the executor
	// runs, and an empty one must not blank the editor's description.
	revised := pm.CleanRevisedDescription(res.Description)
	if revised == "" {
		jsonErr(w, "the model returned nothing to apply", http.StatusBadGateway)
		return
	}

	jsonOK(w, map[string]interface{}{
		"ok":          true,
		"description": revised,
		"provider":    res.Provider,
		"model":       res.Model,
	})
}

// truncateRunes caps s at n runes, never splitting one (pm.TruncateRunes).
func truncateRunes(s string, n int) string { return pm.TruncateRunes(s, n) }
