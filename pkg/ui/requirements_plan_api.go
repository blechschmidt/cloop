package ui

// requirements_plan_api.go: planning from the requirements (Task 20463).
//
//	POST /api/requirements/plan   the model plans the tasks that close the open requirement gaps
//
// The Requirements tab's "Plan from requirements" starts a suggest job (see
// suggest_api.go) whose dispatch is `cloop requirements plan --json` on the
// project's executor, with the caller's Claude account and the hub's
// requirement status summary as an argument — a device's or a Pod's copy of
// the project holds no checks, and what the plan is made against is what the
// hub decided. The plan is reviewed where every plan is, in the Tasks tab's
// suggestions panel, and its tasks added one at a time or all at once; each
// links the requirements it closes, so its agent is held to them.
//
// What comes back is held to the summary the hub sent, whatever cloop the
// executor runs (suggest.ApplyRequirements, in finishSuggest): links only to
// requirements with an open gap, the kind each link makes the task, the must
// gaps first, a task for every must gap the model left open.
//
// The same summary goes with every brainstorm, plan and plan-assistant
// question the dashboard dispatches (requirementsStatusArgs), and into every
// seed (workspace.go) for the auto-evolve of a run on a device.

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/requirements"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
	"github.com/blechschmidt/cloop/pkg/suggest"
)

// requirementsPlanCallTimeout is the model's time on a plan from the
// requirements; the job's dispatch adds the workload's start
// (suggestSubprocessTimeout bounds both).
const requirementsPlanCallTimeout = 5 * time.Minute

// requirementStatusFor is where the approved requirements of the project at
// workDir stand against its plan: the requirement status summary every
// planner is given. A project with none has an empty one, and so does a
// directory with no project — whose database this does not create.
func requirementStatusFor(workDir string) (requirements.StatusSummary, error) {
	ps, err := state.LoadLite(workDir)
	if errors.Is(err, statedb.ErrProjectNotFound) {
		return requirements.StatusSummary{}, nil
	}
	if err != nil {
		return requirements.StatusSummary{}, err
	}
	return requirementStatusOf(workDir, ps.Plan)
}

// requirementStatusOf is requirementStatusFor against a plan the caller
// already holds.
func requirementStatusOf(workDir string, plan *pm.Plan) (requirements.StatusSummary, error) {
	db, err := statedb.Open(state.DBPath(workDir))
	if err != nil {
		return requirements.StatusSummary{}, err
	}
	defer db.Close()
	facts, omitted, err := db.AsProject().RequirementFacts()
	if err != nil {
		return requirements.StatusSummary{}, err
	}
	sum := requirements.Summarize(facts, pm.TaskViews(plan))
	sum.Omitted = omitted
	return sum, nil
}

// requirementsStatusArgs is the argument that hands sum to a planner
// subcommand, or none for a project without approved requirements — whose
// planners run as they did before, on a device's cloop of any age. A cloop
// that predates the argument refuses it (refusedStatusArg), and is asked
// again without it.
func requirementsStatusArgs(sum requirements.StatusSummary) []string {
	if sum.Empty() {
		return nil
	}
	raw, err := sum.Encode()
	if err != nil {
		fmt.Fprintf(os.Stderr, "ui: the requirement status could not be encoded, planning goes without it: %v\n", err)
		return nil
	}
	// Joined to its flag, like every argument that carries text.
	return []string{"--requirements=" + string(raw)}
}

// refusedStatusArg reports whether a planner subcommand's output says the
// cloop that ran it does not know the requirement status argument: one older
// than this hub, a device's own binary. The hub holds the result to the
// requirements itself, so planning without it loses only what the model was
// shown.
func refusedStatusArg(out []byte, args []string) bool {
	return len(args) > 0 && strings.HasPrefix(args[len(args)-1], "--requirements=") &&
		bytes.Contains(out, []byte("unknown flag: --requirements"))
}

// keepCurrentLinks drops from tasks about to be added the links to
// requirements that are no longer approved — deleted, deprecated or made a
// draft again since the plan was made: a plan links only approved ones. A
// database that cannot be read leaves the links the hub checked when the plan
// arrived.
func keepCurrentLinks(workDir string, tasks []*pm.Task) {
	linked := false
	for _, t := range tasks {
		linked = linked || len(t.Requirements) > 0
	}
	if !linked {
		return
	}
	db, err := statedb.Open(state.DBPath(workDir))
	if err != nil {
		return
	}
	defer db.Close()
	reqs, err := db.AsProject().Requirements()
	if err != nil {
		return
	}
	live := map[int]bool{}
	for _, r := range reqs {
		live[r.ID] = r.CurrentStatus() == requirements.StatusApproved
	}
	for _, t := range tasks {
		t.Requirements = slices.DeleteFunc(t.Requirements, func(id int) bool { return !live[id] })
		if len(t.Requirements) == 0 {
			t.Requirements = nil
		}
	}
}

// handleRequirementsPlan answers POST /api/requirements/plan {count}: the
// model plans, on the project's executor, the tasks that close the open gaps
// of its approved requirements. The plan is a suggest job, reviewed in the
// suggestions panel; the answer says whether one started, and when nothing
// has a gap a task closes, why.
func (s *Server) handleRequirementsPlan(w http.ResponseWriter, r *http.Request) {
	workDir := s.resolveWorkDir(r)
	// A job lives in the memory of the hub member that ran it, and the
	// panel's status and adds must reach the same member (Task 20354).
	if s.routeProjectAffinity(w, r, ownerSuggest, workDir) {
		return
	}
	var in struct {
		Count int `json:"count"`
	}
	if !decodeOptionalJSON(w, r, &in) {
		return
	}
	if in.Count < 0 || in.Count > suggest.MaxCount {
		jsonErr(w, fmt.Sprintf("count is between 1 and %d", suggest.MaxCount), http.StatusBadRequest)
		return
	}
	sum, err := requirementStatusFor(workDir)
	if err != nil {
		jsonErr(w, err.Error(), statedb.HTTPStatus(err))
		return
	}
	targets := sum.Targets()
	if len(targets) == 0 {
		jsonOK(w, map[string]any{"ok": true, "started": false, "message": requirements.NothingToPlan(sum)})
		return
	}

	// The plan spends the caller's account where the project runs: a
	// sandbox with no credential of theirs is refused now, with the 409 the
	// dashboard opens the credential dialog on, not minutes later.
	planClear := s.harnessClearanceFor(r, workDir)
	if s.refuseWithoutHarnessCredential(w, planClear) {
		return
	}
	job := &suggestJob{count: in.Count, request: suggest.RequirementsRequest, reqs: sum, purpose: suggest.ForGaps}
	if !s.beginSuggestJob(w, workDir, job) {
		return
	}
	args := []string{"requirements", "plan", "--json", "--timeout", requirementsPlanCallTimeout.String()}
	if in.Count > 0 {
		args = append(args, "--count", strconv.Itoa(in.Count))
	}
	args = append(args, requirementsStatusArgs(sum)...)
	exe := s.selfExe()
	// Resolved here: r must not outlive this handler.
	claudeEnv := s.claudeEnvResolver(r)
	go func() {
		defer s.recoverSuggest(workDir, job)
		out, runErr := runCloopSubcommandFor(context.Background(), exe, workDir, suggestSubprocessTimeout, claudeEnv, planClear, args...)
		s.readSuggestResult(workDir, job, out, runErr)
	}()
	jsonOK(w, map[string]any{"ok": true, "started": true, "gen": job.gen, "targets": len(targets), "must": len(sum.MustGaps())})
}
