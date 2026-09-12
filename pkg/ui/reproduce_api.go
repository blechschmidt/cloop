package ui

// The reproduction panel's backend (Task 20221).
//
// Four routes, sitting next to the provenance view in the task detail modal:
//
//	GET  /api/tasks/{id}/provenance     the reconstructed input state
//	GET  /api/tasks/{id}/reproductions  past verdicts for this task
//	POST /api/tasks/{id}/reproduce      run one now
//	GET  /api/reproductions/{id}        one verdict, diff-of-diffs included
//
// # Permissions
//
// The three reads require authz.PermProjectRead: a verdict is a statement
// about code the caller can already see, and an auditor who can read the
// project but not change it is exactly who this feature is for.
//
// The POST requires authz.PermRunStart. No new permission was minted for it,
// deliberately. A separate `task.reproduce` would be granted to exactly the
// roles that already hold run.start — roles are a fixed ladder here, not a
// custom mapping — so it would add a name without adding a distinction the
// system can express, and every such name is one more thing an operator
// auditing their RBAC config has to reason about. The authorization question a
// reproduction actually poses is "may this caller cause the fleet to execute a
// model and a test suite?", and that is the question run.start answers.
//
// # Why the POST is synchronous
//
// Every other dispatching endpoint here starts a workload and returns; this one
// blocks until the verdict exists. A reproduction has no partial state worth
// streaming — the transcript is the *reproduction's* agent talking, not the
// project's, and showing it in the run log would put a second agent's output in
// the project's event history where it would be read as real work. What the
// caller wants is one of four words, so the request is the unit.
//
// The quota gate is what makes that safe to expose: a reproduction is admitted
// against quota.ResConcurrentReproductions, a gauge of its own, so a browser
// tab held open on a slow reproduction cannot consume the run concurrency a
// tenant's real work needs. The slot is released in a defer, exactly once, on
// every path out.
//
// # Host git, and why these two routes are gated
//
// The agent never runs on the host — that is the whole point, and
// reproduce_runner.go refuses any executor that would allow it. But two things
// here do run on the control plane: reconstructing the prompt calls
// pm.ExecuteTaskPrompt, whose context collection shells out to `git diff`, and
// resolving and comparing commits runs read-only plumbing (rev-parse,
// merge-base, rev-list, diff) plus a fetch into a scratch directory.
//
// All of it is read-only with respect to the project, and none of it is a
// harness. It is still host execution, so it is gated exactly like every other
// such path: denyHostSideEffect refuses both routes under strict
// no-host-execution mode, and tests/security/callgraph_test.go holds them in
// gatedHostExecution with that reason. The consequence is worth stating plainly
// — on a hub configured for strict isolation, reproduction is unavailable from
// the browser, and `cloop task reproduce` on the hub host is the way to get a
// verdict. Moving the comparison into a sandbox of its own would lift that, and
// is the obvious next step for this subsystem.

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/blechschmidt/cloop/pkg/apierror"
	"github.com/blechschmidt/cloop/pkg/logger"
	"github.com/blechschmidt/cloop/pkg/quota"
	"github.com/blechschmidt/cloop/pkg/statedb"
	"github.com/blechschmidt/cloop/pkg/taskreplay"
)

// maxReproductionsListed bounds the history a list response carries.
const maxReproductionsListed = 50

// reproduceHTTPTimeout bounds a reproduction started from the browser.
//
// Shorter than taskreplay.DefaultReproduceTimeout because this one holds an
// HTTP request open, and a reverse proxy in front of the hub will give up long
// before 45 minutes. An operator who needs longer has `cloop task reproduce
// --timeout`, which answers to no proxy.
const reproduceHTTPTimeout = 20 * time.Minute

// handleTaskProvenance returns the reconstructed input state for a task.
//
// GET /api/tasks/{id}/provenance
//
// It is the cheap half of this feature and worth having on its own: it answers
// "could this be reproduced, and how much would the answer be worth?" without
// spending anything. The UI calls it when the modal opens so the Reproduce
// button can explain itself before it is pressed.
func (s *Server) handleTaskProvenance(w http.ResponseWriter, r *http.Request) {
	id, ok := reproTaskID(w, r)
	if !ok {
		return
	}
	workDir := s.resolveWorkDir(r)
	// Reconstructing the prompt collects repository context, which shells out
	// to git in the project directory. See the host-git note above.
	if denyHostSideEffect(w, workDir, "git (task provenance reconstruction)") {
		return
	}

	prov, err := taskreplay.ReadProvenance(workDir, id)
	if err != nil && !errors.Is(err, taskreplay.ErrNoRecordedCommit) {
		jsonErr(w, err.Error(), statedb.HTTPStatus(err))
		return
	}
	// ErrNoRecordedCommit is the ordinary answer for a task that ran on the
	// host, not a failure: ReadProvenance still returns everything it did
	// recover, and the UI needs that to say *why* the button is disabled.
	jsonOK(w, map[string]interface{}{
		"ok":           true,
		"provenance":   prov,
		"reproducible": prov != nil && prov.Reproducible(),
		"reason":       reproducibilityReason(prov, err),
	})
}

// reproducibilityReason explains in one sentence whether a task can be
// reproduced, for a button tooltip.
func reproducibilityReason(prov *taskreplay.Provenance, err error) string {
	switch {
	case errors.Is(err, taskreplay.ErrNoRecordedCommit):
		return "this task has no recorded write-back commit — it ran on the host, so its changes went " +
			"straight into the working tree and there is no commit of its own to reproduce against"
	case err != nil:
		return err.Error()
	case prov == nil:
		return "no provenance could be reconstructed for this task"
	case !prov.Reproducible():
		return "the commit this task was based on could not be determined"
	case prov.Sandbox.PinnedImage != "" && !prov.PinnedImage():
		return "reproducible, but the original ran from a floating image tag, so a difference may be the " +
			"image moving rather than the agent"
	}
	return "reproducible"
}

// handleTaskReproductions lists past verdicts for one task.
//
// GET /api/tasks/{id}/reproductions
func (s *Server) handleTaskReproductions(w http.ResponseWriter, r *http.Request) {
	id, ok := reproTaskID(w, r)
	if !ok {
		return
	}
	runs, err := taskreplay.ListReproductions(s.resolveWorkDir(r), id, maxReproductionsListed)
	if err != nil {
		jsonErr(w, err.Error(), statedb.HTTPStatus(err))
		return
	}
	jsonOK(w, map[string]interface{}{"ok": true, "reproductions": runs})
}

// handleReproductionGet returns one verdict with its diff-of-diffs.
//
// GET /api/reproductions/{id}
func (s *Server) handleReproductionGet(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		jsonErr(w, "invalid reproduction id", http.StatusBadRequest)
		return
	}
	rep, err := taskreplay.GetReproduction(s.resolveWorkDir(r), id)
	if err != nil {
		if errors.Is(err, taskreplay.ErrReproductionNotFound) {
			jsonErr(w, err.Error(), http.StatusNotFound)
			return
		}
		jsonErr(w, err.Error(), statedb.HTTPStatus(err))
		return
	}
	jsonOK(w, map[string]interface{}{"ok": true, "reproduction": rep})
}

// handleTaskReproduce runs one reproduction and returns its verdict.
//
// POST /api/tasks/{id}/reproduce
func (s *Server) handleTaskReproduce(w http.ResponseWriter, r *http.Request) {
	if !requirePOST(w, r) {
		return
	}
	id, ok := reproTaskID(w, r)
	if !ok {
		return
	}

	// The agent runs in a sandbox, but resolving the base commit and diffing
	// the returned one run git here. See the host-git note above.
	if denyHostSideEffect(w, s.resolveWorkDir(r), "git (reproduction comparison)") {
		return
	}

	var req struct {
		SkipTests bool `json:"skip_tests"`
	}
	if r.Body != nil {
		limitJSONBody(w, r, maxJSONBodyBytes)
		// An empty body is the common case from a plain button press, so a
		// decode failure is not worth refusing the request over.
		_ = json.NewDecoder(r.Body).Decode(&req)
	}

	if !s.admitQuota(w, r, quota.ResConcurrentReproductions, 1) {
		return
	}
	// One release, on every path, including a panic unwinding through the
	// recovery middleware. A leaked reproduction slot narrows the tenant until
	// the hub restarts, and unlike a run there is no reconciliation that would
	// notice.
	identity := s.quotaIdentity(r)
	defer s.releaseQuota(identity, quota.ResConcurrentReproductions, 1)

	ctx, cancel := context.WithTimeout(r.Context(), reproduceHTTPTimeout)
	defer cancel()

	rep, err := taskreplay.Reproduce(ctx, s.resolveWorkDir(r), id, taskreplay.ReproduceOptions{
		Runner:    NewReproduceRunner(s.selfExe()),
		Timeout:   reproduceHTTPTimeout,
		SkipTests: req.SkipTests,
	})
	if err != nil {
		if errors.Is(err, taskreplay.ErrNoRecordedCommit) {
			// 409, not 500: the request was well-formed and the caller is
			// allowed to make it; this task is simply not a thing that can be
			// reproduced. The message is the one the UI shows.
			apierror.WriteError(w, apierror.New(apierror.CodeConflict,
				reproducibilityReason(nil, err)).WithStatus(http.StatusConflict))
			return
		}
		if errors.Is(err, ErrNoIsolatingExecutor) {
			apierror.WriteError(w, apierror.New(apierror.CodeConflict,
				ErrNoIsolatingExecutor.Error()).WithStatus(http.StatusConflict))
			return
		}
		jsonErr(w, err.Error(), statedb.HTTPStatus(err))
		return
	}

	if saveErr := taskreplay.SaveReproduction(s.resolveWorkDir(r), rep); saveErr != nil {
		// The verdict is the product. Log the filing failure and return it
		// anyway rather than turning a successful reproduction into a 500.
		s.log().Error(logger.EventTaskDone, id, "could not record the reproduction verdict",
			map[string]interface{}{"error": saveErr.Error()})
	}
	jsonOK(w, map[string]interface{}{"ok": true, "reproduction": rep})
}

// reproTaskID parses and validates the {id} path segment.
func reproTaskID(w http.ResponseWriter, r *http.Request) (int, bool) {
	id, err := strconv.Atoi(r.PathValue("id"))
	if err != nil || id <= 0 {
		jsonErr(w, "invalid task id", http.StatusBadRequest)
		return 0, false
	}
	return id, true
}
