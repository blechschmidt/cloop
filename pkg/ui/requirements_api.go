package ui

// requirements_api.go: the Requirements tab's backend (Task 20458).
//
//	GET    /api/requirements                    the requirements, each with its latest verdict
//	POST   /api/requirements                    add one
//	PUT    /api/requirements/{id}               change one
//	DELETE /api/requirements/{id}               delete one, and its history
//	GET    /api/requirements/{id}/checks        its recent checks, test output included
//	POST   /api/requirements/{id}/verdict       record a verdict by hand
//	POST   /api/requirements/{id}/task          add a task to restore it, or to test it
//	POST   /api/requirement-runs                check them: tests on the project's executor
//	GET    /api/requirement-runs/{run}          how a check is going
//	POST   /api/requirement-runs/{run}/cancel   stop it
//
// # Where a check runs
//
// Never here. A requirement's tests are shell commands, and the hub does not
// run a project's commands on its own host: a check is `cloop requirements
// check --json --no-record --spec=<the requirements>` dispatched to the
// project's executor through runCloopSubcommandFor, exactly like the Split
// preview and the other dashboard helpers — in the project's sandbox, on its
// device, under its firewall and with its lease. The hub sends the
// requirements rather than letting the executor read its own copy of the
// project, which on a device or a Pod holds none, and so that what runs is
// what the hub decided to run; it reads the framed report back and records it
// through requirements.Sanitize, its own copy of the rules, since the cloop
// that produced it may be anything.
//
// # Permissions
//
// Reading is project.read. Writing a requirement — its tests included — is
// task.mutate: a test is a command that runs in the project's sandbox, which is
// what a task already is, and a test runs only when somebody who may start the
// fleet asks. Checking is run.start, as a reproduction is (reproduce_api.go):
// the question it poses is "may this caller make the fleet execute a test suite
// and, with assess, a model?". Stopping a check is run.stop.
//
// # Why a check is asynchronous
//
// Tests take minutes, and a check of every requirement can take far longer.
// The POST starts the check and returns its run; progress and the end arrive
// as requirements_update pushes, and the run's row in the project's database
// (requirement_runs) is what every hub member reads — so a check survives the
// tab that started it closing, a second one is refused wherever it is asked
// for, and a check whose member died is seen to have lapsed once its heartbeat
// stops.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/blechschmidt/cloop/pkg/artifact"
	"github.com/blechschmidt/cloop/pkg/auditaction"
	"github.com/blechschmidt/cloop/pkg/clijson"
	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/redact"
	"github.com/blechschmidt/cloop/pkg/requirements"
	"github.com/blechschmidt/cloop/pkg/rootkey"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

const (
	// requirementsAssessTimeout is the model's time on one requirement that
	// has no tests.
	requirementsAssessTimeout = 5 * time.Minute
	// requirementsDispatchSlack is a batch's time beyond its tests and model
	// calls: starting the workload where the project runs.
	requirementsDispatchSlack = 3 * time.Minute
	// maxRequirementsCheckTime bounds a whole check, whatever its tests ask.
	maxRequirementsCheckTime = 6 * time.Hour
	// requirementsBatchBytes and requirementsBatchSize bound one dispatch's
	// spec: it is one argument of the command, which Linux caps at 128 KiB.
	requirementsBatchBytes = 96 << 10
	requirementsBatchSize  = 25
	// requirementsRunsListed is how many past runs the list carries.
	requirementsRunsListed = 5
	// maxRequirementTaskContext bounds what a task made from a requirement
	// quotes of its last check.
	maxRequirementTaskContext = 6000
)

// requirementView is one requirement as the tab draws it.
type requirementView struct {
	requirements.Requirement
	Fingerprint string                    `json:"fingerprint"`
	LastCheck   *statedb.RequirementCheck `json:"last_check,omitempty"`
	// Stale says why the last verdict may no longer hold: "changed" — the
	// requirement was edited since — or "tasks" — tasks were done since.
	Stale string `json:"stale,omitempty"`
	// TasksDoneSince counts the tasks finished after the last check.
	TasksDoneSince int `json:"tasks_done_since,omitempty"`
}

// requirementsList is GET /api/requirements's answer.
type requirementsList struct {
	OK           bool                     `json:"ok"`
	Requirements []requirementView        `json:"requirements"`
	Counts       requirements.Counts      `json:"counts"`
	Never        int                      `json:"never"`
	Stale        int                      `json:"stale"`
	Active       *statedb.RequirementRun  `json:"active,omitempty"`
	Runs         []statedb.RequirementRun `json:"runs"`
}

// requirementInput is what a client sends to add or change a requirement.
type requirementInput struct {
	Title       string              `json:"title"`
	Description string              `json:"description"`
	Priority    string              `json:"priority"`
	Tags        []string            `json:"tags"`
	Tests       []requirements.Test `json:"tests"`
}

func (in requirementInput) requirement(id int) requirements.Requirement {
	return requirements.Requirement{
		ID: id, Title: in.Title, Description: in.Description, Priority: in.Priority, Tags: in.Tags, Tests: in.Tests,
	}
}

// openRequirementsDB opens the project's database for a request, writing the
// refusal when it cannot.
func openRequirementsDB(w http.ResponseWriter, workDir string) (*statedb.DB, bool) {
	db, err := statedb.Open(state.DBPath(workDir))
	if err != nil {
		jsonErr(w, err.Error(), statedb.HTTPStatus(err))
		return nil, false
	}
	return db.AsProject(), true
}

// requirementErr answers a store error: the caller's mistake (400), a
// requirement that does not exist (404), a check already running (409).
func requirementErr(w http.ResponseWriter, err error) {
	if errors.Is(err, requirements.ErrInvalid) {
		jsonErr(w, err.Error(), http.StatusBadRequest)
		return
	}
	jsonErr(w, err.Error(), statedb.HTTPStatus(err))
}

func requirementPathID(w http.ResponseWriter, r *http.Request) (int, bool) {
	raw := strings.TrimPrefix(strings.TrimPrefix(r.PathValue("id"), "R-"), "r-")
	id, err := strconv.Atoi(raw)
	if err != nil || id <= 0 {
		jsonErr(w, "invalid requirement id", http.StatusBadRequest)
		return 0, false
	}
	return id, true
}

// handleRequirementsList answers GET /api/requirements.
func (s *Server) handleRequirementsList(w http.ResponseWriter, r *http.Request) {
	workDir := s.resolveWorkDir(r)
	db, ok := openRequirementsDB(w, workDir)
	if !ok {
		return
	}
	defer db.Close()
	reqs, err := db.Requirements()
	if err != nil {
		requirementErr(w, err)
		return
	}
	latest, err := db.LatestRequirementChecks()
	if err != nil {
		requirementErr(w, err)
		return
	}
	runs, err := db.RecentRequirementRuns(requirementsRunsListed)
	if err != nil {
		requirementErr(w, err)
		return
	}
	out := requirementsList{OK: true, Requirements: make([]requirementView, 0, len(reqs)), Runs: runs}
	if active, found, err := db.ActiveRequirementRun(); err == nil && found {
		out.Active = &active
	}
	if out.Runs == nil {
		out.Runs = []statedb.RequirementRun{}
	}
	var done []time.Time
	if ps, err := state.LoadLite(workDir); err == nil && ps.Plan != nil {
		for _, t := range ps.Plan.Tasks {
			if t.Status == pm.TaskDone && t.CompletedAt != nil {
				done = append(done, *t.CompletedAt)
			}
		}
	}
	for _, req := range reqs {
		v := requirementView{Requirement: req, Fingerprint: req.Fingerprint()}
		c, checked := latest[req.ID]
		if !checked {
			out.Never++
			out.Requirements = append(out.Requirements, v)
			continue
		}
		// The list carries no test output: a project's worth of it is
		// megabytes, and the details fetch one requirement's.
		c.Tests = withoutOutput(c.Tests)
		v.LastCheck = &c
		out.Counts.Add(c.Verdict)
		for _, at := range done {
			if at.After(c.CheckedAt) {
				v.TasksDoneSince++
			}
		}
		// No verdict cannot go stale; any other may, a person's included:
		// the tasks done since may have changed what they looked at.
		switch {
		case c.Fingerprint != v.Fingerprint:
			v.Stale = "changed"
		case v.TasksDoneSince > 0 && c.Verdict != requirements.VerdictUnverified:
			v.Stale = "tasks"
		}
		if v.Stale != "" {
			out.Stale++
		}
		out.Requirements = append(out.Requirements, v)
	}
	jsonOK(w, out)
}

func withoutOutput(ts []requirements.TestResult) []requirements.TestResult {
	out := make([]requirements.TestResult, len(ts))
	for i, t := range ts {
		t.Truncated = t.Truncated || t.Output != ""
		t.Output = ""
		out[i] = t
	}
	return out
}

// handleRequirementCreate answers POST /api/requirements.
func (s *Server) handleRequirementCreate(w http.ResponseWriter, r *http.Request) {
	var in requirementInput
	if !decodeJSON(w, r, &in) {
		return
	}
	workDir := s.resolveWorkDir(r)
	db, ok := openRequirementsDB(w, workDir)
	if !ok {
		return
	}
	added, err := db.AddRequirement(in.requirement(0), s.auditActor(r))
	db.Close()
	if err != nil {
		requirementErr(w, err)
		return
	}
	s.requirementsChanged(workDir, "", "")
	s.broadcastAuditAppend(string(auditaction.ActionRequirementCreate))
	jsonOK(w, map[string]any{"ok": true, "requirement": added})
}

// handleRequirementUpdate answers PUT /api/requirements/{id}: the definition
// as sent replaces the stored one.
func (s *Server) handleRequirementUpdate(w http.ResponseWriter, r *http.Request) {
	id, ok := requirementPathID(w, r)
	if !ok {
		return
	}
	var in requirementInput
	if !decodeJSON(w, r, &in) {
		return
	}
	workDir := s.resolveWorkDir(r)
	db, ok := openRequirementsDB(w, workDir)
	if !ok {
		return
	}
	updated, err := db.UpdateRequirement(in.requirement(id), s.auditActor(r))
	db.Close()
	if err != nil {
		requirementErr(w, err)
		return
	}
	s.requirementsChanged(workDir, "", "")
	s.broadcastAuditAppend(string(auditaction.ActionRequirementUpdate))
	jsonOK(w, map[string]any{"ok": true, "requirement": updated})
}

// handleRequirementDelete answers DELETE /api/requirements/{id}.
func (s *Server) handleRequirementDelete(w http.ResponseWriter, r *http.Request) {
	id, ok := requirementPathID(w, r)
	if !ok {
		return
	}
	workDir := s.resolveWorkDir(r)
	db, ok := openRequirementsDB(w, workDir)
	if !ok {
		return
	}
	gone, err := db.DeleteRequirement(id, s.auditActor(r))
	db.Close()
	if err != nil {
		requirementErr(w, err)
		return
	}
	s.requirementsChanged(workDir, "", "")
	s.broadcastAuditAppend(string(auditaction.ActionRequirementDelete))
	jsonOK(w, map[string]any{"ok": true, "deleted": gone})
}

// handleRequirementChecks answers GET /api/requirements/{id}/checks.
func (s *Server) handleRequirementChecks(w http.ResponseWriter, r *http.Request) {
	id, ok := requirementPathID(w, r)
	if !ok {
		return
	}
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	db, ok := openRequirementsDB(w, s.resolveWorkDir(r))
	if !ok {
		return
	}
	defer db.Close()
	req, err := db.Requirement(id)
	if err != nil {
		requirementErr(w, err)
		return
	}
	checks, err := db.RequirementChecks(id, limit)
	if err != nil {
		requirementErr(w, err)
		return
	}
	if checks == nil {
		checks = []statedb.RequirementCheck{}
	}
	jsonOK(w, map[string]any{"ok": true, "requirement": req, "fingerprint": req.Fingerprint(), "checks": checks})
}

// handleRequirementVerdict answers POST /api/requirements/{id}/verdict.
func (s *Server) handleRequirementVerdict(w http.ResponseWriter, r *http.Request) {
	id, ok := requirementPathID(w, r)
	if !ok {
		return
	}
	var in struct {
		Verdict string `json:"verdict"`
		Note    string `json:"note"`
	}
	if !decodeJSON(w, r, &in) {
		return
	}
	workDir := s.resolveWorkDir(r)
	db, ok := openRequirementsDB(w, workDir)
	if !ok {
		return
	}
	c, err := db.RecordRequirementVerdict(id, strings.ToLower(strings.TrimSpace(in.Verdict)), in.Note, s.auditActor(r))
	db.Close()
	if err != nil {
		requirementErr(w, err)
		return
	}
	s.requirementsChanged(workDir, "", "")
	s.broadcastAuditAppend(string(auditaction.ActionRequirementVerdict))
	jsonOK(w, map[string]any{"ok": true, "check": c})
}

// handleRequirementTask answers POST /api/requirements/{id}/task: a pending
// task that puts the requirement right ("fix", quoting its last check) or that
// gives it a test ("test"), so the project's own loop does the work.
func (s *Server) handleRequirementTask(w http.ResponseWriter, r *http.Request) {
	id, ok := requirementPathID(w, r)
	if !ok {
		return
	}
	var in struct {
		Kind string `json:"kind"`
	}
	if !decodeOptionalJSON(w, r, &in) {
		return
	}
	workDir := s.resolveWorkDir(r)
	db, ok := openRequirementsDB(w, workDir)
	if !ok {
		return
	}
	req, err := db.Requirement(id)
	var last []statedb.RequirementCheck
	if err == nil {
		last, err = db.RequirementChecks(id, 1)
	}
	db.Close()
	if err != nil {
		requirementErr(w, err)
		return
	}
	var lastCheck *statedb.RequirementCheck
	if len(last) > 0 {
		lastCheck = &last[0]
	}
	title, desc, err := requirementTask(req, lastCheck, strings.TrimSpace(in.Kind))
	if err != nil {
		jsonErr(w, err.Error(), http.StatusBadRequest)
		return
	}

	ps, err := state.LoadLite(workDir)
	if err != nil {
		jsonErr(w, "no project found — run cloop init first", http.StatusNotFound)
		return
	}
	if ps.Plan == nil {
		ps.Plan = pm.NewPlan(ps.Goal)
		ps.PMMode = true
	}
	maxID := 0
	for _, t := range ps.Plan.Tasks {
		maxID = max(maxID, t.ID)
	}
	task := &pm.Task{
		ID: maxID + 1, Title: title, Description: desc, Priority: requirementTaskPriority(req.Priority),
		Status: pm.TaskPending, Tags: []string{"requirement", strings.ToLower(requirements.Key(req.ID))},
	}
	ps.Plan.Tasks = append(ps.Plan.Tasks, task)
	if err := ps.SaveDirect(); err != nil {
		jsonErr(w, "save failed: "+err.Error(), statedb.HTTPStatus(err))
		return
	}
	s.broadcastStateDiff(workDir, ps)
	raw, _ := json.Marshal(map[string]any{"task": task})
	s.broadcastToProject(workDir, wsMessage{Type: "task_added", Data: raw})
	state.LogEvent(workDir, state.EventRow{
		Type: state.EventTaskAdded, TaskID: task.ID, TaskTitle: task.Title, Step: state.NoStep,
		Message: fmt.Sprintf("Task #%d added from requirement %s: %s", task.ID, requirements.Key(req.ID), task.Title),
	})
	jsonOK(w, map[string]any{"ok": true, "task": task})
}

// requirementTask writes the task kind asks for about req.
func requirementTask(req requirements.Requirement, last *statedb.RequirementCheck, kind string) (string, string, error) {
	key := requirements.Key(req.ID)
	var b strings.Builder
	switch kind {
	case "", "fix":
		fmt.Fprintf(&b, "Requirement %s is not fulfilled: %s\n", key, req.Title)
		if req.Description != "" {
			fmt.Fprintf(&b, "\n%s\n", req.Description)
		}
		if last != nil {
			fmt.Fprintf(&b, "\nIts last check (%s, %s): %s\n", last.Verdict, last.Method, last.Summary)
			for _, t := range last.Tests {
				if t.Outcome == requirements.OutcomePass {
					continue
				}
				fmt.Fprintf(&b, "\nTest `%s` — %s, exit %d\n", t.Command, t.Outcome, t.ExitCode)
				if out := strings.TrimSpace(t.Output); out != "" {
					if len(out) > 2000 {
						out = "…" + out[len(out)-2000:]
					}
					fmt.Fprintf(&b, "```\n%s\n```\n", strings.ToValidUTF8(out, ""))
				}
			}
		}
		b.WriteString("\nChange the project so the requirement holds again")
		if req.Tested() {
			b.WriteString(", and run its tests to show it:\n")
			for _, t := range req.Tests {
				fmt.Fprintf(&b, "- `%s`\n", t.Command)
			}
		} else {
			b.WriteString(".\n")
		}
		return truncateRunes("Restore "+key+": "+req.Title, 300), clipRequirementTask(b.String()), nil
	case "test":
		fmt.Fprintf(&b, "Requirement %s has no automated test: %s\n", key, req.Title)
		if req.Description != "" {
			fmt.Fprintf(&b, "\n%s\n", req.Description)
		}
		b.WriteString("\nWrite an automated test that passes exactly when this requirement holds, using the " +
			"project's own test framework, and make it pass. End your summary with the single shell command, " +
			"run from the project's root, that runs only this test — it becomes the requirement's test.\n")
		return truncateRunes("Add a test for "+key+": "+req.Title, 300), clipRequirementTask(b.String()), nil
	}
	return "", "", fmt.Errorf("kind %q is not fix or test", kind)
}

func clipRequirementTask(s string) string {
	if len(s) <= maxRequirementTaskContext {
		return s
	}
	return strings.ToValidUTF8(s[:maxRequirementTaskContext], "") + "\n…"
}

// requirementTaskPriority places a task made from a requirement: a must
// before the plan's usual work, a could after it.
func requirementTaskPriority(p string) int {
	switch p {
	case requirements.PriorityMust:
		return 1
	case requirements.PriorityCould:
		return 4
	}
	return 2
}

// ── check runs ──────────────────────────────────────────────────────────────

// requirementChecks tracks the checks this hub member is running, so shutdown
// can stop them and record that it did.
type requirementChecks struct {
	mu   sync.Mutex
	jobs map[string]context.CancelCauseFunc
	wg   sync.WaitGroup
}

func (c *requirementChecks) add(runID string, cancel context.CancelCauseFunc) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.jobs == nil {
		c.jobs = map[string]context.CancelCauseFunc{}
	}
	c.jobs[runID] = cancel
	c.wg.Add(1)
}

func (c *requirementChecks) done(runID string) {
	c.mu.Lock()
	delete(c.jobs, runID)
	c.mu.Unlock()
	c.wg.Done()
}

func (c *requirementChecks) cancel(runID string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if f, ok := c.jobs[runID]; ok {
		f(errRequirementsCancelled)
		return true
	}
	return false
}

// stop cancels every check and waits up to wait for them to record their end.
func (c *requirementChecks) stop(wait time.Duration) {
	c.mu.Lock()
	for _, f := range c.jobs {
		f(errHubStopping)
	}
	c.mu.Unlock()
	finished := make(chan struct{})
	go func() { c.wg.Wait(); close(finished) }()
	select {
	case <-finished:
	case <-time.After(wait):
	}
}

// Why a check stopped before its end: somebody cancelled it, or the hub
// member running it stopped.
var (
	errRequirementsCancelled = errors.New("cancelled")
	errHubStopping           = errors.New("the hub stopped while the check ran")
)

// requirementCheckJob is one check run's work.
type requirementCheckJob struct {
	run     statedb.RequirementRun
	workDir string
	goal    string
	batches [][]requirements.Requirement
	// dispatch runs `cloop <args>` on the project's executor, for whoever
	// started the check: built by the handler, which knows whom it acts for.
	dispatch func(ctx context.Context, timeout time.Duration, args []string) ([]byte, error)
}

// handleRequirementRunStart answers POST /api/requirement-runs: it starts a
// check of the requirements ids names — all of them when it names none — and
// returns the run. With assess, the model is asked about the ones that have
// no tests; without, those are skipped, and named in the answer.
func (s *Server) handleRequirementRunStart(w http.ResponseWriter, r *http.Request) {
	workDir := s.resolveWorkDir(r)
	// A device's workload is started by the member holding its agent.
	if s.routeDispatch(w, r, workDir) {
		return
	}
	var in struct {
		IDs    []int `json:"ids"`
		Assess bool  `json:"assess"`
	}
	if !decodeOptionalJSON(w, r, &in) {
		return
	}
	db, ok := openRequirementsDB(w, workDir)
	if !ok {
		return
	}
	defer db.Close()
	all, err := db.Requirements()
	if err != nil {
		requirementErr(w, err)
		return
	}
	asked, err := pickRequirements(all, in.IDs)
	if err != nil {
		requirementErr(w, err)
		return
	}
	if len(asked) == 0 {
		jsonErr(w, "the project has no requirements to check", http.StatusBadRequest)
		return
	}
	// A requirement with no tests is checked only by the model. Not asked to
	// assess, the check leaves it alone rather than record that it could not
	// tell — which would bury a verdict a person or the model reached.
	assess := false
	var skipped []int
	if in.Assess {
		for _, q := range asked {
			assess = assess || !q.Tested()
		}
	} else {
		tested := asked[:0:0]
		for _, q := range asked {
			if q.Tested() {
				tested = append(tested, q)
			} else {
				skipped = append(skipped, q.ID)
			}
		}
		asked = tested
	}
	if len(asked) == 0 {
		jsonErr(w, "none of these requirements has a test to run: ask the model about them, or record a verdict by hand",
			http.StatusBadRequest)
		return
	}

	// Refused now, in the words of the refusal, rather than as a run that
	// fails a moment later: where the project may run, and — when the model
	// is asked — whether the caller has a Claude credential there.
	registerBuiltinExecutors()
	if err := checkDispatchConfinement(workDir); err != nil {
		jsonWorkloadErr(w, err)
		return
	}
	ex, err := executor.Resolve(workDir)
	if err != nil {
		jsonWorkloadErr(w, fmt.Errorf("no executor available for %s: %w", workDir, err))
		return
	}
	if err := checkFeatureExecutor(workDir, ex); err != nil {
		jsonWorkloadErr(w, err)
		return
	}
	// A check that only runs tests runs no harness: its lease still
	// withholds other people's personal Claude credentials. Asked to assess,
	// it is a model call on the caller's own account, refused now when a
	// sandbox would give it no credential.
	clear := s.leaseClearanceFor(r, workDir)
	var claudeEnv func(executor.Executor) []string
	if assess {
		clear = s.harnessClearanceFor(r, workDir)
		if s.refuseWithoutHarnessCredential(w, clear) {
			return
		}
		// Resolved here: r must not outlive this handler.
		claudeEnv = s.claudeEnvResolver(r)
	}
	exe := s.selfExe()
	job := &requirementCheckJob{workDir: workDir, batches: requirementBatches(asked),
		dispatch: func(ctx context.Context, timeout time.Duration, args []string) ([]byte, error) {
			return runCloopSubcommandFor(ctx, exe, workDir, timeout, claudeEnv, clear, args...)
		}}
	if ps, err := state.LoadLite(workDir); err == nil {
		job.goal = ps.Goal
		if ps.Plan != nil && ps.Plan.Goal != "" {
			job.goal = ps.Plan.Goal
		}
	}

	ids := make([]int, len(asked))
	for i, q := range asked {
		ids[i] = q.ID
	}
	run, err := db.StartRequirementRun(statedb.RequirementRun{
		RunID: artifact.NewRunID(), Source: "dashboard", StartedBy: s.auditActor(r),
		Deadline: time.Now().Add(checkBudget(job.batches, assess)), ExecutorID: ex.ID(), Assess: assess,
		RequirementIDs: ids,
	})
	if err != nil {
		if errors.Is(err, statedb.ErrRequirementCheckRunning) {
			writeJSONStatus(w, http.StatusConflict, map[string]any{
				"ok": false, "error": "a check of this project's requirements is already running", "active": run,
			})
			return
		}
		requirementErr(w, err)
		return
	}
	job.run = run

	base, stop := context.WithDeadline(context.Background(), run.Deadline)
	ctx, cancel := context.WithCancelCause(base)
	s.reqChecks.add(run.RunID, cancel)
	go func() {
		defer stop()
		s.runRequirementCheck(ctx, cancel, job)
	}()

	s.requirementsChanged(workDir, run.RunID, run.State)
	if skipped == nil {
		skipped = []int{}
	}
	writeJSONStatus(w, http.StatusAccepted, map[string]any{"ok": true, "run": run, "skipped": skipped})
}

// pickRequirements is the requirements ids names, in the order named, or all
// of them when it names none.
func pickRequirements(all []requirements.Requirement, ids []int) ([]requirements.Requirement, error) {
	if len(ids) == 0 {
		return all, nil
	}
	if len(ids) > requirements.MaxRequirements {
		return nil, fmt.Errorf("%w: at most %d requirements per check", requirements.ErrInvalid, requirements.MaxRequirements)
	}
	byID := make(map[int]requirements.Requirement, len(all))
	for _, q := range all {
		byID[q.ID] = q
	}
	var out []requirements.Requirement
	seen := map[int]bool{}
	for _, id := range ids {
		q, ok := byID[id]
		if !ok {
			return nil, fmt.Errorf("%w: %s", statedb.ErrRequirementNotFound, requirements.Key(id))
		}
		if !seen[id] {
			seen[id] = true
			out = append(out, q)
		}
	}
	return out, nil
}

// requirementBatches splits reqs into the dispatches that check them: as few
// as fit one argument each. A requirement too large for any — one written to
// the database past what Normalize admits — is a batch of its own, which
// runRequirementCheck reports rather than sends.
func requirementBatches(reqs []requirements.Requirement) [][]requirements.Requirement {
	var (
		out  [][]requirements.Requirement
		cur  []requirements.Requirement
		size int
	)
	for _, q := range reqs {
		n := q.EncodedSize()
		if len(cur) > 0 && (len(cur) >= requirementsBatchSize || size+n > requirementsBatchBytes || n > requirementsBatchBytes) {
			out = append(out, cur)
			cur, size = nil, 0
		}
		cur = append(cur, q.ForSpec())
		size += n
	}
	if len(cur) > 0 {
		out = append(out, cur)
	}
	return out
}

// oversizedBatch reports whether batch cannot be sent as one argument.
func oversizedBatch(batch []requirements.Requirement) bool {
	size := 0
	for _, q := range batch {
		size += q.EncodedSize()
	}
	return size > requirementsBatchBytes
}

// maxSpecGoalRunes bounds the goal a spec carries: it is context for the
// model, and the requirements are what must fit.
const maxSpecGoalRunes = 2000

// batchBudget is how long one dispatch may take: its tests, its model calls,
// and starting the workload.
func batchBudget(batch []requirements.Requirement, assess bool) time.Duration {
	d := requirementsDispatchSlack
	for _, q := range batch {
		for _, t := range q.Tests {
			d += t.Timeout()
		}
		if assess && !q.Tested() {
			d += requirementsAssessTimeout
		}
	}
	return d
}

// checkBudget is how long a whole check may take, which is also when its run
// lapses should the member running it die.
func checkBudget(batches [][]requirements.Requirement, assess bool) time.Duration {
	var d time.Duration
	for _, b := range batches {
		d += batchBudget(b, assess)
	}
	return min(d, maxRequirementsCheckTime)
}

// runRequirementCheck runs job's batches one after another on the project's
// executor, recording each as it ends, and then the run's end.
func (s *Server) runRequirementCheck(ctx context.Context, cancel context.CancelCauseFunc, job *requirementCheckJob) {
	run := job.run
	var (
		counts           requirements.Counts
		commit           string
		dirty            bool
		endState, reason = statedb.RequirementRunDone, ""
	)
	defer s.reqChecks.done(run.RunID)
	defer cancel(nil)
	defer func() {
		if rec := recover(); rec != nil {
			endState, reason = statedb.RequirementRunFailed, fmt.Sprintf("internal error: %v", rec)
		}
		s.finishRequirementRun(job, endState, counts, commit, dirty, reason)
	}()

	db, err := statedb.Open(state.DBPath(job.workDir))
	if err != nil {
		endState, reason = statedb.RequirementRunFailed, err.Error()
		return
	}
	defer db.Close()
	db.AsProject()

	// The heartbeat that keeps the run holding its project's one check, and
	// the way a cancel asked of any member reaches this one. Stopped, and
	// waited for, before the handle it writes through is closed.
	beat, stopBeat := context.WithCancel(ctx)
	beating := make(chan struct{})
	defer func() { stopBeat(); <-beating }()
	go func() {
		defer close(beating)
		t := time.NewTicker(statedb.RequirementRunHeartbeat)
		defer t.Stop()
		for {
			select {
			case <-beat.Done():
				return
			case <-t.C:
				if asked, err := db.TouchRequirementRun(run.RunID); err == nil && asked {
					cancel(errRequirementsCancelled)
					return
				}
			}
		}
	}()

	scrub := hubScrubber()
	for i, batch := range job.batches {
		if ctx.Err() != nil {
			break
		}
		var rep requirements.Report
		if oversizedBatch(batch) {
			rep = failedRequirementReport(batch, "the requirement is too large to send to the executor")
		} else if rep, err = s.dispatchRequirementBatch(ctx, job, batch); err != nil {
			rep = failedRequirementReport(batch, err.Error())
		}
		clean := requirements.Sanitize(rep, batch, run.Assess, scrub, time.Now().UTC())
		if i == 0 || commit == "" {
			commit, dirty = clean.Commit, clean.Dirty
		}
		stored, err := db.RecordRequirementChecks(statedb.CheckRecord{
			RunID: run.RunID, Commit: clean.Commit, Dirty: clean.Dirty, ExecutorID: run.ExecutorID, CheckedBy: run.StartedBy,
		}, clean.Results)
		if err != nil {
			endState, reason = statedb.RequirementRunFailed, "recording the results: "+err.Error()
			return
		}
		for _, c := range stored {
			counts.Add(c.Verdict)
		}
		s.requirementsChanged(job.workDir, run.RunID, statedb.RequirementRunRunning)
	}
	switch cause := context.Cause(ctx); {
	case ctx.Err() == nil:
	case errors.Is(cause, errHubStopping):
		endState, reason = statedb.RequirementRunFailed, errHubStopping.Error()
	case errors.Is(cause, errRequirementsCancelled):
		endState, reason = statedb.RequirementRunCancelled, "cancelled"
	default:
		endState, reason = statedb.RequirementRunFailed, "the check ran past its deadline"
	}
}

// dispatchRequirementBatch checks one batch on the project's executor and
// returns the report it sent back, unread by Sanitize.
func (s *Server) dispatchRequirementBatch(ctx context.Context, job *requirementCheckJob, batch []requirements.Requirement) (requirements.Report, error) {
	spec, err := requirements.EncodeSpec(requirements.Spec{Goal: truncateRunes(job.goal, maxSpecGoalRunes), Requirements: batch})
	if err != nil {
		return requirements.Report{}, err
	}
	args := []string{"requirements", "check", "--json", "--no-record", "--spec=" + string(spec)}
	if job.run.Assess {
		args = append(args, "--ai", "--ai-timeout", requirementsAssessTimeout.String())
	}
	out, runErr := job.dispatch(ctx, batchBudget(batch, job.run.Assess), args)
	payload, perr := clijson.Extract(out)
	if perr == nil {
		var failed modelCallFailure
		if json.Unmarshal(payload, &failed) == nil && failed.Error != "" {
			return requirements.Report{}, errors.New(failed.Error)
		}
		var rep requirements.Report
		if err := json.Unmarshal(payload, &rep); err == nil && rep.Results != nil {
			return rep, nil
		}
	}
	if runErr == nil {
		return requirements.Report{}, fmt.Errorf("the executor's cloop sent back no report: %v", perr)
	}
	return requirements.Report{}, errors.New(modelCallReason(out, runErr))
}

// failedRequirementReport is a report saying the check of each of batch did
// not work, and why.
func failedRequirementReport(batch []requirements.Requirement, why string) requirements.Report {
	why = truncateRunes(strings.Join(strings.Fields(why), " "), requirements.MaxSummaryRunes)
	rep := requirements.Report{Results: make([]requirements.Result, 0, len(batch))}
	now := time.Now().UTC()
	for _, q := range batch {
		method := requirements.MethodNone
		if q.Tested() {
			method = requirements.MethodTests
		}
		rep.Results = append(rep.Results, requirements.Result{
			RequirementID: q.ID, Fingerprint: q.Fingerprint(), Method: method, Verdict: requirements.VerdictError,
			Summary: "the check did not run: " + why, StartedAt: now,
			Tests: brokenTests(q.Tests, why),
		})
	}
	return rep
}

func brokenTests(ts []requirements.Test, why string) []requirements.TestResult {
	if len(ts) == 0 {
		return nil
	}
	out := make([]requirements.TestResult, len(ts))
	for i, t := range ts {
		out[i] = requirements.TestResult{Name: t.Name, Command: t.Command, Outcome: requirements.OutcomeError, ExitCode: -1, Error: why}
	}
	return out
}

// hubScrubber is what the hub passes a report's text through before it is
// stored: the shapes of credentials, and this hub's own root key. The
// executor's cloop scrubbed with the lease it held; this is the hub's copy of
// the rule, for the cloop it cannot vouch for.
func hubScrubber() func(string) string {
	var own []string
	for _, n := range []string{rootkey.EnvKey, rootkey.EnvPrevious} {
		if v := os.Getenv(n); len(v) >= 8 {
			own = append(own, v)
		}
	}
	set := redact.New(own...)
	return func(s string) string { return redact.Scrub(set.String(s)) }
}

// finishRequirementRun records how a run ended — in its row, in the project's
// audit trail — and tells the project's dashboards.
func (s *Server) finishRequirementRun(job *requirementCheckJob, endState string, counts requirements.Counts, commit string, dirty bool, reason string) {
	run := job.run
	db, err := statedb.Open(state.DBPath(job.workDir))
	if err != nil {
		fmt.Fprintf(os.Stderr, "ui: requirements check %s: record its end: %v\n", run.RunID, err)
		return
	}
	defer db.Close()
	db.AsProject()
	ended, err := db.FinishRequirementRun(run.RunID, endState, counts, run.ExecutorID, reason)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ui: requirements check %s: record its end: %v\n", run.RunID, err)
	}
	if ended {
		run.State, run.Counts, run.Error = endState, counts, reason
		statedb.AuditRequirementCheck(db, run, commit, dirty, run.StartedBy)
		s.broadcastAuditAppend(string(auditaction.ActionRequirementCheck))
	}
	s.requirementsChanged(job.workDir, run.RunID, endState)
}

// handleRequirementRunGet answers GET /api/requirement-runs/{run}.
func (s *Server) handleRequirementRunGet(w http.ResponseWriter, r *http.Request) {
	db, ok := openRequirementsDB(w, s.resolveWorkDir(r))
	if !ok {
		return
	}
	defer db.Close()
	run, err := db.RequirementRunByID(r.PathValue("run"))
	if err != nil {
		requirementErr(w, err)
		return
	}
	jsonOK(w, map[string]any{"ok": true, "run": run})
}

// handleRequirementRunCancel answers POST /api/requirement-runs/{run}/cancel.
// The member running the check stops it at once when it is this one, and at
// its next heartbeat (statedb.RequirementRunHeartbeat) otherwise.
func (s *Server) handleRequirementRunCancel(w http.ResponseWriter, r *http.Request) {
	runID := r.PathValue("run")
	db, ok := openRequirementsDB(w, s.resolveWorkDir(r))
	if !ok {
		return
	}
	asked, err := db.RequestRequirementRunCancel(runID)
	db.Close()
	if err != nil {
		requirementErr(w, err)
		return
	}
	if !asked {
		jsonErr(w, "that check is not running", http.StatusConflict)
		return
	}
	s.reqChecks.cancel(runID)
	jsonOK(w, map[string]any{"ok": true, "run_id": runID})
}

// requirementsChanged tells the project's dashboards, on every member, to read
// the requirements again. It carries no requirement: the tab reads them
// through the gate every reader passes.
func (s *Server) requirementsChanged(workDir, runID, runState string) {
	raw, _ := json.Marshal(map[string]string{"run_id": runID, "state": runState})
	msg := wsMessage{Type: "requirements_update", Data: raw}
	s.deliverToProject(workDir, msg)
	s.deliverSSE(workDir, sseEvent{Event: "requirements_update", Data: string(raw)})
	s.publishWS(workDir, msg, "requirements_update")
}
