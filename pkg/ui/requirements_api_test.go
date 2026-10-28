package ui

// The Requirements tab's backend (Task 20458), driven through the real handlers
// with the stand-in for the cloop binary (modelStub): what the hub asks the
// executor, and what it records of a report it cannot vouch for. The real
// `cloop requirements check` on the far end is exercised in cmd
// (requirements_test.go), through a hub of its own.

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/requirements"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

func addRequirementVia(t *testing.T, ts *httptest.Server, body map[string]any) int {
	t.Helper()
	code, d := rawJSON(t, ts, http.MethodPost, "/api/requirements", body)
	if code != http.StatusOK {
		t.Fatalf("add %v = %d %v", body, code, d)
	}
	r, _ := d["requirement"].(map[string]any)
	return int(r["id"].(float64))
}

// waitRequirementRun polls a run until it ends.
func waitRequirementRun(t *testing.T, ts *httptest.Server, runID string) statedb.RequirementRun {
	t.Helper()
	deadline := time.Now().Add(60 * time.Second)
	for {
		req, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/requirement-runs/"+runID, nil)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		var d struct {
			Run statedb.RequirementRun `json:"run"`
		}
		err = json.NewDecoder(resp.Body).Decode(&d)
		resp.Body.Close()
		if err != nil {
			t.Fatal(err)
		}
		if d.Run.State != statedb.RequirementRunRunning {
			return d.Run
		}
		if time.Now().After(deadline) {
			t.Fatalf("run %s still running: %+v", runID, d.Run)
		}
		time.Sleep(25 * time.Millisecond)
	}
}

func startRequirementRun(t *testing.T, ts *httptest.Server, body map[string]any) (int, map[string]any, string) {
	t.Helper()
	code, d := rawJSON(t, ts, http.MethodPost, "/api/requirement-runs", body)
	run, _ := d["run"].(map[string]any)
	id, _ := run["run_id"].(string)
	return code, d, id
}

func latestChecks(t *testing.T, dir string) map[int]statedb.RequirementCheck {
	t.Helper()
	db, err := statedb.Open(state.DBPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	m, err := db.LatestRequirementChecks()
	if err != nil {
		t.Fatal(err)
	}
	return m
}

// TestRequirementsCheckIsAskedOfTheExecutorAndReadForWhatWasAsked: the hub
// hands the executor the requirements as it has them, and what comes back is
// recorded in the hub's terms — a forged verdict, a rewritten command and a
// report about a requirement nobody asked about change nothing.
func TestRequirementsCheckIsAskedOfTheExecutorAndReadForWhatWasAsked(t *testing.T) {
	dir := setupProjectDir(t, "requirements on the executor", modelCallTasks())
	stub := newModelStub(t)
	ts := modelCallHub(t, dir, stub)

	tested := addRequirementVia(t, ts, map[string]any{"title": "Builds", "priority": "must",
		"tests": []map[string]any{{"name": "build", "command": "go build ./...", "timeout_seconds": 120}}})
	untested := addRequirementVia(t, ts, map[string]any{"title": "Is pleasant", "description": "To use."})

	stub.answer(t, "requirements-check", "warning: a diagnostic on the shared stream\n"+framed(t, map[string]any{
		"commit": "0123456789abcdef0123456789abcdef01234567", "dirty": true,
		"results": []map[string]any{
			{"requirement_id": tested, "method": "tests", "verdict": "fulfilled", "tests": []map[string]any{
				{"command": "echo pwned", "outcome": "fail", "exit_code": 2, "output": "it broke"}}},
			{"requirement_id": untested, "method": "ai", "verdict": "fulfilled", "summary": "Looks fine."},
			{"requirement_id": 999, "method": "tests", "verdict": "fulfilled"},
		},
	}), 0)

	code, d, runID := startRequirementRun(t, ts, map[string]any{})
	if skipped, _ := d["skipped"].([]any); code != http.StatusAccepted || runID == "" || len(skipped) != 1 || skipped[0] != float64(untested) {
		t.Fatalf("start = %d %v, want the untested requirement skipped", code, d)
	}
	run := waitRequirementRun(t, ts, runID)
	if run.State != statedb.RequirementRunDone || run.Counts.Unfulfilled != 1 || run.Counts.Unverified != 0 ||
		len(run.RequirementIDs) != 1 {
		t.Fatalf("the run ended %+v", run)
	}

	args := stubArgs(t, dir)
	if len(args) < 5 || args[0] != "requirements" || args[1] != "check" || args[2] != "--json" || args[3] != "--no-record" ||
		!strings.HasPrefix(args[4], "--spec=") {
		t.Fatalf("the executor was asked %q", args)
	}
	for _, a := range args {
		if a == "--ai" {
			t.Errorf("a check that did not ask for the model passed --ai: %q", args)
		}
	}
	sp, err := requirements.ParseSpec([]byte(strings.TrimPrefix(args[4], "--spec=")))
	if err != nil || len(sp.Requirements) != 1 || sp.Requirements[0].Tests[0].Command != "go build ./..." ||
		sp.Goal != "requirements on the executor" {
		t.Fatalf("the spec sent: %+v (%v)", sp, err)
	}

	got := latestChecks(t, dir)
	if c := got[tested]; c.Verdict != requirements.VerdictUnfulfilled || c.Tests[0].Command != "go build ./..." ||
		c.Tests[0].Name != "build" || c.Commit != "0123456789abcdef0123456789abcdef01234567" || !c.Dirty || c.RunID != runID {
		t.Errorf("the tested requirement was recorded as %+v", c)
	}
	// It was not asked to assess: the untested requirement was not sent, and
	// what the executor claimed about it anyway is not taken.
	if c, ok := got[untested]; ok {
		t.Errorf("the untested requirement was recorded as %+v", c)
	}
	if _, ok := got[999]; ok || len(got) != 1 {
		t.Errorf("recorded %v", got)
	}
	if code, d := rawJSON(t, ts, http.MethodPost, "/api/requirement-runs", map[string]any{"ids": []int{untested}}); code != http.StatusBadRequest {
		t.Errorf("checking only the untested requirement without the model = %d %v", code, d)
	}

	// The list: verdicts, counts, the run — and staleness once a task is done.
	ps, err := state.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	later := time.Now().Add(time.Minute)
	ps.Plan.Tasks[0].Status, ps.Plan.Tasks[0].CompletedAt = "done", &later
	if err := ps.Save(); err != nil {
		t.Fatal(err)
	}
	code, list := rawJSON(t, ts, http.MethodGet, "/api/requirements", nil)
	if code != http.StatusOK {
		t.Fatalf("list = %d %v", code, list)
	}
	raw, _ := json.Marshal(list)
	var parsed requirementsList
	if err := json.Unmarshal(raw, &parsed); err != nil {
		t.Fatal(err)
	}
	if parsed.Counts.Unfulfilled != 1 || parsed.Never != 1 || parsed.Stale != 1 || len(parsed.Runs) != 1 || parsed.Active != nil {
		t.Errorf("list %s", raw)
	}
	if r := parsed.Requirements[0]; r.Stale != "tasks" || r.TasksDoneSince != 1 || r.LastCheck.Tests[0].Output != "" {
		t.Errorf("the tested requirement listed as %+v", r)
	}
}

func TestRequirementsCheckWithTheModelPassesAI(t *testing.T) {
	dir := setupProjectDir(t, "assess", modelCallTasks())
	stub := newModelStub(t)
	ts := modelCallHub(t, dir, stub)
	untested := addRequirementVia(t, ts, map[string]any{"title": "Is pleasant"})
	stub.answer(t, "requirements-check", framed(t, map[string]any{"results": []map[string]any{
		{"requirement_id": untested, "method": "ai", "verdict": "unfulfilled", "summary": "It is not.", "evidence": []string{"ui.go:1"}},
	}}), 0)

	code, d, runID := startRequirementRun(t, ts, map[string]any{"assess": true})
	if code != http.StatusAccepted {
		t.Fatalf("start = %d %v", code, d)
	}
	if run := waitRequirementRun(t, ts, runID); !run.Assess || run.Counts.Unfulfilled != 1 {
		t.Fatalf("run %+v", run)
	}
	if args := strings.Join(stubArgs(t, dir), " "); !strings.Contains(args, "--ai --ai-timeout 5m0s") {
		t.Errorf("the executor was asked %q", args)
	}
	if c := latestChecks(t, dir)[untested]; c.Method != requirements.MethodAI || c.Summary != "It is not." || len(c.Evidence) != 1 {
		t.Errorf("recorded %+v", c)
	}
}

// TestRequirementsCheckThatProducedNoReport: an executor whose cloop predates
// the subcommand, or crashed, leaves each requirement an error naming why —
// never unfulfilled.
func TestRequirementsCheckThatProducedNoReport(t *testing.T) {
	dir := setupProjectDir(t, "old device", modelCallTasks())
	stub := newModelStub(t)
	ts := modelCallHub(t, dir, stub)
	id := addRequirementVia(t, ts, map[string]any{"title": "Builds", "tests": []map[string]any{{"command": "make"}}})

	stub.answer(t, "requirements-check", "Error: unknown command \"requirements\" for \"cloop\"\n", 1)
	_, _, runID := startRequirementRun(t, ts, map[string]any{"ids": []int{id}})
	if run := waitRequirementRun(t, ts, runID); run.State != statedb.RequirementRunDone || run.Counts.Error != 1 {
		t.Fatalf("run %+v", run)
	}
	c := latestChecks(t, dir)[id]
	if c.Verdict != requirements.VerdictError || !strings.Contains(c.Summary, "older than this hub") ||
		len(c.Tests) != 1 || c.Tests[0].Outcome != requirements.OutcomeError {
		t.Errorf("recorded %+v", c)
	}

	stub.answer(t, "requirements-check", framed(t, map[string]string{"error": "requirements: no project"}), 1)
	_, _, runID = startRequirementRun(t, ts, map[string]any{})
	waitRequirementRun(t, ts, runID)
	if c := latestChecks(t, dir)[id]; c.Verdict != requirements.VerdictError || !strings.Contains(c.Summary, "no project") {
		t.Errorf("a framed failure recorded as %+v", c)
	}
}

// TestOneRequirementsCheckAtATimeAndCancel: a second check is refused with
// the one running; Stop ends the running one as cancelled, quickly.
func TestOneRequirementsCheckAtATimeAndCancel(t *testing.T) {
	dir := setupProjectDir(t, "cancel", modelCallTasks())
	stub := newModelStub(t)
	ts := modelCallHub(t, dir, stub)
	addRequirementVia(t, ts, map[string]any{"title": "Slow", "tests": []map[string]any{{"command": "sleep 60"}}})
	stub.script(t, "requirements-check", "sleep 60\n")

	code, d, runID := startRequirementRun(t, ts, map[string]any{})
	if code != http.StatusAccepted {
		t.Fatalf("start = %d %v", code, d)
	}
	code, d, _ = startRequirementRun(t, ts, map[string]any{})
	active, _ := d["active"].(map[string]any)
	if code != http.StatusConflict || active["run_id"] != runID {
		t.Fatalf("a second check = %d %v, want 409 naming %s", code, d, runID)
	}
	code, list := rawJSON(t, ts, http.MethodGet, "/api/requirements", nil)
	if a, _ := list["active"].(map[string]any); code != http.StatusOK || a["run_id"] != runID {
		t.Fatalf("the list does not show the running check: %v", list)
	}

	start := time.Now()
	if code, d := rawJSON(t, ts, http.MethodPost, "/api/requirement-runs/"+runID+"/cancel", map[string]any{}); code != http.StatusOK {
		t.Fatalf("cancel = %d %v", code, d)
	}
	run := waitRequirementRun(t, ts, runID)
	if run.State != statedb.RequirementRunCancelled || time.Since(start) > 20*time.Second {
		t.Fatalf("after Stop the run is %+v, %s later", run, time.Since(start))
	}
	if code, _ := rawJSON(t, ts, http.MethodPost, "/api/requirement-runs/"+runID+"/cancel", map[string]any{}); code != http.StatusConflict {
		t.Errorf("cancelling an ended check = %d", code)
	}
}

// TestShutdownStopsARunningRequirementsCheck: the member that stops records
// why its check ended, rather than leaving it to lapse hours later.
func TestShutdownStopsARunningRequirementsCheck(t *testing.T) {
	dir := setupProjectDir(t, "shutdown", modelCallTasks())
	stub := newModelStub(t)
	srv := New(dir, 0, "")
	srv.SelfExe = stub.exe
	srv.RPS, srv.Burst = 1e6, 1e6
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	addRequirementVia(t, ts, map[string]any{"title": "Slow", "tests": []map[string]any{{"command": "sleep 60"}}})
	stub.script(t, "requirements-check", "sleep 60\n")

	_, _, runID := startRequirementRun(t, ts, map[string]any{})
	srv.reqChecks.stop(20 * time.Second)
	run := waitRequirementRun(t, ts, runID)
	if run.State != statedb.RequirementRunFailed || !strings.Contains(run.Error, "hub stopped") {
		t.Fatalf("after shutdown the run is %+v", run)
	}
}

func TestRequirementsAPIRefusesWhatItCannotStore(t *testing.T) {
	dir := setupProjectDir(t, "validation", modelCallTasks())
	ts := modelCallHub(t, dir, newModelStub(t))

	for name, body := range map[string]map[string]any{
		"no title":      {"title": " "},
		"bad priority":  {"title": "t", "priority": "eventually"},
		"empty command": {"title": "t", "tests": []map[string]any{{"command": ""}}},
		"long command":  {"title": "t", "tests": []map[string]any{{"command": strings.Repeat("x", requirements.MaxCommandBytes+1)}}},
	} {
		if code, d := rawJSON(t, ts, http.MethodPost, "/api/requirements", body); code != http.StatusBadRequest {
			t.Errorf("%s: %d %v, want 400", name, code, d)
		}
	}
	for _, c := range []struct {
		method, path string
		body         any
		want         int
	}{
		{http.MethodPut, "/api/requirements/41", map[string]any{"title": "x"}, http.StatusNotFound},
		{http.MethodDelete, "/api/requirements/41", nil, http.StatusNotFound},
		{http.MethodGet, "/api/requirements/41/checks", nil, http.StatusNotFound},
		{http.MethodGet, "/api/requirements/abc/checks", nil, http.StatusBadRequest},
		{http.MethodPost, "/api/requirements/41/verdict", map[string]any{"verdict": "fulfilled"}, http.StatusNotFound},
		{http.MethodPost, "/api/requirement-runs", map[string]any{}, http.StatusBadRequest},
		{http.MethodPost, "/api/requirement-runs", map[string]any{"ids": []int{41}}, http.StatusNotFound},
		{http.MethodGet, "/api/requirement-runs/nope", nil, http.StatusNotFound},
	} {
		if code, d := rawJSON(t, ts, c.method, c.path, c.body); code != c.want {
			t.Errorf("%s %s = %d %v, want %d", c.method, c.path, code, d, c.want)
		}
	}

	id := addRequirementVia(t, ts, map[string]any{"title": "Real"})
	if code, d := rawJSON(t, ts, http.MethodPost, fmt.Sprintf("/api/requirements/%d/verdict", id), map[string]any{"verdict": "maybe"}); code != http.StatusBadRequest {
		t.Errorf("a verdict of maybe = %d %v", code, d)
	}
	if code, d := rawJSON(t, ts, http.MethodPost, fmt.Sprintf("/api/requirements/%d/task", id), map[string]any{"kind": "party"}); code != http.StatusBadRequest {
		t.Errorf("a task of kind party = %d %v", code, d)
	}
	code, d := rawJSON(t, ts, http.MethodPost, fmt.Sprintf("/api/requirements/%d/task", id), map[string]any{"kind": "test"})
	task, _ := d["task"].(map[string]any)
	if code != http.StatusOK || !strings.HasPrefix(fmt.Sprint(task["title"]), "Add a test for R-") || task["status"] != "pending" {
		t.Fatalf("a test task = %d %v", code, d)
	}
	ps, err := state.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if last := ps.Plan.Tasks[len(ps.Plan.Tasks)-1]; !strings.Contains(last.Description, "single shell command") {
		t.Errorf("the plan's new task: %+v", last)
	}
}

func TestRequirementTaskQuotesTheFailure(t *testing.T) {
	req := requirements.Requirement{ID: 3, Title: "Builds", Priority: requirements.PriorityMust,
		Tests: []requirements.Test{{Command: "go build ./..."}}}
	last := &statedb.RequirementCheck{Verdict: requirements.VerdictUnfulfilled, Method: requirements.MethodTests,
		Summary: "test failed", Tests: []requirements.TestResult{
			{Command: "go build ./...", Outcome: requirements.OutcomeFail, ExitCode: 1, Output: strings.Repeat("x", 5000) + "undefined: Foo"},
		}}
	title, desc, err := requirementTask(req, last, "fix")
	if err != nil || title != "Restore R-3: Builds" || !strings.Contains(desc, "undefined: Foo") ||
		!strings.Contains(desc, "`go build ./...`") || len(desc) > maxRequirementTaskContext+8 {
		t.Fatalf("fix task %q (%d bytes): %v\n%s", title, len(desc), err, desc)
	}
	if p := requirementTaskPriority(req.Priority); p != 1 {
		t.Errorf("a must's task has priority %d", p)
	}
}

func TestRequirementBatchesFitOneArgument(t *testing.T) {
	var reqs []requirements.Requirement
	for i := 1; i <= 80; i++ {
		// As large as Normalize admits: quotes and ampersands, which JSON
		// escaping would inflate, in every field.
		r := requirements.Requirement{ID: i, Title: "t", Description: strings.Repeat(`"é&`, 2600)}
		for j := 0; j < 5; j++ {
			r.Tests = append(r.Tests, requirements.Test{Command: strings.Repeat(`a && "b" `, 300)})
		}
		if err := r.Normalize(); err != nil {
			t.Fatalf("a requirement Normalize admits: %v", err)
		}
		reqs = append(reqs, r)
	}
	batches := requirementBatches(reqs)
	seen := 0
	for _, b := range batches {
		spec, _ := requirements.EncodeSpec(requirements.Spec{Goal: truncateRunes(strings.Repeat(`"`, 9000), maxSpecGoalRunes), Requirements: b})
		if len(spec) > requirements.MaxSpecBytes || len(b) > requirementsBatchSize || oversizedBatch(b) {
			t.Errorf("a batch of %d is %d bytes", len(b), len(spec))
		}
		if _, err := requirements.ParseSpec(spec); err != nil {
			t.Errorf("the executor would refuse the batch: %v", err)
		}
		seen += len(b)
	}
	if seen != len(reqs) || len(batches) < 2 {
		t.Errorf("%d requirements in %d batches", seen, len(batches))
	}
	if d := checkBudget(batches, false); d > maxRequirementsCheckTime {
		t.Errorf("budget %s", d)
	}
}
