package cmd

// `cloop requirements` (Task 20458), run as a person runs it and as the hub
// runs it: this test binary acting as cloop, in the project directory. The
// last test is the whole chain — a hub with single sign-on in this process
// dispatching the real `cloop requirements check` to its executor, with a
// stand-in `claude` answering for the requirement nothing tests.

import (
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/internal/ssohubtest"
	"github.com/blechschmidt/cloop/pkg/claudecodeauth"
	"github.com/blechschmidt/cloop/pkg/clijson"
	"github.com/blechschmidt/cloop/pkg/requirements"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

func reqTestProject(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if _, err := state.Init(dir, "requirements", 0); err != nil {
		t.Fatal(err)
	}
	return dir
}

func mustRun(t *testing.T, exe, dir string, args ...string) string {
	t.Helper()
	out, err := runHelper(t, exe, dir, args...)
	if err != nil {
		t.Fatalf("cloop %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return string(out)
}

func projectChecks(t *testing.T, dir string, id int) []statedb.RequirementCheck {
	t.Helper()
	db, err := statedb.Open(state.DBPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	checks, err := db.RequirementChecks(id, 0)
	if err != nil {
		t.Fatal(err)
	}
	return checks
}

func TestRequirementsCommandsByHand(t *testing.T) {
	exe := cliSelfExe(t)
	dir := reqTestProject(t)

	mustRun(t, exe, dir, "requirements", "add", "Passes", "--test", "echo all good", "--priority", "must", "--tag", "core")
	mustRun(t, exe, dir, "requirements", "add", "Fails", "-d", "It must not.", "--test", "echo broken >&2; exit 4")
	if out := mustRun(t, exe, dir, "requirements", "add", "Nobody tests this"); !strings.Contains(out, "no tests") {
		t.Errorf("adding an untested requirement said nothing of it:\n%s", out)
	}
	if out, err := runHelper(t, exe, dir, "requirements", "add", "Bad", "--priority", "whenever"); err == nil {
		t.Errorf("an invalid priority was taken:\n%s", out)
	}

	// A check that finds a requirement unfulfilled exits 1: it can gate CI.
	out, err := runHelper(t, exe, dir, "requirements", "check")
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 1 {
		t.Fatalf("check exited %v, want 1:\n%s", err, out)
	}
	for _, want := range []string{"R-1", "fulfilled", "R-2", "unfulfilled", "(exit 4)", "R-3", "skipped", "1 fulfilled, 1 unfulfilled, 0 unverified, 0 errors"} {
		if !strings.Contains(string(out), want) {
			t.Errorf("check output lacks %q:\n%s", want, out)
		}
	}
	checks := projectChecks(t, dir, 2)
	if len(checks) != 1 || checks[0].Verdict != requirements.VerdictUnfulfilled || !strings.Contains(checks[0].Tests[0].Output, "broken") ||
		checks[0].ExecutorID != "local" || !strings.HasPrefix(checks[0].CheckedBy, "cli:") {
		t.Fatalf("R-2's recorded check: %+v", checks)
	}
	if n := len(projectChecks(t, dir, 3)); n != 0 {
		t.Errorf("the untested R-3 got %d checks from a check that could not test it", n)
	}
	// One requirement, by key; it passes, so the check does.
	mustRun(t, exe, dir, "requirements", "check", "R-1")
	if n := len(projectChecks(t, dir, 1)); n != 2 {
		t.Errorf("R-1 has %d checks after two runs", n)
	}

	// A person's verdict on R-3 survives a later check that has nothing to
	// run for it.
	mustRun(t, exe, dir, "requirements", "verdict", "3", "fulfilled", "--note", "read the code")
	if out, err := runHelper(t, exe, dir, "requirements", "check"); err == nil || !strings.Contains(string(out), "skipped") {
		t.Fatalf("the second full check: %v\n%s", err, out)
	}
	list := mustRun(t, exe, dir, "requirements", "list", "--json")
	var listed struct {
		Requirements []struct {
			ID        int                       `json:"id"`
			LastCheck *statedb.RequirementCheck `json:"last_check"`
			Stale     bool                      `json:"stale"`
		} `json:"requirements"`
	}
	if err := json.Unmarshal([]byte(list), &listed); err != nil || len(listed.Requirements) != 3 {
		t.Fatalf("list --json: %v\n%s", err, list)
	}
	if lc := listed.Requirements[2].LastCheck; lc == nil || lc.Method != requirements.MethodManual || lc.Verdict != requirements.VerdictFulfilled {
		t.Errorf("R-3's verdict reads %+v", lc)
	}

	// Changing what R-2 says makes its verdict stale; removing its tests
	// leaves it untested.
	mustRun(t, exe, dir, "requirements", "edit", "2", "--clear-tests", "--title", "Fails no more")
	if out := mustRun(t, exe, dir, "requirements", "list"); !strings.Contains(out, "stale") || !strings.Contains(out, "Fails no more") {
		t.Errorf("after the edit:\n%s", out)
	}
	if out := mustRun(t, exe, dir, "requirements", "show", "2"); !strings.Contains(out, "stale") || !strings.Contains(out, "No tests") {
		t.Errorf("show after the edit:\n%s", out)
	}
	if out := mustRun(t, exe, dir, "requirements", "history", "1", "--limit", "1"); strings.Count(out, "fulfilled") != 1 {
		t.Errorf("history --limit 1:\n%s", out)
	}
	mustRun(t, exe, dir, "requirements", "rm", "2")
	if out, err := runHelper(t, exe, dir, "requirements", "show", "2"); err == nil {
		t.Errorf("a removed requirement still shows:\n%s", out)
	}
}

// TestRequirementsCheckAsTheHubRunsIt: --spec, --json and --no-record — the
// requirements the hub sent, a framed report back, and nothing written here.
func TestRequirementsCheckAsTheHubRunsIt(t *testing.T) {
	exe := cliSelfExe(t)
	dir := reqTestProject(t)
	spec, _ := json.Marshal(requirements.Spec{Goal: "g", Requirements: []requirements.Requirement{
		{ID: 7, Title: "seven", Tests: []requirements.Test{{Command: "echo the hub asked for this; exit 0"}}},
		{ID: 9, Title: "nine", Tests: []requirements.Test{{Command: "exit 3"}}},
	}})
	out := mustRun(t, exe, dir, "requirements", "check", "--json", "--no-record", "--spec="+string(spec))
	var rep requirements.Report
	if err := clijson.Unmarshal([]byte(out), &rep); err != nil {
		t.Fatalf("no framed report: %v\n%s", err, out)
	}
	if len(rep.Results) != 2 || rep.Results[0].RequirementID != 7 || rep.Results[0].Verdict != requirements.VerdictFulfilled ||
		rep.Results[1].Verdict != requirements.VerdictUnfulfilled || rep.Results[1].Tests[0].ExitCode != 3 {
		t.Fatalf("report %+v", rep)
	}
	if checks := projectChecks(t, dir, 7); len(checks) != 0 {
		t.Errorf("--no-record recorded %d checks", len(checks))
	}

	out2, err := runHelper(t, exe, dir, "requirements", "check", "--json", "--no-record", `--spec={"requirements":[{"title":"no id"}]}`)
	payload, perr := clijson.Extract(out2)
	if err == nil || perr != nil || !strings.Contains(string(payload), `"error"`) {
		t.Fatalf("an invalid spec: %v, %v\n%s", err, perr, out2)
	}
}

// requirementsClaude is a stand-in `claude` that answers an assessment, and
// records the CLAUDE_CONFIG_DIR it ran on.
func requirementsClaude(t *testing.T) (log string) {
	t.Helper()
	bin := t.TempDir()
	log = filepath.Join(t.TempDir(), "claude.log")
	script := `#!/bin/sh
prompt=$(cat)
echo "${CLAUDE_CONFIG_DIR-<unset>}" >> ` + quoteArg(log) + `
case "$prompt" in
*"fulfils one of its requirements"*)
  echo 'Looked at it. {"verdict":"unfulfilled","rationale":"Nothing handles the error.","evidence":["main.go:3 — no check"]}' ;;
*) echo 'unexpected prompt' ;;
esac
`
	if err := os.WriteFile(filepath.Join(bin, "claude"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	return log
}

func TestRequirementsCheckAsksTheModelAboutTheUntested(t *testing.T) {
	requirementsClaude(t)
	exe := cliSelfExe(t)
	dir := helperProject(t, "claudecode")
	mustRun(t, exe, dir, "requirements", "add", "Errors are handled", "-d", "Every error is checked.")
	out, err := runHelper(t, exe, dir, "requirements", "check", "--ai")
	if err == nil || !strings.Contains(string(out), "Nothing handles the error.") {
		t.Fatalf("check --ai: %v\n%s", err, out)
	}
	c := projectChecks(t, dir, 1)
	if len(c) != 1 || c[0].Method != requirements.MethodAI || c[0].Verdict != requirements.VerdictUnfulfilled || len(c[0].Evidence) != 1 {
		t.Fatalf("recorded %+v", c)
	}
}

// TestTheDashboardChecksRequirementsOnTheExecutor is the whole chain: the
// Requirements tab's check, dispatched by a hub with sign-on to its executor
// as the real `cloop requirements check`, recorded from the report it sends
// back — the model's assessment made on the caller's own Claude account.
func TestTheDashboardChecksRequirementsOnTheExecutor(t *testing.T) {
	log := requirementsClaude(t)
	hub := ssohubtest.Start(t, ssohubtest.Options{SelfExe: cliSelfExe(t), AdminEmails: []string{rootEmail}})
	if err := os.WriteFile(filepath.Join(hub.Dir, ".cloop", "config.yaml"), []byte("provider: claudecode\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(hub.Dir, "probe.txt"), []byte("present"), 0o600); err != nil {
		t.Fatal(err)
	}
	const alice, vic = "alice@example.com", "vic@example.com"
	op := hub.SignIn(t, alice, ssohubtest.GroupOperators)
	viewer := hub.SignIn(t, vic, ssohubtest.GroupViewers)

	add := func(body map[string]any) int {
		t.Helper()
		code, raw := hubCall(t, hub, op, http.MethodPost, "/api/requirements", body)
		var d struct {
			Requirement requirements.Requirement `json:"requirement"`
		}
		if code != http.StatusOK || json.Unmarshal(raw, &d) != nil {
			t.Fatalf("add %v = %d %s", body, code, raw)
		}
		return d.Requirement.ID
	}
	pass := add(map[string]any{"title": "The probe is there", "tests": []map[string]any{{"command": "test -f probe.txt"}}})
	fail := add(map[string]any{"title": "Nothing is missing", "tests": []map[string]any{{"command": "cat missing.txt"}}})
	untested := add(map[string]any{"title": "Errors are handled", "description": "Every error is checked."})

	// A viewer may read the requirements and may not check them.
	if code, raw := hubCall(t, hub, viewer, http.MethodGet, "/api/requirements", nil); code != http.StatusOK {
		t.Fatalf("a viewer's list = %d %s", code, raw)
	}
	if code, _ := hubCall(t, hub, viewer, http.MethodPost, "/api/requirement-runs", map[string]any{}); code != http.StatusForbidden {
		t.Fatalf("a viewer started a check: %d", code)
	}

	code, raw := hubCall(t, hub, op, http.MethodPost, "/api/requirement-runs", map[string]any{"assess": true})
	if code != http.StatusAccepted {
		t.Fatalf("start = %d %s", code, raw)
	}
	var started struct {
		Run statedb.RequirementRun `json:"run"`
	}
	if err := json.Unmarshal(raw, &started); err != nil || !started.Run.Assess {
		t.Fatalf("start answered %s (%v)", raw, err)
	}

	var run statedb.RequirementRun
	deadline := time.Now().Add(2 * time.Minute)
	for {
		code, raw = hubCall(t, hub, op, http.MethodGet, "/api/requirement-runs/"+started.Run.RunID, nil)
		var d struct {
			Run statedb.RequirementRun `json:"run"`
		}
		if code != http.StatusOK || json.Unmarshal(raw, &d) != nil {
			t.Fatalf("run = %d %s", code, raw)
		}
		if run = d.Run; run.State != statedb.RequirementRunRunning {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the check is still running after two minutes: %+v", run)
		}
		time.Sleep(100 * time.Millisecond)
	}
	if run.State != statedb.RequirementRunDone || run.Counts.Fulfilled != 1 || run.Counts.Unfulfilled != 2 {
		t.Fatalf("the run ended %+v", run)
	}

	verdicts := map[int]statedb.RequirementCheck{}
	for _, id := range []int{pass, fail, untested} {
		c := projectChecks(t, hub.Dir, id)
		if len(c) != 1 {
			t.Fatalf("R-%d has %d checks", id, len(c))
		}
		verdicts[id] = c[0]
	}
	if c := verdicts[pass]; c.Verdict != requirements.VerdictFulfilled || c.CheckedBy != alice || c.RunID != run.RunID {
		t.Errorf("the passing requirement: %+v", c)
	}
	if c := verdicts[fail]; c.Verdict != requirements.VerdictUnfulfilled || !strings.Contains(c.Tests[0].Output, "missing.txt") {
		t.Errorf("the failing requirement: %+v", c)
	}
	if c := verdicts[untested]; c.Verdict != requirements.VerdictUnfulfilled || c.Method != requirements.MethodAI ||
		c.Summary != "Nothing handles the error." {
		t.Errorf("the untested requirement: %+v", c)
	}

	// The model was asked on alice's own Claude account.
	raw2, err := os.ReadFile(log)
	if err != nil {
		t.Fatal(err)
	}
	home, err := claudecodeauth.HomeFor(alice)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.TrimSpace(string(raw2)); got != home {
		t.Errorf("the assessment ran on CLAUDE_CONFIG_DIR %q, want alice's %q", got, home)
	}

	// The list carries the verdicts, and no test output.
	code, raw = hubCall(t, hub, op, http.MethodGet, "/api/requirements", nil)
	if code != http.StatusOK || !strings.Contains(string(raw), `"verdict":"unfulfilled"`) || strings.Contains(string(raw), "No such file") {
		t.Errorf("the list = %d %s", code, raw)
	}
	// And a fix task quotes what failed.
	code, raw = hubCall(t, hub, op, http.MethodPost, "/api/requirements/"+strconv.Itoa(fail)+"/task", map[string]any{"kind": "fix"})
	if code != http.StatusOK || !strings.Contains(string(raw), "No such file") || !strings.Contains(string(raw), "Restore R-") {
		t.Errorf("fix task = %d %s", code, raw)
	}
}
