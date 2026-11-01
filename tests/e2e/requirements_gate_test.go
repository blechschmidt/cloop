package e2e_test

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/clijson"
	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// The requirements gate end to end (Task 20461), with the real binary and a
// stub `claude` on PATH. The project keeps R-1, "feature.txt says done",
// tested by `grep -qx done feature.txt`; the task implements it. The stub is
// the agent: it writes feature.txt — "wip" unless its prompt tells it the
// requirements failed, or STUB_GOOD says to get it right the first time — and,
// with STUB_BREAK, also breaks the project's must requirement R-2 by creating
// broken.txt. It always ends with TASK_DONE: whether the task is done is the
// gate's to say, and the gate runs `cloop requirements check` — this binary —
// for real, in the project.

const requirementsGateStub = `#!/bin/bash
prompt="$(cat)"
n=$(( $(cat "$STUB_DIR/count" 2>/dev/null || echo 0) + 1 ))
echo "$n" > "$STUB_DIR/count"
printf '%s' "$prompt" > "$STUB_DIR/prompt.$n"
if [[ -n "$STUB_GOOD" || "$prompt" == *"REQUIREMENTS NOT MET ON THE LAST ATTEMPT"* ]]; then
  echo done > feature.txt
else
  echo wip > feature.txt
fi
if [ -n "$STUB_BREAK" ]; then
  touch broken.txt
fi
echo "Wrote feature.txt."
echo "TASK_DONE"
`

type reqGateE2E struct {
	project, stubDir string
}

func setupReqGateE2E(t *testing.T, gateMode string) reqGateE2E {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}
	base := newWorkDir(t)
	g := reqGateE2E{project: filepath.Join(base, "project"), stubDir: filepath.Join(base, "stub")}
	for _, d := range []string{g.project, g.stubDir} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	git := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", args...)
		cmd.Dir = g.project
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	git("init", "-q", "-b", "main")
	git("config", "user.email", "agent@example.com")
	git("config", "user.name", "agent")
	git("config", "commit.gpgsign", "false")
	if err := os.WriteFile(filepath.Join(g.project, ".gitignore"), []byte(".cloop/\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	git("add", ".gitignore")
	git("commit", "-q", "-m", "initial")
	if err := os.WriteFile(filepath.Join(g.stubDir, "claude"), []byte(requirementsGateStub), 0o755); err != nil {
		t.Fatal(err)
	}

	mustRun(t, g.project, "init", "--provider", "claudecode", "--skip-clarify", "Ship the feature")
	mustRun(t, g.project, "requirements", "add", "feature.txt says done", "--test", "grep -qx done feature.txt")
	mustRun(t, g.project, "requirements", "add", "Nothing is broken", "--priority", "must", "--test", "test ! -e broken.txt")
	mustRun(t, g.project, "task", "add", "Write feature.txt", "--no-ai", "--auto", "--requirement", "1")
	if gateMode != "" {
		mustRun(t, g.project, "requirements", "gate", gateMode)
	}
	return g
}

func (g reqGateE2E) run(t *testing.T, extraEnv []string, args ...string) (string, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, binaryPath(t), args...)
	cmd.Dir = g.project
	cmd.Env = append(os.Environ(), "NO_COLOR=1", "TERM=dumb",
		"PATH="+g.stubDir+string(os.PathListSeparator)+os.Getenv("PATH"), "STUB_DIR="+g.stubDir)
	cmd.Env = append(cmd.Env, extraEnv...)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func (g reqGateE2E) calls(t *testing.T) int {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(g.stubDir, "count"))
	if err != nil {
		return 0
	}
	n, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil {
		t.Fatalf("the stub's count: %v", err)
	}
	return n
}

func (g reqGateE2E) prompt(t *testing.T, n int) string {
	t.Helper()
	return readFile(t, filepath.Join(g.stubDir, "prompt."+strconv.Itoa(n)))
}

func (g reqGateE2E) task(t *testing.T) *pm.Task {
	t.Helper()
	s, err := state.Load(g.project)
	if err != nil {
		t.Fatal(err)
	}
	task := s.Plan.TaskByID(1)
	if task == nil {
		t.Fatal("task 1 is missing")
	}
	return task
}

// history is what `cloop requirements history <id> --json` prints.
func (g reqGateE2E) history(t *testing.T, id string) []statedb.RequirementCheck {
	t.Helper()
	out := mustRun(t, g.project, "requirements", "history", id, "--json")
	var doc struct {
		Checks []statedb.RequirementCheck `json:"checks"`
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("history %s --json: %v\n%s", id, err, out)
	}
	return doc.Checks
}

func (g reqGateE2E) events(t *testing.T, typ state.EventType) []state.EventRow {
	t.Helper()
	rows, _, err := state.ListEvents(g.project, 0, 500)
	if err != nil {
		t.Fatal(err)
	}
	var out []state.EventRow
	for _, r := range rows {
		if r.Type == typ {
			out = append(out, r)
		}
	}
	return out
}

// Pass: the agent gets it right, the gate runs R-1's test for real and lets
// the task through, and the check is recorded against the task and the
// commit.
func TestE2ERequirementsGatePass(t *testing.T) {
	g := setupReqGateE2E(t, "linked")
	out, err := g.run(t, []string{"STUB_GOOD=1"}, "run")
	if err != nil {
		t.Fatalf("cloop run: %v\n%s", err, out)
	}
	if n := g.calls(t); n != 1 {
		t.Fatalf("the agent ran %d times, want once\n%s", n, out)
	}
	task := g.task(t)
	if task.Status != pm.TaskDone || !task.RequirementsCheck.Met() {
		t.Fatalf("task = %s, check = %+v\n%s", task.Status, task.RequirementsCheck, out)
	}
	if !strings.Contains(out, "Requirements gate: checking R-1 for task 1") {
		t.Errorf("the run did not say it checked R-1:\n%s", out)
	}
	checks := g.history(t, "1")
	if len(checks) != 1 || checks[0].TaskID != 1 || checks[0].Verdict != "fulfilled" || checks[0].Commit == "" ||
		checks[0].Tests[0].Command != "grep -qx done feature.txt" {
		t.Fatalf("R-1's checks = %+v", checks)
	}
	status := mustRun(t, g.project, "status")
	if !strings.Contains(status, "Done:     only once its linked requirements pass") {
		t.Errorf("cloop status does not show the gate:\n%s", status)
	}
	var gate pm.RequirementsGate
	if err := clijson.Unmarshal([]byte(mustRun(t, g.project, "requirements", "gate", "--json")), &gate); err != nil ||
		gate.EffectiveMode() != pm.RequirementsGateLinked {
		t.Errorf("requirements gate --json = %+v, %v", gate, err)
	}
}

// Fail, then retry: the first attempt's work fails R-1's test, so the task
// goes back to pending with the command and its result in the next prompt;
// the retry fixes it and the task is done.
func TestE2ERequirementsGateFailThenRetry(t *testing.T) {
	g := setupReqGateE2E(t, "linked")
	out, err := g.run(t, nil, "run")
	if err != nil {
		t.Fatalf("cloop run: %v\n%s", err, out)
	}
	if n := g.calls(t); n != 2 {
		t.Fatalf("the agent ran %d times, want the task and its retry\n%s", n, out)
	}
	if strings.Contains(g.prompt(t, 1), "REQUIREMENTS NOT MET") {
		t.Error("the first attempt was told about a failure that had not happened")
	}
	retry := g.prompt(t, 2)
	for _, want := range []string{"## REQUIREMENTS NOT MET ON THE LAST ATTEMPT", "R-1 feature.txt says done",
		"$ grep -qx done feature.txt", "exited 1"} {
		if !strings.Contains(retry, want) {
			t.Errorf("the retry's prompt does not say %q:\n%s", want, retry)
		}
	}
	task := g.task(t)
	if task.Status != pm.TaskDone || !task.RequirementsCheck.Met() {
		t.Fatalf("task = %s, check = %+v\n%s", task.Status, task.RequirementsCheck, out)
	}
	checks := g.history(t, "1")
	if len(checks) != 2 || checks[0].Verdict != "fulfilled" || checks[1].Verdict != "unfulfilled" ||
		checks[1].TaskID != 1 || checks[1].Regression {
		t.Fatalf("R-1's checks = %+v", checks)
	}
	rows := g.events(t, state.EventTaskRequirements)
	requeued := 0
	for _, r := range rows {
		if strings.Contains(r.Message, "Task back to pending.") {
			requeued++
		}
	}
	if len(rows) != 2 || requeued != 1 {
		t.Errorf("journal = %+v", rows)
	}
}

// A regression: R-2, a must requirement the task does not implement, passed
// before the run. The agent breaks it on every attempt, so in linked+must
// mode the task is sent back, and once the retries are spent it fails with
// requirements_unmet — the regression on the check, on the task and in the
// event history.
func TestE2ERequirementsGateRegression(t *testing.T) {
	g := setupReqGateE2E(t, "linked+must")
	// R-2 passes as the project stands.
	if out, err := g.run(t, nil, "requirements", "check", "2"); err != nil {
		t.Fatalf("baseline check: %v\n%s", err, out)
	}
	out, err := g.run(t, []string{"STUB_GOOD=1", "STUB_BREAK=1"}, "run", "--max-verify-retries", "1")
	if err != nil {
		t.Fatalf("cloop run: %v\n%s", err, out)
	}
	if n := g.calls(t); n != 2 {
		t.Fatalf("the agent ran %d times, want the task and one retry\n%s", n, out)
	}
	if retry := g.prompt(t, 2); !strings.Contains(retry, "R-2 Nothing is broken — unfulfilled (regression") ||
		!strings.Contains(retry, "[a must requirement of the project]") {
		t.Errorf("the retry was not told about the regression:\n%s", retry)
	}
	task := g.task(t)
	if task.Status != pm.TaskFailed {
		t.Fatalf("task = %s, want failed\n%s", task.Status, out)
	}
	rc := task.RequirementsCheck
	if !rc.Unmet() || len(rc.Regressions()) != 1 || rc.Regressions()[0].RequirementID != 2 {
		t.Fatalf("the task's record = %+v", rc)
	}
	if !strings.Contains(task.FailureDiagnosis, "test ! -e broken.txt") {
		t.Errorf("diagnosis = %q", task.FailureDiagnosis)
	}
	if !hasNote(task, "requirements_unmet") {
		t.Errorf("no note of requirements_unmet: %+v", task.Annotations)
	}
	// Newest first: the retry's check, where the regression persisted; the
	// first attempt's, where it happened; the baseline, which gated no task.
	checks := g.history(t, "2")
	if len(checks) != 3 || !checks[0].Regression || !checks[0].Persisting || !checks[1].Regression || checks[1].Persisting ||
		checks[1].TaskID != 1 || checks[2].TaskID != 0 || checks[2].Verdict != "fulfilled" {
		t.Fatalf("R-2's checks = %+v", checks)
	}
	// The event history reports the regression once, where it happened.
	rows := g.events(t, state.EventRequirementRegression)
	if len(rows) != 1 || rows[0].TaskID != 1 || !strings.Contains(rows[0].Message, "R-2 Nothing is broken regressed") {
		t.Fatalf("event history = %+v", rows)
	}
}

func hasNote(task *pm.Task, needle string) bool {
	for _, a := range task.Annotations {
		if strings.Contains(a.Text, needle) {
			return true
		}
	}
	return false
}

// The gate switched off: the same failing work is taken at the agent's word,
// and nothing is checked.
func TestE2ERequirementsGateOff(t *testing.T) {
	g := setupReqGateE2E(t, "off")
	out, err := g.run(t, nil, "run")
	if err != nil {
		t.Fatalf("cloop run: %v\n%s", err, out)
	}
	if n := g.calls(t); n != 1 {
		t.Fatalf("the agent ran %d times, want once\n%s", n, out)
	}
	task := g.task(t)
	if task.Status != pm.TaskDone || task.RequirementsCheck != nil {
		t.Fatalf("task = %s, check = %+v", task.Status, task.RequirementsCheck)
	}
	if strings.Contains(out, "Requirements gate") {
		t.Errorf("the gate ran while off:\n%s", out)
	}
	if checks := g.history(t, "1"); len(checks) != 0 {
		t.Errorf("checks were recorded with the gate off: %+v", checks)
	}
}

// A config.yaml that declares the gate is applied when a run starts.
func TestE2ERequirementsGateFromConfig(t *testing.T) {
	g := setupReqGateE2E(t, "")
	mustRun(t, g.project, "config", "set", "requirements.gate", "linked")
	out, err := g.run(t, []string{"STUB_GOOD=1"}, "run")
	if err != nil {
		t.Fatalf("cloop run: %v\n%s", err, out)
	}
	if task := g.task(t); task.Status != pm.TaskDone || !task.RequirementsCheck.Met() {
		t.Fatalf("the declared gate did not check the task: %s %+v\n%s", task.Status, task.RequirementsCheck, out)
	}
	if out, err := run(t, g.project, "config", "set", "requirements.gate", "sometimes"); err == nil {
		t.Errorf("config set accepted an unknown mode:\n%s", out)
	}
}
