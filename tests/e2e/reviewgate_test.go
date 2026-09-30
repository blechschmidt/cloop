package e2e_test

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/clijson"
	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/state"
)

// The review gate end to end (Task 20357), with the real binary: the agent's
// `git push` is rewritten by the gate to cloop's own remote helper and held,
// the reviewer — a different model, called read-only — requests changes, the
// agent is resumed in its own conversation to fix them, and only after the
// reviewer approves does cloop push, at the reviewed commit, to the remote.
//
// `claude` is a stub on PATH that plays both parts: the reviewer when cloop
// calls it with --tools (read-only), the worker otherwise.

const gateStub = `#!/bin/bash
prompt="$(cat)"
args="$*"
if [[ " $args " == *" --tools "* ]]; then
  n=$(cat "$STUB_DIR/reviews" 2>/dev/null || echo 0); n=$((n+1)); echo $n > "$STUB_DIR/reviews"
  echo "review $n: $args" >> "$STUB_DIR/calls.log"
  git -C "$REMOTE" rev-parse refs/heads/main >> "$STUB_DIR/remote-at-review"
  if [ "$n" = 1 ] || [ -n "$STUB_REJECT" ]; then
    echo '{"verdict":"request_changes","summary":"hello.txt greets nobody.","findings":[{"severity":"major","file":"hello.txt","line":1,"title":"missing name","detail":"greet the world"}]}'
  else
    echo '{"verdict":"approve","summary":"Fixed."}'
  fi
  exit 0
fi
echo "work: $args" >> "$STUB_DIR/calls.log"
if [[ "$prompt" == *"requested changes"* ]]; then
  echo "hello, world" > hello.txt; msg="greet the world"
else
  echo "hello" > hello.txt; msg="add hello"
fi
git add hello.txt && git commit -q -m "$msg"
git push >> "$STUB_DIR/push.log" 2>&1
echo "push exit $?" >> "$STUB_DIR/push.log"
echo "Committed and pushed."
echo "TASK_DONE"
`

type gateE2E struct {
	project, remote, stubDir string
	initial                  string
}

func setupGateE2E(t *testing.T) gateE2E {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}
	base := newWorkDir(t)
	g := gateE2E{remote: filepath.Join(base, "remote.git"), project: filepath.Join(base, "project"), stubDir: filepath.Join(base, "stub")}
	git := func(dir string, args ...string) string {
		t.Helper()
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
		return strings.TrimSpace(string(out))
	}
	git(base, "init", "-q", "--bare", "-b", "main", g.remote)
	git(base, "clone", "-q", g.remote, g.project)
	git(g.project, "checkout", "-q", "-b", "main")
	git(g.project, "config", "user.email", "agent@example.com")
	git(g.project, "config", "user.name", "agent")
	git(g.project, "config", "commit.gpgsign", "false")
	if err := os.WriteFile(filepath.Join(g.project, ".gitignore"), []byte(".cloop/\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	git(g.project, "add", ".gitignore")
	git(g.project, "commit", "-q", "-m", "initial")
	git(g.project, "push", "-q", "-u", "origin", "main")
	g.initial = git(g.remote, "rev-parse", "refs/heads/main")

	if err := os.MkdirAll(g.stubDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(g.stubDir, "claude"), []byte(gateStub), 0o755); err != nil {
		t.Fatal(err)
	}

	mustRun(t, g.project, "init", "--provider", "claudecode", "--skip-clarify", "Say hello")
	mustRun(t, g.project, "task", "add", "Write hello.txt", "--no-ai", "--auto")
	return g
}

// run runs the cloop binary with the stub claude first on PATH.
func (g gateE2E) run(t *testing.T, extraEnv []string, args ...string) (string, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, binaryPath(t), args...)
	cmd.Dir = g.project
	cmd.Env = append(os.Environ(), "NO_COLOR=1", "TERM=dumb",
		"PATH="+g.stubDir+string(os.PathListSeparator)+os.Getenv("PATH"),
		"STUB_DIR="+g.stubDir, "REMOTE="+g.remote)
	cmd.Env = append(cmd.Env, extraEnv...)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func (g gateE2E) remoteFile(t *testing.T, name string) string {
	t.Helper()
	out, err := exec.Command("git", "-C", g.remote, "show", "refs/heads/main:"+name).CombinedOutput()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	b, _ := os.ReadFile(path)
	return string(b)
}

func TestE2EReviewGateHoldsPushesUntilApproval(t *testing.T) {
	g := setupGateE2E(t)

	out := mustRun(t, g.project, "review", "gate", "--enable", "--provider", "claudecode",
		"--model", "reviewer-model", "--mode", "fix", "--json")
	var shown pm.ReviewGate
	if err := clijson.Unmarshal([]byte(out), &shown); err != nil || !shown.Enabled || shown.Model != "reviewer-model" {
		t.Fatalf("review gate --json = %q (%v)", out, err)
	}

	runOut, err := g.run(t, nil, "run")
	if err != nil {
		t.Fatalf("cloop run: %v\n%s", err, runOut)
	}

	// Every push the agent made was held, not sent.
	pushes := readFile(t, filepath.Join(g.stubDir, "push.log"))
	if strings.Count(pushes, "held by cloop's review gate") != 2 || strings.Contains(pushes, "push exit 0") {
		t.Fatalf("the agent's pushes were not held:\n%s", pushes)
	}
	// The remote had not moved at either review.
	for _, sha := range strings.Fields(readFile(t, filepath.Join(g.stubDir, "remote-at-review"))) {
		if sha != g.initial {
			t.Fatalf("the remote moved before the reviewer approved: %s", sha)
		}
	}
	// After approval, cloop pushed the fixed, reviewed work.
	if got := g.remoteFile(t, "hello.txt"); got != "hello, world" {
		t.Fatalf("remote hello.txt = %q, want the reviewed fix\nrun output:\n%s", got, runOut)
	}

	calls := readFile(t, filepath.Join(g.stubDir, "calls.log"))
	lines := strings.Split(strings.TrimSpace(calls), "\n")
	if len(lines) != 4 {
		t.Fatalf("calls:\n%s", calls)
	}
	// work, review 1, fix (resumed), review 2
	session := regexp.MustCompile(`--session-id ([0-9a-f-]{36})`).FindStringSubmatch(lines[0])
	if session == nil {
		t.Fatalf("the worker's first call has no session id: %s", lines[0])
	}
	if !strings.HasPrefix(lines[2], "work:") || !strings.Contains(lines[2], "--resume "+session[1]) {
		t.Errorf("the fix round did not resume the agent's conversation:\n%s", calls)
	}
	for _, i := range []int{1, 3} {
		l := lines[i]
		if !strings.HasPrefix(l, "review") || !strings.Contains(l, "--tools Read,Grep,Glob") ||
			!strings.Contains(l, "--model reviewer-model") || !strings.Contains(l, "--strict-mcp-config") {
			t.Errorf("review call is not the configured read-only reviewer: %s", l)
		}
	}

	s, err := state.Load(g.project)
	if err != nil {
		t.Fatal(err)
	}
	task := s.Plan.TaskByID(1)
	if task == nil || task.Status != pm.TaskDone {
		t.Fatalf("task = %+v", task)
	}
	r := task.Review
	if r == nil || r.Verdict != pm.ReviewApproved || r.FixRounds != 1 || r.Rounds != 2 || r.Model != "reviewer-model" {
		t.Fatalf("review record = %+v", r)
	}
	if len(r.Published) != 1 || r.Published[0].Outcome != pm.PublishPushed || r.Published[0].Ref != "refs/heads/main" {
		t.Fatalf("publish record = %+v", r.Published)
	}
	head := strings.TrimSpace(func() string {
		b, _ := exec.Command("git", "-C", g.remote, "rev-parse", "refs/heads/main").Output()
		return string(b)
	}())
	if r.Published[0].Commit != head {
		t.Errorf("recorded pushed commit %s, remote is at %s", r.Published[0].Commit, head)
	}
}

func TestE2EReviewGateBlockLeavesTheRemoteAlone(t *testing.T) {
	g := setupGateE2E(t)
	mustRun(t, g.project, "review", "gate", "--enable", "--mode", "block")

	runOut, _ := g.run(t, []string{"STUB_REJECT=1"}, "run")

	if got := g.remoteFile(t, "hello.txt"); got != "" {
		t.Fatalf("a rejected task's work reached the remote: %q\n%s", got, runOut)
	}
	s, err := state.Load(g.project)
	if err != nil {
		t.Fatal(err)
	}
	task := s.Plan.TaskByID(1)
	if task == nil || task.Status != pm.TaskFailed || task.Review == nil || !task.Review.Blocked {
		t.Fatalf("task = %+v", task)
	}
	if len(task.Review.Published) != 1 || task.Review.Published[0].Outcome != pm.PublishWithheld {
		t.Errorf("publish record = %+v", task.Review.Published)
	}
	if !strings.Contains(task.FailureDiagnosis, "missing name") {
		t.Errorf("diagnosis = %q", task.FailureDiagnosis)
	}
	// The commit is still there locally, for a person to look at.
	if b, _ := os.ReadFile(filepath.Join(g.project, "hello.txt")); strings.TrimSpace(string(b)) != "hello" {
		t.Errorf("local work was discarded: %q", b)
	}
}
