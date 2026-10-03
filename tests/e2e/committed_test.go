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
	"github.com/blechschmidt/cloop/pkg/pausereason"
	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/state"
)

// "Done means committed" end to end (Task 20370), with the real binary and a
// stub `claude` on PATH. The stub plays the agent that stranded Task 20368: it
// does the work, says it is drafting the commit message, and ends its turn
// with TASK_DONE — work uncommitted. Handed its turn back with the paths named,
// it commits and pushes.

const committedStub = `#!/bin/bash
prompt="$(cat)"
echo "call: $*" >> "$STUB_DIR/calls.log"
if [[ "$prompt" == *"only once its work is committed"* ]]; then
  printf '%s' "$prompt" > "$STUB_DIR/handback.txt"
  if [ -z "$STUB_NEVER" ]; then
    git add feature.txt && git commit -q -m "add the feature" && git push -q
    echo "Committed and pushed."
  else
    echo "I will get to the commit later."
  fi
  echo "TASK_DONE"
  exit 0
fi
echo "feature" > feature.txt
echo "The commit message is drafted. I'll re-run the suite, then commit and push."
echo "TASK_DONE"
`

type committedE2E struct {
	project, remote, stubDir string
}

func setupCommittedE2E(t *testing.T) committedE2E {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}
	base := newWorkDir(t)
	c := committedE2E{remote: filepath.Join(base, "remote.git"), project: filepath.Join(base, "project"), stubDir: filepath.Join(base, "stub")}
	git := func(dir string, args ...string) {
		t.Helper()
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	git(base, "init", "-q", "--bare", "-b", "main", c.remote)
	git(base, "clone", "-q", c.remote, c.project)
	git(c.project, "checkout", "-q", "-b", "main")
	git(c.project, "config", "user.email", "agent@example.com")
	git(c.project, "config", "user.name", "agent")
	git(c.project, "config", "commit.gpgsign", "false")
	if err := os.WriteFile(filepath.Join(c.project, ".gitignore"), []byte(".cloop/\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	git(c.project, "add", ".gitignore")
	git(c.project, "commit", "-q", "-m", "initial")
	git(c.project, "push", "-q", "-u", "origin", "main")

	if err := os.MkdirAll(c.stubDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(c.stubDir, "claude"), []byte(committedStub), 0o755); err != nil {
		t.Fatal(err)
	}
	mustRun(t, c.project, "init", "--provider", "claudecode", "--skip-clarify", "Ship the feature")
	mustRun(t, c.project, "task", "add", "Write feature.txt", "--no-ai", "--auto")
	return c
}

func (c committedE2E) run(t *testing.T, extraEnv []string, args ...string) (string, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, binaryPath(t), args...)
	cmd.Dir = c.project
	cmd.Env = append(os.Environ(), "NO_COLOR=1", "TERM=dumb",
		"PATH="+c.stubDir+string(os.PathListSeparator)+os.Getenv("PATH"), "STUB_DIR="+c.stubDir)
	cmd.Env = append(cmd.Env, extraEnv...)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func (c committedE2E) task(t *testing.T) *pm.Task {
	t.Helper()
	s, err := state.Load(c.project)
	if err != nil {
		t.Fatal(err)
	}
	task := s.Plan.TaskByID(1)
	if task == nil {
		t.Fatal("task 1 is missing")
	}
	return task
}

func TestE2EDoneMeansCommittedHandsTheTurnBack(t *testing.T) {
	c := setupCommittedE2E(t)

	out, err := c.run(t, nil, "run", "--require-committed=pushed")
	if err != nil {
		t.Fatalf("cloop run: %v\n%s", err, out)
	}

	calls := strings.Split(strings.TrimSpace(readFile(t, filepath.Join(c.stubDir, "calls.log"))), "\n")
	if len(calls) != 2 {
		t.Fatalf("the agent ran %d times, want the task and one hand-back:\n%s\nrun output:\n%s", len(calls), strings.Join(calls, "\n"), out)
	}
	session := regexp.MustCompile(`--session-id ([0-9a-f-]{36})`).FindStringSubmatch(calls[0])
	if session == nil || !strings.Contains(calls[1], "--resume "+session[1]) {
		t.Errorf("the hand-back did not resume the agent's conversation:\n%s", strings.Join(calls, "\n"))
	}
	handback := readFile(t, filepath.Join(c.stubDir, "handback.txt"))
	if !strings.Contains(handback, "?? feature.txt") || !strings.Contains(handback, "committed and pushed") {
		t.Errorf("the hand-back does not name the work:\n%s", handback)
	}
	// `cloop init` edited .gitignore before the task started; that is not the
	// task's to commit, and the agent is not told to.
	if strings.Contains(handback, ".gitignore") {
		t.Errorf("the hand-back blames the task for init's edit:\n%s", handback)
	}

	task := c.task(t)
	if task.Status != pm.TaskDone {
		t.Fatalf("task = %s\n%s", task.Status, out)
	}
	if got := strings.TrimSpace(gitIn(t, c.remote, "show", "refs/heads/main:feature.txt")); got != "feature" {
		t.Errorf("the remote does not have the work: %q", got)
	}

	// The setting is the project's, and says so.
	status := mustRun(t, c.project, "status")
	if !strings.Contains(status, "Done:     only once committed and pushed") {
		t.Errorf("cloop status does not show it:\n%s", status)
	}
	var p pm.CommitPolicy
	if err := clijson.Unmarshal([]byte(mustRun(t, c.project, "require-committed", "--json")), &p); err != nil || !p.RequiresPush() {
		t.Errorf("require-committed --json = %+v, %v", p, err)
	}
}

// An agent that never commits is not recorded done: the task goes back to
// pending with its work where it left it, and the run pauses for a person.
func TestE2EDoneMeansCommittedNeverCommittedStaysPending(t *testing.T) {
	c := setupCommittedE2E(t)
	mustRun(t, c.project, "require-committed", "committed")

	out, err := c.run(t, []string{"STUB_NEVER=1"}, "run", "--max-failures", "1")
	if err != nil {
		t.Fatalf("cloop run: %v\n%s", err, out)
	}
	if n := strings.Count(readFile(t, filepath.Join(c.stubDir, "calls.log")), "call:"); n != 3 {
		t.Fatalf("the agent ran %d times, want the task and two hand-backs\n%s", n, out)
	}
	task := c.task(t)
	if task.Status != pm.TaskPending {
		t.Fatalf("task = %s, want pending\n%s", task.Status, out)
	}
	s, err := state.Load(c.project)
	if err != nil {
		t.Fatal(err)
	}
	if !s.PausedFor(pausereason.CodeUncommittedWork) {
		t.Errorf("run = %s %+v, want paused for uncommitted work", s.Status, s.PauseReason)
	}
	if b, err := os.ReadFile(filepath.Join(c.project, "feature.txt")); err != nil || strings.TrimSpace(string(b)) != "feature" {
		t.Errorf("the agent's work is not where it left it: %q %v", b, err)
	}
	// `cloop init` added .cloop/env.yaml to .gitignore before the task ever
	// started: not the task's, so still exactly as init left it.
	if st := gitIn(t, c.project, "status", "--porcelain"); st != "M .gitignore\n?? feature.txt" {
		t.Errorf("status = %q, want the work untouched and uncommitted", st)
	}
	if !strings.Contains(out, "uncommitted_work") {
		t.Errorf("the run's output does not name the abort:\n%s", out)
	}
}

func gitIn(t *testing.T, dir string, args ...string) string {
	t.Helper()
	out, err := exec.Command("git", append([]string{"-C", dir}, args...)...).CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}
