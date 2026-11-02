package e2e_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/requirements"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// The requirements gate's red-green proof end to end (Task 20464), with the
// real binary — the gate dispatches `cloop requirements prove` to this
// binary, which checks the base out and runs the test there — and a stub
// `claude`. The project keeps R-1, a must requirement tested by `sh
// tests/greet_test.sh`; greet says hello. The stub is the agent: it makes
// greet say hello, world and writes the test — first one that passes whatever
// greet says, then, told its test is vacuous, one that checks the greeting.

const requirementsProofStub = `#!/bin/bash
prompt="$(cat)"
n=$(( $(cat "$STUB_DIR/count" 2>/dev/null || echo 0) + 1 ))
echo "$n" > "$STUB_DIR/count"
printf '%s' "$prompt" > "$STUB_DIR/prompt.$n"
echo "greet() { echo 'hello, world'; }" > lib.sh
mkdir -p tests
if [[ "$prompt" == *"vacuous"* ]]; then
  printf '. ./lib.sh\n[ "$(greet)" = "hello, world" ]\n' > tests/greet_test.sh
else
  printf '. ./lib.sh\ngreet >/dev/null\n' > tests/greet_test.sh
fi
git add -A && git commit -q -m "attempt $n"
echo "Greeted the world."
echo "TASK_DONE"
`

func TestE2ERequirementsGateProvesTheTestsATaskAdds(t *testing.T) {
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
	git := func(args ...string) string {
		t.Helper()
		cmd := exec.Command("git", args...)
		cmd.Dir = g.project
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
		return strings.TrimSpace(string(out))
	}
	git("init", "-q", "-b", "main")
	git("config", "user.email", "agent@example.com")
	git("config", "user.name", "agent")
	git("config", "commit.gpgsign", "false")
	for name, body := range map[string]string{".gitignore": ".cloop/\n", "lib.sh": "greet() { echo hello; }\n"} {
		if err := os.WriteFile(filepath.Join(g.project, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	git("add", "-A")
	git("commit", "-q", "-m", "initial")
	start := git("rev-parse", "HEAD")
	if err := os.WriteFile(filepath.Join(g.stubDir, "claude"), []byte(requirementsProofStub), 0o755); err != nil {
		t.Fatal(err)
	}
	mustRun(t, g.project, "init", "--provider", "claudecode", "--skip-clarify", "Greet the world")
	mustRun(t, g.project, "requirements", "add", "Greets the world", "--priority", "must", "--test", "sh tests/greet_test.sh")
	mustRun(t, g.project, "task", "add", "Greet the world", "--no-ai", "--auto", "--requirement", "1")
	mustRun(t, g.project, "requirements", "gate", "linked+must")

	out, err := g.run(t, nil, "run")
	if err != nil {
		t.Fatalf("cloop run: %v\n%s", err, out)
	}
	if n := g.calls(t); n != 2 {
		t.Fatalf("the agent ran %d times, want the task and its retry\n%s", n, out)
	}
	retry := g.prompt(t, 2)
	for _, want := range []string{"R-1 Greets the world — vacuous", "A red-green proof ran them on the code before the task",
		start[:12], "tests/greet_test.sh"} {
		if !strings.Contains(retry, want) {
			t.Errorf("the retry's prompt does not say %q:\n%s", want, retry)
		}
	}
	task := g.task(t)
	if task.Status != pm.TaskDone || !task.RequirementsCheck.Met() || task.RequirementsCheck.Base != start {
		t.Fatalf("task = %s, check = %+v\n%s", task.Status, task.RequirementsCheck, out)
	}
	if p := task.RequirementsCheck.Requirements[0].Proof; p == nil || p.Outcome != requirements.ProofProven {
		t.Fatalf("the task's proof = %+v", p)
	}

	db, err := statedb.Open(state.DBPath(g.project))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	proofs, err := db.RequirementProofs(1, 0)
	if err != nil || len(proofs) != 2 {
		t.Fatalf("R-1's proofs = %+v, %v", proofs, err)
	}
	if proofs[1].Outcome != requirements.ProofVacuous || proofs[0].Outcome != requirements.ProofProven ||
		proofs[0].Before.Commit != start || proofs[1].Before.Commit != start || proofs[0].TaskID != 1 {
		t.Fatalf("R-1's proofs: %+v", proofs)
	}
	// The project's checkout is the agent's work, and no checkout of the base
	// is left behind.
	if lib, _ := os.ReadFile(filepath.Join(g.project, "lib.sh")); !strings.Contains(string(lib), "hello, world") {
		t.Fatalf("lib.sh = %q", lib)
	}
	if list := git("worktree", "list", "--porcelain"); strings.Count(list, "worktree ") != 1 {
		t.Fatalf("a proof checkout is left:\n%s", list)
	}
	if show := mustRun(t, g.project, "requirements", "show", "1"); !strings.Contains(show, "Proof: proven") {
		t.Errorf("show does not give the proof:\n%s", show)
	}
}
