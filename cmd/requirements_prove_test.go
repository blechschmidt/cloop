package cmd

// `cloop requirements prove` (Task 20464), run as a person runs it and as the
// hub dispatches it, in a real git checkout: a proven test, a vacuous one and
// a broken one.

import (
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/pkg/clijson"
	"github.com/blechschmidt/cloop/pkg/requirements"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// proveTestRepo makes dir a git checkout whose last commit changes what greet
// says and adds three tests of it: one that shows the change, one that passes
// either way, and one that fails on the change.
func proveTestRepo(t *testing.T, dir string) (base string) {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}
	t.Setenv("GIT_CONFIG_GLOBAL", os.DevNull)
	t.Setenv("GIT_CONFIG_NOSYSTEM", "1")
	git := func(args ...string) string {
		t.Helper()
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, out)
		}
		return strings.TrimSpace(string(out))
	}
	write := func(rel, content string) {
		t.Helper()
		p := filepath.Join(dir, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	git("init", "-q", "-b", "main")
	git("config", "user.email", "proof@example.com")
	git("config", "user.name", "proof test")
	write(".gitignore", ".cloop/\n")
	write("lib.sh", "greet() { echo hello; }\n")
	git("add", "-A")
	git("commit", "-q", "-m", "base")
	base = git("rev-parse", "HEAD")
	write("lib.sh", "greet() { echo 'hello, world'; }\n")
	write("tests/proven_test.sh", ". ./lib.sh\n[ \"$(greet)\" = 'hello, world' ]\n")
	write("tests/vacuous_test.sh", ". ./lib.sh\ntrue\n")
	write("tests/broken_test.sh", ". ./lib.sh\n[ \"$(greet)\" = goodbye ]\n")
	git("add", "-A")
	git("commit", "-q", "-m", "greet the world, with tests")
	return base
}

func projectProofs(t *testing.T, dir string, id int) []statedb.RequirementProof {
	t.Helper()
	db, err := statedb.Open(state.DBPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	proofs, err := db.RequirementProofs(id, 0)
	if err != nil {
		t.Fatal(err)
	}
	return proofs
}

func TestRequirementsProveByHand(t *testing.T) {
	exe := cliSelfExe(t)
	dir := reqTestProject(t)
	base := proveTestRepo(t, dir)

	mustRun(t, exe, dir, "requirements", "add", "Greets the world", "--test", "sh tests/proven_test.sh")
	mustRun(t, exe, dir, "requirements", "add", "Vacuously greets", "--test", "sh tests/vacuous_test.sh")
	mustRun(t, exe, dir, "requirements", "add", "Says goodbye", "--test", "sh tests/broken_test.sh")
	mustRun(t, exe, dir, "requirements", "add", "Nobody tests this")

	out := mustRun(t, exe, dir, "requirements", "prove", "R-1")
	if !strings.Contains(out, "proven") {
		t.Fatalf("prove R-1:\n%s", out)
	}
	proofs := projectProofs(t, dir, 1)
	if len(proofs) != 1 || proofs[0].Outcome != requirements.ProofProven || proofs[0].Before.Commit != base ||
		proofs[0].BaseFrom != requirements.BaseFromTest || proofs[0].ExecutorID != "local" ||
		!strings.HasPrefix(proofs[0].ProvedBy, "cli:") {
		t.Fatalf("R-1's recorded proof: %+v", proofs)
	}

	// A vacuous test and a broken one fail the command: it can gate CI.
	for id, want := range map[string]string{"2": "vacuous", "3": "broken"} {
		out, err := runHelper(t, exe, dir, "requirements", "prove", id, "--base", "HEAD~1")
		var exit *exec.ExitError
		if !errors.As(err, &exit) || exit.ExitCode() != 1 || !strings.Contains(string(out), want) {
			t.Fatalf("prove R-%s exited %v, want 1 saying %s:\n%s", id, err, want, out)
		}
	}
	if p := projectProofs(t, dir, 2); len(p) != 1 || p[0].BaseFrom != requirements.BaseFromGiven || p[0].Before.Commit != base {
		t.Fatalf("R-2's proof with --base: %+v", p)
	}

	if out := mustRun(t, exe, dir, "requirements", "show", "1"); !strings.Contains(out, "Proof: proven") {
		t.Errorf("show does not give the latest proof:\n%s", out)
	}
	for _, args := range [][]string{
		{"requirements", "prove"},
		{"requirements", "prove", "4"},
		{"requirements", "prove", "1", "--base", "no-such-commit"},
	} {
		if out, err := runHelper(t, exe, dir, args...); err == nil {
			t.Errorf("cloop %s succeeded:\n%s", strings.Join(args, " "), out)
		}
	}
	// The project's checkout is as it was.
	if b, _ := os.ReadFile(filepath.Join(dir, "lib.sh")); !strings.Contains(string(b), "hello, world") {
		t.Fatalf("lib.sh is %q", b)
	}
}

// TestRequirementsProveAsTheHubRunsIt: --spec, --json and --no-record — the
// requirements the hub sent, a framed report back, and nothing written: not
// even a project database where there was none.
func TestRequirementsProveAsTheHubRunsIt(t *testing.T) {
	exe := cliSelfExe(t)
	dir := t.TempDir()
	proveTestRepo(t, dir)
	spec, err := requirements.EncodeSpec(requirements.Spec{Requirements: []requirements.Requirement{
		{ID: 1, Title: "Greets the world", Tests: []requirements.Test{{Command: "sh tests/proven_test.sh"}}},
		{ID: 2, Title: "Vacuously greets", Tests: []requirements.Test{{Command: "sh tests/vacuous_test.sh"}}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	out := mustRun(t, exe, dir, "requirements", "prove", "--json", "--no-record", "--spec="+string(spec))
	payload, err := clijson.Extract([]byte(out))
	if err != nil {
		t.Fatalf("no framed report: %v\n%s", err, out)
	}
	var rep requirements.ProofReport
	if err := json.Unmarshal(payload, &rep); err != nil || len(rep.Results) != 2 {
		t.Fatalf("report: %v %+v", err, rep)
	}
	if rep.Results[0].Outcome != requirements.ProofProven || rep.Results[1].Outcome != requirements.ProofVacuous {
		t.Fatalf("outcomes %s, %s", rep.Results[0].Outcome, rep.Results[1].Outcome)
	}
	if _, err := os.Stat(state.DBPath(dir)); !os.IsNotExist(err) {
		t.Fatalf("the dispatched proof left a project database behind: %v", err)
	}
}
