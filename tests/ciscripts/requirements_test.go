package ciscripts_test

// CI's requirements job (Task 20466): `make requirements-check` runs
// scripts/requirements-check.sh, which runs `cloop requirements check --file
// .cloop/requirements.yaml --json` hermetically, and the job's last step
// annotates each requirement the check found failing by its R-<n>. These run
// the script with a stand-in cloop that records how it was called and answers
// as the real one does, so they hold the script to its isolation without
// running cloop's requirements' tests from inside cloop's tests.

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/internal/hometest"
	"github.com/blechschmidt/cloop/pkg/requirements"
)

// standIn writes a stand-in for cloop into dir: each call records its
// arguments, working directory and environment under dir/<subcommand>.*, and
// `requirements check` prints report — framed, as the real one does — and
// exits checkStatus; `requirements lint` exits lintStatus.
func standIn(t *testing.T, dir, report string, lintStatus, checkStatus int) string {
	t.Helper()
	path := filepath.Join(dir, "cloop")
	script := fmt.Sprintf(`#!/bin/sh
rec=%q/"$2"
printf '%%s\n' "$@" > "$rec.args"
pwd > "$rec.cwd"
env -0 > "$rec.env"
case $2 in
lint)
	echo "lint called"
	exit %d
	;;
check)
	echo "R-1    checking    the stand-in" >&2
	printf '\n<<<cloop-json:begin>>>\n%%s\n<<<cloop-json:end>>>\n' '%s'
	exit %d
	;;
esac
exit 64
`, dir, lintStatus, report, checkStatus)
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

// recorded is what the stand-in recorded of its call to sub.
type recorded struct {
	args []string
	cwd  string
	env  map[string]string
}

func readCall(t *testing.T, dir, sub string) (recorded, bool) {
	t.Helper()
	args, err := os.ReadFile(filepath.Join(dir, sub+".args"))
	if os.IsNotExist(err) {
		return recorded{}, false
	}
	if err != nil {
		t.Fatal(err)
	}
	cwd, err := os.ReadFile(filepath.Join(dir, sub+".cwd"))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, sub+".env"))
	if err != nil {
		t.Fatal(err)
	}
	c := recorded{args: strings.Split(strings.TrimRight(string(args), "\n"), "\n"), cwd: strings.TrimSpace(string(cwd)),
		env: map[string]string{}}
	for _, kv := range strings.Split(strings.TrimRight(string(raw), "\x00"), "\x00") {
		if k, v, ok := strings.Cut(kv, "="); ok {
			c.env[k] = v
		}
	}
	return c, true
}

// ambient is what an agent's environment carries into the script — every
// variable hometest clears, and the credentials and per-task settings a hub
// hands the agent that runs this — each set to a value no test may see.
func ambient(dir string) []string {
	var env []string
	for _, k := range hometest.Cleared() {
		env = append(env, k+"="+filepath.Join(dir, "leaked-"+k))
	}
	for _, k := range []string{"CLOOP_TASK_ID", "CLOOP_TASK_ATTACHMENTS", "CLOOP_UI_TOKEN", "CLAUDE_CODE_SESSION_ID",
		"ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "COPILOT_GITHUB_TOKEN", "GH_TOKEN", "GITHUB_TOKEN"} {
		env = append(env, k+"=leaked-"+k)
	}
	return env
}

// leaks are the names of env that the script must have cleared.
var leaks = regexp.MustCompile(`^(CLOOP_.*|CLAUDE_.*|ANTHROPIC_.*|COPILOT_.*|GH_TOKEN|GITHUB_TOKEN|XDG_CONFIG_HOME|CREDENTIALS_DIRECTORY)$`)

// TestRequirementsCheckRunsHermetically: the script runs the check from the
// module's root with exactly the job's arguments, after linting the spec, in
// a fresh home it removes afterwards, with every CLOOP_* variable and every
// variable hometest clears unset and Go's caches where they were, and exits
// with the check's status.
func TestRequirementsCheckRunsHermetically(t *testing.T) {
	root := repoRoot(t)
	dir, tmp := t.TempDir(), t.TempDir()
	report := `{"results": [{"requirement_id": 1, "verdict": "unfulfilled", "summary": "test failed (exit 1)"}]}`
	cloop := standIn(t, dir, report, 0, 1)
	env := append(ambient(dir), "REQUIREMENTS_CHECK_CLOOP="+cloop, "TMPDIR="+tmp)
	out, errOut, code := runIn(t, root, env, "bash", filepath.Join(root, "scripts", "requirements-check.sh"))
	if code != 1 {
		t.Fatalf("the script exited %d, want the check's 1:\n%s\n%s", code, out, errOut)
	}
	if !strings.Contains(out, "<<<cloop-json:begin>>>") || !strings.Contains(errOut, "R-1    checking") {
		t.Errorf("the check's report and progress did not come through:\n%s\n%s", out, errOut)
	}

	lint, ok := readCall(t, dir, "lint")
	if !ok {
		t.Fatal("the spec was not linted")
	}
	check, ok := readCall(t, dir, "check")
	if !ok {
		t.Fatal("the check did not run")
	}
	for _, c := range []struct {
		call recorded
		want []string
	}{
		{lint, []string{"requirements", "lint", "--file", ".cloop/requirements.yaml"}},
		{check, []string{"requirements", "check", "--file", ".cloop/requirements.yaml", "--json"}},
	} {
		if !slices.Equal(c.call.args, c.want) {
			t.Errorf("called with %q, want %q", c.call.args, c.want)
		}
		if c.call.cwd != root {
			t.Errorf("%s ran in %s, want the module's root %s", c.want[1], c.call.cwd, root)
		}
		var leaked []string
		for k := range c.call.env {
			if leaks.MatchString(k) {
				leaked = append(leaked, k)
			}
		}
		slices.Sort(leaked)
		if len(leaked) > 0 {
			t.Errorf("%s inherited %q", c.want[1], leaked)
		}
		home := c.call.env["HOME"]
		if home == "" || home == os.Getenv("HOME") || !strings.HasPrefix(home, tmp+string(filepath.Separator)) ||
			c.call.env["USERPROFILE"] != home {
			t.Errorf("%s ran with HOME %q, USERPROFILE %q; want a fresh directory under TMPDIR %s", c.want[1], home,
				c.call.env["USERPROFILE"], tmp)
		}
		if _, err := os.Stat(home); !os.IsNotExist(err) {
			t.Errorf("the home %s was left behind: %v", home, err)
		}
		for _, kv := range goEnv {
			k, v, _ := strings.Cut(kv, "=")
			if c.call.env[k] != v {
				t.Errorf("%s ran with %s=%q, want Go's own %q", c.want[1], k, c.call.env[k], v)
			}
		}
		if c.call.env["GOENV"] == "" {
			t.Errorf("%s ran with no GOENV: Go would look for its settings in the fresh home", c.want[1])
		}
	}
	for _, k := range hometest.Redirected() {
		if check.env[k] != check.env["HOME"] {
			t.Errorf("hometest redirects %s, and the script left it %q", k, check.env[k])
		}
	}
	if entries, _ := os.ReadDir(tmp); len(entries) != 0 {
		t.Errorf("the script left %d entries in TMPDIR", len(entries))
	}

	// A spec that does not lint is not checked.
	dir2 := t.TempDir()
	cloop = standIn(t, dir2, report, 1, 0)
	_, _, code = runIn(t, root, []string{"REQUIREMENTS_CHECK_CLOOP=" + cloop, "TMPDIR=" + tmp}, "bash",
		filepath.Join(root, "scripts", "requirements-check.sh"))
	if _, ran := readCall(t, dir2, "check"); code != 1 || ran {
		t.Errorf("with the lint failing the script exited %d, and the check ran: %v", code, ran)
	}
}

// TestAFailingRequirementIsAnnotatedByItsKey runs the job's two steps as CI
// does, through scripts/ci-step.sh: the check finds a requirement of the real
// spec failing, and the job's last step annotates it by its R-<n> and title on
// its line of .cloop/requirements.yaml, where scripts/ci-why.sh reads it.
func TestAFailingRequirementIsAnnotatedByItsKey(t *testing.T) {
	if testing.Short() {
		t.Skip("builds and runs scripts/ci-annotate")
	}
	root := repoRoot(t)
	sf, _, err := requirements.LoadSpecFile(root, requirements.SpecFileName)
	if err != nil {
		t.Fatal(err)
	}
	if len(sf.Requirements) < 2 {
		t.Fatalf("the spec holds %d requirements", len(sf.Requirements))
	}
	failing := sf.Requirements[1]
	report := fmt.Sprintf(`{"results": [`+
		`{"requirement_id": %d, "verdict": "fulfilled", "summary": "1 test passed"},`+
		`{"requirement_id": %d, "verdict": "unfulfilled", "summary": "test \"x\" failed (exit 1)",`+
		` "tests": [{"command": "go test ./x", "outcome": "fail", "exit_code": 1, "output": "--- FAIL: TestX\nthe reason it failed\n"}]}]}`,
		sf.Requirements[0].ID, failing.ID)

	r := newStepRig(t)
	cloop := standIn(t, t.TempDir(), report, 0, 1)
	if out, code := r.step("make -C "+root+" requirements-check\n", "REQUIREMENTS_CHECK_CLOOP="+cloop); code == 0 {
		t.Fatalf("the requirements step passed:\n%s", out)
	}
	script := filepath.Join(r.temp, "why.sh")
	if err := os.WriteFile(script, []byte("bash scripts/ci-step.sh --why\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	out, errOut, code := runIn(t, root, r.env(), "bash", r.wrapper, script)
	if code != 0 {
		t.Fatalf("the why step exited %d: %q", code, errOut)
	}
	as := readAnnotations(t, out)
	want := requirements.Key(failing.ID) + " is unfulfilled: " + failing.Title
	if len(as) != 1 || as[0].Title != want || as[0].Path != requirements.SpecFileName ||
		as[0].Line != sf.Line(failing.ID) || !strings.HasSuffix(as[0].Message, "the reason it failed") {
		t.Fatalf("annotations %+v, want one titled %q at %s:%d", as, want, requirements.SpecFileName, sf.Line(failing.ID))
	}
}

// TestCIChecksCloopsOwnRequirements reads ci.yml and the Makefile: a job runs
// `make requirements-check` on every push and pull request, with the history
// the changelog requirement reads and the home-directory decoys around it,
// and the target runs the script these tests hold.
func TestCIChecksCloopsOwnRequirements(t *testing.T) {
	job, ok := jobBlocks(t)["requirements"]
	if !ok {
		t.Fatal("ci.yml has no requirements job")
	}
	for _, want := range []string{"fetch-depth: 0", "run: ./scripts/home-decoys.sh seed", "run: make requirements-check",
		"if: always()\n        run: ./scripts/home-decoys.sh verify"} {
		if !strings.Contains(job, want) {
			t.Errorf("the requirements job does not contain %q:\n%s", want, job)
		}
	}
	makefile, err := os.ReadFile(filepath.Join(repoRoot(t), "Makefile"))
	if err != nil {
		t.Fatal(err)
	}
	if !regexp.MustCompile(`(?m)^requirements-check:\n\t@GO=\$\(GO\) \./scripts/requirements-check\.sh$`).Match(makefile) {
		t.Error("the Makefile's requirements-check target does not run scripts/requirements-check.sh")
	}
	script, err := os.ReadFile(filepath.Join(repoRoot(t), "scripts", "requirements-check.sh"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(script), `"$cloop" requirements check --file "$spec" --json`) {
		t.Error("scripts/requirements-check.sh does not run `cloop requirements check --file … --json`")
	}
}
