package ciscripts_test

// ciwhy_test.go tests how a red CI job says why without a token (Task 20444):
// scripts/ci-step.sh, the shell every step of ci.yml runs under, which records
// each step and must leave its verdict alone; its --why, each job's last
// step, which annotates the failed steps through scripts/ci-annotate or, with
// no Go, by their last lines; scripts/ci-why.sh, which reads the annotations
// back from GitHub's public API, against a stand-in for that API serving
// responses recorded from it; the workflow wiring; and that ci-annotate still
// reads what the toolchain at hand prints.
//
// The step scripts run here are inert — echo, false, exit — and run in a
// temporary directory: a "sample" step of `docker compose build` run from the
// repository root once built the eval stack for real.

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// runIn runs a command in dir with env added to the test's environment.
func runIn(t *testing.T, dir string, env []string, name string, args ...string) (stdout, stderr string, code int) {
	t.Helper()
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	cmd.Env = append(append(os.Environ(), goEnv...), env...)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	err := cmd.Run()
	var exit *exec.ExitError
	switch {
	case err == nil:
	case errors.As(err, &exit):
		code = exit.ExitCode()
	default:
		t.Fatalf("%s %s: %v", name, strings.Join(args, " "), err)
	}
	return out.String(), errb.String(), code
}

// noRecord clears what scripts/ci-step.sh gives the step these tests run
// in on CI: run with it, ci-annotate would count that step's output against
// its cap and mark it annotated, and the job's last step would skip it.
var noRecord = []string{"CI_WHY_DIR=", "CI_WHY_STEP_DIR=", "GITHUB_STEP_SUMMARY="}

// combined runs a command from the repository's root with its stdout and
// stderr in one stream, as a step's `2>&1` has them.
func combined(t *testing.T, name string, args ...string) (string, int) {
	t.Helper()
	cmd := exec.Command(name, args...)
	cmd.Dir = repoRoot(t)
	cmd.Env = append(append(os.Environ(), goEnv...), noRecord...)
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	err := cmd.Run()
	var exit *exec.ExitError
	switch {
	case err == nil:
		return out.String(), 0
	case errors.As(err, &exit):
		return out.String(), exit.ExitCode()
	}
	t.Fatalf("%s %s: %v", name, strings.Join(args, " "), err)
	return "", 0
}

// stepRig is a job's worth of steps run through ci-step.sh.
type stepRig struct {
	t       *testing.T
	work    string // the steps' working directory
	temp    string // RUNNER_TEMP
	summary string
	wrapper string
}

func newStepRig(t *testing.T) *stepRig {
	t.Helper()
	r := &stepRig{t: t, work: t.TempDir(), temp: t.TempDir(), wrapper: filepath.Join(repoRoot(t), "scripts", "ci-step.sh")}
	r.summary = filepath.Join(r.temp, "summary.md")
	return r
}

func (r *stepRig) env(extra ...string) []string {
	return append([]string{"RUNNER_TEMP=" + r.temp, "GITHUB_STEP_SUMMARY=" + r.summary,
		"CI_WHY_DIR=", "CI_WHY_STEP_DIR=", "CI_WHY_LEVEL=", "CI_WHY_NO_GO="}, extra...)
}

// step runs script as a step would run it and returns what the log shows.
func (r *stepRig) step(script string, extra ...string) (output string, code int) {
	r.t.Helper()
	f, err := os.CreateTemp(r.temp, "step-*.sh")
	if err != nil {
		r.t.Fatal(err)
	}
	if _, err := f.WriteString(script); err != nil {
		r.t.Fatal(err)
	}
	f.Close()
	out, errOut, code := runIn(r.t, r.work, r.env(extra...), "bash", r.wrapper, f.Name())
	return out + errOut, code
}

func (r *stepRig) record(n int, name string) string {
	r.t.Helper()
	b, err := os.ReadFile(filepath.Join(r.temp, "ci-why", fmt.Sprintf("%03d", n), name))
	if err != nil {
		return "<" + err.Error() + ">"
	}
	return string(b)
}

// TestCIStepLeavesTheVerdictAlone: a step under ci-step.sh exits as `bash -e`
// would have — the failing command ends it, its own pipefail is honoured and
// its absence too, any exit status comes through — prints what it printed in
// the order it printed it, and is recorded: script, output, exit status.
func TestCIStepLeavesTheVerdictAlone(t *testing.T) {
	r := newStepRig(t)
	cases := []struct {
		script string
		code   int
		out    string
	}{
		{"echo one\necho two >&2\necho three\n", 0, "one\ntwo\nthree\n"},
		{"echo before\nfalse\necho after\n", 1, "before\n"},
		{"exit 7\n", 7, ""},
		{"set -o pipefail\nfalse | true\necho unreached\n", 1, ""},
		{"false | true\necho no pipefail by default\n", 0, "no pipefail by default\n"},
		{"echo \"$CI_WHY_STEP_DIR\"\n", 0, filepath.Join(r.temp, "ci-why", "006") + "\n"},
	}
	for i, c := range cases {
		out, code := r.step(c.script)
		if code != c.code || out != c.out {
			t.Errorf("step %d (%q): exit %d, output %q; want %d, %q", i+1, c.script, code, out, c.code, c.out)
		}
		n := i + 1
		if got := r.record(n, "status"); got != strconv.Itoa(c.code)+"\n" {
			t.Errorf("step %d: recorded status %q, want %d", n, got, c.code)
		}
		if got := r.record(n, "log"); got != c.out {
			t.Errorf("step %d: recorded log %q, want %q", n, got, c.out)
		}
		if got := r.record(n, "script"); got != c.script {
			t.Errorf("step %d: recorded script %q", n, got)
		}
	}
}

// TestCIStepDoesNotWaitOnABackgroundProcess: a step that leaves a process
// running with the step's output still open ends when its script does, give
// or take the wrapper's three seconds — GitHub moves on after five itself.
func TestCIStepDoesNotWaitOnABackgroundProcess(t *testing.T) {
	r := newStepRig(t)
	script := filepath.Join(r.temp, "step.sh")
	if err := os.WriteFile(script, []byte("(sleep 8; echo late) &\necho started\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// Output to a file, not a pipe: exec would wait for a pipe's last
	// holder, the background sleep, and time that rather than the step.
	out, err := os.Create(filepath.Join(r.temp, "out"))
	if err != nil {
		t.Fatal(err)
	}
	defer out.Close()
	cmd := exec.Command("bash", r.wrapper, script)
	cmd.Dir, cmd.Env, cmd.Stdout, cmd.Stderr = r.work, append(os.Environ(), r.env()...), out, out
	start := time.Now()
	err = cmd.Run()
	if took := time.Since(start); err != nil || took > 5*time.Second {
		t.Errorf("the step ended after %s with %v; want success within 5s", took, err)
	}
	if got := r.record(1, "status"); got != "0\n" {
		t.Errorf("recorded status %q", got)
	}
}

// TestCIStepRunsUnrecordedWhenItCannotRecord: with nowhere to write the
// record the step still runs, with its own verdict.
func TestCIStepRunsUnrecordedWhenItCannotRecord(t *testing.T) {
	r := newStepRig(t)
	blocked := filepath.Join(r.temp, "a-file")
	if err := os.WriteFile(blocked, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	out, code := r.step("echo ran\nexit 4\n", "CI_WHY_DIR="+filepath.Join(blocked, "ci-why"))
	if code != 4 || out != "ran\n" {
		t.Errorf("exit %d, %q; want 4, \"ran\\n\"", code, out)
	}
}

// commandRe is a workflow command, as the runner finds one.
var commandRe = regexp.MustCompile(`^\s*::([a-z-]+)( [^:]*)?::(.*)$`)

type annotation struct {
	Level, Title, Message, Path string
	Line                        int
}

// readAnnotations parses what a step emitted the way GitHub's runner does.
func readAnnotations(t *testing.T, out string) []annotation {
	t.Helper()
	unData := strings.NewReplacer("%0D", "\r", "%0A", "\n", "%25", "%")
	unProp := strings.NewReplacer("%0D", "\r", "%0A", "\n", "%3A", ":", "%2C", ",", "%25", "%")
	var as []annotation
	for _, l := range strings.Split(out, "\n") {
		m := commandRe.FindStringSubmatch(l)
		if m == nil {
			continue
		}
		a := annotation{Level: m[1], Message: unData.Replace(m[3])}
		for _, kv := range strings.Split(strings.TrimSpace(m[2]), ",") {
			k, v, _ := strings.Cut(kv, "=")
			switch k {
			case "title":
				a.Title = unProp.Replace(v)
			case "file":
				a.Path = unProp.Replace(v)
			case "line":
				a.Line, _ = strconv.Atoi(v)
			}
		}
		as = append(as, a)
	}
	return as
}

// TestCIStepWhyAnnotatesTheFailedSteps: the job's last step annotates each
// failed step — go test's failures by name through scripts/ci-annotate, a
// step without go output by its last forty lines — and leaves alone the
// steps that passed and itself. With no Go it falls back to the last lines
// of every failed step, escaped as the runner unescapes them.
func TestCIStepWhyAnnotatesTheFailedSteps(t *testing.T) {
	for _, noGo := range []bool{false, true} {
		t.Run(fmt.Sprintf("noGo=%v", noGo), func(t *testing.T) {
			r := newStepRig(t)
			recorded, err := os.ReadFile(filepath.Join(repoRoot(t), "scripts", "ci-annotate", "testdata", "recorded", "build.txt"))
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(r.work, "build.txt"), recorded, 0o644); err != nil {
				t.Fatal(err)
			}
			r.step("echo all good\n")
			r.step("set -o pipefail\ncat build.txt | tee race.log\nexit 1\n")
			r.step("printf 'line %d: 100%% \\r\\n' $(seq 1 60)\necho 'make: *** [terraform-test] Error 1'\nexit 2\n")

			// The last step runs from the repository's root, as a job's does.
			var extra []string
			if noGo {
				extra = append(extra, "CI_WHY_NO_GO=1")
			}
			script := filepath.Join(r.temp, "why.sh")
			if err := os.WriteFile(script, []byte("bash scripts/ci-step.sh --why\n"), 0o644); err != nil {
				t.Fatal(err)
			}
			out, errOut, code := runIn(t, repoRoot(t), r.env(extra...), "bash", r.wrapper, script)
			if code != 0 {
				t.Fatalf("the why step exited %d: %q", code, errOut)
			}
			as := readAnnotations(t, out)
			if len(as) == 0 {
				t.Fatalf("no annotations: %q / %q", out, errOut)
			}
			last := as[len(as)-1]
			if last.Title != "A step exited 2: printf 'line %d: 100%% \\r\\n' $(seq 1 60)" ||
				!strings.HasSuffix(last.Message, "line 60: 100% \r\nmake: *** [terraform-test] Error 1") ||
				strings.Count(last.Message, "\n") != 39 {
				t.Errorf("the non-Go step's annotation: %q / %q", last.Title, last.Message)
			}
			if noGo {
				if len(as) != 2 || as[0].Title != "A step exited 1: cat build.txt | tee race.log" {
					t.Errorf("without Go: %d annotations, the first %q", len(as), as[0].Title)
				}
				return
			}
			if len(as) != 2 || as[0].Title != "scripts/ci-annotate/testdata/red/broken: build failed" ||
				as[0].Path != "scripts/ci-annotate/testdata/red/broken/broken.go" || as[0].Line != 6 {
				t.Errorf("%d annotations, the first %q at %s:%d", len(as), as[0].Title, as[0].Path, as[0].Line)
			}
			md, err := os.ReadFile(r.summary)
			if err != nil || !strings.Contains(string(md), "## Why it failed") || strings.Count(string(md), "<details>") != 2 {
				t.Errorf("summary: %v\n%s", err, md)
			}
		})
	}
}

// fakeGitHub serves the API ci-why.sh reads, from responses recorded from
// GitHub for f6e1ab1f — a commit whose Build and Test job failed with
// nothing to show but "Process completed with exit code 1." — and counts the
// requests, and the rate limit, as GitHub does.
type fakeGitHub struct {
	*httptest.Server
	requests    atomic.Int32
	annotations map[string]string // check run id → JSON
	exhausted   bool
}

const redSHA = "f6e1ab1f817fa4cd60e2b467fd5edd4780133d9f"

func newFakeGitHub(t *testing.T) *fakeGitHub {
	t.Helper()
	dir := filepath.Join(repoRoot(t), "tests", "ciscripts", "testdata", "ciwhy")
	read := func(name string) string {
		b, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	f := &fakeGitHub{annotations: map[string]string{"117268531890": read("annotations.json")}}
	runs, jobs := read("runs.json"), read("jobs.json")
	f.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		n := f.requests.Add(1)
		w.Header().Set("X-RateLimit-Limit", "60")
		w.Header().Set("X-RateLimit-Remaining", strconv.Itoa(max(0, 60-int(n))))
		w.Header().Set("X-RateLimit-Reset", "1793068800")
		if f.exhausted {
			w.Header().Set("X-RateLimit-Remaining", "0")
			http.Error(w, `{"message":"API rate limit exceeded"}`, http.StatusForbidden)
			return
		}
		const base = "/repos/blechschmidt/cloop/"
		p, q := req.URL.Path, req.URL.Query()
		switch {
		case p == base+"actions/runs" && q.Get("head_sha") == redSHA && q.Get("event") == "push":
			fmt.Fprint(w, runs)
		case p == base+"actions/runs":
			fmt.Fprint(w, `{"total_count":0,"workflow_runs":[]}`)
		case p == base+"actions/runs/38989510992/jobs":
			fmt.Fprint(w, jobs)
		case strings.HasPrefix(p, base+"actions/runs/") && strings.HasSuffix(p, "/jobs"):
			fmt.Fprint(w, `{"total_count":0,"jobs":[]}`)
		case strings.HasPrefix(p, base+"check-runs/") && strings.HasSuffix(p, "/annotations"):
			id := strings.TrimSuffix(strings.TrimPrefix(p, base+"check-runs/"), "/annotations")
			body, ok := f.annotations[id]
			if !ok {
				body = "[]"
			}
			fmt.Fprint(w, body)
		case p == base+"commits/f6e1ab1":
			fmt.Fprintf(w, `{"sha":%q}`, redSHA)
		default:
			http.Error(w, `{"message":"Not Found"}`, http.StatusNotFound)
		}
	}))
	t.Cleanup(f.Close)
	return f
}

// why runs ci-why.sh against the stand-in, from dir.
func (f *fakeGitHub) why(t *testing.T, dir string, args ...string) (string, string, int) {
	t.Helper()
	f.requests.Store(0)
	return runIn(t, dir, []string{"CI_WHY_API=" + f.URL, "CI_WHY_REPO=blechschmidt/cloop", "GITHUB_TOKEN="},
		"bash", append([]string{filepath.Join(repoRoot(t), "scripts", "ci-why.sh")}, args...)...)
}

// asAPI turns workflow commands into the annotations GitHub's check-runs API
// returns for them.
func asAPI(t *testing.T, as []annotation) string {
	t.Helper()
	type api struct {
		Path       string `json:"path"`
		StartLine  int    `json:"start_line"`
		Level      string `json:"annotation_level"`
		Title      string `json:"title"`
		Message    string `json:"message"`
		RawDetails string `json:"raw_details"`
	}
	out := []api{{Path: ".github", StartLine: 2302, Level: "failure", Message: "Process completed with exit code 1."}}
	for _, a := range as {
		path, line := a.Path, a.Line
		if path == "" {
			path, line = ".github", 1
		}
		level := map[string]string{"error": "failure"}[a.Level]
		if level == "" {
			level = a.Level
		}
		out = append(out, api{Path: path, StartLine: line, Level: level, Title: a.Title, Message: a.Message})
	}
	b, err := json.Marshal(out)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// TestCIWhyReadsWhyAJobFailed: for a red commit ci-why.sh prints each run,
// the failed job, the step it failed at, a link to its log and its
// annotations, in three requests. Before Task 20444 those said only "Process
// completed with exit code 1."; with what ci-annotate writes they name the
// failing tests and where they failed, and the boilerplate is left out.
func TestCIWhyReadsWhyAJobFailed(t *testing.T) {
	gh := newFakeGitHub(t)
	root := repoRoot(t)
	out, errOut, code := gh.why(t, root, redSHA)
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errOut)
	}
	for _, want := range []string{
		redSHA,
		"  CI: failure  https://github.com/blechschmidt/cloop/actions/runs/38989510992",
		"    Build and Test: failure",
		"      failed at: Test with race detector and coverage",
		"      https://github.com/blechschmidt/cloop/actions/runs/38989510992/job/117268531890",
		"      error   Process completed with exit code 1.",
		"  Publish images: success",
		"(3 request(s) to GitHub; 57 left this hour)",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("the output lacks %q:\n%s", want, out)
		}
	}
	if n := gh.requests.Load(); n != 3 {
		t.Errorf("%d requests, want 3", n)
	}

	// What the job's last step writes now, read back.
	recorded := filepath.Join(root, "scripts", "ci-annotate", "testdata", "recorded", "red.txt")
	emitted, code := combined(t, "go", "run", "./scripts/ci-annotate", "-summary", "", recorded)
	if code != 0 {
		t.Fatalf("ci-annotate: exit %d", code)
	}
	gh.annotations["117268531890"] = asAPI(t, readAnnotations(t, emitted))
	out, _, _ = gh.why(t, root, redSHA)
	for _, want := range []string{
		"      error   scripts/ci-annotate/testdata/red/missing: setup failed  scripts/ci-annotate/testdata/red/missing/missing_test.go:8",
		"      error   scripts/ci-annotate/testdata/red/failing TestAssertion  scripts/ci-annotate/testdata/red/failing/failing_test.go:16",
		"              failing_test.go:16: 2+2 = 4, want 5",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("the output lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "Process completed with exit code") {
		t.Errorf("the boilerplate is printed beside the reasons:\n%s", out)
	}
}

// TestCIWhyResolvesAndReportsLimits: a short SHA this clone does not have is
// resolved by GitHub, one request more; a job is printed by name whatever
// its verdict; a spent rate limit is said as such, with when it comes back;
// and a commit with no push runs says so.
func TestCIWhyResolvesAndReportsLimits(t *testing.T) {
	gh := newFakeGitHub(t)
	notGit := t.TempDir() // not a clone: nothing resolves here

	out, errOut, code := gh.why(t, notGit, "f6e1ab1")
	if code != 0 || !strings.Contains(out, redSHA) || gh.requests.Load() != 4 {
		t.Errorf("a short SHA: exit %d, %d requests\n%s%s", code, gh.requests.Load(), out, errOut)
	}

	gh.annotations["117268531879"] = `[{"path":".github","start_line":1,"annotation_level":"notice","title":"","message":"a fixture's notice"}]`
	out, _, code = gh.why(t, notGit, "--job", "Static analysis", redSHA)
	if code != 0 || !strings.Contains(out, "    Static analysis: success") ||
		!strings.Contains(out, "      notice  a fixture's notice") || strings.Contains(out, "Build and Test") {
		t.Errorf("--job: exit %d\n%s", code, out)
	}

	out, _, _ = gh.why(t, notGit, strings.Repeat("0", 40))
	if !strings.Contains(out, "no push runs") {
		t.Errorf("a commit with no runs:\n%s", out)
	}

	gh.exhausted = true
	_, errOut, code = gh.why(t, notGit, redSHA)
	if code != 1 || !strings.Contains(errOut, "60 requests an hour for this address are spent") ||
		!strings.Contains(errOut, "come back at") || !strings.Contains(errOut, "GITHUB_TOKEN") {
		t.Errorf("a spent limit: exit %d, %q", code, errOut)
	}

	if _, errOut, code := gh.why(t, notGit, "main"); code != 1 || !strings.Contains(errOut, "name it by its SHA") {
		t.Errorf("a branch name outside a clone: exit %d, %q", code, errOut)
	}
}

// jobBlocks splits ci.yml into its jobs, each from its key to the next.
func jobBlocks(t *testing.T) map[string]string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(repoRoot(t), ".github", "workflows", "ci.yml"))
	if err != nil {
		t.Fatal(err)
	}
	wf := string(raw)
	start := strings.Index(wf, "\njobs:\n")
	if start < 0 {
		t.Fatal("ci.yml has no jobs")
	}
	body := wf[start:]
	keys := regexp.MustCompile(`(?m)^  ([A-Za-z0-9_-]+):\s*$`).FindAllStringSubmatchIndex(body, -1)
	jobs := map[string]string{}
	for i, k := range keys {
		end := len(body)
		if i+1 < len(keys) {
			end = keys[i+1][0]
		}
		jobs[body[k[2]:k[3]]] = body[k[0]:end]
	}
	return jobs
}

// TestEveryJobSaysWhyItFailed reads ci.yml: every run step is recorded
// (ci-step.sh is the workflow's default shell, and no step names another),
// and every job's last step is the one that says why it failed, run when the
// job failed or was cancelled.
func TestEveryJobSaysWhyItFailed(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(repoRoot(t), ".github", "workflows", "ci.yml"))
	if err != nil {
		t.Fatal(err)
	}
	wf := string(raw)
	head := wf[:strings.Index(wf, "\njobs:\n")]
	if !regexp.MustCompile(`(?m)^defaults:\n  run:\n    shell: bash scripts/ci-step\.sh \{0\}$`).MatchString(head) {
		t.Error("ci.yml's defaults do not run every step under scripts/ci-step.sh")
	}
	if m := regexp.MustCompile(`(?m)^\s+shell:.*$`).FindAllString(wf[len(head):], -1); len(m) > 0 {
		t.Errorf("steps name a shell of their own, and go unrecorded: %q", m)
	}
	jobs := jobBlocks(t)
	if len(jobs) < 20 {
		t.Fatalf("found %d jobs; the split is broken", len(jobs))
	}
	last := regexp.MustCompile(`(?s)\n      - name: Say why the job failed\n(?:        [^\n]*\n|\s*#[^\n]*\n)*?` +
		`        if: failure\(\) \|\| cancelled\(\)\n(?:        [^\n]*\n)*?        run: bash scripts/ci-step\.sh --why\n*$`)
	for name, job := range jobs {
		if !last.MatchString(job) {
			t.Errorf("job %s does not end with the step that says why it failed", name)
		}
	}
}

// TestAnnotatorReadsThisToolchain runs the fixtures with the go at hand and
// checks scripts/ci-annotate finds in its output what it finds in the
// recordings it is tested on: Go's output format is not a promise, and a
// toolchain bump could change it under the recordings.
func TestAnnotatorReadsThisToolchain(t *testing.T) {
	if testing.Short() {
		t.Skip("runs go test on nine fixture packages")
	}
	const fixtures = "./scripts/ci-annotate/testdata/red/..."
	want := []string{
		"scripts/ci-annotate/testdata/red/missing: setup failed",
		"scripts/ci-annotate/testdata/red/broken: build failed",
		"scripts/ci-annotate/testdata/red/vetted: vet failed",
		"scripts/ci-annotate/testdata/red/panicking TestPanics: panic: runtime error: invalid memory address or nil pointer dereference",
		"scripts/ci-annotate/testdata/red/slow TestHangs/waiting_on_the_store: test timed out after 3s",
		"scripts/ci-annotate/testdata/red/failing TestAssertion",
		"scripts/ci-annotate/testdata/red/failing TestFatal",
		"scripts/ci-annotate/testdata/red/failing TestNested/fails",
		"scripts/ci-annotate/testdata/red/failing TestNested/deeper/still_deeper",
		"scripts/ci-annotate/testdata/red/failing TestLongLog",
		"scripts/ci-annotate/testdata/red/failing TestHostileMessage",
		"scripts/ci-annotate/testdata/red/failing TestParallelOne",
		"scripts/ci-annotate/testdata/red/failing TestParallelTwo",
		"scripts/ci-annotate/testdata/red/exits: failed outside any test",
	}
	slices.Sort(want)
	dir := t.TempDir()
	for _, format := range []string{"plain", "json"} {
		t.Run(format, func(t *testing.T) {
			args := []string{"test", "-count=1", "-timeout", "3s", fixtures}
			if format == "json" {
				args = append(args[:1], append([]string{"-json"}, args[1:]...)...)
			}
			out, code := combined(t, "go", args...)
			if code == 0 {
				t.Fatal("the fixtures passed")
			}
			log := filepath.Join(dir, format+".log")
			if err := os.WriteFile(log, []byte(out), 0o644); err != nil {
				t.Fatal(err)
			}
			emitted, code := combined(t, "go", "run", "./scripts/ci-annotate", "-max", "20", "-summary", "", log)
			if code != 0 {
				t.Fatalf("ci-annotate: exit %d: %q", code, emitted)
			}
			var got []string
			for _, a := range readAnnotations(t, emitted) {
				got = append(got, a.Title)
			}
			slices.Sort(got)
			if !slices.Equal(got, want) {
				t.Errorf("this toolchain's output reads as\n%q\nwant\n%q", got, want)
			}
		})
	}
}
