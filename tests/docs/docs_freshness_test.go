// docs_freshness_test.go holds scripts/docs-freshness.py — the scheduled check
// that the published documentation site is as new as main — to the verdicts it
// exists to give.
//
// It exists because a deploy can stop without anything failing: GitHub left
// docs.yml run 36765144410's deploy job waiting on the github-pages
// environment from 2026-09-30, every later run queued behind it, and the site
// kept serving its Sep 29 build under a column of green checks. A checker's own
// worst failure has the same shape — it says OK when it should not — so each
// case here pins one verdict, with the clock fixed, against a scratch
// repository, a fake site and a fake GitHub API.
package docs_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

const freshnessScript = "scripts/docs-freshness.py"

// python3 finds the interpreter the script needs. Every CI runner has one, so
// there a missing interpreter is a failure; on a developer box it is a skip.
func python3(t *testing.T) string {
	t.Helper()
	path, err := exec.LookPath("python3")
	if err != nil {
		if os.Getenv("CI") != "" {
			t.Fatalf("python3 is not on PATH, so %s cannot be checked: %v", freshnessScript, err)
		}
		t.Skipf("python3 is not on PATH: %v", err)
	}
	return path
}

// freshnessEnv is the test's environment minus what would change the script's
// behaviour: GITHUB_ACTIONS and GITHUB_STEP_SUMMARY would annotate CI's own job
// and append to its summary, a token would be sent to the fake API, and a
// proxy would intercept requests meant for it.
func freshnessEnv() []string {
	var env []string
	for _, kv := range os.Environ() {
		name, _, _ := strings.Cut(kv, "=")
		upper := strings.ToUpper(name)
		if strings.HasPrefix(upper, "GITHUB_") || upper == "GH_TOKEN" || strings.HasSuffix(upper, "_PROXY") {
			continue
		}
		env = append(env, kv)
	}
	return env
}

// scratchRepo is a throwaway repository whose commits carry chosen dates.
type scratchRepo struct {
	t   *testing.T
	dir string
}

func newScratchRepo(t *testing.T) *scratchRepo {
	t.Helper()
	r := &scratchRepo{t: t, dir: t.TempDir()}
	r.git(time.Time{}, "init", "--quiet", "--initial-branch=main")
	return r
}

func (r *scratchRepo) git(when time.Time, args ...string) string {
	r.t.Helper()
	cmd := exec.Command("git", append([]string{"-C", r.dir}, args...)...)
	cmd.Env = append(os.Environ(),
		"GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL="+os.DevNull,
		"GIT_AUTHOR_NAME=docs freshness", "GIT_AUTHOR_EMAIL=docs@example.invalid",
		"GIT_COMMITTER_NAME=docs freshness", "GIT_COMMITTER_EMAIL=docs@example.invalid")
	if !when.IsZero() {
		date := when.UTC().Format(time.RFC3339)
		cmd.Env = append(cmd.Env, "GIT_AUTHOR_DATE="+date, "GIT_COMMITTER_DATE="+date)
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		r.t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return strings.TrimSpace(string(out))
}

// commit writes files and commits them as of when, returning the commit.
func (r *scratchRepo) commit(subject string, when time.Time, files map[string]string) string {
	r.t.Helper()
	for name, body := range files {
		path := filepath.Join(r.dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			r.t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			r.t.Fatal(err)
		}
	}
	r.git(when, "add", "-A")
	r.git(when, "commit", "--quiet", "-m", subject)
	return r.git(when, "rev-parse", "HEAD")
}

// scratchWorkflow is the docs.yml the scratch repository publishes with. Only
// on.push.paths matters to the script: it is what makes a commit docs-touching.
const scratchWorkflow = `name: Documentation site
on:
  push:
    branches: [main]
    paths:
      # the guides, and the build that renders them
      - "docs/**"
      - "Makefile"
  pull_request:
    paths: ["docs/**", "Makefile"]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: make docs-site
`

// fakeGitHub serves the live site under /site/ and the REST API under /api/.
// Every field is set before the server starts and never written after.
type fakeGitHub struct {
	stamp       string // build.json's body; empty answers 404
	apiDown     bool   // every API request answers 404
	runs        []map[string]any
	jobs        map[int64][]map[string]any
	pending     map[int64][]map[string]any
	deployments []map[string]any // newest first, as GitHub lists them
	statuses    map[int64][]map[string]any
}

func (f fakeGitHub) serve(t *testing.T) string {
	t.Helper()
	writeJSON := func(w http.ResponseWriter, v any) {
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(v); err != nil {
			t.Errorf("encode fake API response: %v", err)
		}
	}
	idIn := func(path, prefix, suffix string) int64 {
		id, _ := strconv.ParseInt(strings.TrimSuffix(strings.TrimPrefix(path, prefix), suffix), 10, 64)
		return id
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/site/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/site/build.json" {
			if f.stamp == "" {
				http.NotFound(w, r)
				return
			}
			_, _ = w.Write([]byte(f.stamp))
			return
		}
		w.Header().Set("Last-Modified", "Tue, 29 Sep 2026 01:53:12 GMT")
		_, _ = w.Write([]byte("<!doctype html><title>cloop</title>"))
	})
	mux.HandleFunc("/api/", func(w http.ResponseWriter, r *http.Request) {
		path := strings.TrimPrefix(r.URL.Path, "/api/repos/o/r")
		switch {
		case f.apiDown || path == r.URL.Path:
			w.WriteHeader(http.StatusNotFound)
			writeJSON(w, map[string]any{"message": "Not Found"})
		case path == "/actions/workflows/docs.yml/runs":
			if got := r.URL.Query().Get("branch"); got != "main" {
				t.Errorf("runs listed for branch %q, want main", got)
			}
			out := []map[string]any{}
			for _, run := range f.runs {
				if s := r.URL.Query().Get("status"); s == "" || run["status"] == s {
					out = append(out, run)
				}
			}
			writeJSON(w, map[string]any{"total_count": len(out), "workflow_runs": out})
		case strings.HasSuffix(path, "/jobs"):
			jobs := f.jobs[idIn(path, "/actions/runs/", "/jobs")]
			if jobs == nil {
				jobs = []map[string]any{}
			}
			writeJSON(w, map[string]any{"total_count": len(jobs), "jobs": jobs})
		case strings.HasSuffix(path, "/pending_deployments"):
			pending := f.pending[idIn(path, "/actions/runs/", "/pending_deployments")]
			if pending == nil {
				pending = []map[string]any{}
			}
			writeJSON(w, pending)
		case path == "/deployments":
			if got := r.URL.Query().Get("environment"); got != "github-pages" {
				t.Errorf("deployments listed for environment %q, want github-pages", got)
			}
			writeJSON(w, append([]map[string]any{}, f.deployments...))
		case strings.HasSuffix(path, "/statuses"):
			statuses := f.statuses[idIn(path, "/deployments/", "/statuses")]
			if statuses == nil {
				statuses = []map[string]any{}
			}
			writeJSON(w, statuses)
		default:
			t.Errorf("unexpected API request %s", r.URL)
			http.NotFound(w, r)
		}
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv.URL
}

func iso(t time.Time) string { return t.UTC().Format(time.RFC3339) }

func fakeRun(id int64, sha, event, status, conclusion string, created time.Time) map[string]any {
	run := map[string]any{
		"id": id, "head_sha": sha, "head_branch": "main", "event": event,
		"status": status, "conclusion": nil,
		"created_at": iso(created), "updated_at": iso(created.Add(2 * time.Minute)),
		"html_url": fmt.Sprintf("https://github.example/o/r/actions/runs/%d", id),
	}
	if conclusion != "" {
		run["conclusion"] = conclusion
	}
	return run
}

func fakeStamp(t *testing.T, commit any) string {
	t.Helper()
	body, err := json.Marshal(map[string]any{
		"format": 1, "commit": commit, "commit_time": "2026-10-04T06:00:00+00:00",
		"dirty": false, "built_at": "2026-10-04T06:05:00Z", "ref": "refs/heads/main",
		"run": "https://github.example/o/r/actions/runs/1",
	})
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}

// runFreshness runs the script against repo and the fake at server, as of now.
func runFreshness(t *testing.T, repoDir, server string, now time.Time, extra ...string) (int, string) {
	t.Helper()
	args := append([]string{
		filepath.Join(repoRoot(t), freshnessScript),
		"--repo-dir", repoDir, "--no-fetch", "--ref", "main",
		"--site-url", server + "/site/", "--api-url", server + "/api", "--repo", "o/r",
		"--now", iso(now),
	}, extra...)
	cmd := exec.Command(python3(t), args...)
	cmd.Env = freshnessEnv()
	out, err := cmd.CombinedOutput()
	var exit *exec.ExitError
	switch {
	case err == nil:
		return 0, string(out)
	case errors.As(err, &exit):
		return exit.ExitCode(), string(out)
	}
	t.Fatalf("run %s: %v\n%s", freshnessScript, err, out)
	return -1, ""
}

func mustContain(t *testing.T, out string, wants ...string) {
	t.Helper()
	for _, want := range wants {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
}

func TestDocsFreshnessVerdicts(t *testing.T) {
	python3(t)
	at := func(s string) time.Time {
		v, err := time.Parse(time.RFC3339, s)
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	repo := newScratchRepo(t)
	tA, tB, tC := at("2026-09-28T12:00:00Z"), at("2026-09-30T19:00:00Z"), at("2026-10-01T09:00:00Z")
	tD, tE := at("2026-10-03T08:00:00Z"), at("2026-10-04T06:00:00Z")
	a := repo.commit("docs: the first guides", tA, map[string]string{
		".github/workflows/docs.yml": scratchWorkflow, "docs/a.md": "# A\n", "Makefile": "docs-site:\n",
	})
	b := repo.commit("docs: the review gate guide", tB, map[string]string{"docs/b.md": "# B\n"})
	c := repo.commit("feat: code only", tC, map[string]string{"pkg/x.go": "package x\n"})
	d := repo.commit("docs: a guide written well before its push", tD, map[string]string{"docs/d.md": "# D\n"})
	e := repo.commit("ci: code only", tE, map[string]string{"pkg/y.go": "package y\n"})

	// The shape of 2026-10-04: an unstamped site from A, B's deploy held
	// on the environment, D's run pending behind it.
	heldJobs := map[int64][]map[string]any{102: {{
		"name": "Deploy to GitHub Pages", "status": "waiting", "created_at": iso(tB.Add(2 * time.Minute)),
	}}}
	heldPending := map[int64][]map[string]any{102: {{
		"environment": map[string]any{"name": "github-pages"}, "wait_timer": 0,
		"reviewers": []any{}, "current_user_can_approve": false,
	}}}

	t.Run("a held deploy and an unstamped site fail, naming the run to cancel", func(t *testing.T) {
		server := fakeGitHub{
			runs: []map[string]any{
				fakeRun(101, a, "push", "completed", "success", tA.Add(time.Minute)),
				fakeRun(102, b, "push", "waiting", "", tB.Add(time.Minute)),
				fakeRun(103, d, "push", "pending", "", tD.Add(5*time.Minute)),
			},
			jobs: heldJobs, pending: heldPending,
			deployments: []map[string]any{{"id": 2, "sha": b}, {"id": 1, "sha": a}},
			statuses: map[int64][]map[string]any{
				2: {{"state": "waiting", "created_at": iso(tB.Add(2 * time.Minute))}},
				1: {{"state": "success", "created_at": iso(tA.Add(2 * time.Minute))},
					{"state": "in_progress", "created_at": iso(tA.Add(time.Minute))}},
			},
		}.serve(t)
		code, out := runFreshness(t, repo.dir, server, at("2026-10-04T08:00:00Z"))
		if code != 1 {
			t.Fatalf("exit %d, want 1:\n%s", code, out)
		}
		mustContain(t, out,
			// The lag leads, measured from B's push, not from the deploy that held it.
			"FAIL: the live site lags main by 3d 12h (allowed: 6h) — 2 docs-touching commits",
			"build.json answered 404",
			"last successful github-pages deployment: "+a[:7],
			"its push created docs.yml run 102",
			`job "Deploy to GitHub Pages": waiting since 2026-09-30 19:02 UTC`,
			"requires no reviewer and sets no wait timer",
			"docs.yml run 103 for "+d[:7]+" (push): pending since 2026-10-03 08:05 UTC",
			"to fix: docs.yml run 102 has been waiting since 2026-09-30 19:02 UTC",
			"Cancel workflow",
		)
	})

	t.Run("a republished site passes", func(t *testing.T) {
		server := fakeGitHub{
			stamp: fakeStamp(t, e),
			runs: []map[string]any{
				fakeRun(102, b, "push", "completed", "cancelled", tB.Add(time.Minute)),
				fakeRun(106, e, "workflow_dispatch", "completed", "success", tE.Add(time.Hour)),
			},
		}.serve(t)
		code, out := runFreshness(t, repo.dir, server, at("2026-10-04T09:00:00Z"))
		if code != 0 {
			t.Fatalf("exit %d, want 0:\n%s", code, out)
		}
		mustContain(t, out, "built from "+e[:7], "nothing: every docs-touching commit is published",
			"docs.yml run 106 for "+e[:7]+" (workflow_dispatch): success", "OK: ")
	})

	t.Run("a current site still warns about a deploy that will hold the next push", func(t *testing.T) {
		server := fakeGitHub{
			stamp: fakeStamp(t, e),
			runs:  []map[string]any{fakeRun(102, b, "push", "waiting", "", tB.Add(time.Minute))},
			jobs:  heldJobs, pending: heldPending,
		}.serve(t)
		code, out := runFreshness(t, repo.dir, server, at("2026-10-04T09:00:00Z"))
		if code != 0 {
			t.Fatalf("exit %d, want 0:\n%s", code, out)
		}
		mustContain(t, out, "warning: docs.yml run 102 has been waiting since 2026-09-30 19:02 UTC: "+
			"the next docs-touching push will not publish until it is cancelled")
	})

	// The site was built from C: it has B, lacks D.
	deployOfD := func(status, conclusion string, created time.Time) fakeGitHub {
		return fakeGitHub{
			stamp: fakeStamp(t, c),
			runs: []map[string]any{
				fakeRun(102, b, "push", "completed", "success", tB.Add(time.Minute)),
				fakeRun(103, d, "push", status, conclusion, created),
			},
		}
	}

	t.Run("a deploy under way within the allowance passes", func(t *testing.T) {
		server := deployOfD("in_progress", "", tD.Add(5*time.Minute)).serve(t)
		code, out := runFreshness(t, repo.dir, server, tD.Add(2*time.Hour))
		if code != 0 {
			t.Fatalf("exit %d, want 0:\n%s", code, out)
		}
		mustContain(t, out, "1 docs-touching commit the site does not have",
			"since 2026-10-03 08:05 UTC (1h 55m)", "oldest: "+d[:7])
	})

	t.Run("a failed deploy past the allowance fails and says to run the workflow", func(t *testing.T) {
		server := deployOfD("completed", "failure", tD.Add(5*time.Minute)).serve(t)
		code, out := runFreshness(t, repo.dir, server, tD.Add(7*time.Hour))
		if code != 1 {
			t.Fatalf("exit %d, want 1:\n%s", code, out)
		}
		mustContain(t, out, "FAIL: the live site lags main by 6h 55m (allowed: 6h)",
			"docs.yml run 103 for "+d[:7]+" (push): failure",
			"to fix: no docs.yml run is under way: run the Documentation site workflow on main")
	})

	t.Run("the allowance is the push's age, not the commit's", func(t *testing.T) {
		// D was written at tD and pushed twenty hours later; the site has had
		// two hours, not twenty-two.
		server := deployOfD("in_progress", "", tD.Add(20*time.Hour)).serve(t)
		code, out := runFreshness(t, repo.dir, server, tD.Add(22*time.Hour))
		if code != 0 {
			t.Fatalf("exit %d, want 0:\n%s", code, out)
		}
		mustContain(t, out, "(2h 00m)", "its push created docs.yml run 103")
	})

	t.Run("without a run on record the commit date stands in", func(t *testing.T) {
		server := fakeGitHub{stamp: fakeStamp(t, c)}.serve(t)
		code, out := runFreshness(t, repo.dir, server, tD.Add(7*time.Hour), "--max-lag-hours", "6")
		if code != 1 {
			t.Fatalf("exit %d, want 1:\n%s", code, out)
		}
		mustContain(t, out, "lags main by 7h 00m", "its commit date; no docs.yml push run on record contains it")
	})

	t.Run("an unreachable API is reported, not fatal", func(t *testing.T) {
		server := fakeGitHub{stamp: fakeStamp(t, e), apiDown: true}.serve(t)
		code, out := runFreshness(t, repo.dir, server, at("2026-10-04T09:00:00Z"))
		if code != 0 {
			t.Fatalf("exit %d, want 0:\n%s", code, out)
		}
		mustContain(t, out, "warning: could not list docs.yml runs", "OK: ")
	})

	t.Run("a stamp naming a commit main lacks fails", func(t *testing.T) {
		server := fakeGitHub{stamp: fakeStamp(t, strings.Repeat("0123456789", 4))}.serve(t)
		code, out := runFreshness(t, repo.dir, server, at("2026-10-04T09:00:00Z"))
		if code != 1 {
			t.Fatalf("exit %d, want 1:\n%s", code, out)
		}
		mustContain(t, out, "which main does not contain")
	})

	t.Run("a stamp naming no commit fails", func(t *testing.T) {
		server := fakeGitHub{stamp: fakeStamp(t, nil)}.serve(t)
		code, out := runFreshness(t, repo.dir, server, at("2026-10-04T09:00:00Z"))
		if code != 1 {
			t.Fatalf("exit %d, want 1:\n%s", code, out)
		}
		mustContain(t, out, "names no commit")
	})

	t.Run("a check that cannot run exits 2, not 1", func(t *testing.T) {
		server := fakeGitHub{stamp: fakeStamp(t, e)}.serve(t)
		code, out := runFreshness(t, repo.dir, server, at("2026-10-04T09:00:00Z"), "--ref", "no-such-branch")
		if code != 2 {
			t.Fatalf("exit %d, want 2:\n%s", code, out)
		}
		mustContain(t, out, "cannot check: no-such-branch does not name a commit")
	})
}

// TestDocsFreshnessReadsDocsYmlTriggers holds the script's line scanner to a
// real YAML parser on the real docs.yml. The trigger list is what defines a
// docs-touching commit; a scanner that dropped an entry would quietly stop
// counting that path's commits, and the check would pass a stale site.
func TestDocsFreshnessReadsDocsYmlTriggers(t *testing.T) {
	py := python3(t)
	listPaths := func(t *testing.T, repoDir string) (int, []string, string) {
		t.Helper()
		cmd := exec.Command(py, filepath.Join(repoRoot(t), freshnessScript), "--list-paths", "--repo-dir", repoDir)
		cmd.Env = freshnessEnv()
		out, err := cmd.CombinedOutput()
		var exit *exec.ExitError
		if err != nil && !errors.As(err, &exit) {
			t.Fatalf("run %s: %v\n%s", freshnessScript, err, out)
		}
		code := 0
		if exit != nil {
			code = exit.ExitCode()
		}
		return code, strings.Fields(string(out)), string(out)
	}

	t.Run("the real docs.yml", func(t *testing.T) {
		root := repoRoot(t)
		raw, err := os.ReadFile(filepath.Join(root, ".github", "workflows", "docs.yml"))
		if err != nil {
			t.Fatal(err)
		}
		var workflow struct {
			On struct {
				Push        struct{ Paths []string } `yaml:"push"`
				PullRequest struct{ Paths []string } `yaml:"pull_request"`
			} `yaml:"on"`
		}
		if err := yaml.Unmarshal(raw, &workflow); err != nil {
			t.Fatalf("parse docs.yml: %v", err)
		}
		if len(workflow.On.Push.Paths) == 0 {
			t.Fatal("docs.yml has no on.push.paths — the script would refuse to run")
		}
		code, got, out := listPaths(t, root)
		if code != 0 || !reflect.DeepEqual(got, workflow.On.Push.Paths) {
			t.Errorf("the script reads on.push.paths as %q (exit %d), YAML says %q\n%s",
				got, code, workflow.On.Push.Paths, out)
		}
		// docs.yml says the two lists are kept in sync by hand. A pull request
		// that the gate does not build is one whose breakage lands on main.
		if !reflect.DeepEqual(workflow.On.Push.Paths, workflow.On.PullRequest.Paths) {
			t.Errorf("docs.yml's push and pull_request paths differ:\n push %q\n   pr %q",
				workflow.On.Push.Paths, workflow.On.PullRequest.Paths)
		}
	})

	shapes := []struct {
		name, workflow string
		want           []string // nil: the script must refuse, exit 2
	}{
		{"flow list", "on:\n  push:\n    paths: [\"docs/**\", 'Makefile']\n", []string{"docs/**", "Makefile"}},
		{"sequence at its key's indentation", "on:\n  push:\n    paths:\n    - docs/**\n    - Makefile # build\n" +
			"  pull_request:\n    paths:\n    - other/**\n", []string{"docs/**", "Makefile"}},
		{"quoted keys and comments", "\"on\":\n  # publishes\n  'push':\n    paths:\n      - \"docs/#1/**\"  # odd but legal\n",
			[]string{"docs/#1/**"}},
		{"no paths filter", "on: [push]\n", nil},
		{"a negated pattern", "on:\n  push:\n    paths:\n      - docs/**\n      - \"!docs/drafts/**\"\n", nil},
	}
	for _, shape := range shapes {
		t.Run(shape.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, ".github", "workflows", "docs.yml")
			if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, []byte(shape.workflow), 0o644); err != nil {
				t.Fatal(err)
			}
			code, got, out := listPaths(t, dir)
			switch {
			case shape.want == nil && code != 2:
				t.Errorf("exit %d, want 2 (refused):\n%s", code, out)
			case shape.want != nil && (code != 0 || !reflect.DeepEqual(got, shape.want)):
				t.Errorf("read %q (exit %d), want %q:\n%s", got, code, shape.want, out)
			}
		})
	}
}
