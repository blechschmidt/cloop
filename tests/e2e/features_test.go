package e2e_test

// Parallel features, end to end (Task 20341): the built binary serving the
// dashboard API, `cloop feature` dispatched by it, real git worktrees, three
// runs of one repository executing at the same time, and pull requests opened
// against a fake GitHub.
//
// The repository's origin is https://github.com/acme/app.git — what the pull
// request code reads to find the forge — with a url.insteadOf rewrite that
// sends git's pushes to a local bare repository instead, so every push is real
// and inspectable and nothing leaves the machine.

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeForge is the part of the GitHub REST API the feature pull requests use.
type fakeForge struct {
	mu    sync.Mutex
	token string
	next  int
	prs   map[int]map[string]any
}

func (f *fakeForge) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	if r.Header.Get("Authorization") != "Bearer "+f.token {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = io.WriteString(w, `{"message":"Bad credentials"}`)
		return
	}
	const base = "/repos/acme/app/pulls"
	switch {
	case r.Method == http.MethodPost && r.URL.Path == base:
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		for _, p := range f.prs {
			if p["head"].(map[string]any)["ref"] == body["head"] && p["state"] == "open" {
				w.WriteHeader(http.StatusUnprocessableEntity)
				_, _ = io.WriteString(w, `{"message":"Validation Failed"}`)
				return
			}
		}
		f.next++
		p := map[string]any{
			"number": f.next, "state": "open", "draft": body["draft"], "title": body["title"], "body": body["body"],
			"html_url": fmt.Sprintf("https://github.com/acme/app/pull/%d", f.next),
			"head":     map[string]any{"ref": body["head"]}, "base": map[string]any{"ref": body["base"]},
		}
		f.prs[f.next] = p
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(p)
	case r.Method == http.MethodGet && r.URL.Path == base:
		var out []map[string]any
		for _, p := range f.prs {
			if "acme:"+p["head"].(map[string]any)["ref"].(string) == r.URL.Query().Get("head") && p["state"] == "open" {
				out = append(out, p)
			}
		}
		_ = json.NewEncoder(w).Encode(out)
	case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, base+"/"):
		var n int
		fmt.Sscanf(strings.TrimPrefix(r.URL.Path, base+"/"), "%d", &n)
		if p, ok := f.prs[n]; ok {
			_ = json.NewEncoder(w).Encode(p)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	default:
		w.WriteHeader(http.StatusTeapot)
	}
}

func (f *fakeForge) byHead(head string) map[string]any {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, p := range f.prs {
		if p["head"].(map[string]any)["ref"] == head {
			return p
		}
	}
	return nil
}

func TestE2EFeatures_ParallelDevelopmentAndPullRequests(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	bin := binaryPath(t)
	root := t.TempDir()
	home := filepath.Join(root, "home")
	if err := os.MkdirAll(home, 0o755); err != nil {
		t.Fatal(err)
	}
	gitconfig := filepath.Join(home, ".gitconfig")
	if err := os.WriteFile(gitconfig, []byte("[user]\n\tname = E2E\n\temail = e2e@example.com\n[init]\n\tdefaultBranch = main\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	forge := &fakeForge{token: "e2e-forge-token", prs: map[int]map[string]any{}, next: 40}
	api := httptest.NewServer(forge)
	defer api.Close()

	env := append(os.Environ(),
		"HOME="+home,
		"CLOOP_HOME="+filepath.Join(home, ".cloop"),
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_CONFIG_GLOBAL="+gitconfig,
		"GIT_TERMINAL_PROMPT=0",
		"NO_COLOR=1",
		"CLOOP_GITHUB_API_URL="+api.URL,
		"GITHUB_TOKEN="+forge.token,
	)
	git := func(dir string, args ...string) string {
		t.Helper()
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		cmd.Env = env
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("git %v in %s: %v\n%s", args, dir, err, out)
		}
		return strings.TrimSpace(string(out))
	}
	cloop := func(dir string, args ...string) string {
		t.Helper()
		cmd := exec.Command(bin, args...)
		cmd.Dir = dir
		cmd.Env = env
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("cloop %v in %s: %v\n%s", args, dir, err, out)
		}
		return string(out)
	}

	// The project: a repository whose origin names GitHub and pushes locally.
	origin := filepath.Join(root, "origin.git")
	proj := filepath.Join(root, "proj")
	git(root, "init", "-q", "--bare", origin)
	if err := os.MkdirAll(proj, 0o755); err != nil {
		t.Fatal(err)
	}
	git(proj, "init", "-q")
	if err := os.WriteFile(filepath.Join(proj, "README.md"), []byte("app\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	git(proj, "add", "README.md")
	git(proj, "commit", "-qm", "init")
	git(proj, "remote", "add", "origin", "https://github.com/acme/app.git")
	git(proj, "config", "url."+origin+".insteadOf", "https://github.com/acme/app.git")
	git(proj, "push", "-q", "origin", "main")
	cloop(proj, "init", "--provider", "mock", "--skip-clarify", "Parent goal")
	// init leaves a .gitignore for .cloop/env.yaml; committed, as a user would.
	git(proj, "add", ".gitignore")
	git(proj, "commit", "-qm", "ignore cloop env")
	git(proj, "push", "-q", "origin", "main")
	cloop(proj, "task", "add", "Parent task", "--no-ai")
	// Stands in for a harness committing its work: every task, in whichever
	// worktree it runs, appends to a log named after that worktree and commits.
	// Features inherit this config, so the hook runs in each of them too.
	cfg := filepath.Join(proj, ".cloop", "config.yaml")
	f, err := os.OpenFile(cfg, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = f.WriteString("hooks:\n    post_task: 'sleep 1; n=$(basename \"$PWD\"); echo \"$CLOOP_TASK_TITLE\" >> \"LOG-$n.md\" && git add \"LOG-$n.md\" && git commit -qm \"$n task $CLOOP_TASK_ID\"'\n")
	_ = f.Close()

	// The hub, from a directory of its own, with the project registered.
	hubDir := filepath.Join(root, "hub")
	if err := os.MkdirAll(hubDir, 0o755); err != nil {
		t.Fatal(err)
	}
	cloop(hubDir, "init", "--provider", "mock", "--skip-clarify", "hub")
	port := freePort(t)
	hub := exec.Command(bin, "ui", "--port", fmt.Sprint(port), "--no-browser", "--projects", proj)
	hub.Dir = hubDir
	hub.Env = env
	var hubLog strings.Builder
	logw := &syncWriter{w: &hubLog}
	hub.Stdout, hub.Stderr = logw, logw
	if err := hub.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = hub.Process.Kill()
		_, _ = hub.Process.Wait()
		if t.Failed() {
			t.Logf("hub log:\n%s", hubLog.String())
		}
	})
	base := fmt.Sprintf("http://127.0.0.1:%d", port)
	call := func(method, path string, body any) (int, map[string]any) {
		t.Helper()
		var rd io.Reader
		if body != nil {
			b, _ := json.Marshal(body)
			rd = strings.NewReader(string(b))
		}
		req, _ := http.NewRequest(method, base+path, rd)
		if body != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("%s %s: %v", method, path, err)
		}
		defer resp.Body.Close()
		var out map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&out)
		return resp.StatusCode, out
	}
	projects := func() []map[string]any {
		t.Helper()
		_, body := call("GET", "/api/projects", nil)
		raw, _ := body["projects"].([]any)
		out := make([]map[string]any, len(raw))
		for i, r := range raw {
			out[i] = r.(map[string]any)
		}
		return out
	}
	waitFor := func(what string, timeout time.Duration, cond func() bool) {
		t.Helper()
		deadline := time.Now().Add(timeout)
		for !cond() {
			if time.Now().After(deadline) {
				t.Fatalf("timed out waiting for %s; projects: %v", what, projects())
			}
			time.Sleep(200 * time.Millisecond)
		}
	}
	waitFor("the hub", 30*time.Second, func() bool {
		resp, err := http.Get(base + "/api/projects")
		if err != nil {
			return false
		}
		resp.Body.Close()
		return resp.StatusCode == 200
	})

	// Two features of the project, each with its own tasks and settings.
	code, login := call("POST", "/api/projects/1/features", map[string]any{
		"name": "Login", "description": "Users can sign in", "tasks": []string{"Form", "Hashing"}, "auto_pr": true})
	if code != 200 || login["project_idx"] != float64(2) || login["branch"] != "cloop/feature/login" {
		t.Fatalf("create login = %d %v", code, login)
	}
	code, dark := call("POST", "/api/projects/1/features", map[string]any{
		"name": "Dark mode", "description": "A dark theme", "tasks": []string{"CSS variables"}, "innovate": true})
	if code != 200 || dark["project_idx"] != float64(3) {
		t.Fatalf("create dark mode = %d %v", code, dark)
	}
	ps := projects()
	if len(ps) != 4 || ps[2]["parent"] != proj || ps[3]["parent"] != proj {
		t.Fatalf("projects after creating two features: %v", ps)
	}
	if fs := ps[3]["feature"].(map[string]any); fs["innovate"] != true || fs["auto_evolve"] == true {
		t.Errorf("dark mode's own settings: %v", fs)
	}
	if fs := ps[2]["feature"].(map[string]any); fs["auto_pr"] != true || fs["innovate"] == true {
		t.Errorf("login's own settings: %v", fs)
	}

	// All three at once.
	for _, i := range []int{1, 2, 3} {
		if code, body := call("POST", fmt.Sprintf("/api/run?project_idx=%d", i), map[string]any{}); code != 200 || body["ok"] != true {
			t.Fatalf("start %d = %d %v", i, code, body)
		}
	}
	maxConcurrent := 0
	waitFor("all three to complete", 90*time.Second, func() bool {
		ps := projects()
		running, complete := 0, 0
		for _, p := range ps[1:] {
			if p["running"] == true {
				running++
			}
			if p["status"] == "complete" && p["running"] != true {
				complete++
			}
		}
		if running > maxConcurrent {
			maxConcurrent = running
		}
		return complete == 3
	})
	if maxConcurrent < 2 {
		t.Errorf("at most %d of the three ran at the same time — the features did not run in parallel", maxConcurrent)
	}

	// Each line of work landed on its own branch and nowhere else.
	onBranch := func(branch string) string { return git(proj, "log", "--format=%s", "main.."+branch) }
	if log := git(proj, "log", "--format=%s", "-3", "main"); !strings.Contains(log, "proj task 1") || strings.Contains(log, "login") || strings.Contains(log, "dark-mode") {
		t.Errorf("main's history:\n%s", log)
	}
	if log := onBranch("cloop/feature/login"); strings.Count(log, "login task") != 2 || strings.Contains(log, "proj task") {
		t.Errorf("login's history:\n%s", log)
	}
	if log := onBranch("cloop/feature/dark-mode"); strings.Count(log, "dark-mode task") != 1 {
		t.Errorf("dark mode's history:\n%s", log)
	}
	if out := git(proj, "status", "--porcelain"); out != "" {
		t.Errorf("the project's worktree is dirty after its features ran:\n%s", out)
	}

	// Login asked for its pull request on completion.
	waitFor("login's automatic pull request", 60*time.Second, func() bool {
		p := projects()[2]
		fs, _ := p["feature"].(map[string]any)
		return fs != nil && fs["pr"] != nil
	})
	pr := forge.byHead("cloop/feature/login")
	if pr == nil || pr["base"].(map[string]any)["ref"] != "main" || pr["title"] != "Login" ||
		!strings.Contains(pr["body"].(string), "- [x] #1 Form") {
		t.Errorf("login's pull request = %v", pr)
	}
	if sha := git(origin, "rev-parse", "refs/heads/cloop/feature/login"); sha != git(proj, "rev-parse", "cloop/feature/login") {
		t.Errorf("origin has %s for login, the project %s", sha, git(proj, "rev-parse", "cloop/feature/login"))
	}

	// Dark mode's, by hand, as a draft.
	code, body := call("POST", "/api/projects/1/features/dark-mode/pr", map[string]any{"draft": true})
	if code != 200 || body["ok"] != true {
		t.Fatalf("dark mode PR = %d %v", code, body)
	}
	if p := forge.byHead("cloop/feature/dark-mode"); p == nil || p["draft"] != true {
		t.Errorf("dark mode's pull request = %v", p)
	}
	// Asked again, the open one is returned rather than a second opened.
	code, body = call("POST", "/api/projects/1/features/dark-mode/pr", map[string]any{})
	if res, _ := body["result"].(map[string]any); code != 200 || res["existing"] != true {
		t.Errorf("repeat PR = %d %v", code, body)
	}

	// Removing a feature keeps its branch, and the project's list follows.
	code, body = call("DELETE", "/api/projects/1/features/dark-mode", nil)
	if code != 200 || body["branch_deleted"] != false {
		t.Fatalf("remove = %d %v", code, body)
	}
	if ps := projects(); len(ps) != 3 {
		t.Errorf("after removing a feature the list has %d entries", len(ps))
	}
	if out := git(proj, "branch", "--list", "cloop/feature/dark-mode"); out == "" {
		t.Error("removing the feature deleted its branch")
	}
	if list := git(proj, "worktree", "list"); strings.Contains(list, "dark-mode") {
		t.Errorf("the worktree is still registered:\n%s", list)
	}
}

// freePort returns a TCP port nothing is listening on right now.
func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

// syncWriter serialises writes from the hub's stdout and stderr.
type syncWriter struct {
	mu sync.Mutex
	w  io.Writer
}

func (s *syncWriter) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.w.Write(p)
}
