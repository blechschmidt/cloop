package e2e_test

// Project confinement on a real hub whose only executor is a container
// sandbox (Task 20418).
//
// A strict hub (executors.allow_host_process: false) runs every workload in a
// Docker container that bind-mounts the project's directory read-write at
// /workspace — so the directory a project is registered at is exactly what
// model-authored code can read and write. This test drives the real `cloop ui`
// with a maintainer's API token and an administrator's, and checks:
//
//   - a maintainer cannot register the projects root's parent, the root
//     itself (with or without a trailing slash), a directory outside the root
//     or the hub's own directory — and nothing is made for any of them;
//   - the same maintainer can create a project by name, and its `cloop init`
//     ran in a container (on this hub nothing else can run it);
//   - a row that breaks the rule, written to the registry the way a registry
//     from before the rule — or an operator's --projects — would hold it, is
//     listed and flagged, refused at dispatch with the overlap named, never
//     reaches Docker, and fails `cloop hub doctor`.
//
// It starts real containers and builds a small image, so it is opt-in:
// CLOOP_CONFINE_CONTAINER_E2E=1 (CI's flagship job sets it).

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestE2EProjectConfinementInAContainer(t *testing.T) {
	if os.Getenv("CLOOP_CONFINE_CONTAINER_E2E") != "1" {
		t.Skip("set CLOOP_CONFINE_CONTAINER_E2E=1 to run project confinement against a container sandbox (needs docker)")
	}
	if out, err := exec.Command("docker", "version", "--format", "{{.Server.Version}}").CombinedOutput(); err != nil {
		t.Skipf("docker is not usable: %v %s", err, out)
	}
	image := buildFeatureImage(t)
	bin := binaryPath(t)

	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	// HOME apart from the hub and its projects: a directory containing the
	// hub user's home is refused by a rule of its own, which would answer
	// before the ones this test is about.
	home := t.TempDir()
	hubDir := filepath.Join(base, "hub")
	root := filepath.Join(base, "projects")
	for _, d := range []string{home, hubDir} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	env := append(withoutCloopEnv(os.Environ()),
		"HOME="+home,
		"CLOOP_HOME="+filepath.Join(home, ".cloop"),
		"CLOOP_SECRET_KEY=e2e-project-confinement",
		"GIT_CONFIG_NOSYSTEM=1",
		"NO_COLOR=1",
	)
	cloop := func(dir string, args ...string) (string, error) {
		cmd := exec.Command(bin, args...)
		cmd.Dir = dir
		cmd.Env = env
		out, err := cmd.CombinedOutput()
		return string(out), err
	}
	mustCloop := func(dir string, args ...string) string {
		t.Helper()
		out, err := cloop(dir, args...)
		if err != nil {
			t.Fatalf("cloop %v in %s: %v\n%s", args, dir, err, out)
		}
		return out
	}

	mustCloop(hubDir, "init", "--provider", "mock", "--skip-clarify", "the hub")
	// The workload runs as the owner of the project's directory, which for a
	// directory the hub made is the hub's own user. The driver refuses uid 0
	// unless told otherwise, and a developer's machine runs this as root.
	rootUser := ""
	if os.Getuid() == 0 {
		rootUser = "        allow_root_user: true\n"
	}
	appendConfig(t, hubDir, fmt.Sprintf("executors:\n    allow_host_process: false\n"+
		"    container:\n        enabled: true\n        runtime: docker\n        image: %s\n        network: none\n%s"+
		"ui:\n    projects_root: %s\n", image, rootUser, root))
	maintainer := strings.TrimSpace(mustCloop(hubDir, "hub", "token", "create", "e2e-maintainer", "--role", "maintainer", "--quiet"))
	admin := strings.TrimSpace(mustCloop(hubDir, "hub", "token", "create", "e2e-admin", "--role", "admin", "--quiet"))

	port := freePort(t)
	baseURL := fmt.Sprintf("http://127.0.0.1:%d", port)
	hub := exec.Command(bin, "ui", "--port", fmt.Sprint(port), "--no-browser")
	hub.Dir = hubDir
	hub.Env = env
	hub.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	hubLog := &strings.Builder{}
	w := &syncWriter{w: hubLog}
	hub.Stdout, hub.Stderr = w, w
	if err := hub.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = syscall.Kill(-hub.Process.Pid, syscall.SIGKILL)
		_, _ = hub.Process.Wait()
		if t.Failed() {
			t.Logf("hub log:\n%s", tail(hubLog.String(), 12000))
		}
	})
	waitHealthy(t, baseURL)

	call := func(token, method, path string, body any) (int, map[string]any) {
		t.Helper()
		var rd io.Reader
		if body != nil {
			b, _ := json.Marshal(body)
			rd = strings.NewReader(string(b))
		}
		req, _ := http.NewRequest(method, baseURL+path, rd)
		if body != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		req.Header.Set("Authorization", "Bearer "+token)
		resp, err := (&http.Client{Timeout: 5 * time.Minute}).Do(req)
		if err != nil {
			t.Fatalf("%s %s: %v", method, path, err)
		}
		defer resp.Body.Close()
		var out map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&out)
		return resp.StatusCode, out
	}
	message := func(body map[string]any) string {
		if e, ok := body["error"].(map[string]any); ok {
			m, _ := e["message"].(string)
			return m
		}
		m, _ := body["error"].(string)
		return m
	}

	// ── A maintainer, at the directories the task names ─────────────────────
	baseBefore := listDir(t, base)
	for _, c := range []struct {
		name, dir string
		status    int
		says      string
	}{
		{"the root's parent", root + "/..", http.StatusConflict, "contains the hub's projects root"},
		{"the root", root, http.StatusConflict, "is the hub's projects root"},
		{"the root, trailing slash", root + "/", http.StatusConflict, "is the hub's projects root"},
		{"outside the root", filepath.Join(base, "elsewhere"), http.StatusForbidden, "only an administrator"},
		{"the hub's own directory", hubDir, http.StatusForbidden, "only an administrator"},
	} {
		status, body := call(maintainer, http.MethodPost, "/api/projects/new", map[string]any{"dir": c.dir, "goal": "probe"})
		if status != c.status || !strings.Contains(message(body), c.says) {
			t.Fatalf("%s (%s): HTTP %d %v, want %d saying %q", c.name, c.dir, status, body, c.status, c.says)
		}
	}
	if after := listDir(t, base); after != baseBefore {
		t.Fatalf("refused creations changed %s:\nbefore %s\nafter  %s", base, baseBefore, after)
	}
	if _, err := os.Stat(filepath.Join(base, ".cloop")); !os.IsNotExist(err) {
		t.Fatalf("a refused creation initialised the root's parent: %v", err)
	}

	// ── The same maintainer, by name: init ran in a container ───────────────
	status, body := call(maintainer, http.MethodPost, "/api/projects/new", map[string]any{"name": "widgets", "goal": "Ship widgets"})
	widgets := filepath.Join(root, "widgets")
	if status != http.StatusOK || body["dir"] != widgets {
		t.Fatalf("a maintainer's creation by name: HTTP %d %v", status, body)
	}
	if _, err := os.Stat(filepath.Join(widgets, ".cloop", "state.db")); err != nil {
		t.Fatalf("the project was not initialised — on a strict hub only the container could have: %v", err)
	}
	// "Only the container could have": nothing else that runs work is
	// registered on this hub.
	_, body = call(admin, http.MethodGet, "/api/executors", nil)
	executors, _ := body["executors"].([]any)
	var kinds []string
	for _, e := range executors {
		if m, _ := e.(map[string]any); m["registered"] == true {
			kinds = append(kinds, fmt.Sprint(m["kind"]))
		}
	}
	if len(kinds) != 1 || kinds[0] != "container" {
		t.Fatalf("registered executors are %v, want the container sandbox alone", kinds)
	}

	// ── A row that breaks the rule ──────────────────────────────────────────
	// A project inside the hub's own directory, initialised and registered
	// outside the API, as a registry from before the rule would hold it.
	nested := filepath.Join(hubDir, "nested")
	if err := os.MkdirAll(nested, 0o755); err != nil {
		t.Fatal(err)
	}
	mustCloop(nested, "init", "--provider", "mock", "--skip-clarify", "nested goal")
	registerRow(t, filepath.Join(home, ".cloop", "projects.json"), nested)

	status, body = call(admin, http.MethodGet, "/api/projects", nil)
	list, _ := body["projects"].([]any)
	idx := -1
	for i, p := range list {
		if m, _ := p.(map[string]any); m["path"] == nested {
			idx = i
			if flag, _ := m["confinement"].(string); !strings.Contains(flag, "will not run this project") {
				t.Errorf("the row is listed without its flag: %v", m)
			}
		}
	}
	if status != http.StatusOK || idx < 0 {
		t.Fatalf("the nested row is not listed: HTTP %d %v", status, body)
	}
	status, body = call(admin, http.MethodPost, fmt.Sprintf("/api/projects/%d/run", idx), map[string]any{})
	if status != http.StatusConflict || body["code"] != "project_unconfined" ||
		!strings.Contains(fmt.Sprint(body["error"]), "inside the hub's control plane ("+hubDir+")") {
		t.Fatalf("an administrator's run of the nested row: HTTP %d %v, want 409 project_unconfined naming the overlap", status, body)
	}
	if out, _ := exec.Command("docker", "ps", "-aq", "--filter", "label=cloop.managed=true",
		"--filter", "label=cloop.project="+nested).Output(); strings.TrimSpace(string(out)) != "" {
		t.Fatalf("a container was made for the refused row: %s", out)
	}
	out, err := cloop(hubDir, "hub", "doctor", "--offline")
	if err == nil || !strings.Contains(out, "projects.confinement") && !strings.Contains(out, "Project directories") ||
		!strings.Contains(out, nested) {
		t.Fatalf("`cloop hub doctor` does not fail naming the row (err %v):\n%s", err, out)
	}
	if _, err := os.Stat(filepath.Join(nested, ".cloop", "state.db")); err != nil {
		t.Fatalf("the doctor or the refusal touched the nested project: %v", err)
	}
}

// appendConfig appends text to dir's .cloop/config.yaml.
func appendConfig(t *testing.T, dir, text string) {
	t.Helper()
	f, err := os.OpenFile(filepath.Join(dir, ".cloop", "config.yaml"), os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := f.WriteString("\n" + text); err != nil {
		t.Fatal(err)
	}
}

// registerRow appends path to the registry file as an unowned row.
func registerRow(t *testing.T, registry, path string) {
	t.Helper()
	var reg struct {
		Projects []map[string]any `json:"projects"`
	}
	if data, err := os.ReadFile(registry); err == nil {
		if err := json.Unmarshal(data, &reg); err != nil {
			t.Fatal(err)
		}
	}
	reg.Projects = append(reg.Projects, map[string]any{"name": filepath.Base(path), "path": path})
	data, _ := json.Marshal(reg)
	if err := os.MkdirAll(filepath.Dir(registry), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(registry, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

// listDir is a directory's entries, for a before-and-after comparison.
func listDir(t *testing.T, dir string) string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	return strings.Join(names, ",")
}

// waitHealthy waits for the hub at baseURL to answer /healthz.
func waitHealthy(t *testing.T, baseURL string) {
	t.Helper()
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		if resp, err := http.Get(baseURL + "/healthz"); err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return
			}
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatalf("the hub at %s did not answer within a minute", baseURL)
}
