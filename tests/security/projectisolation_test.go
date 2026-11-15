package security

// Projects on the hub's own host, end to end (Task 20500): a hub without
// sign-in in this process serves three projects — its own directory and two
// registered ones — and dispatches a model call for one of them to this test
// binary acting as cloop, through the real host-process driver and the real
// host sandbox, as a hub running as root uses it: Landlock under private
// mount, PID and IPC namespaces. A stand-in `claude` tries to open, list and
// write the other project, and reports what it reached as the model's answer.
// The operator's opt-out lets a project's runs out again, and the hub's own
// directory, which cannot be confined, runs only once it is opted out.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/internal/statedbtest"
	"github.com/blechschmidt/cloop/pkg/hostsandbox"
	"github.com/blechschmidt/cloop/pkg/multiui"
	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/ui"
)

// openHub is a hub without sign-in, on loopback, as `cloop ui` runs one.
type openHub struct {
	url, dir, home string
}

func startOpenHub(t *testing.T) *openHub {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	dir := t.TempDir()
	statedbtest.SeedDir(t, dir)
	if _, err := state.Init(dir, "the hub's own project", 0); err != nil {
		t.Fatal(err)
	}
	srv := ui.New(dir, 0, "")
	srv.RPS, srv.Burst = 10000, 10000
	srv.SelfExe = selfAsCLI(t)
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	})
	return &openHub{url: ts.URL, dir: dir, home: home}
}

func (h *openHub) call(t *testing.T, method, path string, body any) (int, []byte) {
	t.Helper()
	var rdr io.Reader
	if body != nil {
		blob, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		rdr = bytes.NewReader(blob)
	}
	req, err := http.NewRequest(method, h.url+path, rdr)
	if err != nil {
		t.Fatal(err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Origin", h.url)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, raw
}

// project registers a project with one task under the hub's home.
func (h *openHub) project(t *testing.T, name string) string {
	t.Helper()
	dir := filepath.Join(h.home, "projects", name)
	plan(t, dir, true)
	if err := multiui.AddPaths([]string{dir}); err != nil {
		t.Fatal(err)
	}
	return dir
}

// plan gives the project at dir (made when init) one task to revise.
func plan(t *testing.T, dir string, init bool) {
	t.Helper()
	var ps *state.ProjectState
	var err error
	if init {
		ps, err = state.Init(dir, "Ship "+filepath.Base(dir), 0)
	} else {
		ps, err = state.Load(dir)
	}
	if err != nil {
		t.Fatal(err)
	}
	ps.Plan = &pm.Plan{Goal: ps.Goal, Tasks: []*pm.Task{
		{ID: 1, Title: "Migrate the database", Description: "Move every table.", Status: pm.TaskPending, Priority: 1},
	}}
	if err := ps.Save(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".cloop", "config.yaml"), []byte("provider: claudecode\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}

func (h *openHub) index(t *testing.T, dir string) int {
	t.Helper()
	code, raw := h.call(t, http.MethodGet, "/api/projects", nil)
	if code != http.StatusOK {
		t.Fatalf("projects = %d %s", code, raw)
	}
	var list []struct {
		Path string `json:"path"`
	}
	if err := json.Unmarshal(raw, &list); err != nil {
		var wrapped struct {
			Projects []struct {
				Path string `json:"path"`
			} `json:"projects"`
		}
		if err := json.Unmarshal(raw, &wrapped); err != nil {
			t.Fatalf("projects: %v %s", err, raw)
		}
		list = wrapped.Projects
	}
	for i, p := range list {
		if p.Path == dir {
			return i
		}
	}
	t.Fatalf("%s is not among the projects: %s", dir, raw)
	return -1
}

// optOut writes executors.host_sandbox.opt_out into the hub's configuration.
func (h *openHub) optOut(t *testing.T, projects ...string) {
	t.Helper()
	var cfg strings.Builder
	cfg.WriteString("executors:\n  host_sandbox:\n    opt_out:\n")
	for _, p := range projects {
		cfg.WriteString("      - " + p + "\n")
	}
	if err := os.WriteFile(filepath.Join(h.dir, ".cloop", "config.yaml"), []byte(cfg.String()), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestProjectsOnTheHubsHostCannotReachEachOther(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root-gated: proves the host sandbox as a hub running as root gives it — Landlock under " +
			"private mount, PID and IPC namespaces; run the suite as root")
	}
	if err := hostsandbox.Available(); err != nil {
		t.Skipf("no host sandbox on this host: %v", err)
	}
	hub := startOpenHub(t)
	t.Setenv("CLOOP_SECRET_KEY", "the-hubs-root-key-0123456789abcdef")
	web := hub.project(t, "web")
	api := hub.project(t, "api")
	if err := os.WriteFile(filepath.Join(api, "secret.txt"), []byte("api's unreleased code\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	probeClaude(t, map[string]string{
		"own-project":   "cat " + filepath.Join(web, ".cloop", "config.yaml"),
		"write-project": "touch " + filepath.Join(web, "built.txt"),
		"api-read":      "cat " + filepath.Join(api, "secret.txt"),
		"api-list":      "ls " + api,
		"api-state":     "cat " + filepath.Join(api, ".cloop", "state.db"),
		"api-write":     "touch " + filepath.Join(api, "planted"),
		"hub-database":  "cat " + filepath.Join(hub.dir, ".cloop", "state.db"),
		"hub-registry":  "cat " + filepath.Join(hub.home, ".cloop", "projects.json"),
		"hub-process":   fmt.Sprintf("cat /proc/%d/environ", os.Getpid()),
	})
	revise := func(t *testing.T, dir string) (int, string) {
		t.Helper()
		code, raw := hub.call(t, http.MethodPost, fmt.Sprintf("/api/tasks/1/revise?project_idx=%d", hub.index(t, dir)),
			map[string]any{"instruction": "and the indexes", "description": "Move every table."})
		return code, string(raw)
	}

	t.Run("a run of one project cannot open, list or write another", func(t *testing.T) {
		code, got := revise(t, web)
		if code != http.StatusOK || !strings.Contains(got, "probes:") {
			t.Fatalf("revise = %d %s", code, got)
		}
		for _, want := range []string{"own-project:ok", "write-project:ok", "api-read:denied", "api-list:denied",
			"api-state:denied", "api-write:denied", "hub-database:denied", "hub-registry:denied",
			"hub-process:denied", "root-key:absent"} {
			if !strings.Contains(got, want) {
				t.Errorf("want %s in web's model call's answer: %s", want, got)
			}
		}
		if _, err := os.Stat(filepath.Join(api, "planted")); err == nil {
			t.Error("web's run wrote into api's tree")
		}
	})

	t.Run("the hub's own directory runs only once opted out", func(t *testing.T) {
		plan(t, hub.dir, false)
		code, got := revise(t, hub.dir)
		if code != http.StatusConflict || !strings.Contains(got, "executors.host_sandbox.opt_out") {
			t.Fatalf("a run of the hub's own directory on a shared host = %d %s", code, got)
		}
		hub.optOut(t, hub.dir)
		if code, got := revise(t, hub.dir); code != http.StatusOK || !strings.Contains(got, "api-read:ok") {
			t.Errorf("the opted-out hub directory's run = %d %s", code, got)
		}
	})

	t.Run("an opted-out project's run is not confined", func(t *testing.T) {
		// The control: the probes reach the other project once nothing keeps
		// web's run from it, so the denials above are the sandbox's.
		hub.optOut(t, web)
		code, got := revise(t, web)
		if code != http.StatusOK || !strings.Contains(got, "api-read:ok") || !strings.Contains(got, "api-list:ok") ||
			!strings.Contains(got, "root-key:absent") {
			t.Errorf("the opted-out project's run = %d %s", code, got)
		}
	})
}
