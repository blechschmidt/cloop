package cmd

// People's work on the hub's own host, end to end (Task 20480): a hub with
// single sign-on in this process dispatches a model call for one person to
// this test binary acting as cloop, through the real host-process driver and
// the real host sandbox, and a stand-in `claude` tries to reach another
// person's files, the hub's database and the hub's root key. What it could and
// could not reach comes back as the model's answer.

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/internal/ssohubtest"
	"github.com/blechschmidt/cloop/pkg/claudecodeauth"
	"github.com/blechschmidt/cloop/pkg/hostsandbox"
	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/state"
	"gopkg.in/yaml.v3"
)

// sandboxProbeClaude writes a stand-in `claude` first on PATH that answers
// every prompt with what it could reach: each probe prints name:ok or
// name:denied.
func sandboxProbeClaude(t *testing.T, probes map[string]string) {
	t.Helper()
	bin := t.TempDir()
	var script strings.Builder
	script.WriteString("#!/bin/sh\ncat >/dev/null\nprintf 'probes: '\n")
	for name, cmd := range probes {
		fmt.Fprintf(&script, "if %s >/dev/null 2>&1; then printf '%s:ok '; else printf '%s:denied '; fi\n",
			cmd, name, name)
	}
	script.WriteString("if [ -n \"$CLOOP_SECRET_KEY\" ]; then printf 'root-key:present '; else printf 'root-key:absent '; fi\necho\n")
	if err := os.WriteFile(filepath.Join(bin, "claude"), []byte(script.String()), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
}

// newPersonProject creates a project as who and returns its directory and the
// index who addresses it by.
func newPersonProject(t *testing.T, hub *ssohubtest.Hub, browser *http.Client, name string) (string, int) {
	t.Helper()
	code, raw := hubCall(t, hub, browser, http.MethodPost, "/api/projects/new", map[string]any{"name": name, "goal": "Ship " + name})
	var out struct {
		Dir string `json:"dir"`
		Idx int    `json:"project_idx"`
	}
	if err := json.Unmarshal(raw, &out); code != http.StatusOK || err != nil || out.Dir == "" || out.Idx < 0 {
		t.Fatalf("create %s = %d %s (%v)", name, code, raw, err)
	}
	ps, err := state.Load(out.Dir)
	if err != nil {
		t.Fatal(err)
	}
	ps.Plan = &pm.Plan{Goal: ps.Goal, Tasks: []*pm.Task{
		{ID: 1, Title: "Migrate the database", Description: "Move every table.", Status: pm.TaskPending, Priority: 1},
	}}
	if err := ps.Save(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(out.Dir, ".cloop", "config.yaml"), []byte("provider: claudecode\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return out.Dir, out.Idx
}

func TestAPersonsWorkOnTheHubsHostCannotReachAnotherPersonsFiles(t *testing.T) {
	if err := hostsandbox.Available(); err != nil {
		t.Skipf("no host sandbox on this host: %v", err)
	}
	hub := ssohubtest.Start(t, ssohubtest.Options{SelfExe: cliSelfExe(t), AdminEmails: []string{rootEmail}})
	// The hub's root key, in its own environment as a key a unit file sets.
	t.Setenv("CLOOP_SECRET_KEY", "the-hubs-root-key-0123456789abcdef")

	const alice, bob = "alice@example.com", "bob@example.com"
	aliceB := hub.SignIn(t, alice, ssohubtest.GroupMaintainers)
	bobB := hub.SignIn(t, bob, ssohubtest.GroupMaintainers)
	rootB := hub.SignIn(t, rootEmail, ssohubtest.GroupMaintainers)
	aliceDir, aliceIdx := newPersonProject(t, hub, aliceB, "alice-app")
	bobDir, _ := newPersonProject(t, hub, bobB, "bob-app")
	if err := os.WriteFile(filepath.Join(bobDir, "secret.txt"), []byte("bob's unreleased code\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	bobHome, err := claudecodeauth.HomeFor(bob)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bobHome, ".credentials.json"), []byte(`{"claudeAiOauth":{}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	aliceHome, err := claudecodeauth.HomeFor(alice)
	if err != nil {
		t.Fatal(err)
	}
	// Another run's temporary file, where every run on this host used to share
	// one /tmp.
	otherTmp, err := os.CreateTemp("", "another-runs-scratch-")
	if err != nil {
		t.Fatal(err)
	}
	otherTmp.Close()
	t.Cleanup(func() { os.Remove(otherTmp.Name()) })
	sandboxProbeClaude(t, map[string]string{
		"own-project":    "cat " + filepath.Join(aliceDir, ".cloop", "config.yaml"),
		"own-home":       "ls " + aliceHome,
		"write-project":  "touch " + filepath.Join(aliceDir, "built.txt"),
		"bob-project":    "cat " + filepath.Join(bobDir, "secret.txt"),
		"bob-login":      "cat " + filepath.Join(bobHome, ".credentials.json"),
		"hub-database":   "cat " + filepath.Join(hub.Dir, ".cloop", "state.db"),
		"hub-registry":   "cat " + filepath.Join(hub.Home, ".cloop", "projects.json"),
		"hub-process":    fmt.Sprintf("cat /proc/%d/environ", os.Getpid()),
		"other-run-tmp":  "cat " + otherTmp.Name(),
		"hub-users-home": "ls -A " + hub.Home + " | grep -q cloop",
	})

	revise := func(t *testing.T, b *http.Client, idx int) string {
		t.Helper()
		code, raw := hubCall(t, hub, b, http.MethodPost, fmt.Sprintf("/api/tasks/1/revise?project_idx=%d", idx),
			map[string]any{"instruction": "and the indexes", "description": "Move every table."})
		if code != http.StatusOK || !strings.Contains(string(raw), "probes:") {
			t.Fatalf("revise = %d %s", code, raw)
		}
		return string(raw)
	}

	t.Run("a person's model call is sandboxed", func(t *testing.T) {
		got := revise(t, aliceB, aliceIdx)
		for _, want := range []string{
			"own-project:ok", "own-home:ok", "write-project:ok",
			"bob-project:denied", "bob-login:denied", "hub-database:denied", "hub-registry:denied",
			"hub-process:denied", "other-run-tmp:denied", "hub-users-home:denied", "root-key:absent",
		} {
			if !strings.Contains(got, want) {
				t.Errorf("want %s in alice's model call's answer: %s", want, got)
			}
		}
	})

	t.Run("an administrator's is sandboxed on a project a sandboxed person writes", func(t *testing.T) {
		code, raw := hubCall(t, hub, rootB, http.MethodGet, "/api/projects", nil)
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
		idx := -1
		for i, p := range list {
			if p.Path == aliceDir {
				idx = i
			}
		}
		if idx < 0 {
			t.Fatalf("the administrator cannot see alice's project: %s", raw)
		}
		// alice's agent may have left a hook in her project, which the
		// administrator's run would otherwise run with the whole host.
		got := revise(t, rootB, idx)
		if !strings.Contains(got, "bob-project:denied") || !strings.Contains(got, "root-key:absent") {
			t.Errorf("the administrator's call on alice's project under mode auto: %s", got)
		}
	})

	t.Run("an administrator's is not on a project only administrators write, and holds no root key", func(t *testing.T) {
		_, rootIdx := newPersonProject(t, hub, rootB, "root-app")
		got := revise(t, rootB, rootIdx)
		if !strings.Contains(got, "bob-project:ok") || !strings.Contains(got, "root-key:absent") {
			t.Errorf("the administrator's call on their own project under mode auto: %s", got)
		}
	})

	t.Run("the hub's own directory is an administrator's", func(t *testing.T) {
		ps, err := state.Load(hub.Dir)
		if err != nil {
			t.Fatal(err)
		}
		ps.Plan = &pm.Plan{Goal: ps.Goal, Tasks: []*pm.Task{{ID: 1, Title: "Tidy", Status: pm.TaskPending, Priority: 1}}}
		if err := ps.Save(); err != nil {
			t.Fatal(err)
		}
		code, raw := hubCall(t, hub, aliceB, http.MethodPost, "/api/tasks/1/revise?project_idx=0",
			map[string]any{"instruction": "x", "description": "y"})
		if code != http.StatusConflict || !strings.Contains(string(raw), "host sandbox") ||
			!strings.Contains(string(raw), "Only a hub administrator") {
			t.Errorf("alice's call on the hub's own directory = %d %s", code, raw)
		}
	})
}

// hostSandboxOff turns the host sandbox off on hub, for a test in which people
// work on the hub's own directory, which the sandbox refuses them, to test
// something the sandbox does not change: whose account a call runs on, what a
// requirement check reads. Call it after the test has written the hub's
// config.yaml, which it merges into.
func hostSandboxOff(t *testing.T, hub *ssohubtest.Hub) {
	t.Helper()
	path := filepath.Join(hub.Dir, ".cloop", "config.yaml")
	raw, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	doc := map[string]any{}
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	executors, _ := doc["executors"].(map[string]any)
	if executors == nil {
		executors = map[string]any{}
	}
	executors["host_sandbox"] = map[string]any{"mode": "off"}
	doc["executors"] = executors
	out, err := yaml.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, out, 0o600); err != nil {
		t.Fatal(err)
	}
}
