package security

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
	"github.com/blechschmidt/cloop/pkg/multiui"
	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/state"
)

// asCLIEnv makes this test binary act as the cloop CLI (TestMain), for the
// hub in the test to dispatch its work to.
const asCLIEnv = "CLOOP_SECURITY_TEST_AS_CLI"

// selfAsCLI writes the wrapper the hub dispatches its work through: this
// binary, told to act as cloop.
func selfAsCLI(t *testing.T) string {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "cloop")
	script := "#!/bin/sh\n" + asCLIEnv + "=1 exec '" + strings.ReplaceAll(exe, "'", `'\''`) + "' \"$@\"\n"
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

// probeClaude writes a stand-in `claude` first on PATH that answers every
// prompt with what it could reach: each probe prints name:ok or name:denied.
func probeClaude(t *testing.T, probes map[string]string) {
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

// ownedProject makes a project owned by owner, with one task and the
// claudecode provider, as the dashboard would have registered it.
func ownedProject(t *testing.T, hub *ssohubtest.Hub, name, owner string) string {
	t.Helper()
	dir := filepath.Join(hub.Home, "projects", name)
	ps, err := state.Init(dir, "Ship "+name, 0)
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
	if err := multiui.AddPathsOwned([]string{dir}, owner); err != nil {
		t.Fatal(err)
	}
	return dir
}

// indexOf is the index browser addresses dir by.
func indexOf(t *testing.T, hub *ssohubtest.Hub, browser *http.Client, dir string) int {
	t.Helper()
	code, raw := hub.Call(t, browser, http.MethodGet, "/api/projects", nil)
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

func TestAPersonsWorkOnTheHubsHostCannotReachAnotherPersonsFiles(t *testing.T) {
	if err := hostsandbox.Available(); err != nil {
		t.Skipf("no host sandbox on this host: %v", err)
	}
	const alice, bob, root = "alice@example.com", "bob@example.com", "root@example.com"
	hub := ssohubtest.Start(t, ssohubtest.Options{SelfExe: selfAsCLI(t), AdminEmails: []string{root}})
	// The hub's root key, in its own environment as a key a unit file sets.
	t.Setenv("CLOOP_SECRET_KEY", "the-hubs-root-key-0123456789abcdef")

	aliceB := hub.SignIn(t, alice, ssohubtest.GroupMaintainers)
	rootB := hub.SignIn(t, root, ssohubtest.GroupMaintainers)
	aliceDir := ownedProject(t, hub, "alice-app", alice)
	bobDir := ownedProject(t, hub, "bob-app", bob)
	rootDir := ownedProject(t, hub, "root-app", root)
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
	probeClaude(t, map[string]string{
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
		code, raw := hub.Call(t, b, http.MethodPost, fmt.Sprintf("/api/tasks/1/revise?project_idx=%d", idx),
			map[string]any{"instruction": "and the indexes", "description": "Move every table."})
		if code != http.StatusOK || !strings.Contains(string(raw), "probes:") {
			t.Fatalf("revise = %d %s", code, raw)
		}
		return string(raw)
	}

	t.Run("a person's model call is sandboxed", func(t *testing.T) {
		got := revise(t, aliceB, indexOf(t, hub, aliceB, aliceDir))
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
		// alice's agent may have left a hook in her project, which the
		// administrator's call would otherwise run with the whole host.
		got := revise(t, rootB, indexOf(t, hub, rootB, aliceDir))
		if !strings.Contains(got, "bob-project:denied") || !strings.Contains(got, "root-key:absent") {
			t.Errorf("the administrator's call on alice's project under mode auto: %s", got)
		}
	})

	t.Run("an administrator's is not on a project only administrators write, and holds no root key", func(t *testing.T) {
		got := revise(t, rootB, indexOf(t, hub, rootB, rootDir))
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
		code, raw := hub.Call(t, aliceB, http.MethodPost, fmt.Sprintf("/api/tasks/1/revise?project_idx=%d",
			indexOf(t, hub, aliceB, hub.Dir)), map[string]any{"instruction": "x", "description": "y"})
		if code != http.StatusConflict || !strings.Contains(string(raw), "host sandbox") ||
			!strings.Contains(string(raw), "Only a hub administrator") {
			t.Errorf("alice's call on the hub's own directory = %d %s", code, raw)
		}
	})
}
