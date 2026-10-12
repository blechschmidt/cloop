package cluster_test

// Changing CLOOP_SECRET_KEY on a running three-member hub cluster (Task 20425):
// the procedure the runbook documents, done with real processes.
//
//  1. Three members serve, reading the root key from a file.
//  2. A rolling restart gives every member the new key as CLOOP_SECRET_KEY_FILE
//     and the old one as CLOOP_SECRET_KEY_PREVIOUS_FILE. `cloop hub key rotate
//     --retire-previous` refuses for as long as any live member advertises the
//     old root, and while no escrow of the new one is on record.
//  3. Escrowed, it rewraps everything onto a key of the new root and retires
//     every key of the old one.
//  4. A second rolling restart drops the previous key. The secret granted
//     before the change still leases, and a member started on the old key
//     alone refuses to start.

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

const (
	clusterOldRoot = "cluster-e2e-old-root-key-Zq4pV9mW2xT7rL0yH3nB8"
	clusterNewRoot = "cluster-e2e-new-root-key-kD5sF1gJ6cA-uE_oI4tR7"
)

// rootStatus is /api/cluster with the root fingerprints members advertise.
type rootStatus struct {
	Members []struct {
		ID        string            `json:"id"`
		Alive     bool              `json:"alive"`
		Endpoints map[string]string `json:"endpoints"`
	} `json:"members"`
}

// rootStatus asks the newest member: a rolling restart replaces every process,
// so no address but the latest is sure to answer.
func (w *world) rootStatus() rootStatus {
	w.t.Helper()
	var st rootStatus
	r := w.do("GET", w.newest().url(), "/api/cluster", nil)
	if err := json.Unmarshal([]byte(r.body), &st); err != nil {
		w.t.Fatalf("decode /api/cluster: %v\n%s", err, r.body)
	}
	return st
}

// runRoot runs a cloop subcommand that may fail, with rootEnv as the root key
// setting, and returns its output and exit error.
func (w *world) runRoot(dir string, rootEnv []string, args ...string) (string, error) {
	w.t.Helper()
	saved := w.rootEnv
	w.rootEnv = rootEnv
	env := w.env()
	w.rootEnv = saved
	cmd := exec.Command(w.bin, args...)
	cmd.Dir = dir
	cmd.Env = env
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// restartWith replaces h with a hub started under rootEnv, the way a rolling
// restart replaces a Pod: the old process is told to stop and leaves the
// cluster, and a new one joins on its own port.
func (w *world) restartWith(h *hub, rootEnv []string) *hub {
	w.t.Helper()
	w.kill(h, syscall.SIGTERM)
	w.waitExit(h)
	for i, o := range w.hubs {
		if o == h {
			w.hubs = append(w.hubs[:i], w.hubs[i+1:]...)
			break
		}
	}
	w.rootEnv = rootEnv
	return w.startHub()
}

func (w *world) newest() *hub { return w.hubs[len(w.hubs)-1] }

// waitLive waits for three live members, asking the newest one.
func (w *world) waitLive(what string) {
	w.t.Helper()
	w.waitClusterVia(w.newest(), what, func(s clusterStatus) bool { return s.live() == 3 })
}

func TestRootChangeAcrossARollingRestart(t *testing.T) {
	if os.Getenv(enableEnv) == "" {
		t.Skipf("%s is not set; this builds cloop and runs a cluster of hub processes", enableEnv)
	}
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash is required for the stub harness")
	}
	w := newWorld(t)
	keys := filepath.Join(w.root, "keys")
	if err := os.MkdirAll(keys, 0o700); err != nil {
		t.Fatal(err)
	}
	keyFile := func(name, value string) string {
		path := filepath.Join(keys, name)
		if err := os.WriteFile(path, []byte(value+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	oldFile, newFile := keyFile("old", clusterOldRoot), keyFile("new", clusterNewRoot)
	onOld := []string{"CLOOP_SECRET_KEY_FILE=" + oldFile}
	changing := []string{"CLOOP_SECRET_KEY_FILE=" + newFile, "CLOOP_SECRET_KEY_PREVIOUS_FILE=" + oldFile}
	onNew := []string{"CLOOP_SECRET_KEY_FILE=" + newFile}

	// ── 1. Three members on the old root ─────────────────────────────────────
	w.rootEnv = onOld
	w.initProjects() // a secret, minted and granted under the old root
	for i := 0; i < 3; i++ {
		w.startHub()
	}
	w.waitLive("three live members")
	oldFP := w.advertisedRoot(t, "")
	if out, err := w.runRoot(w.hubDir, onOld, "secret", "lease", "--project", w.projDir); err != nil ||
		!strings.Contains(out, "1 material(s)") {
		t.Fatalf("the secret does not lease before the change: %v\n%s", err, out)
	}

	retire := func() (string, error) {
		return w.runRoot(w.hubDir, changing, "hub", "key", "rotate", "--retire-previous")
	}
	if out, err := retire(); err == nil || !strings.Contains(out, "runs on root key "+oldFP) {
		t.Fatalf("--retire-previous with every member on the old root: %v\n%s", err, out)
	}

	// ── 2. The rolling restart, one member at a time ─────────────────────────
	for i := 0; i < 3; i++ {
		w.restartWith(w.hubs[0], changing)
		w.waitLive(fmt.Sprintf("three live members after restarting %d", i+1))
		if i < 2 {
			out, err := retire()
			if err == nil || !strings.Contains(out, "runs on root key "+oldFP) {
				t.Fatalf("--retire-previous with %d member(s) still on the old root: %v\n%s", 2-i, err, out)
			}
		}
	}
	newFP := w.advertisedRoot(t, oldFP)
	if out, err := retire(); err == nil || !strings.Contains(out, "no escrow is on record") {
		t.Fatalf("--retire-previous before the new key is escrowed: %v\n%s", err, out)
	}

	// ── 3. Escrow, then finish the change ────────────────────────────────────
	pass := filepath.Join(w.root, "escrow-passphrase")
	if err := os.WriteFile(pass, []byte("five random words make a fine escrow passphrase\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if out, err := w.runRoot(w.hubDir, changing, "hub", "key", "escrow", "export",
		"--output", filepath.Join(w.root, "hub.escrow"), "--passphrase-file", pass); err != nil {
		t.Fatalf("escrow the new key: %v\n%s", err, out)
	}
	out, err := retire()
	if err != nil || !strings.Contains(out, "previous root's") {
		t.Fatalf("--retire-previous with every member ready: %v\n%s", err, out)
	}
	if out, err := w.runRoot(w.hubDir, changing, "secret", "lease", "--project", w.projDir); err != nil ||
		!strings.Contains(out, "1 material(s)") {
		t.Fatalf("the secret does not lease mid-change: %v\n%s", err, out)
	}

	// ── 4. Drop the previous key ─────────────────────────────────────────────
	for i := 0; i < 3; i++ {
		w.restartWith(w.hubs[0], onNew)
		w.waitLive(fmt.Sprintf("three live members on the new root alone (%d)", i+1))
	}
	if got := w.advertisedRoot(t, ""); got != newFP {
		t.Fatalf("members advertise %s, want %s", got, newFP)
	}
	if out, err := w.runRoot(w.hubDir, onNew, "secret", "lease", "--project", w.projDir); err != nil ||
		!strings.Contains(out, "1 material(s)") {
		t.Fatalf("the secret does not lease on the new root alone: %v\n%s", err, out)
	}
	out, err = w.runRoot(w.hubDir, onNew, "hub", "key", "list", "--json")
	if err != nil {
		t.Fatalf("key list: %v\n%s", err, out)
	}
	var keysOut []struct {
		ID       string `json:"id"`
		State    string `json:"state"`
		Openable bool   `json:"openable"`
		Root     string `json:"root"`
	}
	if err := json.Unmarshal([]byte(out[strings.Index(out, "["):]), &keysOut); err != nil {
		t.Fatalf("decode key list: %v\n%s", err, out)
	}
	for _, k := range keysOut {
		switch {
		case k.State == "retired":
		case !k.Openable || k.Root != newFP:
			t.Errorf("live key %+v, want openable and of the new root %s", k, newFP)
		}
	}

	// A member started on the old key alone refuses to start, naming why.
	logPath := filepath.Join(w.root, "stale-member.log")
	saved := w.rootEnv
	w.rootEnv = onOld
	stale, exited := w.spawn(w.hubDir, logPath, w.env(), "ui", "--port", fmt.Sprint(freePort(t)), "--no-browser")
	w.rootEnv = saved
	select {
	case <-exited:
	case <-time.After(45 * time.Second):
		_ = syscall.Kill(-stale.Process.Pid, syscall.SIGKILL)
		t.Fatal("a member on the old root alone is still running after 45s")
	}
	if stale.ProcessState.Success() {
		t.Error("a member on the old root alone exited successfully")
	}
	if b, _ := os.ReadFile(logPath); !strings.Contains(string(b), "derive from no root this hub holds") {
		t.Errorf("the refused member's log does not say why:\n%s", b)
	}
}

// advertisedRoot returns the current root every live member advertises,
// failing unless they agree. not, when set, is a fingerprint they must not be
// advertising any more.
func (w *world) advertisedRoot(t *testing.T, not string) string {
	t.Helper()
	var root string
	w.eventually("every live member advertising one root", 30*time.Second, func() bool {
		st := w.rootStatus()
		root = ""
		live := 0
		for _, m := range st.Members {
			if !m.Alive {
				continue
			}
			live++
			fp := m.Endpoints["root_key"]
			if fp == "" || (root != "" && fp != root) || fp == not {
				return false
			}
			root = fp
		}
		return live == 3
	})
	return root
}
