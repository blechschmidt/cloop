package cluster_test

// Moving a running three-member hub cluster's secret store onto a KMS
// (Task 20433), with real processes and a KMS v2 plugin served over a real
// unix socket by kmstest.
//
//  1. Three members serve on CLOOP_SECRET_KEY alone.
//  2. config.yaml gains secrets.kms and previous_root: passphrase, and a
//     rolling restart picks it up one member at a time. Members on either
//     configuration keep opening the store; `cloop hub key rotate
//     --retire-previous` refuses while any live member advertises the
//     passphrase's root.
//  3. With every member on the KMS it needs no escrow, moves every row onto a
//     key the KMS holds and retires the passphrase's keys.
//  4. previous_root is dropped and the members restarted again. The secret
//     granted before the move still leases; a member whose configuration has
//     no KMS, and one whose KMS does not answer, refuse to start.

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/kms/kmstest"
)

func TestKMSMoveAcrossARollingRestart(t *testing.T) {
	if os.Getenv(enableEnv) == "" {
		t.Skipf("%s is not set; this builds cloop and runs a cluster of hub processes", enableEnv)
	}
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash is required for the stub harness")
	}
	plugin, err := kmstest.NewPlugin()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { plugin.Stop(); plugin.Cleanup() })

	w := newWorld(t)
	keys := filepath.Join(w.root, "keys")
	if err := os.MkdirAll(keys, 0o700); err != nil {
		t.Fatal(err)
	}
	keyFile := filepath.Join(keys, "root")
	if err := os.WriteFile(keyFile, []byte(clusterOldRoot+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	rootEnv := []string{"CLOOP_SECRET_KEY_FILE=" + keyFile}
	w.rootEnv = rootEnv

	// ── 1. Three members on the passphrase ───────────────────────────────────
	w.initProjects()
	cfgPath := filepath.Join(w.hubDir, ".cloop", "config.yaml")
	base, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	setSecrets := func(block string) {
		t.Helper()
		if err := os.WriteFile(cfgPath, append(append([]byte(nil), base...), []byte("\n"+block)...), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < 3; i++ {
		w.startHub()
	}
	w.waitLive("three live members on the passphrase")
	passFP := w.advertisedRoot(t, "")
	lease := func(what string) {
		t.Helper()
		if out, err := w.runRoot(w.hubDir, rootEnv, "secret", "lease", "--project", w.projDir); err != nil ||
			!strings.Contains(out, "1 material(s)") {
			t.Fatalf("the secret does not lease %s: %v\n%s", what, err, out)
		}
	}
	lease("before the move")

	// ── 2. The rolling restart onto the KMS ──────────────────────────────────
	kmsBlock := fmt.Sprintf(`secrets:
  kms:
    provider: kmsv2
    name: e2e-kms
    startup_timeout: 5s
    kmsv2:
      endpoint: %s
`, plugin.Endpoint())
	setSecrets(kmsBlock + "  previous_root: passphrase\n")
	retire := func() (string, error) {
		return w.runRoot(w.hubDir, rootEnv, "hub", "key", "rotate", "--retire-previous")
	}
	for i := 0; i < 3; i++ {
		w.restartWith(w.hubs[0], rootEnv)
		w.waitLive(fmt.Sprintf("three live members after restarting %d onto the KMS", i+1))
		// Members on both configurations open the store throughout.
		lease(fmt.Sprintf("with %d member(s) on the KMS", i+1))
		if i < 2 {
			out, err := retire()
			if err == nil || !strings.Contains(out, "runs on root key "+passFP) {
				t.Fatalf("--retire-previous with %d member(s) still on the passphrase: %v\n%s", 2-i, err, out)
			}
		}
	}
	if got := w.advertisedRoot(t, passFP); got != "e2e-kms" {
		t.Fatalf("members advertise %q, want the KMS e2e-kms", got)
	}
	if plugin.Calls("Encrypt") != 0 {
		t.Fatal("the KMS was asked to wrap a key before the retire step")
	}

	// ── 3. Finish the move ───────────────────────────────────────────────────
	out, err := retire()
	if err != nil || !strings.Contains(out, "no escrow is needed") || !strings.Contains(out, "previous root's") {
		t.Fatalf("--retire-previous with every member on the KMS: %v\n%s", err, out)
	}
	if plugin.Calls("Encrypt") == 0 {
		t.Fatal("the retire step minted no key under the KMS")
	}
	lease("right after the move")

	// ── 4. Drop previous_root ────────────────────────────────────────────────
	setSecrets(kmsBlock)
	for i := 0; i < 3; i++ {
		w.restartWith(w.hubs[0], rootEnv)
		w.waitLive(fmt.Sprintf("three live members on the KMS alone (%d)", i+1))
	}
	lease("on the KMS alone")
	out, err = w.runRoot(w.hubDir, rootEnv, "hub", "key", "list")
	if err != nil || !strings.Contains(out, "secrets.kms e2e-kms") || !strings.Contains(out, "shredded") {
		t.Fatalf("key list after the move: %v\n%s", err, out)
	}

	// A member whose configuration names no KMS refuses to start, saying what
	// holds the keys.
	refused := func(what, want string) {
		t.Helper()
		logPath := filepath.Join(w.root, strings.ReplaceAll(what, " ", "-")+".log")
		cmd, exited := w.spawn(w.hubDir, logPath, w.env(), "ui", "--port", fmt.Sprint(freePort(t)), "--no-browser")
		select {
		case <-exited:
		case <-time.After(60 * time.Second):
			_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
			t.Fatalf("a member %s is still running after 60s", what)
		}
		if cmd.ProcessState.Success() {
			t.Errorf("a member %s exited successfully", what)
		}
		if b, _ := os.ReadFile(logPath); !strings.Contains(string(b), want) {
			t.Errorf("the member %s does not say %q:\n%s", what, want, b)
		}
	}
	setSecrets("")
	refused("with no KMS configured", "held by the KMS e2e-kms")
	setSecrets(kmsBlock)

	// And one whose KMS does not answer refuses too — after waiting
	// startup_timeout for it — and seals under nothing else.
	plugin.Stop()
	refused("whose KMS is down", "refusing to open the secret store")
}
