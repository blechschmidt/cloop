//go:build linux

package netfilter

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/caps"
)

// agentEnv switches the test binary into the role of an executor agent started
// the way its systemd unit starts it: an ordinary user holding CAP_NET_ADMIN
// in its ambient set, bounded to that one capability, with no_new_privs.
const agentEnv = "CLOOP_NETFILTER_TEST_AGENT"

func TestMain(m *testing.M) {
	if os.Getenv(agentEnv) != "" {
		os.Exit(runAgentRole())
	}
	os.Exit(m.Run())
}

type agentReport struct {
	Confine   string `json:"confine"`
	Available string `json:"available"`
	PlainNft  string `json:"plain_nft"`
}

func runAgentRole() int {
	var rep agentReport
	if err := caps.Confine(); err != nil {
		rep.Confine = err.Error()
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if a, err := NewApplier(); err != nil {
		rep.Available = err.Error()
	} else if err := a.Available(ctx); err != nil {
		rep.Available = err.Error()
	}
	// The same nft, started the way anything else the agent runs is started.
	if out, err := exec.CommandContext(ctx, "nft", "list", "tables").CombinedOutput(); err == nil {
		rep.PlainNft = "succeeded"
	} else {
		rep.PlainNft = strings.TrimSpace(string(out))
	}
	_ = json.NewEncoder(os.Stdout).Encode(rep)
	return 0
}

// TestConfinedAgentStillReachesNft is Task 20352 from the agent's side: once
// the agent has kept CAP_NET_ADMIN from everything it starts, the Applier must
// still hand it to nft(8) — and only there. A plain nft started by the same
// process has to fail, or the capability would be reaching workloads too.
func TestConfinedAgentStillReachesNft(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to start a process with an ambient capability set")
	}
	setpriv, err := exec.LookPath("setpriv")
	if err != nil {
		t.Skip("setpriv(1) is not installed")
	}
	if help, _ := exec.Command(setpriv, "--help").CombinedOutput(); !strings.Contains(string(help), "--ambient-caps") {
		t.Skip("this setpriv cannot set ambient capabilities")
	}
	if _, err := exec.LookPath("nft"); err != nil {
		t.Skip("nft(8) is not installed")
	}
	if err := exec.Command("nft", "list", "tables").Run(); err != nil {
		t.Skipf("nft cannot list tables here even as root: %v", err)
	}

	dir, err := os.MkdirTemp("", "cloop-netfilter-test-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(dir, "netfilter.test")
	if err := copyExecutable(os.Args[0], bin); err != nil {
		t.Fatalf("copy the test binary: %v", err)
	}

	cmd := exec.Command(setpriv,
		"--reuid=65534", "--regid=65534", "--clear-groups",
		"--inh-caps=+net_admin", "--ambient-caps=+net_admin",
		"--bounding-set=-all,+net_admin", "--no-new-privs",
		bin, "-test.run=^$")
	cmd.Env = append(os.Environ(), agentEnv+"=1")
	cmd.Dir = dir
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("stand-in agent: %v\n%s", err, out)
	}
	var rep agentReport
	if err := json.Unmarshal(out, &rep); err != nil {
		t.Fatalf("stand-in agent printed %q: %v", out, err)
	}
	if rep.Confine != "" {
		t.Errorf("Confine: %s", rep.Confine)
	}
	if rep.Available != "" {
		t.Errorf("a confined agent holding CAP_NET_ADMIN cannot reach nft(8) through the Applier: %s", rep.Available)
	}
	if rep.PlainNft == "succeeded" {
		t.Error("an nft the agent started without the Applier ran with CAP_NET_ADMIN — " +
			"the capability is reaching everything the agent starts")
	}
}

func copyExecutable(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o755)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	if err := out.Close(); err != nil {
		return err
	}
	return os.Chmod(dst, 0o755)
}
