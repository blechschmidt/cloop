package container

// Task 20397 on a real kernel: a sandbox on a filtered bridge whose allowlist
// holds 169.254.0.0/16 — a rule set stored before such a list was refused —
// cannot reach the cloud metadata service inside it, and the installed
// ruleset says why, with the drop ahead of the accept. The control names
// 169.254.169.254/32 and must reach it, so the first half cannot pass on a
// host where the service was never reachable at all.
//
// Opt-in, and it needs root (for nft), an engine, a local alpine image and a
// host that itself reaches a metadata service at 169.254.169.254:80 — a cloud
// VM:
//
//	CLOOP_FIREWALL_CONTAINER_E2E=1 go test ./pkg/executor/container -run TestIntegration_AContainingAllowKeepsTheMetadataServiceClosed -v

import (
	"net"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/netfilter"
)

func TestIntegration_AContainingAllowKeepsTheMetadataServiceClosed(t *testing.T) {
	if os.Getenv("CLOOP_FIREWALL_CONTAINER_E2E") != "1" {
		t.Skip("set CLOOP_FIREWALL_CONTAINER_E2E=1 to install a real firewall and start a sandbox behind it")
	}
	if os.Geteuid() != 0 {
		t.Skip("installing the bridge firewall needs root")
	}
	if _, err := exec.LookPath("nft"); err != nil {
		t.Skip("nft is not installed")
	}
	conn, err := net.DialTimeout("tcp", "169.254.169.254:80", 3*time.Second)
	if err != nil {
		t.Skipf("this host reaches no metadata service at 169.254.169.254:80 (%v), so there is nothing to keep closed", err)
	}
	_ = conn.Close()

	// A TCP connect and nothing more: whether the packet gets through is the
	// whole question, and a zero-I/O probe asks it without sending the service
	// a request or reading a byte of what it would answer.
	probe := []string{"/bin/sh", "-c", "nc -z -w 5 169.254.169.254 80; echo rc=$?"}
	reached := func(out string) bool { return strings.Contains(out, "rc=0") }

	run := func(id string, allow []string) (string, string) {
		t.Helper()
		ex := newTestExecutor(t, defaultTestImage, func(o *Options) {
			o.ID = id
			o.Network = NetworkBridge
			o.EgressFilter = EgressFilter{Enabled: true, AllowCIDRs: allow, AllowPorts: []int{80},
				Resolvers: []string{"1.1.1.1"}}
		})
		table := netfilter.TableName("sbx", id)
		t.Cleanup(func() {
			_ = exec.Command("nft", "delete", "table", "inet", table).Run()
			_ = exec.Command(ex.rt.Name, "network", "rm", "cloop-sbx-"+id).Run()
		})
		res, err := runInSandbox(t, ex, t.TempDir(), probe, nil)
		if err != nil {
			t.Fatalf("%s: Run: %v (output %q)", id, err, res.Output)
		}
		ruleset, err := exec.Command("nft", "list", "table", "inet", table).CombinedOutput()
		if err != nil {
			t.Fatalf("%s: no ruleset was installed: %v %s", id, err, ruleset)
		}
		return string(res.Output), string(ruleset)
	}

	out, ruleset := run("test-md-contained", []string{"169.254.0.0/16"})
	if reached(out) {
		t.Errorf("the sandbox reached the metadata service through a range that only contains it:\n%s\n%s", out, ruleset)
	}
	// The drop is ahead of the accept in the forward chain, and it is the rule
	// that saw the sandbox's packet: its counter moved.
	forward, _, _ := strings.Cut(ruleset, "chain input")
	drop := strings.Index(forward, "ip daddr 169.254.169.254 counter packets")
	accept := strings.Index(forward, "ip daddr 169.254.0.0/16 tcp dport 80 counter")
	if drop < 0 || accept < 0 || drop > accept {
		t.Errorf("the installed forward chain does not drop the service ahead of the range (drop at %d, accept at %d):\n%s",
			drop, accept, forward)
	}
	counted := false
	for _, line := range strings.Split(forward, "\n") {
		if strings.Contains(line, "ip daddr 169.254.169.254 counter packets") && !strings.Contains(line, "packets 0 ") {
			counted = true
		}
	}
	if !counted {
		t.Errorf("the metadata drop counted no packets from the sandbox, so the ruleset is not on its bridge:\n%s", forward)
	}

	// The control: named, the same service is reached through the same kind
	// of filter on the same host.
	out, ruleset = run("test-md-named", []string{"169.254.0.0/16", "169.254.169.254/32"})
	if !reached(out) {
		t.Errorf("with 169.254.169.254/32 named the sandbox still could not reach the service, so the check above "+
			"proves nothing:\n%s\n%s", out, ruleset)
	}
}
