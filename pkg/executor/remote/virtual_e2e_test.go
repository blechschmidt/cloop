package remote_test

// Loopback tests for virtual executors (Task 20345): a real hub, a real agent,
// a real WebSocket, and a fixture sysfs standing in for the device's hardware.
//
// The default-on tests stop short of starting a container, so they run on any
// machine: they cover the inventory travelling to the hub, the refresh frame,
// and every refusal that has to happen before a sandbox exists. The one that
// starts a real sandbox — a firewall on its bridge, a device node inside it —
// is behind CLOOP_AGENT_SANDBOX_E2E=1, for the reasons given in
// pkg/executor/agent/driver_integration_test.go.

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/executor/agent"
	"github.com/blechschmidt/cloop/pkg/executor/remote"
)

// fakeUSB lays out one USB device in a fixture sysfs tree the way the kernel
// does: a real directory under devices/ and a symlink to it from
// bus/usb/devices.
func fakeUSB(t *testing.T, root, port, vendor, product, bus, dev, serial string) {
	t.Helper()
	real := filepath.Join(root, "devices", "usb"+bus, port)
	if err := os.MkdirAll(real, 0o755); err != nil {
		t.Fatal(err)
	}
	for name, v := range map[string]string{
		"idVendor": vendor, "idProduct": product, "busnum": bus, "devnum": dev,
		"manufacturer": "Yubico", "product": "YubiHSM", "serial": serial,
	} {
		if err := os.WriteFile(filepath.Join(real, name), []byte(v+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	link := filepath.Join(root, "bus", "usb", "devices")
	if err := os.MkdirAll(link, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(real, filepath.Join(link, port)); err != nil {
		t.Fatal(err)
	}
}

// withSysfs points the loopback agent at a fixture tree.
func withSysfs(root string) func(*agent.Config) {
	return func(c *agent.Config) {
		c.SysfsRoot = root
		c.DevRoot = filepath.Join(root, "dev-invisible")
	}
}

func virtualOver(t *testing.T, parent *remote.Executor, id string, spec executor.VirtualSpec) *remote.Virtual {
	t.Helper()
	v, err := remote.NewVirtual(parent, id, "test "+id, func() (executor.VirtualSpec, error) { return spec, nil })
	if err != nil {
		t.Fatalf("NewVirtual: %v", err)
	}
	return v
}

// TestLoopbackUSBInventoryReachesTheHub: the hello carries the device's USB
// hardware, and the refresh frame picks up a device plugged in afterwards —
// the moment an admin is most likely to be looking.
func TestLoopbackUSBInventoryReachesTheHub(t *testing.T) {
	sysfs := t.TempDir()
	fakeUSB(t, sysfs, "1-1", "1050", "0030", "1", "2", "0031650425")
	lb := newLoopback(t, withSysfs(sysfs))
	ex := lb.executor(t)

	inv := ex.AgentCapabilities().USBDevices
	if len(inv) != 1 || inv[0].Node != "/dev/bus/usb/001/002" || inv[0].Serial != "0031650425" {
		t.Fatalf("hello inventory = %+v", inv)
	}

	fakeUSB(t, sysfs, "1-2", "0403", "6001", "1", "3", "FT123")
	caps, err := ex.RefreshInventory(context.Background())
	if err != nil {
		t.Fatalf("RefreshInventory: %v", err)
	}
	if len(caps.USBDevices) != 2 || len(ex.AgentCapabilities().USBDevices) != 2 {
		t.Fatalf("refresh did not pick up the new device: %+v", caps.USBDevices)
	}
}

// TestLoopbackVirtualFirewallNeedsAPacketFilter: a virtual executor with a
// firewall is refused on a device that cannot install one, before anything is
// sent — never started unfiltered in its place.
func TestLoopbackVirtualFirewallNeedsAPacketFilter(t *testing.T) {
	lb := newLoopback(t, withSysfs(t.TempDir()))
	parent := lb.executor(t)
	if parent.AgentCapabilities().PacketFilter {
		t.Fatal("the loopback agent claims a packet filter it was never probed for")
	}
	v := virtualOver(t, parent, "vx-firewalled", executor.VirtualSpec{
		Sandbox:  executor.SandboxSettings{Mode: executor.SandboxModeContainer},
		Firewall: &executor.FirewallRules{AllowPublicInternet: true, Resolvers: []string{"1.1.1.1"}},
	})
	if v.Capabilities().FilteredEgress {
		t.Error("the virtual executor advertises filtered egress its device cannot install")
	}
	_, err := v.Start(context.Background(), executor.Spec{
		WorkDir: filepath.Join(lb.root, "p"), Argv: []string{"/bin/true"},
	})
	if !errors.Is(err, remote.ErrVirtualExecutorUnsupported) {
		t.Fatalf("Start = %v, want ErrVirtualExecutorUnsupported", err)
	}
	if len(parent.Handles()) != 0 {
		t.Errorf("a refused dispatch left handles %v", parent.Handles())
	}
	if err := v.HealthCheck(context.Background()); err == nil {
		t.Error("HealthCheck passes for a configuration its device cannot apply")
	}
}

// TestLoopbackVirtualDeviceMustBeAttached: a selected USB device that is not
// plugged in fails the start on the device, naming it — not a sandbox without
// its hardware.
func TestLoopbackVirtualDeviceMustBeAttached(t *testing.T) {
	sysfs := t.TempDir()
	fakeUSB(t, sysfs, "1-1", "1050", "0030", "1", "2", "0031650425")
	lb := newLoopback(t, withSysfs(sysfs))
	v := virtualOver(t, lb.executor(t), "vx-hsm", executor.VirtualSpec{
		Sandbox: executor.SandboxSettings{Mode: executor.SandboxModeContainer},
		Devices: []executor.DeviceSelector{{
			Name: "other-hsm",
			USB:  &executor.USBMatch{VendorID: "1050", ProductID: "0030", Serial: "9999999999"},
		}},
	})
	if err := os.MkdirAll(filepath.Join(lb.root, "p"), 0o755); err != nil {
		t.Fatal(err)
	}
	_, err := v.Start(context.Background(), executor.Spec{
		WorkDir: filepath.Join(lb.root, "p"), Argv: []string{"/bin/true"},
	})
	if err == nil || !strings.Contains(err.Error(), "other-hsm") || !strings.Contains(err.Error(), "not attached") {
		t.Fatalf("Start = %v, want a refusal naming the missing device", err)
	}
}

// TestIntegration_VirtualExecutorSandbox is the whole feature on a real engine:
// a virtual executor's firewall is installed on its own bridge before the
// sandbox joins it, its denylist is in the ruleset, the sandbox resolves through
// the allowed resolver, and its device node is inside the sandbox. It runs once
// per installed engine — docker and rootful podman name and report their
// bridges differently, which is exactly where a host-side filter can silently
// attach to nothing.
//
// Opt-in, and it needs root (for nft), an engine and a local alpine image:
//
//	CLOOP_AGENT_SANDBOX_E2E=1 go test ./pkg/executor/remote -run TestIntegration_VirtualExecutorSandbox -v
func TestIntegration_VirtualExecutorSandbox(t *testing.T) {
	if os.Getenv("CLOOP_AGENT_SANDBOX_E2E") != "1" {
		t.Skip("set CLOOP_AGENT_SANDBOX_E2E=1 to start a real sandbox")
	}
	if os.Geteuid() != 0 {
		t.Skip("installing the bridge firewall needs root")
	}
	if _, err := exec.LookPath("nft"); err != nil {
		t.Skip("nft is not installed")
	}
	ran := 0
	for _, engine := range []string{"docker", "podman"} {
		if _, err := exec.LookPath(engine); err != nil {
			continue
		}
		if err := exec.Command(engine, "image", "inspect", "alpine:3.20").Run(); err != nil {
			t.Logf("%s: alpine:3.20 is not in its local image store; skipping it", engine)
			continue
		}
		ran++
		t.Run(engine, func(t *testing.T) { runVirtualSandbox(t, engine) })
	}
	if ran == 0 {
		t.Skip("no engine with alpine:3.20 in its local store")
	}
}

func runVirtualSandbox(t *testing.T, engine string) {
	lb := newLoopback(t, withSysfs(t.TempDir()), func(c *agent.Config) { c.HostProbes = true })
	parent := lb.executor(t)
	if !parent.AgentCapabilities().PacketFilter {
		t.Fatalf("the agent reports no packet filter: %s", parent.AgentCapabilities().PacketFilterIssue)
	}
	id := "vx-e2e-" + engine
	table := "cloop_sbx_" + strings.ReplaceAll(id, "-", "_")
	v := virtualOver(t, parent, id, executor.VirtualSpec{
		Sandbox: executor.SandboxSettings{Mode: executor.SandboxModeContainer, Engine: engine, Image: "alpine:3.20"},
		Firewall: &executor.FirewallRules{
			AllowPublicInternet: true,
			DenyCIDRs:           []string{"203.0.113.0/24"},
			Resolvers:           []string{"1.1.1.1"},
		},
		Devices: []executor.DeviceSelector{{Name: "zero", Path: "/dev/zero", Permissions: executor.DeviceRead}},
	})
	t.Cleanup(func() {
		_ = exec.Command("nft", "delete", "table", "inet", table).Run()
		_ = exec.Command(engine, "network", "rm", "cloop-sbx-"+id).Run()
	})

	work := filepath.Join(lb.root, "p")
	if err := os.MkdirAll(work, 0o755); err != nil {
		t.Fatal(err)
	}
	// The sandbox runs as the workspace's owner and refuses uid 0, which is
	// who owns everything a root test creates.
	if err := os.Chown(work, 65534, 65534); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	res, err := executor.Run(ctx, v, executor.Spec{
		WorkDir: work,
		// The wget is aimed into the denylist: TEST-NET-3 is unroutable, so
		// the attempt fails either way, and what it proves is that the deny
		// rule on the host counted the sandbox's packet — see below.
		Argv: []string{"/bin/sh", "-c", "head -c 4 /dev/zero | wc -c; grep -i nameserver /etc/resolv.conf; " +
			"wget -q -T 2 -O /dev/null http://203.0.113.1/ 2>/dev/null; true"},
	})
	if err != nil {
		t.Fatalf("Run: %v (output %q)", err, res.Output)
	}
	out := string(res.Output)
	if !strings.Contains(out, "4") {
		t.Errorf("the device did not reach the sandbox: %q", out)
	}
	if res.Handle.ExecutorID != id {
		t.Errorf("handle executor = %q, want the virtual executor %q", res.Handle.ExecutorID, id)
	}

	ruleset, err := exec.Command("nft", "list", "table", "inet", table).CombinedOutput()
	if err != nil {
		t.Fatalf("no ruleset installed for the virtual executor: %v %s", err, ruleset)
	}
	if !strings.Contains(string(ruleset), "203.0.113.0/24") || !strings.Contains(string(ruleset), "operator deny list") {
		t.Errorf("the denylist is not in the installed ruleset:\n%s", ruleset)
	}
	// The ruleset must be attached to the bridge the sandbox actually joined:
	// a table keyed to an interface name the engine never used loads cleanly
	// and filters nothing. Whether the interface exists *now* proves nothing —
	// netavark deletes a podman bridge with its last container — so the proof
	// is the deny rule's own counter: it saw the sandbox's packet.
	denied := false
	for _, line := range strings.Split(string(ruleset), "\n") {
		if strings.Contains(line, "203.0.113.0/24") && strings.Contains(line, "counter packets") &&
			!strings.Contains(line, "counter packets 0 ") {
			denied = true
		}
	}
	if !denied {
		t.Errorf("the deny rule counted no packets from the sandbox, so the ruleset is not on its "+
			"bridge:\n%s", ruleset)
	}
}
