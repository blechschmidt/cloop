package container

// Tests for the container-driver half of virtual executors (Task 20345): the
// deny list reaching the compiled filter, the resolvers the sandbox is pointed
// at, supplementary groups for device nodes, and the refusal of devices under
// runtimes that cannot open them.

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/netfilter"
)

// TestEgressFilterDenyListIsCompiled: the deny list is part of the policy the
// bridge ruleset is rendered from, not a field that is parsed and dropped.
func TestEgressFilterDenyListIsCompiled(t *testing.T) {
	f := EgressFilter{
		Enabled:             true,
		AllowPublicInternet: true,
		AllowAllPorts:       true,
		Resolvers:           []string{"1.1.1.1"},
		DenyCIDRs:           []string{"203.0.113.0/24"},
	}
	p, err := f.Policy()
	if err != nil {
		t.Fatalf("Policy: %v", err)
	}
	if v, _ := p.Evaluate(netip.MustParseAddr("203.0.113.5"), 443, netfilter.ProtoTCP); v != netfilter.VerdictDrop {
		t.Error("a denied public address is reachable")
	}
	if v, _ := p.Evaluate(netip.MustParseAddr("198.51.100.5"), 443, netfilter.ProtoTCP); v != netfilter.VerdictAllow {
		t.Error("the deny list removed more than it named")
	}

	bad := f
	bad.DenyCIDRs = []string{"not-a-cidr"}
	if _, err := bad.Compile(); err == nil || !strings.Contains(err.Error(), "deny_cidrs[0]") {
		t.Errorf("a malformed deny entry compiled, or the error does not name it: %v", err)
	}
}

// TestEgressScopeKeepsTheDenyList: a project narrowing its executor's firewall
// must not shed the executor's deny list, which would add reach back.
func TestEgressScopeKeepsTheDenyList(t *testing.T) {
	ex := scopedExecutor(t, EgressFilter{
		Enabled:             true,
		AllowPublicInternet: true,
		AllowAllPorts:       true,
		Resolvers:           []string{"1.1.1.1:53"},
		DenyCIDRs:           []string{"203.0.113.0/24"},
	})
	f, err := ex.effectiveFilter(executor.EgressScopePublic)
	if err != nil {
		t.Fatalf("effectiveFilter: %v", err)
	}
	p, err := f.Policy()
	if err != nil {
		t.Fatalf("Policy: %v", err)
	}
	if v, _ := p.Evaluate(netip.MustParseAddr("203.0.113.5"), 443, netfilter.ProtoTCP); v != netfilter.VerdictDrop {
		t.Error("the project's scope re-opened a range the executor denies")
	}
}

// TestEgressScopePublicRefusedWhenTheExecutorHasNoInternet is the widening
// Task 20345 closed: an executor that reaches only a private range cannot be
// asked, by a repo-committed file, for the public Internet instead.
func TestEgressScopePublicRefusedWhenTheExecutorHasNoInternet(t *testing.T) {
	ex := scopedExecutor(t, EgressFilter{
		Enabled:    true,
		AllowCIDRs: []string{"10.8.0.0/24"},
		AllowPorts: []int{443},
		Resolvers:  []string{"10.8.0.53:53"},
	})
	_, err := ex.effectiveFilter(executor.EgressScopePublic)
	if err == nil {
		t.Fatal("a project scope widened a private-only executor to the public Internet")
	}
	if !errors.Is(err, executor.ErrUnsupported) || !strings.Contains(err.Error(), "public Internet") {
		t.Errorf("refusal %q does not explain itself", err)
	}
}

// TestSandboxResolvers: only standard-port resolvers can become --dns, because
// the flag takes an address and nothing else.
func TestSandboxResolvers(t *testing.T) {
	got := sandboxResolvers([]string{"1.1.1.1:53", "9.9.9.9", "10.0.0.53:5353", "[2606:4700:4700::1111]:53"})
	want := []string{"1.1.1.1", "9.9.9.9", "2606:4700:4700::1111"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("sandboxResolvers = %v, want %v", got, want)
	}
}

// TestBuildRunArgs_DNSAndGroups renders the two flags a virtual executor adds.
func TestBuildRunArgs_DNSAndGroups(t *testing.T) {
	req := baseRequest()
	req.Network = "cloop-sbx-vx-test"
	req.DNS = []string{"1.1.1.1", "2606:4700:4700::1111"}
	req.GroupAdd = []string{"46"}
	built, err := buildRunArgs(req)
	if err != nil {
		t.Fatalf("buildRunArgs: %v", err)
	}
	line := strings.Join(built.Args, " ")
	for _, want := range []string{"--dns 1.1.1.1", "--dns 2606:4700:4700::1111", "--group-add 46"} {
		if !strings.Contains(line, want) {
			t.Errorf("argv lacks %q:\n%s", want, line)
		}
	}

	// --dns is refused by both runtimes alongside --network=none.
	req.Network = NetworkNone
	built, err = buildRunArgs(req)
	if err != nil {
		t.Fatalf("buildRunArgs(none): %v", err)
	}
	if strings.Contains(strings.Join(built.Args, " "), "--dns") {
		t.Error("--dns rendered on a sandbox with no network")
	}

	for _, bad := range []string{"0", "-5", "plugdev", "4 6"} {
		req := baseRequest()
		req.GroupAdd = []string{bad}
		if _, err := buildRunArgs(req); err == nil {
			t.Errorf("--group-add %q was rendered", bad)
		}
	}
	req = baseRequest()
	req.Network = NetworkBridge
	req.DNS = []string{"dns.google"}
	if _, err := buildRunArgs(req); err == nil {
		t.Error("a --dns name, rather than an address, was rendered")
	}
}

// TestGroupAddOptionIsValidated: the option is checked when the executor is
// built, so a bad value fails construction rather than every start.
func TestGroupAddOptionIsValidated(t *testing.T) {
	for _, bad := range []string{"0", "root", ""} {
		if _, err := (Options{GroupAdd: []string{bad}}).Normalize(); err == nil {
			t.Errorf("group_add %q accepted", bad)
		}
	}
	if _, err := (Options{GroupAdd: []string{"46"}}).Normalize(); err != nil {
		t.Errorf("group_add 46 refused: %v", err)
	}
}

// TestDevicesRefusedUnderKernelIsolatedRuntimes pins the measured behaviour:
// gVisor answers every open of a passed-through node with ENXIO, so the driver
// neither advertises devices there nor renders the flag.
func TestDevicesRefusedUnderKernelIsolatedRuntimes(t *testing.T) {
	for _, rt := range []string{"runsc", "kata-qemu"} {
		ex := &Executor{id: "sbx-" + rt, opts: Options{OCIRuntime: rt, Network: NetworkNone}}
		if ex.Capabilities().SupportsDevices {
			t.Errorf("%s: advertises SupportsDevices", rt)
		}
		_, err := ex.buildRequest(executor.Spec{
			WorkDir: t.TempDir(),
			Argv:    []string{"/bin/true"},
			Devices: []executor.HostDevice{{Name: "zero", Source: "/dev/zero"}},
		}, t.TempDir(), nil)
		if err == nil || !errors.Is(err, executor.ErrUnsupported) {
			t.Errorf("%s: a device was accepted: %v", rt, err)
		}
	}
	plain := &Executor{id: "sbx-runc", opts: Options{Network: NetworkNone}}
	if !plain.Capabilities().SupportsDevices {
		t.Error("the default runtime stopped advertising devices")
	}
}

// TestRootlessEngineCannotFilter: a rootless podman network lives in the user's
// own network namespace, so a host-side ruleset would match nothing. The driver
// must neither advertise filtering nor start a filtered sandbox there.
func TestRootlessEngineCannotFilter(t *testing.T) {
	ex := &Executor{id: "sbx-rootless", rt: Runtime{Name: RuntimePodman, Rootless: true},
		opts: Options{Network: NetworkBridge, EgressFilter: EgressFilter{
			Enabled: true, AllowPublicInternet: true, AllowAllPorts: true, Resolvers: []string{"1.1.1.1"},
		}}}
	caps := ex.Capabilities()
	if caps.FilteredEgress || caps.SupportsEgressScope {
		t.Errorf("a rootless engine advertises filtering: %+v", caps)
	}
	if _, _, err := ex.installFirewall(context.Background(), executor.EgressScopeUnset); err == nil ||
		!errors.Is(err, executor.ErrUnsupported) || !strings.Contains(err.Error(), "rootless") {
		t.Fatalf("installFirewall on a rootless engine = %v", err)
	}
}

// TestResolvConfIsStagedWhereTheEngineCanSeeIt: the file names exactly the
// allowed resolvers, lives under the configured stage directory (the agent's
// work root, not its private /tmp), is readable by the unprivileged sandbox
// user, and is written once per resolver list.
func TestResolvConfIsStagedWhereTheEngineCanSeeIt(t *testing.T) {
	stage := t.TempDir()
	ex := &Executor{id: "vx-abc", opts: Options{StageDir: stage}}
	path, err := ex.resolvConf([]string{"1.1.1.1", "2606:4700:4700::1111"})
	if err != nil {
		t.Fatalf("resolvConf: %v", err)
	}
	if !strings.HasPrefix(path, stage+string(os.PathSeparator)) {
		t.Errorf("staged at %s, outside the stage dir %s", path, stage)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "nameserver 1.1.1.1\n") ||
		!strings.Contains(string(raw), "nameserver 2606:4700:4700::1111\n") ||
		strings.Contains(string(raw), "127.0.0.11") {
		t.Errorf("resolv.conf = %q", raw)
	}
	if fi, _ := os.Stat(path); fi.Mode().Perm() != 0o644 {
		t.Errorf("mode %v, want 0644 so the sandbox user can read it", fi.Mode().Perm())
	}
	again, err := ex.resolvConf([]string{"1.1.1.1", "2606:4700:4700::1111"})
	if err != nil || again != path {
		t.Errorf("the same list produced another file: %s vs %s (%v)", again, path, err)
	}
	other, _ := ex.resolvConf([]string{"9.9.9.9"})
	if other == path {
		t.Error("a different list reused the same file, which a running sandbox may have mounted")
	}
	if _, err := ex.resolvConf([]string{"dns.google"}); err == nil {
		t.Error("a name was accepted as a resolver")
	}
}
