package container

// Task 20502 on a real engine: two projects' sandboxes on one executor, a
// listener in project alpha's, and project bravo's sandbox trying to connect
// to it. Bravo must not get through; a second sandbox of alpha's own must, or
// the refusal proves nothing about the listener. Each configuration a sandbox
// network can come from is covered, and each under every engine installed:
//
//   - an unfiltered executor (network: bridge), which used to put every
//     sandbox on the engine's default bridge, where a container reaches its
//     neighbours directly;
//   - an --internal filter, which used to put every project on one internal
//     bridge, a Layer 2 segment with nothing in between;
//   - a direct-egress filter whose allow list covers every engine's subnet
//     pool, and two projects carrying the same firewall rules — both of which
//     used to share one bridge per confinement. These need root and nft, and
//     check that the installed ruleset carries the sibling rules. Which of the
//     host's filters refuses the packet first — the sandbox's ruleset or the
//     engine's own isolation rules, all on one hook — is the kernel's choice,
//     so the rules' effect on their own is proved without an engine, by
//     pkg/netfilter's TestSiblingRulesKeepTwoBridgesApart.
//
// After the last of a project's workloads ends, its network and its ruleset
// are gone.
//
// Opt-in: it starts real containers.
//
//	CLOOP_FIREWALL_CONTAINER_E2E=1 go test ./pkg/executor/container -run TestIntegration_TwoProjectsSandboxesCannotReachEachOther -v

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor"
)

func TestIntegration_TwoProjectsSandboxesCannotReachEachOther(t *testing.T) {
	if os.Getenv("CLOOP_FIREWALL_CONTAINER_E2E") != "1" {
		t.Skip("set CLOOP_FIREWALL_CONTAINER_E2E=1 to start two projects' sandboxes and probe one from the other")
	}
	covering := []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"}
	rules := &executor.FirewallRules{AllowCIDRs: covering, AllowPorts: []int{isolationPort}}
	configs := []struct {
		name     string
		mutate   func(*Options)
		rules    *executor.FirewallRules
		needsNft bool
	}{
		{name: "unfiltered", mutate: func(o *Options) { o.Network = NetworkBridge }},
		{name: "internal", mutate: func(o *Options) {
			o.Network = NetworkBridge
			o.EgressFilter = EgressFilter{Enabled: true, Internal: true}
		}},
		{name: "covering-filter", needsNft: true, mutate: func(o *Options) {
			o.Network = NetworkBridge
			o.EgressFilter = EgressFilter{Enabled: true, AllowCIDRs: covering, AllowPorts: []int{isolationPort}}
		}},
		{name: "identical-rules", needsNft: true, rules: rules, mutate: func(o *Options) { o.Network = NetworkBridge }},
	}
	image := testImage()
	ran := 0
	for _, engine := range []string{RuntimeDocker, RuntimePodman} {
		rt, ok := usableEngine(t, engine, image)
		if !ok {
			continue
		}
		for _, c := range configs {
			t.Run(engine+"/"+c.name, func(t *testing.T) {
				if c.needsNft && !canInstallNft() {
					t.Skip("installing a bridge ruleset needs root and nft(8)")
				}
				ran++
				proveTwoProjectsApart(t, rt, image, c.name, c.mutate, c.rules)
			})
		}
	}
	if ran == 0 {
		t.Skip("neither docker nor podman is usable here with " + image)
	}
}

// isolationPort is what alpha's listener binds inside its sandbox.
const isolationPort = 8080

func proveTwoProjectsApart(t *testing.T, rt Runtime, image, config string, mutate func(*Options), rules *executor.FirewallRules) {
	t.Helper()
	id := "t20502-" + rt.Name + "-" + config
	ex, err := New(func() Options {
		o := Options{ID: id, Runtime: rt.Name, Image: image, AllowRootUser: true}
		mutate(&o)
		return o
	}())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		for _, h := range ex.Handles() {
			_ = ex.Signal(ctx, h, executor.SignalKill)
		}
		_, _ = ex.ReapOrphans(ctx)
	})
	project := func(name string) executor.Spec {
		return executor.Spec{WorkDir: t.TempDir(), Labels: map[string]string{"project": "/srv/" + name},
			EgressRules: rules}
	}

	// Alpha's listener: answers every connection with one line, until killed.
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	listen := project("alpha")
	listen.Argv = []string{"/bin/sh", "-c", fmt.Sprintf(
		"trap 'exit 0' TERM; while true; do echo reached-alpha | nc -l -p %d; done", isolationPort)}
	h, err := ex.Start(ctx, listen)
	if err != nil {
		t.Fatalf("start alpha's listener: %v", err)
	}
	ex.mu.Lock()
	rec := ex.handles[h.ID]
	ex.mu.Unlock()
	if rec == nil || rec.tenantNetwork == "" {
		t.Fatalf("alpha's listener joined no tenant network (record %+v)", rec)
	}
	alphaNet, alphaTable := rec.tenantNetwork, rec.tenantTable
	var addr string
	for deadline := time.Now().Add(30 * time.Second); addr == "" && time.Now().Before(deadline); time.Sleep(200 * time.Millisecond) {
		if addrs, err := ex.containerAddrs(ctx, rec.name, alphaNet); err == nil {
			addr = addrs[0].String()
		}
	}
	if addr == "" {
		t.Fatalf("alpha's listener has no address on %s", alphaNet)
	}
	t.Logf("%s: alpha listens at %s:%d on %s (bridge %s, table %q)", config, addr, isolationPort, alphaNet,
		bridgeName(alphaNet), alphaTable)

	probe := func(name string) string {
		t.Helper()
		spec := project(name)
		spec.Argv = []string{"/bin/sh", "-c", fmt.Sprintf("nc -w 3 %s %d </dev/null; echo rc=$?", addr, isolationPort)}
		res, err := executor.Run(ctx, ex, spec)
		if err != nil {
			t.Fatalf("%s's probe: %v (output %q)", name, err, res.Output)
		}
		return string(res.Output)
	}

	// The control first, and retried while the listener comes up: a refusal
	// from bravo means something only once alpha's own sandbox gets through.
	var out string
	for i := 0; i < 10; i++ {
		if out = probe("alpha"); strings.Contains(out, "reached-alpha") {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	controlReached := strings.Contains(out, "reached-alpha")
	if !controlReached && !(rt.Name == RuntimePodman && config == "internal") {
		t.Fatalf("%s: alpha's own second sandbox could not reach alpha's listener, so the probe proves nothing:\n%s",
			config, out)
	}
	out = probe("bravo")
	if strings.Contains(out, "reached-alpha") {
		t.Fatalf("%s: project bravo's sandbox reached project alpha's listener at %s:%d:\n%s",
			config, addr, isolationPort, out)
	}
	// Nor does a container on the engine's default network, where a podman
	// derived-image build used to run the project's setup: podman's isolate
	// does not cover that network, so on podman only the sandbox's ruleset
	// keeps it out — and a process that may not install one is warned about
	// by preflight instead.
	if _, nftErr := ex.nftForGuards(ctx); nftErr == nil || rt.Name == RuntimeDocker {
		if out := outsiderProbe(ctx, t, rt, image, addr); strings.Contains(out, "reached-alpha") {
			t.Fatalf("%s: a container on %s's default network reached project alpha's listener:\n%s",
				config, rt.Name, out)
		}
	}
	// And the hub's egress proxy, which dials from this host past every
	// sandbox rule, refuses alpha's address whatever a grant covers.
	if why := SandboxAddressRefusal(netip.MustParseAddr(addr)); why == "" {
		t.Errorf("%s: the egress proxy's refusal does not know %s, on sandbox bridge %s", config, addr, bridgeName(alphaNet))
	}
	if why := SandboxAddressRefusal(netip.MustParseAddr("1.1.1.1")); why != "" {
		t.Errorf("%s: the egress proxy refuses a public address: %s", config, why)
	}
	if !controlReached {
		// Measured on netavark 1.4 with br_netfilter loaded: an --internal
		// podman network passes no traffic between its own containers at all,
		// isolate or not, so there is no neighbour for anything to keep out.
		t.Skipf("%s: %s's internal network carries no traffic between its own containers on this host, "+
			"so the refusal above proves nothing more", config, rt.Name)
	}

	// The networks: neither the engine's default bridge nor each other's, and
	// alpha's bridge one the sibling pattern matches.
	bravoNet := networkName(ex.id, confinement{rules: rules}, tenantTag(tenantOf(project("bravo"), "")))
	if alphaNet == bravoNet || alphaNet == NetworkBridge || !strings.HasPrefix(bridgeName(alphaNet), sandboxBridgePrefix) {
		t.Errorf("%s: alpha joined %q and bravo would join %q", config, alphaNet, bravoNet)
	}

	// Under a ruleset, alpha's refuses connections into it — and, a filter's,
	// its own to other sandboxes — and bravo's went with bravo's last
	// workload.
	if alphaTable != "" {
		bravoTable := firewallTable(ex.id, confinement{rules: rules}, tenantTag(tenantOf(project("bravo"), "")))
		var listing []byte
		var err error
		for deadline := time.Now().Add(15 * time.Second); time.Now().Before(deadline); time.Sleep(250 * time.Millisecond) {
			if listing, err = exec.Command("nft", "list", "table", "inet", bravoTable).CombinedOutput(); err != nil {
				break
			}
		}
		if err == nil {
			t.Errorf("%s: bravo's table %s outlived bravo's last workload:\n%s", config, bravoTable, listing)
		}
		listing, err = exec.Command("nft", "list", "table", "inet", alphaTable).CombinedOutput()
		if err != nil {
			t.Fatalf("%s: alpha's table %s is not installed: %v %s", config, alphaTable, err, listing)
		}
		rules := []string{"nothing opens a connection into this sandbox"}
		if config == "covering-filter" || config == "identical-rules" {
			rules = append(rules, "another sandbox's network\"")
		}
		for _, rule := range rules {
			if !strings.Contains(string(listing), rule) {
				t.Errorf("%s: alpha's ruleset has no %q rule:\n%s", config, rule, listing)
			}
		}
		t.Logf("%s: alpha's inbound rule: %s", config,
			strings.TrimSpace(sibLine(string(listing), "nothing opens a connection into this sandbox")))
	}

	// Killing the listener ends alpha's last workload: its network and its
	// ruleset go with it.
	if err := ex.Signal(ctx, h.ID, executor.SignalKill); err != nil {
		t.Fatalf("kill alpha's listener: %v", err)
	}
	gone := false
	for deadline := time.Now().Add(30 * time.Second); time.Now().Before(deadline); time.Sleep(250 * time.Millisecond) {
		if _, err := ex.inspectNetwork(ctx, alphaNet); err != nil {
			gone = true
			break
		}
	}
	if !gone {
		t.Errorf("%s: alpha's network %s outlived its last workload", config, alphaNet)
	}
	if alphaTable != "" {
		// The table goes right after the network, under the same lock.
		var listing []byte
		var err error
		for deadline := time.Now().Add(15 * time.Second); time.Now().Before(deadline); time.Sleep(250 * time.Millisecond) {
			if listing, err = exec.Command("nft", "list", "table", "inet", alphaTable).CombinedOutput(); err != nil {
				break
			}
		}
		if err == nil {
			t.Errorf("%s: alpha's table %s outlived its network:\n%s", config, alphaTable, listing)
		}
	}
}

// outsiderProbe connects to addr from a container on the engine's own
// default network, started straight through the engine's CLI: what no cloop
// sandbox is, and what a podman build used to be.
func outsiderProbe(ctx context.Context, t *testing.T, rt Runtime, image, addr string) string {
	t.Helper()
	network := NetworkBridge
	if rt.Name == RuntimePodman {
		network = "podman"
	}
	res, err := runCLI(ctx, rt, nil, "run", "--rm", "--network", network, "--cap-drop=ALL", image,
		"/bin/sh", "-c", fmt.Sprintf("nc -w 3 %s %d </dev/null; echo rc=$?", addr, isolationPort))
	if err != nil {
		t.Fatalf("outsider probe: %v", err)
	}
	return res.Stdout + res.Stderr
}

// sibLine returns the first line of listing containing sub.
func sibLine(listing, sub string) string {
	for _, l := range strings.Split(listing, "\n") {
		if strings.Contains(l, sub) {
			return l
		}
	}
	return ""
}

// testImage is the image the isolation probes run: CLOOP_TEST_CONTAINER_IMAGE
// when set (CI passes its pinned alpine), else defaultTestImage. It needs
// busybox's nc.
func testImage() string {
	if v := strings.TrimSpace(os.Getenv(testImageEnv)); v != "" {
		return v
	}
	return defaultTestImage
}

// usableEngine reports whether engine is installed, answering, and holds the
// test image.
func usableEngine(t *testing.T, engine, image string) (Runtime, bool) {
	t.Helper()
	rt, err := DetectRuntime(engine)
	if err != nil {
		t.Logf("%s: %v", engine, err)
		return Runtime{}, false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if res, err := runCLI(ctx, rt, nil, "info"); err != nil || res.ExitCode != 0 {
		t.Logf("%s is installed but not answering", engine)
		return Runtime{}, false
	}
	if res, err := runCLI(ctx, rt, nil, "image", "inspect", image); err != nil || res.ExitCode != 0 {
		t.Logf("%s has no %s; `%s pull %s` to cover it", engine, image, engine, image)
		return Runtime{}, false
	}
	if rt.Rootless {
		t.Logf("%s runs rootless here; its networks live where this test cannot inspect the host's rules", engine)
	}
	return rt, true
}

// canInstallNft reports whether this process can install a bridge ruleset.
func canInstallNft() bool {
	if os.Geteuid() != 0 {
		return false
	}
	if _, err := exec.LookPath("nft"); err != nil {
		return false
	}
	return exec.Command("nft", "list", "tables").Run() == nil
}

// holdTenantNetwork starts a workload that keeps workDir's project network —
// and its ruleset — in place until the returned function stops it: a test
// reading a ruleset after its probe has ended needs one, because the network
// and its table go with the project's last workload (Task 20502).
func holdTenantNetwork(t *testing.T, ex *Executor, workDir string) func() {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	h, err := ex.Start(ctx, executor.Spec{WorkDir: workDir,
		Argv: []string{"/bin/sh", "-c", "trap 'exit 0' TERM; sleep 600 & wait"}})
	if err != nil {
		t.Fatalf("start the workload holding the project's network: %v", err)
	}
	return func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		_ = ex.Signal(ctx, h.ID, executor.SignalKill)
	}
}
