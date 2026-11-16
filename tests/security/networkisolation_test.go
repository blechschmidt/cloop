package security

// Two runs of different projects on one container executor never share a
// network (Task 20502). Before, an unfiltered executor put every sandbox on
// the engine's default bridge, where a container reaches its neighbours'
// listeners; an --internal filter put every project on one internal bridge;
// and a direct-egress filter shared one bridge between every project confined
// alike. This checks the network each sandbox is started on, through the real
// argv builder and the same decision Start provisions by (AuditRunArgv), so it
// holds on a machine with no engine. The containers themselves are probed by
// pkg/executor/container's TestIntegration_TwoProjectsSandboxesCannotReachEachOther.

import (
	"testing"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/executor/container"
)

func TestTwoProjectsSandboxesNeverShareANetwork(t *testing.T) {
	rules := &executor.FirewallRules{AllowCIDRs: []string{"10.0.0.0/8"}, AllowPorts: []int{443}}
	configs := map[string]struct {
		opts  container.Options
		rules *executor.FirewallRules
	}{
		"unfiltered bridge": {opts: container.Options{Network: container.NetworkBridge}},
		"internal filter": {opts: container.Options{Network: container.NetworkBridge,
			EgressFilter: container.EgressFilter{Enabled: true, Internal: true}}},
		"direct filter": {opts: container.Options{Network: container.NetworkBridge,
			EgressFilter: container.EgressFilter{Enabled: true, AllowCIDRs: []string{"10.0.0.0/8"}, AllowPorts: []int{443}}}},
		"identical rules": {opts: container.Options{Network: container.NetworkBridge}, rules: rules},
	}
	network := func(t *testing.T, opts container.Options, project string, r *executor.FirewallRules) string {
		t.Helper()
		opts.ID = "shared-executor"
		opts.AllowRootUser = true
		spec := executor.Spec{Argv: []string{"cloop", "run"}, EgressRules: r,
			Labels: map[string]string{"project": project}}
		argv, err := container.AuditRunArgv(opts, container.AuditRuntime{Name: "docker"}, t.TempDir(), spec)
		if err != nil {
			t.Fatalf("AuditRunArgv for %s: %v", project, err)
		}
		for i, a := range argv {
			if a == "--network" && i+1 < len(argv) {
				return argv[i+1]
			}
			if len(a) > len("--network=") && a[:len("--network=")] == "--network=" {
				return a[len("--network="):]
			}
		}
		t.Fatalf("argv names no network: %v", argv)
		return ""
	}
	for name, c := range configs {
		t.Run(name, func(t *testing.T) {
			alpha := network(t, c.opts, "/srv/alpha", c.rules)
			alphaAgain := network(t, c.opts, "/srv/alpha", c.rules)
			bravo := network(t, c.opts, "/srv/bravo", c.rules)
			for _, n := range []string{alpha, bravo} {
				if n == container.NetworkBridge || n == "podman" || n == container.NetworkNone {
					t.Fatalf("a sandbox joins %q, the engine's default network, which every container on "+
						"the host shares", n)
				}
			}
			if alpha == bravo {
				t.Fatalf("two projects' sandboxes join one network, %q", alpha)
			}
			if alpha != alphaAgain {
				t.Errorf("one project's two workloads join %q and %q; they share their project's network", alpha, alphaAgain)
			}
		})
	}
	// A sandbox with no network keeps none, whatever its project.
	if n := network(t, container.Options{Network: container.NetworkNone}, "/srv/alpha", nil); n != container.NetworkNone {
		t.Errorf("an executor with no network started a sandbox on %q", n)
	}
}
