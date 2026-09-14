package config

// A container egress_filter the driver cannot compile must be refused, or at
// minimum reported, by every path that reads the config — not just by the one
// an operator happens to have used.
//
// The trap these tests exist to hold shut is that the executor section has
// three entry points with three different jobs, and a check added to one of
// them looks complete while covering a third of the surface:
//
//	cloop config set      -> Config.ValidateNumeric -> ValidateExecutors   (reject)
//	config.Load           -> validateAndClamp       -> clampContainerExec  (repair/disable)
//	cloop config validate -> configvalidate.Run     -> checkExecutors      (report)
//
// Before this, the container filter was compiled by none of them, while the
// Kubernetes filter beside it was compiled by two. The asymmetry is the bug:
// the same typo in the same kind of value was a startup error under
// executors.kubernetes and silent under executors.container until the first
// sandbox made a network request.
//
// The configvalidate leg of the table lives in pkg/configvalidate, which
// imports this package; asserting it from here would be an import cycle.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// badFilters are the shapes netfilter refuses, each paired with the substring
// an operator should see. Every one of them loaded clean before this check.
var badFilters = []struct {
	name string
	yaml string
	cfg  ContainerEgressFilterConfig
	want string
}{
	{
		// The case with no other coverage anywhere: the section is switched
		// off, so the driver's own Validate returns early without looking at
		// it, and the mistake waits in the file for whoever flips the boolean.
		name: "disabled section with a mistyped CIDR",
		yaml: "enabled: false\n      allow_cidrs: [\"10.8.0.0\"]\n      allow_ports: [443]",
		cfg:  ContainerEgressFilterConfig{Enabled: false, AllowCIDRs: []string{"10.8.0.0"}, AllowPorts: []int{443}},
		want: "allow_cidrs[0]",
	},
	{
		name: "disabled section with an unparseable resolver",
		yaml: "enabled: false\n      resolvers: [\"dns.internal\"]",
		cfg:  ContainerEgressFilterConfig{Enabled: false, Resolvers: []string{"dns.internal"}},
		want: "resolvers[0]",
	},
	{
		// Enabled, but relying on an --internal network alone, so the driver
		// installed no ruleset and never compiled the port list. A per-project
		// egress scope can add the destinations that turn it into one later.
		name: "internal-only filter with an out-of-range port",
		yaml: "enabled: true\n      internal: true\n      allow_ports: [99999]",
		cfg:  ContainerEgressFilterConfig{Enabled: true, Internal: true, AllowPorts: []int{99999}},
		want: "allow_ports[0]",
	},
	{
		name: "enabled filter with a mistyped CIDR",
		yaml: "enabled: true\n      internal: true\n      allow_cidrs: [\"10.8.0.0/33\"]\n      allow_ports: [443]",
		cfg:  ContainerEgressFilterConfig{Enabled: true, Internal: true, AllowCIDRs: []string{"10.8.0.0/33"}, AllowPorts: []int{443}},
		want: "allow_cidrs[0]",
	},
	{
		// Destinations with no ports is an allow rule with no bound — the hole
		// netfilter.Compile refuses on purpose.
		name: "destinations allowed on no ports",
		yaml: "enabled: true\n      internal: true\n      allow_cidrs: [\"10.8.0.0/24\"]",
		cfg:  ContainerEgressFilterConfig{Enabled: true, Internal: true, AllowCIDRs: []string{"10.8.0.0/24"}},
		want: "no ports",
	},
}

// goodFilter is the recommended two-line shape, carried through every case as
// a control: a check that refuses everything would pass each table below.
var goodFilter = ContainerEgressFilterConfig{Enabled: true, Internal: true}

func containerWith(f ContainerEgressFilterConfig) ContainerExecutorConfig {
	return ContainerExecutorConfig{
		Enabled:      true,
		Network:      "bridge",
		Image:        "ghcr.io/blechschmidt/cloop-harness:v1",
		EgressFilter: f,
	}
}

// TestConfigSetRejectsBadContainerEgressFilter covers the strict path, through
// ValidateNumeric rather than the leaf validator — ValidateNumeric is what
// `cloop config set` actually calls, and a test that reached past it would
// keep passing if the two were ever disconnected.
func TestConfigSetRejectsBadContainerEgressFilter(t *testing.T) {
	for _, tc := range badFilters {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &Config{}
			cfg.Executors.Container = containerWith(tc.cfg)

			err := cfg.ValidateNumeric()
			if err == nil {
				t.Fatalf("ValidateNumeric accepted a filter the driver cannot compile")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error does not name the offending key\n got: %v\nwant substring: %q", err, tc.want)
			}
			if !strings.Contains(err.Error(), "executors.container.egress_filter") {
				t.Errorf("error does not name the config section: %v", err)
			}
		})
	}

	t.Run("control: the recommended filter is accepted", func(t *testing.T) {
		cfg := &Config{}
		cfg.Executors.Container = containerWith(goodFilter)
		if err := cfg.ValidateNumeric(); err != nil {
			t.Fatalf("ValidateNumeric rejected a valid filter: %v", err)
		}
	})
}

// TestLoadReportsBadContainerEgressFilter covers the defensive path.
//
// Load never errors, so the assertion is on the two outcomes it can produce,
// and which one applies turns on whether there is a security control to lose:
// a filter switched *on* that cannot compile is one the executor cannot
// enforce, so the executor is not registered; a filter switched *off* confines
// nothing either way, so disabling an executor over it would be an outage with
// no security gain, and it is only reported.
func TestLoadReportsBadContainerEgressFilter(t *testing.T) {
	for _, tc := range badFilters {
		t.Run(tc.name, func(t *testing.T) {
			c := containerWith(tc.cfg)
			msgs := clampContainerExecutor(&c)
			if len(msgs) == 0 {
				t.Fatalf("clamp reported nothing for a filter the driver cannot compile")
			}
			joined := strings.Join(msgs, "\n")
			if !strings.Contains(joined, tc.want) {
				t.Errorf("clamp message does not name the offending key\n got: %s\nwant substring: %q", joined, tc.want)
			}

			if tc.cfg.Enabled {
				if c.Enabled {
					t.Errorf("executor still registered with an unenforceable egress filter: %s", joined)
				}
				if !strings.Contains(joined, "disabled") {
					t.Errorf("message does not say the executor was disabled: %s", joined)
				}
			} else if !c.Enabled {
				t.Errorf("executor disabled over a typo in a switched-off section: %s", joined)
			}
		})
	}

	t.Run("control: the recommended filter is left alone", func(t *testing.T) {
		c := containerWith(goodFilter)
		if msgs := clampContainerExecutor(&c); len(msgs) != 0 {
			t.Fatalf("clamp complained about a valid filter: %v", msgs)
		}
		if !c.Enabled {
			t.Fatal("clamp disabled an executor with a valid filter")
		}
	})
}

// TestLoadDisablesExecutorWithUnenforceableFilter drives the same repair
// through Load and a real config.yaml, so the wiring between the clamp and the
// loader is covered and not just the clamp in isolation.
func TestLoadDisablesExecutorWithUnenforceableFilter(t *testing.T) {
	for _, tc := range badFilters {
		if !tc.cfg.Enabled {
			continue
		}
		t.Run(tc.name, func(t *testing.T) {
			dir := writeExecutorConfig(t, tc.yaml)
			cfg, err := Load(dir)
			if err != nil {
				t.Fatalf("Load: %v", err)
			}
			if cfg.Executors.Container.Enabled {
				t.Error("Load registered a container executor whose egress filter cannot compile")
			}
		})
	}

	t.Run("control: a valid filter survives Load", func(t *testing.T) {
		dir := writeExecutorConfig(t, "enabled: true\n      internal: true")
		cfg, err := Load(dir)
		if err != nil {
			t.Fatalf("Load: %v", err)
		}
		if !cfg.Executors.Container.Enabled {
			t.Error("Load disabled a container executor with a valid egress filter")
		}
		if !cfg.Executors.Container.EgressFilter.Internal {
			t.Error("Load dropped the filter it accepted")
		}
	})
}

// writeExecutorConfig writes a .cloop/config.yaml whose container executor
// carries the given egress_filter body, indented to sit under the key.
func writeExecutorConfig(t *testing.T, filterYAML string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, ".cloop"), 0o755); err != nil {
		t.Fatalf("mkdir .cloop: %v", err)
	}
	body := "executors:\n" +
		"  container:\n" +
		"    enabled: true\n" +
		"    network: bridge\n" +
		"    image: ghcr.io/blechschmidt/cloop-harness:v1\n" +
		"    egress_filter:\n" +
		"      " + filterYAML + "\n"
	if err := os.WriteFile(filepath.Join(dir, ".cloop", "config.yaml"), []byte(body), 0o600); err != nil {
		t.Fatalf("write config.yaml: %v", err)
	}
	return dir
}
