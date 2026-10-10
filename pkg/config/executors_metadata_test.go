package config

// An egress_filter allowlist entry that contains a cloud metadata service
// without naming it (Task 20397) compiles — the filter keeps the service
// closed — and is refused anyway, at every path that writes or reads the file:
//
//	cloop config set      -> ValidateExecutors         (reject, on or off)
//	config.Load           -> nothing to repair          (the filter is safe)
//	cloop ui              -> MetadataExposures          (refuse to start while in force)
//	cloop hub doctor      -> MetadataExposures          (fail while in force, warn otherwise)
//
// This file holds the first two legs and the in-force rule the last two share;
// cmd and pkg/hubdoctor test their own.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidateExecutorsRefusesAnAllowlistThatContainsAMetadataService(t *testing.T) {
	cases := []struct {
		name string
		e    ExecutorsConfig
		want []string
	}{
		{
			name: "container, switched off",
			e: ExecutorsConfig{Container: ContainerExecutorConfig{EgressFilter: ContainerEgressFilterConfig{
				AllowCIDRs: []string{"169.254.169.0/24"}, AllowPorts: []int{80}}}},
			want: []string{"executors.container.egress_filter.allow_cidrs: 169.254.169.0/24 contains 2 cloud metadata services",
				"Add their addresses (169.254.169.252/32, 169.254.169.254/32) to executors.container.egress_filter.allow_cidrs"},
		},
		{
			name: "kubernetes ULA",
			e: ExecutorsConfig{Kubernetes: KubernetesExecutorConfig{EgressFilter: KubernetesEgressFilterConfig{
				Enabled: true, CIDRs: []string{"fd00:ec2::/32", "fd00:ec2::23/128"}, Ports: []int{443}}}},
			want: []string{"executors.kubernetes.egress_filter.cidrs: fd00:ec2::/32 contains the cloud metadata service " +
				"at fd00:ec2::254 (AWS instance metadata over IPv6)", "or allow a range that leaves it out"},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := ValidateExecutors(c.e)
			if err == nil {
				t.Fatal("ValidateExecutors accepted an allowlist that contains a metadata service")
			}
			for _, w := range c.want {
				if !strings.Contains(err.Error(), w) {
					t.Errorf("refusal %q lacks %q", err, w)
				}
			}
		})
	}

	// Naming the service, or allowing around it, is the supported shape.
	ok := ExecutorsConfig{Container: ContainerExecutorConfig{Network: "bridge", EgressFilter: ContainerEgressFilterConfig{
		Enabled: true, Internal: true, AllowCIDRs: []string{"169.254.169.254/32", "100.64.0.0/16"},
		AllowPorts: []int{80}}}}
	if err := ValidateExecutors(ok); err != nil {
		t.Errorf("a named service was refused: %v", err)
	}
}

// TestMetadataExposuresKnowsWhatIsInForce: `cloop ui` refuses only what is in
// force — the filter and its executor both switched on — and warns about the
// rest, because a switched-off section confines nothing either way.
func TestMetadataExposuresKnowsWhatIsInForce(t *testing.T) {
	filter := ContainerEgressFilterConfig{Enabled: true, Internal: true, AllowCIDRs: []string{"100.64.0.0/10"},
		AllowPorts: []int{443}}
	for _, c := range []struct {
		executor, filter, want bool
	}{{true, true, true}, {false, true, false}, {true, false, false}} {
		f := filter
		f.Enabled = c.filter
		e := ExecutorsConfig{Container: ContainerExecutorConfig{Enabled: c.executor, EgressFilter: f}}
		xs := e.MetadataExposures()
		if len(xs) != 1 {
			t.Fatalf("exposures = %v", xs)
		}
		if xs[0].InForce != c.want {
			t.Errorf("executor on=%t, filter on=%t: in force = %t, want %t", c.executor, c.filter, xs[0].InForce, c.want)
		}
		if xs[0].Key != "executors.container.egress_filter.allow_cidrs" ||
			!strings.Contains(xs[0].Error(), "100.100.100.200 (Alibaba Cloud instance metadata)") {
			t.Errorf("exposure = %q", xs[0].Error())
		}
	}
}

// TestLoadLeavesAContainingAllowlistRunning: there is nothing to repair — the
// compiled filter keeps the service closed — so Load neither switches the
// executor off nor rewrites the list. Refusing is cloop ui's to do, where the
// operator sees why.
func TestLoadLeavesAContainingAllowlistRunning(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, ".cloop"), 0o700); err != nil {
		t.Fatal(err)
	}
	yaml := `executors:
  container:
    enabled: true
    network: bridge
    egress_filter:
      enabled: true
      allow_cidrs: ["169.254.0.0/16"]
      allow_ports: [80]
      resolvers: ["1.1.1.1"]
`
	if err := os.WriteFile(filepath.Join(dir, ".cloop", "config.yaml"), []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(dir)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !cfg.Executors.Container.Enabled || len(cfg.Executors.Container.EgressFilter.AllowCIDRs) != 1 {
		t.Errorf("Load changed the section: %+v", cfg.Executors.Container)
	}
	xs := cfg.Executors.MetadataExposures()
	if len(xs) != 1 || !xs[0].InForce || len(xs[0].Finding.Services) != 6 {
		t.Errorf("exposures = %+v, want the six link-local services, in force", xs)
	}
}
