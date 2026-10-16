package fwpolicy

import (
	"net/netip"
	"testing"

	"github.com/blechschmidt/cloop/pkg/executor"
)

// TestExplainNamesTheLevel: each deny path's sentence names the level a
// developer would go and change — the project's allowlist for an address
// nothing allowed, the device's deny list for a range it denied.
func TestExplainNamesTheLevel(t *testing.T) {
	device := executor.FirewallRules{AllowPublicInternet: true, AllowPorts: []int{80, 443},
		DenyCIDRs: []string{"203.0.113.0/24"}, Resolvers: []string{"1.1.1.1:53"}}
	project := executor.FirewallRules{AllowCIDRs: []string{"1.1.1.1/32", "198.51.100.0/24"},
		AllowPorts: []int{443}, Resolvers: []string{"1.1.1.1:53"}}
	levels := []Level{
		{Kind: "config", Name: "executor sgx's configuration"},
		{Kind: "device", Name: "device sgx's firewall", Rules: &device},
		{Kind: "own", Name: "virtual executor vx-1's firewall"},
		{Kind: "project", Name: "this project's firewall", Rules: &project},
	}
	a := netip.MustParseAddr
	for _, c := range []struct {
		rule  string
		dst   netip.Addr
		port  uint16
		proto string
		want  string
	}{
		{"default", a("8.8.8.8"), 443, "tcp", "not in the project's allow list"},
		{"default", a("198.51.100.7"), 22, "tcp", "port 22 is not one the project's allow list opens (443)"},
		{"default", a("8.8.8.8"), 53, "udp", "UDP is not allowed: the project's allow list opens TCP only, and UDP reaches only the resolvers it names"},
		{"default", a("1.1.1.1"), 5353, "udp", "port 5353 is not where the project's allow list names this resolver"},
		{"default", a("8.8.8.8"), 0, "icmp", "ICMP is not allowed: the project's allow list opens TCP only"},
		{"deny:203.0.113.0/24", a("203.0.113.7"), 443, "tcp", "in device sgx's deny list (203.0.113.0/24)"},
		{"block:10.0.0.0/8", a("10.1.2.3"), 5432, "tcp", "private (RFC1918/ULA) range 10.0.0.0/8, which the project's allow list does not name"},
		{"meta:169.254.169.254/32", a("169.254.169.254"), 80, "tcp", "the cloud metadata service at 169.254.169.254 (instance metadata on AWS, Azure, Google Cloud, Oracle Cloud and most other clouds), which a firewall opens only when every level names its own address"},
		{"xlat:64:ff9b::/96", a("64:ff9b::808:808"), 443, "tcp", "an IPv6 translation prefix (64:ff9b::/96), which no allow list waives — allow the IPv4 range it stands for instead"},
	} {
		if got := Explain(levels, c.rule, c.dst, c.port, c.proto); got != c.want {
			t.Errorf("%s %s:%d/%s\n got %q\nwant %q", c.rule, c.dst, c.port, c.proto, got, c.want)
		}
	}

	// Under a virtual executor's own firewall, with no stored levels.
	own := executor.FirewallRules{AllowPublicInternet: true, DenyCIDRs: []string{"1.0.0.1/32"}}
	vx := []Level{{Kind: "own", Name: "virtual executor vx-1's firewall", Rules: &own}}
	if got := Explain(vx, "deny:1.0.0.1/32", a("1.0.0.1"), 443, "tcp"); got != "in virtual executor vx-1's deny list (1.0.0.1/32)" {
		t.Errorf("virtual executor deny: %q", got)
	}
	if got := Explain(vx, "default", a("8.8.8.8"), 53, "udp"); got != "UDP is not allowed: virtual executor vx-1's allow list opens TCP only, and UDP reaches only the resolvers it names" {
		t.Errorf("virtual executor default: %q", got)
	}
	cfg := []Level{{Kind: "config", Name: "executor container-1's configuration", Rules: &own}}
	if got := Explain(cfg, "default", a("10.0.0.1"), 443, "tcp"); got != "not in executor container-1's configured allow list" {
		t.Errorf("config default: %q", got)
	}
	if got := Explain(nil, "default", a("8.8.8.8"), 443, "tcp"); got != "not allowed by the sandbox's firewall" {
		t.Errorf("no levels: %q", got)
	}
	if got := Explain(levels, "bogus", a("8.8.8.8"), 443, "tcp"); got != "refused by the sandbox's firewall" {
		t.Errorf("unknown rule: %q", got)
	}
}
