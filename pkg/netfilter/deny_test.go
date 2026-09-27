package netfilter

// Tests for the operator deny list (Task 20345): an IP blacklist that wins
// over every allow, in the compiled policy and in both renderers.

import (
	"net/netip"
	"strings"
	"testing"
)

// TestDenyListWinsOverEveryAllow is the property the whole feature rests on: a
// denied range is unreachable however the allows above it are written — a
// granted CIDR, the public Internet, a resolver.
func TestDenyListWinsOverEveryAllow(t *testing.T) {
	p, err := Compile(Input{
		AllowPublicInternet: true,
		AllowAllPorts:       true,
		AllowCIDRs:          prefixes(t, "10.8.0.0/16"),
		Resolvers:           []netip.AddrPort{netip.MustParseAddrPort("1.1.1.1:53")},
		DenyCIDRs:           prefixes(t, "10.8.5.0/24", "8.8.8.0/24", "2001:db8::/32"),
	})
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	for _, tc := range []struct {
		addr  string
		port  uint16
		proto Proto
		want  Verdict
	}{
		{"8.8.8.8", 443, ProtoTCP, VerdictDrop},       // public, but denied
		{"8.8.8.8", 0, ProtoAny, VerdictDrop},         // ICMP too: deny is every transport
		{"8.8.4.4", 443, ProtoTCP, VerdictAllow},      // public, outside the deny list
		{"10.8.5.7", 22, ProtoTCP, VerdictDrop},       // inside the grant, carved out by the deny
		{"10.8.6.7", 22, ProtoTCP, VerdictAllow},      // the rest of the grant survives
		{"10.9.0.1", 22, ProtoTCP, VerdictDrop},       // private and not granted: block set
		{"2001:db8::1", 443, ProtoTCP, VerdictDrop},   // v6 deny
		{"2606:4700::1", 443, ProtoTCP, VerdictAllow}, // v6 public
		{"1.1.1.1", 53, ProtoUDP, VerdictAllow},       // resolver untouched
	} {
		if v, why := p.Evaluate(addr(t, tc.addr), tc.port, tc.proto); v != tc.want {
			t.Errorf("Evaluate(%s:%d/%v) = %v (%s), want %v", tc.addr, tc.port, tc.proto, v, why, tc.want)
		}
	}
}

// TestDenyListNeverWidens: adding a deny list to a policy must only ever turn
// allows into drops, never the reverse. Checked address by address against the
// same policy compiled without it.
func TestDenyListNeverWidens(t *testing.T) {
	base := Input{
		AllowPublicInternet: true,
		AllowPorts:          []uint16{443},
		AllowCIDRs:          prefixes(t, "172.20.0.0/16"),
	}
	without, err := Compile(base)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	withDeny := base
	withDeny.DenyCIDRs = prefixes(t, "0.0.0.0/0")
	with, err := Compile(withDeny)
	if err != nil {
		t.Fatalf("Compile with a /0 deny: %v", err)
	}
	for _, a := range []string{"8.8.8.8", "172.20.1.1", "10.0.0.1", "169.254.169.254", "2606:4700::1"} {
		before, _ := without.Evaluate(addr(t, a), 443, ProtoTCP)
		after, _ := with.Evaluate(addr(t, a), 443, ProtoTCP)
		if before == VerdictDrop && after == VerdictAllow {
			t.Errorf("%s: a deny list widened the policy from drop to allow", a)
		}
	}
	// And the /0 deny does what it says for v4.
	if v, _ := with.Evaluate(addr(t, "8.8.8.8"), 443, ProtoTCP); v != VerdictDrop {
		t.Errorf("a 0.0.0.0/0 deny left 8.8.8.8 reachable")
	}
}

// TestDenyListKeepsSandboxLoopback: a deny covering 127.0.0.0/8 must not break
// the sandbox talking to itself — the loopback allow is namespace-local and
// sits above the deny list for exactly that reason.
func TestDenyListKeepsSandboxLoopback(t *testing.T) {
	p, err := Compile(Input{DenyCIDRs: prefixes(t, "127.0.0.0/8")})
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	if v, why := p.Evaluate(addr(t, "127.0.0.1"), 8080, ProtoTCP); v != VerdictAllow {
		t.Errorf("sandbox loopback = %v (%s), want allow", v, why)
	}
}

// TestDenyListWarnsAboutShadowedInfrastructure: denying your own resolver is
// legal and nearly always a mistake, and its symptom ("DNS is broken") points
// nowhere near the cause. The policy must say so.
func TestDenyListWarnsAboutShadowedInfrastructure(t *testing.T) {
	p, err := Compile(Input{
		AllowCIDRs: prefixes(t, "10.1.2.0/24"),
		AllowPorts: []uint16{443},
		Resolvers:  []netip.AddrPort{netip.MustParseAddrPort("10.0.0.53:53")},
		Brokers:    []netip.AddrPort{netip.MustParseAddrPort("10.7.0.2:8118")},
		DenyCIDRs:  prefixes(t, "10.0.0.0/8"),
	})
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	joined := strings.Join(p.Warnings, "\n")
	for _, want := range []string{"10.1.2.0/24", "10.0.0.53:53", "10.7.0.2:8118"} {
		if !strings.Contains(joined, want) {
			t.Errorf("warnings do not name the shadowed %s:\n%s", want, joined)
		}
	}
}

// TestDenyListRendersIntoNftables: the deny rules reach the bridge chain as
// drops that precede every accept, with the operator-facing comment.
func TestDenyListRendersIntoNftables(t *testing.T) {
	p, err := Compile(Input{
		AllowPublicInternet: true,
		AllowAllPorts:       true,
		Resolvers:           []netip.AddrPort{netip.MustParseAddrPort("1.1.1.1:53")},
		DenyCIDRs:           prefixes(t, "203.0.113.0/24"),
	})
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	script, err := RenderNftables(p, NftablesOptions{Table: "cloop_sbx_test", Bridge: "br-test"})
	if err != nil {
		t.Fatalf("RenderNftables: %v", err)
	}
	forward := script[strings.Index(script, "chain forward"):strings.Index(script, "chain input")]
	deny := strings.Index(forward, "203.0.113.0/24")
	if deny < 0 {
		t.Fatalf("the denied range is not in the forward chain:\n%s", forward)
	}
	if !strings.Contains(forward[deny:], "drop") || !strings.Contains(forward, "operator deny list") {
		t.Errorf("the denied range is not rendered as a commented drop:\n%s", forward)
	}
	for _, accept := range []string{"1.1.1.1", "0.0.0.0/0"} {
		if i := strings.Index(forward, accept); i >= 0 && i < deny {
			t.Errorf("allow for %s precedes the deny rule, so the deny would not bite:\n%s", accept, forward)
		}
	}
}

// TestDenyListInNetworkPolicy: a NetworkPolicy has no deny rule, so a denied
// range must be carved out of every allow that covers it and an allow a deny
// swallows whole must vanish.
func TestDenyListInNetworkPolicy(t *testing.T) {
	p, err := Compile(Input{
		AllowPublicInternet: true,
		AllowAllPorts:       true,
		AllowCIDRs:          prefixes(t, "10.8.0.0/16", "10.9.1.0/24"),
		DenyCIDRs:           prefixes(t, "10.8.5.0/24", "10.9.0.0/16", "198.51.100.0/24"),
	})
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	np, err := RenderNetworkPolicy(p, NetworkPolicyOptions{
		Name: "t", Namespace: "ns", PodSelector: map[string]string{"a": "b"},
	})
	if err != nil {
		t.Fatalf("RenderNetworkPolicy: %v", err)
	}
	blocks := map[string][]string{}
	for _, rule := range np.Spec.Egress {
		for _, peer := range rule.To {
			if peer.IPBlock != nil {
				blocks[peer.IPBlock.CIDR] = peer.IPBlock.Except
			}
		}
	}
	if _, ok := blocks["10.9.1.0/24"]; ok {
		t.Error("an allow the deny list covers entirely is still rendered as a peer")
	}
	if ex := blocks["10.8.0.0/16"]; !contains(ex, "10.8.5.0/24") {
		t.Errorf("10.8.0.0/16 excepts = %v, want the denied 10.8.5.0/24 carved out", ex)
	}
	v4 := blocks["0.0.0.0/0"]
	if !contains(v4, "198.51.100.0/24") {
		t.Errorf("0.0.0.0/0 excepts = %v, want the denied public range carved out", v4)
	}
	if contains(v4, "10.9.0.0/16") {
		t.Errorf("0.0.0.0/0 excepts = %v repeat a range already inside 10.0.0.0/8", v4)
	}
	// And the agreement with Evaluate that the package promises.
	for _, a := range []string{"10.8.5.1", "198.51.100.9", "10.9.1.5"} {
		if v, _ := p.Evaluate(addr(t, a), 443, ProtoTCP); v != VerdictDrop {
			t.Errorf("Evaluate(%s) = %v, want drop", a, v)
		}
	}
}

// TestNetworkPolicyWithoutDenyListIsUnchanged pins the byte-compatibility
// promise mergeExcepts makes: no deny list, same excepts as before.
func TestNetworkPolicyWithoutDenyListIsUnchanged(t *testing.T) {
	p, err := Compile(Input{AllowPublicInternet: true, AllowAllPorts: true})
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	np, err := RenderNetworkPolicy(p, NetworkPolicyOptions{
		Name: "t", Namespace: "ns", PodSelector: map[string]string{"a": "b"},
	})
	if err != nil {
		t.Fatalf("RenderNetworkPolicy: %v", err)
	}
	want := exceptSets(p).v4
	for _, rule := range np.Spec.Egress {
		for _, peer := range rule.To {
			if peer.IPBlock != nil && peer.IPBlock.CIDR == "0.0.0.0/0" {
				if strings.Join(peer.IPBlock.Except, ",") != strings.Join(want, ",") {
					t.Errorf("excepts changed without a deny list:\n got %v\nwant %v", peer.IPBlock.Except, want)
				}
				return
			}
		}
	}
	t.Fatal("no 0.0.0.0/0 peer rendered")
}

func contains(ss []string, want string) bool {
	for _, s := range ss {
		if s == want {
			return true
		}
	}
	return false
}
