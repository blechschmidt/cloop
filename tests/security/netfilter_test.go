package security

// Guarantee 9: a sandbox's reach is bounded at the IP layer, not only at the
// HTTP layer.
//
// Every other egress control cloop has binds a cooperating workload. The
// broker is a forward proxy: it enforces hosts, methods and quotas, and it
// only ever sees traffic a harness chose to send it. A harness that opens a
// raw socket — or speaks SSH, or DNS, or QUIC, or anything that is not HTTP
// through $HTTP_PROXY — was, until this guarantee, entirely unconstrained.
// The threat is not hypothetical: the workload is an LLM-driven agent running
// attacker-influenced code from a git repository, which is the single least
// trustworthy thing in the system.
//
// The properties below are about the *compiled policy*, driven through the
// real compiler and the real renderers, so they hold wherever that policy is
// enforced. Two of them are the shape of a bug that was actually present and
// is now fixed; those are marked.
//
// What none of this can check is whether the kernel or the CNI honours what
// was installed. `nft -f` either commits or fails, so the container path is
// verifiable; a Kubernetes NetworkPolicy is inert unless the cluster runs a
// CNI that implements it, and the driver reports that as a preflight warning
// rather than pretending otherwise.

import (
	"encoding/json"
	"net/netip"
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/pkg/egressbroker"
	"github.com/blechschmidt/cloop/pkg/executor/container"
	"github.com/blechschmidt/cloop/pkg/netfilter"
	"github.com/blechschmidt/cloop/pkg/secretbroker"
)

// blockedSamples are one address from each range the proxy refuses. They are
// what a compromised sandbox would reach for: the metadata endpoint holds the
// host's cloud credentials, RFC1918 is the operator's internal network, and
// loopback is whatever the hub itself is listening on.
var blockedSamples = []string{
	"169.254.169.254", // cloud metadata — the crown jewels
	"169.254.0.1",     // link-local
	"10.0.0.1",        // RFC1918
	"172.16.0.1",      // RFC1918
	"192.168.1.1",     // RFC1918
	"100.64.0.1",      // CGNAT — cloud infrastructure the tenant does not own
	"224.0.0.1",       // multicast
	"fd00::1",         // ULA
	"fe80::1",         // link-local
	"64:ff9b::a00:1",  // 10.0.0.1 wearing a NAT64 disguise
	"2002:a00:1::",    // 10.0.0.1 wearing a 6to4 disguise
	"::a00:1",         // 10.0.0.1 as a v4-compatible address
}

// TestNoCompiledPolicyReachesBlockedSpaceByAccident: the block set holds
// against every authorisation shape cloop can produce, not just the one the
// unit tests happen to build. Only an explicit CIDR naming the range waives
// it, which is the same rule the proxy applies.
func TestNoCompiledPolicyReachesBlockedSpaceByAccident(t *testing.T) {
	shapes := map[string]netfilter.Input{
		"isolated": {},
		"brokered": {
			Brokers: []netip.AddrPort{netip.MustParseAddrPort("10.7.0.2:8118")},
		},
		"public internet": {
			AllowPublicInternet: true,
			AllowPorts:          []uint16{80, 443},
		},
		"wildcard host allowlist": {
			AllowPublicInternet: true,
			AllowPorts:          []uint16{443},
			HostPatterns:        []string{"*"},
		},
		"an unrelated private grant": {
			AllowCIDRs: []netip.Prefix{netip.MustParsePrefix("10.99.0.0/24")},
			AllowPorts: []uint16{443},
		},
		"everything at once": {
			AllowCIDRs:          []netip.Prefix{netip.MustParsePrefix("10.99.0.0/24")},
			AllowPorts:          []uint16{443},
			AllowPublicInternet: true,
			HostPatterns:        []string{"*.github.com"},
			Brokers:             []netip.AddrPort{netip.MustParseAddrPort("10.7.0.2:8118")},
			Resolvers:           []netip.AddrPort{netip.MustParseAddrPort("10.7.0.10:53")},
		},
	}

	for name, in := range shapes {
		t.Run(name, func(t *testing.T) {
			p, err := netfilter.Compile(in)
			if err != nil {
				t.Fatalf("Compile: %v", err)
			}
			wire := p.WireOnly()
			for _, s := range blockedSamples {
				a := netip.MustParseAddr(s)
				for _, port := range []uint16{22, 80, 443, 6443, 8118} {
					if v, why := wire.Evaluate(a, port, netfilter.ProtoTCP); v != netfilter.VerdictDrop {
						t.Errorf("%s:%d reachable under %q (%s)", s, port, name, why)
					}
				}
			}
		})
	}
}

// TestOnlyAnExplicitCIDRWaivesTheBlockSet: the waiver exists, it is narrow,
// and it is the same one the proxy honours. An operator who needs the
// metadata service has to write the address out; nothing else grants it.
func TestOnlyAnExplicitCIDRWaivesTheBlockSet(t *testing.T) {
	p, err := netfilter.Compile(netfilter.Input{
		AllowCIDRs: []netip.Prefix{netip.MustParsePrefix("169.254.169.254/32")},
		AllowPorts: []uint16{80},
	})
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	wire := p.WireOnly()
	meta := netip.MustParseAddr("169.254.169.254")

	if v, why := wire.Evaluate(meta, 80, netfilter.ProtoTCP); v != netfilter.VerdictAllow {
		t.Fatalf("an explicit /32 for the metadata service was refused: %v (%s)", v, why)
	}
	// And it bought that address on that port, and nothing adjacent.
	if v, _ := wire.Evaluate(meta, 443, netfilter.ProtoTCP); v != netfilter.VerdictDrop {
		t.Error("the waiver leaked to another port")
	}
	if v, _ := wire.Evaluate(netip.MustParseAddr("169.254.169.253"), 80, netfilter.ProtoTCP); v != netfilter.VerdictDrop {
		t.Error("the waiver leaked to a neighbouring address")
	}
	if v, _ := wire.Evaluate(netip.MustParseAddr("10.0.0.1"), 80, netfilter.ProtoTCP); v != netfilter.VerdictDrop {
		t.Error("the waiver leaked to an unrelated blocked range")
	}
}

// TestGrantsThatWouldRemoveTheBlockSetAreRefused is a regression test for a
// real vulnerability.
//
// `cloop egress grant --cidrs 0.0.0.0/0` was accepted, and because an
// explicit CIDR waives the block set, it waived all of it — cloud metadata,
// loopback, the operator's entire internal network — from one flag. The
// grant field's own documentation said this could not happen ("there is no
// blanket allow_private flag... 'let this sandbox reach the metadata service'
// should be a sentence an operator has to write out as 169.254.169.254/32").
// A /0 was that checkbox, spelled differently. So was 169.254.0.0/16.
//
// Both layers refuse them now, and both have to: the broker because it issues
// the grant, the compiler because it renders the filter.
func TestGrantsThatWouldRemoveTheBlockSetAreRefused(t *testing.T) {
	for _, cidr := range []string{"0.0.0.0/0", "::/0", "169.254.0.0/16", "169.254.128.0/17"} {
		t.Run(cidr, func(t *testing.T) {
			g := egressbroker.Grant{
				ID:      "egress_conformance",
				Subject: secretbroker.Subject{Type: secretbroker.SubjectProject, Value: "/srv/app"},
				CIDRs:   []string{cidr},
				Ports:   []int{443},
			}
			if err := g.Validate(); err == nil {
				t.Errorf("the broker accepted --cidrs %s, which waives the block set wholesale", cidr)
			}

			// The compiler refuses the /0 forms outright. The
			// metadata-containing prefixes it does compile, but only into a
			// filter the broker will never be able to hand it.
			if strings.HasSuffix(cidr, "/0") {
				_, err := netfilter.Compile(netfilter.Input{
					AllowCIDRs: []netip.Prefix{netip.MustParsePrefix(cidr)},
					AllowPorts: []uint16{443},
				})
				if err == nil {
					t.Errorf("the compiler accepted %s as an allowlist entry", cidr)
				}
			}
		})
	}
}

// TestHostSideFilterCoversHostBoundServices is a regression test for the
// second real vulnerability found while building this.
//
// The first host-side ruleset had a forward chain and nothing else. That
// filters the Internet and leaves the host itself completely open: the
// routing decision picks the hook, and a destination that belongs to the host
// — the bridge gateway, or anything bound on any of its interfaces — takes
// the input hook. So a sandbox under a policy that dropped 172.16.0.0/12
// could still open a connection to a service on the host's own 172.x bridge
// address. Verified against a real container before and after the fix.
//
// Both chains must carry the whole block set, because "which hook does this
// destination take" is a fact about the host's routing table and not a
// security boundary.
func TestHostSideFilterCoversHostBoundServices(t *testing.T) {
	p, err := netfilter.Compile(netfilter.Input{
		AllowCIDRs: []netip.Prefix{netip.MustParsePrefix("1.1.1.1/32")},
		AllowPorts: []uint16{443},
	})
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	script, err := netfilter.RenderNftables(p, netfilter.NftablesOptions{
		Table: "cloop_conformance", Bridge: "br-abc123",
	})
	if err != nil {
		t.Fatalf("RenderNftables: %v", err)
	}

	for _, hook := range []string{"hook forward", "hook input"} {
		if !strings.Contains(script, hook) {
			t.Fatalf("the host-side ruleset has no %s chain — "+
				"a sandbox would reach every service bound on the host:\n%s", hook, script)
		}
	}
	// Count the drops rather than merely finding them: one occurrence means
	// only one chain carries the block set, which is the bug.
	for _, blocked := range []string{"172.16.0.0/12", "10.0.0.0/8", "169.254.169.254/32"} {
		if n := strings.Count(script, blocked+" counter drop"); n < 2 {
			t.Errorf("%s is dropped in %d chain(s), want 2 — the other hook is unfiltered", blocked, n)
		}
	}
	// And the chain policy stays accept: a drop policy on a shared hook
	// would take the host's own traffic down with the sandbox's.
	if strings.Contains(script, "policy drop;") {
		t.Errorf("the host-side ruleset uses a drop policy on a shared hook:\n%s", script)
	}
}

// TestBothBackendsRefuseTheSameDestinations: one compiler, two renderers, and
// a guarantee that does not depend on which executor a task lands on.
//
// A Kubernetes NetworkPolicy has no deny rule, so the ordered form's drops
// become ipBlock excepts. That translation is where the two backends could
// silently disagree, and a sandbox that is confined on the container executor
// and open on the Kubernetes one is worse than one that is open on both —
// because nobody would look.
func TestBothBackendsRefuseTheSameDestinations(t *testing.T) {
	p, err := netfilter.Compile(netfilter.Input{
		AllowPublicInternet: true,
		AllowPorts:          []uint16{443},
		HostPatterns:        []string{"*.github.com"},
	})
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}

	np, err := netfilter.RenderNetworkPolicy(p, netfilter.NetworkPolicyOptions{
		Name:        "cloop-conformance",
		Namespace:   "cloop",
		PodSelector: map[string]string{"cloop.dev/handle-id": "h1"},
	})
	if err != nil {
		t.Fatalf("RenderNetworkPolicy: %v", err)
	}
	encoded, err := json.Marshal(np)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	// Every blocked v4 range the ordered policy drops has to appear as an
	// except on the wide allow, or the NetworkPolicy grants what the
	// nftables ruleset refuses.
	for _, blocked := range []netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/8"),
		netip.MustParsePrefix("172.16.0.0/12"),
		netip.MustParsePrefix("192.168.0.0/16"),
		netip.MustParsePrefix("169.254.169.254/32"),
		netip.MustParsePrefix("169.254.0.0/16"),
		netip.MustParsePrefix("100.64.0.0/10"),
		netip.MustParsePrefix("127.0.0.0/8"),
	} {
		if !exceptedSomewhere(np, blocked.String()) {
			t.Errorf("%s is dropped by the filter but not excepted by the NetworkPolicy:\n%s",
				blocked, encoded)
		}
	}

	// Inbound is denied by naming the policy type with no rules. Omitting
	// the type would leave it governed by nothing at all.
	var hasIngressType bool
	for _, pt := range np.Spec.PolicyTypes {
		if pt == "Ingress" {
			hasIngressType = true
		}
	}
	if !hasIngressType || len(np.Spec.Ingress) != 0 {
		t.Errorf("inbound is not denied: policyTypes=%v ingress=%d",
			np.Spec.PolicyTypes, len(np.Spec.Ingress))
	}

	// A selector that matched nothing specific would firewall every Pod in
	// the namespace, including other tenants'.
	if len(np.Spec.PodSelector.MatchLabels) == 0 {
		t.Error("the NetworkPolicy selects every Pod in the namespace")
	}
}

// exceptedSomewhere reports whether a prefix appears in any peer's except.
func exceptedSomewhere(np *netfilter.NetworkPolicy, cidr string) bool {
	for _, rule := range np.Spec.Egress {
		for _, peer := range rule.To {
			if peer.IPBlock == nil {
				continue
			}
			for _, e := range peer.IPBlock.Except {
				if e == cidr {
					return true
				}
			}
		}
	}
	return false
}

// TestContainerEgressFilterCannotBeEnabledIntoAHole: the driver's
// configuration surface is the one an operator touches, so the shapes that
// would produce a filter weaker than it reads have to be refused at
// configuration time rather than discovered in production.
func TestContainerEgressFilterCannotBeEnabledIntoAHole(t *testing.T) {
	cases := map[string]container.EgressFilter{
		"a /0 in the allowlist": {
			Enabled: true, AllowCIDRs: []string{"0.0.0.0/0"}, AllowPorts: []int{443},
		},
		"destinations with no port bound": {
			Enabled: true, AllowCIDRs: []string{"10.8.0.0/24"},
		},
		"the public Internet with no port bound": {
			Enabled: true, AllowPublicInternet: true,
		},
		"a broker named by hostname": {
			Enabled: true, Broker: "proxy.internal:8118",
		},
		"enabled but allowing nothing": {
			Enabled: true,
		},
	}
	for name, f := range cases {
		if err := f.Validate(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}

	// And the shape that is correct stays accepted, so the guard above is
	// not passing by refusing everything.
	ok := container.EgressFilter{
		Enabled: true, AllowCIDRs: []string{"10.8.0.0/24"}, AllowPorts: []int{6443},
	}
	if err := ok.Validate(); err != nil {
		t.Errorf("a well-formed filter was refused: %v", err)
	}
}

// TestSandboxSpecCannotTurnTheFilterOff: .cloop/sandbox.yaml is the least
// trusted input in the system — it arrives by git pull. The egress filter is
// executor configuration, so no field in a repo-committed spec should reach
// it. This is the same one-directional property the rest of this file's
// sandbox tests assert, applied to the new knob.
func TestSandboxSpecCannotTurnTheFilterOff(t *testing.T) {
	filtered := container.Options{
		Network: container.NetworkBridge,
		EgressFilter: container.EgressFilter{
			Enabled: true, AllowCIDRs: []string{"10.8.0.0/24"}, AllowPorts: []int{6443},
		},
	}
	norm, err := filtered.Normalize()
	if err != nil {
		t.Fatalf("Normalize: %v", err)
	}
	if !norm.EgressFilter.Enabled {
		t.Fatal("Normalize turned the filter off")
	}
	// The only network knob a spec has is capabilities.network, and its
	// effect is DisableNetwork — which narrows to "no interfaces at all".
	// There is no spec field that widens, and none that names an executor's
	// EgressFilter. Guard the absence by shape: the sandbox package's
	// Spec must not carry anything that maps onto these fields.
	if got := len(norm.EgressFilter.AllowCIDRs); got != 1 {
		t.Fatalf("AllowCIDRs = %d, want 1", got)
	}
}
