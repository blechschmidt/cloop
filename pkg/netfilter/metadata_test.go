package netfilter

// metadata_test.go pins what Task 20397 changed in the compiler: an allowed
// range that contains a cloud metadata service does not open it, in the
// ordered policy, in the rendered nftables ruleset and in the NetworkPolicy,
// and the translation prefixes are not waived by an allow either.

import (
	"math/rand"
	"net/netip"
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/pkg/cloudmeta"
)

// ruleIndex is the position of the first rule matching pred, or -1.
func ruleIndex(p Policy, pred func(Rule) bool) int {
	for i, r := range p.Rules {
		if pred(r) {
			return i
		}
	}
	return -1
}

// TestAContainingAllowDoesNotOpenTheServices: the defence in depth for a rule
// set stored before the containment rule. 169.254.0.0/16 opens link-local on
// its port and none of the six metadata services inside it, and each is
// dropped by a rule ahead of the allow.
func TestAContainingAllowDoesNotOpenTheServices(t *testing.T) {
	p := mustCompilePolicy(t, Input{AllowCIDRs: prefixes(t, "169.254.0.0/16"), AllowPorts: []uint16{80}})
	allow := ruleIndex(p, func(r Rule) bool { return r.Verdict == VerdictAllow && r.Prefix.String() == "169.254.0.0/16" })
	if allow < 0 {
		t.Fatalf("no allow for the granted range: %v", p.Rules)
	}
	if !strings.Contains(p.Rules[allow].Reason, "waives link-local") {
		t.Errorf("the allow says it waives %q; the services inside it are not waived", p.Rules[allow].Reason)
	}
	inside := cloudmeta.Within(netip.MustParsePrefix("169.254.0.0/16"))
	if len(inside) != 6 {
		t.Fatalf("the table has %d services in 169.254.0.0/16, this test expects 6", len(inside))
	}
	for _, s := range inside {
		v, why := p.Evaluate(s.Addr, 80, ProtoTCP)
		if v != VerdictDrop || !strings.Contains(why, s.Addr.String()) {
			t.Errorf("%s:80 = %v (%s), want a drop naming the service", s.Addr, v, why)
		}
		carve := ruleIndex(p, func(r Rule) bool { return r.Verdict == VerdictDrop && r.Prefix == s.Prefix() })
		if carve < 0 || carve > allow || !p.Rules[carve].Carve {
			t.Errorf("%s is dropped by rule %d, want a carve ahead of the allow at %d", s.Addr, carve, allow)
		}
	}
	if v, why := p.Evaluate(netip.MustParseAddr("169.254.10.1"), 80, ProtoTCP); v != VerdictAllow {
		t.Errorf("the rest of the range must stay open: 169.254.10.1:80 = %v (%s)", v, why)
	}
	if w := strings.Join(p.Warnings, " "); !strings.Contains(w, "169.254.169.254") || !strings.Contains(w, "keeps them closed") {
		t.Errorf("the policy does not say what it kept closed: %v", p.Warnings)
	}
}

// TestNamingAServiceOpensThatServiceOnly: the one explicit way in, and it
// opens exactly the address named.
func TestNamingAServiceOpensThatServiceOnly(t *testing.T) {
	p := mustCompilePolicy(t, Input{AllowCIDRs: prefixes(t, "169.254.0.0/16", "169.254.169.254/32"),
		AllowPorts: []uint16{80}})
	if v, why := p.Evaluate(netip.MustParseAddr("169.254.169.254"), 80, ProtoTCP); v != VerdictAllow {
		t.Errorf("the named service is closed: %v (%s)", v, why)
	}
	if v, _ := p.Evaluate(netip.MustParseAddr("169.254.169.254"), 22, ProtoTCP); v != VerdictDrop {
		t.Error("naming the service opened it on a port the grant does not name")
	}
	for _, a := range []string{"169.254.169.252", "169.254.170.2"} {
		if v, _ := p.Evaluate(netip.MustParseAddr(a), 80, ProtoTCP); v != VerdictDrop {
			t.Errorf("%s opened though only 169.254.169.254 was named", a)
		}
	}
}

// TestADeniedServiceIsNotCarvedTwice: the deny list already drops it ahead of
// every allow, so a carve would be a second line saying the same thing.
func TestADeniedServiceIsNotCarvedTwice(t *testing.T) {
	p := mustCompilePolicy(t, Input{AllowCIDRs: prefixes(t, "100.64.0.0/10"), DenyCIDRs: prefixes(t, "100.100.100.200/32"),
		AllowPorts: []uint16{443}})
	n := 0
	for _, r := range p.Rules {
		if r.Prefix.String() == "100.100.100.200/32" && r.Verdict == VerdictDrop && r.Carve {
			n++
		}
	}
	if n != 0 {
		t.Errorf("a denied service was carved as well: %v", p.Rules)
	}
	if v, _ := p.Evaluate(netip.MustParseAddr("100.100.100.200"), 443, ProtoTCP); v != VerdictDrop {
		t.Error("the denied service is reachable")
	}
}

// TestCarvesWorkInEveryFamilyAndSpace: the three the task names, each inside a
// range the UI used to call by another name.
func TestCarvesWorkInEveryFamilyAndSpace(t *testing.T) {
	cases := []struct{ allow, service, neighbour string }{
		{"fc00::/7", "fd00:ec2::254", "fd12::1"},
		{"100.64.0.0/10", "100.100.100.200", "100.100.100.201"},
		{"168.63.0.0/16", "168.63.129.16", "168.63.129.17"},
		{"fe80::/10", "fe80::a9fe:a9fe", "fe80::1"},
		{"::ffff:169.254.0.0/112", "169.254.169.254", "169.254.1.1"},
	}
	for _, c := range cases {
		p := mustCompilePolicy(t, Input{AllowCIDRs: prefixes(t, c.allow), AllowPorts: []uint16{443}})
		if v, why := p.Evaluate(netip.MustParseAddr(c.service), 443, ProtoTCP); v != VerdictDrop {
			t.Errorf("%s under %s = %v (%s), want drop", c.service, c.allow, v, why)
		}
		if v, why := p.Evaluate(netip.MustParseAddr(c.neighbour), 443, ProtoTCP); v != VerdictAllow {
			t.Errorf("%s under %s = %v (%s), want allow", c.neighbour, c.allow, v, why)
		}
	}
}

// TestAResolverAtAMetadataAddressKeepsItsPort: a Google Cloud VM resolves
// through its metadata server, 169.254.169.254:53. The carve sits after the
// infrastructure allows, so DNS still works while the containing range does
// not open the server's HTTP port.
func TestAResolverAtAMetadataAddressKeepsItsPort(t *testing.T) {
	p := mustCompilePolicy(t, Input{AllowCIDRs: prefixes(t, "169.254.0.0/16"), AllowPorts: []uint16{53, 80},
		Resolvers: []netip.AddrPort{netip.MustParseAddrPort("169.254.169.254:53")}})
	m := netip.MustParseAddr("169.254.169.254")
	for _, proto := range []Proto{ProtoUDP, ProtoTCP} {
		if v, why := p.Evaluate(m, 53, proto); v != VerdictAllow {
			t.Errorf("the resolver over %v = %v (%s), want allow", proto, v, why)
		}
	}
	if v, why := p.Evaluate(m, 80, ProtoTCP); v != VerdictDrop {
		t.Errorf("the metadata server's HTTP port = %v (%s), want drop", v, why)
	}
}

// TestTranslationPrefixesAreNeverWaived: a granted CIDR inside a translation
// prefix used to waive its drop wholesale, which with a NAT64 gateway on the
// path is every private range and the metadata service. The proxy never let a
// v6 CIDR waive an embedded address; now neither does the filter, and it says
// so. Infrastructure on a translated address still works.
func TestTranslationPrefixesAreNeverWaived(t *testing.T) {
	p := mustCompilePolicy(t, Input{AllowCIDRs: prefixes(t, "64:ff9b::/96", "2000::/3"), AllowPorts: []uint16{443},
		Resolvers: []netip.AddrPort{netip.MustParseAddrPort("[64:ff9b::808:808]:53")}})
	for _, a := range []string{"64:ff9b::a9fe:a9fe", "64:ff9b::a00:1", "64:ff9b::808:808", "2002:a9fe:a9fe::1"} {
		if v, why := p.Evaluate(netip.MustParseAddr(a), 443, ProtoTCP); v != VerdictDrop {
			t.Errorf("%s:443 = %v (%s), want drop", a, v, why)
		}
	}
	if v, why := p.Evaluate(netip.MustParseAddr("2606:4700::1111"), 443, ProtoTCP); v != VerdictAllow {
		t.Errorf("global unicast outside 2002::/16 = %v (%s), want allow", v, why)
	}
	if v, why := p.Evaluate(netip.MustParseAddr("64:ff9b::808:808"), 53, ProtoUDP); v != VerdictAllow {
		t.Errorf("a resolver on a translated address = %v (%s), want allow", v, why)
	}
	w := strings.Join(p.Warnings, " ")
	for _, want := range []string{"64:ff9b::/96 overlaps 64:ff9b::/96", "2000::/3 overlaps 2002::/16"} {
		if !strings.Contains(w, want) {
			t.Errorf("warnings %q do not say %q", w, want)
		}
	}
}

// TestRenderedRulesetDropsTheServiceAheadOfTheAllow is the ordering in the
// text nft(8) is given, in both hooks of the host-side form and in the
// in-namespace form: a drop for the service on a line before the accept for
// the range that contains it.
func TestRenderedRulesetDropsTheServiceAheadOfTheAllow(t *testing.T) {
	p := mustCompilePolicy(t, Input{AllowCIDRs: prefixes(t, "169.254.0.0/16", "fc00::/7"), AllowPorts: []uint16{80}})
	for name, opts := range map[string]NftablesOptions{
		"bridge":    {Table: "cloop_sbx", Bridge: "br-abc123"},
		"namespace": {Table: "cloop_sbx"},
	} {
		t.Run(name, func(t *testing.T) {
			out := mustRenderNft(t, p, opts)
			chains := strings.Split(out, "\tchain ")[1:]
			if name == "bridge" && len(chains) != 2 {
				t.Fatalf("want the forward and input chains, got %d", len(chains))
			}
			for _, chain := range chains {
				if strings.HasPrefix(chain, "input") && name == "namespace" {
					continue // the in-namespace input chain carries no destination rules
				}
				if strings.HasPrefix(chain, "forward") && name == "namespace" {
					continue
				}
				for _, pair := range [][2]string{
					{"ip daddr 169.254.169.254/32 counter drop", "ip daddr 169.254.0.0/16 tcp dport 80 counter accept"},
					{"ip daddr 169.254.0.23/32 counter drop", "ip daddr 169.254.0.0/16 tcp dport 80 counter accept"},
					{"ip6 daddr fd00:ec2::254/128 counter drop", "ip6 daddr fc00::/7 tcp dport 80 counter accept"},
				} {
					drop, accept := strings.Index(chain, pair[0]), strings.Index(chain, pair[1])
					if drop < 0 || accept < 0 || drop > accept {
						t.Errorf("%s chain: %q at %d, %q at %d — the drop must come first:\n%s",
							strings.SplitN(chain, " ", 2)[0], pair[0], drop, pair[1], accept, chain)
					}
				}
				if !strings.Contains(chain, "inside an allowed range that does not name it") {
					t.Errorf("the carve's comment does not say why it is there:\n%s", chain)
				}
			}
		})
	}
	if !strings.Contains(mustRenderNft(t, p, NftablesOptions{Table: "cloop_sbx"}), "# WARNING: 169.254.0.0/16 contains 6") {
		t.Error("the ruleset's header does not warn about the carved services")
	}
}

// npAllows evaluates a rendered NetworkPolicy's ipBlock peers for one packet:
// a union of rules, each a cross product of its peers and its ports.
func npAllows(np *NetworkPolicy, addr netip.Addr, port uint16, proto Proto) bool {
	addr = addr.Unmap()
	name := map[Proto]string{ProtoTCP: "TCP", ProtoUDP: "UDP"}[proto]
	for _, r := range np.Spec.Egress {
		portOK := len(r.Ports) == 0
		for _, p := range r.Ports {
			if p.Protocol == name && p.Port != nil && *p.Port == int(port) {
				portOK = true
			}
		}
		if !portOK {
			continue
		}
		for _, peer := range r.To {
			if peer.IPBlock == nil {
				continue
			}
			cidr := netip.MustParsePrefix(peer.IPBlock.CIDR)
			if cidr.Addr().Is4() != addr.Is4() || !cidr.Contains(addr) {
				continue
			}
			excepted := false
			for _, e := range peer.IPBlock.Except {
				if ep := netip.MustParsePrefix(e); ep.Contains(addr) {
					excepted = true
				}
			}
			if !excepted {
				return true
			}
		}
	}
	return false
}

// TestNetworkPolicyExceptsWhatTheOrderedPolicyCarves: the unordered form has
// no drop to put ahead of the allow, so the carve becomes an except on the
// ipBlock that contains it — and only on allows after it, so a resolver that
// is itself a metadata server keeps its port.
func TestNetworkPolicyExceptsWhatTheOrderedPolicyCarves(t *testing.T) {
	p := mustCompilePolicy(t, Input{AllowCIDRs: prefixes(t, "169.254.0.0/16"), AllowPorts: []uint16{80},
		Resolvers: []netip.AddrPort{netip.MustParseAddrPort("169.254.169.254:53")}, AllowPublicInternet: true})
	np := mustRenderNP(t, p, npOpts())
	block := npFindIPBlock(np, "169.254.0.0/16")
	if block == nil {
		t.Fatalf("no peer for the granted range: %+v", npIPBlocks(np))
	}
	for _, s := range cloudmeta.Within(netip.MustParsePrefix("169.254.0.0/16")) {
		if !npHasString(block.Except, s.Prefix().String()) {
			t.Errorf("the granted range's peer does not except %s: %v", s.Prefix(), block.Except)
		}
	}
	if r := npFindIPBlock(np, "169.254.169.254/32"); r == nil || len(r.Except) != 0 {
		t.Errorf("the resolver's peer is missing or carved: %+v", r)
	}
	m := netip.MustParseAddr("169.254.169.254")
	if !npAllows(np, m, 53, ProtoUDP) || npAllows(np, m, 80, ProtoTCP) {
		t.Errorf("the NetworkPolicy reaches the metadata server: udp/53=%t tcp/80=%t, want true, false",
			npAllows(np, m, 53, ProtoUDP), npAllows(np, m, 80, ProtoTCP))
	}
}

// TestNetworkPolicyKeepsAPublicServiceOutOfTheWidePeer: Azure's WireServer is
// a public address and Azure's DNS resolver. Allowing it as a resolver must
// not take it out of the public peer's except — that would open it on the
// public ports, which the ordered policy drops.
func TestNetworkPolicyKeepsAPublicServiceOutOfTheWidePeer(t *testing.T) {
	p := mustCompilePolicy(t, Input{AllowPublicInternet: true, AllowPorts: []uint16{80, 443},
		Resolvers: []netip.AddrPort{netip.MustParseAddrPort("168.63.129.16:53")}})
	np := mustRenderNP(t, p, npOpts())
	wide := npFindIPBlock(np, "0.0.0.0/0")
	if wide == nil || !npHasString(wide.Except, "168.63.129.16/32") {
		t.Fatalf("the public peer does not except WireServer: %+v", wide)
	}
	ws := netip.MustParseAddr("168.63.129.16")
	if npAllows(np, ws, 80, ProtoTCP) || !npAllows(np, ws, 53, ProtoUDP) {
		t.Error("the NetworkPolicy opens WireServer on a public port, or closes the resolver")
	}
}

// TestNetworkPolicyDropsAPeerACarveCovers: a granted range inside a
// translation prefix reaches nothing in the ordered policy, and an ipBlock
// whose except is its own cidr is invalid — so it has no peer at all.
func TestNetworkPolicyDropsAPeerACarveCovers(t *testing.T) {
	p := mustCompilePolicy(t, Input{AllowCIDRs: prefixes(t, "64:ff9b::/96", "2001:db8::/32"),
		AllowPorts: []uint16{443}, AllowPublicInternet: true})
	np := mustRenderNP(t, p, npOpts())
	if npFindIPBlock(np, "64:ff9b::/96") != nil {
		t.Errorf("a range the translation drop covers whole still has a peer: %+v", npIPBlocks(np))
	}
	if wide := npFindIPBlock(np, "::/0"); wide == nil || !npHasString(wide.Except, "64:ff9b::/96") {
		t.Errorf("granting 64:ff9b::/96 took it out of the public peer's except: %+v", wide)
	}
}

// TestNetworkPolicyAgreesWithTheOrderedPolicy: for random authorisations that
// contain metadata services, translation prefixes, resolvers on metadata
// addresses and deny lists, the rendered object and Evaluate give every probe
// the same answer. The NetworkPolicy has no order, so this is the test that
// the set arithmetic standing in for it is right.
func TestNetworkPolicyAgreesWithTheOrderedPolicy(t *testing.T) {
	ranges := []string{"169.254.0.0/16", "169.254.169.0/24", "169.254.169.254/32", "100.64.0.0/10",
		"168.63.0.0/16", "10.8.0.0/24", "fc00::/7", "fd00:ec2::254/128", "64:ff9b::/96", "2000::/3",
		"140.82.112.0/20", "0.0.0.0/1"}
	resolvers := []string{"169.254.169.254:53", "168.63.129.16:53", "1.1.1.1:53", "[fd00:ec2::254]:53"}
	var probes []netip.Addr
	for _, s := range cloudmeta.Services() {
		probes = append(probes, s.Addr, s.Addr.Next(), s.Addr.Prev())
	}
	for _, a := range []string{"169.254.10.1", "10.8.0.5", "10.9.0.1", "8.8.8.8", "140.82.113.1", "100.65.0.1",
		"fd12::1", "64:ff9b::808:808", "2606:4700::1111", "2002:a9fe:a9fe::1", "1.1.1.1", "168.63.1.1"} {
		probes = append(probes, netip.MustParseAddr(a))
	}
	rng := rand.New(rand.NewSource(20397))
	for i := 0; i < 300; i++ {
		var in Input
		for n := rng.Intn(3); n >= 0; n-- {
			in.AllowCIDRs = append(in.AllowCIDRs, netip.MustParsePrefix(ranges[rng.Intn(len(ranges))]))
		}
		if rng.Intn(3) == 0 {
			in.DenyCIDRs = append(in.DenyCIDRs, netip.MustParsePrefix(ranges[rng.Intn(len(ranges))]))
		}
		if rng.Intn(2) == 0 {
			in.Resolvers = append(in.Resolvers, netip.MustParseAddrPort(resolvers[rng.Intn(len(resolvers))]))
		}
		in.AllowPublicInternet = rng.Intn(2) == 0
		in.AllowPorts = []uint16{53, 80, 443}[:1+rng.Intn(3)]
		p, err := Compile(in)
		if err != nil {
			t.Fatalf("Compile(%+v): %v", in, err)
		}
		np := mustRenderNP(t, p, npOpts())
		wire := p.WireOnly()
		for _, a := range probes {
			for _, port := range []uint16{53, 80, 443} {
				for _, proto := range []Proto{ProtoTCP, ProtoUDP} {
					v, why := wire.Evaluate(a, port, proto)
					if got := npAllows(np, a, port, proto); got != (v == VerdictAllow) {
						t.Fatalf("%v %s:%d: the ordered policy says %v (%s), the NetworkPolicy %t\ninput %+v\n%v",
							proto, a, port, v, why, got, in, npIPBlocks(np))
					}
				}
			}
		}
	}
}
