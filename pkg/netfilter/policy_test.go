package netfilter

import (
	"net/netip"
	"strings"
	"testing"
)

// prefixes is a test helper: parse or fail.
func prefixes(t *testing.T, ss ...string) []netip.Prefix {
	t.Helper()
	out := make([]netip.Prefix, 0, len(ss))
	for _, s := range ss {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			t.Fatalf("parse prefix %q: %v", s, err)
		}
		out = append(out, p)
	}
	return out
}

func addr(t *testing.T, s string) netip.Addr {
	t.Helper()
	a, err := netip.ParseAddr(s)
	if err != nil {
		t.Fatalf("parse addr %q: %v", s, err)
	}
	return a
}

// TestCompileRefusesDestinationsWithoutPorts: an allow rule with no port
// restriction is a hole, and guessing 80/443 is not a decision a firewall
// compiler gets to make.
func TestCompileRefusesDestinationsWithoutPorts(t *testing.T) {
	for name, in := range map[string]Input{
		"cidr":     {AllowCIDRs: prefixes(t, "10.8.0.0/24")},
		"internet": {AllowPublicInternet: true},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Compile(in); err == nil {
				t.Fatal("Compile accepted destinations with no ports")
			}
		})
	}
}

// TestIsolatedPolicyDropsEverything: the zero Input is a sandbox with no
// egress, and every address has to fall through to the default deny.
func TestIsolatedPolicyDropsEverything(t *testing.T) {
	p, err := Compile(Input{})
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	if p.Mode != ModeIsolated {
		t.Fatalf("Mode = %v, want isolated", p.Mode)
	}
	for _, a := range []string{"8.8.8.8", "10.0.0.1", "169.254.169.254", "2606:4700::1111"} {
		if v, why := p.Evaluate(addr(t, a), 443, ProtoTCP); v != VerdictDrop {
			t.Errorf("Evaluate(%s) = %v (%s), want drop", a, v, why)
		}
	}
	// Loopback is the sandbox itself and must survive, or a harness that
	// binds a local port breaks in a way that looks nothing like egress.
	if v, _ := p.Evaluate(addr(t, "127.0.0.1"), 8080, ProtoTCP); v != VerdictAllow {
		t.Error("sandbox-local loopback must stay reachable in an isolated policy")
	}
}

// TestBrokeredPolicyAllowsOnlyTheBroker is the central claim of the brokered
// mode: the L3 filter and the L7 allowlist coincide because nothing but the
// proxy is addressable, so a workload that ignores $HTTP_PROXY reaches
// nothing at all.
func TestBrokeredPolicyAllowsOnlyTheBroker(t *testing.T) {
	broker := netip.MustParseAddrPort("10.7.0.2:8118")
	p, err := Compile(Input{Brokers: []netip.AddrPort{broker}})
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	if p.Mode != ModeBrokered {
		t.Fatalf("Mode = %v, want brokered", p.Mode)
	}
	if v, why := p.Evaluate(broker.Addr(), broker.Port(), ProtoTCP); v != VerdictAllow {
		t.Fatalf("broker endpoint = %v (%s), want allow", v, why)
	}
	// Same host, different port: the broker is an endpoint, not a subnet.
	if v, _ := p.Evaluate(broker.Addr(), 22, ProtoTCP); v != VerdictDrop {
		t.Error("a brokered policy must not open the broker host's other ports")
	}
	// Neighbours on the broker's own subnet stay unreachable.
	if v, _ := p.Evaluate(addr(t, "10.7.0.3"), 8118, ProtoTCP); v != VerdictDrop {
		t.Error("a brokered policy must not open the broker's subnet")
	}
	for _, a := range []string{"8.8.8.8", "169.254.169.254", "2606:4700::1111"} {
		if v, _ := p.Evaluate(addr(t, a), 443, ProtoTCP); v != VerdictDrop {
			t.Errorf("%s reachable under a brokered policy", a)
		}
	}
}

// TestGrantedCIDRWaivesOnlyItselfAndOnlyOnItsPorts: the waiver rule from
// egressbroker.CheckAddr, expressed as rule ordering. An explicit CIDR buys
// that prefix on those ports and nothing else.
func TestGrantedCIDRWaivesOnlyItselfAndOnlyOnItsPorts(t *testing.T) {
	p, err := Compile(Input{
		AllowCIDRs: prefixes(t, "10.8.0.0/24"),
		AllowPorts: []uint16{6443},
	})
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	if p.Mode != ModeFiltered {
		t.Fatalf("Mode = %v, want filtered", p.Mode)
	}
	cases := []struct {
		addr string
		port uint16
		want Verdict
		why  string
	}{
		{"10.8.0.5", 6443, VerdictAllow, "granted prefix on a granted port"},
		{"10.8.0.5", 22, VerdictDrop, "granted prefix, ungranted port"},
		{"10.9.0.5", 6443, VerdictDrop, "private, but outside the granted prefix"},
		{"169.254.169.254", 6443, VerdictDrop, "metadata is never waived by an unrelated grant"},
		{"8.8.8.8", 6443, VerdictDrop, "a CIDR grant does not open the Internet"},
	}
	for _, c := range cases {
		if v, reason := p.Evaluate(addr(t, c.addr), c.port, ProtoTCP); v != c.want {
			t.Errorf("%s:%d = %v (%s), want %v — %s", c.addr, c.port, v, reason, c.want, c.why)
		}
	}
}

// TestPublicInternetAllowNeverReachesTheBlockSet: the ordered form's whole
// point. The Internet allow is emitted after the drops, so opening "the
// Internet" does not open the metadata service.
func TestPublicInternetAllowNeverReachesTheBlockSet(t *testing.T) {
	p, err := Compile(Input{
		AllowPublicInternet: true,
		AllowPorts:          []uint16{80, 443},
		HostPatterns:        []string{"*.github.com"},
	})
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	for _, a := range []string{
		"169.254.169.254", "169.254.0.1", "10.0.0.1", "172.16.0.1", "192.168.1.1",
		"100.64.0.1", "224.0.0.1", "0.0.0.0",
		"fe80::1", "fd00::1", "ff02::1", "::",
	} {
		if v, why := p.Evaluate(addr(t, a), 443, ProtoTCP); v != VerdictDrop {
			t.Errorf("%s = %v (%s) under a public-Internet allow, want drop", a, v, why)
		}
	}
	// Loopback is the one block-set entry that stays allowed, because the
	// two policies are talking about two different namespaces. The proxy
	// refuses 127.0.0.1 to stop a sandbox reaching services on the *hub's*
	// loopback; inside a sandbox's own network namespace there is nothing on
	// 127.0.0.0/8 but the sandbox, and the packet never touches a wire. It
	// is a ScopeLocal rule for exactly that reason — see WireOnly.
	for _, a := range []string{"127.0.0.1", "::1"} {
		if v, why := p.Evaluate(addr(t, a), 8080, ProtoTCP); v != VerdictAllow {
			t.Errorf("%s = %v (%s), want allow: it is the sandbox itself", a, v, why)
		}
		if v, why := p.WireOnly().Evaluate(addr(t, a), 8080, ProtoTCP); v != VerdictDrop {
			t.Errorf("%s on the wire = %v (%s), want drop", a, v, why)
		}
	}
	for _, a := range []string{"8.8.8.8", "140.82.121.4", "2606:4700::1111"} {
		if v, why := p.Evaluate(addr(t, a), 443, ProtoTCP); v != VerdictAllow {
			t.Errorf("%s = %v (%s), want allow", a, v, why)
		}
	}
	// The warning has to name the widening, because "*.github.com" reading
	// as "the Internet" is exactly the surprise this package exists to
	// prevent an operator from having in production.
	if len(p.Warnings) == 0 || !strings.Contains(strings.Join(p.Warnings, " "), "*.github.com") {
		t.Errorf("a host-pattern grant compiled to a public-Internet allow without warning: %v", p.Warnings)
	}
}

// TestUnmaskedCIDRIsMaskedNotSilentlyDead: netip.Prefix.Contains is false for
// every address when a prefix has bits set below its length, so "10.8.0.5/24"
// would compile to a rule that matches nothing.
func TestUnmaskedCIDRIsMaskedNotSilentlyDead(t *testing.T) {
	p, err := Compile(Input{
		AllowCIDRs: []netip.Prefix{netip.MustParsePrefix("10.8.0.5/24")},
		AllowPorts: []uint16{443},
	})
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	if v, why := p.Evaluate(addr(t, "10.8.0.9"), 443, ProtoTCP); v != VerdictAllow {
		t.Fatalf("10.8.0.9 = %v (%s), want allow — the /24 was not masked", v, why)
	}
}

// TestV4MappedAllowCIDRBecomesV4: an operator (or a caller round-tripping
// through net.IP) can hand over ::ffff:10.8.0.0/120, and it has to mean the
// v4 prefix rather than an unreachable v6 one.
func TestV4MappedAllowCIDRBecomesV4(t *testing.T) {
	p, err := Compile(Input{
		AllowCIDRs: []netip.Prefix{netip.MustParsePrefix("::ffff:10.8.0.0/120")},
		AllowPorts: []uint16{443},
	})
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	if v, why := p.Evaluate(addr(t, "10.8.0.9"), 443, ProtoTCP); v != VerdictAllow {
		t.Fatalf("10.8.0.9 = %v (%s), want allow", v, why)
	}
}

// TestV4MappedDestinationIsCheckedAsV4: ::ffff:10.0.0.1 is 10.0.0.1 wearing a
// disguise, and Evaluate must see through it exactly as the proxy's
// normalizeAddr does.
func TestV4MappedDestinationIsCheckedAsV4(t *testing.T) {
	p, err := Compile(Input{AllowPublicInternet: true, AllowPorts: []uint16{443}})
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	if v, _ := p.Evaluate(addr(t, "::ffff:10.0.0.1"), 443, ProtoTCP); v != VerdictDrop {
		t.Error("::ffff:10.0.0.1 must be evaluated as the private address it is")
	}
}

// TestResolversOpenBothTransports: a resolver reachable only over UDP fails on
// truncated answers, and the failure reads as a DNS outage rather than a
// firewall rule.
func TestResolversOpenBothTransports(t *testing.T) {
	p, err := Compile(Input{
		Resolvers:           []netip.AddrPort{netip.MustParseAddrPort("10.7.0.10:53")},
		AllowPublicInternet: true,
		AllowPorts:          []uint16{443},
	})
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	r := addr(t, "10.7.0.10")
	for _, proto := range []Proto{ProtoUDP, ProtoTCP} {
		if v, why := p.Evaluate(r, 53, proto); v != VerdictAllow {
			t.Errorf("resolver over %v = %v (%s), want allow", proto, v, why)
		}
	}
	// The resolver's other ports stay shut: it is a resolver, not a host
	// the sandbox was granted.
	if v, _ := p.Evaluate(r, 443, ProtoTCP); v != VerdictDrop {
		t.Error("a resolver grant must not open the resolver's other ports")
	}
}

// TestFilteredWithoutResolverWarns: a policy that opens the Internet but no
// resolver looks broken from inside the sandbox, and the warning is the only
// thing standing between an operator and an hour of debugging DNS.
func TestFilteredWithoutResolverWarns(t *testing.T) {
	p, err := Compile(Input{AllowPublicInternet: true, AllowPorts: []uint16{443}})
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	if !strings.Contains(strings.Join(p.Warnings, " "), "resolver") {
		t.Errorf("no resolver warning: %v", p.Warnings)
	}
}

// TestICMPIsDroppedByTheBlockSet: an exfiltration channel over ICMP is still
// an exfiltration channel, so the drops are ProtoAny rather than TCP.
func TestICMPIsDroppedByTheBlockSet(t *testing.T) {
	p, err := Compile(Input{AllowPublicInternet: true, AllowPorts: []uint16{443}})
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	if v, _ := p.Evaluate(addr(t, "169.254.169.254"), 0, ProtoAny); v != VerdictDrop {
		t.Error("non-TCP traffic to the metadata service must be dropped")
	}
	// And the Internet allow is TCP-only: a UDP allow would open QUIC and
	// DNS-over-UDP to arbitrary servers, neither of which the grant named.
	if v, _ := p.Evaluate(addr(t, "8.8.8.8"), 443, ProtoUDP); v != VerdictDrop {
		t.Error("a TCP port grant must not open the same port over UDP")
	}
}

// TestPortAndPrefixLimits: the rendered ruleset is handed to another program,
// so an unbounded list is an argv overflow rather than a policy.
func TestPortAndPrefixLimits(t *testing.T) {
	many := make([]uint16, MaxPorts+1)
	for i := range many {
		many[i] = uint16(i + 1)
	}
	if _, err := Compile(Input{AllowPublicInternet: true, AllowPorts: many}); err == nil {
		t.Error("Compile accepted more than MaxPorts ports")
	}
	pfx := make([]netip.Prefix, MaxPrefixes+1)
	for i := range pfx {
		pfx[i] = netip.PrefixFrom(netip.AddrFrom4([4]byte{10, byte(i / 256), byte(i % 256), 0}), 24)
	}
	if _, err := Compile(Input{AllowCIDRs: pfx, AllowPorts: []uint16{443}}); err == nil {
		t.Error("Compile accepted more than MaxPrefixes CIDRs")
	}
}

// TestPortZeroIsRefused: port 0 is not a destination, and an allow rule
// carrying it would render as a match nothing reaches.
func TestPortZeroIsRefused(t *testing.T) {
	if _, err := Compile(Input{AllowPublicInternet: true, AllowPorts: []uint16{0, 443}}); err == nil {
		t.Error("Compile accepted port 0")
	}
}

// TestCompileIsDeterministic: two runs of the same authorisation must produce
// the same rules, or every reconcile pass looks like a change and the
// rendered artefacts churn.
func TestCompileIsDeterministic(t *testing.T) {
	in := Input{
		AllowCIDRs:          prefixes(t, "10.9.0.0/24", "10.8.0.0/24", "10.8.0.0/24"),
		AllowPorts:          []uint16{443, 80, 443},
		Brokers:             []netip.AddrPort{netip.MustParseAddrPort("10.7.0.2:8118")},
		AllowPublicInternet: true,
	}
	first, err := Compile(in)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	second, err := Compile(in)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	if len(first.Rules) != len(second.Rules) {
		t.Fatalf("rule counts differ: %d vs %d", len(first.Rules), len(second.Rules))
	}
	for i := range first.Rules {
		if first.Rules[i].String() != second.Rules[i].String() {
			t.Fatalf("rule %d differs:\n %s\n %s", i, first.Rules[i], second.Rules[i])
		}
	}
	// De-duplication happened, so the duplicate CIDR and port did not
	// become duplicate rules.
	var cidrAllows int
	for _, r := range first.Rules {
		if r.Verdict == VerdictAllow && strings.HasPrefix(r.Reason, "granted CIDR") {
			cidrAllows++
		}
	}
	if cidrAllows != 2 {
		t.Errorf("granted CIDR rules = %d, want 2 (the duplicate should collapse)", cidrAllows)
	}
}

// TestBlockedPrefixesIsACopy: the block set is process-wide, and a caller
// that sorts the returned slice must not be sorting every future sandbox's
// rule order.
func TestBlockedPrefixesIsACopy(t *testing.T) {
	got := BlockedPrefixes()
	if len(got) == 0 {
		t.Fatal("empty block set")
	}
	want := got[0]
	got[0] = Blocked{Prefix: netip.MustParsePrefix("203.0.113.0/24"), Reason: "tampered"}
	if again := BlockedPrefixes(); again[0] != want {
		t.Fatal("BlockedPrefixes shares its backing array with the package block set")
	}
}

// TestBlockReasonForPrefixCoversBothContainments: 10.8.0.0/24 is blocked
// because it sits inside private space, and 0.0.0.0/0 is blocked because it
// contains it. Reporting the second as unblocked would let a "waiver" for
// everything read as narrow.
func TestBlockReasonForPrefixCoversBothContainments(t *testing.T) {
	cases := map[string]bool{
		"10.8.0.0/24":        true,
		"0.0.0.0/0":          true,
		"169.254.169.254/32": true,
		"::/0":               true,
		"fd00::/8":           true,
		"140.82.121.0/24":    false,
		"2606:4700::/32":     false,
	}
	for s, want := range cases {
		if got := BlockReasonForPrefix(netip.MustParsePrefix(s)); (got != "") != want {
			t.Errorf("BlockReasonForPrefix(%s) = %q, want blocked=%t", s, got, want)
		}
	}
}
