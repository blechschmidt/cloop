package netfilter_test

import (
	"errors"
	"fmt"
	"math/rand"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/cloudmeta"
	"github.com/blechschmidt/cloop/pkg/egressbroker"
	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/executor/container"
	"github.com/blechschmidt/cloop/pkg/executor/kubernetes"
	"github.com/blechschmidt/cloop/pkg/netfilter"
	"github.com/blechschmidt/cloop/pkg/secretbroker"
)

// agreement_test.go checks pkg/netfilter against pkg/egressbroker.
//
// The two enforce the same authorisation at different layers: the broker
// refuses a *connection* to a blocked address, the filter drops a *packet*
// to one. If they disagree, one of them is wrong, and which one is wrong
// depends on the direction of the disagreement:
//
//   - the filter allowing something the broker refuses is a hole — the
//     firewall would be handing back the reach the SSRF block set exists to
//     deny;
//   - the filter dropping something the broker allows is a sandbox that
//     mysteriously cannot reach a destination its grant names.
//
// Both directions are checked. The second has exactly one permitted class of
// exception, enumerated in translationPrefixes, and the test fails if a
// disagreement falls outside it — so a future edit to either block set has to
// be a deliberate, visible change rather than a drift nobody noticed.
//
// This file is the reason the two implementations are allowed to be separate
// code. They have to be: one produces prefixes for a packet filter, the other
// evaluates predicates against a single address. Sharing an implementation
// was not an option, so agreeing under test is.

// translationPrefixes are the IPv6 encodings that carry an IPv4 address.
//
// The broker unwraps them and judges the address inside; a packet filter
// cannot do arithmetic on an embedded address, so netfilter drops the whole
// prefix. That makes it stricter than the broker for public addresses written
// in translation form — 64:ff9b::8.8.8.8 — and stricter is the safe
// direction. See the pkg/netfilter package comment.
var translationPrefixes = []netip.Prefix{
	netip.MustParsePrefix("64:ff9b::/96"),
	netip.MustParsePrefix("64:ff9b:1::/48"),
	netip.MustParsePrefix("::ffff:0:0:0/96"),
	netip.MustParsePrefix("2002::/16"),
	netip.MustParsePrefix("::/96"),
}

func inTranslationPrefix(a netip.Addr) bool {
	for _, p := range translationPrefixes {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// wideGrant is a grant that allows every host on 443 — the widest
// authorisation the broker can express, and therefore the one whose refusals
// are purely the work of the block set.
func wideGrant() egressbroker.Grant {
	g := egressbroker.Grant{
		Hosts:     []string{"*"},
		Ports:     []int{443},
		ExpiresAt: time.Now().Add(time.Hour),
	}
	g.Normalize()
	return g
}

// widePolicy is the netfilter equivalent: the public Internet on 443.
func widePolicy(t *testing.T) netfilter.Policy {
	t.Helper()
	p, err := netfilter.Compile(netfilter.Input{
		AllowPublicInternet: true,
		AllowPorts:          []uint16{443},
		HostPatterns:        []string{"*"},
	})
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	return p.WireOnly()
}

// checkAgreement compares the two verdicts for one address and reports a
// disagreement that is not a permitted exception.
func checkAgreement(t *testing.T, p netfilter.Policy, g egressbroker.Grant, a netip.Addr) {
	t.Helper()
	brokerRefused := g.CheckAddr(a, true) != nil
	verdict, why := p.Evaluate(a, 443, netfilter.ProtoTCP)
	filterDropped := verdict == netfilter.VerdictDrop

	switch {
	case brokerRefused && !filterDropped:
		t.Errorf("HOLE: %s is refused by the broker but allowed by the filter (%s)", a, why)
	case !brokerRefused && filterDropped:
		if !inTranslationPrefix(a) {
			t.Errorf("OVER-BLOCK: %s is allowed by the broker but dropped by the filter (%s)", a, why)
		}
	}
}

// TestFilterAgreesWithBrokerOnNamedAddresses walks the boundaries of every
// block-set entry. Boundaries are where an off-by-one prefix length shows up,
// and a /12 written as a /16 is the kind of mistake that reads fine and
// leaves 172.31.0.0 reachable.
func TestFilterAgreesWithBrokerOnNamedAddresses(t *testing.T) {
	p, g := widePolicy(t), wideGrant()
	named := []string{
		// Metadata, and the link-local range around it.
		"169.254.169.254", "169.254.169.253", "169.254.0.0", "169.254.255.255",
		"169.253.255.255", "169.255.0.0",
		// RFC1918, each range and both edges.
		"10.0.0.0", "10.255.255.255", "9.255.255.255", "11.0.0.0",
		"172.16.0.0", "172.31.255.255", "172.15.255.255", "172.32.0.0",
		"192.168.0.0", "192.168.255.255", "192.167.255.255", "192.169.0.0",
		// Loopback.
		"127.0.0.0", "127.0.0.1", "127.255.255.255", "126.255.255.255", "128.0.0.0",
		// CGNAT.
		"100.64.0.0", "100.127.255.255", "100.63.255.255", "100.128.0.0",
		// Multicast and the unspecified address.
		"224.0.0.0", "239.255.255.255", "223.255.255.255", "240.0.0.0",
		"0.0.0.0", "0.0.0.1",
		// Ordinary public addresses.
		"8.8.8.8", "1.1.1.1", "140.82.121.4", "203.0.113.5",
		// IPv6: loopback, unspecified, ULA, link-local, multicast, public.
		"::", "::1", "fc00::", "fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
		"fbff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", "fe00::",
		"fe80::", "febf:ffff:ffff:ffff:ffff:ffff:ffff:ffff", "fec0::",
		"ff00::", "ff02::1", "2606:4700::1111", "2001:4860:4860::8888",
		// IPv4 wearing an IPv6 disguise. Every one of these is a way to
		// write a private or loopback address that no IPv6 predicate
		// recognises, and both implementations have to see through them.
		"::ffff:127.0.0.1", "::ffff:10.0.0.1", "::ffff:169.254.169.254",
		"64:ff9b::7f00:1", "64:ff9b::a00:1", "64:ff9b::808:808",
		"2002:7f00:1::", "2002:a00:1::", "2002:808:808::",
		"::127.0.0.1", "::a00:1",
	}
	for _, s := range named {
		a, err := netip.ParseAddr(s)
		if err != nil {
			t.Fatalf("parse %q: %v", s, err)
		}
		checkAgreement(t, p, g, a)
	}
}

// TestFilterAgreesWithBrokerOnASweep runs a deterministic pseudo-random sweep
// so that a block-set change nobody wrote a boundary case for still gets
// caught. The seed is fixed: a flaky security test is a security test people
// learn to re-run.
func TestFilterAgreesWithBrokerOnASweep(t *testing.T) {
	p, g := widePolicy(t), wideGrant()
	rng := rand.New(rand.NewSource(20186))

	for i := 0; i < 20000; i++ {
		var b [4]byte
		rng.Read(b[:])
		checkAgreement(t, p, g, netip.AddrFrom4(b))
	}
	for i := 0; i < 20000; i++ {
		var b [16]byte
		rng.Read(b[:])
		// Bias a slice of the sweep into the ranges that matter: uniform
		// random IPv6 is public with overwhelming probability, so an
		// unbiased sweep would test one thing forty thousand times.
		switch i % 4 {
		case 1:
			b[0], b[1] = 0xfe, 0x80|(b[1]&0x3f)
		case 2:
			b[0] = 0xfc | (b[0] & 0x01)
		case 3:
			b[0] = 0xff
		}
		checkAgreement(t, p, g, netip.AddrFrom16(b))
	}
}

// TestWaiverAgrees: an explicit CIDR is the only thing that opens blocked
// space, in both implementations, and it opens exactly itself.
func TestWaiverAgrees(t *testing.T) {
	g := egressbroker.Grant{
		CIDRs:     []string{"10.8.0.0/24"},
		Ports:     []int{6443},
		ExpiresAt: time.Now().Add(time.Hour),
	}
	g.Normalize()

	p, err := netfilter.Compile(netfilter.Input{
		AllowCIDRs: []netip.Prefix{netip.MustParsePrefix("10.8.0.0/24")},
		AllowPorts: []uint16{6443},
	})
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	p = p.WireOnly()

	cases := []struct {
		addr  string
		allow bool
	}{
		{"10.8.0.1", true},
		{"10.8.0.255", true},
		{"10.8.1.1", false},
		{"10.0.0.1", false},
		{"169.254.169.254", false},
		{"8.8.8.8", false},
	}
	for _, c := range cases {
		a := netip.MustParseAddr(c.addr)
		// hostAllowed is false: this grant names no hosts, so the CIDR is
		// the only allow dimension — the same shape as the filter's.
		brokerAllowed := g.CheckAddr(a, false) == nil
		verdict, why := p.Evaluate(a, 6443, netfilter.ProtoTCP)
		filterAllowed := verdict == netfilter.VerdictAllow

		if brokerAllowed != c.allow {
			t.Errorf("broker: %s allowed=%t, want %t", c.addr, brokerAllowed, c.allow)
		}
		if filterAllowed != c.allow {
			t.Errorf("filter: %s allowed=%t (%s), want %t", c.addr, filterAllowed, why, c.allow)
		}
	}
}

// TestPortAgreement: the broker's port allowlist and the filter's have to
// cover the same set, or a grant for 443 leaves 22 open on every address the
// CIDR names.
func TestPortAgreement(t *testing.T) {
	g := egressbroker.Grant{
		CIDRs:     []string{"10.8.0.0/24"},
		Ports:     []int{443, 6443},
		ExpiresAt: time.Now().Add(time.Hour),
	}
	g.Normalize()
	p, err := netfilter.Compile(netfilter.Input{
		AllowCIDRs: []netip.Prefix{netip.MustParsePrefix("10.8.0.0/24")},
		AllowPorts: []uint16{443, 6443},
	})
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	p = p.WireOnly()

	a := netip.MustParseAddr("10.8.0.5")
	for port := 1; port <= 65535; port += 7 {
		brokerAllowed := g.CheckPort(port) == nil
		verdict, _ := p.Evaluate(a, uint16(port), netfilter.ProtoTCP)
		filterAllowed := verdict == netfilter.VerdictAllow
		if brokerAllowed != filterAllowed {
			t.Fatalf("port %d: broker allowed=%t, filter allowed=%t", port, brokerAllowed, filterAllowed)
		}
	}
	for _, port := range []int{443, 6443} {
		if g.CheckPort(port) != nil {
			t.Errorf("broker refused granted port %d", port)
		}
		if v, _ := p.Evaluate(a, uint16(port), netfilter.ProtoTCP); v != netfilter.VerdictAllow {
			t.Errorf("filter dropped granted port %d", port)
		}
	}
}

// TestBrokeredPolicyIsNarrowerThanAnyGrant is the argument for the brokered
// mode. Whatever the grant says, a brokered filter opens one endpoint, so the
// host allowlist the filter cannot enforce is enforced by the only thing the
// sandbox can reach.
func TestBrokeredPolicyIsNarrowerThanAnyGrant(t *testing.T) {
	broker := netip.MustParseAddrPort("10.7.0.2:8118")
	p, err := netfilter.Compile(netfilter.Input{Brokers: []netip.AddrPort{broker}})
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	p = p.WireOnly()

	g := wideGrant()
	rng := rand.New(rand.NewSource(7))
	for i := 0; i < 5000; i++ {
		var b [4]byte
		rng.Read(b[:])
		a := netip.AddrFrom4(b)
		if a == broker.Addr() {
			continue
		}
		if v, why := p.Evaluate(a, 443, netfilter.ProtoTCP); v != netfilter.VerdictDrop {
			t.Fatalf("brokered filter allowed %s (%s) though the grant is %v", a, why, g.Hosts)
		}
	}
}

// metadataCorpus is the prefix corpus Task 20397's agreement is checked over:
// allowlists that contain a cloud metadata service, name one, name one beside
// a range containing it, spell one as an IPv4-mapped prefix, and contain none.
// refuse is the verdict every surface must reach.
var metadataCorpus = []struct {
	cidrs  []string
	refuse bool
}{
	{[]string{"169.254.0.0/16"}, true},
	{[]string{"169.254.128.0/17"}, true},
	{[]string{"169.254.0.0/17"}, true},
	{[]string{"169.254.169.0/24", "169.254.169.254/32"}, true},
	{[]string{"169.254.169.0/24", "169.254.169.254/32", "169.254.169.252/32"}, false},
	{[]string{"169.254.169.254/32"}, false},
	{[]string{"169.254.100.0/24"}, false},
	{[]string{"fc00::/7"}, true},
	{[]string{"fd00:ec2::/32"}, true},
	{[]string{"fd00:ec2::254/128", "fd00:ec2::23/128"}, false},
	{[]string{"fd12:3456::/32"}, false},
	{[]string{"fe80::/10"}, true},
	{[]string{"100.64.0.0/10"}, true},
	{[]string{"100.100.100.0/24"}, true},
	{[]string{"100.100.100.200/32"}, false},
	{[]string{"100.64.0.0/16"}, false},
	{[]string{"168.63.0.0/16"}, true},
	{[]string{"168.63.129.16/32"}, false},
	{[]string{"0.0.0.0/1"}, true},
	{[]string{"128.0.0.0/1"}, true},
	{[]string{"0.0.0.0/0"}, true},
	{[]string{"::/0"}, true},
	{[]string{"::ffff:0.0.0.0/96"}, true},
	{[]string{"::ffff:169.254.0.0/112"}, true},
	{[]string{"::ffff:169.254.169.254/128"}, false},
	{[]string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"}, false},
	{[]string{"140.82.112.0/20", "2001:db8::/32"}, false},
	{[]string{"64:ff9b::/96"}, false},
	{[]string{"2000::/3"}, false},
}

// TestAllowListVerdictAgreesAcrossFilterAndBroker: the containment rule has
// one implementation, in pkg/cloudmeta, and four surfaces that apply it — the
// dashboard's device, virtual-executor and project firewalls, the container
// and Kubernetes egress_filter sections, and egress grants. This proves each
// surface reaches the same verdict on the same allowlist, through its own
// parsing: a surface that skipped the rule, or canonicalised a mapped prefix
// differently, is what the two used to disagree by.
func TestAllowListVerdictAgreesAcrossFilterAndBroker(t *testing.T) {
	for _, c := range metadataCorpus {
		t.Run(strings.Join(c.cidrs, ","), func(t *testing.T) {
			verdicts := map[string]error{}

			g := egressbroker.Grant{ID: "egress_corpus",
				Subject: secretbroker.Subject{Type: secretbroker.SubjectProject, Value: "/srv/app"},
				CIDRs:   c.cidrs, Ports: []int{443}}
			verdicts["egress grant"] = g.Validate()

			rules, err := executor.FirewallRules{AllowCIDRs: c.cidrs, AllowPorts: []int{443}}.Normalize()
			if err == nil {
				err = rules.CheckMetadata()
			}
			verdicts["dashboard firewall"] = err

			cf := container.EgressFilter{Enabled: true, AllowCIDRs: c.cidrs, AllowPorts: []int{443}}
			_, err = cf.Compile()
			if err == nil && len(cf.MetadataFindings()) > 0 {
				err = errors.New(cf.MetadataFindings()[0].Sentence())
			}
			verdicts["container egress_filter"] = err

			kf := kubernetes.EgressFilter{Enabled: true, CIDRs: c.cidrs, Ports: []int{443}}
			_, err = kf.Compile()
			if err == nil && len(kf.MetadataFindings()) > 0 {
				err = errors.New(kf.MetadataFindings()[0].Sentence())
			}
			verdicts["kubernetes egress_filter"] = err

			for surface, err := range verdicts {
				if (err != nil) != c.refuse {
					t.Errorf("%s: refused=%t (%v), want refused=%t", surface, err != nil, err, c.refuse)
				}
			}
		})
	}
}

// TestStoredAllowListsReachTheSameMetadata is the fail-safe half: rule sets
// and grants stored before the rule are never re-validated, so the compiled
// filter and the proxy must each keep a contained service closed on their own
// — and agree, address by address, on every service, its neighbours and its
// IPv6 disguises.
func TestStoredAllowListsReachTheSameMetadata(t *testing.T) {
	var probes []netip.Addr
	for _, s := range cloudmeta.Services() {
		probes = append(probes, s.Addr, s.Addr.Next(), s.Addr.Prev())
		if s.Addr.Is4() {
			b := s.Addr.As4()
			for _, wrap := range []string{"64:ff9b::%d.%d.%d.%d", "::ffff:%d.%d.%d.%d", "::%d.%d.%d.%d"} {
				probes = append(probes, netip.MustParseAddr(fmt.Sprintf(wrap, b[0], b[1], b[2], b[3])))
			}
		}
	}
	for _, c := range metadataCorpus {
		var in netfilter.Input
		for _, s := range c.cidrs {
			in.AllowCIDRs = append(in.AllowCIDRs, netip.MustParsePrefix(s))
		}
		in.AllowPorts = []uint16{443}
		p, err := netfilter.Compile(in)
		if err != nil {
			continue // a /0: refused by the compiler too, so it is never stored as a filter
		}
		wire := p.WireOnly()
		g := egressbroker.Grant{CIDRs: c.cidrs, Ports: []int{443}, ExpiresAt: time.Now().Add(time.Hour)}
		g.Normalize()
		for _, a := range probes {
			brokerRefused := g.CheckAddr(a, false) != nil
			verdict, why := wire.Evaluate(a, 443, netfilter.ProtoTCP)
			filterDropped := verdict == netfilter.VerdictDrop
			switch {
			case brokerRefused && !filterDropped:
				t.Errorf("HOLE under %v: %s is refused by the broker but allowed by the filter (%s)", c.cidrs, a, why)
			case !brokerRefused && filterDropped && !inTranslationPrefix(a):
				t.Errorf("OVER-BLOCK under %v: %s is allowed by the broker but dropped by the filter (%s)",
					c.cidrs, a, why)
			}
			if svc, ok := cloudmeta.Lookup(a); ok && !filterDropped {
				named := false
				for _, s := range c.cidrs {
					if pfx, ok := cloudmeta.Canonical(netip.MustParsePrefix(s)); ok && pfx == svc.Prefix() {
						named = true
					}
				}
				if !named {
					t.Errorf("under %v the filter reaches %s, which no entry names", c.cidrs, svc.Describe())
				}
			}
		}
	}
}

// TestBlockReasonsAgreeOnEveryService: one table, so the sentence an audit row
// carries for a refused service is the same at both layers.
func TestBlockReasonsAgreeOnEveryService(t *testing.T) {
	p := widePolicy(t)
	for _, s := range cloudmeta.Services() {
		_, why := p.Evaluate(s.Addr, 443, netfilter.ProtoTCP)
		if br := egressbroker.BlockReason(s.Addr); br != why || br != s.Reason() {
			t.Errorf("%s: filter says %q, broker says %q, table says %q", s.Addr, why, br, s.Reason())
		}
	}
}
