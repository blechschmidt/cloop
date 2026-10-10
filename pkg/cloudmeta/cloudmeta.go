// Package cloudmeta is the one table of cloud metadata services, and the one
// rule for an allow list that contains one (Task 20397).
//
// A metadata service is an address on which a cloud hands whatever runs on a
// machine that machine's identity: instance credentials, user data, extension
// settings, a pod's role. A sandbox that reaches one holds the host's cloud
// account for as long as those credentials last, which is why every egress
// control in cloop drops these addresses unless an allow list names them.
//
// # Why one table
//
// Three enforcement points decide whether a sandbox reaches a metadata service:
// pkg/netfilter compiles allow lists into nftables rules and Kubernetes
// NetworkPolicies, pkg/egressbroker refuses connections at its proxy, and every
// surface that accepts an allow list — the hub's configuration, the dashboard's
// device, virtual-executor and project firewalls, egress grants — validates what
// it is given. Until this package each kept its own idea of what a metadata
// service is, and that idea was one address, 169.254.169.254. AWS's IPv6
// endpoint is in ULA space and Alibaba Cloud's in CGNAT space, so an edge host
// allowed fc00::/7 for hardware work opened a metadata service while every
// surface called the range "private". And the rule for a prefix that merely
// contains one differed: the broker refused it, the packet filter compiled it
// ahead of the drop that was meant to keep the address closed.
//
// # The rule
//
// An allow-list entry that strictly contains a metadata address — contains it,
// and is not that address's own /32 or /128 — opens the service without naming
// it. Check reports every such entry unless the same list also names the
// address, or a deny list keeps it closed. Every surface refuses what Check
// reports when it is written, and every compiler keeps the address closed when
// it meets one anyway (a rule stored before the rule existed): Carved names the
// addresses to drop ahead of the allows that contain them.
//
// The package depends on nothing but the standard library, so every one of the
// enforcement points can import it without importing each other.
package cloudmeta

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"
)

// Service is one metadata endpoint.
type Service struct {
	// Addr is the address the service answers on.
	Addr netip.Addr
	// Name says whose service it is, short enough to list several in one
	// sentence: "Alibaba Cloud", "Amazon EKS Pod Identity".
	Name string
}

// Prefix is the service's own host prefix: the /32 or /128 an allow list names
// it by.
func (s Service) Prefix() netip.Prefix { return netip.PrefixFrom(s.Addr, s.Addr.BitLen()) }

// Reason is the sentence a drop for the service carries: in an nft comment, in
// the proxy's refusal, in the audit trail. It names the address rather than the
// cloud, because one address serves most clouds and the address is what an
// operator reading a ruleset can act on.
func (s Service) Reason() string { return "cloud metadata service (" + s.Addr.String() + ")" }

// Describe names the service in a sentence: "169.254.0.23 (Tencent Cloud)".
func (s Service) Describe() string { return s.Addr.String() + " (" + s.Name + ")" }

// table is every metadata service cloop knows, sorted by family then address.
//
// The sources are the providers' own documentation. Every address here except
// Azure's WireServer is already inside a range the block set drops — link-local
// 169.254.0.0/16 and fe80::/10, ULA fc00::/7, CGNAT 100.64.0.0/10 — so naming
// it changes no verdict on its own. What it changes is the containment rule: a
// grant of fc00::/7 now has to say what it means for fd00:ec2::254. WireServer
// is a public address, so listing it closes it under "the public Internet" as
// well: on an Azure VM the agent's iptables rule that reserves it for root
// applies to the host's own processes and not to a container's forwarded
// traffic, and what it serves — the VM's goal state, certificates and extension
// settings with their protected values — is the host's, not the sandbox's.
var table = sortedTable([]Service{
	{Addr: netip.MustParseAddr("169.254.169.254"),
		Name: "instance metadata on AWS, Azure, Google Cloud, Oracle Cloud and most other clouds"},
	{Addr: netip.MustParseAddr("169.254.169.252"), Name: "GKE metadata server for Workload Identity"},
	{Addr: netip.MustParseAddr("169.254.170.2"), Name: "Amazon ECS task metadata and credentials"},
	{Addr: netip.MustParseAddr("169.254.170.23"), Name: "Amazon EKS Pod Identity Agent"},
	{Addr: netip.MustParseAddr("169.254.0.23"), Name: "Tencent Cloud instance metadata"},
	{Addr: netip.MustParseAddr("169.254.42.42"), Name: "Scaleway instance metadata"},
	{Addr: netip.MustParseAddr("100.100.100.200"), Name: "Alibaba Cloud instance metadata"},
	{Addr: netip.MustParseAddr("168.63.129.16"), Name: "Azure WireServer"},
	{Addr: netip.MustParseAddr("fd00:ec2::254"), Name: "AWS instance metadata over IPv6"},
	{Addr: netip.MustParseAddr("fd00:ec2::23"), Name: "Amazon EKS Pod Identity Agent over IPv6"},
	{Addr: netip.MustParseAddr("fd20:ce::254"), Name: "Google Cloud metadata server over IPv6"},
	{Addr: netip.MustParseAddr("fd00:42::42"), Name: "Scaleway instance metadata over IPv6"},
	{Addr: netip.MustParseAddr("fd00:a9fe:a9fe::1"), Name: "Akamai (Linode) metadata service over IPv6"},
	{Addr: netip.MustParseAddr("fe80::a9fe:a9fe"), Name: "OpenStack metadata service over IPv6"},
})

func sortedTable(in []Service) []Service {
	out := append([]Service(nil), in...)
	sortServices(out)
	return out
}

// sortServices orders IPv4 before IPv6, then by address: the order every list
// of services in this package is rendered in, so a sentence is stable.
func sortServices(ss []Service) {
	sort.Slice(ss, func(i, j int) bool {
		a, b := ss[i].Addr, ss[j].Addr
		if a.Is4() != b.Is4() {
			return a.Is4()
		}
		return a.Less(b)
	})
}

// Services returns the table. The slice is a copy, so a caller that sorts or
// filters it cannot reach into what every filter is compiled against.
func Services() []Service { return append([]Service(nil), table...) }

// Lookup reports the service at addr, seen through an IPv4-mapped spelling.
func Lookup(addr netip.Addr) (Service, bool) {
	if !addr.IsValid() {
		return Service{}, false
	}
	addr = addr.Unmap()
	for _, s := range table {
		if s.Addr == addr {
			return s, true
		}
	}
	return Service{}, false
}

// Canonical returns p the way every allow list compares prefixes: masked, and
// an IPv4-mapped prefix as the IPv4 prefix it spells — ::ffff:169.254.0.0/112
// is 169.254.0.0/16, and treating it as anything else would let a spelling
// decide whether the rule applies. ok is false for an invalid prefix and for a
// mapped one shorter than /96, which mixes mapped and native space.
func Canonical(p netip.Prefix) (netip.Prefix, bool) {
	if !p.IsValid() {
		return netip.Prefix{}, false
	}
	if p.Addr().Is4In6() {
		if p.Bits() < 96 {
			return netip.Prefix{}, false
		}
		p = netip.PrefixFrom(p.Addr().Unmap(), p.Bits()-96)
	}
	return p.Masked(), true
}

// Within returns the services strictly inside p: inside it, and p is not the
// service's own host prefix. Sorted like Services.
func Within(p netip.Prefix) []Service {
	p, ok := Canonical(p)
	if !ok {
		return nil
	}
	var out []Service
	for _, s := range table {
		if s.Addr.Is4() == p.Addr().Is4() && p.Contains(s.Addr) && p.Bits() < s.Addr.BitLen() {
			out = append(out, s)
		}
	}
	return out
}

// Finding is one allow-list entry and every metadata service it opens without
// naming.
type Finding struct {
	// Allow is the entry, canonical.
	Allow netip.Prefix
	// Services are the services it contains and nothing names or closes,
	// sorted like Services.
	Services []Service
}

// Check applies the rule to an allow list: one Finding per entry that strictly
// contains a metadata service the list does not also name by its own host
// prefix. closed holds prefixes that keep an address unreachable whatever the
// allows say — a deny list — and a service inside one of them is not reported:
// an operator who denied it has said what they meant as clearly as one who
// allowed it.
//
// Entries that do not parse are skipped: syntax is each surface's own check,
// and this one has to be callable on a list that has not passed it yet.
func Check(allow, closed []netip.Prefix) []Finding {
	named := map[netip.Addr]bool{}
	var canon []netip.Prefix
	for _, p := range allow {
		c, ok := Canonical(p)
		if !ok {
			continue
		}
		canon = append(canon, c)
		if c.Bits() == c.Addr().BitLen() {
			named[c.Addr()] = true
		}
	}
	var shut []netip.Prefix
	for _, p := range closed {
		if c, ok := Canonical(p); ok {
			shut = append(shut, c)
		}
	}
	isClosed := func(a netip.Addr) bool {
		for _, c := range shut {
			if c.Addr().Is4() == a.Is4() && c.Contains(a) {
				return true
			}
		}
		return false
	}

	seen := map[netip.Prefix]bool{}
	var out []Finding
	for _, p := range canon {
		if seen[p] {
			continue
		}
		seen[p] = true
		var open []Service
		for _, s := range Within(p) {
			if !named[s.Addr] && !isClosed(s.Addr) {
				open = append(open, s)
			}
		}
		if len(open) > 0 {
			out = append(out, Finding{Allow: p, Services: open})
		}
	}
	sort.Slice(out, func(i, j int) bool { return lessPrefix(out[i].Allow, out[j].Allow) })
	return out
}

// Carved returns the services Check reports for an allow list, once each: the
// addresses a compiled filter drops ahead of the allows that contain them, so
// that an entry stored before the rule existed fails closed rather than open.
func Carved(allow, closed []netip.Prefix) []Service {
	seen := map[netip.Addr]bool{}
	var out []Service
	for _, f := range Check(allow, closed) {
		for _, s := range f.Services {
			if !seen[s.Addr] {
				seen[s.Addr] = true
				out = append(out, s)
			}
		}
	}
	sortServices(out)
	return out
}

// Sentence states the finding, without a remedy: "169.254.0.0/16 contains the
// cloud metadata service at 169.254.169.254 (…) without naming it".
func (f Finding) Sentence() string {
	if len(f.Services) == 1 {
		return fmt.Sprintf("%s contains the cloud metadata service at %s without naming it",
			f.Allow, f.Services[0].Describe())
	}
	parts := make([]string, len(f.Services))
	for i, s := range f.Services {
		parts[i] = s.Describe()
	}
	return fmt.Sprintf("%s contains %d cloud metadata services without naming them: %s",
		f.Allow, len(f.Services), strings.Join(parts, ", "))
}

// Hosts lists the host prefixes that would name the finding's services:
// "169.254.169.254/32", or "169.254.0.23/32, 169.254.42.42/32".
func (f Finding) Hosts() string {
	parts := make([]string, len(f.Services))
	for i, s := range f.Services {
		parts[i] = s.Prefix().String()
	}
	return strings.Join(parts, ", ")
}

// Remedy is the explicit alternative, in the words of the surface the list was
// written on. allowIn names where an allow goes ("the allowlist",
// "allow_cidrs"); denyIn names a deny list, or is empty where the surface has
// none, and then the alternative is a narrower range.
func (f Finding) Remedy(allowIn, denyIn string) string {
	it, them, hosts := "it", "it", f.Hosts()
	if len(f.Services) > 1 {
		it, them, hosts = "them", "they", "their addresses ("+hosts+")"
	}
	if denyIn == "" {
		return fmt.Sprintf("add %s to %s if a sandbox should reach %s, or allow a range that leaves %s out",
			hosts, allowIn, it, it)
	}
	return fmt.Sprintf("add %s to %s if a sandbox should reach %s, or to %s so %s stay%s closed",
		hosts, allowIn, it, denyIn, them, plural(len(f.Services)))
}

func plural(n int) string {
	if n == 1 {
		return "s"
	}
	return ""
}

// Explain is the whole refusal: the finding and its remedy as one sentence.
func (f Finding) Explain(allowIn, denyIn string) string {
	return f.Sentence() + ". " + capitalize(f.Remedy(allowIn, denyIn))
}

func capitalize(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

func lessPrefix(a, b netip.Prefix) bool {
	if a.Addr().Is4() != b.Addr().Is4() {
		return a.Addr().Is4()
	}
	if c := a.Addr().Compare(b.Addr()); c != 0 {
		return c < 0
	}
	return a.Bits() < b.Bits()
}
