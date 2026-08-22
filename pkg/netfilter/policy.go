// Package netfilter compiles an egress authorisation into an IP-layer
// firewall.
//
// The problem it solves is that, until now, cloop's egress allowlist was
// advisory. pkg/egressbroker is an HTTP forward proxy: it checks hosts,
// ports, CIDRs and the SSRF block set beautifully, and it only ever sees
// traffic a workload chose to send it. A harness that opens a raw socket,
// runs `curl --noproxy '*'`, resolves a name over DoH or speaks anything
// that is not HTTP walks straight past every one of those checks. The
// container driver said as much in its own doc comment — "it does not filter
// egress" — and the Kubernetes driver said the same about NetworkPolicy.
// Both were honest, and both left the sandbox with unrestricted outbound
// access the moment an operator turned the network on.
//
// A firewall closes that, but only if it means the same thing everywhere. So
// there is one compiler here and several renderers: Compile turns an
// authorisation into an ordered, first-match-wins Policy, and the backends
// render that same Policy as nftables rules or as a Kubernetes
// NetworkPolicy. Evaluate answers "what would this policy do to that packet"
// without any backend at all, which is what lets a test compare the firewall
// against the proxy address-by-address instead of trusting that two
// hand-written rule sets agree.
//
// # Relationship to the proxy's block set
//
// egressbroker.BlockReason refuses loopback, RFC1918, link-local, the cloud
// metadata endpoint, CGNAT and multicast unless the grant names an explicit
// CIDR. This package reproduces that set as prefixes and reproduces the
// waiver rule: an allow for a granted CIDR is emitted *before* the drop that
// would otherwise cover it, so an explicit CIDR — and nothing else — buys
// reach into blocked space. agreement_test.go checks the two implementations
// against each other in both directions.
//
// The agreement is exact but for one deliberate delta. The proxy normalises
// IPv6 encodings that carry an IPv4 address (NAT64, 6to4, v4-translated,
// v4-compatible) and then checks the address inside. A packet filter cannot
// do arithmetic on an embedded address, so this package drops those transition
// prefixes wholesale. That is stricter than the proxy — 64:ff9b::8.8.8.8 is a
// public address the proxy would allow — and strictness is the safe direction.
// No sandbox reaches the Internet through a translation prefix it addresses
// itself; that is a gateway's job.
//
// # What a hostname allowlist becomes
//
// It becomes the public Internet. "*.github.com" is a name, and names do not
// exist at layer 3. Compile therefore refuses to silently widen: opening
// direct egress for a host-pattern grant requires AllowPublicInternet, and
// the resulting Policy carries a Warning saying exactly how much wider the
// firewall is than the grant. The narrow configuration is the brokered one,
// where the only reachable address is the proxy and the host allowlist is
// enforced where it can be — inside it.
//
// The package depends on nothing but the standard library, so the executor
// drivers can all reach it without dragging the broker's storage and crypto
// along behind. Compile and the renderers are pure functions; apply.go is the
// one file that touches the host, and it is separated precisely so that
// everything deciding what the firewall *means* stays testable without one.
package netfilter

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"
)

// Verdict is what the filter does with a packet.
type Verdict uint8

const (
	// VerdictDrop discards the packet silently. Silence rather than a
	// rejection is deliberate: a sandbox probing for reachable networks
	// learns nothing from a timeout, whereas an ICMP unreachable confirms
	// that something is listening on the other side of the filter.
	VerdictDrop Verdict = iota
	// VerdictAllow forwards the packet.
	VerdictAllow
)

// String renders the verdict for rule comments and audit rows.
func (v Verdict) String() string {
	if v == VerdictAllow {
		return "allow"
	}
	return "drop"
}

// Proto narrows a rule to one transport, or to all of them.
type Proto uint8

const (
	// ProtoAny matches every transport, including ICMP and anything else
	// that is neither TCP nor UDP. A drop rule wants this: an exfiltration
	// channel over ICMP is still an exfiltration channel.
	ProtoAny Proto = iota
	ProtoTCP
	ProtoUDP
)

// String renders the transport for rule comments.
func (p Proto) String() string {
	switch p {
	case ProtoTCP:
		return "tcp"
	case ProtoUDP:
		return "udp"
	default:
		return "any"
	}
}

// Scope says which filters a rule is meaningful to.
type Scope uint8

const (
	// ScopeWire covers traffic that leaves the sandbox's network namespace.
	// Every backend can express it.
	ScopeWire Scope = iota
	// ScopeLocal covers traffic that never reaches a wire — the sandbox
	// talking to its own loopback. An in-namespace packet filter has to
	// allow it explicitly or a harness that binds a local port breaks in a
	// way that looks nothing like a firewall problem. A Kubernetes
	// NetworkPolicy never sees it, so that renderer drops these rules
	// rather than emitting a meaningless 127.0.0.0/8 peer.
	ScopeLocal
)

// Rule is one line of the compiled filter.
type Rule struct {
	Verdict Verdict
	// Prefix is the destination address range.
	Prefix netip.Prefix
	// Ports is the destination port allowlist. Empty means every port,
	// which is what a drop rule wants and what an allow rule should almost
	// never have.
	Ports []uint16
	Proto Proto
	Scope Scope
	// Reason is the human sentence that lands in an nft comment, in the
	// NetworkPolicy annotation and in an operator's terminal. It is part of
	// the output, not a debugging aid.
	Reason string
}

// String renders the rule as a single readable line.
func (r Rule) String() string {
	var b strings.Builder
	b.WriteString(r.Verdict.String())
	b.WriteString(" ")
	b.WriteString(r.Prefix.String())
	if r.Proto != ProtoAny {
		b.WriteString(" ")
		b.WriteString(r.Proto.String())
	}
	if len(r.Ports) > 0 {
		b.WriteString(" port ")
		b.WriteString(joinPorts(r.Ports))
	}
	if r.Reason != "" {
		b.WriteString(" — ")
		b.WriteString(r.Reason)
	}
	return b.String()
}

// Policy is a compiled firewall: an ordered rule list evaluated first-match
// wins, with an implicit drop at the end.
//
// The default is not a field. A firewall whose default could be "allow" is a
// firewall an operator can misconfigure into uselessness, and there is no
// authorisation this package can be handed that would justify it.
type Policy struct {
	// Mode summarises the shape of the authorisation for display.
	Mode Mode
	// Rules are evaluated in order; the first match decides.
	Rules []Rule
	// Warnings record where the filter is necessarily wider than the
	// authorisation it was compiled from. They are rendered into the
	// output of every backend, because an operator reading a ruleset needs
	// to see that "*.github.com" became "the Internet".
	Warnings []string
}

// Mode is the shape of an authorisation, derived by Compile and used for
// display and for the rendered header.
type Mode uint8

const (
	// ModeIsolated is a sandbox with no egress at all.
	ModeIsolated Mode = iota
	// ModeBrokered is a sandbox whose only reachable address is the egress
	// proxy. The L3 filter and the L7 allowlist coincide here: nothing can
	// leave except through the thing that enforces hosts and methods.
	ModeBrokered
	// ModeFiltered is a sandbox dialling destinations directly under a
	// CIDR/port allowlist. Narrow when the grant names CIDRs, and no
	// narrower than "the public Internet on these ports" when it names
	// hostnames.
	ModeFiltered
)

// String renders the mode.
func (m Mode) String() string {
	switch m {
	case ModeBrokered:
		return "brokered"
	case ModeFiltered:
		return "filtered"
	default:
		return "isolated"
	}
}

// Input is the authorisation to compile.
//
// It is deliberately not egressbroker.Grant. A grant carries subjects, TTLs,
// byte quotas and HTTP methods, none of which a packet filter can act on, and
// depending on that package would drag the broker's storage and crypto into
// something that should stay a pure function. The caller projects a grant
// down to the dimensions layer 3 understands; GrantInput in the executor
// wiring does exactly that.
type Input struct {
	// AllowCIDRs are the address ranges the authorisation names. These are
	// the only thing that waives the block set, exactly as in the proxy.
	AllowCIDRs []netip.Prefix

	// AllowPorts bounds every destination allow. Empty means the caller
	// named no ports, and Compile refuses rather than guessing: an allow
	// rule with no port restriction is a hole, and "they probably meant
	// 80 and 443" is not a thing a firewall compiler should decide.
	AllowPorts []uint16

	// Brokers are egress proxy endpoints the sandbox must reach. Naming
	// any of them is what makes the policy brokered.
	Brokers []netip.AddrPort

	// Resolvers are DNS servers the sandbox may query directly. Each is
	// opened on both UDP and TCP — a truncated answer retries over TCP, and
	// a resolver reachable only over UDP fails on large responses in a way
	// that looks like a DNS outage rather than a firewall rule.
	//
	// A brokered policy needs none: the proxy resolves on the sandbox's
	// behalf, which is also what makes its resolve-once pinning meaningful.
	Resolvers []netip.AddrPort

	// AllowPublicInternet opens every address outside the block set on
	// AllowPorts. It exists because a hostname allowlist cannot be
	// expressed at layer 3, and it is a separate field rather than an
	// inference from HostPatterns so that widening the filter to the whole
	// Internet is something a caller states rather than something that
	// happens to it.
	AllowPublicInternet bool

	// HostPatterns is the L7 allowlist this policy could not enforce. It is
	// used only to write an accurate warning.
	HostPatterns []string
}

// Compile turns an authorisation into an ordered filter.
//
// Rule order is the security-relevant part, so it is fixed here rather than
// left to a renderer:
//
//  1. sandbox-local loopback, so a harness that binds 127.0.0.1 works;
//  2. allows for explicitly granted CIDRs, ahead of the drops they waive;
//  3. allows for the broker and for resolvers, which are infrastructure;
//  4. drops for the block set;
//  5. the public-Internet allow, if the caller asked for one;
//  6. the implicit final drop.
//
// Steps 2 and 4 are the waiver rule from egressbroker.CheckAddr expressed as
// ordering: a granted 10.8.0.0/24 is allowed on its ports before 10.0.0.0/8
// is dropped, so the grant buys that prefix and those ports and nothing else.
// Putting the Internet allow last rather than first is what keeps step 4
// meaningful.
func Compile(in Input) (Policy, error) {
	ports, err := normalizePorts(in.AllowPorts)
	if err != nil {
		return Policy{}, err
	}
	cidrs, err := normalizePrefixes(in.AllowCIDRs)
	if err != nil {
		return Policy{}, err
	}
	brokers, err := normalizeAddrPorts(in.Brokers, "broker")
	if err != nil {
		return Policy{}, err
	}
	resolvers, err := normalizeAddrPorts(in.Resolvers, "resolver")
	if err != nil {
		return Policy{}, err
	}

	wantsDestinations := len(cidrs) > 0 || in.AllowPublicInternet
	if wantsDestinations && len(ports) == 0 {
		return Policy{}, fmt.Errorf("netfilter: destinations are allowed but no ports are — " +
			"name the ports the sandbox may reach (the egress grant's --ports)")
	}

	p := Policy{Mode: modeFor(len(brokers) > 0, wantsDestinations)}

	// 1. Loopback inside the namespace. A fresh network namespace has
	// exactly one other thing on 127.0.0.0/8: the sandbox itself.
	p.Rules = append(p.Rules, Rule{
		Verdict: VerdictAllow,
		Prefix:  netip.MustParsePrefix("127.0.0.0/8"),
		Scope:   ScopeLocal,
		Reason:  "sandbox-local loopback",
	}, Rule{
		Verdict: VerdictAllow,
		Prefix:  netip.MustParsePrefix("::1/128"),
		Scope:   ScopeLocal,
		Reason:  "sandbox-local loopback",
	})

	// 2. Granted CIDRs, ahead of the drops they waive.
	for _, c := range cidrs {
		// A /0 is not a waiver, it is the removal of the block set: placed
		// ahead of the drops it would allow the metadata service, and the
		// NetworkPolicy renderer — which has no ordering and expresses the
		// block set as ipBlock excepts — could not reproduce that even if
		// it wanted to. Rather than let the two backends mean different
		// things, refuse it and name the field that does say "the Internet"
		// and says it with a warning attached.
		if c.Bits() == 0 {
			return Policy{}, fmt.Errorf(
				"netfilter: CIDR %s is not an allowlist entry — it waives every blocked range, "+
					"including the cloud metadata service. Use the public-Internet allow if that is "+
					"the intent, or name the prefixes the sandbox actually needs", c)
		}
		reason := "granted CIDR"
		if blocked := BlockReasonForPrefix(c); blocked != "" {
			reason = "granted CIDR (waives " + blocked + ")"
		}
		p.Rules = append(p.Rules, Rule{
			Verdict: VerdictAllow,
			Prefix:  c,
			Ports:   ports,
			Proto:   ProtoTCP,
			Reason:  reason,
		})
	}

	// 3. Infrastructure the sandbox cannot function without. Both are
	// pinned to a single address and port: "the broker" is one endpoint,
	// not a subnet, and widening either to a prefix would hand back the
	// lateral movement the filter exists to prevent.
	for _, b := range brokers {
		p.Rules = append(p.Rules, Rule{
			Verdict: VerdictAllow,
			Prefix:  netip.PrefixFrom(b.Addr(), b.Addr().BitLen()),
			Ports:   []uint16{b.Port()},
			Proto:   ProtoTCP,
			Reason:  "egress broker",
		})
	}
	for _, r := range resolvers {
		host := netip.PrefixFrom(r.Addr(), r.Addr().BitLen())
		p.Rules = append(p.Rules,
			Rule{Verdict: VerdictAllow, Prefix: host, Ports: []uint16{r.Port()}, Proto: ProtoUDP, Reason: "DNS resolver"},
			Rule{Verdict: VerdictAllow, Prefix: host, Ports: []uint16{r.Port()}, Proto: ProtoTCP, Reason: "DNS resolver (truncated answers retry over TCP)"},
		)
	}

	// 4. The block set. ProtoAny, because an exfiltration channel over
	// ICMP or SCTP is still an exfiltration channel.
	for _, b := range BlockedPrefixes() {
		p.Rules = append(p.Rules, Rule{
			Verdict: VerdictDrop,
			Prefix:  b.Prefix,
			Proto:   ProtoAny,
			Reason:  b.Reason,
		})
	}

	// 5. The public Internet, last, so every drop above still bites.
	if in.AllowPublicInternet {
		p.Rules = append(p.Rules,
			Rule{Verdict: VerdictAllow, Prefix: netip.MustParsePrefix("0.0.0.0/0"), Ports: ports, Proto: ProtoTCP, Reason: "public Internet"},
			Rule{Verdict: VerdictAllow, Prefix: netip.MustParsePrefix("::/0"), Ports: ports, Proto: ProtoTCP, Reason: "public Internet"},
		)
		if len(in.HostPatterns) > 0 {
			p.Warnings = append(p.Warnings, fmt.Sprintf(
				"host allowlist (%s) is not enforced by this filter: hostnames do not exist at layer 3, "+
					"so direct egress opens every public address on port %s. Route the sandbox through the "+
					"egress broker to have the host allowlist enforced.",
				strings.Join(in.HostPatterns, ", "), joinPorts(ports)))
		} else {
			p.Warnings = append(p.Warnings, fmt.Sprintf(
				"every public address is reachable on port %s; only the private, loopback, link-local, "+
					"CGNAT and metadata ranges are filtered", joinPorts(ports)))
		}
	}

	if p.Mode == ModeIsolated {
		p.Warnings = append(p.Warnings,
			"no destination is allowed: this policy drops every packet that leaves the sandbox")
	}
	if p.Mode == ModeFiltered && len(resolvers) == 0 && in.AllowPublicInternet {
		p.Warnings = append(p.Warnings,
			"no resolver is allowed, so DNS will fail: name lookups leave the sandbox on UDP/53 and this "+
				"policy drops them. Pass the sandbox's resolvers, or use the broker, which resolves on its behalf.")
	}
	return p, nil
}

func modeFor(hasBroker, hasDestinations bool) Mode {
	switch {
	case hasDestinations:
		return ModeFiltered
	case hasBroker:
		return ModeBrokered
	default:
		return ModeIsolated
	}
}

// Evaluate reports what the policy does to one packet, and why.
//
// This is the policy's own semantics, independent of any backend: the tests
// that compare this package against egressbroker's address checks call it,
// and so does `cloop egress firewall --check`. A renderer that disagrees with
// Evaluate is a renderer with a bug.
func (p Policy) Evaluate(addr netip.Addr, port uint16, proto Proto) (Verdict, string) {
	if !addr.IsValid() {
		return VerdictDrop, "invalid address"
	}
	a := addr.Unmap()
	for _, r := range p.Rules {
		if !r.matches(a, port, proto) {
			continue
		}
		return r.Verdict, r.Reason
	}
	return VerdictDrop, "default deny"
}

// WireOnly returns the policy with its namespace-local rules removed.
//
// It answers "what can leave the sandbox", which is the question the proxy's
// address checks answer too — and the only footing on which the two can be
// compared. The loopback allows are the whole difference: they permit the
// sandbox to talk to itself, a conversation that never reaches an interface
// and that the proxy, sitting on another host, has no opinion about.
func (p Policy) WireOnly() Policy {
	out := Policy{Mode: p.Mode, Warnings: p.Warnings}
	for _, r := range p.Rules {
		if r.Scope == ScopeWire {
			out.Rules = append(out.Rules, r)
		}
	}
	return out
}

// matches reports whether the rule covers this packet.
func (r Rule) matches(addr netip.Addr, port uint16, proto Proto) bool {
	if r.Prefix.Addr().Is4() != addr.Is4() {
		return false
	}
	if !r.Prefix.Contains(addr) {
		return false
	}
	// ProtoAny on the rule matches everything; otherwise the transports
	// must agree. A caller asking about ProtoAny traffic — ICMP, say — is
	// only covered by a ProtoAny rule.
	if r.Proto != ProtoAny && r.Proto != proto {
		return false
	}
	if len(r.Ports) == 0 {
		return true
	}
	for _, p := range r.Ports {
		if p == port {
			return true
		}
	}
	return false
}

// Blocked is one entry of the hard-block set: a prefix and the sentence that
// explains it.
type Blocked struct {
	Prefix netip.Prefix
	Reason string
}

// blockSet is the address space a sandbox may not reach unless its
// authorisation names an explicit CIDR covering it.
//
// It mirrors egressbroker.BlockReason prefix-for-reason, and the order is the
// same specificity-first order for the same purpose: the metadata endpoint is
// inside link-local, and "cloud metadata service" is the sentence that has to
// reach the audit log.
//
// The four IPv6 transition prefixes at the end have no counterpart in the
// proxy's block set, which unwraps them and checks the address inside. A
// packet filter cannot, so it drops them whole. See the package comment.
var blockSet = []Blocked{
	{netip.MustParsePrefix("169.254.169.254/32"), "cloud metadata service (169.254.169.254)"},
	{netip.MustParsePrefix("0.0.0.0/32"), "unspecified address"},
	{netip.MustParsePrefix("127.0.0.0/8"), "loopback"},
	{netip.MustParsePrefix("224.0.0.0/4"), "multicast"},
	{netip.MustParsePrefix("169.254.0.0/16"), "link-local"},
	{netip.MustParsePrefix("10.0.0.0/8"), "private (RFC1918/ULA)"},
	{netip.MustParsePrefix("172.16.0.0/12"), "private (RFC1918/ULA)"},
	{netip.MustParsePrefix("192.168.0.0/16"), "private (RFC1918/ULA)"},
	{netip.MustParsePrefix("100.64.0.0/10"), "carrier-grade NAT (RFC6598)"},

	{netip.MustParsePrefix("::/128"), "unspecified address"},
	{netip.MustParsePrefix("::1/128"), "loopback"},
	{netip.MustParsePrefix("ff00::/8"), "multicast"},
	{netip.MustParsePrefix("fe80::/10"), "link-local"},
	{netip.MustParsePrefix("fc00::/7"), "private (RFC1918/ULA)"},

	{netip.MustParsePrefix("64:ff9b::/96"), "NAT64 translation prefix"},
	{netip.MustParsePrefix("64:ff9b:1::/48"), "NAT64 translation prefix (RFC 8215)"},
	{netip.MustParsePrefix("::ffff:0:0:0/96"), "IPv4-translatable prefix"},
	{netip.MustParsePrefix("2002::/16"), "6to4 translation prefix"},
	{netip.MustParsePrefix("::/96"), "IPv4-compatible prefix (deprecated)"},
}

// BlockedPrefixes returns the hard-block set, in evaluation order. The slice
// is a copy: a caller that sorts or filters it cannot reach into the policy
// every sandbox on the host is compiled against.
func BlockedPrefixes() []Blocked {
	return append([]Blocked(nil), blockSet...)
}

// BlockReasonForPrefix reports why a prefix is blocked, or "" when it is not.
//
// A prefix is blocked when it is contained in a blocked one — 10.8.0.0/24 is
// private — and also when it *contains* one, because allowing 0.0.0.0/0 would
// otherwise be reported as unblocked while covering every blocked range.
func BlockReasonForPrefix(p netip.Prefix) string {
	if !p.IsValid() {
		return ""
	}
	p = p.Masked()
	for _, b := range blockSet {
		if b.Prefix.Addr().Is4() != p.Addr().Is4() {
			continue
		}
		if b.Prefix.Overlaps(p) {
			return b.Reason
		}
	}
	return ""
}

// normalizePorts sorts, de-duplicates and range-checks a port list.
func normalizePorts(ports []uint16) ([]uint16, error) {
	if len(ports) == 0 {
		return nil, nil
	}
	if len(ports) > MaxPorts {
		return nil, fmt.Errorf("netfilter: %d ports exceeds the %d-port limit", len(ports), MaxPorts)
	}
	seen := make(map[uint16]struct{}, len(ports))
	out := make([]uint16, 0, len(ports))
	for _, p := range ports {
		if p == 0 {
			return nil, fmt.Errorf("netfilter: port 0 is not a destination")
		}
		if _, dup := seen[p]; dup {
			continue
		}
		seen[p] = struct{}{}
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out, nil
}

// MaxPorts and MaxPrefixes bound a compiled policy. The limits exist because
// the rendered ruleset is handed to another program — nft, or the Kubernetes
// API server — and an unbounded list turns a config mistake into an argv
// overflow or a rejected object, neither of which reads as "your grant is
// too big".
const (
	MaxPorts    = 64
	MaxPrefixes = 256
)

// normalizePrefixes masks, de-duplicates and sorts an allow list.
//
// Masking matters: netip.Prefix.Contains is false for every address when the
// prefix has bits set below its length, so an operator who writes
// "10.8.0.5/24" would get a rule that silently matches nothing.
func normalizePrefixes(in []netip.Prefix) ([]netip.Prefix, error) {
	if len(in) == 0 {
		return nil, nil
	}
	if len(in) > MaxPrefixes {
		return nil, fmt.Errorf("netfilter: %d CIDRs exceeds the %d-entry limit", len(in), MaxPrefixes)
	}
	seen := make(map[netip.Prefix]struct{}, len(in))
	out := make([]netip.Prefix, 0, len(in))
	for _, p := range in {
		if !p.IsValid() {
			return nil, fmt.Errorf("netfilter: invalid CIDR %q", p.String())
		}
		m := netip.PrefixFrom(p.Addr().Unmap(), p.Bits())
		if p.Addr().Is4In6() {
			// Unmapping a ::ffff: address shortens it to 4 bytes, so the
			// prefix length has to come down by the 96 bits that went away.
			m = netip.PrefixFrom(p.Addr().Unmap(), p.Bits()-96)
		}
		if !m.IsValid() {
			return nil, fmt.Errorf("netfilter: invalid CIDR %q", p.String())
		}
		m = m.Masked()
		if _, dup := seen[m]; dup {
			continue
		}
		seen[m] = struct{}{}
		out = append(out, m)
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.Addr().Is4() != b.Addr().Is4() {
			return a.Addr().Is4()
		}
		if c := a.Addr().Compare(b.Addr()); c != 0 {
			return c < 0
		}
		return a.Bits() < b.Bits()
	})
	return out, nil
}

// normalizeAddrPorts validates infrastructure endpoints.
func normalizeAddrPorts(in []netip.AddrPort, kind string) ([]netip.AddrPort, error) {
	if len(in) == 0 {
		return nil, nil
	}
	if len(in) > MaxPrefixes {
		return nil, fmt.Errorf("netfilter: %d %s endpoints exceeds the %d-entry limit", len(in), kind, MaxPrefixes)
	}
	seen := make(map[netip.AddrPort]struct{}, len(in))
	out := make([]netip.AddrPort, 0, len(in))
	for _, ap := range in {
		if !ap.IsValid() {
			return nil, fmt.Errorf("netfilter: invalid %s endpoint %q", kind, ap.String())
		}
		if ap.Port() == 0 {
			return nil, fmt.Errorf("netfilter: %s endpoint %q names no port", kind, ap.String())
		}
		n := netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())
		if _, dup := seen[n]; dup {
			continue
		}
		seen[n] = struct{}{}
		out = append(out, n)
	}
	sort.Slice(out, func(i, j int) bool {
		if c := out[i].Addr().Compare(out[j].Addr()); c != 0 {
			return c < 0
		}
		return out[i].Port() < out[j].Port()
	})
	return out, nil
}

// joinPorts renders a port list for a human sentence.
func joinPorts(ports []uint16) string {
	if len(ports) == 0 {
		return "any"
	}
	parts := make([]string, len(ports))
	for i, p := range ports {
		parts[i] = fmt.Sprint(p)
	}
	return strings.Join(parts, ", ")
}
