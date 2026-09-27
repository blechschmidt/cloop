package executor

// firewall.go is the editable form of an executor's IP-layer egress firewall
// (Task 20345): the allowlist and denylist an admin types into a form.
//
// # Why this is not netfilter.Input
//
// netfilter.Input is the compiled authorisation — parsed prefixes and ports,
// ready for a rule generator. It is the right shape for a compiler and the
// wrong one for a form, a database row or a start frame: an admin types
// "10.0.0.0/8", and when they mistype it they need to be told which field and
// which line was wrong rather than handed a decode error for the whole body.
// So FirewallRules is strings and ints that round-trip through JSON unchanged,
// and Normalize is the one parser. The container driver converts the
// normalized form into its EgressFilter, which compiles it with
// pkg/netfilter — the same compiler, and so the same semantics, the hub's own
// container executor has used since Task 20186.
//
// # Semantics, in one paragraph
//
// Nothing is reachable unless an allow names it. AllowPublicInternet opens
// every address outside the hard-block set (RFC1918, link-local and the cloud
// metadata endpoint, CGNAT, loopback, multicast); AllowCIDRs open specific
// ranges and are the only thing that reaches into blocked space; Resolvers are
// opened on UDP and TCP and are also what the sandbox is told to resolve
// through. DenyCIDRs are dropped before any of that is consulted, so a denied
// range is unreachable however the allows are written. AllowPorts bounds the
// allows; empty means every port, because in this form the address list is
// the bound an admin is drawing and a mandatory port list would only invite
// "1-65535" typed by hand.

import (
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"
)

// Firewall list bounds. They mirror pkg/netfilter's, which are the real limit
// — the rendered ruleset goes to nft(8) — and are restated here so a form is
// refused naming the field at the moment it is submitted, rather than a
// dispatch failing on a compile error minutes later on a device.
const (
	MaxFirewallCIDRs     = 256
	MaxFirewallPorts     = 64
	MaxFirewallResolvers = 16
)

// FirewallRules is an editable IP-layer egress policy.
//
// The zero value allows nothing: a sandbox under it has an interface and no
// destination. That is the deliberate default for a stored rule set, and the
// opposite of an absent one — a nil *FirewallRules means "no firewall", which
// is a different decision (see VirtualSpec.Firewall).
type FirewallRules struct {
	// AllowPublicInternet opens every address outside the hard-block set.
	AllowPublicInternet bool `json:"allow_public_internet,omitempty"`
	// AllowCIDRs is the IP allowlist: ranges the sandbox may reach directly,
	// including private ones. A bare address is read as a single host.
	AllowCIDRs []string `json:"allow_cidrs,omitempty"`
	// DenyCIDRs is the IP denylist: ranges the sandbox may never reach,
	// whatever else is allowed.
	DenyCIDRs []string `json:"deny_cidrs,omitempty"`
	// AllowPorts bounds every allow above to these destination ports. Empty
	// means any port.
	AllowPorts []int `json:"allow_ports,omitempty"`
	// Resolvers are DNS servers the sandbox may query and is configured to
	// use, as address literals with an optional port (default 53).
	Resolvers []string `json:"resolvers,omitempty"`
}

// HasDestination reports whether the rules make anything reachable.
func (r FirewallRules) HasDestination() bool {
	return r.AllowPublicInternet || len(r.AllowCIDRs) > 0 || len(r.Resolvers) > 0
}

// Normalize returns the canonical form: trimmed, parsed, masked, deduplicated
// and sorted. Every comparison and every rendered rule downstream works on
// this form, so "10.1.2.3/8" and "10.0.0.0/8" are the same range everywhere.
//
// Errors name the field and the zero-based index, because that is what a form
// can attach to an input.
func (r FirewallRules) Normalize() (FirewallRules, error) {
	out := FirewallRules{AllowPublicInternet: r.AllowPublicInternet}

	var err error
	if out.AllowCIDRs, err = normalizeCIDRList("allow_cidrs", r.AllowCIDRs, false); err != nil {
		return FirewallRules{}, err
	}
	if out.DenyCIDRs, err = normalizeCIDRList("deny_cidrs", r.DenyCIDRs, true); err != nil {
		return FirewallRules{}, err
	}

	if len(r.AllowPorts) > MaxFirewallPorts {
		return FirewallRules{}, fmt.Errorf("%w: allow_ports: %d entries exceeds the maximum of %d",
			ErrInvalidSpec, len(r.AllowPorts), MaxFirewallPorts)
	}
	seenPort := map[int]bool{}
	for i, p := range r.AllowPorts {
		if p <= 0 || p > 65535 {
			return FirewallRules{}, fmt.Errorf("%w: allow_ports[%d]: %d is not a port (1-65535)",
				ErrInvalidSpec, i, p)
		}
		if !seenPort[p] {
			seenPort[p] = true
			out.AllowPorts = append(out.AllowPorts, p)
		}
	}
	sort.Ints(out.AllowPorts)

	if len(r.Resolvers) > MaxFirewallResolvers {
		return FirewallRules{}, fmt.Errorf("%w: resolvers: %d entries exceeds the maximum of %d",
			ErrInvalidSpec, len(r.Resolvers), MaxFirewallResolvers)
	}
	seenRes := map[string]bool{}
	for i, raw := range r.Resolvers {
		s := strings.TrimSpace(raw)
		if s == "" {
			continue
		}
		ap, err := ParseResolver(s)
		if err != nil {
			return FirewallRules{}, fmt.Errorf("%w: resolvers[%d]: %q: %v", ErrInvalidSpec, i, raw, err)
		}
		key := ap.String()
		if !seenRes[key] {
			seenRes[key] = true
			out.Resolvers = append(out.Resolvers, key)
		}
	}
	sort.Strings(out.Resolvers)
	return out, nil
}

// Validate reports whether the rules are admissible.
func (r FirewallRules) Validate() error {
	_, err := r.Normalize()
	return err
}

// normalizeCIDRList parses one list. allowAll admits a /0, which is a strange
// deny and a legitimate one, and is refused as an allow because "every
// address" is what AllowPublicInternet says with the hard-block set still in
// force — a /0 allow would waive the metadata service along with everything
// else.
func normalizeCIDRList(field string, in []string, allowAll bool) ([]string, error) {
	if len(in) > MaxFirewallCIDRs {
		return nil, fmt.Errorf("%w: %s: %d entries exceeds the maximum of %d",
			ErrInvalidSpec, field, len(in), MaxFirewallCIDRs)
	}
	var out []string
	seen := map[string]bool{}
	for i, raw := range in {
		s := strings.TrimSpace(raw)
		if s == "" {
			continue
		}
		p, err := ParseFirewallPrefix(s)
		if err != nil {
			return nil, fmt.Errorf("%w: %s[%d]: %v", ErrInvalidSpec, field, i, err)
		}
		if p.Bits() == 0 && !allowAll {
			return nil, fmt.Errorf("%w: %s[%d]: %s would waive every blocked range, including the "+
				"cloud metadata service; use allow_public_internet for \"the Internet\" and keep "+
				"the block set in force", ErrInvalidSpec, field, i, p)
		}
		key := p.String()
		if !seen[key] {
			seen[key] = true
			out = append(out, key)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := netip.MustParsePrefix(out[i]), netip.MustParsePrefix(out[j])
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

// ParseFirewallPrefix accepts a CIDR or a bare address and returns it masked.
//
// A bare address is read as a single host because "block 203.0.113.9" is a
// thing an admin means, and forcing them to write /32 invites the typo /3 —
// eight million times wider, and nearly identical on screen. Masking matters
// for more than tidiness: netip.Prefix.Contains is false for every address
// when bits are set below the length, so an unmasked 10.8.0.5/24 would be a
// rule that silently matches nothing.
func ParseFirewallPrefix(s string) (netip.Prefix, error) {
	s = strings.TrimSpace(s)
	if p, err := netip.ParsePrefix(s); err == nil {
		if p.Addr().Is4In6() {
			// ::ffff:10.0.0.0/104 and 10.0.0.0/8 are the same addresses; keep
			// one spelling so containment and deduplication stay exact.
			if p.Bits() < 96 {
				return netip.Prefix{}, fmt.Errorf("%q mixes IPv4-mapped and native IPv6 space", s)
			}
			return netip.PrefixFrom(p.Addr().Unmap(), p.Bits()-96).Masked(), nil
		}
		return p.Masked(), nil
	}
	if a, err := netip.ParseAddr(s); err == nil {
		a = a.Unmap()
		return netip.PrefixFrom(a, a.BitLen()), nil
	}
	return netip.Prefix{}, fmt.Errorf("%q is not a CIDR (want a form like 10.0.0.0/8, 2001:db8::/32 "+
		"or a single address)", s)
}

// ParseResolver accepts "addr" or "addr:port" ("[v6]:port" for IPv6), with the
// port defaulting to 53.
//
// Address literals only, never names: a packet filter matches addresses, and
// resolving a name here would pin it silently at configuration time — a DNS
// rebinding hazard dressed up as a convenience.
func ParseResolver(s string) (netip.AddrPort, error) {
	s = strings.TrimSpace(s)
	if ap, err := netip.ParseAddrPort(s); err == nil {
		if ap.Port() == 0 {
			return netip.AddrPort{}, fmt.Errorf("port 0 is not a resolver port")
		}
		return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port()), nil
	}
	if a, err := netip.ParseAddr(s); err == nil {
		return netip.AddrPortFrom(a.Unmap(), 53), nil
	}
	return netip.AddrPort{}, fmt.Errorf("want an address literal (1.1.1.1) or address:port " +
		"(1.1.1.1:53); host names are not accepted because a packet filter matches addresses")
}

// Describe renders the rules for a log line, an audit row or a card.
func (r FirewallRules) Describe() string {
	var parts []string
	if r.AllowPublicInternet {
		parts = append(parts, "public Internet")
	}
	if n := len(r.AllowCIDRs); n > 0 {
		parts = append(parts, "allow "+strings.Join(r.AllowCIDRs, ","))
	}
	if n := len(r.DenyCIDRs); n > 0 {
		parts = append(parts, "deny "+strings.Join(r.DenyCIDRs, ","))
	}
	if len(r.AllowPorts) > 0 {
		ps := make([]string, len(r.AllowPorts))
		for i, p := range r.AllowPorts {
			ps[i] = strconv.Itoa(p)
		}
		parts = append(parts, "ports "+strings.Join(ps, ","))
	}
	if len(r.Resolvers) > 0 {
		parts = append(parts, "dns "+strings.Join(r.Resolvers, ","))
	}
	if len(parts) == 0 {
		return "no destination allowed"
	}
	return strings.Join(parts, "; ")
}
