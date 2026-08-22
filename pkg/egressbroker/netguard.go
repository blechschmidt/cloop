package egressbroker

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strings"
)

// netguard.go holds the address policy: which destinations are refused
// regardless of the host allowlist, and how a name is turned into the single
// address the proxy will actually dial.
//
// The threat it answers is DNS rebinding. A proxy that checks "is
// evil.example allowed?" against a name and then hands that same name to
// net.Dial has performed two lookups, and an attacker controlling the
// authoritative server only has to answer the second one differently. Every
// check below therefore operates on addresses, and the dial goes to an
// address literal that was itself checked — there is no second lookup to
// poison.

// MetadataIPv4 is the cloud instance metadata endpoint. It is inside
// link-local and would be blocked by that rule alone; it is named separately
// so the denial says "metadata service" rather than "link-local", because
// that is the sentence an operator needs to see in an audit log.
var MetadataIPv4 = netip.MustParseAddr("169.254.169.254")

// The IPv6 ranges that carry an IPv4 address inside them.
//
// Each is a way to write "127.0.0.1" that no IPv6 predicate recognises, so
// normalizeAddr unwraps them all before any check runs. They are enumerated
// rather than approximated by "check the low 32 bits of every IPv6 address",
// which would misread a legitimate public address whose suffix happens to
// look like an RFC1918 one (2606:4700::7f00:1 is not loopback).
var (
	// nat64WKP is the well-known NAT64 prefix (RFC 6052 §2.1), v4 in the
	// low 32 bits.
	nat64WKP = netip.MustParsePrefix("64:ff9b::/96")
	// nat64LocalUse is the local-use NAT64 prefix (RFC 8215). It is a /48,
	// so RFC 6052 §2.2 scatters the v4 around the reserved u-octet at
	// bits 64-71 rather than placing it contiguously.
	nat64LocalUse = netip.MustParsePrefix("64:ff9b:1::/48")
	// v4Translated is the IPv4-translatable form (RFC 6145), distinct from
	// the v4-mapped ::ffff:0:0/96 that Addr.Unmap already handles.
	v4Translated = netip.MustParsePrefix("::ffff:0:0:0/96")
	// sixToFour is RFC 3056, which embeds the v4 address in bits 16-47.
	// Deprecated, and still worth unwrapping: a host with a 6to4 route
	// configured will happily forward it.
	sixToFour = netip.MustParsePrefix("2002::/16")
)

// cgnatPrefix is RFC 6598 carrier-grade NAT space. Not private by Go's
// definition, but it is not the public Internet either: on a cloud host it
// routes to infrastructure the tenant does not own.
var cgnatPrefix = netip.MustParsePrefix("100.64.0.0/10")

// normalizeAddr reduces an address to the form the policy predicates
// understand, unwrapping every encoding that hides an IPv4 address inside an
// IPv6 one.
//
// They all matter for the same reason: ::ffff:127.0.0.1, 64:ff9b::7f00:1 and
// ::127.0.0.1 are IPv6 addresses that a suitably-configured kernel will
// happily route to the v4 loopback, and neither Addr.IsLoopback nor
// Addr.IsPrivate says yes to any of them.
func normalizeAddr(addr netip.Addr) netip.Addr {
	addr = addr.Unmap()
	if !addr.Is6() {
		return addr
	}
	b := addr.As16()
	switch {
	case nat64WKP.Contains(addr), v4Translated.Contains(addr):
		return netip.AddrFrom4([4]byte{b[12], b[13], b[14], b[15]})
	case sixToFour.Contains(addr):
		return netip.AddrFrom4([4]byte{b[2], b[3], b[4], b[5]})
	case nat64LocalUse.Contains(addr):
		// RFC 6052 §2.2: for a /48 prefix the v4 occupies bits 48-63 and
		// 72-95, skipping the reserved u-octet at byte 8.
		return netip.AddrFrom4([4]byte{b[6], b[7], b[9], b[10]})
	}
	// The deprecated "IPv4-compatible" form (::a.b.c.d): twelve zero bytes
	// followed by a v4 address. Excluded are :: itself and ::1, which the
	// unspecified and loopback predicates already name correctly.
	if !addr.IsUnspecified() && !addr.IsLoopback() {
		allZero := true
		for _, v := range b[:12] {
			if v != 0 {
				allZero = false
				break
			}
		}
		if allZero {
			return netip.AddrFrom4([4]byte{b[12], b[13], b[14], b[15]})
		}
	}
	return addr
}

// BlockReason classifies an address against the hard-block set and returns a
// human-readable reason, or "" when the address is on the public Internet.
//
// Ordering is by specificity, not by prefix length: the reason text is what
// lands in the audit log and in the operator's terminal, so "cloud metadata
// service" beats the technically-equally-true "link-local".
func BlockReason(addr netip.Addr) string {
	if !addr.IsValid() {
		return "invalid address"
	}
	a := normalizeAddr(addr)

	switch {
	case a == MetadataIPv4:
		return "cloud metadata service (169.254.169.254)"
	case a.IsUnspecified():
		return "unspecified address"
	case a.IsLoopback():
		return "loopback"
	// Multicast is tested before link-local unicast because 224.0.0.0/24 and
	// ff02::/16 satisfy both predicates, and "link-local" would be the less
	// useful half of the truth in an audit row.
	case a.IsInterfaceLocalMulticast(), a.IsLinkLocalMulticast(), a.IsMulticast():
		return "multicast"
	case a.IsLinkLocalUnicast():
		return "link-local"
	case a.IsPrivate():
		return "private (RFC1918/ULA)"
	case a.Is4() && cgnatPrefix.Contains(a):
		return "carrier-grade NAT (RFC6598)"
	default:
		return ""
	}
}

// CheckAddr is the address gate: it applies the hard-block set, then the
// grant's own dimensions.
//
// The order is deliberate. The block set is consulted first and can only be
// waived by an explicit CIDR in the grant — never by the host allowlist. That
// is what stops "--hosts '*'" from being a route to the metadata service:
// wildcards buy reach on the public Internet, and nothing else.
//
// hostAllowed carries the result of the name-level check so the two allow
// dimensions compose. A destination is authorised when its name matched, or
// when its address is inside an allowed CIDR.
func (g Grant) CheckAddr(addr netip.Addr, hostAllowed bool) error {
	a := normalizeAddr(addr)
	inCIDR := g.AllowsAddr(a)

	if reason := BlockReason(a); reason != "" && !inCIDR {
		return fmt.Errorf("%w: %s is %s; add an explicit --cidrs entry to allow it",
			ErrDestinationBlocked, a, reason)
	}
	if !hostAllowed && !inCIDR {
		return fmt.Errorf("%w: %s matches neither the host allowlist (%s) nor an allowed CIDR (%s)",
			ErrHostNotAllowed, a,
			joinOrNone(g.Hosts), joinOrNone(g.CIDRs))
	}
	return nil
}

func joinOrNone(vals []string) string {
	if len(vals) == 0 {
		return "none"
	}
	return strings.Join(vals, ", ")
}

// Resolver is the DNS interface the proxy depends on. Narrowing it to the one
// method used lets a test substitute a resolver that answers differently on
// each call — which is exactly the rebinding attack, and exactly what the
// resolve-once discipline is meant to survive.
type Resolver interface {
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}

// Destination is an authorised, pinned destination: the name the client
// asked for, and the single address that will be dialled for it.
type Destination struct {
	// Host is the requested name (or address literal), lowercased.
	Host string
	Port int
	// Addr is the resolved address the dial will target. Every other
	// address the name resolved to was checked too — see Resolve.
	Addr netip.Addr
	// Resolved is the full answer set, for the audit trail.
	Resolved []netip.Addr
	// Literal reports whether Host was already an address, so no lookup
	// happened and there is nothing to rebind.
	Literal bool
}

// AddrPort renders the pinned destination for net.Dial.
func (d Destination) AddrPort() string {
	return netip.AddrPortFrom(d.Addr, uint16(d.Port)).String()
}

// String renders "host:port" for logs and audit rows.
func (d Destination) String() string {
	return net.JoinHostPort(d.Host, fmt.Sprint(d.Port))
}

// Resolve turns a requested host:port into a pinned, authorised Destination,
// or returns the typed reason it may not be reached.
//
// The rules, in order:
//
//  1. The port must be allowed. Checked first because it is free and needs no
//     network traffic — a grant that permits only 443 should not generate a
//     DNS query for a request to port 22.
//  2. The name must be on the host allowlist, unless the grant is
//     CIDR-only. Also free, also before any lookup.
//  3. The name is resolved exactly once.
//  4. *Every* returned address must pass CheckAddr. Not just the one that
//     will be dialled: a name that answers with a mix of public and private
//     addresses is either misconfigured or hostile, and picking the public
//     one would let the sandbox retry until the resolver's rotation handed it
//     the other. Failing the whole name is the only reading with no race in
//     it.
//  5. The first surviving address is pinned, and the caller dials that
//     literal.
func Resolve(ctx context.Context, r Resolver, g Grant, host string, port int) (Destination, error) {
	host = strings.ToLower(strings.TrimSpace(strings.TrimSuffix(host, ".")))
	if host == "" {
		return Destination{}, fmt.Errorf("%w: empty destination host", ErrInvalidRequest)
	}
	if err := g.CheckPort(port); err != nil {
		return Destination{}, err
	}

	hostAllowed := g.HostMatches(host)
	// With no host patterns at all the grant is CIDR-only and has no opinion
	// on names; the address check below is then the whole gate.
	if len(g.Hosts) > 0 && !hostAllowed && len(g.CIDRs) == 0 {
		return Destination{}, g.CheckHost(host)
	}

	if addr, err := netip.ParseAddr(host); err == nil {
		if cerr := g.CheckAddr(addr, hostAllowed); cerr != nil {
			return Destination{}, cerr
		}
		norm := normalizeAddr(addr)
		return Destination{
			Host: host, Port: port, Addr: norm,
			Resolved: []netip.Addr{norm}, Literal: true,
		}, nil
	}

	if r == nil {
		r = net.DefaultResolver
	}
	addrs, err := r.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return Destination{}, fmt.Errorf("%w: %s: %v", ErrResolveFailed, host, err)
	}
	if len(addrs) == 0 {
		return Destination{}, fmt.Errorf("%w: %s resolved to no addresses", ErrResolveFailed, host)
	}

	resolved := make([]netip.Addr, 0, len(addrs))
	for _, a := range addrs {
		norm := normalizeAddr(a)
		if !norm.IsValid() {
			return Destination{}, fmt.Errorf("%w: %s resolved to an invalid address", ErrResolveFailed, host)
		}
		if cerr := g.CheckAddr(norm, hostAllowed); cerr != nil {
			// Name the host as well as the address: "93.184.216.34 is
			// loopback" is confusing, "example.test resolved to 127.0.0.1"
			// is the finding.
			return Destination{}, fmt.Errorf("%s resolved to %s: %w", host, norm, cerr)
		}
		resolved = append(resolved, norm)
	}

	return Destination{
		Host: host, Port: port, Addr: resolved[0], Resolved: resolved,
	}, nil
}

// DialFunc is the connection factory the proxy uses. Tests replace it to
// avoid touching the real network; production leaves it nil and gets a
// net.Dialer.
type DialFunc func(ctx context.Context, network, addr string) (net.Conn, error)
