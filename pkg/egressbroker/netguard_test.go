package egressbroker

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sync/atomic"
	"testing"
)

// fakeResolver answers from a script, counting calls. The count is the point:
// the rebinding defence rests on resolving exactly once per request, and a
// regression that reintroduced a second lookup would otherwise pass every
// functional test in this file.
type fakeResolver struct {
	answers [][]string
	calls   atomic.Int32
	err     error
}

func (f *fakeResolver) LookupNetIP(_ context.Context, _, _ string) ([]netip.Addr, error) {
	n := int(f.calls.Add(1)) - 1
	if f.err != nil {
		return nil, f.err
	}
	if len(f.answers) == 0 {
		return nil, fmt.Errorf("no answers scripted")
	}
	// The last scripted answer repeats, so a resolver can be asked "and
	// forever after, this".
	idx := n
	if idx >= len(f.answers) {
		idx = len(f.answers) - 1
	}
	out := make([]netip.Addr, 0, len(f.answers[idx]))
	for _, s := range f.answers[idx] {
		out = append(out, netip.MustParseAddr(s))
	}
	return out, nil
}

// TestBlockReasonMatrix is the SSRF allowlist matrix: every address family
// and encoding that has ever been used to make a "public" destination reach
// inward.
func TestBlockReasonMatrix(t *testing.T) {
	tests := []struct {
		addr    string
		blocked bool
		reason  string
	}{
		// Public — the only class that may pass.
		{"93.184.216.34", false, ""},
		{"1.1.1.1", false, ""},
		{"2606:4700:4700::1111", false, ""},

		// The metadata service gets its own reason so an audit row says what
		// actually happened.
		{"169.254.169.254", true, "cloud metadata service (169.254.169.254)"},

		{"127.0.0.1", true, "loopback"},
		{"127.1.2.3", true, "loopback"},
		{"::1", true, "loopback"},
		{"0.0.0.0", true, "unspecified address"},
		{"::", true, "unspecified address"},
		{"10.0.0.1", true, "private (RFC1918/ULA)"},
		{"172.16.5.4", true, "private (RFC1918/ULA)"},
		{"192.168.1.1", true, "private (RFC1918/ULA)"},
		{"fd00::1", true, "private (RFC1918/ULA)"},
		{"169.254.1.1", true, "link-local"},
		{"fe80::1", true, "link-local"},
		{"224.0.0.1", true, "multicast"},
		{"ff02::1", true, "multicast"},
		{"100.64.0.1", true, "carrier-grade NAT (RFC6598)"},

		// The encodings. Each of these routes to a v4 address that every
		// IPv6 predicate would call public.
		{"::ffff:127.0.0.1", true, "loopback"},
		{"::ffff:10.0.0.1", true, "private (RFC1918/ULA)"},
		{"::ffff:169.254.169.254", true, "cloud metadata service (169.254.169.254)"},
		{"64:ff9b::7f00:1", true, "loopback"},       // NAT64 of 127.0.0.1
		{"64:ff9b::a9fe:a9fe", true, "cloud metadata service (169.254.169.254)"},
		{"::127.0.0.1", true, "loopback"},           // deprecated v4-compatible
		{"::a00:1", true, "private (RFC1918/ULA)"},  // ::10.0.0.1
		// The encodings an adversarial review turned up: local-use NAT64
		// (RFC 8215), IPv4-translatable (RFC 6145), and 6to4 (RFC 3056).
		// Each routes to the embedded v4 on a host configured for it.
		// RFC 6052 §2.2 splits the v4 around the reserved u-octet for a /48,
		// so 127.0.0.1 lands in bytes 6,7,9,10 — not contiguously.
		{"64:ff9b:1:7f00:0:100::", true, "loopback"},
		{"64:ff9b:1:a9fe:a9:fe00::", true, "cloud metadata service (169.254.169.254)"},
		{"::ffff:0:7f00:1", true, "loopback"},                 // IPv4-translatable
		{"::ffff:0:a00:1", true, "private (RFC1918/ULA)"},     // IPv4-translatable 10.0.0.1
		{"2002:7f00:1::1", true, "loopback"},                  // 6to4 of 127.0.0.1
		{"2002:a9fe:a9fe::1", true, "cloud metadata service (169.254.169.254)"},
		// A legitimate public address whose suffix merely looks inward must
		// still pass: the unwrapping is prefix-driven, not suffix-driven.
		{"2606:4700::7f00:1", false, ""},
	}

	for _, tc := range tests {
		t.Run(tc.addr, func(t *testing.T) {
			addr := netip.MustParseAddr(tc.addr)
			reason := BlockReason(addr)
			if (reason != "") != tc.blocked {
				t.Fatalf("BlockReason(%s) = %q, want blocked=%v", tc.addr, reason, tc.blocked)
			}
			if tc.blocked && reason != tc.reason {
				t.Errorf("BlockReason(%s) = %q, want %q", tc.addr, reason, tc.reason)
			}
		})
	}
}

// TestWildcardHostsDoNotWaiveTheBlockSet is the rule that keeps "--hosts '*'"
// from being a route to the metadata service. Reach on the public Internet is
// one decision; reach inward is a different one and has to be made
// separately.
func TestWildcardHostsDoNotWaiveTheBlockSet(t *testing.T) {
	g := Grant{Hosts: []string{"*"}, Ports: []int{80}}
	err := g.CheckAddr(MetadataIPv4, true)
	if !errors.Is(err, ErrDestinationBlocked) {
		t.Fatalf("want ErrDestinationBlocked under --hosts '*', got %v", err)
	}
	if err := g.CheckAddr(netip.MustParseAddr("10.1.2.3"), true); !errors.Is(err, ErrDestinationBlocked) {
		t.Errorf("wildcard must not reach RFC1918, got %v", err)
	}
	if err := g.CheckAddr(netip.MustParseAddr("93.184.216.34"), true); err != nil {
		t.Errorf("wildcard should reach the public Internet: %v", err)
	}
}

// TestExplicitCIDRIsTheOptIn: naming a range waives the block for exactly
// that range and nothing adjacent to it.
func TestExplicitCIDRIsTheOptIn(t *testing.T) {
	g := Grant{CIDRs: []string{"169.254.169.254/32"}, Ports: []int{80}}
	if err := g.CheckAddr(MetadataIPv4, false); err != nil {
		t.Fatalf("an explicit /32 should waive the block: %v", err)
	}
	// The neighbour is still refused: the opt-in is the range that was
	// written, not the class it belongs to.
	if err := g.CheckAddr(netip.MustParseAddr("169.254.169.253"), false); !errors.Is(err, ErrDestinationBlocked) {
		t.Errorf("an adjacent link-local address must stay blocked, got %v", err)
	}
	// And a public address is still refused, because this grant has no host
	// dimension to allow it.
	if err := g.CheckAddr(netip.MustParseAddr("93.184.216.34"), false); !errors.Is(err, ErrHostNotAllowed) {
		t.Errorf("want ErrHostNotAllowed for an unlisted public address, got %v", err)
	}
}

// TestHostsAndCIDRsComposeAsOr pins a design decision that is easy to get
// backwards, and consequential either way: the two allow dimensions are a
// union, not an intersection.
//
// So a grant carrying --cidrs 10.0.0.0/8 permits *any* name that resolves
// into 10/8, not only the names also listed in --hosts. That is what "allow
// this range" means, and requiring both would make the common case — "reach
// the internal registry, whatever it is called today" — unexpressible. The
// consequence an operator must understand is that adding a CIDR widens the
// grant by an address range, independently of the host list.
func TestHostsAndCIDRsComposeAsOr(t *testing.T) {
	g := Grant{Hosts: []string{"allowed.test"}, CIDRs: []string{"10.0.0.0/8"}, Ports: []int{443}}

	// Allowed by name, on a public address.
	if err := g.CheckAddr(netip.MustParseAddr("93.184.216.34"), true); err != nil {
		t.Errorf("a listed name on a public address should pass: %v", err)
	}
	// Allowed by CIDR alone, despite the name not being listed.
	if err := g.CheckAddr(netip.MustParseAddr("10.1.2.3"), false); err != nil {
		t.Errorf("an address inside a listed CIDR should pass regardless of name: %v", err)
	}
	// Neither dimension: refused.
	if err := g.CheckAddr(netip.MustParseAddr("93.184.216.34"), false); !errors.Is(err, ErrHostNotAllowed) {
		t.Errorf("want ErrHostNotAllowed when neither dimension matches, got %v", err)
	}
	// The CIDR waives the block for its own range only; a different private
	// range stays refused even though the name is listed.
	if err := g.CheckAddr(netip.MustParseAddr("192.168.1.1"), true); !errors.Is(err, ErrDestinationBlocked) {
		t.Errorf("want ErrDestinationBlocked for an unlisted private range, got %v", err)
	}
}

func TestResolveChecksPortBeforeLookingUpDNS(t *testing.T) {
	r := &fakeResolver{answers: [][]string{{"93.184.216.34"}}}
	g := Grant{Hosts: []string{"example.test"}, Ports: []int{443}}

	_, err := Resolve(context.Background(), r, g, "example.test", 22)
	if !errors.Is(err, ErrPortNotAllowed) {
		t.Fatalf("want ErrPortNotAllowed, got %v", err)
	}
	if n := r.calls.Load(); n != 0 {
		t.Errorf("a port refusal must not generate DNS traffic, got %d lookups", n)
	}
}

func TestResolveRefusesUnlistedHostBeforeLookingUpDNS(t *testing.T) {
	r := &fakeResolver{answers: [][]string{{"93.184.216.34"}}}
	g := Grant{Hosts: []string{"allowed.test"}, Ports: []int{443}}

	_, err := Resolve(context.Background(), r, g, "evil.test", 443)
	if !errors.Is(err, ErrHostNotAllowed) {
		t.Fatalf("want ErrHostNotAllowed, got %v", err)
	}
	if n := r.calls.Load(); n != 0 {
		t.Errorf("a host refusal must not generate DNS traffic, got %d lookups", n)
	}
}

// TestResolveResolvesExactlyOnce is the core rebinding assertion: the address
// the policy approved is the address the caller is told to dial, and there is
// no second lookup for a hostile server to answer differently.
func TestResolveResolvesExactlyOnce(t *testing.T) {
	r := &fakeResolver{answers: [][]string{
		{"93.184.216.34"}, // first answer: public, approved
		{"127.0.0.1"},     // every answer after: the rebind
	}}
	g := Grant{Hosts: []string{"example.test"}, Ports: []int{443}}

	dest, err := Resolve(context.Background(), r, g, "example.test", 443)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if got := dest.Addr.String(); got != "93.184.216.34" {
		t.Fatalf("pinned address = %s, want the first answer", got)
	}
	if dest.AddrPort() != "93.184.216.34:443" {
		t.Errorf("AddrPort = %s, want the literal to dial", dest.AddrPort())
	}
	if n := r.calls.Load(); n != 1 {
		t.Fatalf("resolved %d times; the pin only holds if it is exactly 1", n)
	}
}

// TestResolveRejectsSplitAnswers: a name that answers with both a public and
// a private address fails as a whole. Picking the public one would let a
// caller retry until the rotation handed it the other.
func TestResolveRejectsSplitAnswers(t *testing.T) {
	r := &fakeResolver{answers: [][]string{{"93.184.216.34", "127.0.0.1"}}}
	g := Grant{Hosts: []string{"example.test"}, Ports: []int{443}}

	_, err := Resolve(context.Background(), r, g, "example.test", 443)
	if !errors.Is(err, ErrDestinationBlocked) {
		t.Fatalf("want ErrDestinationBlocked for a split answer, got %v", err)
	}
	if !contains(err.Error(), "example.test") || !contains(err.Error(), "127.0.0.1") {
		t.Errorf("the error should name the host and the offending address, got %q", err)
	}
}

func TestResolveRejectsInwardAnswerForAnAllowedName(t *testing.T) {
	r := &fakeResolver{answers: [][]string{{"169.254.169.254"}}}
	g := Grant{Hosts: []string{"*"}, Ports: []int{80}}

	_, err := Resolve(context.Background(), r, g, "metadata.test", 80)
	if !errors.Is(err, ErrDestinationBlocked) {
		t.Fatalf("want ErrDestinationBlocked, got %v", err)
	}
}

func TestResolveLiteralSkipsDNS(t *testing.T) {
	r := &fakeResolver{answers: [][]string{{"127.0.0.1"}}}
	g := Grant{Hosts: []string{"*"}, CIDRs: []string{"10.0.0.0/8"}, Ports: []int{443}}

	dest, err := Resolve(context.Background(), r, g, "10.1.2.3", 443)
	if err != nil {
		t.Fatalf("resolve literal: %v", err)
	}
	if !dest.Literal {
		t.Error("an address literal should be flagged as such")
	}
	if n := r.calls.Load(); n != 0 {
		t.Errorf("a literal must not be looked up, got %d lookups", n)
	}
	if dest.Addr.String() != "10.1.2.3" {
		t.Errorf("pinned = %s", dest.Addr)
	}
}

func TestResolveFailurePropagatesTypedError(t *testing.T) {
	r := &fakeResolver{err: errors.New("no such host")}
	g := Grant{Hosts: []string{"*"}, Ports: []int{443}}

	if _, err := Resolve(context.Background(), r, g, "nx.test", 443); !errors.Is(err, ErrResolveFailed) {
		t.Fatalf("want ErrResolveFailed, got %v", err)
	}
	empty := &fakeResolver{answers: [][]string{{}}}
	if _, err := Resolve(context.Background(), empty, g, "nx.test", 443); !errors.Is(err, ErrResolveFailed) {
		t.Fatalf("want ErrResolveFailed for an empty answer, got %v", err)
	}
}

func contains(haystack, needle string) bool {
	return len(needle) == 0 || (len(haystack) >= len(needle) &&
		func() bool {
			for i := 0; i+len(needle) <= len(haystack); i++ {
				if haystack[i:i+len(needle)] == needle {
					return true
				}
			}
			return false
		}())
}
