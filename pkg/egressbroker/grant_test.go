package egressbroker

import (
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/secretbroker"
)

func testSubject(t *testing.T) secretbroker.Subject {
	t.Helper()
	sub, err := secretbroker.ParseSubject("project:/srv/app")
	if err != nil {
		t.Fatalf("parse subject: %v", err)
	}
	return sub
}

// TestValidateRequiresAnAllowDimension is the fail-closed check: a grant that
// bounds nothing cannot be created, so there is no way to end up with an
// egress policy whose meaning depends on whether an empty list reads as
// "nothing" or "everything".
func TestValidateRequiresAnAllowDimension(t *testing.T) {
	g := Grant{ID: "egress_1", Subject: testSubject(t)}
	err := g.Validate()
	if !errors.Is(err, ErrInvalidGrant) {
		t.Fatalf("want ErrInvalidGrant, got %v", err)
	}
	if !strings.Contains(err.Error(), "--hosts") {
		t.Errorf("error should tell the operator what to pass, got %q", err)
	}

	// Explicit "*" is accepted — the operator said it.
	wide := Grant{ID: "egress_1", Subject: testSubject(t), Hosts: []string{"*"}}
	if err := wide.Validate(); err != nil {
		t.Fatalf("explicit wildcard should validate: %v", err)
	}

	// A CIDR-only grant is a supported shape and must validate. It is the
	// form an operator reaches for to open an internal service —
	// "--cidrs 10.20.0.0/16 --ports 5432" with no name involved — and an
	// earlier version rejected it, because the borrowed credential-broker
	// validator enforces its own rule that an egress_proxy secret needs a
	// host list. That rule does not apply to a brokered capability.
	cidrOnly := Grant{ID: "egress_1", Subject: testSubject(t), CIDRs: []string{"10.20.0.0/16"}, Ports: []int{5432}}
	if err := cidrOnly.Validate(); err != nil {
		t.Fatalf("a CIDR-only grant must validate: %v", err)
	}
	if len(cidrOnly.Hosts) != 0 {
		t.Errorf("validation must not invent a host allowlist, got %v", cidrOnly.Hosts)
	}
}

// TestNormalizeWritesDefaultsIntoTheGrant proves the defaults are stored
// rather than applied at decision time, which is what makes `cloop egress
// list` an honest description of what will be honoured.
func TestNormalizeWritesDefaultsIntoTheGrant(t *testing.T) {
	g := Grant{ID: "egress_1", Subject: testSubject(t), Hosts: []string{"Api.Example.COM", "api.example.com"}}
	if err := g.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
	if len(g.Ports) != 2 || g.Ports[0] != 80 || g.Ports[1] != 443 {
		t.Errorf("ports should default to 80,443, got %v", g.Ports)
	}
	if len(g.Methods) != 1 || g.Methods[0] != "*" {
		t.Errorf("methods should default to [*], got %v", g.Methods)
	}
	if len(g.Hosts) != 1 || g.Hosts[0] != "api.example.com" {
		t.Errorf("hosts should be lowercased and deduped, got %v", g.Hosts)
	}
}

func TestValidateRejectsMalformedFields(t *testing.T) {
	tests := []struct {
		name string
		g    Grant
	}{
		{"bad cidr", Grant{ID: "g", Hosts: []string{"*"}, CIDRs: []string{"10.0.0.0/64"}}},
		{"cidr without mask", Grant{ID: "g", Hosts: []string{"*"}, CIDRs: []string{"10.0.0.1"}}},
		{"bad method", Grant{ID: "g", Hosts: []string{"*"}, Methods: []string{"GET;DROP"}}},
		{"host traversal", Grant{ID: "g", Hosts: []string{"../evil"}}},
		{"host with shell metachar", Grant{ID: "g", Hosts: []string{"a`b`.com"}}},
		{"empty id", Grant{Hosts: []string{"*"}}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			g := tc.g
			g.Subject = testSubject(t)
			if err := g.Validate(); err == nil {
				t.Fatal("want a validation error, got nil")
			} else if !errors.Is(err, ErrInvalidGrant) {
				t.Errorf("want ErrInvalidGrant, got %v", err)
			}
		})
	}
}

// TestCheckPortDeniesWithATypedError: the four refusal reasons the task calls
// out must be distinguishable by errors.Is, because that is what the audit
// verdict and the X-Cloop-Egress-Verdict header are derived from.
func TestCheckPortDeniesWithATypedError(t *testing.T) {
	g := Grant{Ports: []int{443}}
	if err := g.CheckPort(443); err != nil {
		t.Fatalf("443 should be allowed: %v", err)
	}
	err := g.CheckPort(22)
	if !errors.Is(err, ErrPortNotAllowed) {
		t.Fatalf("want ErrPortNotAllowed, got %v", err)
	}
	// An empty list denies rather than allowing everything.
	if err := (Grant{}).CheckPort(443); !errors.Is(err, ErrPortNotAllowed) {
		t.Errorf("empty port list must deny, got %v", err)
	}
}

func TestCheckMethod(t *testing.T) {
	tests := []struct {
		methods []string
		method  string
		allowed bool
	}{
		{[]string{"*"}, "DELETE", true},
		{[]string{"GET", "POST"}, "GET", true},
		{[]string{"GET", "POST"}, "get", true},
		{[]string{"GET", "POST"}, "DELETE", false},
		{nil, "GET", false},
	}
	for _, tc := range tests {
		g := Grant{Methods: tc.methods}
		err := g.CheckMethod(tc.method)
		if (err == nil) != tc.allowed {
			t.Errorf("CheckMethod(%q) with %v = %v, want allowed=%v", tc.method, tc.methods, err, tc.allowed)
		}
		if err != nil && !errors.Is(err, ErrMethodNotAllowed) {
			t.Errorf("want ErrMethodNotAllowed, got %v", err)
		}
	}
}

// TestCheckHostReusesTheCredentialBrokerSemantics pins the property that made
// reuse worth it: "*.example.com" means subdomains and not the apex, in both
// brokers, because there is one implementation.
func TestCheckHostReusesTheCredentialBrokerSemantics(t *testing.T) {
	g := Grant{Hosts: []string{"*.example.com"}}
	if !g.HostMatches("api.example.com") {
		t.Error("subdomain should match")
	}
	if g.HostMatches("example.com") {
		t.Error("apex must not match a *. pattern")
	}
	if g.HostMatches("notexample.com") {
		t.Error("suffix confusion must not match")
	}
	if err := g.CheckHost("evil.test"); !errors.Is(err, ErrHostNotAllowed) {
		t.Errorf("want ErrHostNotAllowed, got %v", err)
	}
	// A CIDR-only grant has no host opinion, so the name check must not
	// refuse on its own — the address check is the gate.
	if err := (Grant{CIDRs: []string{"10.0.0.0/8"}}).CheckHost("anything.test"); err != nil {
		t.Errorf("CIDR-only grant should not refuse on name: %v", err)
	}
}

func TestAllowsAddr(t *testing.T) {
	g := Grant{CIDRs: []string{"10.20.0.0/16", "2001:db8::/32"}}
	tests := []struct {
		addr string
		want bool
	}{
		{"10.20.1.1", true},
		{"10.21.1.1", false},
		{"2001:db8::1", true},
		{"2001:dead::1", false},
		// A v4-mapped v6 address must be unmapped before the prefix test,
		// or ::ffff:10.20.1.1 would silently miss an IPv4 allowlist.
		{"::ffff:10.20.1.1", true},
	}
	for _, tc := range tests {
		addr := netip.MustParseAddr(tc.addr)
		if got := g.AllowsAddr(addr); got != tc.want {
			t.Errorf("AllowsAddr(%s) = %v, want %v", tc.addr, got, tc.want)
		}
	}
	// A corrupt stored prefix must deny, not widen.
	if (Grant{CIDRs: []string{"not-a-cidr"}}).AllowsAddr(netip.MustParseAddr("1.2.3.4")) {
		t.Error("an unparseable CIDR must not match anything")
	}
}

func TestDenyReasonAndSentinel(t *testing.T) {
	now := time.Now()
	expired := Grant{ExpiresAt: now.Add(-time.Minute)}
	if expired.Active(now) {
		t.Error("an expired grant must not be active")
	}
	if !errors.Is(expired.DenySentinel(), ErrGrantExpired) {
		t.Errorf("want ErrGrantExpired, got %v", expired.DenySentinel())
	}
	revoked := Grant{ExpiresAt: now.Add(time.Hour), RevokedAt: now.Add(-time.Second)}
	if revoked.Active(now) {
		t.Error("a revoked grant must not be active")
	}
	if !errors.Is(revoked.DenySentinel(), ErrGrantRevoked) {
		t.Errorf("want ErrGrantRevoked, got %v", revoked.DenySentinel())
	}
}

// TestSessionDeadlineNeverOutlivesTheGrant is the property that makes
// revocation bounded: a session cannot be issued with a TTL that reaches past
// the authority it was issued under.
func TestSessionDeadlineNeverOutlivesTheGrant(t *testing.T) {
	now := time.Date(2026, 8, 22, 12, 0, 0, 0, time.UTC)

	grantEndsSoon := Grant{ExpiresAt: now.Add(2 * time.Minute), SessionTTL: time.Hour}
	if got := grantEndsSoon.SessionDeadline(now, time.Hour); !got.Equal(grantEndsSoon.ExpiresAt) {
		t.Errorf("session should be clamped to grant expiry, got %s", got)
	}

	ceilingBinds := Grant{ExpiresAt: now.Add(24 * time.Hour), SessionTTL: time.Hour}
	if got := ceilingBinds.SessionDeadline(now, 10*time.Minute); !got.Equal(now.Add(10 * time.Minute)) {
		t.Errorf("session should be clamped to the broker ceiling, got %s", got)
	}

	noTTL := Grant{ExpiresAt: now.Add(24 * time.Hour)}
	if got := noTTL.SessionDeadline(now, 0); !got.Equal(now.Add(DefaultSessionTTL)) {
		t.Errorf("session should fall back to the default TTL, got %s", got)
	}
}

func TestParseBytesRoundTrip(t *testing.T) {
	tests := []struct {
		in   string
		want int64
	}{
		{"", 0},
		{"0", 0},
		{"unlimited", 0},
		{"1024", 1024},
		{"64k", 64 << 10},
		{"10m", 10 << 20},
		{"2g", 2 << 30},
		{"512b", 512},
	}
	for _, tc := range tests {
		got, err := ParseBytes(tc.in)
		if err != nil {
			t.Fatalf("ParseBytes(%q): %v", tc.in, err)
		}
		if got != tc.want {
			t.Errorf("ParseBytes(%q) = %d, want %d", tc.in, got, tc.want)
		}
		if got > 0 {
			// FormatBytes must produce something ParseBytes reads back, so a
			// value copied out of a listing can be pasted into a grant.
			back, berr := ParseBytes(FormatBytes(got))
			if berr != nil || back != got {
				t.Errorf("round trip of %d via %q gave %d (%v)", got, FormatBytes(got), back, berr)
			}
		}
	}
	for _, bad := range []string{"-1", "abc", "m", "9223372036854775807g"} {
		if _, err := ParseBytes(bad); err == nil {
			t.Errorf("ParseBytes(%q) should have failed", bad)
		}
	}
}
