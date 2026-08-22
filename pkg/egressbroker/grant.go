// Package egressbroker leases the control plane's Internet connection to
// isolated executors through an authenticated forward proxy.
//
// It closes the last gap in the grantable-resource set. pkg/secretbroker
// brokers GitHub repositories, PATs, and Kubernetes clusters; network egress
// was the missing pillar, and it is the one that matters most for isolation,
// because a sandbox that needs the network has until now had to be given a
// network — which means all of it.
//
// The shape of the answer is a proxy rather than a firewall rule. A container
// or Pod runs with --network=none-style isolation and no route of its own; it
// reaches the outside world only by asking the control plane, which decides
// per connection. That inverts the usual arrangement: the sandbox has no
// egress capability to lose, and the allowlist lives somewhere the workload
// cannot edit.
//
// Three types, mirroring pkg/secretbroker so the two read alike:
//
//	Grant    who may make outbound connections, to which hosts, ports, and
//	         methods, under what byte quota, until when.
//	Session  a short-lived redemption of a matching grant, carrying a
//	         single-use proxy credential and live byte counters.
//	Proxy    the enforcement point: an HTTP forward proxy speaking CONNECT
//	         for TLS and absolute-URI GET/POST/... for plain HTTP.
//
// What is actually enforced, honestly scoped:
//
//   - Host, port, and method are checked before a single byte leaves.
//   - The destination name is resolved exactly once, every returned address
//     is checked, and the dial goes to the resolved literal — so a name that
//     answers "93.184.216.34" to the policy check and "127.0.0.1" to the dial
//     has nowhere to put the second answer. See netguard.go.
//   - Loopback, RFC1918, CGNAT, link-local (which is where the cloud metadata
//     service at 169.254.169.254 lives), multicast, and unspecified addresses
//     are refused unless an allowed CIDR explicitly covers them.
//   - Byte quotas are enforced during the copy, so an over-quota transfer is
//     cut mid-stream rather than noticed afterwards.
//   - A session's TTL applies to open tunnels, not just to new connections.
//
// What is not enforced: anything inside a CONNECT tunnel. Those bytes are
// TLS, cloop does not hold the origin's key, and no CA is installed in the
// sandbox — deliberately, because a proxy that could read the tunnel would be
// a far more valuable thing to compromise than the credential it protects.
// So Grant.Methods gates plain HTTP only, and the tunnel is authorised at its
// host:port and then accounted, not inspected.
package egressbroker

import (
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/secretbroker"
)

// DefaultPorts is what a grant gets when the operator names no ports. It is
// written into the stored grant rather than applied at decision time, so
// `cloop egress list` shows the ports that will actually be honoured and
// there is no invisible default to be surprised by later.
var DefaultPorts = []int{80, 443}

// MaxHostPatterns bounds an allowlist. The limit exists because every
// pattern is walked on every connection; it is generous enough that no
// legitimate grant reaches it.
const MaxHostPatterns = 256

// Grant authorises one subject to make outbound connections through the
// proxy, under constraints, until ExpiresAt.
//
// Subject reuses pkg/secretbroker's: an egress grant is aimed at a project,
// an executor, or a labelled fleet by exactly the same rules as a credential
// grant, and an operator should not have to learn a second targeting syntax
// for the second resource.
type Grant struct {
	ID string `json:"id"`
	// Scope is a free-form operator label ("ci", "deps"). It carries no
	// authorisation weight, so editing it cannot widen the grant.
	Scope   string               `json:"scope,omitempty"`
	Subject secretbroker.Subject `json:"subject"`

	// Hosts is the destination allowlist, in pkg/secretbroker's host syntax:
	// an exact name, "*.example.com" for subdomains only (not the apex), or
	// "*" for everything. Matching is delegated to
	// secretbroker.Constraints.CheckHost so that "which hosts does this
	// pattern cover" has exactly one definition in the codebase.
	Hosts []string `json:"hosts,omitempty"`

	// CIDRs is a second, address-level allow dimension, and the *only* way
	// to reach a private address.
	//
	// A destination is authorised when its hostname matches Hosts or its
	// resolved address falls inside one of these prefixes. Listing a private
	// prefix here is what waives the SSRF block for that prefix and nothing
	// else — which is why there is no blanket allow_private flag. "Let this
	// sandbox reach the metadata service" should be a sentence an operator
	// has to write out as 169.254.169.254/32, not a checkbox.
	CIDRs []string `json:"cidrs,omitempty"`

	// Ports is the destination port allowlist. Never empty after Normalize.
	Ports []int `json:"ports,omitempty"`

	// Methods gates plain-HTTP requests. "*" allows every method.
	//
	// It does not, and cannot, gate a CONNECT tunnel: the method lives
	// inside the TLS record layer. Normalize writes "*" rather than leaving
	// the field empty so that a listing never implies a restriction that is
	// not there.
	Methods []string `json:"methods,omitempty"`

	// MaxBytesUp and MaxBytesDown cap one session's transfer, in bytes,
	// counted from the sandbox's point of view: "up" is what it sends. Zero
	// means unlimited.
	MaxBytesUp   int64 `json:"max_bytes_up,omitempty"`
	MaxBytesDown int64 `json:"max_bytes_down,omitempty"`

	// SessionTTL bounds one redemption. Zero means the broker's default.
	// The split from ExpiresAt is the same one pkg/secretbroker draws
	// between grant and lease: a day-long authorisation does not imply a
	// day-long credential in a sandbox.
	SessionTTL time.Duration `json:"session_ttl,omitempty"`

	ExpiresAt time.Time `json:"expires_at,omitempty"`
	CreatedAt time.Time `json:"created_at"`
	CreatedBy string    `json:"created_by,omitempty"`
	RevokedAt time.Time `json:"revoked_at,omitempty"`
}

// Normalize canonicalises a grant and fills in the defaults that must be
// visible in storage rather than applied silently at decision time.
//
// It is called by Validate, so anything that reaches the store has already
// been through it.
func (g *Grant) Normalize() {
	g.Scope = strings.TrimSpace(g.Scope)
	g.Hosts = normalizePatterns(g.Hosts)
	g.CIDRs = normalizePatterns(g.CIDRs)

	g.Ports = dedupePorts(g.Ports)
	if len(g.Ports) == 0 {
		g.Ports = append([]int(nil), DefaultPorts...)
	}

	methods := make([]string, 0, len(g.Methods))
	seen := make(map[string]bool, len(g.Methods))
	for _, m := range g.Methods {
		m = strings.ToUpper(strings.TrimSpace(m))
		if m == "" || seen[m] {
			continue
		}
		seen[m] = true
		methods = append(methods, m)
	}
	if len(methods) == 0 {
		methods = []string{"*"}
	}
	sort.Strings(methods)
	g.Methods = methods

	if g.MaxBytesUp < 0 {
		g.MaxBytesUp = 0
	}
	if g.MaxBytesDown < 0 {
		g.MaxBytesDown = 0
	}
	if g.SessionTTL < 0 {
		g.SessionTTL = 0
	}
}

func normalizePatterns(in []string) []string {
	out := make([]string, 0, len(in))
	seen := make(map[string]bool, len(in))
	for _, p := range in {
		p = strings.ToLower(strings.TrimSpace(p))
		if p == "" || seen[p] {
			continue
		}
		seen[p] = true
		out = append(out, p)
	}
	sort.Strings(out)
	if len(out) == 0 {
		return nil
	}
	return out
}

func dedupePorts(in []int) []int {
	out := make([]int, 0, len(in))
	seen := make(map[int]bool, len(in))
	for _, p := range in {
		if p <= 0 || p > 65535 || seen[p] {
			continue
		}
		seen[p] = true
		out = append(out, p)
	}
	sort.Ints(out)
	if len(out) == 0 {
		return nil
	}
	return out
}

// Validate normalises the grant and checks its invariants.
//
// A grant with neither hosts nor CIDRs is rejected rather than treated as
// "allow nothing" or "allow everything": both readings are defensible, which
// is precisely why the operator has to say. Pass --hosts '*' to mean it.
func (g *Grant) Validate() error {
	g.Normalize()

	if strings.TrimSpace(g.ID) == "" {
		return fmt.Errorf("%w: grant id is empty", ErrInvalidGrant)
	}
	if err := g.Subject.Validate(); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidGrant, err)
	}
	if len(g.Hosts) == 0 && len(g.CIDRs) == 0 {
		return fmt.Errorf(
			"%w: an egress grant needs --hosts and/or --cidrs (pass --hosts '*' to allow everything)",
			ErrInvalidGrant)
	}
	if len(g.Hosts) > MaxHostPatterns || len(g.CIDRs) > MaxHostPatterns {
		return fmt.Errorf("%w: allowlist exceeds %d entries", ErrInvalidGrant, MaxHostPatterns)
	}

	// Host patterns go through the credential broker's own validator, which
	// bounds the charset and rejects traversal tokens and malformed globs.
	// Sharing it means an egress allowlist cannot express a pattern a
	// credential allowlist would have refused.
	//
	// The guard is not just an optimisation: ValidateFor(KindEgressProxy)
	// also enforces *its* gating rule, that an egress_proxy secret must carry
	// a host allowlist. That rule is right for a proxy URL handed to a
	// workload and wrong here, where a CIDR-only grant is a supported shape —
	// so only the pattern validation is borrowed, and the fail-closed gate is
	// the len(Hosts)+len(CIDRs) check above.
	if len(g.Hosts) > 0 {
		if err := (secretbroker.Constraints{Hosts: g.Hosts}).ValidateFor(secretbroker.KindEgressProxy); err != nil {
			return fmt.Errorf("%w: %v", ErrInvalidGrant, err)
		}
	}

	for _, c := range g.CIDRs {
		p, err := netip.ParsePrefix(c)
		if err != nil {
			return fmt.Errorf("%w: %q is not a CIDR prefix (want 10.0.0.0/8 or 2001:db8::/32)",
				ErrInvalidGrant, c)
		}
		if err := validateAllowPrefix(p); err != nil {
			return fmt.Errorf("%w: %v", ErrInvalidGrant, err)
		}
	}
	for _, m := range g.Methods {
		if m == "*" {
			continue
		}
		if !validMethodToken(m) {
			return fmt.Errorf("%w: %q is not an HTTP method token", ErrInvalidGrant, m)
		}
	}
	if !g.ExpiresAt.IsZero() && !g.CreatedAt.IsZero() && !g.ExpiresAt.After(g.CreatedAt) {
		return fmt.Errorf("%w: grant %s expires at or before its creation time", ErrInvalidGrant, g.ID)
	}
	return nil
}

// validateAllowPrefix refuses the two CIDR shapes that turn the allow list
// into a bypass of the hard-block set.
//
// CheckAddr lets an explicit CIDR waive the block set, and the field's own
// documentation explains why that is safe: waiving "for that prefix and
// nothing else" is why there is no blanket allow_private flag, and why
// reaching the metadata service is meant to be a sentence an operator writes
// out as 169.254.169.254/32. Two prefixes break that promise:
//
//   - 0.0.0.0/0 and ::/0 waive every blocked range at once. That is the
//     blanket flag, spelled differently.
//   - any prefix that merely *contains* 169.254.169.254 — 169.254.0.0/16,
//     say — reaches the credentials of the host the hub runs on without ever
//     naming it. On a cloud instance that is the whole account.
//
// Refusing them here rather than at CheckAddr keeps the rejection where an
// operator sees it, at grant time, with a message that says what to write
// instead. pkg/netfilter refuses the same shapes for the same reason, which
// is what lets the packet filter and the proxy stay in agreement.
func validateAllowPrefix(p netip.Prefix) error {
	if p.Bits() == 0 {
		return fmt.Errorf(
			"CIDR %s is not an allowlist entry — it waives every blocked range, including the "+
				"cloud metadata service. Pass --hosts '*' to allow the public Internet, or name "+
				"the prefixes the sandbox actually needs", p)
	}
	if p.Contains(MetadataIPv4) && p.Bits() != p.Addr().BitLen() {
		return fmt.Errorf(
			"CIDR %s contains the cloud metadata service (%s) without naming it. Write "+
				"%s/32 if that is the intent, or choose a prefix that excludes it",
			p, MetadataIPv4, MetadataIPv4)
	}
	return nil
}

// validMethodToken reports whether s is an RFC 9110 token. Restricting the
// charset here means a method never has to be escaped at a sink — it reaches
// an audit row, a CLI listing, and an outbound request line unchanged.
func validMethodToken(s string) bool {
	if s == "" || len(s) > 32 {
		return false
	}
	for _, r := range s {
		if r < 'A' || r > 'Z' {
			return false
		}
	}
	return true
}

// Active reports whether the grant may be redeemed at now.
func (g Grant) Active(now time.Time) bool { return g.DenyReason(now) == "" }

// DenyReason returns the audit-friendly reason this grant is unusable at now,
// or "" when it is usable. Mirrors secretbroker.Grant.DenyReason so a denial
// reads the same in both audit trails.
func (g Grant) DenyReason(now time.Time) string {
	if !g.RevokedAt.IsZero() && !now.Before(g.RevokedAt) {
		return "grant revoked at " + g.RevokedAt.UTC().Format(time.RFC3339)
	}
	if !g.ExpiresAt.IsZero() && !now.Before(g.ExpiresAt) {
		return "grant expired at " + g.ExpiresAt.UTC().Format(time.RFC3339)
	}
	return ""
}

// DenySentinel returns the error matching DenyReason, so a caller can attach
// the right typed error to an inactive grant without re-deriving why.
func (g Grant) DenySentinel() error {
	if !g.RevokedAt.IsZero() {
		return ErrGrantRevoked
	}
	return ErrGrantExpired
}

// ---------------------------------------------------------------------------
// decisions
// ---------------------------------------------------------------------------

// CheckHost reports whether the destination hostname is on the allowlist.
//
// A grant with only CIDRs has no host opinion; the address check in CheckAddr
// is then the gate, and this returns nil so the two dimensions compose as an
// OR rather than an AND. A grant that lists hosts and a destination that
// matches none of them is refused here, before any DNS traffic is generated.
func (g Grant) CheckHost(host string) error {
	if len(g.Hosts) == 0 {
		return nil
	}
	if err := (secretbroker.Constraints{Hosts: g.Hosts}).CheckHost(host); err != nil {
		return fmt.Errorf("%w: %s is not in the grant's host allowlist (%s)",
			ErrHostNotAllowed, host, strings.Join(g.Hosts, ", "))
	}
	return nil
}

// HostMatches is CheckHost as a boolean, for the OR with the CIDR dimension.
func (g Grant) HostMatches(host string) bool {
	return len(g.Hosts) > 0 && (secretbroker.Constraints{Hosts: g.Hosts}).AllowsHost(host)
}

// CheckPort reports whether the destination port is allowed. An empty list
// denies: Normalize guarantees a stored grant always names its ports, so an
// empty list here means the grant was hand-built and skipped validation.
func (g Grant) CheckPort(port int) error {
	for _, p := range g.Ports {
		if p == port {
			return nil
		}
	}
	return fmt.Errorf("%w: %d is not in the grant's port allowlist (%s)",
		ErrPortNotAllowed, port, joinInts(g.Ports))
}

// CheckMethod reports whether a plain-HTTP method is allowed.
func (g Grant) CheckMethod(method string) error {
	m := strings.ToUpper(strings.TrimSpace(method))
	for _, allowed := range g.Methods {
		if allowed == "*" || allowed == m {
			return nil
		}
	}
	return fmt.Errorf("%w: %s is not in the grant's method allowlist (%s)",
		ErrMethodNotAllowed, method, strings.Join(g.Methods, ", "))
}

// AllowsAddr reports whether an address is inside one of the grant's CIDRs.
//
// This is both the second allow dimension and the SSRF opt-in: netguard's
// blocked-range check consults it, so an operator who lists 10.0.0.0/8 gets
// exactly 10.0.0.0/8 and not the loopback, the metadata service, or their
// IPv6 equivalents.
func (g Grant) AllowsAddr(addr netip.Addr) bool {
	if !addr.IsValid() || len(g.CIDRs) == 0 {
		return false
	}
	addr = addr.Unmap()
	for _, c := range g.CIDRs {
		pfx, err := netip.ParsePrefix(c)
		if err != nil {
			// A prefix that no longer parses is a corrupt or hostile row.
			// Skipping it denies; honouring it would widen the grant.
			continue
		}
		if pfx.Addr().Unmap().Is4() != addr.Is4() {
			continue
		}
		if pfx.Contains(addr) {
			return true
		}
	}
	return false
}

// SessionDeadline returns when a session redeemed at now must expire, given
// the broker's ceiling. A session never outlives the grant that authorised
// it, which is what makes revocation effective within one session period.
func (g Grant) SessionDeadline(now time.Time, ceiling time.Duration) time.Time {
	ttl := g.SessionTTL
	if ttl <= 0 || (ceiling > 0 && ttl > ceiling) {
		ttl = ceiling
	}
	if ttl <= 0 {
		ttl = DefaultSessionTTL
	}
	deadline := now.Add(ttl)
	if !g.ExpiresAt.IsZero() && g.ExpiresAt.Before(deadline) {
		return g.ExpiresAt
	}
	return deadline
}

// Summary renders the grant's policy as a short, stable, audit-safe string.
// It contains allowlist patterns and limits only — an egress grant holds no
// credential material at all, which is one of the nicer properties of
// brokering a capability rather than a token.
func (g Grant) Summary() string {
	var parts []string
	if len(g.Hosts) > 0 {
		parts = append(parts, "hosts="+strings.Join(g.Hosts, "|"))
	}
	if len(g.CIDRs) > 0 {
		parts = append(parts, "cidrs="+strings.Join(g.CIDRs, "|"))
	}
	if len(g.Ports) > 0 {
		parts = append(parts, "ports="+joinInts(g.Ports))
	}
	if len(g.Methods) > 0 {
		parts = append(parts, "methods="+strings.Join(g.Methods, "|"))
	}
	if g.MaxBytesUp > 0 {
		parts = append(parts, "up<="+FormatBytes(g.MaxBytesUp))
	}
	if g.MaxBytesDown > 0 {
		parts = append(parts, "down<="+FormatBytes(g.MaxBytesDown))
	}
	if len(parts) == 0 {
		return "none"
	}
	return strings.Join(parts, " ")
}

func joinInts(vals []int) string {
	parts := make([]string, 0, len(vals))
	for _, v := range vals {
		parts = append(parts, strconv.Itoa(v))
	}
	return strings.Join(parts, ",")
}

// FormatBytes renders a byte count in the same units the CLI accepts, so a
// value copied out of `cloop egress list` can be pasted back into
// `cloop egress grant`.
func FormatBytes(n int64) string {
	switch {
	case n <= 0:
		return "unlimited"
	case n%(1<<30) == 0:
		return strconv.FormatInt(n>>30, 10) + "g"
	case n%(1<<20) == 0:
		return strconv.FormatInt(n>>20, 10) + "m"
	case n%(1<<10) == 0:
		return strconv.FormatInt(n>>10, 10) + "k"
	default:
		return strconv.FormatInt(n, 10) + "b"
	}
}

// ParseBytes reads a byte quota: a bare integer (bytes) or a suffixed size
// ("64k", "10m", "2g"). Empty yields 0, meaning unlimited.
func ParseBytes(s string) (int64, error) {
	s = strings.TrimSpace(strings.ToLower(s))
	if s == "" || s == "unlimited" || s == "0" {
		return 0, nil
	}
	mult := int64(1)
	switch s[len(s)-1] {
	case 'b':
		s = s[:len(s)-1]
	case 'k':
		mult, s = 1<<10, s[:len(s)-1]
	case 'm':
		mult, s = 1<<20, s[:len(s)-1]
	case 'g':
		mult, s = 1<<30, s[:len(s)-1]
	}
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, fmt.Errorf("size has a unit but no value")
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("%q is not a size (expected forms: 1048576, 64k, 10m, 2g)", s)
	}
	if n < 0 {
		return 0, fmt.Errorf("size must not be negative")
	}
	// Reject an overflow rather than wrapping into a small — or negative —
	// quota, which would read as "unlimited" or refuse every byte.
	if mult > 1 && n > (1<<62)/mult {
		return 0, fmt.Errorf("size %q is too large", s)
	}
	return n * mult, nil
}
