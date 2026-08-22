package egressbroker

import "errors"

// Sentinel errors. Every refusal in this package wraps exactly one of them,
// and the choice of sentinel is what the audit row's verdict is derived from
// — so "why was this request refused" is answerable by errors.Is at any call
// site, not by string matching on a message.
//
// The denial set is deliberately fine-grained. "Blocked" is not a useful
// verdict to an operator staring at a sandbox that cannot reach GitHub: the
// difference between "you forgot to allow port 443", "the host is not on the
// list", "you have burned your download quota", and "the lease died under
// you" is the difference between a one-line fix and an afternoon.
var (
	// ErrHostNotAllowed: the destination hostname is outside the grant's
	// host allowlist and its resolved address is outside every allowed CIDR.
	ErrHostNotAllowed = errors.New("egressbroker: destination host not allowed")

	// ErrPortNotAllowed: the destination port is outside the grant's port
	// allowlist.
	ErrPortNotAllowed = errors.New("egressbroker: destination port not allowed")

	// ErrMethodNotAllowed: the HTTP method is outside the grant's method
	// allowlist. Only reachable on the plain-HTTP path — see Grant.Methods
	// for why a CONNECT tunnel cannot be method-filtered.
	ErrMethodNotAllowed = errors.New("egressbroker: HTTP method not allowed")

	// ErrDestinationBlocked: the destination resolved to a loopback,
	// RFC1918, carrier-grade-NAT, link-local, multicast, or unspecified
	// address, and no allowed CIDR covers it. This is the SSRF guard, and it
	// fires after resolution, so a public name that resolves inward is
	// caught as surely as a literal 169.254.169.254.
	ErrDestinationBlocked = errors.New("egressbroker: destination address is in a blocked range")

	// ErrQuotaExceeded: the session transferred more bytes than the grant
	// permits. Raised mid-stream, which tears the transfer down rather than
	// letting it finish — a quota that only applies at the end of a
	// download is not a quota.
	ErrQuotaExceeded = errors.New("egressbroker: transfer quota exceeded")

	// ErrSessionExpired: the proxy session's TTL elapsed. Also raised
	// mid-tunnel: an open CONNECT tunnel does not outlive its lease.
	ErrSessionExpired = errors.New("egressbroker: proxy session expired")

	// ErrUnauthenticated: the Proxy-Authorization header was missing,
	// malformed, named an unknown session, or carried the wrong token.
	// One sentinel for all four on purpose — distinguishing them to the
	// caller would turn the proxy into a session-ID oracle.
	ErrUnauthenticated = errors.New("egressbroker: proxy credential missing or invalid")

	// ErrGrantNotFound: no egress grant with that ID exists.
	ErrGrantNotFound = errors.New("egressbroker: grant not found")

	// ErrGrantExpired: the grant's TTL elapsed.
	ErrGrantExpired = errors.New("egressbroker: grant expired")

	// ErrGrantRevoked: the grant was revoked.
	ErrGrantRevoked = errors.New("egressbroker: grant revoked")

	// ErrNoGrant: no active grant matches the requester, so there is
	// nothing to redeem. Distinct from ErrGrantNotFound, which is about a
	// specific ID.
	ErrNoGrant = errors.New("egressbroker: no active egress grant matches this requester")

	// ErrInvalidGrant: the grant failed structural validation and was never
	// stored. A validation failure is not a denial: it never became a
	// security decision, so it does not produce a deny audit row.
	ErrInvalidGrant = errors.New("egressbroker: invalid grant")

	// ErrInvalidRequest: the proxy request was malformed — an unparseable
	// CONNECT target, a relative URI on the plain-HTTP path, an unsupported
	// scheme.
	ErrInvalidRequest = errors.New("egressbroker: malformed proxy request")

	// ErrResolveFailed: DNS lookup for the destination failed or returned
	// no usable address.
	ErrResolveFailed = errors.New("egressbroker: destination resolution failed")

	// ErrDialFailed: the connection to the (already authorised) destination
	// could not be established.
	ErrDialFailed = errors.New("egressbroker: destination dial failed")
)
