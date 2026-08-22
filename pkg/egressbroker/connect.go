package egressbroker

import (
	"encoding/base64"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

// connect.go holds the two parsers that read attacker-controlled bytes: the
// CONNECT request-target and the Proxy-Authorization credential.
//
// They are separated from the handler and exported so they can be fuzzed
// directly. That is not ceremony — a proxy's request-target parser is the
// classic place where "host:port" is split one way for the policy check and
// another way for the dial, and the whole allowlist evaporates. Keeping the
// split in one function means there is only one splitting to get right, and
// the fuzz target in fuzz_test.go asserts the properties that make it safe:
// no panic, no embedded separator surviving into the host, a port always in
// range, and idempotence under re-parse.

// MaxHostLength bounds a destination hostname. 253 is the DNS maximum for a
// fully-qualified name; anything longer cannot resolve and is more likely to
// be an attempt to overflow something downstream.
const MaxHostLength = 253

// ParseConnectTarget parses the authority-form request-target of a CONNECT
// request ("example.com:443", "[2001:db8::1]:443") into a host and port.
//
// RFC 9110 requires authority-form to carry a port, and this parser enforces
// it rather than defaulting: a CONNECT with no port is malformed, and
// inventing 443 for it would mean the policy check ran against a port the
// client never asked for.
//
// Everything that is not unambiguously a host and a port is rejected. In
// particular a userinfo prefix, a path, a query, a fragment, a wildcard, any
// whitespace, any control byte, and an unbracketed IPv6 literal are all
// errors, because each of them is a way to make one reader see a different
// host than another.
func ParseConnectTarget(target string) (host string, port int, err error) {
	t := strings.TrimSpace(target)
	if t == "" {
		return "", 0, fmt.Errorf("%w: empty CONNECT target", ErrInvalidRequest)
	}
	if len(t) > MaxHostLength+8 {
		return "", 0, fmt.Errorf("%w: CONNECT target exceeds %d bytes", ErrInvalidRequest, MaxHostLength+8)
	}
	// A scheme means this is an absolute-URI, which belongs on the plain-HTTP
	// path. Rejecting it here rather than tolerating it keeps the two request
	// shapes from being interchangeable.
	if strings.Contains(t, "://") {
		return "", 0, fmt.Errorf("%w: CONNECT target %q is a URI, not an authority", ErrInvalidRequest, target)
	}
	if i := strings.IndexAny(t, "/?#@"); i >= 0 {
		return "", 0, fmt.Errorf("%w: CONNECT target %q contains %q", ErrInvalidRequest, target, string(t[i]))
	}
	for _, r := range t {
		if r < 0x21 || r > 0x7e {
			return "", 0, fmt.Errorf("%w: CONNECT target contains a non-printable or non-ASCII byte", ErrInvalidRequest)
		}
	}

	var portStr string
	if strings.HasPrefix(t, "[") {
		end := strings.Index(t, "]")
		if end < 0 {
			return "", 0, fmt.Errorf("%w: CONNECT target %q has an unclosed bracket", ErrInvalidRequest, target)
		}
		host = t[1:end]
		rest := t[end+1:]
		if !strings.HasPrefix(rest, ":") {
			return "", 0, fmt.Errorf("%w: CONNECT target %q has no port", ErrInvalidRequest, target)
		}
		portStr = rest[1:]
		// A bracketed literal must actually be an IPv6 address; otherwise
		// the brackets are decoration hiding something else.
		addr, perr := netip.ParseAddr(host)
		if perr != nil || !addr.Is6() {
			return "", 0, fmt.Errorf("%w: %q is not an IPv6 literal", ErrInvalidRequest, host)
		}
		// Canonicalise through the same normalisation the address guard uses,
		// which unwraps the v4-in-v6 encodings. Two things follow, and the
		// second is the reason it happens here rather than being rejected as
		// malformed: two spellings of one address cannot produce two
		// different verdicts, and [::ffff:127.0.0.1]:443 is refused as
		// "loopback" rather than as "malformed request" — which is the
		// difference between an audit log that shows an SSRF attempt and one
		// that shows a typo.
		host = normalizeAddr(addr).String()
	} else {
		i := strings.LastIndex(t, ":")
		if i < 0 {
			return "", 0, fmt.Errorf("%w: CONNECT target %q has no port", ErrInvalidRequest, target)
		}
		host = t[:i]
		portStr = t[i+1:]
		// An unbracketed colon left in the host means an IPv6 literal was
		// written without brackets: "::1:443" is ambiguous and must not be
		// guessed at.
		if strings.Contains(host, ":") {
			return "", 0, fmt.Errorf("%w: CONNECT target %q looks like an unbracketed IPv6 literal", ErrInvalidRequest, target)
		}
	}

	host, err = NormalizeDestinationHost(host)
	if err != nil {
		return "", 0, err
	}
	port, err = parsePort(portStr)
	if err != nil {
		return "", 0, err
	}
	return host, port, nil
}

// NormalizeDestinationHost canonicalises and validates a destination
// hostname or address literal.
//
// Both request parsers route through it, and that shared definition is the
// point rather than a convenience: if CONNECT and the plain-HTTP authority
// disagreed about what counts as a host, one of them would be the way past
// the allowlist. A fuzz run found exactly that — splitHostPort had no
// charset rule at all and accepted "0\r0", which would have reached both a
// dial target and an audit row.
func NormalizeDestinationHost(host string) (string, error) {
	// Canonicalise *before* validating, not on the way out.
	//
	// A fuzz run found why: with the trailing-dot trim deferred to the
	// return statement, ".:1" passed the non-empty check as "." and then
	// left as "", so a caller received an empty host with a nil error. Every
	// rule below must see the string the caller will actually get.
	h := strings.ToLower(strings.TrimSpace(host))
	h = strings.TrimSuffix(h, ".")

	if h == "" {
		return "", fmt.Errorf("%w: %q has no host", ErrInvalidRequest, host)
	}
	if len(h) > MaxHostLength {
		return "", fmt.Errorf("%w: host exceeds %d bytes", ErrInvalidRequest, MaxHostLength)
	}
	for _, r := range h {
		if r < 0x21 || r > 0x7e {
			return "", fmt.Errorf("%w: host contains a non-printable or non-ASCII byte", ErrInvalidRequest)
		}
	}
	if strings.ContainsAny(h, "*?[]\\%,/@#") {
		return "", fmt.Errorf("%w: host %q contains an illegal character", ErrInvalidRequest, h)
	}
	// No empty DNS label, in any position.
	//
	// The leading- and trailing-dot cases are not decoration: a second fuzz
	// run produced "..", which the trailing-dot trim above turns into ".",
	// which contains no ".." and so is not caught by that rule alone. A "."
	// host also fails to re-parse, breaking the idempotence the policy check
	// depends on.
	if strings.HasPrefix(h, ".") || strings.HasSuffix(h, ".") || strings.Contains(h, "..") {
		return "", fmt.Errorf("%w: host %q has an empty label", ErrInvalidRequest, h)
	}
	// A colon survives only in a genuine IPv6 literal, canonicalised through
	// the same normalisation the address guard uses.
	if strings.Contains(h, ":") {
		addr, err := netip.ParseAddr(h)
		if err != nil || !addr.Is6() {
			return "", fmt.Errorf("%w: host %q has a colon but is not an IPv6 literal", ErrInvalidRequest, h)
		}
		return normalizeAddr(addr).String(), nil
	}
	return h, nil
}

// parsePort accepts only a bare decimal in range. strconv.Atoi alone would
// accept "+443" and "-1", and a leading zero would let "0443" and "443" be
// two spellings of one port.
func parsePort(s string) (int, error) {
	if s == "" {
		return 0, fmt.Errorf("%w: missing port", ErrInvalidRequest)
	}
	if len(s) > 5 {
		return 0, fmt.Errorf("%w: port %q is too long", ErrInvalidRequest, s)
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return 0, fmt.Errorf("%w: port %q is not a number", ErrInvalidRequest, s)
		}
	}
	if len(s) > 1 && s[0] == '0' {
		return 0, fmt.Errorf("%w: port %q has a leading zero", ErrInvalidRequest, s)
	}
	n, err := strconv.Atoi(s)
	if err != nil || n < 1 || n > 65535 {
		return 0, fmt.Errorf("%w: port %q is outside 1-65535", ErrInvalidRequest, s)
	}
	return n, nil
}

// ProxyAuthScheme is the only authentication scheme the proxy accepts.
// Basic over a loopback- or VPN-reachable proxy carries a 256-bit random
// token, not a password, so there is nothing to guess and nothing reused
// elsewhere; the scheme is chosen because every HTTP client and every
// language runtime already speaks it from a proxy URL's userinfo.
const ProxyAuthScheme = "Basic"

// ParseProxyCredential extracts the session ID and token from a
// Proxy-Authorization header value.
//
// It returns ErrUnauthenticated for every failure shape, and never says which
// one. A parser that distinguished "no such session" from "wrong token" would
// be an oracle for enumerating live sessions.
func ParseProxyCredential(header string) (sessionID, token string, err error) {
	h := strings.TrimSpace(header)
	if h == "" {
		return "", "", fmt.Errorf("%w: no Proxy-Authorization header", ErrUnauthenticated)
	}
	scheme, rest, found := strings.Cut(h, " ")
	if !found || !strings.EqualFold(strings.TrimSpace(scheme), ProxyAuthScheme) {
		return "", "", fmt.Errorf("%w: unsupported proxy auth scheme", ErrUnauthenticated)
	}
	rest = strings.TrimSpace(rest)
	if rest == "" || len(rest) > 1024 {
		return "", "", fmt.Errorf("%w: malformed proxy credential", ErrUnauthenticated)
	}
	raw, derr := base64.StdEncoding.DecodeString(rest)
	if derr != nil {
		return "", "", fmt.Errorf("%w: proxy credential is not base64", ErrUnauthenticated)
	}
	id, tok, ok := strings.Cut(string(raw), ":")
	if !ok || id == "" || tok == "" {
		return "", "", fmt.Errorf("%w: proxy credential is not id:token", ErrUnauthenticated)
	}
	// Both halves are minted by this package from a fixed alphabet. Anything
	// else is either corruption or an injection attempt against whatever
	// reads the session ID next (a map key, an audit row, a log line).
	if !validCredentialToken(id) || !validCredentialToken(tok) {
		return "", "", fmt.Errorf("%w: proxy credential contains illegal characters", ErrUnauthenticated)
	}
	return id, tok, nil
}

// validCredentialToken restricts a session ID or token to the charset this
// package mints: hex, plus '_' for the "sess_" prefix.
func validCredentialToken(s string) bool {
	if s == "" || len(s) > 256 {
		return false
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '_', r == '-':
		default:
			return false
		}
	}
	return true
}

// FormatProxyCredential builds the header value a client sends. Used by the
// `cloop egress test` client and by the round-trip tests, so the encoding has
// one definition on both sides.
func FormatProxyCredential(sessionID, token string) string {
	return ProxyAuthScheme + " " +
		base64.StdEncoding.EncodeToString([]byte(sessionID+":"+token))
}
