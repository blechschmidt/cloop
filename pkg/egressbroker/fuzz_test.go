package egressbroker

import (
	"net"
	"net/netip"
	"strconv"
	"strings"
	"testing"
)

// fuzz_test.go targets the two parsers that read bytes an attacker controls.
//
// The CONNECT request-target parser is the one that matters most. It is the
// classic place a forward proxy fails open: "host:port" gets split one way
// for the policy check and another way for the dial, and the allowlist
// evaporates without anything looking wrong. The properties asserted below
// are exactly the ones that make that impossible — most importantly
// idempotence, which is what guarantees the string the policy approved and
// the string a later reader sees cannot disagree.

// FuzzParseConnectTarget asserts the safety properties of the CONNECT
// authority parser.
func FuzzParseConnectTarget(f *testing.F) {
	seeds := []string{
		"example.com:443",
		"EXAMPLE.COM:443",
		"example.com.:443",
		"127.0.0.1:80",
		"[2001:db8::1]:443",
		"[::ffff:127.0.0.1]:443",
		"[64:ff9b::7f00:1]:443",
		"example.com",             // no port
		"example.com:",            // empty port
		"example.com:0",           // out of range
		"example.com:65536",       // out of range
		"example.com:0443",        // leading zero
		"example.com:+443",        // signed
		"example.com:44 3",        // whitespace
		"user@example.com:443",    // userinfo
		"example.com:443/path",    // path
		"http://example.com:443",  // scheme
		"example.com:443?q=1",     // query
		"*.example.com:443",       // wildcard
		"../etc:443",              // traversal
		"::1:443",                 // unbracketed IPv6
		"[::1:443",                // unclosed bracket
		"[example.com]:443",       // bracketed name
		"exa\rmple.com:443",       // CR injection
		"exa\nmple.com:443",       // LF injection
		"example.com:443\r\nX: y", // header smuggling
		"",
		":",
		":443",
		strings.Repeat("a", 300) + ":443",
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, target string) {
		host, port, err := ParseConnectTarget(target)
		if err != nil {
			// A refusal is always an acceptable outcome; it must simply not
			// hand back a usable destination alongside the error.
			if host != "" || port != 0 {
				t.Fatalf("ParseConnectTarget(%q) returned %q,%d with error %v", target, host, port, err)
			}
			return
		}

		if host == "" {
			t.Fatalf("ParseConnectTarget(%q) accepted an empty host", target)
		}
		if len(host) > MaxHostLength {
			t.Fatalf("ParseConnectTarget(%q) host exceeds %d bytes", target, MaxHostLength)
		}
		if port < 1 || port > 65535 {
			t.Fatalf("ParseConnectTarget(%q) port %d out of range", target, port)
		}
		if host != strings.ToLower(host) {
			t.Fatalf("ParseConnectTarget(%q) host %q is not lowercased; case-varying "+
				"spellings would produce differing verdicts", target, host)
		}

		// Nothing that could re-open a second reading of the destination, or
		// forge a line in a header block, a log, or an audit row.
		for _, bad := range []string{"/", "?", "#", "@", "\\", "*", "\r", "\n", "\t", " ", "..", "%"} {
			if strings.Contains(host, bad) {
				t.Fatalf("ParseConnectTarget(%q) host %q contains %q", target, host, bad)
			}
		}
		for _, r := range host {
			if r < 0x21 || r > 0x7e {
				t.Fatalf("ParseConnectTarget(%q) host %q contains a non-printable byte", target, host)
			}
		}

		// A colon may survive only in a genuine IPv6 literal, which is the
		// one host shape that legitimately contains one.
		if strings.Contains(host, ":") {
			addr, perr := netip.ParseAddr(host)
			if perr != nil || !addr.Is6() {
				t.Fatalf("ParseConnectTarget(%q) host %q has a colon but is not an IPv6 literal", target, host)
			}
		}

		// The property the whole allowlist rests on: re-parsing the parsed
		// form yields the same answer. Without it, the string the policy
		// approved and the string a later reader recovers could differ.
		round := net.JoinHostPort(host, strconv.Itoa(port))
		host2, port2, err2 := ParseConnectTarget(round)
		if err2 != nil {
			t.Fatalf("ParseConnectTarget(%q) -> %q, which no longer parses: %v", target, round, err2)
		}
		if host2 != host || port2 != port {
			t.Fatalf("ParseConnectTarget is not idempotent: %q -> %q:%d -> %q:%d",
				target, host, port, host2, port2)
		}

		// An address literal must also be stable under the guard's
		// normalisation, so the parser and the SSRF check cannot disagree
		// about which address a target names.
		if addr, perr := netip.ParseAddr(host); perr == nil {
			if got := normalizeAddr(addr); got.String() != addr.String() {
				t.Fatalf("ParseConnectTarget(%q) host %q is not normalised (guard sees %s)",
					target, host, got)
			}
		}
	})
}

// FuzzParseProxyCredential asserts that a malformed credential can neither
// panic nor produce identifiers outside the minted alphabet — the session ID
// becomes a map key and an audit field, and the token reaches a
// constant-time compare.
func FuzzParseProxyCredential(f *testing.F) {
	seeds := []string{
		"",
		"Basic",
		"Basic ",
		"Basic !!!",
		"Bearer abc",
		"basic " + FormatProxyCredential("sess_a", "b")[len("Basic "):],
		FormatProxyCredential("sess_0123456789abcdef", strings.Repeat("ab", 32)),
		FormatProxyCredential("sess_a", ""),
		FormatProxyCredential("", "tok"),
		FormatProxyCredential("sess:a", "tok"),
		FormatProxyCredential("sess_a", "tok\r\nX: y"),
		"Basic " + strings.Repeat("QQ", 1024),
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, header string) {
		id, token, err := ParseProxyCredential(header)
		if err != nil {
			if id != "" || token != "" {
				t.Fatalf("ParseProxyCredential(%q) returned %q,%q with error %v", header, id, token, err)
			}
			return
		}
		if id == "" || token == "" {
			t.Fatalf("ParseProxyCredential(%q) accepted an empty half", header)
		}
		if !validCredentialToken(id) || !validCredentialToken(token) {
			t.Fatalf("ParseProxyCredential(%q) produced out-of-alphabet %q/%q", header, id, token)
		}
		// Re-encoding must recover the same pair, so the wire form and the
		// in-memory form cannot drift.
		id2, token2, err2 := ParseProxyCredential(FormatProxyCredential(id, token))
		if err2 != nil || id2 != id || token2 != token {
			t.Fatalf("credential round trip failed: %q -> %q/%q -> %q/%q (%v)",
				header, id, token, id2, token2, err2)
		}
	})
}

// FuzzSplitHostPort covers the plain-HTTP path's authority parser, which
// reads the absolute-URI a client supplies.
func FuzzSplitHostPort(f *testing.F) {
	for _, s := range []string{
		"example.com", "example.com:8080", "[2001:db8::1]:443", "[2001:db8::1]",
		"example.com:", ":8080", "", "example.com:-1", "EXAMPLE.COM.",
		"exa mple.com:80", "example.com:99999",
	} {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, authority string) {
		host, port, err := splitHostPort(authority, 80)
		if err != nil {
			return
		}
		if host == "" {
			t.Fatalf("splitHostPort(%q) accepted an empty host", authority)
		}
		if host != strings.ToLower(host) {
			t.Fatalf("splitHostPort(%q) host %q is not lowercased", authority, host)
		}
		if port < 1 || port > 65535 {
			t.Fatalf("splitHostPort(%q) port %d out of range", authority, port)
		}
		if strings.ContainsAny(host, "\r\n") {
			t.Fatalf("splitHostPort(%q) host %q contains a line break", authority, host)
		}
	})
}
