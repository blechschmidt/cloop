package tlsconf

// transport.go is the client half: deciding whether an outbound endpoint is
// safe to dial, and building the tls.Config that dials it.
//
// The rule this file enforces is that plaintext is a local-development
// affordance, not a deployment option. An agent that will happily speak ws://
// to a public hostname hands its bearer credential to whoever answers DNS —
// and because the agent retries forever, a single successful interception is
// enough to keep the credential. So plaintext to a non-loopback host is
// refused outright, and the only way past is an explicit flag that says so in
// its name.

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"
)

// ErrInsecureTransport is returned when an endpoint would send credentials in
// the clear to a host that is not loopback.
var ErrInsecureTransport = errors.New("tlsconf: refusing to send credentials over an unencrypted connection")

// ErrEndpointInvalid is returned for URLs that are malformed or use a scheme
// this transport does not speak.
var ErrEndpointInvalid = errors.New("tlsconf: invalid endpoint URL")

// Endpoint is the parsed, classified result of checking a dial target.
type Endpoint struct {
	// URL is the parsed endpoint.
	URL *url.URL
	// Secure reports whether the scheme provides TLS (wss/https).
	Secure bool
	// Loopback reports whether the host is a loopback address or "localhost".
	Loopback bool
}

// Host returns the hostname without any port.
func (e Endpoint) Host() string {
	if e.URL == nil {
		return ""
	}
	return e.URL.Hostname()
}

// ParseEndpoint validates a WebSocket/HTTP endpoint and classifies it.
//
// It does not decide policy — see CheckEndpoint for that — so callers that
// only need the classification (the hub's own external URL, for instance) do
// not have to pretend to be dialling.
func ParseEndpoint(raw string) (Endpoint, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return Endpoint{}, fmt.Errorf("%w: empty", ErrEndpointInvalid)
	}
	u, err := url.Parse(s)
	if err != nil {
		return Endpoint{}, fmt.Errorf("%w: %q: %v", ErrEndpointInvalid, raw, err)
	}
	if u.Host == "" {
		return Endpoint{}, fmt.Errorf("%w: %q has no host", ErrEndpointInvalid, raw)
	}
	var secure bool
	switch strings.ToLower(u.Scheme) {
	case "wss", "https":
		secure = true
	case "ws", "http":
		secure = false
	default:
		return Endpoint{}, fmt.Errorf("%w: %q uses scheme %q (want wss, ws, https or http)",
			ErrEndpointInvalid, raw, u.Scheme)
	}
	return Endpoint{URL: u, Secure: secure, Loopback: IsLoopbackHost(u.Hostname())}, nil
}

// CheckEndpoint applies the plaintext policy to an endpoint.
//
// allowInsecure corresponds to the agent's --insecure-transport flag. When it
// lets a plaintext non-loopback endpoint through, the returned warning is
// non-empty and the caller is expected to log it loudly on every connection
// attempt — a warning printed once at startup scrolls away, and the whole
// point is that nobody should be able to forget this is on.
func CheckEndpoint(raw string, allowInsecure bool) (ep Endpoint, warning string, err error) {
	ep, err = ParseEndpoint(raw)
	if err != nil {
		return Endpoint{}, "", err
	}
	if ep.Secure || ep.Loopback {
		return ep, "", nil
	}
	if !allowInsecure {
		return Endpoint{}, "", fmt.Errorf(
			"%w: %s is plaintext %s to a non-loopback host.\n"+
				"  The enrollment token and the long-lived credential would both travel in the clear,\n"+
				"  and anything that can answer DNS for %q could keep them.\n"+
				"  Use wss:// (see `cloop hub tls-init` for a development certificate),\n"+
				"  or pass --insecure-transport if this link is already protected some other way.",
			ErrInsecureTransport, ep.URL.Redacted(), ep.URL.Scheme, ep.Host())
	}
	return ep, fmt.Sprintf(
		"INSECURE TRANSPORT: talking to %s without TLS because --insecure-transport was passed. "+
			"Credentials are visible to anything on the path.", ep.URL.Redacted()), nil
}

// IsLoopbackHost reports whether a hostname refers to this machine.
//
// "localhost" is matched by name because it is not an IP literal, and its
// resolution to 127.0.0.1/::1 is guaranteed by RFC 6761 for exactly this kind
// of local-only trust decision.
func IsLoopbackHost(host string) bool {
	h := strings.ToLower(strings.TrimSpace(host))
	// Strip one balanced bracket pair, not every bracket: strings.Trim would
	// also accept "[[::1]]" and "]::1[", which are not addresses. Callers
	// normally pass url.Hostname() output (already de-bracketed), but this is
	// an exported predicate and must be safe for anyone who does not.
	if strings.HasPrefix(h, "[") && strings.HasSuffix(h, "]") {
		h = h[1 : len(h)-1]
	}
	if h == "localhost" || strings.HasSuffix(h, ".localhost") {
		return true
	}
	if ip := net.ParseIP(h); ip != nil {
		return ip.IsLoopback()
	}
	return false
}

// ClientOptions parameterises ClientConfig.
type ClientOptions struct {
	// Pins restricts which server public keys are acceptable. Empty means
	// normal PKI verification only.
	Pins PinSet
	// RootCAFile adds a PEM bundle to the trusted roots, on top of the
	// system store. This is how a development certificate from
	// `cloop hub tls-init` becomes dialable without ever disabling
	// verification.
	RootCAFile string
	// MinVersion overrides the TLS floor. Zero uses TLS 1.2.
	MinVersion uint16
	// ServerName overrides SNI / hostname verification. Empty lets the
	// dialer derive it from the URL, which is what production wants.
	ServerName string
}

// ClientConfig builds the tls.Config for an outbound connection.
//
// InsecureSkipVerify is never set, and there is no option to set it. Pinning
// is layered on top of chain verification through VerifyPeerCertificate, which
// Go calls only after the standard checks pass — so a pinned dial is strictly
// stronger than an unpinned one, never a substitute for it. An operator with a
// certificate the system store does not trust supplies RootCAFile; that keeps
// "which authorities do I trust" an explicit, auditable decision instead of
// "no authorities at all".
func ClientConfig(opts ClientOptions) (*tls.Config, error) {
	min := opts.MinVersion
	if min == 0 {
		min = tls.VersionTLS12
	}
	cfg := &tls.Config{
		MinVersion: min,
		ServerName: opts.ServerName,
	}
	if path := strings.TrimSpace(opts.RootCAFile); path != "" {
		pem, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("tlsconf: read CA bundle %s: %w", path, err)
		}
		// Start from the system pool so adding one private CA does not
		// silently drop trust in every public one — a surprise that shows up
		// later as an unrelated endpoint failing.
		pool, err := x509.SystemCertPool()
		if err != nil || pool == nil {
			pool = x509.NewCertPool()
		}
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("tlsconf: no certificates found in CA bundle %s", path)
		}
		cfg.RootCAs = pool
	}
	if verify := opts.Pins.VerifyPeerCertificate(); verify != nil {
		cfg.VerifyPeerCertificate = verify
	}
	return cfg, nil
}
