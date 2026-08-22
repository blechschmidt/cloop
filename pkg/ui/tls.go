package ui

// tls.go holds the dashboard's transport-security decisions: whether this
// process terminates TLS itself, and how a request's true scheme is
// determined when something else terminated it.
//
// The two questions are separate on purpose. cloop supports both deployments —
// native HTTPS, and plaintext behind a TLS-terminating reverse proxy — and the
// headers that only make sense over TLS (HSTS, Secure cookies) must be
// correct in both. Keying them off "did *this* process load a certificate"
// would silently omit them from the far more common proxied deployment.

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"

	"github.com/blechschmidt/cloop/pkg/tlsconf"
)

// hstsValue is the header sent on TLS responses.
//
// One year is what the preload requirements and every mainstream hardening
// guide converge on; shorter windows leave a re-exposure gap for any client
// that has not visited recently. includeSubDomains is on because an enterprise
// hub is normally the only thing on its hostname, and a plaintext sibling
// subdomain is a downgrade path for the session cookie. There is no preload
// directive: submitting to the preload list is a months-to-undo commitment
// that belongs to the operator, not to a default.
const hstsValue = "max-age=31536000; includeSubDomains"

// serverTLSConfig builds the tls.Config for the listener, or nil when this
// process should serve plaintext.
//
// A half-configuration (certificate without key, or the reverse) is an error.
// Falling back to plaintext there would mean an operator who intended HTTPS
// gets HTTP, discovers it from a browser warning at best and from a packet
// capture at worst, and in the meantime every session cookie and bearer token
// crossed the network in the clear.
func (s *Server) serverTLSConfig() (*tls.Config, error) {
	cert, key := strings.TrimSpace(s.TLSCertFile), strings.TrimSpace(s.TLSKeyFile)
	switch {
	case cert == "" && key == "":
		return nil, nil
	case cert == "":
		return nil, fmt.Errorf("ui: a TLS key was configured without a certificate; " +
			"set both --tls-cert and --tls-key (or ui.tls.cert_file and ui.tls.key_file)")
	case key == "":
		return nil, fmt.Errorf("ui: a TLS certificate was configured without a key; " +
			"set both --tls-cert and --tls-key (or ui.tls.cert_file and ui.tls.key_file)")
	}
	cfg, err := tlsconf.ServerConfig(cert, key, s.TLSMinVersion)
	if err != nil {
		return nil, fmt.Errorf("ui: %w", err)
	}
	return cfg, nil
}

// TLSEnabled reports whether this process is configured to terminate TLS.
func (s *Server) TLSEnabled() bool {
	return strings.TrimSpace(s.TLSCertFile) != "" && strings.TrimSpace(s.TLSKeyFile) != ""
}

// requestIsTLS reports whether the client's connection to the deployment is
// encrypted — either directly to this process, or to a reverse proxy in front
// of it that said so via X-Forwarded-Proto.
//
// X-Forwarded-Proto is believed from two sources, and only those:
//
//   - a loopback peer, i.e. a proxy on this host, matching clientIP's trust
//     model in server.go;
//   - any peer, when the operator has declared an https ui.external_url. A
//     proxy on a *different* host is the standard enterprise topology (nginx,
//     an ALB, an ingress controller), and the loopback rule alone silently
//     drops HSTS from every response in that deployment — forever, with
//     nothing in the logs to say so. The external URL is operator-supplied
//     configuration, not an attacker-controlled header, so keying on it does
//     not extend trust to the client.
//
// Getting this wrong in the permissive direction costs nothing: a browser
// ignores HSTS received over plaintext (RFC 6797 §8.1). Getting it wrong in
// the strict direction costs the header entirely.
func (s *Server) requestIsTLS(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	if !forwardedProtoIsHTTPS(r) {
		return false
	}
	return peerIsLoopback(r) || s.externalURLIsHTTPS()
}

// externalURLIsHTTPS reports whether the operator declared this deployment as
// https, which is what licenses trusting a non-loopback proxy's
// X-Forwarded-Proto.
func (s *Server) externalURLIsHTTPS() bool {
	ext := strings.TrimSpace(s.ExternalURL)
	if ext == "" {
		return false
	}
	u, err := url.Parse(ext)
	return err == nil && strings.EqualFold(u.Scheme, "https")
}

// forwardedProtoIsHTTPS reads the client-facing hop from X-Forwarded-Proto.
// A proxy chain may append: "https, http" — the first entry is the one that
// decided the browser's view.
func forwardedProtoIsHTTPS(r *http.Request) bool {
	proto := r.Header.Get("X-Forwarded-Proto")
	if i := strings.IndexByte(proto, ','); i >= 0 {
		proto = proto[:i]
	}
	return strings.EqualFold(strings.TrimSpace(proto), "https")
}

// peerIsLoopback reports whether the direct TCP peer is on this host.
func peerIsLoopback(r *http.Request) bool {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
