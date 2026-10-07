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
// X-Forwarded-Proto is believed only from a trusted proxy: loopback, an
// address in ui.trusted_proxies, or another member of this hub's cluster
// (Task 20394). Until then it was also believed from *any* peer once
// ui.external_url was https — configuration.md said loopback only — and the
// scheme it yields is no longer just a header choice: it is half of the origin
// the forgery guard and the WebSocket check judge a browser's request
// against. A client that could set it would choose the origin it is compared
// with. A TLS terminator on another host belongs in ui.trusted_proxies; HSTS
// for such a deployment is kept by securityHeaders, which sends it whenever
// ui.external_url is https.
func (s *Server) requestIsTLS(r *http.Request) bool {
	return s.clientView(r).TLS()
}

// publicURLIsHTTPS reports whether the operator declared this deployment as
// https — ui.external_url, else the SSO callback (publicURL): browsers reach it
// over TLS, whatever this process can see of it.
func (s *Server) publicURLIsHTTPS() bool {
	public, _ := s.publicURL()
	if public == "" {
		return false
	}
	u, err := url.Parse(public)
	return err == nil && strings.EqualFold(u.Scheme, "https")
}

// RequestIsTLS is requestIsTLS for the OIDC authenticator: cookie_secure
// "auto" follows the same rule about whose X-Forwarded-Proto to believe as
// HSTS and the origin checks do (oidcauth.Config.RequestIsTLS; wired by
// cmd/ui_cmd.go).
func (s *Server) RequestIsTLS(r *http.Request) bool { return s.requestIsTLS(r) }
