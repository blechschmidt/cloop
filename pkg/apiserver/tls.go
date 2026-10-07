package apiserver

// tls.go gives `cloop serve` the same transport-security posture as
// `cloop ui`: optional native TLS, and HSTS on responses the client received
// over TLS.
//
// The REST API needs this at least as much as the dashboard does. Its bearer
// token is sent on every request, grants the ability to start runs, and — being
// long-lived and script-held — is far more likely to be replayed than a browser
// session cookie is.

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"strings"

	"github.com/blechschmidt/cloop/pkg/sameorigin"
	"github.com/blechschmidt/cloop/pkg/tlsconf"
)

// hstsValue matches pkg/ui's: one year, subdomains included, no preload.
const hstsValue = "max-age=31536000; includeSubDomains"

// serverTLSConfig builds the listener's tls.Config, or nil for plaintext.
// A half-configuration is an error rather than a silent downgrade.
func (s *Server) serverTLSConfig() (*tls.Config, error) {
	cert, key := strings.TrimSpace(s.TLSCertFile), strings.TrimSpace(s.TLSKeyFile)
	switch {
	case cert == "" && key == "":
		return nil, nil
	case cert == "":
		return nil, fmt.Errorf("serve: a TLS key was configured without a certificate; " +
			"set both --tls-cert and --tls-key")
	case key == "":
		return nil, fmt.Errorf("serve: a TLS certificate was configured without a key; " +
			"set both --tls-cert and --tls-key")
	}
	cfg, err := tlsconf.ServerConfig(cert, key, s.TLSMinVersion)
	if err != nil {
		return nil, fmt.Errorf("serve: %w", err)
	}
	return cfg, nil
}

// securityHeadersMiddleware sets the headers that apply to a JSON API.
//
// It is a smaller set than the dashboard's: there is no HTML to frame and no
// script to inject, so nosniff plus HSTS is the whole of it. CSP and
// X-Frame-Options are omitted rather than cargo-culted, because a header that
// governs nothing is a header nobody maintains.
func (s *Server) securityHeadersMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		// Or when this process is configured for TLS: a plaintext port
		// fronted by a terminator elsewhere is the same HTTPS deployment, and
		// a browser ignores the header on a response that arrived in
		// plaintext.
		if s.requestIsTLS(r) || strings.TrimSpace(s.TLSCertFile) != "" {
			w.Header().Set("Strict-Transport-Security", hstsValue)
		}
		next.ServeHTTP(w, r)
	})
}

// requestIsTLS reports whether the client reached this deployment over TLS,
// directly or through a reverse proxy that said so via X-Forwarded-Proto —
// believed from loopback and ui.trusted_proxies only (Task 20394), as the
// dashboard does. It used to be believed from any peer once this process had a
// certificate; HSTS for that topology is now sent on the declaration alone
// (securityHeadersMiddleware), without trusting the header.
func (s *Server) requestIsTLS(r *http.Request) bool {
	return sameorigin.ViewOf(r, s.TrustedProxies.TrustsPeer(r)).TLS()
}
