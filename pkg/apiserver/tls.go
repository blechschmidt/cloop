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
	"net"
	"net/http"
	"strings"

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
		if s.requestIsTLS(r) {
			w.Header().Set("Strict-Transport-Security", hstsValue)
		}
		next.ServeHTTP(w, r)
	})
}

// requestIsTLS reports whether the client reached this deployment over TLS,
// directly or through a reverse proxy that said so via X-Forwarded-Proto.
//
// The header is believed from a loopback peer (a proxy on this host), or from
// any peer once this process is itself configured for TLS — in which case the
// operator has already declared the deployment to be HTTPS, and a plaintext
// port fronted by an off-host terminator is the same deployment. Restricting
// to loopback alone would silently drop HSTS from every response in the
// standard enterprise topology, forever, with nothing in the logs to say so.
// See pkg/ui/tls.go for the same reasoning against ui.external_url.
func (s *Server) requestIsTLS(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	proto := r.Header.Get("X-Forwarded-Proto")
	if i := strings.IndexByte(proto, ','); i >= 0 {
		proto = proto[:i]
	}
	if !strings.EqualFold(strings.TrimSpace(proto), "https") {
		return false
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
		return true
	}
	return strings.TrimSpace(s.TLSCertFile) != ""
}
