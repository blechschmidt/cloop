package ui

// tls_test.go covers the dashboard's TLS configuration and the HSTS header.
//
// The recurring theme is that a transport misconfiguration is silent by
// nature. A server that meant to serve HTTPS and fell back to HTTP still
// answers every request; a missing HSTS header changes nothing a user can see.
// Both are only visible in a packet capture or an incident, so they get pinned
// here instead.

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/blechschmidt/cloop/pkg/tlsconf"
)

func TestServerTLSConfig(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	cert := filepath.Join(dir, "cert.pem")
	key := filepath.Join(dir, "key.pem")
	if _, err := tlsconf.GenerateSelfSigned(cert, key, tlsconf.SelfSignedOptions{}); err != nil {
		t.Fatalf("GenerateSelfSigned: %v", err)
	}

	t.Run("unset means plaintext", func(t *testing.T) {
		s := &Server{}
		cfg, err := s.serverTLSConfig()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if cfg != nil {
			t.Error("an unconfigured server should serve plaintext, not TLS")
		}
		if s.TLSEnabled() {
			t.Error("TLSEnabled() is true with no certificate configured")
		}
	})

	t.Run("both set means TLS", func(t *testing.T) {
		s := &Server{TLSCertFile: cert, TLSKeyFile: key}
		cfg, err := s.serverTLSConfig()
		if err != nil {
			t.Fatalf("serverTLSConfig: %v", err)
		}
		if cfg == nil {
			t.Fatal("no tls.Config returned for a configured server")
		}
		if cfg.MinVersion != tls.VersionTLS12 {
			t.Errorf("MinVersion = %#x, want TLS 1.2", cfg.MinVersion)
		}
		if !s.TLSEnabled() {
			t.Error("TLSEnabled() is false with a certificate configured")
		}
	})

	t.Run("min version 1.3 is honoured", func(t *testing.T) {
		s := &Server{TLSCertFile: cert, TLSKeyFile: key, TLSMinVersion: "1.3"}
		cfg, err := s.serverTLSConfig()
		if err != nil {
			t.Fatalf("serverTLSConfig: %v", err)
		}
		if cfg.MinVersion != tls.VersionTLS13 {
			t.Errorf("MinVersion = %#x, want TLS 1.3", cfg.MinVersion)
		}
	})

	// A half-configuration must fail loudly. Falling back to plaintext would
	// hand an operator who asked for HTTPS a server that answers every request
	// over HTTP — discovered, if at all, from a browser warning.
	t.Run("half configurations are errors", func(t *testing.T) {
		for _, s := range []*Server{
			{TLSCertFile: cert},
			{TLSKeyFile: key},
		} {
			if _, err := s.serverTLSConfig(); err == nil {
				t.Errorf("cert=%q key=%q: want error, got nil", s.TLSCertFile, s.TLSKeyFile)
			}
		}
	})

	t.Run("bad paths and versions are errors", func(t *testing.T) {
		missing := &Server{TLSCertFile: filepath.Join(dir, "nope.pem"), TLSKeyFile: key}
		if _, err := missing.serverTLSConfig(); err == nil {
			t.Error("missing certificate file: want error")
		}
		obsolete := &Server{TLSCertFile: cert, TLSKeyFile: key, TLSMinVersion: "1.0"}
		if _, err := obsolete.serverTLSConfig(); err == nil {
			t.Error("TLS 1.0 floor: want error")
		}
	})
}

func TestRequestIsTLS(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name        string
		externalURL string
		remoteAddr  string
		tlsState    *tls.ConnectionState
		forwarded   string
		want        bool
	}{
		{"native TLS", "", "203.0.113.5:443", &tls.ConnectionState{}, "", true},
		{"plaintext, no header", "", "203.0.113.5:80", nil, "", false},
		{"loopback proxy says https", "", "127.0.0.1:5555", nil, "https", true},
		{"loopback proxy, chain", "", "127.0.0.1:5555", nil, "https, http", true},
		{"loopback proxy says http", "", "127.0.0.1:5555", nil, "http", false},
		{"ipv6 loopback proxy", "", "[::1]:5555", nil, "https", true},
		{"case insensitive", "", "127.0.0.1:5555", nil, "HTTPS", true},

		// Without a declared external URL the header is only believed from a
		// loopback peer, matching clientIP's trust model for X-Forwarded-For.
		{"remote client cannot claim https", "", "203.0.113.5:80", nil, "https", false},

		// With one, a proxy on another host is recognised — the standard
		// enterprise topology (nginx, ALB, ingress), where the loopback-only
		// rule silently drops HSTS from every response forever.
		{"declared https + remote proxy", "https://hub.example.com", "10.0.0.7:80", nil, "https", true},
		{"declared https, no header", "https://hub.example.com", "10.0.0.7:80", nil, "", false},
		{"declared https, proxy says http", "https://hub.example.com", "10.0.0.7:80", nil, "http", false},
		// A declared *http* external URL grants nothing: the operator did not
		// claim TLS, so a client header cannot manufacture it.
		{"declared http + remote proxy", "http://hub.example.com", "10.0.0.7:80", nil, "https", false},
		{"malformed external url", "://broken", "10.0.0.7:80", nil, "https", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := &Server{ExternalURL: c.externalURL}
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			r.RemoteAddr = c.remoteAddr
			r.TLS = c.tlsState
			if c.forwarded != "" {
				r.Header.Set("X-Forwarded-Proto", c.forwarded)
			}
			if got := s.requestIsTLS(r); got != c.want {
				t.Errorf("requestIsTLS = %v, want %v", got, c.want)
			}
		})
	}
}

// TestSecurityHeadersHSTS pins both directions.
//
// Present over TLS is the point. Absent over plaintext is not a detail: a
// browser ignores HSTS received over http (RFC 6797 §8.1), but a developer
// running `cloop ui` on localhost would otherwise pin *localhost* to https for
// a year, breaking every other local project on that hostname — a genuinely
// nasty thing to do to someone's machine, and hard to undo.
func TestSecurityHeadersHSTS(t *testing.T) {
	t.Parallel()
	srv := &Server{ExternalURL: "https://hub.example.com"}
	handler := srv.securityHeaders(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	t.Run("set over TLS", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.TLS = &tls.ConnectionState{}
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)

		got := w.Header().Get("Strict-Transport-Security")
		if got == "" {
			t.Fatal("no Strict-Transport-Security header on a TLS response")
		}
		if got != hstsValue {
			t.Errorf("HSTS = %q, want %q", got, hstsValue)
		}
	})

	t.Run("set behind a remote https proxy with a declared external URL", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.RemoteAddr = "10.0.0.7:41000"
		r.Header.Set("X-Forwarded-Proto", "https")
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		if w.Header().Get("Strict-Transport-Security") == "" {
			t.Error("no HSTS header behind an off-host TLS terminator — " +
				"the standard enterprise topology")
		}
	})

	t.Run("set behind a loopback https proxy", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.RemoteAddr = "127.0.0.1:5555"
		r.Header.Set("X-Forwarded-Proto", "https")
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		if w.Header().Get("Strict-Transport-Security") == "" {
			t.Error("no HSTS header behind a TLS-terminating reverse proxy — " +
				"the most common way cloop is actually deployed")
		}
	})

	t.Run("absent on plaintext", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.RemoteAddr = "127.0.0.1:5555"
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		if got := w.Header().Get("Strict-Transport-Security"); got != "" {
			t.Errorf("HSTS = %q on a plaintext response; "+
				"this would pin localhost to https in the developer's browser", got)
		}
	})

	// The pre-existing headers must survive the change.
	t.Run("other hardening headers still set", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		for h, want := range map[string]string{
			"X-Content-Type-Options": "nosniff",
			"X-Frame-Options":        "DENY",
			"Referrer-Policy":        "no-referrer",
		} {
			if got := w.Header().Get(h); got != want {
				t.Errorf("%s = %q, want %q", h, got, want)
			}
		}
		if w.Header().Get("Content-Security-Policy") == "" {
			t.Error("Content-Security-Policy is missing")
		}
	})
}

// TestWSOriginAllowedHonoursExternalURL covers the addition to the dashboard's
// own origin check. The hub's equivalent is tested in
// pkg/executor/remote/origin_test.go; both are fed from the same config so
// that one deployment cannot end up with two different answers to "is this
// origin us".
func TestWSOriginAllowedHonoursExternalURL(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name        string
		externalURL string
		allowed     []string
		host        string
		origin      string
		want        bool
	}{
		{"no origin", "", nil, "hub.example.com", "", true},
		{"same origin", "", nil, "hub.example.com", "https://hub.example.com", true},
		{"loopback", "", nil, "hub.example.com", "http://localhost:8080", true},
		{"external url behind a rewriting proxy", "https://hub.example.com", nil,
			"10.0.0.5:8080", "https://hub.example.com", true},
		{"external url with port", "https://hub.example.com:8443", nil,
			"internal:8080", "https://hub.example.com:8443", true},
		{"dashboard allowlist", "", []string{"ops.example.com"}, "hub.example.com", "https://ops.example.com", true},
		{"cross origin", "https://hub.example.com", nil, "hub.example.com", "https://evil.example", false},
		{"suffix confusion", "https://hub.example.com", nil, "hub.example.com",
			"https://hub.example.com.evil.test", false},
		{"malformed external url is ignored", "://broken", nil, "hub.example.com",
			"https://evil.example", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := &Server{ExternalURL: c.externalURL, AllowedWSOrigins: c.allowed}
			r := httptest.NewRequest(http.MethodGet, "/ws", nil)
			r.Host = c.host
			if c.origin != "" {
				r.Header.Set("Origin", c.origin)
			}
			if got := s.wsOriginAllowed(r); got != c.want {
				t.Errorf("wsOriginAllowed(host=%q, origin=%q) = %v, want %v",
					c.host, c.origin, got, c.want)
			}
		})
	}
}

// TestAllowedOriginsScopeIsNotShared pins the blast-radius separation between
// the two allowlists.
//
// ui.allowed_ws_origins is dashboard-scoped; ui.allowed_origins is
// deployment-wide and reaches /api/executors/connect, where an entry can open
// an agent connection. Merging them — which an earlier version of the wiring
// did — silently promotes every dashboard-scoped origin to the agent endpoint.
// The dashboard honours both; only AllowedOrigins is handed to the hub (see
// executor_agents.go).
func TestAllowedOriginsScopeIsNotShared(t *testing.T) {
	t.Parallel()
	s := &Server{
		AllowedWSOrigins: []string{"dash-only.example.com"},
		AllowedOrigins:   []string{"deployment-wide.example.com"},
	}
	for _, origin := range []string{
		"https://dash-only.example.com",
		"https://deployment-wide.example.com",
	} {
		r := httptest.NewRequest(http.MethodGet, "/ws", nil)
		r.Host = "hub.example.com"
		r.Header.Set("Origin", origin)
		if !s.wsOriginAllowed(r) {
			t.Errorf("the dashboard socket refused %s; it must honour both lists", origin)
		}
	}

	// The hub's half of the contract is asserted where it is implemented, in
	// pkg/executor/remote/origin_test.go — it only ever receives AllowedOrigins,
	// so a dashboard-scoped entry cannot reach it. What is checked here is that
	// the field the wiring passes along exists and is distinct.
	if len(s.AllowedOrigins) != 1 || s.AllowedOrigins[0] != "deployment-wide.example.com" {
		t.Fatalf("AllowedOrigins = %v; the two lists must stay separate on Server",
			s.AllowedOrigins)
	}
	if len(s.AllowedWSOrigins) != 1 || s.AllowedWSOrigins[0] != "dash-only.example.com" {
		t.Fatalf("AllowedWSOrigins = %v; the two lists must stay separate on Server",
			s.AllowedWSOrigins)
	}
}
