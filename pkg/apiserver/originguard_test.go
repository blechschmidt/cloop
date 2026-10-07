package apiserver

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/pkg/sameorigin"
)

// guarded is the server's middleware in front of a handler that records
// whether it was reached.
func guarded(s *Server) (http.Handler, *int) {
	reached := 0
	return s.originGuard(s.authMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached++
		w.WriteHeader(http.StatusNoContent)
	}))), &reached
}

// TestServeWithoutATokenGrantsNoPageElsewhere (Task 20394): `cloop serve` used
// to answer every origin with Access-Control-Allow-Origin: * and grant every
// preflight, so on its default — no token, on loopback — any page on the
// Internet could read the plan and POST /run/start.
func TestServeWithoutATokenGrantsNoPageElsewhere(t *testing.T) {
	s := &Server{WorkDir: t.TempDir()}
	h, reached := guarded(s)

	for _, method := range []string{http.MethodGet, http.MethodOptions} {
		r := httptest.NewRequest(method, "http://127.0.0.1:8081/plan", nil)
		r.Header.Set("Origin", "https://evil.example")
		r.Header.Set("Access-Control-Request-Method", "POST")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, r)
		if v := rec.Header().Get("Access-Control-Allow-Origin"); v != "" {
			t.Errorf("%s from a page elsewhere: Access-Control-Allow-Origin: %s", method, v)
		}
		if method == http.MethodOptions && rec.Code == http.StatusNoContent && *reached == 0 {
			t.Error("a preflight was granted without a token")
		}
	}

	for _, tc := range []struct {
		name   string
		header map[string]string
		ct     string
		want   int
	}{
		{"cross-site run start", map[string]string{"Sec-Fetch-Site": "cross-site", "Origin": "https://evil.example"}, "", http.StatusForbidden},
		{"another loopback port", map[string]string{"Sec-Fetch-Site": "same-site", "Origin": "http://127.0.0.1:3000"}, "", http.StatusForbidden},
		{"a text/plain form", nil, "text/plain", http.StatusUnsupportedMediaType},
		{"its own page", map[string]string{"Sec-Fetch-Site": "same-origin"}, "application/json", http.StatusNoContent},
		{"a CLI", nil, "application/json", http.StatusNoContent},
	} {
		r := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:8081/run/start", strings.NewReader(`{}`))
		r.RemoteAddr = "127.0.0.1:40000"
		if tc.ct != "" {
			r.Header.Set("Content-Type", tc.ct)
		}
		for k, v := range tc.header {
			r.Header.Set(k, v)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, r)
		if rec.Code != tc.want {
			t.Errorf("%s: %d %s, want %d", tc.name, rec.Code, rec.Body.String(), tc.want)
		}
	}
}

// TestServeWithoutATokenRefusesARebindingHost: DNS rebinding makes a page on
// attacker.example same-origin with a tokenless server on loopback.
func TestServeWithoutATokenRefusesARebindingHost(t *testing.T) {
	for _, tc := range []struct {
		token, host string
		allowed     []string
		want        int
	}{
		{"", "attacker.example:8081", nil, http.StatusMisdirectedRequest},
		{"", "127.0.0.1:8081", nil, http.StatusNoContent},
		{"", "localhost:8081", nil, http.StatusNoContent},
		{"", "devbox.lan:8081", []string{"devbox.lan"}, http.StatusNoContent},
		// With a token the name proves nothing either way: the page cannot
		// present the token.
		{"tok", "attacker.example:8081", nil, http.StatusUnauthorized},
	} {
		s := &Server{WorkDir: t.TempDir(), Token: tc.token, AllowedHosts: tc.allowed}
		h, _ := guarded(s)
		r := httptest.NewRequest(http.MethodGet, "http://"+tc.host+"/plan", nil)
		r.Host = tc.host
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, r)
		if rec.Code != tc.want {
			t.Errorf("token=%q Host %s: %d, want %d", tc.token, tc.host, rec.Code, tc.want)
		}
	}
}

// TestServeWithATokenKeepsCORSForTheTokenHolder: a tool on another origin the
// operator handed the token to — a hosted OpenAPI explorer — still gets its
// preflight and its answer, because every request it makes carries the token.
func TestServeWithATokenKeepsCORSForTheTokenHolder(t *testing.T) {
	s := &Server{WorkDir: t.TempDir(), Token: "tok"}
	h, reached := guarded(s)
	pre := httptest.NewRequest(http.MethodOptions, "http://hub.example.com:8081/run/start", nil)
	pre.Header.Set("Origin", "https://explorer.example")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, pre)
	if rec.Code != http.StatusNoContent || rec.Header().Get("Access-Control-Allow-Origin") == "" ||
		!strings.Contains(rec.Header().Get("Access-Control-Allow-Headers"), "Authorization") {
		t.Fatalf("preflight with a token: %d %v", rec.Code, rec.Header())
	}
	post := httptest.NewRequest(http.MethodPost, "http://hub.example.com:8081/run/start", strings.NewReader(`{}`))
	post.Header.Set("Origin", "https://explorer.example")
	post.Header.Set("Sec-Fetch-Site", "cross-site")
	post.Header.Set("Content-Type", "application/json")
	post.Header.Set("Authorization", "Bearer tok")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, post)
	if rec.Code != http.StatusNoContent || *reached != 1 {
		t.Errorf("a bearer request from the explorer: %d %s", rec.Code, rec.Body.String())
	}
}

// TestServeBelievesForwardedHeadersOnlyFromATrustedProxy: the scheme decides
// HSTS and the origin; the client address keys the rate limiter.
func TestServeBelievesForwardedHeadersOnlyFromATrustedProxy(t *testing.T) {
	s := &Server{TrustedProxies: sameorigin.MustParseProxies("10.0.0.0/8")}
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "203.0.113.9:1"
	r.Header.Set("X-Forwarded-Proto", "https")
	r.Header.Set("X-Forwarded-For", "198.51.100.1")
	if s.requestIsTLS(r) {
		t.Error("X-Forwarded-Proto from an untrusted peer was believed")
	}
	if got := s.clientIP(r); got != "203.0.113.9" {
		t.Errorf("clientIP = %s, want the peer", got)
	}
	r.RemoteAddr = "10.4.4.4:1"
	if !s.requestIsTLS(r) || s.clientIP(r) != "198.51.100.1" {
		t.Error("a proxy in ui.trusted_proxies was not believed")
	}
}
