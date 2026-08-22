package oidcauth

// cookie_test.go covers the session cookie's SameSite policy and the landing
// page that makes SameSite=Strict survive the IdP round trip.
//
// Strict is the strongest setting a session cookie can carry: the browser
// withholds it from every cross-site request, including top-level navigations,
// so CSRF against the dashboard is not merely defended against but
// unexpressible. It has exactly one cost, and it is the reason most
// deployments quietly stay on Lax — the navigation from the identity provider
// back to /auth/callback is cross-site, so a Strict cookie set on that response
// is not sent on the redirect that follows, and the user lands back on the
// login page in a loop.
//
// Both the policy and the mitigation are pinned here, because a regression in
// either is invisible in normal use: reverting to Lax silently weakens every
// session, and dropping the landing page breaks login only under Strict, only
// in some browsers, and only in production.

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestSessionCookieSameSiteFollowsSecure pins the policy: Strict over TLS,
// Lax on plaintext (loopback development, where there is no attacker for
// Strict to stop and the landing-page round trip is pure friction).
func TestSessionCookieSameSiteFollowsSecure(t *testing.T) {
	idp := newFakeIdP(t)

	plain := httptest.NewRequest(http.MethodGet, "/", nil)

	proxied := httptest.NewRequest(http.MethodGet, "/", nil)
	proxied.Header.Set("X-Forwarded-Proto", "https")

	direct := httptest.NewRequest(http.MethodGet, "/", nil)
	direct.TLS = &tls.ConnectionState{}

	for _, tc := range []struct {
		name     string
		mode     string
		req      *http.Request
		wantSec  bool
		wantSite http.SameSite
	}{
		{"auto over plaintext", "auto", plain, false, http.SameSiteLaxMode},
		{"auto behind an https proxy", "auto", proxied, true, http.SameSiteStrictMode},
		{"auto with native TLS", "auto", direct, true, http.SameSiteStrictMode},
		{"always forces Strict even on plaintext", "always", plain, true, http.SameSiteStrictMode},
		{"never stays Lax even over TLS", "never", direct, false, http.SameSiteLaxMode},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := newTestAuthenticator(t, idp)
			a.cfg.CookieSecure = tc.mode
			c := a.sessionCookie(tc.req, "value", 60)

			if c.Secure != tc.wantSec {
				t.Errorf("Secure = %v, want %v", c.Secure, tc.wantSec)
			}
			if c.SameSite != tc.wantSite {
				t.Errorf("SameSite = %v, want %v", c.SameSite, tc.wantSite)
			}
			// HttpOnly is not conditional on anything: a session cookie
			// readable from script is one XSS away from being exfiltrated,
			// regardless of transport.
			if !c.HttpOnly {
				t.Error("session cookie is not HttpOnly")
			}
			if c.Path != "/" {
				t.Errorf("Path = %q, want /", c.Path)
			}
		})
	}
}

// TestSecureSessionIsNeverSentCrossSite is the property statement rather than
// the field check: over TLS, no configuration path may leave the cookie at
// SameSite=None (or unset, which several browsers still treat as None).
func TestSecureSessionIsNeverSentCrossSite(t *testing.T) {
	idp := newFakeIdP(t)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.TLS = &tls.ConnectionState{}

	for _, mode := range []string{"", "auto", "always"} {
		a := newTestAuthenticator(t, idp)
		a.cfg.CookieSecure = mode
		c := a.sessionCookie(req, "value", 60)
		if c.SameSite == http.SameSiteNoneMode || c.SameSite == http.SameSiteDefaultMode {
			t.Errorf("mode %q: SameSite = %v — the session would ride cross-site requests",
				mode, c.SameSite)
		}
		if !c.Secure {
			t.Errorf("mode %q: a TLS session cookie is missing the Secure flag", mode)
		}
	}
}

// TestCallbackUsesLandingPageUnderStrict is the mitigation.
//
// After the IdP redirects the browser to /auth/callback, the whole navigation
// chain is cross-site, so a 302 to "/" would not carry the freshly-set Strict
// cookie and the dashboard would bounce the user straight back to login. A
// client-initiated navigation from a page already on our origin is
// unambiguously same-site, so the cookie rides along.
func TestCallbackUsesLandingPageUnderStrict(t *testing.T) {
	idp := newFakeIdP(t)
	a := newTestAuthenticator(t, idp)
	a.cfg.CookieSecure = "always" // as if behind TLS

	state, nonce := beginLogin(t, a)
	idp.nonce = nonce
	rec := doCallback(a, state)

	if rec.Code != http.StatusOK {
		t.Fatalf("callback status = %d, want 200 (a redirect would drop the Strict cookie); body: %s",
			rec.Code, rec.Body.String())
	}

	var c *http.Cookie
	for _, got := range rec.Result().Cookies() {
		if got.Name == SessionCookieName {
			c = got
		}
	}
	if c == nil {
		t.Fatal("no session cookie set by the callback")
	}
	if c.SameSite != http.SameSiteStrictMode {
		t.Errorf("SameSite = %v, want Strict", c.SameSite)
	}
	if c.Value == "" {
		t.Fatal("session cookie is empty")
	}

	body := rec.Body.String()
	// Three independent ways to reach "/": script, meta refresh, and a link.
	// The first two cover the automatic case under different browser settings;
	// the link means a user with both disabled gets a button rather than a
	// blank page.
	for _, want := range []string{`location.replace("/")`, `http-equiv="refresh"`, `href="/"`} {
		if !strings.Contains(body, want) {
			t.Errorf("landing page is missing %s:\n%s", want, body)
		}
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Errorf("Content-Type = %q, want text/html", ct)
	}
	// The page carries a live session in a Set-Cookie header; a shared cache
	// storing it would hand that session to the next visitor.
	if cc := rec.Header().Get("Cache-Control"); !strings.Contains(cc, "no-store") {
		t.Errorf("Cache-Control = %q, want no-store", cc)
	}

	// The session must be usable straight away — the landing page is a
	// navigation aid, not an extra step in the handshake.
	req := httptest.NewRequest(http.MethodGet, "/api/state", nil)
	req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: c.Value})
	if a.IdentityFromRequest(req) == nil {
		t.Fatal("the session established by the callback is not valid")
	}
}

// TestCallbackRedirectsOnPlaintext keeps the cheap path for loopback
// development: with a Lax cookie the ordinary 302 works and saves a round trip.
func TestCallbackRedirectsOnPlaintext(t *testing.T) {
	idp := newFakeIdP(t)
	a := newTestAuthenticator(t, idp)
	a.cfg.CookieSecure = "never"

	state, nonce := beginLogin(t, a)
	idp.nonce = nonce
	rec := doCallback(a, state)

	if rec.Code != http.StatusFound {
		t.Fatalf("callback status = %d, want 302", rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != "/" {
		t.Errorf("Location = %q, want /", loc)
	}
}

// TestLogoutCookieMatchesSessionCookie: a clearing cookie whose attributes
// differ from the one it is replacing is a *different* cookie as far as the
// browser is concerned, so the real session would survive the logout.
func TestLogoutCookieMatchesSessionCookie(t *testing.T) {
	idp := newFakeIdP(t)
	a := newTestAuthenticator(t, idp)
	a.cfg.CookieSecure = "always"

	req := httptest.NewRequest(http.MethodPost, "/auth/logout", nil)
	req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: "whatever"})
	rec := httptest.NewRecorder()
	a.Logout(rec, req)

	var c *http.Cookie
	for _, got := range rec.Result().Cookies() {
		if got.Name == SessionCookieName {
			c = got
		}
	}
	if c == nil {
		t.Fatal("logout set no cookie")
	}
	if c.Value != "" || c.MaxAge >= 0 {
		t.Errorf("logout cookie does not clear the session: value=%q maxAge=%d", c.Value, c.MaxAge)
	}
	want := a.sessionCookie(req, "", -1)
	if c.SameSite != want.SameSite || c.Secure != want.Secure || c.Path != want.Path {
		t.Errorf("logout cookie attributes differ from the session cookie's "+
			"(SameSite %v/%v, Secure %v/%v, Path %q/%q) — the browser would keep the original",
			c.SameSite, want.SameSite, c.Secure, want.Secure, c.Path, want.Path)
	}
}
