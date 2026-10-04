package security

// Guarantee 13: the dashboard cannot be framed, and the two documents of the
// silent sign-in renewal only by the dashboard's own origin (Task 20359).
//
// Silent renewal needs a hidden frame: the dashboard loads /auth/renew, which
// redirects to the identity provider with prompt=none, which sends the frame
// back to the OIDC callback. Both of those documents must therefore be
// framable — and the moment anything is framable, clickjacking is back on the
// table for whatever else the relaxation reaches. The safe shape is narrow in
// two directions at once: exactly those two documents, and only by this
// origin. A relaxation by prefix ("everything under /auth/") or by value
// ("SAMEORIGIN everywhere, it is our own origin anyway") would each pass a
// test that only looked at the renewal path.
//
// So this sweeps every route the hub serves, through the real middleware
// chain, with single sign-on configured at a non-default callback path — a
// sweep against /auth/callback alone would not notice a hard-coded path.
//
// The rest of the renewal's guarantees are asserted where they can be checked
// against the real thing:
//
//	no cookie, no lifetime extension, no idle-clock advance, no subject change
//	    pkg/oidcauth: TestSilentRenewNeverSetsACookie,
//	    TestSilentRenewDoesNotExtendTheAbsoluteCeiling,
//	    TestSilentRenewLeavesTheIdleClockAlone, TestSilentRenewRefusesADifferentSubject
//	the verdict goes to a same-origin parent only
//	    pkg/oidcauth: TestRenewDocumentPostsOnlyToItsOwnOrigin; in Chrome,
//	    pkg/ui: TestSilentRenewalInBrowser
//	the login route is not an open redirector
//	    pkg/oidcauth: TestSafeReturnPath, TestLoginRefusesAnOffSiteReturn
//	two hub processes never race one session's claims
//	    pkg/ui: TestClusterRenewalCompletesOnTheMemberThatBeganIt

import (
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/internal/statedbtest"
	"github.com/blechschmidt/cloop/pkg/oidcauth"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/ui"
)

func TestOnlyTheRenewalDocumentsAreFramable(t *testing.T) {
	// An issuer that answers nothing: the sweep must not depend on, or wait
	// for, a provider. Loopback, so plain http is accepted.
	idp := httptest.NewServer(http.NotFoundHandler())
	t.Cleanup(idp.Close)

	dir := statedbtest.Dir(t)
	if _, err := state.Init(dir, "framing conformance", 0); err != nil {
		t.Fatalf("state.Init: %v", err)
	}
	srv := ui.New(dir, 0, "")
	auth, err := oidcauth.New(oidcauth.Config{
		Enabled:     true,
		Issuer:      idp.URL,
		ClientID:    "cloop-dashboard",
		RedirectURL: "https://hub.example.com/auth/oidc",
	})
	if err != nil {
		t.Fatalf("oidcauth.New: %v", err)
	}
	srv.OIDC = auth
	// The rate limiter sits outside the hardening layer, so a 429 carries no
	// headers at all; a sweep from one address must not be throttled into
	// passing or failing for that reason.
	srv.RPS, srv.Burst = 1e6, 1e6
	h := srv.Handler()

	framable := map[string]bool{"/auth/renew": true, "/auth/oidc": true}
	wildcard := regexp.MustCompile(`\{[^}]+\}`)
	paths := map[string]bool{"/auth/oidc": true, "/auth/callback": true, "/": true}
	for _, rt := range ui.APIRoutes() {
		if rt.Method == http.MethodGet {
			paths[wildcard.ReplaceAllString(rt.Path, "x")] = true
		}
	}
	if len(paths) < 50 {
		t.Fatalf("swept only %d paths — the route table is not being read, so this would pass vacuously", len(paths))
	}

	// The liveness and readiness probes are answered before every middleware,
	// hardening included: they return a fixed JSON body to load balancers.
	delete(paths, "/healthz")
	delete(paths, "/readyz")
	for path := range paths {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		csp := rec.Header().Get("Content-Security-Policy")
		xfo := rec.Header().Values("X-Frame-Options")
		if framable[path] {
			if !strings.Contains(csp, "frame-ancestors 'self'") || len(xfo) == 0 || xfo[len(xfo)-1] != "SAMEORIGIN" {
				t.Errorf("%s: frame-ancestors/X-Frame-Options = %q/%v, want 'self'/SAMEORIGIN — "+
					"the renewal frame could not load it", path, csp, xfo)
			}
			continue
		}
		if !strings.Contains(csp, "frame-ancestors 'none'") || len(xfo) != 1 || xfo[0] != "DENY" {
			t.Errorf("%s: frame-ancestors/X-Frame-Options = %q/%v, want 'none'/DENY — "+
				"only the two renewal documents may be framed", path, csp, xfo)
		}
	}

	// And the dashboard may frame the provider and nothing else on another
	// origin: frame-src is the list a malicious script on the page would
	// need to embed anything of its own.
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if want := "frame-src 'self' " + idp.URL + ";"; !strings.Contains(rec.Header().Get("Content-Security-Policy"), want) {
		t.Errorf("dashboard CSP = %q, want exactly %q", rec.Header().Get("Content-Security-Policy"), want)
	}
}
