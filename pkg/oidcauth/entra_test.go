package oidcauth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The three behaviours here all come from one deployment: a cloop hub behind
// Microsoft Entra ID, with the callback registered under Entra's "Single-page
// application" platform. Each was a defect that produced no useful diagnostic
// — a login loop, a startup refusal, and a token exchange rejected for a
// reason that named the authorization code instead of the registration.

// entraCfg is a minimal valid Config pointed at a test server.
func entraCfg(issuer, redirect string) Config {
	return Config{
		Enabled:     true,
		Issuer:      issuer,
		ClientID:    "33dc8f31-6f43-4b46-abf9-86ea785b6008",
		RedirectURL: redirect,
	}
}

// TestCallbackPathFollowsRedirectURL locks in that the hub serves the callback
// where the IdP actually sends the browser. Before this, the route was fixed
// at /auth/callback: an app registration using any other path authenticated
// the user and then dropped them into the SPA shell with no session, which
// presents as an endless redirect to /auth/login.
func TestCallbackPathFollowsRedirectURL(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name     string
		redirect string
		want     string
	}{
		{"default", "https://cloop.example.com/auth/callback", "/auth/callback"},
		{"entra spa registration", "https://aiden.blechschmidt.io:8889/auth/oidc", "/auth/oidc"},
		{"nested", "https://cloop.example.com/auth/sso/return", "/auth/sso/return"},
		{"query string is not part of the path", "https://cloop.example.com/auth/cb?x=1", "/auth/cb"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			a, err := New(entraCfg("https://idp.example.com", tc.redirect))
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			if got := a.CallbackPath(); got != tc.want {
				t.Errorf("CallbackPath() = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestCallbackPathDefaultsWhenUnusable covers the two receivers that have no
// configured redirect to read. Both must report the default rather than "",
// which as a mux pattern would panic the route table at startup.
func TestCallbackPathDefaultsWhenUnusable(t *testing.T) {
	t.Parallel()

	var nilAuth *Authenticator
	if got := nilAuth.CallbackPath(); got != DefaultCallbackPath {
		t.Errorf("nil authenticator: CallbackPath() = %q, want %q", got, DefaultCallbackPath)
	}
	// A hand-built zero value, as a test elsewhere might produce.
	if got := (&Authenticator{}).CallbackPath(); got != DefaultCallbackPath {
		t.Errorf("zero authenticator: CallbackPath() = %q, want %q", got, DefaultCallbackPath)
	}
}

// TestRedirectURLPathIsConstrained is the fail-closed half: a redirect_url
// cloop cannot serve is refused at startup with an explanation, rather than
// accepted and discovered by a user who can never sign in. The /auth/ prefix
// is what lets oidcGate pass the callback through unauthenticated and what
// stops a stray path shadowing "/" or an /api route.
func TestRedirectURLPathIsConstrained(t *testing.T) {
	t.Parallel()

	bad := []string{
		"https://cloop.example.com/callback", // outside /auth/
		"https://cloop.example.com/",         // would shadow the dashboard
		"https://cloop.example.com",          // no path at all
		"https://cloop.example.com/auth/",    // nothing after the prefix
		"https://cloop.example.com/api/oidc", // would shadow the API
		"https://cloop.example.com/authx/cb", // prefix must be a path segment
	}
	for _, redirect := range bad {
		t.Run(redirect, func(t *testing.T) {
			t.Parallel()
			_, err := New(entraCfg("https://idp.example.com", redirect))
			if err == nil {
				t.Fatalf("New accepted unusable redirect_url %q", redirect)
			}
			if !strings.Contains(err.Error(), "/auth/") {
				t.Errorf("error should name the constraint, got: %v", err)
			}
		})
	}
}

// TestDiscoveryAcceptsSameOriginIssuerAlias is the Entra tenant-addressing
// case, verified against the real provider before it was written: fetching
// .../{domain}.onmicrosoft.com/v2.0/.well-known/openid-configuration returns
// a document declaring .../{tenant-guid}/v2.0. Both name the same provider at
// the same origin, and the GUID form is what ID tokens carry — which is the
// form this package already validates them against.
func TestDiscoveryAcceptsSameOriginIssuerAlias(t *testing.T) {
	t.Parallel()

	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{
			// Same host, different path — the tenant addressed by GUID.
			"issuer":                 srv.URL + "/fe0a66c4-bd40-47f9-a1af-b63c8dda09cf/v2.0",
			"authorization_endpoint": srv.URL + "/authorize",
			"token_endpoint":         srv.URL + "/token",
			"jwks_uri":               srv.URL + "/jwks",
		})
	}))
	defer srv.Close()

	doc, err := fetchDiscovery(context.Background(), srv.Client(), srv.URL+"/contoso.onmicrosoft.com/v2.0")
	if err != nil {
		t.Fatalf("same-origin alias rejected: %v", err)
	}
	if !strings.Contains(doc.Issuer, "fe0a66c4") {
		t.Errorf("declared issuer not preserved: %q", doc.Issuer)
	}
}

// TestDiscoveryRefusesCrossOriginIssuer is the half that must not loosen. A
// document that names a provider at another origin is not an alias — it is
// somebody else's metadata, and accepting it would let whoever controls the
// configured URL nominate an arbitrary token issuer.
func TestDiscoveryRefusesCrossOriginIssuer(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{
			"issuer":                 "https://attacker.example.com/v2.0",
			"authorization_endpoint": "https://attacker.example.com/authorize",
			"token_endpoint":         "https://attacker.example.com/token",
			"jwks_uri":               "https://attacker.example.com/jwks",
		})
	}))
	defer srv.Close()

	_, err := fetchDiscovery(context.Background(), srv.Client(), srv.URL)
	if err == nil {
		t.Fatal("cross-origin issuer redefinition was accepted")
	}
	var pe *PreflightError
	if !asPreflight(err, &pe) {
		t.Fatalf("want *PreflightError, got %T: %v", err, err)
	}
	if pe.Reason != PreflightIssuerMismatch {
		t.Errorf("reason = %q, want %q", pe.Reason, PreflightIssuerMismatch)
	}
}

// TestSameOriginIssuer covers the comparison directly, including the cases a
// round trip cannot easily produce.
func TestSameOriginIssuer(t *testing.T) {
	t.Parallel()

	cases := []struct {
		configured, declared string
		want                 bool
	}{
		{"https://login.microsoftonline.com/contoso.onmicrosoft.com/v2.0",
			"https://login.microsoftonline.com/fe0a66c4-bd40-47f9-a1af-b63c8dda09cf/v2.0", true},
		{"https://idp.example.com/main", "https://IDP.EXAMPLE.COM/other", true}, // host compare is case-insensitive
		{"https://idp.example.com", "https://idp.example.com/", true},
		// A different port is a different origin.
		{"https://idp.example.com", "https://idp.example.com:8443", false},
		// A downgrade to plaintext is a different origin, not an alias.
		{"https://idp.example.com/a", "http://idp.example.com/a", false},
		{"https://idp.example.com", "https://evil.example.com", false},
		// A subdomain is not the same origin.
		{"https://idp.example.com", "https://sso.idp.example.com", false},
		{"https://idp.example.com", "", false},
		{"", "https://idp.example.com", false},
		{"https://idp.example.com", "not a url at all", false},
	}
	for _, tc := range cases {
		if got := sameOriginIssuer(tc.configured, tc.declared); got != tc.want {
			t.Errorf("sameOriginIssuer(%q, %q) = %v, want %v",
				tc.configured, tc.declared, got, tc.want)
		}
	}
}

// TestSPACallbackRetriesWithOrigin is the Entra single-page-application rule.
// A redirect URI registered under that platform may only be redeemed
// cross-origin; Go's http.Client sends no Origin header, so every server-side
// redemption was refused with AADSTS9002327 and the operator saw an error
// blaming the authorization code.
//
// The first attempt must carry no Origin — a Web or desktop registration is
// refused with AADSTS9002326 when one is present, so the header cannot be
// sent pre-emptively.
func TestSPACallbackRetriesWithOrigin(t *testing.T) {
	t.Parallel()

	var origins []string
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			_ = json.NewEncoder(w).Encode(map[string]string{
				"issuer":                 srv.URL,
				"authorization_endpoint": srv.URL + "/authorize",
				"token_endpoint":         srv.URL + "/token",
				"jwks_uri":               srv.URL + "/jwks",
			})
		case "/token":
			origin := r.Header.Get("Origin")
			origins = append(origins, origin)
			if origin == "" {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte(`{"error":"invalid_request","error_description":` +
					`"AADSTS9002327: Tokens issued for the 'Single-Page Application' client-type ` +
					`may only be redeemed via cross-origin requests."}`))
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"access_token": "at", "id_token": "it", "token_type": "Bearer", "expires_in": 3600,
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	a, err := New(entraCfg(srv.URL, "https://aiden.blechschmidt.io:8889/auth/oidc"))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	a.client = srv.Client()

	tok, err := a.exchangeCode(context.Background(), "the-code", "the-verifier")
	if err != nil {
		t.Fatalf("exchangeCode: %v", err)
	}
	if tok.AccessToken != "at" {
		t.Errorf("access_token = %q, want %q", tok.AccessToken, "at")
	}
	if len(origins) != 2 {
		t.Fatalf("token endpoint hit %d times (%q), want exactly 2: one without Origin, one with",
			len(origins), origins)
	}
	if origins[0] != "" {
		t.Errorf("first attempt sent Origin %q — it must be absent so a Web "+
			"registration is not refused with AADSTS9002326", origins[0])
	}
	if want := "https://aiden.blechschmidt.io:8889"; origins[1] != want {
		t.Errorf("retry Origin = %q, want %q (the redirect URI's own origin)", origins[1], want)
	}
}

// TestSPARetryNotAttemptedForOtherFailures keeps the retry narrow: an ordinary
// refusal must cost exactly one request, or every genuinely bad code doubles
// the load on the IdP and muddies the error the operator sees.
func TestSPARetryNotAttemptedForOtherFailures(t *testing.T) {
	t.Parallel()

	var hits int
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			_ = json.NewEncoder(w).Encode(map[string]string{
				"issuer":                 srv.URL,
				"authorization_endpoint": srv.URL + "/authorize",
				"token_endpoint":         srv.URL + "/token",
				"jwks_uri":               srv.URL + "/jwks",
			})
		case "/token":
			hits++
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"invalid_grant","error_description":` +
				`"AADSTS9002313: Invalid request. Request is malformed or invalid."}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	a, err := New(entraCfg(srv.URL, "https://cloop.example.com/auth/callback"))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	a.client = srv.Client()

	if _, err := a.exchangeCode(context.Background(), "bad", "verifier"); err == nil {
		t.Fatal("exchangeCode accepted a refused code")
	}
	if hits != 1 {
		t.Errorf("token endpoint hit %d times, want 1 — only AADSTS9002327 earns a retry", hits)
	}
}

// TestSPARetrySkippedForConfidentialClient: Entra refuses client credentials
// and an Origin header in the same request, so a hub configured with a secret
// must not take the SPA path. A registration needing the Origin header should
// not have a secret in the first place.
func TestSPARetrySkippedForConfidentialClient(t *testing.T) {
	t.Parallel()

	var hits int
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			_ = json.NewEncoder(w).Encode(map[string]string{
				"issuer":                 srv.URL,
				"authorization_endpoint": srv.URL + "/authorize",
				"token_endpoint":         srv.URL + "/token",
				"jwks_uri":               srv.URL + "/jwks",
			})
		case "/token":
			hits++
			if got := r.Header.Get("Origin"); got != "" {
				t.Errorf("confidential client sent Origin %q alongside a secret", got)
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"invalid_request","error_description":"AADSTS9002327: ..."}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	cfg := entraCfg(srv.URL, "https://cloop.example.com/auth/oidc")
	cfg.ClientSecret = "s3cret"
	a, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	a.client = srv.Client()

	if _, err := a.exchangeCode(context.Background(), "c", "v"); err == nil {
		t.Fatal("exchangeCode succeeded unexpectedly")
	}
	// Exactly one attempt. The existing secret-encoding retry is keyed on a
	// 401 or invalid_client, and this is a 400 invalid_request, so it does
	// not fire either — which leaves the Origin retry as the only thing that
	// could have produced a second request, and it must not.
	if hits != 1 {
		t.Errorf("token endpoint hit %d times, want 1 — a confidential client "+
			"must not retry with an Origin header", hits)
	}
}

// TestEmailFallsBackToPreferredUsername is the claim that decides whether an
// Entra administrator can do anything after signing in. Entra emits `email`
// only when the account has a mail attribute; the address the person signs in
// with is their UPN, which arrives as `preferred_username`. Reading only
// `email` resolved that administrator to no role at all — an empty dashboard
// with a successful login behind it.
func TestEmailFallsBackToPreferredUsername(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name     string
		email    string
		username string
		want     string
	}{
		{"email claim wins", "Admin@Example.com", "other@example.com", "admin@example.com"},
		{"entra upn with no email claim", "", "microsoft@blechschmidt.saarland", "microsoft@blechschmidt.saarland"},
		{"username is lowercased like an email", "", "Microsoft@Blechschmidt.Saarland", "microsoft@blechschmidt.saarland"},
		// A bare login name is not an address and must not become one: it
		// could never match an email binding, and pretending otherwise
		// would widen identity matching for every provider.
		{"bare username is not an address", "", "dana", ""},
		{"domainless username", "", "dana@localhost", ""},
		{"no claims at all", "", "", ""},
		{"whitespace only", "   ", "  ", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			c := &idClaims{Email: tc.email, PreferredUsername: tc.username}
			if got := c.emailAddress(); got != tc.want {
				t.Errorf("emailAddress() = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestLooksLikeEmail pins the guard directly, including the shapes a hostile
// or merely sloppy provider might send.
func TestLooksLikeEmail(t *testing.T) {
	t.Parallel()

	yes := []string{"a@b.co", "microsoft@blechschmidt.saarland", "first.last@sub.example.com"}
	no := []string{
		"", "dana", "@example.com", "dana@", "dana@com",
		"a@@b.com",      // two separators is not one address
		"a@b.com c@d.e", // a list, not an address
		"a@.com", "a@b.", "a b@c.com",
	}
	for _, s := range yes {
		if !looksLikeEmail(s) {
			t.Errorf("looksLikeEmail(%q) = false, want true", s)
		}
	}
	for _, s := range no {
		if looksLikeEmail(s) {
			t.Errorf("looksLikeEmail(%q) = true, want false", s)
		}
	}
}

// asPreflight is errors.As specialised, kept local so this file states its own
// expectations without reaching for a helper defined for another test.
func asPreflight(err error, target **PreflightError) bool {
	for err != nil {
		if pe, ok := err.(*PreflightError); ok {
			*target = pe
			return true
		}
		u, ok := err.(interface{ Unwrap() error })
		if !ok {
			return false
		}
		err = u.Unwrap()
	}
	return false
}
