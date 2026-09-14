package oidcauth

// Tests for the startup identity preflight and the clock-skew knob
// (Task 20247).
//
// The property under test throughout is that a misconfigured identity provider
// is discovered by the hub rather than by the first person who tries to sign
// in — and that the report names the two things an operator needs to act on:
// which URL was contacted and what came back from it.

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// stubIdP serves whatever the test tells it to at the two metadata endpoints,
// including nothing at all. Distinct from fakeIdP, which is a *working*
// provider used to drive whole logins; this one exists to be broken.
type stubIdP struct {
	server *httptest.Server

	discoveryStatus int    // 0 = 200
	discoveryBody   string // "" = a well-formed document
	issuerOverride  string // what the document calls the issuer ("" = self)

	jwksStatus int
	jwksBody   string

	discoveryHits int
}

func newStubIdP(t *testing.T) *stubIdP {
	t.Helper()
	s := &stubIdP{}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		s.discoveryHits++
		if s.discoveryStatus != 0 {
			w.WriteHeader(s.discoveryStatus)
			_, _ = w.Write([]byte(s.discoveryBody))
			return
		}
		if s.discoveryBody != "" {
			_, _ = w.Write([]byte(s.discoveryBody))
			return
		}
		issuer := s.issuerOverride
		if issuer == "" {
			issuer = s.server.URL
		}
		_ = json.NewEncoder(w).Encode(map[string]string{
			"issuer":                 issuer,
			"authorization_endpoint": s.server.URL + "/authorize",
			"token_endpoint":         s.server.URL + "/token",
			"jwks_uri":               s.server.URL + "/jwks",
			"end_session_endpoint":   s.server.URL + "/logout",
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		if s.jwksStatus != 0 {
			w.WriteHeader(s.jwksStatus)
		}
		body := s.jwksBody
		if body == "" {
			body = `{"keys":[]}`
		}
		_, _ = w.Write([]byte(body))
	})
	s.server = httptest.NewServer(mux)
	t.Cleanup(s.server.Close)
	return s
}

func authenticatorFor(t *testing.T, issuer string) *Authenticator {
	t.Helper()
	a, err := New(Config{
		Enabled:      true,
		Issuer:       issuer,
		ClientID:     "cloop-dashboard",
		ClientSecret: "s3cret",
		RedirectURL:  "http://localhost:8080/auth/callback",
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return a
}

// TestPreflightAgainstFailingIdP is the headline case: an issuer that answers
// with a server error.
//
// Two things are asserted beyond "it returns an error". The issuer URL and the
// HTTP status must both be recoverable from the failure, because an operator
// reading it has to know *which* of the several URLs in their config was
// contacted and whether the provider answered at all — a 500 is an outage, a
// 404 is a wrong path, and the remediation differs.
func TestPreflightAgainstFailingIdP(t *testing.T) {
	idp := newStubIdP(t)
	idp.discoveryStatus = http.StatusInternalServerError
	idp.discoveryBody = `{"error":"realm unavailable"}`

	a := authenticatorFor(t, idp.server.URL)
	res, err := a.Preflight(context.Background())
	if err == nil {
		t.Fatalf("Preflight succeeded against an issuer returning 500: %+v", res)
	}

	var pe *PreflightError
	if !errors.As(err, &pe) {
		t.Fatalf("Preflight error is %T, want *PreflightError: %v", err, err)
	}
	if pe.Status != http.StatusInternalServerError {
		t.Errorf("Status = %d, want 500 — an operator cannot tell an outage from a wrong path without it", pe.Status)
	}
	if pe.Stage != StageDiscovery {
		t.Errorf("Stage = %q, want %q", pe.Stage, StageDiscovery)
	}
	if pe.Reason != PreflightUnreachable {
		t.Errorf("Reason = %q, want %q", pe.Reason, PreflightUnreachable)
	}
	if pe.Resolved != nil {
		t.Error("a discovery failure established nothing and must not report a resolved document")
	}
	if !strings.Contains(err.Error(), idp.server.URL) {
		t.Errorf("error does not name the issuer URL, so it names nothing actionable: %v", err)
	}
	if !strings.Contains(err.Error(), "500") {
		t.Errorf("error does not name the HTTP status: %v", err)
	}
	if pe.Remediation() == "" {
		t.Error("every preflight failure must carry a remediation")
	}

	// The whole point of the gate: readiness reports the same failure rather
	// than a hub that looks healthy until somebody tries to sign in.
	if ready := a.IdPReady(); ready == nil {
		t.Fatal("IdPReady is nil after a failed preflight, so /readyz would report a hub nobody can log into as ready")
	}
}

// TestPreflightJWKSFailureStillReportsDiscovery: the stages fail separately and
// are diagnosed separately. An unusable key set is not a reason to go quiet
// about an issuer that resolved.
func TestPreflightJWKSFailureStillReportsDiscovery(t *testing.T) {
	idp := newStubIdP(t)
	idp.jwksStatus = http.StatusNotFound

	a := authenticatorFor(t, idp.server.URL)
	_, err := a.Preflight(context.Background())
	if err == nil {
		t.Fatal("Preflight succeeded with an unreachable JWKS endpoint")
	}
	var pe *PreflightError
	if !errors.As(err, &pe) {
		t.Fatalf("error is %T, want *PreflightError", err)
	}
	if pe.Stage != StageJWKS {
		t.Fatalf("Stage = %q, want %q", pe.Stage, StageJWKS)
	}
	if pe.Resolved == nil {
		t.Fatal("a JWKS failure must still report what discovery established")
	}
	if pe.Resolved.TokenEndpoint == "" || pe.Resolved.AuthorizationEndpoint == "" {
		t.Errorf("resolved document is missing endpoints: %+v", pe.Resolved)
	}
	if a.IdPReady() == nil {
		t.Error("a hub that cannot fetch signing keys can verify no token and is not ready")
	}
}

// TestPreflightEmptyKeySetIsNotUsable. The provider works; this hub can never
// validate a token it issues, which presents to a user as "login worked and
// then nothing happened".
func TestPreflightEmptyKeySetIsNotUsable(t *testing.T) {
	idp := newStubIdP(t)
	idp.jwksBody = `{"keys":[]}`

	_, err := Preflight(context.Background(), idp.server.URL, PreflightOptions{Client: idp.server.Client()})
	var pe *PreflightError
	if !errors.As(err, &pe) || pe.Reason != PreflightNoKeys {
		t.Fatalf("want a %s failure, got %v", PreflightNoKeys, err)
	}
}

// TestPreflightIssuerMismatch. The spec makes this equality load-bearing and
// cloop enforces it at token validation, so a document that disagrees about
// its own name is a hub where every sign-in fails.
func TestPreflightIssuerMismatch(t *testing.T) {
	idp := newStubIdP(t)
	idp.issuerOverride = "https://somewhere-else.example.com"

	_, err := Preflight(context.Background(), idp.server.URL, PreflightOptions{Client: idp.server.Client()})
	var pe *PreflightError
	if !errors.As(err, &pe) || pe.Reason != PreflightIssuerMismatch {
		t.Fatalf("want an %s failure, got %v", PreflightIssuerMismatch, err)
	}
	if !strings.Contains(err.Error(), "somewhere-else.example.com") {
		t.Errorf("the error must name what the provider calls itself: %v", err)
	}
}

// TestPreflightSucceedsAndResolvesEndpoints covers the reporting half: what an
// operator is shown by `cloop hub doctor` when it works.
func TestPreflightSucceedsAndResolvesEndpoints(t *testing.T) {
	full := newFakeIdP(t) // a provider that actually publishes a usable key
	a := newTestAuthenticator(t, full)

	res, err := a.Preflight(context.Background())
	if err != nil {
		t.Fatalf("Preflight: %v", err)
	}
	if res.AuthorizationEndpoint != full.server.URL+"/authorize" {
		t.Errorf("authorization_endpoint = %q", res.AuthorizationEndpoint)
	}
	if res.TokenEndpoint != full.server.URL+"/token" {
		t.Errorf("token_endpoint = %q", res.TokenEndpoint)
	}
	if res.JWKSURI != full.server.URL+"/jwks" {
		t.Errorf("jwks_uri = %q", res.JWKSURI)
	}
	if res.SigningKeys != 1 {
		t.Errorf("signing_keys = %d, want 1", res.SigningKeys)
	}
	if err := a.IdPReady(); err != nil {
		t.Errorf("IdPReady after a clean preflight = %v, want nil", err)
	}
}

// TestLazyPathRecoversFromAFailedPreflight is the other half of the design: a
// preflight that failed must not latch the hub into a broken state, because
// the IdP being down for a minute at startup is a transient condition and
// requiring a restart to notice it had cleared would be a worse failure than
// the one the preflight exists to catch.
func TestLazyPathRecoversFromAFailedPreflight(t *testing.T) {
	idp := newStubIdP(t)
	idp.discoveryStatus = http.StatusServiceUnavailable

	a := authenticatorFor(t, idp.server.URL)
	if _, err := a.Preflight(context.Background()); err == nil {
		t.Fatal("preflight unexpectedly succeeded")
	}
	if a.IdPReady() == nil {
		t.Fatal("IdPReady must report the failure")
	}

	// The provider comes back.
	idp.discoveryStatus = 0
	if _, err := a.Preflight(context.Background()); err == nil {
		// Still fails: the stub publishes an empty key set. What matters is
		// that discovery was retried rather than the failure being cached.
		t.Log("second preflight succeeded")
	}
	if idp.discoveryHits < 2 {
		t.Errorf("discovery was attempted %d time(s): a failed preflight must not be cached, "+
			"or a transiently-down IdP would need a hub restart", idp.discoveryHits)
	}
}

// TestIdPReadyBeforeAnyContact: a hub that has never resolved its issuer is not
// ready, even though nothing has failed yet. "Not attempted" and "succeeded"
// must not read the same to a readiness probe.
func TestIdPReadyBeforeAnyContact(t *testing.T) {
	a := authenticatorFor(t, "https://idp.invalid")
	if err := a.IdPReady(); err == nil {
		t.Fatal("IdPReady is nil before the issuer was ever contacted")
	}
	// Nil and disabled authenticators are ready by construction: there is no
	// identity path to be degraded.
	var nilAuth *Authenticator
	if err := nilAuth.IdPReady(); err != nil {
		t.Errorf("a nil authenticator must not degrade readiness: %v", err)
	}
}

// ── Clock skew ──────────────────────────────────────────────────────────────

// TestClockSkewConfigBounds. The upper bound is an error rather than a clamp:
// an operator who configured an hour believes they got an hour, and quietly
// giving them ten minutes leaves them debugging the wrong thing.
func TestClockSkewConfigBounds(t *testing.T) {
	base := func() Config {
		return Config{
			Enabled:      true,
			Issuer:       "https://idp.example.com",
			ClientID:     "c",
			ClientSecret: "s",
			RedirectURL:  "https://cloop.example.com/auth/callback",
		}
	}

	cases := []struct {
		name      string
		configure time.Duration
		wantErr   bool
		want      time.Duration
	}{
		{name: "unset takes the default", configure: 0, want: DefaultClockSkew},
		{name: "inside the bound", configure: 90 * time.Second, want: 90 * time.Second},
		{name: "at the bound", configure: MaxClockSkew, want: MaxClockSkew},
		{name: "negative disables leeway", configure: -1 * time.Second, want: 0},
		{name: "past the bound is refused", configure: MaxClockSkew + time.Second, wantErr: true},
		{name: "an hour is refused", configure: time.Hour, wantErr: true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := base()
			cfg.ClockSkew = tc.configure
			a, err := New(cfg)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("New accepted a %s skew", tc.configure)
				}
				if !strings.Contains(err.Error(), "clock_skew") {
					t.Errorf("the error must name the setting: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			if got := a.clockSkew(); got != tc.want {
				t.Errorf("clockSkew = %s, want %s", got, tc.want)
			}
		})
	}
}

// TestClockSkewIsEnforcedAtTheConfiguredBound drives a whole login with a token
// that expired, and shows the verdict tracking the configured leeway rather
// than a constant: accepted inside the window, rejected outside it.
func TestClockSkewIsEnforcedAtTheConfiguredBound(t *testing.T) {
	const skew = 30 * time.Second

	newAuth := func(t *testing.T, idp *fakeIdP, configured time.Duration) *Authenticator {
		t.Helper()
		a, err := New(Config{
			Enabled:      true,
			Issuer:       idp.server.URL,
			ClientID:     "cloop-dashboard",
			ClientSecret: "s3cret",
			RedirectURL:  "http://localhost:8080/auth/callback",
			ClockSkew:    configured,
		})
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		return a
	}

	t.Run("expired inside the configured leeway is accepted", func(t *testing.T) {
		idp := newFakeIdP(t)
		idp.expOffset = -10 * time.Second // already expired
		a := newAuth(t, idp, skew)

		state, nonce := beginLogin(t, a)
		idp.nonce = nonce
		if rec := doCallback(a, state); rec.Code != http.StatusFound && rec.Code != http.StatusOK {
			t.Fatalf("callback = %d, want a completed sign-in — %s of leeway should absorb %s of expiry (body: %s)",
				rec.Code, skew, -idp.expOffset, rec.Body.String())
		}
	})

	t.Run("expired past the configured leeway is rejected", func(t *testing.T) {
		idp := newFakeIdP(t)
		idp.expOffset = -(skew + 10*time.Second)
		a := newAuth(t, idp, skew)

		state, nonce := beginLogin(t, a)
		idp.nonce = nonce
		rec := doCallback(a, state)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("callback = %d, want 403: a token %s past expiry must not be accepted with %s of leeway",
				rec.Code, -idp.expOffset, skew)
		}
	})

	t.Run("the same token is rejected outright with leeway disabled", func(t *testing.T) {
		idp := newFakeIdP(t)
		idp.expOffset = -10 * time.Second
		a := newAuth(t, idp, -1) // no leeway at all

		state, nonce := beginLogin(t, a)
		idp.nonce = nonce
		if rec := doCallback(a, state); rec.Code != http.StatusForbidden {
			t.Fatalf("callback = %d, want 403 with leeway disabled", rec.Code)
		}
	})
}

// TestLoginOutcomesAreReported checks the verdict each branch of the flow
// returns, which is what the hub turns into cloop_oidc_login_total.
func TestLoginOutcomesAreReported(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		idp := newFakeIdP(t)
		a := newTestAuthenticator(t, idp)
		state, nonce := beginLogin(t, a)
		idp.nonce = nonce

		req := httptest.NewRequest(http.MethodGet, "/auth/callback?code=c&state="+state, nil)
		if got := a.HandleCallback(httptest.NewRecorder(), req); got != LoginSuccess {
			t.Errorf("outcome = %q, want %q", got, LoginSuccess)
		}
	})

	t.Run("the redirect to the provider is not a verdict", func(t *testing.T) {
		idp := newFakeIdP(t)
		a := newTestAuthenticator(t, idp)
		got := a.BeginLogin(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/auth/login", nil))
		if got.Recorded() {
			t.Errorf("outcome = %q: counting a redirect would make the success ratio depend on "+
				"how many people opened the login page and wandered off", got)
		}
	})

	t.Run("an unresolvable issuer is reported as discovery, not as a bad login", func(t *testing.T) {
		idp := newStubIdP(t)
		idp.discoveryStatus = http.StatusBadGateway
		a := authenticatorFor(t, idp.server.URL)

		got := a.BeginLogin(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/auth/login", nil))
		if got != LoginDiscoveryFailed {
			t.Errorf("outcome = %q, want %q", got, LoginDiscoveryFailed)
		}
	})

	t.Run("replayed state", func(t *testing.T) {
		idp := newFakeIdP(t)
		a := newTestAuthenticator(t, idp)
		state, nonce := beginLogin(t, a)
		idp.nonce = nonce
		doCallback(a, state) // consumes it

		req := httptest.NewRequest(http.MethodGet, "/auth/callback?code=c&state="+state, nil)
		if got := a.HandleCallback(httptest.NewRecorder(), req); got != LoginInvalidState {
			t.Errorf("outcome = %q, want %q", got, LoginInvalidState)
		}
	})

	t.Run("the provider refused", func(t *testing.T) {
		idp := newFakeIdP(t)
		a := newTestAuthenticator(t, idp)
		req := httptest.NewRequest(http.MethodGet, "/auth/callback?error=access_denied", nil)
		if got := a.HandleCallback(httptest.NewRecorder(), req); got != LoginIdPError {
			t.Errorf("outcome = %q, want %q", got, LoginIdPError)
		}
	})

	t.Run("no state or code", func(t *testing.T) {
		idp := newFakeIdP(t)
		a := newTestAuthenticator(t, idp)
		req := httptest.NewRequest(http.MethodGet, "/auth/callback", nil)
		if got := a.HandleCallback(httptest.NewRecorder(), req); got != LoginInvalidRequest {
			t.Errorf("outcome = %q, want %q", got, LoginInvalidRequest)
		}
	})

	t.Run("the token does not validate", func(t *testing.T) {
		idp := newFakeIdP(t)
		a := newTestAuthenticator(t, idp)
		state, _ := beginLogin(t, a)
		idp.nonce = "not-the-nonce-we-issued"

		req := httptest.NewRequest(http.MethodGet, "/auth/callback?code=c&state="+state, nil)
		if got := a.HandleCallback(httptest.NewRecorder(), req); got != LoginTokenInvalid {
			t.Errorf("outcome = %q, want %q", got, LoginTokenInvalid)
		}
	})
}

// TestRemediationDiscriminatesByStatus. "Check the network and the certificate"
// is the wrong advice for a host that answered 404: it is reachable and
// trusted, and the operator sent to inspect their firewall will find nothing.
func TestRemediationDiscriminatesByStatus(t *testing.T) {
	cases := []struct {
		status int
		want   string // a phrase that must appear
	}{
		{status: http.StatusNotFound, want: "realm or tenant path segment"},
		{status: http.StatusUnauthorized, want: "publicly readable"},
		{status: http.StatusForbidden, want: "publicly readable"},
		{status: http.StatusBadGateway, want: "still be starting"},
		{status: 0, want: "certificate"},
	}
	for _, tc := range cases {
		pe := &PreflightError{Issuer: "https://idp.example.com", Reason: PreflightUnreachable, Status: tc.status}
		if got := pe.Remediation(); !strings.Contains(got, tc.want) {
			t.Errorf("status %d remediation = %q, want it to mention %q", tc.status, got, tc.want)
		}
	}
}

// TestEveryReasonCarriesRemediation: a failure that reports a problem and stops
// is the failure this whole gate exists to remove.
func TestEveryReasonCarriesRemediation(t *testing.T) {
	reasons := []string{
		PreflightUnreachable, PreflightMalformed, PreflightIssuerMismatch,
		PreflightNoJWKSURI, PreflightNoKeys, PreflightNotConfigured, PreflightUnverified,
	}
	for _, r := range reasons {
		pe := &PreflightError{Issuer: "https://idp.example.com", Reason: r}
		if got := pe.Remediation(); strings.TrimSpace(got) == "" {
			t.Errorf("reason %q carries no remediation", r)
		}
	}
}
