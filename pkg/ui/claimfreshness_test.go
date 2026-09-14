package ui

// End-to-end enforcement of bounded authorization staleness (Task 20273).
//
// pkg/oidcauth proves the policy in isolation. What is proved here is that it
// is actually wired into the thing that decides requests: a demotion at the
// identity provider has to change the answer to an HTTP call, over a live
// session, with no background pass running and nobody signing in again.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/authz"
	"github.com/blechschmidt/cloop/pkg/oidcauth"
)

// newClaimFreshnessFixture builds an OIDC hub whose claims are stale the
// instant they are written.
//
// MaxClaimAge is one nanosecond rather than a realistic five minutes, and a
// fake clock is deliberately avoided: the question at this layer is not when
// the bound trips but what happens when it does, and a one-nanosecond bound
// makes every privileged request take the synchronous path without the test
// having to reach into pkg/oidcauth's clock. The window arithmetic is covered
// by TestClaimsStaleHonoursBothDeadlines.
func newClaimFreshnessFixture(t *testing.T, maxClaimAge time.Duration) (*Server, *httptest.Server, *uiFakeIdP, *http.Client) {
	t.Helper()

	idp := newUIFakeIdP(t)
	idp.issueRefresh = "rt-1" // without one, nothing can be revalidated
	idp.groups = []string{"owners"}

	dir := setupProjectDir(t, cloopGoal, nil)
	srv := New(dir, 0, "")
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	auth, err := oidcauth.New(oidcauth.Config{
		Enabled:      true,
		Issuer:       idp.server.URL,
		ClientID:     "cloop-dashboard",
		ClientSecret: "test-secret",
		RedirectURL:  ts.URL + "/auth/callback",
		// The background pass is off, so anything this test observes was
		// established by the request that observed it.
		RefreshInterval: -1,
		MaxClaimAge:     maxClaimAge,
	})
	if err != nil {
		t.Fatalf("oidcauth.New: %v", err)
	}
	srv.OIDC = auth

	resolver, err := authz.New(authz.Config{
		Bindings: []authz.Binding{
			{Claim: authz.ClaimGroup, Value: "owners", Role: authz.RoleAdmin},
			{Claim: authz.ClaimGroup, Value: "engineers", Role: authz.RoleOperator},
		},
	})
	if err != nil {
		t.Fatalf("authz.New: %v", err)
	}
	srv.Authz = resolver

	c := jarClient(t)
	login(t, c, ts)
	return srv, ts, idp, c
}

// TestIdPDemotionReachesTheNextPrivilegedRequest is the end-to-end statement of
// the defect.
//
// The user signs in holding the group that maps to admin, and GET /api/sessions
// (session.admin) works. The group is then removed at the provider — nothing
// else changes, no janitor runs, the cookie is untouched and still valid — and
// the very next privileged request must be refused.
func TestIdPDemotionReachesTheNextPrivilegedRequest(t *testing.T) {
	_, ts, idp, c := newClaimFreshnessFixture(t, time.Nanosecond)

	if status, _ := do(t, c, http.MethodGet, ts.URL+"/api/sessions", ""); status != http.StatusOK {
		t.Fatalf("an admin must be able to list sessions, got %d", status)
	}
	if idp.refreshRequests == 0 {
		t.Fatal("a privileged request with stale claims must re-check them with the IdP")
	}

	// Removed from the admin group at the provider.
	idp.groups = []string{"engineers"}

	status, body := do(t, c, http.MethodGet, ts.URL+"/api/sessions", "")
	if status != http.StatusForbidden {
		t.Fatalf("GET /api/sessions after the IdP withdrew the admin group = %d, want 403 — "+
			"the demotion is waiting for a background pass instead of reaching this request "+
			"(body: %s)", status, body)
	}

	// Reads must keep working: the user is still an operator, and the whole
	// design rests on read paths never depending on the IdP being reachable.
	if status, _ := do(t, c, http.MethodGet, ts.URL+"/api/state", ""); status != http.StatusOK {
		t.Fatalf("GET /api/state after the demotion = %d, want 200: a narrowing must "+
			"not sign the user out of what they still may do", status)
	}
}

// TestReadsDoNotConsultTheIdP is the performance contract as a test.
//
// The claim-freshness gate is only affordable because it never runs on a read.
// A benchmark can show the fresh path is cheap; only this can show the path is
// not taken at all — which is the property that matters when the IdP is slow or
// down, since a read that waited on it would make a provider outage look like a
// dashboard outage.
func TestReadsDoNotConsultTheIdP(t *testing.T) {
	_, ts, idp, c := newClaimFreshnessFixture(t, time.Nanosecond)

	idp.refreshRequests = 0
	for _, path := range []string{"/api/state", "/api/projects", "/api/steps", "/api/me"} {
		if status, _ := do(t, c, http.MethodGet, ts.URL+path, ""); status != http.StatusOK {
			t.Fatalf("GET %s = %d, want 200", path, status)
		}
	}
	if idp.refreshRequests != 0 {
		t.Fatalf("reads made %d IdP round trips, want 0 — the gate has leaked onto "+
			"the hot path and an IdP outage now degrades every request", idp.refreshRequests)
	}
}

// TestUnreachableIdPRefusesPrivilegedWithAnActionableMessage covers what an
// administrator actually sees when the provider cannot be asked.
//
// A bare "Forbidden" here is a support ticket: the operator goes and inspects
// role bindings that were never wrong. The response has to name the cause and
// the remedy, and it has to do so in the body — which is the only place anybody
// is looking at the moment their action was refused.
func TestUnreachableIdPRefusesPrivilegedWithAnActionableMessage(t *testing.T) {
	_, ts, idp, c := newClaimFreshnessFixture(t, time.Nanosecond)

	// Take the provider away after sign-in, leaving a live session whose claims
	// can no longer be confirmed.
	idp.server.Close()

	status, body := do(t, c, http.MethodGet, ts.URL+"/api/sessions", "")
	if status != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 (body: %s)", status, body)
	}
	var resp struct {
		Error struct {
			Message string         `json:"message"`
			Details map[string]any `json:"details"`
		} `json:"error"`
	}
	if err := json.Unmarshal([]byte(body), &resp); err != nil {
		t.Fatalf("decode error body %q: %v", body, err)
	}
	if !strings.Contains(strings.ToLower(resp.Error.Message), "identity provider") {
		t.Fatalf("the refusal does not name the identity provider, so it reads as a "+
			"role problem: %q", resp.Error.Message)
	}
	if resp.Error.Details["reason"] == nil {
		t.Fatalf("the refusal carries no machine-readable reason: %+v", resp.Error.Details)
	}

	// Still not a logout: an IdP outage must not sign the fleet out.
	if status, _ := do(t, c, http.MethodGet, ts.URL+"/api/state", ""); status != http.StatusOK {
		t.Fatalf("GET /api/state during an IdP outage = %d, want 200", status)
	}
}

// TestClaimFreshnessDisabledLeavesPrivilegedRequestsAlone covers the opt-out
// end to end, since it is what a hub with no CLOOP_SECRET_KEY is told to set.
// If it did not fully disable the gate, that advice would be a lockout.
func TestClaimFreshnessDisabledLeavesPrivilegedRequestsAlone(t *testing.T) {
	_, ts, idp, c := newClaimFreshnessFixture(t, -1)
	idp.server.Close() // the provider is gone entirely

	if status, body := do(t, c, http.MethodGet, ts.URL+"/api/sessions", ""); status != http.StatusOK {
		t.Fatalf("with max_claim_age disabled a privileged request = %d, want 200 "+
			"(body: %s)", status, body)
	}
}

// TestSessionViewReportsClaimAge covers the surfacing half: an operator has to
// be able to see that claims are older than the grant check, because on most
// providers that gap is the whole story and nothing else in the dashboard shows
// it.
func TestSessionViewReportsClaimAge(t *testing.T) {
	_, ts, _, c := newClaimFreshnessFixture(t, 5*time.Minute)

	status, body := do(t, c, http.MethodGet, ts.URL+"/api/sessions", "")
	if status != http.StatusOK {
		t.Fatalf("GET /api/sessions = %d (body: %s)", status, body)
	}
	var resp struct {
		Sessions []struct {
			ClaimsAsOf      string `json:"claims_as_of"`
			ClaimAgeSeconds int64  `json:"claim_age_seconds"`
			ClaimsStale     bool   `json:"claims_stale"`
		} `json:"sessions"`
		MaxClaimAgeSeconds int64 `json:"max_claim_age_seconds"`
	}
	if err := json.Unmarshal([]byte(body), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(resp.Sessions) == 0 {
		t.Fatal("no sessions listed")
	}
	if resp.MaxClaimAgeSeconds != 300 {
		t.Fatalf("max_claim_age_seconds = %d, want 300 — the panel cannot state the "+
			"policy it is colouring rows against", resp.MaxClaimAgeSeconds)
	}
	s := resp.Sessions[0]
	if s.ClaimsAsOf == "" {
		t.Fatal("claims_as_of is empty for a session that signed in moments ago")
	}
	if s.ClaimsStale {
		t.Fatal("a session that just signed in must not report stale claims")
	}
	if s.ClaimAgeSeconds < 0 {
		t.Fatalf("claim_age_seconds = %d", s.ClaimAgeSeconds)
	}
}
