package ui

// Silent sign-in renewal at the layer where the browser meets it (Task 20359).
//
// pkg/oidcauth proves the flow. What is proved here is what the dashboard
// depends on and what lives entirely on this side of the boundary:
//
//	the route        /auth/renew is served, reachable without being signed in,
//	                 and answers in the frame's language on every path
//	the schedule     /api/me says when the claims lapse, and only asks the
//	                 browser to renew them when the hub cannot do it itself
//	the refusal      a 403 for claim age says whether a renewal can clear it,
//	                 and a 401 says where to sign in again
//	the framing      the Content-Security-Policy lets the dashboard frame the
//	                 renewal and the frame reach the provider — and nothing else
//
// The last is why this file exists at all: a frame's navigations are checked
// against the framing document's frame-src, redirects included, so a hub with a
// correct renewal and a stock CSP produces renewals that time out.

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/authz"
	"github.com/blechschmidt/cloop/pkg/hubmetrics"
	"github.com/blechschmidt/cloop/pkg/oidcauth"
)

// renewFixture is a signed-in hub retaining no refresh token — the deployment
// silent renewal exists for — whose identity provider maps the user to admin.
type renewFixture struct {
	srv *Server
	ts  *httptest.Server
	idp *uiFakeIdP
	c   *http.Client
	clk *fixtureClock
}

// fixtureClock is the hub's clock, advanced by the test rather than by sleeping
// through a claim window.
type fixtureClock struct{ off time.Duration }

func (f *fixtureClock) now() time.Time { return time.Now().Add(f.off) }

func newRenewFixture(t *testing.T, mutate func(*oidcauth.Config)) *renewFixture {
	t.Helper()
	idp := newUIFakeIdP(t)
	idp.groups = []string{"owners"}

	dir := setupProjectDir(t, cloopGoal, nil)
	srv := New(dir, 0, "")
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	clk := &fixtureClock{}
	cfg := oidcauth.Config{
		Enabled:         true,
		Issuer:          idp.server.URL,
		ClientID:        "cloop-dashboard",
		RedirectURL:     ts.URL + "/auth/callback",
		RefreshInterval: -1,
		MaxClaimAge:     5 * time.Minute,
		Clock:           func() time.Time { return clk.now() },
		RenewObserver:   RecordRenewOutcome,
	}
	if mutate != nil {
		mutate(&cfg)
	}
	auth, err := oidcauth.New(cfg)
	if err != nil {
		t.Fatalf("oidcauth.New: %v", err)
	}
	srv.OIDC = auth
	resolver, err := authz.New(authz.Config{
		Bindings: []authz.Binding{{Claim: authz.ClaimGroup, Value: "owners", Role: authz.RoleAdmin}},
	})
	if err != nil {
		t.Fatalf("authz.New: %v", err)
	}
	srv.Authz = resolver

	c := jarClient(t)
	login(t, c, ts)
	return &renewFixture{srv: srv, ts: ts, idp: idp, c: c, clk: clk}
}

// me reads /api/me as the signed-in client.
func (f *renewFixture) me(t *testing.T) map[string]any {
	t.Helper()
	status, body := do(t, f.c, http.MethodGet, f.ts.URL+"/api/me", "")
	if status != http.StatusOK {
		t.Fatalf("GET /api/me = %d: %s", status, body)
	}
	var me map[string]any
	if err := json.Unmarshal([]byte(body), &me); err != nil {
		t.Fatalf("decode /api/me: %v (%s)", err, body)
	}
	return me
}

// renew follows the whole frame chain — /auth/renew, the provider, the
// callback — as a hidden frame does, and returns the document it ends on.
func (f *renewFixture) renew(t *testing.T, c *http.Client) (*http.Response, string) {
	t.Helper()
	resp, err := c.Get(f.ts.URL + "/auth/renew")
	if err != nil {
		t.Fatalf("GET /auth/renew: %v", err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read renewal document: %v", err)
	}
	return resp, string(b)
}

func TestRenewRouteIsServed(t *testing.T) {
	f := newRenewFixture(t, nil)
	f.clk.off = 10 * time.Minute // past the bound: the state the feature exists for

	resp, body := f.renew(t, f.c)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200 (%s)", resp.StatusCode, body)
	}
	if !strings.Contains(body, `outcome: "ok"`) || !strings.Contains(body, "parent.postMessage(") {
		t.Fatalf("the renewal did not report success to its parent:\n%s", body)
	}
	if _, silent := f.idp.authorizeCounts(); silent != 1 {
		t.Errorf("the provider saw %d prompt=none requests, want 1", silent)
	}
	// The claims actually moved, which is the point of all of it.
	me := f.me(t)
	if age := me["claim_age_seconds"].(float64); age > 5 {
		t.Errorf("claim_age_seconds = %v after a renewal, want a fresh assertion", age)
	}
	// And the frame learns when to come back without asking /api/me, whose
	// request would count as the user being active.
	if !strings.Contains(body, "renew_in: ") {
		t.Errorf("the answer carries no next schedule:\n%s", body)
	}
}

func TestRenewWithoutASessionSaysSo(t *testing.T) {
	f := newRenewFixture(t, nil)
	// A bare client: the route is public, so this reaches the handler rather
	// than the gate, which must refuse in the frame's own language.
	resp, body := f.renew(t, &http.Client{})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200 — a frame cannot surface a 401", resp.StatusCode)
	}
	if !strings.Contains(body, `outcome: "no_session"`) {
		t.Fatalf("body = %s, want a no_session verdict", body)
	}
}

func TestRenewOnAHubWithoutSingleSignOn(t *testing.T) {
	dir := setupProjectDir(t, cloopGoal, nil)
	ts := httptest.NewServer(New(dir, 0, "").Handler())
	t.Cleanup(ts.Close)
	resp, err := http.Get(ts.URL + "/auth/renew")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(b), `outcome: "not_enabled"`) {
		t.Fatalf("GET /auth/renew without OIDC = %d %s, want a not_enabled document", resp.StatusCode, b)
	}
}

func TestRenewInteractionRequired(t *testing.T) {
	f := newRenewFixture(t, nil)
	f.idp.setSilentError("login_required")
	_, body := f.renew(t, f.c)
	if !strings.Contains(body, `outcome: "interaction_required"`) {
		t.Fatalf("a provider that needs to see the user produced:\n%s", body)
	}
	// The session survives: the provider declining to answer silently says
	// nothing about whether this person is signed in here.
	if me := f.me(t); me["authenticated"] != true {
		t.Fatal("a silent refusal ended the session")
	}
}

func TestRenewalsAreCounted(t *testing.T) {
	before := renewalCount(t, "ok")
	f := newRenewFixture(t, nil)
	f.renew(t, f.c)
	if got := renewalCount(t, "ok"); got != before+1 {
		t.Fatalf("cloop_oidc_renewal_total{outcome=\"ok\"} = %v, want %v", got, before+1)
	}
}

// renewalCount reads one series of the renewal counter from a real scrape.
func renewalCount(t *testing.T, outcome string) float64 {
	t.Helper()
	want := `cloop_oidc_renewal_total{outcome="` + outcome + `"} `
	for _, line := range strings.Split(hubmetrics.Default.Gather(), "\n") {
		if strings.HasPrefix(line, want) {
			v, err := strconv.ParseFloat(strings.TrimSpace(strings.TrimPrefix(line, want)), 64)
			if err != nil {
				t.Fatalf("parse %q: %v", line, err)
			}
			return v
		}
	}
	return 0
}

func TestMeReportsTheRenewalSchedule(t *testing.T) {
	f := newRenewFixture(t, nil)
	me := f.me(t)
	if me["max_claim_age_seconds"] != float64(300) {
		t.Errorf("max_claim_age_seconds = %v, want 300", me["max_claim_age_seconds"])
	}
	// Claims asserted seconds ago: due at the bound less the slack.
	renew, ok := me["renew_in_seconds"].(float64)
	if !ok || renew < 200 || renew > 210 {
		t.Errorf("renew_in_seconds = %v, want ~210 (5m less 90s of slack)", me["renew_in_seconds"])
	}
	if exp, _ := me["session_expires_in_seconds"].(float64); exp < 23*3600 {
		t.Errorf("session_expires_in_seconds = %v, want the 24h ceiling", me["session_expires_in_seconds"])
	}

	// Past the bound: renew now, not at some time in the past.
	f.clk.off = 10 * time.Minute
	if got := f.me(t)["renew_in_seconds"]; got != float64(0) {
		t.Errorf("renew_in_seconds past the bound = %v, want 0", got)
	}
}

// TestMeLeavesRenewalToTheServer: a hub holding a refresh token re-asserts the
// claims itself on the request that needs them. That is the first layer, and
// the browser must not stack a frame on top of it — wherever third-party
// cookies are blocked that frame fails, and its banner would ask the user to
// sign in over a session the hub was about to renew by itself.
func TestMeLeavesRenewalToTheServer(t *testing.T) {
	idp := newUIFakeIdP(t)
	idp.issueRefresh = "rt-1"
	_, ts := newOIDCTestServer(t, idp, "", nil)
	c := jarClient(t)
	login(t, c, ts)
	_, body := do(t, c, http.MethodGet, ts.URL+"/api/me", "")
	if strings.Contains(body, "renew_in_seconds") {
		t.Fatalf("/api/me scheduled a browser renewal for a session the hub can refresh itself: %s", body)
	}
	if !strings.Contains(body, "claim_age_seconds") {
		t.Fatalf("/api/me dropped the claim clock: %s", body)
	}
}

func TestMeOmitsTheScheduleWhenFreshnessIsOff(t *testing.T) {
	f := newRenewFixture(t, func(c *oidcauth.Config) { c.MaxClaimAge = -1 })
	_, body := do(t, f.c, http.MethodGet, f.ts.URL+"/api/me", "")
	for _, k := range []string{"renew_in_seconds", "claim_age_seconds"} {
		if strings.Contains(body, k) {
			t.Fatalf("/api/me reports %s on a hub with the freshness check off: %s", k, body)
		}
	}
}

// TestClaimRefusalSaysWhetherARenewalClearsIt is the reactive layer's contract:
// the refusal names itself renewable, a renewal from the browser follows, and
// the retried request succeeds.
func TestClaimRefusalSaysWhetherARenewalClearsIt(t *testing.T) {
	f := newRenewFixture(t, nil)
	f.clk.off = 10 * time.Minute

	status, body := do(t, f.c, http.MethodGet, f.ts.URL+"/api/sessions", "")
	if status != http.StatusForbidden {
		t.Fatalf("GET /api/sessions with stale claims = %d, want 403: %s", status, body)
	}
	var refusal struct {
		Error struct {
			Details map[string]any `json:"details"`
		} `json:"error"`
	}
	if err := json.Unmarshal([]byte(body), &refusal); err != nil {
		t.Fatalf("decode refusal: %v (%s)", err, body)
	}
	if refusal.Error.Details["renewable"] != true || refusal.Error.Details["reason"] != "no_refresh_token" {
		t.Fatalf("details = %v, want renewable no_refresh_token", refusal.Error.Details)
	}

	if _, doc := f.renew(t, f.c); !strings.Contains(doc, `outcome: "ok"`) {
		t.Fatalf("renewal failed:\n%s", doc)
	}
	if status, body := do(t, f.c, http.MethodGet, f.ts.URL+"/api/sessions", ""); status != http.StatusOK {
		t.Fatalf("retry after the renewal = %d, want 200: %s", status, body)
	}
}

// TestUnauthorizedCarriesTheSignInHint: every 401 an SSO hub sends says where
// the browser signs in again, so the dashboard never has to ask a hub it is no
// longer signed in to — which, on an SSO hub, it cannot.
func TestUnauthorizedCarriesTheSignInHint(t *testing.T) {
	f := newRenewFixture(t, nil)
	for _, path := range []string{"/api/state", "/api/me", "/api/projects"} {
		resp, err := http.Get(f.ts.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized || resp.Header.Get(signInHintHeader) != "/auth/login" {
			t.Errorf("GET %s signed out = %d with %s=%q, want 401 naming /auth/login",
				path, resp.StatusCode, signInHintHeader, resp.Header.Get(signInHintHeader))
		}
	}

	// A token-only hub's 401 must not carry it: there is nowhere to sign in,
	// and the access-token prompt is the right answer there.
	dir := setupProjectDir(t, cloopGoal, nil)
	ts := httptest.NewServer(New(dir, 0, "s3cret-token").Handler())
	t.Cleanup(ts.Close)
	resp, err := http.Get(ts.URL + "/api/state")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized || resp.Header.Get(signInHintHeader) != "" {
		t.Fatalf("token-only hub: %d with %s=%q, want a bare 401",
			resp.StatusCode, signInHintHeader, resp.Header.Get(signInHintHeader))
	}
}

// TestSignInReturnsToTheRequestedPage: a navigation that finds no session goes
// through the identity provider and lands where it was headed.
func TestSignInReturnsToTheRequestedPage(t *testing.T) {
	idp := newUIFakeIdP(t)
	_, ts := newOIDCTestServer(t, idp, "", nil)
	c := jarClient(t)
	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/?project_idx=0", nil)
	req.Header.Set("Accept", "text/html")
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || resp.Request.URL.RequestURI() != "/?project_idx=0" {
		t.Fatalf("the sign-in chain ended at %d %s, want 200 /?project_idx=0",
			resp.StatusCode, resp.Request.URL.RequestURI())
	}
	// And a return that names another origin lands on the dashboard root.
	c2 := jarClient(t)
	resp, err = c2.Get(ts.URL + "/auth/login?return=" + url.QueryEscape("//evil.example/x"))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.Request.URL.Host != strings.TrimPrefix(ts.URL, "http://") || resp.Request.URL.Path != "/" {
		t.Fatalf("an off-site return ended at %s, want this hub's /", resp.Request.URL)
	}
}

func TestCSPAdmitsTheRenewalFrame(t *testing.T) {
	f := newRenewFixture(t, nil)
	resp, err := f.c.Get(f.ts.URL + "/")
	if err != nil {
		t.Fatalf("GET /: %v", err)
	}
	resp.Body.Close()

	csp := resp.Header.Get("Content-Security-Policy")
	if !strings.Contains(csp, "frame-src 'self' "+f.idp.server.URL) {
		t.Fatalf("frame-src does not name the identity provider, so the frame's hop to it "+
			"is blocked and every renewal times out.\nCSP: %s", csp)
	}
	// The dashboard itself stays unframable.
	if !strings.Contains(csp, "frame-ancestors 'none'") {
		t.Errorf("the dashboard became framable: %s", csp)
	}
	if got := resp.Header.Get("X-Frame-Options"); got != "DENY" {
		t.Errorf("X-Frame-Options on the dashboard = %q, want DENY", got)
	}
}

// TestOnlyTheRenewalDocumentsAreFramable: the frame loads /auth/renew and then
// the callback, so both must allow being framed — by this origin and no other —
// and everything else, the login route included, stays unframable.
func TestOnlyTheRenewalDocumentsAreFramable(t *testing.T) {
	f := newRenewFixture(t, nil)
	noRedirect := &http.Client{Jar: f.c.Jar, CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	for path, framable := range map[string]bool{
		"/auth/renew":          true,
		"/auth/callback?x=1":   true,
		"/auth/login":          false,
		"/":                    false,
		"/api/me":              false,
		"/assets/nonexistent1": false,
	} {
		resp, err := noRedirect.Get(f.ts.URL + path)
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		resp.Body.Close()
		csp := resp.Header.Get("Content-Security-Policy")
		xfo := resp.Header.Get("X-Frame-Options")
		if framable && (!strings.Contains(csp, "frame-ancestors 'self'") || xfo != "SAMEORIGIN") {
			t.Errorf("%s: frame-ancestors/XFO = %q/%q, want 'self'/SAMEORIGIN — the renewal frame cannot load it", path, csp, xfo)
		}
		if !framable && (!strings.Contains(csp, "frame-ancestors 'none'") || xfo != "DENY") {
			t.Errorf("%s: frame-ancestors/XFO = %q/%q, want 'none'/DENY", path, csp, xfo)
		}
	}
}

// TestRenewalFrameRulesNeedSingleSignOn: without an identity provider there is
// no renewal, so nothing is framable and nothing but 'self' may be framed.
func TestRenewalFrameRulesNeedSingleSignOn(t *testing.T) {
	dir := setupProjectDir(t, cloopGoal, nil)
	ts := httptest.NewServer(New(dir, 0, "").Handler())
	t.Cleanup(ts.Close)
	resp, err := http.Get(ts.URL + "/auth/renew")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	csp := resp.Header.Get("Content-Security-Policy")
	if !strings.Contains(csp, "frame-src 'self';") || !strings.Contains(csp, "frame-ancestors 'none'") {
		t.Fatalf("CSP on a hub without SSO = %q, want frame-src 'self' and frame-ancestors 'none'", csp)
	}
}
