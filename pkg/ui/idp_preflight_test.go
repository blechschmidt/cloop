package ui

// Tests for the hub's identity preflight, the readiness gate it feeds, the
// sign-in metrics, and the one-shot diagnosis of role mappings the identity
// provider cannot satisfy (Task 20247).
//
// The failure all of these exist to remove is the same one: a hub pointed at
// an issuer that is unreachable, misspelled, or wrongly registered starts
// green, reports healthy, and fails for the first human who tries to sign in —
// at which point the only evidence is an error page written by the provider,
// in the provider's words, about a value the provider was never shown.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/pkg/authz"
	"github.com/blechschmidt/cloop/pkg/hubmetrics"
	"github.com/blechschmidt/cloop/pkg/logger"
	"github.com/blechschmidt/cloop/pkg/oidcauth"
)

// brokenIdP serves an HTTP status of the test's choosing at the discovery
// endpoint — the "misconfigured issuer" case, standing in for a wrong realm
// path, an issuer behind authentication, or a provider that is simply down.
func brokenIdP(t *testing.T, status int) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(status)
		_, _ = w.Write([]byte(`{"error":"realm not found"}`))
	}))
	t.Cleanup(srv.Close)
	return srv
}

// serverWithIssuer builds a hub whose OIDC is wired to issuer and whose state
// store is initialised, so /readyz reaches the identity gate rather than
// stopping at storage.
func serverWithIssuer(t *testing.T, issuer string) *Server {
	t.Helper()
	dir := setupProjectDir(t, cloopGoal, nil)
	srv := New(dir, 0, "")
	auth, err := oidcauth.New(oidcauth.Config{
		Enabled:      true,
		Issuer:       issuer,
		ClientID:     "cloop-dashboard",
		ClientSecret: "test-secret",
		RedirectURL:  "http://127.0.0.1:8080/auth/callback",
	})
	if err != nil {
		t.Fatalf("oidcauth.New: %v", err)
	}
	srv.OIDC = auth
	return srv
}

// TestPreflightRequireIdPRefusesToStart is the Kubernetes case: a rollout must
// fail rather than replace a working hub with one nobody can log into.
func TestPreflightRequireIdPRefusesToStart(t *testing.T) {
	idp := brokenIdP(t, http.StatusInternalServerError)
	srv := serverWithIssuer(t, idp.URL)
	srv.RequireIdP = true

	err := srv.PreflightIdP(context.Background())
	if err == nil {
		t.Fatal("PreflightIdP returned nil with --require-idp against a broken issuer: " +
			"the hub would start and the rollout would go green")
	}
	if !strings.Contains(err.Error(), idp.URL) {
		t.Errorf("the refusal must name the issuer that failed: %v", err)
	}
	if !strings.Contains(err.Error(), "500") {
		t.Errorf("the refusal must name the HTTP status: %v", err)
	}
	if !strings.Contains(err.Error(), "require_idp") {
		t.Errorf("the refusal must say which setting made it fatal, or an operator "+
			"cannot tell it from a hard requirement: %v", err)
	}
}

// TestPreflightWithoutRequireIdPWarnsAndStarts is the other half of the
// decision. A hub holding live sessions serves them through a transient
// provider outage; refusing to start would turn a login outage into a total
// one. So the default is loud, not fatal.
func TestPreflightWithoutRequireIdPWarnsAndStarts(t *testing.T) {
	idp := brokenIdP(t, http.StatusBadGateway)
	srv := serverWithIssuer(t, idp.URL)
	cap := &captureLogger{}
	srv.Log = cap

	if err := srv.PreflightIdP(context.Background()); err != nil {
		t.Fatalf("PreflightIdP must not be fatal without --require-idp: %v", err)
	}

	entries := cap.snapshot()
	found := warnEntries(entries, "identity provider preflight failed")
	if len(found) != 1 {
		t.Fatalf("got %d warning(s) for a failed preflight, want exactly 1 — logging it is the entire point: %+v",
			len(found), entries)
	}
	warned := found[0]
	if got, _ := warned.Data["issuer"].(string); got != idp.URL {
		t.Errorf("warning issuer = %q, want %q", got, idp.URL)
	}
	if fix, _ := warned.Data["remediation"].(string); fix == "" {
		t.Error("the warning must carry a remediation")
	}
}

// TestReadyzDegradedUntilTheIssuerResolves. A hub whose issuer has never
// resolved is not ready: nobody can get in at all, and a probe that goes green
// anyway is what lets a broken rollout complete.
func TestReadyzDegradedUntilTheIssuerResolves(t *testing.T) {
	idp := brokenIdP(t, http.StatusNotFound)
	srv := serverWithIssuer(t, idp.URL)

	code, body := probeReadyz(t, srv)
	if code != http.StatusServiceUnavailable {
		t.Fatalf("/readyz = %d, want 503 before the issuer has ever resolved (body=%v)", code, body)
	}
	if got, _ := body["check"].(string); got != "identity" {
		t.Errorf("/readyz must name the failing gate as %q, got %q", "identity", got)
	}
	if got, _ := body["remediation"].(string); got == "" {
		t.Error("the not-ready body must carry a remediation: it is read in `kubectl describe pod`")
	}

	// Preflight against a working provider flips the gate — and so does an
	// ordinary sign-in, since both go through the same cache.
	working := newUIFakeIdP(t)
	ok := serverWithIssuer(t, working.server.URL)
	if err := ok.PreflightIdP(context.Background()); err != nil {
		t.Fatalf("preflight against a working IdP: %v", err)
	}
	if code, body := probeReadyz(t, ok); code != http.StatusOK {
		t.Fatalf("/readyz = %d after a successful preflight, want 200 (body=%v)", code, body)
	}
}

// TestReadyzUnaffectedWhenOIDCIsOff: the identity gate must not exist for a
// deployment that has no identity provider.
func TestReadyzUnaffectedWhenOIDCIsOff(t *testing.T) {
	dir := setupProjectDir(t, cloopGoal, nil)
	srv := New(dir, 0, "")
	if code, body := probeReadyz(t, srv); code != http.StatusOK {
		t.Fatalf("/readyz = %d with OIDC disabled, want 200 (body=%v)", code, body)
	}
}

// ── Sign-in metrics ─────────────────────────────────────────────────────────

// counterValue reads one sample out of a rendered scrape. Returns 0 when the
// series has not been touched, which is what an unrecorded counter looks like.
func counterValue(t *testing.T, scrape, name, labels string) float64 {
	t.Helper()
	want := name
	if labels != "" {
		want += "{" + labels + "}"
	}
	re := regexp.MustCompile(`(?m)^` + regexp.QuoteMeta(want) + ` ([0-9.e+-]+)$`)
	m := re.FindStringSubmatch(scrape)
	if m == nil {
		return 0
	}
	v, err := strconv.ParseFloat(m[1], 64)
	if err != nil {
		t.Fatalf("parsing %s: %v", want, err)
	}
	return v
}

// TestOIDCLoginMetrics. Sessions were the only credential path the hub could
// not graph: a hub where every human sign-in failed looked identical in a
// scrape to one where nobody had tried.
//
// Asserted as deltas because hubmetrics.Default is process-global and every
// other test in this package shares it.
func TestOIDCLoginMetrics(t *testing.T) {
	before := hubmetrics.Default.Gather()
	baseDiscovery := counterValue(t, before, "cloop_oidc_discovery_failures_total", "")
	baseFailed := counterValue(t, before, "cloop_oidc_login_total", `outcome="discovery_failed"`)
	baseSuccess := counterValue(t, before, "cloop_oidc_login_total", `outcome="success"`)

	// A hub whose issuer does not resolve: the login attempt is counted, and
	// so is the discovery failure behind it.
	idp := brokenIdP(t, http.StatusInternalServerError)
	broken := serverWithIssuer(t, idp.URL)
	req := httptest.NewRequest(http.MethodGet, "/auth/login", nil)
	broken.handleOIDCLogin(httptest.NewRecorder(), req)

	after := hubmetrics.Default.Gather()
	if got := counterValue(t, after, "cloop_oidc_login_total", `outcome="discovery_failed"`); got != baseFailed+1 {
		t.Errorf("cloop_oidc_login_total{outcome=discovery_failed} = %v, want %v", got, baseFailed+1)
	}
	if got := counterValue(t, after, "cloop_oidc_discovery_failures_total", ""); got != baseDiscovery+1 {
		t.Errorf("cloop_oidc_discovery_failures_total = %v, want %v", got, baseDiscovery+1)
	}

	// A successful sign-in through the real handler chain.
	working := newUIFakeIdP(t)
	_, ts := newOIDCTestServer(t, working, "", nil)
	login(t, jarClient(t), ts)

	after = hubmetrics.Default.Gather()
	if got := counterValue(t, after, "cloop_oidc_login_total", `outcome="success"`); got != baseSuccess+1 {
		t.Errorf("cloop_oidc_login_total{outcome=success} = %v, want %v", got, baseSuccess+1)
	}
	// The redirect that started that login must not have been counted twice.
	if got := counterValue(t, after, "cloop_oidc_login_total", `outcome="pending"`); got != 0 {
		t.Errorf("a redirect to the provider was counted as a verdict: %v", got)
	}
}

// ── Unsatisfiable role mappings ─────────────────────────────────────────────

// warnEntries returns the captured warnings whose message contains substr.
func warnEntries(entries []captureEntry, substr string) []captureEntry {
	var out []captureEntry
	for _, e := range entries {
		if e.Level == logger.LevelWarn && strings.Contains(e.Message, substr) {
			out = append(out, e)
		}
	}
	return out
}

// TestUnsatisfiableBindingWarnsExactlyOnce.
//
// A group binding against a provider that releases no group claim is inert:
// every user falls through to default_role and nothing in the request path
// says why, because from resolution's point of view nothing went wrong. The
// warning is the only operator signal — and it must fire once, not once per
// request, or it becomes something people filter out.
func TestUnsatisfiableBindingWarnsExactlyOnce(t *testing.T) {
	idp := newUIFakeIdP(t)
	idp.roles = []string{"platform"} // roles released, groups deliberately not

	srv, ts := newOIDCTestServer(t, idp, "", nil)
	cap := &captureLogger{}
	srv.Log = cap

	resolver, err := authz.New(authz.Config{
		DefaultRole: authz.RoleViewer,
		Bindings: []authz.Binding{
			{Claim: authz.ClaimGroup, Value: "cloop-admins", Role: authz.RoleAdmin},
			{Claim: authz.ClaimRole, Value: "platform", Role: authz.RoleOperator},
		},
	})
	if err != nil {
		t.Fatalf("authz.New: %v", err)
	}
	srv.Authz = resolver

	// Two authenticated requests. The second must add nothing.
	c := jarClient(t)
	login(t, c, ts)
	for i := 0; i < 2; i++ {
		resp, err := c.Get(ts.URL + "/api/me")
		if err != nil {
			t.Fatalf("GET /api/me: %v", err)
		}
		resp.Body.Close()
	}

	got := warnEntries(cap.snapshot(), "role mapping can never match")
	if len(got) != 1 {
		t.Fatalf("got %d warning(s) across several authenticated requests, want exactly 1: %+v",
			len(got), cap.snapshot())
	}
	data := got[0].Data
	if claim, _ := data["claim"].(string); claim != string(authz.ClaimGroup) {
		t.Errorf("the warning must name the dead claim, got %q", claim)
	}
	if value, _ := data["value"].(string); value != "cloop-admins" {
		t.Errorf("the warning must name the binding that is inert, got %q", value)
	}
	if def, _ := data["default_role"].(string); def != string(authz.RoleViewer) {
		t.Errorf("the warning must name what users silently fall back to, got %q", def)
	}
	present, _ := data["claims_present"].([]string)
	if !containsString(present, string(authz.ClaimRole)) {
		t.Errorf("the warning must name the claims that were released, got %v", present)
	}
	if containsString(present, string(authz.ClaimGroup)) {
		t.Errorf("group is reported present on a token that carried none: %v", present)
	}
	if roles, ok := data["roles_released"].([]string); !ok || !containsString(roles, "platform") {
		t.Errorf("the released role values are the actionable half and must be echoed, got %v", data["roles_released"])
	}
	if _, leaked := data["email"]; leaked {
		t.Error("the warning must not echo the user's email: it identifies a person and does not fix a group binding")
	}
}

// TestSatisfiableBindingsWarnAboutNothing: the diagnosis is narrow on purpose.
// A binding whose value simply did not match this user is the ordinary case —
// most bindings belong to somebody else — and reporting those would drown the
// one that is genuinely dead.
func TestSatisfiableBindingsWarnAboutNothing(t *testing.T) {
	idp := newUIFakeIdP(t)
	idp.groups = []string{"engineering"}

	srv, ts := newOIDCTestServer(t, idp, "", nil)
	cap := &captureLogger{}
	srv.Log = cap

	resolver, err := authz.New(authz.Config{
		DefaultRole: authz.RoleViewer,
		Bindings: []authz.Binding{
			{Claim: authz.ClaimGroup, Value: "cloop-admins", Role: authz.RoleAdmin},
		},
	})
	if err != nil {
		t.Fatalf("authz.New: %v", err)
	}
	srv.Authz = resolver

	login(t, jarClient(t), ts)

	if got := warnEntries(cap.snapshot(), "role mapping can never match"); len(got) != 0 {
		t.Errorf("warned about a binding that a different user could match: %+v", got)
	}
}

func containsString(values []string, want string) bool {
	for _, v := range values {
		if v == want {
			return true
		}
	}
	return false
}
