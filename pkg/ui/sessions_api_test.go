package ui

// End-to-end tests for the session admin surface (Task 20176).
//
// The unit-level policy lives in pkg/oidcauth; what these cover is the part
// only a real server can show: that a revoked session's *next HTTP request*
// is refused, that the list and the terminate button are gated, and that
// self-service logout-all cannot be aimed at anybody else.

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/pkg/authz"
)

// newSessionsFixture builds an OIDC dashboard with one signed-in client per
// role. Only admin holds session.admin, which is the property the gating tests
// assert on.
func newSessionsFixture(t *testing.T) (*httptest.Server, *uiFakeIdP, map[string]*http.Client) {
	t.Helper()

	idp := newUIFakeIdP(t)
	srv, ts := newOIDCTestServer(t, idp, "", nil)

	resolver, err := authz.New(authz.Config{
		Bindings: []authz.Binding{
			{Claim: authz.ClaimGroup, Value: "readers", Role: authz.RoleViewer},
			{Claim: authz.ClaimGroup, Value: "engineers", Role: authz.RoleOperator},
			{Claim: authz.ClaimGroup, Value: "leads", Role: authz.RoleMaintainer},
			{Claim: authz.ClaimGroup, Value: "owners", Role: authz.RoleAdmin},
		},
	})
	if err != nil {
		t.Fatalf("authz.New: %v", err)
	}
	srv.Authz = resolver

	loginAs := func(sub, email string, groups []string) *http.Client {
		idp.sub, idp.email, idp.groups = sub, email, groups
		c := jarClient(t)
		login(t, c, ts)
		return c
	}
	clients := map[string]*http.Client{
		"viewer":     loginAs("u-viewer", "viewer@example.com", []string{"readers"}),
		"operator":   loginAs("u-operator", "operator@example.com", []string{"engineers"}),
		"maintainer": loginAs("u-maintainer", "maintainer@example.com", []string{"leads"}),
		"admin":      loginAs("u-admin", "admin@example.com", []string{"owners"}),
	}
	return ts, idp, clients
}

// sessionsOf fetches GET /api/sessions as c and decodes the rows.
func sessionsOf(t *testing.T, c *http.Client, base string) []map[string]any {
	t.Helper()
	resp, err := c.Get(base + "/api/sessions")
	if err != nil {
		t.Fatalf("GET /api/sessions: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /api/sessions = %d, want 200 (body %s)", resp.StatusCode, body)
	}
	var out struct {
		Sessions []map[string]any `json:"sessions"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("decode sessions: %v (body %s)", err, body)
	}
	return out.Sessions
}

// statusOf issues a request and returns just the status code.
func statusOf(t *testing.T, c *http.Client, method, url string) int {
	t.Helper()
	req, err := http.NewRequest(method, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, url, err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.StatusCode
}

// TestRevokedSessionIsRefusedOnNextRequest is the operator kill switch end to
// end: after DELETE /api/sessions/{id}, the very next API call from that
// browser must be a 401, not a stale success served from cache.
func TestRevokedSessionIsRefusedOnNextRequest(t *testing.T) {
	ts, _, clients := newSessionsFixture(t)
	base := ts.URL
	admin, victim := clients["admin"], clients["operator"]

	// The victim is signed in and working.
	if got := statusOf(t, victim, http.MethodGet, base+"/api/state"); got != http.StatusOK {
		t.Fatalf("victim GET /api/state = %d before revocation, want 200", got)
	}

	// Find the victim's session and terminate it.
	var victimID string
	for _, s := range sessionsOf(t, admin, base) {
		if s["subject"] == "u-operator" {
			victimID, _ = s["id"].(string)
		}
	}
	if victimID == "" {
		t.Fatal("the admin's session list did not include the signed-in operator")
	}
	if got := statusOf(t, admin, http.MethodDelete, base+"/api/sessions/"+victimID); got != http.StatusOK {
		t.Fatalf("DELETE /api/sessions/%s = %d, want 200", victimID, got)
	}

	if got := statusOf(t, victim, http.MethodGet, base+"/api/state"); got != http.StatusUnauthorized {
		t.Fatalf("revoked session GET /api/state = %d, want 401", got)
	}
	// The admin's own session is untouched.
	if got := statusOf(t, admin, http.MethodGet, base+"/api/state"); got != http.StatusOK {
		t.Fatalf("admin GET /api/state = %d after revoking someone else, want 200", got)
	}
	// Revoking again is a 404, not a second success.
	if got := statusOf(t, admin, http.MethodDelete, base+"/api/sessions/"+victimID); got != http.StatusNotFound {
		t.Fatalf("second DELETE = %d, want 404", got)
	}
}

// TestSessionsListRequiresSessionAdmin pins the gate. Every role below admin
// must be refused both the list — which names who is signed in, from where —
// and the terminate.
func TestSessionsListRequiresSessionAdmin(t *testing.T) {
	ts, _, clients := newSessionsFixture(t)
	base := ts.URL

	for _, role := range []string{"viewer", "operator", "maintainer"} {
		c := clients[role]
		if got := statusOf(t, c, http.MethodGet, base+"/api/sessions"); got != http.StatusForbidden {
			t.Errorf("%s GET /api/sessions = %d, want 403 — the session list is reconnaissance", role, got)
		}
		if got := statusOf(t, c, http.MethodDelete, base+"/api/sessions/deadbeef"); got != http.StatusForbidden {
			t.Errorf("%s DELETE /api/sessions/{id} = %d, want 403", role, got)
		}
	}
	if got := statusOf(t, clients["admin"], http.MethodGet, base+"/api/sessions"); got != http.StatusOK {
		t.Errorf("admin GET /api/sessions = %d, want 200", got)
	}
}

// TestSessionsListShapeAndPolicy checks the rows carry what an operator needs
// to recognise a session, mark their own, and nothing that could be replayed
// as a credential.
func TestSessionsListShapeAndPolicy(t *testing.T) {
	ts, _, clients := newSessionsFixture(t)
	base := ts.URL
	admin := clients["admin"]

	resp, err := admin.Get(base + "/api/sessions")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	var out struct {
		Sessions           []map[string]any `json:"sessions"`
		AbsoluteTTLSeconds int64            `json:"absolute_ttl_seconds"`
		IdleTimeoutSeconds int64            `json:"idle_timeout_seconds"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if out.AbsoluteTTLSeconds <= 0 || out.IdleTimeoutSeconds <= 0 {
		t.Errorf("policy fields = %d/%d, want both positive so the panel can state the rules",
			out.AbsoluteTTLSeconds, out.IdleTimeoutSeconds)
	}
	if len(out.Sessions) < 4 {
		t.Fatalf("got %d sessions, want at least the 4 signed-in clients", len(out.Sessions))
	}

	current := 0
	for _, s := range out.Sessions {
		if s["subject"] == "" {
			t.Error("a row without a subject is not attributable")
		}
		if _, ok := s["issued_at"].(string); !ok {
			t.Error("row is missing issued_at")
		}
		if _, ok := s["last_seen"].(string); !ok {
			t.Error("row is missing last_seen")
		}
		if cur, _ := s["current"].(bool); cur {
			current++
		}
		// Nothing resembling credential material may appear.
		for _, banned := range []string{"refresh_token", "cookie", "session_id", "token", "refresh_sealed"} {
			if _, present := s[banned]; present {
				t.Errorf("session row exposes %q — no response may carry credential material", banned)
			}
		}
	}
	if current != 1 {
		t.Errorf("%d rows marked current, want exactly 1 (the caller's own)", current)
	}

	// The whole payload must not contain the caller's actual cookie value.
	for _, c := range admin.Jar.Cookies(mustParseURL(t, base)) {
		if c.Name == "cloop_session" && strings.Contains(string(body), c.Value) {
			t.Fatal("the sessions payload echoes a live session cookie")
		}
	}
}

// TestLogoutAllEndsOnlyTheCallersOtherSessions covers the self-service path
// over HTTP: the caller's other browsers are signed out, the calling browser
// keeps working, and another user is untouched.
func TestLogoutAllEndsOnlyTheCallersOtherSessions(t *testing.T) {
	ts, idp, clients := newSessionsFixture(t)
	base := ts.URL

	// A second and third browser for the operator.
	idp.sub, idp.email, idp.groups = "u-operator", "operator@example.com", []string{"engineers"}
	second := jarClient(t)
	login(t, second, ts)
	third := jarClient(t)
	login(t, third, ts)

	for name, c := range map[string]*http.Client{"second": second, "third": third} {
		if got := statusOf(t, c, http.MethodGet, base+"/api/state"); got != http.StatusOK {
			t.Fatalf("%s browser GET /api/state = %d before logout-all, want 200", name, got)
		}
	}

	resp, err := second.Post(base+"/api/session/logout-all", "application/json", strings.NewReader("{}"))
	if err != nil {
		t.Fatalf("POST /api/session/logout-all: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("logout-all = %d, want 200 (body %s)", resp.StatusCode, body)
	}

	// The calling browser survives; the operator's others do not.
	if got := statusOf(t, second, http.MethodGet, base+"/api/state"); got != http.StatusOK {
		t.Errorf("the calling browser was signed out (%d) — logout-all must spare it", got)
	}
	if got := statusOf(t, third, http.MethodGet, base+"/api/state"); got != http.StatusUnauthorized {
		t.Errorf("the operator's other browser = %d, want 401", got)
	}
	if got := statusOf(t, clients["operator"], http.MethodGet, base+"/api/state"); got != http.StatusUnauthorized {
		t.Errorf("the operator's first browser = %d, want 401", got)
	}
	// A different user is completely unaffected.
	if got := statusOf(t, clients["admin"], http.MethodGet, base+"/api/state"); got != http.StatusOK {
		t.Errorf("another user's session = %d after someone else's logout-all, want 200", got)
	}
}

// TestLogoutAllIsUngatedButNeedsASession checks the ungated route is still
// useless without a browser session — there is no id parameter, so a caller
// with no session has no subject to scope the deletion to and must be refused
// rather than defaulted to something.
func TestLogoutAllIsUngatedButNeedsASession(t *testing.T) {
	ts, _, _ := newSessionsFixture(t)
	base := ts.URL

	// A bare client: authenticated by nothing.
	resp, err := http.Post(base+"/api/session/logout-all", "application/json", strings.NewReader("{}"))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("anonymous logout-all = %d, want 401", resp.StatusCode)
	}
}

// TestLogoutClearsSessionAndOffersIdPRedirect checks sign-out ends the session
// server-side and reports where to finish at the provider. The fake IdP
// advertises no end_session_endpoint, so the field must be present and empty
// rather than absent — the frontend branches on it.
func TestLogoutClearsSessionAndOffersIdPRedirect(t *testing.T) {
	ts, _, clients := newSessionsFixture(t)
	base := ts.URL
	c := clients["operator"]

	resp, err := c.Post(base+"/auth/logout", "application/json", strings.NewReader("{}"))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST /auth/logout = %d, want 200", resp.StatusCode)
	}
	var out map[string]any
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("decode: %v (body %s)", err, body)
	}
	if _, ok := out["redirect"]; !ok {
		t.Error("logout response must carry a redirect field, even when empty")
	}
	if got := statusOf(t, c, http.MethodGet, base+"/api/state"); got != http.StatusUnauthorized {
		t.Fatalf("GET /api/state after logout = %d, want 401", got)
	}
}
