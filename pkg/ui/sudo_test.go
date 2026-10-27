package ui

// What the route gate does with sudo mode (Task 20448): which callers it asks,
// in what order, and what it answers.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/auditaction"
	"github.com/blechschmidt/cloop/pkg/authz"
	"github.com/blechschmidt/cloop/pkg/oidcauth"
)

// sudoHub is an SSO hub with a role policy: owners are admins, leads
// maintainers, readers viewers. Sign-ins made while the provider's own sign-in
// is three hours old are stale; the others are fresh.
type sudoHub struct {
	srv *Server
	ts  *httptest.Server
	idp *uiFakeIdP
}

func newSudoHub(t *testing.T, policy bool) *sudoHub {
	t.Helper()
	idp := newUIFakeIdP(t)
	srv, ts := newOIDCTestServer(t, idp, "", nil)
	srv.RPS, srv.Burst = 10000, 10000
	if policy {
		resolver, err := authz.New(authz.Config{Bindings: []authz.Binding{
			{Claim: authz.ClaimGroup, Value: "readers", Role: authz.RoleViewer},
			{Claim: authz.ClaimGroup, Value: "leads", Role: authz.RoleMaintainer},
			{Claim: authz.ClaimGroup, Value: "owners", Role: authz.RoleAdmin},
		}})
		if err != nil {
			t.Fatal(err)
		}
		srv.Authz = resolver
	}
	if _, err := srv.OpenMemberStore(); err != nil {
		t.Fatalf("OpenMemberStore: %v", err)
	}
	return &sudoHub{srv: srv, ts: ts, idp: idp}
}

// signIn signs a browser in as email with groups; stale makes the provider's
// own sign-in three hours old, so the session is not recent.
func (h *sudoHub) signIn(t *testing.T, email string, stale bool, groups ...string) *http.Client {
	t.Helper()
	h.idp.email, h.idp.sub, h.idp.groups = email, "sub-"+email, groups
	at := time.Time{}
	if stale {
		at = time.Now().Add(-3 * time.Hour)
	}
	h.idp.setSignedInAt(at)
	c := jarClient(t)
	login(t, c, h.ts)
	return c
}

func (h *sudoHub) call(t *testing.T, c *http.Client, method, path string, body any) (*http.Response, []byte) {
	t.Helper()
	var rdr io.Reader
	if body != nil {
		blob, _ := json.Marshal(body)
		rdr = bytes.NewReader(blob)
	}
	req, _ := http.NewRequest(method, h.ts.URL+path, rdr)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json")
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	return resp, raw
}

func reauthCode(raw []byte) string {
	var env struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	_ = json.Unmarshal(raw, &env)
	return env.Error.Code
}

// TestSudoRefusalIsTypedAndLeavesTheSessionLive: 401 REAUTH_REQUIRED with the
// window, the confirm URL and X-Cloop-Reauth — and not X-Cloop-Sign-In, which
// would send the tab through the provider on its own. The session keeps its
// reads, and /api/me says how it stands.
func TestSudoRefusalIsTypedAndLeavesTheSessionLive(t *testing.T) {
	h := newSudoHub(t, true)
	admin := h.signIn(t, "ada@example.com", true, "owners")

	resp, raw := h.call(t, admin, http.MethodPost, "/api/executors/enroll", map[string]any{"name": "edge"})
	if resp.StatusCode != http.StatusUnauthorized || reauthCode(raw) != "REAUTH_REQUIRED" {
		t.Fatalf("stale enrollment = %d %s, want 401 REAUTH_REQUIRED", resp.StatusCode, raw)
	}
	if got := resp.Header.Get(reauthHeader); got != "7200" {
		t.Errorf("%s = %q, want 7200", reauthHeader, got)
	}
	if resp.Header.Get(signInHintHeader) != "" {
		t.Errorf("a REAUTH_REQUIRED refusal must not carry %s: the tab would leave the page", signInHintHeader)
	}
	var env struct {
		Error struct {
			Details map[string]any `json:"details"`
		} `json:"error"`
	}
	_ = json.Unmarshal(raw, &env)
	d := env.Error.Details
	if d["max_age_seconds"] != float64(7200) || d["reauth_url"] != oidcauth.ReauthURL("", true) || d["session_kind"] != "browser" {
		t.Errorf("details = %v", d)
	}
	if ago, _ := d["signed_in_seconds_ago"].(float64); ago < 3*3600-60 {
		t.Errorf("signed_in_seconds_ago = %v, want about three hours", d["signed_in_seconds_ago"])
	}

	if resp, raw := h.call(t, admin, http.MethodGet, "/api/executors", nil); resp.StatusCode != http.StatusOK {
		t.Errorf("a stale session lost its reads: GET /api/executors = %d %s", resp.StatusCode, raw)
	}
	_, raw = h.call(t, admin, http.MethodGet, "/api/me", nil)
	var me struct {
		RecentSignIn struct {
			MaxAge    int64 `json:"max_age_seconds"`
			Remaining int64 `json:"remaining_seconds"`
		} `json:"recent_sign_in"`
	}
	if err := json.Unmarshal(raw, &me); err != nil || me.RecentSignIn.MaxAge != 7200 || me.RecentSignIn.Remaining != 0 {
		t.Errorf("/api/me recent_sign_in = %+v (%s)", me.RecentSignIn, raw)
	}

	fresh := h.signIn(t, "ada@example.com", false, "owners")
	if resp, raw := h.call(t, fresh, http.MethodPost, "/api/executors/enroll", map[string]any{"name": "edge"}); resp.StatusCode != http.StatusOK {
		t.Fatalf("a fresh session's enrollment = %d %s", resp.StatusCode, raw)
	}
	_, raw = h.call(t, fresh, http.MethodGet, "/api/me", nil)
	_ = json.Unmarshal(raw, &me)
	if me.RecentSignIn.Remaining < 7100 {
		t.Errorf("a fresh session has %ds of its window left, want about 7200", me.RecentSignIn.Remaining)
	}
}

// TestSudoIsAskedAfterAuthorization: somebody who may not act at all is told
// that — never sent to the provider to sign in for nothing.
func TestSudoIsAskedAfterAuthorization(t *testing.T) {
	h := newSudoHub(t, true)
	viewer := h.signIn(t, "vic@example.com", true, "readers")
	resp, raw := h.call(t, viewer, http.MethodPost, "/api/executors/enroll", map[string]any{"name": "edge"})
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("a stale viewer's enrollment = %d %s, want 403", resp.StatusCode, raw)
	}
}

// TestSudoNeverAsksTokens: an API token is not a session — nobody signs in
// behind it — and neither is the static token.
func TestSudoNeverAsksTokens(t *testing.T) {
	h := newSudoHub(t, true)
	t.Cleanup(h.srv.closeTokenManager)
	// Minted the way an admin mints one: from a session that signed in just now.
	admin := h.signIn(t, "ada@example.com", false, "owners")
	resp, raw := h.call(t, admin, http.MethodPost, "/api/tokens", map[string]any{"name": "ci", "roles": []string{"admin"}})
	var minted struct {
		Plaintext string `json:"plaintext"`
	}
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK || json.Unmarshal(raw, &minted) != nil || minted.Plaintext == "" {
		t.Fatalf("mint = %d %s", resp.StatusCode, raw)
	}
	req, _ := http.NewRequest(http.MethodPost, h.ts.URL+"/api/executors/enroll", strings.NewReader(`{"name":"edge-ci"}`))
	req.Header.Set("Authorization", "Bearer "+minted.Plaintext)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("an API token's enrollment = %d %s, want 200: tokens are not sessions", resp.StatusCode, raw)
	}

	idp := newUIFakeIdP(t)
	srv, ts := newOIDCTestServer(t, idp, "static-secret", nil)
	_ = srv
	req, _ = http.NewRequest(http.MethodPost, ts.URL+"/api/executors/enroll", strings.NewReader(`{"name":"edge-static"}`))
	req.Header.Set("Authorization", "Bearer static-secret")
	req.Header.Set("Content-Type", "application/json")
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("the static token's enrollment = %d %s, want 200", resp.StatusCode, raw)
	}
}

// TestSudoAsksOnAHubWithoutARolePolicy: with single sign-on and no role
// mappings every identity holds every privileged permission, which is where a
// stolen cookie is worth most — the rule still applies there.
func TestSudoAsksOnAHubWithoutARolePolicy(t *testing.T) {
	h := newSudoHub(t, false)
	c := h.signIn(t, "ada@example.com", true)
	resp, raw := h.call(t, c, http.MethodPost, "/api/tokens", map[string]any{"name": "x", "roles": []string{"viewer"}})
	if resp.StatusCode != http.StatusUnauthorized || reauthCode(raw) != "REAUTH_REQUIRED" {
		t.Fatalf("a stale session minting a token on a hub without a policy = %d %s, want 401 REAUTH_REQUIRED", resp.StatusCode, raw)
	}
}

// TestSudoAsksForMaintainerGrantsOnly: sharing a project at viewer or operator
// takes any live session; at maintainer — who may then broker the project's
// credentials and share it on — it asks.
func TestSudoAsksForMaintainerGrantsOnly(t *testing.T) {
	h := newSudoHub(t, true)
	admin := h.signIn(t, "ada@example.com", true, "owners")
	path := "/api/projects/0/members"
	resp, raw := h.call(t, admin, http.MethodPost, path, map[string]any{"identity": "olive@example.com", "role": "operator"})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("sharing at operator = %d %s, want 201", resp.StatusCode, raw)
	}
	resp, raw = h.call(t, admin, http.MethodPost, path, map[string]any{"identity": "max@example.com", "role": "maintainer"})
	if resp.StatusCode != http.StatusUnauthorized || reauthCode(raw) != "REAUTH_REQUIRED" {
		t.Fatalf("sharing at maintainer from a stale session = %d %s, want 401 REAUTH_REQUIRED", resp.StatusCode, raw)
	}
	resp, raw = h.call(t, admin, http.MethodPatch, path+"?identity=olive%40example.com", map[string]any{"role": "maintainer"})
	if resp.StatusCode != http.StatusUnauthorized || reauthCode(raw) != "REAUTH_REQUIRED" {
		t.Fatalf("raising a member to maintainer from a stale session = %d %s, want 401", resp.StatusCode, raw)
	}
	resp, raw = h.call(t, admin, http.MethodPatch, path+"?identity=olive%40example.com", map[string]any{"role": "viewer"})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("lowering a member = %d %s, want 200", resp.StatusCode, raw)
	}
}

// TestSudoAsksToEndSomebodyElsesSession: ending one of one's own sessions is
// containment and never asks; ending a colleague's does.
func TestSudoAsksToEndSomebodyElsesSession(t *testing.T) {
	h := newSudoHub(t, true)
	h.signIn(t, "bob@example.com", false, "readers")
	h.signIn(t, "ada@example.com", false, "owners")
	admin := h.signIn(t, "ada@example.com", true, "owners")

	ids := map[string]string{}
	recs, err := h.srv.OIDC.ListSessions()
	if err != nil {
		t.Fatal(err)
	}
	for _, rec := range recs {
		if rec.Identity.Email == "bob@example.com" {
			ids["bob"] = rec.ID
		}
	}
	// ada's fresh session — not the stale one asking.
	for _, rec := range recs {
		if rec.Identity.Email == "ada@example.com" && h.srv.OIDC.RecentSignIn(rec).Recent {
			ids["ada"] = rec.ID
		}
	}
	if ids["bob"] == "" || ids["ada"] == "" {
		t.Fatalf("sessions not found: %v", ids)
	}
	resp, raw := h.call(t, admin, http.MethodDelete, "/api/sessions/"+ids["bob"], nil)
	if resp.StatusCode != http.StatusUnauthorized || reauthCode(raw) != "REAUTH_REQUIRED" {
		t.Fatalf("ending somebody else's session from a stale one = %d %s, want 401", resp.StatusCode, raw)
	}
	resp, raw = h.call(t, admin, http.MethodDelete, "/api/sessions/"+ids["ada"], nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("ending one's own other session = %d %s, want 200", resp.StatusCode, raw)
	}
}

// TestAttachInfoSaysTheTerminalWouldAsk: the terminal is a WebSocket, whose
// refused handshake a page cannot read, so the read the Attach button makes
// first says whether opening it would ask.
func TestAttachInfoSaysTheTerminalWouldAsk(t *testing.T) {
	h := newSudoHub(t, true)
	stale := h.signIn(t, "ada@example.com", true, "owners")
	_, raw := h.call(t, stale, http.MethodGet, "/api/tasks/1/attach/info", nil)
	var info map[string]any
	if err := json.Unmarshal(raw, &info); err != nil || info["reauth_required"] != true {
		t.Fatalf("attach info for a stale session = %s, want reauth_required", raw)
	}
	fresh := h.signIn(t, "ada@example.com", false, "owners")
	_, raw = h.call(t, fresh, http.MethodGet, "/api/tasks/1/attach/info", nil)
	info = nil
	if err := json.Unmarshal(raw, &info); err != nil || info["reauth_required"] != nil {
		t.Fatalf("attach info for a fresh session = %s, want no reauth_required", raw)
	}
}

// TestStaleRefusalsAreCountedAndAudited: every refusal is counted, the trail
// takes them at a bounded rate and says how many it left out.
func TestStaleRefusalsAreCountedAndAudited(t *testing.T) {
	h := newSudoHub(t, true)
	h.srv.OIDC = mustAuthWithAudit(t, h)
	admin := h.signIn(t, "ada@example.com", true, "owners")
	sample := `cloop_session_reauth_total{outcome="stale-refused"}`
	before := metricValue(h.srv, sample)
	const n = refusalAuditPerMinute + 5
	for i := 0; i < n; i++ {
		if resp, _ := h.call(t, admin, http.MethodPost, "/api/executors/enroll", map[string]any{"name": fmt.Sprint("e", i)}); resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("refusal %d = %d", i, resp.StatusCode)
		}
	}
	if got := metricValue(h.srv, sample) - before; got != n {
		t.Errorf("stale-refused counted %v, want %d", got, n)
	}
	rows := auditRowsOf(t, h.srv.WorkDir, auditaction.ActionSessionReauth)
	if len(rows) != refusalAuditPerMinute {
		t.Errorf("%d session.reauth rows written, want the limit %d", len(rows), refusalAuditPerMinute)
	}
	for _, r := range rows {
		if !strings.Contains(r.Payload, `"outcome":"stale-refused"`) || !strings.Contains(r.Payload, `"path":"/api/executors/enroll"`) {
			t.Errorf("row payload %s", r.Payload)
			break
		}
	}
}

// mustAuthWithAudit rebuilds h's authenticator with the hub's audit sink, as
// `cloop ui` wires it.
func mustAuthWithAudit(t *testing.T, h *sudoHub) *oidcauth.Authenticator {
	t.Helper()
	cfg := oidcauth.Config{
		Enabled:      true,
		Issuer:       h.idp.server.URL,
		ClientID:     "cloop-dashboard",
		ClientSecret: "test-secret",
		RedirectURL:  h.ts.URL + "/auth/callback",
		Audit:        h.srv.SessionAuditSink(),
	}
	h.srv.InstallOIDCHooks(&cfg)
	auth, err := oidcauth.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return auth
}

// TestConfirmItsYouOnAProviderWithoutAuthTime: Entra ID without the optional
// claim — an ordinary sign-in is never recent, and the confirm-it's-you
// sign-in the hub itself started with prompt=login is, from its callback. A
// provider that ignores the prompt and reports its old sign-in is refused.
func TestConfirmItsYouOnAProviderWithoutAuthTime(t *testing.T) {
	h := newSudoHub(t, true)
	h.idp.setAuthTimeBehaviour(true, false)
	c := h.signIn(t, "ada@example.com", false, "owners")
	if resp, raw := h.call(t, c, http.MethodPost, "/api/executors/enroll", map[string]any{"name": "e1"}); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("an ordinary sign-in with no auth_time enrolled: %d %s", resp.StatusCode, raw)
	}
	confirm := func(c *http.Client) (int, string) {
		res, err := c.Get(h.ts.URL + "/auth/login?reauth=window")
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		doc, _ := io.ReadAll(res.Body)
		return res.StatusCode, string(doc)
	}
	if status, doc := confirm(c); status != http.StatusOK || !strings.Contains(doc, "granted") {
		t.Fatalf("confirm-it's-you with no auth_time = %d:\n%s", status, doc)
	}
	if resp, raw := h.call(t, c, http.MethodPost, "/api/executors/enroll", map[string]any{"name": "e2"}); resp.StatusCode != http.StatusOK {
		t.Fatalf("after a prompted sign-in the enrollment = %d %s", resp.StatusCode, raw)
	}

	h.idp.setAuthTimeBehaviour(false, true)
	stale := h.signIn(t, "ada@example.com", true, "owners")
	if status, doc := confirm(stale); status != http.StatusForbidden || !strings.Contains(doc, "refused") {
		t.Fatalf("a provider that ignored prompt=login = %d:\n%s", status, doc)
	}
	if resp, _ := h.call(t, stale, http.MethodPost, "/api/executors/enroll", map[string]any{"name": "e3"}); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("a refused confirmation freshened the session: %d", resp.StatusCode)
	}
}

// TestSudoCoversCredentialsOutsideTheSecretStore (found in review): a glasses
// link is a thirty-day token, a provider's API key or base URL decides where
// the hub's credential goes, the CI relay's settings decide where its
// Anthropic key goes and whose tokens it believes — each asks a stale session;
// the model a project uses does not.
func TestSudoCoversCredentialsOutsideTheSecretStore(t *testing.T) {
	h := newSudoHub(t, true)
	admin := h.signIn(t, "ada@example.com", true, "owners")
	for _, c := range []struct {
		method, path string
		body         any
	}{
		{http.MethodPost, "/api/glasses/link", map[string]any{}},
		{http.MethodPost, "/api/config/set", map[string]any{"key": "anthropic.base_url", "value": "https://attacker.example"}},
		{http.MethodPost, "/api/config/set", map[string]any{"key": "openai.api_key", "value": "sk-x"}},
		{http.MethodPut, "/api/ci/config", map[string]any{"enabled": true}},
		{http.MethodPut, "/api/config/stt", map[string]any{"groq_api_key": "gsk_x"}},
	} {
		resp, raw := h.call(t, admin, c.method, c.path, c.body)
		if resp.StatusCode != http.StatusUnauthorized || reauthCode(raw) != "REAUTH_REQUIRED" {
			t.Errorf("%s %s from a stale session = %d %s, want 401 REAUTH_REQUIRED", c.method, c.path, resp.StatusCode, raw)
		}
	}
	if resp, raw := h.call(t, admin, http.MethodPost, "/api/config/set",
		map[string]any{"key": "claudecode.model", "value": "claude-opus-5-5"}); resp.StatusCode != http.StatusOK {
		t.Errorf("choosing a model from a stale session = %d %s, want 200: it is no credential", resp.StatusCode, raw)
	}
	// A session id the store cannot vouch for is not the caller's own, so
	// ending it asks rather than going through.
	if resp, raw := h.call(t, admin, http.MethodDelete, "/api/sessions/"+strings.Repeat("0", 64), nil); resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("ending an unknown session from a stale one = %d %s, want 401", resp.StatusCode, raw)
	}
}
