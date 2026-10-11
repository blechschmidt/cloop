package ui

// The static admin token, retired at runtime (Task 20406).
//
// None of these starts a run.

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/apitoken"
	"github.com/blechschmidt/cloop/pkg/auditaction"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
	"github.com/blechschmidt/cloop/pkg/statictoken"
)

// staticTok20406 is the fixture hubs' static token.
const staticTok20406 = "static-admin-token-20406"

// newStaticHub starts a token-only hub over dir (a fresh project when dir is
// empty) with token as its static token.
func newStaticHub(t *testing.T, dir, token string) (*Server, *httptest.Server) {
	t.Helper()
	if dir == "" {
		dir = setupProjectDir(t, cloopGoal, nil)
	}
	srv := New(dir, 0, token)
	srv.RPS, srv.Burst = 10000, 10000
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	t.Cleanup(srv.closeTokenManager)
	return srv, ts
}

// staticCall sends method path to base presenting hdr, with body as JSON for
// a write, and returns the status, the decoded JSON body and the headers.
func staticCall(t *testing.T, base, method, path string, hdr http.Header, body string) (int, map[string]any, http.Header) {
	t.Helper()
	var rd io.Reader
	if body != "" {
		rd = strings.NewReader(body)
	}
	req, err := http.NewRequest(method, base+path, rd)
	if err != nil {
		t.Fatal(err)
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range hdr {
		req.Header[k] = v
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var out map[string]any
	_ = json.Unmarshal(raw, &out)
	return resp.StatusCode, out, resp.Header
}

// retireViaRoute retires the hub's static token through the Settings route,
// presenting hdr, and fails unless it was retired.
func retireViaRoute(t *testing.T, base string, hdr http.Header, force bool) map[string]any {
	t.Helper()
	body := `{"reason":"suspected leak in a CI log, INC-20406"}`
	if force {
		body = `{"reason":"suspected leak in a CI log, INC-20406","force":true}`
	}
	code, out, _ := staticCall(t, base, http.MethodPost, "/api/static-token/retire", hdr, body)
	if code != http.StatusOK || out["retired"] != true {
		t.Fatalf("POST /api/static-token/retire = %d %v, want 200 retired", code, out)
	}
	return out
}

// mintAdminToken mints an active admin API token on srv's control plane.
func mintAdminToken(t *testing.T, srv *Server) apitoken.Minted {
	t.Helper()
	mgr, err := srv.tokenManager()
	if err != nil {
		t.Fatal(err)
	}
	m, err := mgr.Mint(apitoken.MintOptions{Name: "break-glass", Roles: []string{"admin"}, CreatedBy: "root"})
	if err != nil {
		t.Fatal(err)
	}
	return m
}

// authFailureCount is how many failures srv has counted toward the lockout,
// across every address. An entry with no failures exists for any address the
// lockout was merely asked about.
func authFailureCount(srv *Server) int {
	srv.authMu.Lock()
	defer srv.authMu.Unlock()
	n := 0
	for _, e := range srv.authFails {
		n += e.count
	}
	return n
}

// wantRetiredRefusal asserts a refusal is the retired token's 401, saying
// when and by whom and what to use instead.
func wantRetiredRefusal(t *testing.T, what string, code int, body map[string]any, by string) {
	t.Helper()
	if code != http.StatusUnauthorized {
		t.Fatalf("%s = %d %v, want 401", what, code, body)
	}
	if body["code"] != staticTokenRetiredCode {
		t.Fatalf("%s: code %v, want %q (body %v)", what, body["code"], staticTokenRetiredCode, body)
	}
	if body["retired_by"] != by {
		t.Errorf("%s: retired_by %v, want %q", what, body["retired_by"], by)
	}
	at, _ := body["retired_at"].(string)
	if _, err := time.Parse(time.RFC3339, at); err != nil {
		t.Errorf("%s: retired_at %q is not a time", what, at)
	}
	msg, _ := body["error"].(string)
	if !strings.Contains(msg, "retired on "+at) || !strings.Contains(msg, by) || !strings.Contains(msg, "API token") {
		t.Errorf("%s: the refusal does not say when, by whom and what instead: %q", what, msg)
	}
	if strings.Contains(msg, "INC-20406") {
		t.Errorf("%s: the refusal carries the operator's reason, which is for the trail: %q", what, msg)
	}
}

// TestStaticToken_RetiredIsRefusedOnTheRetiringMember: the static token
// retires itself on a token-only hub — break the glass, then lock — and from
// then on both forms of it are refused with when and by whom, the retirement
// is in the audit trail, and none of the refusals counts toward the lockout.
func TestStaticToken_RetiredIsRefusedOnTheRetiringMember(t *testing.T) {
	srv, ts := newStaticHub(t, "", staticTok20406)
	static := bearerHeader(staticTok20406)
	if code, _, _ := staticCall(t, ts.URL, http.MethodGet, "/api/state", static, ""); code != http.StatusOK {
		t.Fatalf("GET /api/state with the static token = %d before retirement", code)
	}

	out := retireViaRoute(t, ts.URL, static, true)
	if tok, _ := out["token"].(map[string]any); tok["status"] != "retired" {
		t.Fatalf("the retire response's view = %v, want retired", out["token"])
	}

	code, body, hdr := staticCall(t, ts.URL, http.MethodGet, "/api/state", static, "")
	wantRetiredRefusal(t, "the header form", code, body, "static-token")
	if hdr.Get(signInHintHeader) != "" {
		t.Error("a token-only hub's refusal names a sign-in page it does not have")
	}
	code, body, _ = staticCall(t, ts.URL, http.MethodGet, "/api/state?token="+staticTok20406, nil, "")
	wantRetiredRefusal(t, "the ?token= form", code, body, "static-token")
	code, body, _ = staticCall(t, ts.URL, http.MethodGet, "/api/events?token="+staticTok20406, nil, "")
	wantRetiredRefusal(t, "an EventSource", code, body, "static-token")

	// Not a guess: a dozen refusals, and the address is not locked out.
	for i := 0; i < 12; i++ {
		staticCall(t, ts.URL, http.MethodGet, "/api/state", static, "")
	}
	if fails := authFailureCount(srv); fails != 0 {
		t.Fatalf("retired-token refusals counted %d auth failures, want none", fails)
	}
	if code, _, _ := staticCall(t, ts.URL, http.MethodGet, "/api/state", bearerHeader("a-wrong-guess"), ""); code != http.StatusUnauthorized {
		t.Fatalf("a wrong guess after the refusals = %d, want 401 (not a lockout)", code)
	}

	db, err := statedb.Open(state.DBPath(srv.WorkDir))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	rows, _, err := db.ListAuditEvents(statedb.AuditFilter{EventType: string(auditaction.ActionStaticTokenRetired)})
	if err != nil || len(rows) != 1 {
		t.Fatalf("static_token.retired rows = %d, %v", len(rows), err)
	}
	var p map[string]any
	_ = json.Unmarshal([]byte(rows[0].Payload), &p)
	fp := statictoken.Fingerprint(staticTok20406)
	if rows[0].EntityID != fp || rows[0].Actor != "static-token" || p["self"] != true || p["forced"] != true || p["via"] != "ui" {
		t.Fatalf("audit row %+v payload %v", rows[0], p)
	}
	if strings.Contains(rows[0].Payload, staticTok20406) {
		t.Fatal("the audit row carries the token's value")
	}
}

// TestStaticToken_TokenOnlyHubStaysClosedAfterRetirement: a retired token is
// never no token. The hub keeps refusing a request with no credential, keeps
// the bind decision a hub with sign-in gets, and admits API tokens.
func TestStaticToken_TokenOnlyHubStaysClosedAfterRetirement(t *testing.T) {
	srv, ts := newStaticHub(t, "", staticTok20406)
	admin := mintAdminToken(t, srv)
	retireViaRoute(t, ts.URL, bearerHeader(staticTok20406), false)

	if code, _, _ := staticCall(t, ts.URL, http.MethodGet, "/api/state", nil, ""); code != http.StatusUnauthorized {
		t.Fatalf("GET /api/state with no credential after retirement = %d, want 401: the hub opened", code)
	}
	if !srv.staticTokenConfigured() || srv.openHub() {
		t.Fatal("after retirement the hub reads as having no sign-in")
	}
	srv.Port = 8080
	plan, err := srv.listenPlan()
	if err != nil || plan.String() != "*:8080" {
		t.Fatalf("listenPlan after retirement = %v, %v; want the token hub's *:8080", plan, err)
	}
	if code, _, _ := staticCall(t, ts.URL, http.MethodGet, "/api/state", bearerHeader(admin.Plaintext), ""); code != http.StatusOK {
		t.Fatalf("an admin API token after retirement = %d, want 200", code)
	}
	// The root page still loads, so the token prompt can say what happened.
	if code, _, _ := staticCall(t, ts.URL, http.MethodGet, "/", nil, ""); code != http.StatusOK {
		t.Fatalf("GET / = %d", code)
	}
}

// TestStaticToken_RetireRefusesToStrandATokenOnlyHub: with no single sign-on
// and no admin API token, the static token is the only way to administer the
// hub, and retiring it is refused unless forced.
func TestStaticToken_RetireRefusesToStrandATokenOnlyHub(t *testing.T) {
	srv, ts := newStaticHub(t, "", staticTok20406)
	static := bearerHeader(staticTok20406)

	code, view, _ := staticCall(t, ts.URL, http.MethodGet, "/api/static-token", static, "")
	if code != http.StatusOK || view["status"] != "accepted" || view["strands"] != true ||
		view["self"] != true || view["configured"] != true || view["sso"] != false {
		t.Fatalf("GET /api/static-token = %d %v", code, view)
	}
	if fp, _ := view["fingerprint"].(string); fp != statictoken.Short(statictoken.Fingerprint(staticTok20406)) {
		t.Fatalf("the view's fingerprint %q is not the short fingerprint", fp)
	}

	code, body, _ := staticCall(t, ts.URL, http.MethodPost, "/api/static-token/retire", static,
		`{"reason":"SSO is coming, INC-20406"}`)
	if code != http.StatusConflict || !strings.Contains(body["error"].(string), "no way in") {
		t.Fatalf("retiring a token-only hub's only credential = %d %v, want 409 naming the lock-out", code, body)
	}
	if code, _, _ := staticCall(t, ts.URL, http.MethodGet, "/api/state", static, ""); code != http.StatusOK {
		t.Fatalf("the refused retirement retired the token anyway: %d", code)
	}
	if code, body, _ := staticCall(t, ts.URL, http.MethodPost, "/api/static-token/retire", static, `{"reason":"x"}`); code != http.StatusBadRequest {
		t.Fatalf("a retirement without a reason = %d %v, want 400", code, body)
	}

	// An admin API token is a way in: now it may go, unforced.
	mintAdminToken(t, srv)
	code, view, _ = staticCall(t, ts.URL, http.MethodGet, "/api/static-token", static, "")
	if code != http.StatusOK || view["strands"] != false || view["admin_tokens"] != float64(1) {
		t.Fatalf("with an admin token, GET /api/static-token = %d %v", code, view)
	}
	retireViaRoute(t, ts.URL, static, false)
}

// TestStaticToken_RetirementSurvivesARestartAndANewValueIsAdmitted: a hub
// process that starts after the retirement reads it before it serves, and
// refuses the token; one started with a new value admits it — the rotation
// path — and still refuses the retired one.
func TestStaticToken_RetirementSurvivesARestartAndANewValueIsAdmitted(t *testing.T) {
	first, ts := newStaticHub(t, "", staticTok20406)
	mintAdminToken(t, first)
	retireViaRoute(t, ts.URL, bearerHeader(staticTok20406), false)
	ts.Close()

	// The same value, after a restart.
	_, again := newStaticHub(t, first.WorkDir, staticTok20406)
	code, body, _ := staticCall(t, again.URL, http.MethodGet, "/api/state", bearerHeader(staticTok20406), "")
	wantRetiredRefusal(t, "the retired token after a restart", code, body, "static-token")

	// A new value.
	const rotated = "static-admin-token-20406-rotated"
	srv, next := newStaticHub(t, first.WorkDir, rotated)
	if code, _, _ := staticCall(t, next.URL, http.MethodGet, "/api/state", bearerHeader(rotated), ""); code != http.StatusOK {
		t.Fatalf("the new static token = %d, want 200", code)
	}
	code, body, _ = staticCall(t, next.URL, http.MethodGet, "/api/state", bearerHeader(staticTok20406), "")
	wantRetiredRefusal(t, "the retired value presented to the rotated hub", code, body, "static-token")
	if authFailureCount(srv) != 0 {
		t.Fatalf("presenting the retired value to the rotated hub counted as a guess")
	}
	code, view, _ := staticCall(t, next.URL, http.MethodGet, "/api/static-token", bearerHeader(rotated), "")
	if code != http.StatusOK || view["status"] != "accepted" {
		t.Fatalf("the rotated hub's view = %d %v", code, view)
	}
}

// TestStaticToken_LastUseIsKeptInMemoryAndFlushed: an admitted request is
// recorded in memory, shown on the card, and written by the flush — never by
// the request itself; refusals of the retired token are counted the same way.
func TestStaticToken_LastUseIsKeptInMemoryAndFlushed(t *testing.T) {
	srv, ts := newStaticHub(t, "", staticTok20406)
	static := bearerHeader(staticTok20406)
	fp := statictoken.Fingerprint(staticTok20406)
	useRow := func() (statedb.StaticTokenUseRow, bool) {
		t.Helper()
		db, err := statedb.Open(state.DBPath(srv.WorkDir))
		if err != nil {
			t.Fatal(err)
		}
		defer db.Close()
		rows, err := db.ListStaticTokenUse()
		if err != nil {
			t.Fatal(err)
		}
		for _, r := range rows {
			if r.Fingerprint == fp {
				return r, true
			}
		}
		return statedb.StaticTokenUseRow{}, false
	}

	before := time.Now()
	if code, _, _ := staticCall(t, ts.URL, http.MethodGet, "/api/state", static, ""); code != http.StatusOK {
		t.Fatal(code)
	}
	if _, ok := useRow(); ok {
		t.Fatal("an admitted request wrote its use to the database: the write is the flush's, never the request's")
	}
	code, view, _ := staticCall(t, ts.URL, http.MethodGet, "/api/static-token", static, "")
	if code != http.StatusOK || view["last_used_ip"] != "127.0.0.1" || view["last_used_at"] == nil {
		t.Fatalf("the card before any flush = %d %v, want the use held in memory", code, view)
	}

	if err := srv.flushStaticTokenUse(time.Now()); err != nil {
		t.Fatal(err)
	}
	row, ok := useRow()
	if !ok || row.LastUsedIP != "127.0.0.1" || row.LastUsedAt.Before(before.Add(-time.Second)) || row.HeldAt.IsZero() {
		t.Fatalf("after the flush: %+v (found %v)", row, ok)
	}

	mintAdminToken(t, srv)
	retireViaRoute(t, ts.URL, static, false)
	staticCall(t, ts.URL, http.MethodGet, "/api/state", static, "")
	staticCall(t, ts.URL, http.MethodGet, "/api/state?token="+staticTok20406, nil, "")
	if err := srv.flushStaticTokenUse(time.Now()); err != nil {
		t.Fatal(err)
	}
	row, _ = useRow()
	if row.RefusedCount != 2 || row.LastRefusedIP != "127.0.0.1" {
		t.Fatalf("refusals after the flush: %+v", row)
	}
}

// TestStaticToken_SSOHubRefusesItAndPointsAtSignIn: on a hub with single
// sign-on an administrator's session retires it — no force needed, the
// session is a way in — and its refusal carries the sign-in hint.
func TestStaticToken_SSOHubRefusesItAndPointsAtSignIn(t *testing.T) {
	f := newCredFixture(t)
	static := bearerHeader(credStaticToken)
	if code := f.call(t, http.DefaultClient, http.MethodGet, "/api/state", static); code != http.StatusOK {
		t.Fatalf("the static token on an SSO hub = %d before retirement", code)
	}
	req, _ := http.NewRequest(http.MethodPost, f.ts.URL+"/api/static-token/retire",
		strings.NewReader(`{"reason":"single sign-on works now"}`))
	req.Header.Set("Content-Type", "application/json")
	resp, err := f.root.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("an administrator retiring it = %d", resp.StatusCode)
	}

	code, body, hdr := staticCall(t, f.ts.URL, http.MethodGet, "/api/state", static, "")
	wantRetiredRefusal(t, "the retired token on an SSO hub", code, body, rootEmail)
	if hdr.Get(signInHintHeader) == "" {
		t.Error("an SSO hub's refusal does not point the browser at sign-in")
	}
	if !strings.Contains(body["instead"].(string), "single sign-on") {
		t.Errorf("instead = %v, want single sign-on named", body["instead"])
	}
	// The administrator's session is unaffected.
	if code := f.call(t, f.root, http.MethodGet, "/api/me", nil); code != http.StatusOK {
		t.Fatalf("the administrator's session after the retirement = %d", code)
	}
}

// TestStaticToken_UnreadableRetirementsRefuseTheToken: whether the token is
// retired cannot be told — the retirements have never been read — so the
// token is refused, as unavailable rather than as a guess.
func TestStaticToken_UnreadableRetirementsRefuseTheToken(t *testing.T) {
	srv, ts := newStaticHub(t, "", staticTok20406)
	// A directory where the database should be: present, and unopenable.
	path := state.DBPath(srv.WorkDir)
	for _, p := range []string{path, path + "-wal", path + "-shm"} {
		if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
			t.Fatal(err)
		}
	}
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	code, body, _ := staticCall(t, ts.URL, http.MethodGet, "/api/state", bearerHeader(staticTok20406), "")
	if code != http.StatusServiceUnavailable || !strings.Contains(body["error"].(string), "cannot be verified") {
		t.Fatalf("the static token with unreadable retirements = %d %v, want 503", code, body)
	}
	if authFailureCount(srv) != 0 {
		t.Fatal("an unverifiable token counted as a guess")
	}
}
