package ui

// Terminal sign-in over HTTP (Task 20412): `cloop login`'s two endpoints, the
// approval page and its three routes, and the CLI session they produce,
// driven through the real middleware chain against a fake identity provider.
//
// pkg/oidcauth covers the grant's own rules. What only a real server shows is
// here: that the terminal's endpoints answer before authentication and the
// browser's only after it, that the result authenticates by bearer through
// every gate a browser session goes through — RBAC, claim freshness, the
// streams it opens — and that revoking, demoting or offboarding the person
// reaches the terminal.
//
// None of these tests starts a run.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/authz"
	"github.com/blechschmidt/cloop/pkg/oidcauth"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// deviceFixture is a hub with single sign-on, terminal sign-in on, RBAC by
// group, runtime bindings (which offboarding writes), and a clock the test
// drives.
type deviceFixture struct {
	srv *Server
	ts  *httptest.Server
	idp *uiFakeIdP
	clk *clusterRenewClock
}

func newDeviceFixture(t *testing.T, mutate func(*oidcauth.Config)) *deviceFixture {
	t.Helper()
	idp := newUIFakeIdP(t)
	idp.issueRefresh = "rt-device"
	dir := setupProjectDir(t, cloopGoal, nil)
	srv := New(dir, 0, "")
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	clk := &clusterRenewClock{}
	cfg := oidcauth.Config{
		Enabled:         true,
		Issuer:          idp.server.URL,
		ClientID:        "cloop-dashboard",
		ClientSecret:    "test-secret",
		RedirectURL:     ts.URL + "/auth/callback",
		AdminEmails:     []string{rootEmail},
		SessionTTL:      24 * time.Hour,
		IdleTimeout:     8 * time.Hour,
		RefreshInterval: 15 * time.Minute,
		MaxClaimAge:     5 * time.Minute,
		Clock:           clk.now,
		DeviceLogin:     true,
		Audit:           srv.SessionAuditSink(),
	}
	if mutate != nil {
		mutate(&cfg)
	}
	srv.InstallOIDCHooks(&cfg)
	auth, err := oidcauth.New(cfg)
	if err != nil {
		t.Fatalf("oidcauth.New: %v", err)
	}
	srv.OIDC = auth
	roles, err := srv.OpenRoleStore()
	if err != nil {
		t.Fatalf("OpenRoleStore: %v", err)
	}
	t.Cleanup(srv.closeRoleStore)
	resolver, err := authz.New(authz.Config{
		Bindings: []authz.Binding{
			{Claim: authz.ClaimGroup, Value: "readers", Role: authz.RoleViewer},
			{Claim: authz.ClaimGroup, Value: "engineers", Role: authz.RoleOperator},
			{Claim: authz.ClaimGroup, Value: "owners", Role: authz.RoleAdmin},
		},
		AdminEmails: []string{rootEmail},
		Runtime:     roles,
	})
	if err != nil {
		t.Fatalf("authz.New: %v", err)
	}
	srv.Authz = resolver
	srv.RPS, srv.Burst = 10000, 10000
	return &deviceFixture{srv: srv, ts: ts, idp: idp, clk: clk}
}

// signIn completes a browser sign-in as email with groups.
func (f *deviceFixture) signIn(t *testing.T, email, sub string, groups ...string) *http.Client {
	t.Helper()
	f.idp.email, f.idp.sub, f.idp.name, f.idp.groups = email, sub, strings.Split(email, "@")[0], groups
	c := jarClient(t)
	login(t, c, f.ts)
	return c
}

// post sends a JSON body as c (nil: no credential) with hdr, returning the
// status and the decoded answer.
func (f *deviceFixture) post(t *testing.T, c *http.Client, path string, body any, hdr http.Header) (int, map[string]any) {
	t.Helper()
	blob, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest(http.MethodPost, f.ts.URL+path, bytes.NewReader(blob))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range hdr {
		req.Header[k] = v
	}
	if c == nil {
		c = &http.Client{}
	}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("POST %s: %v", path, err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var out map[string]any
	_ = json.Unmarshal(raw, &out)
	if out == nil {
		out = map[string]any{"raw": string(raw)}
	}
	return resp.StatusCode, out
}

// get sends a GET as c with hdr.
func (f *deviceFixture) get(t *testing.T, c *http.Client, path string, hdr http.Header) (int, map[string]any) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, f.ts.URL+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range hdr {
		req.Header[k] = v
	}
	if c == nil {
		c = &http.Client{}
	}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var out map[string]any
	_ = json.Unmarshal(raw, &out)
	if out == nil {
		out = map[string]any{"raw": string(raw)}
	}
	return resp.StatusCode, out
}

// terminalCode is what `cloop login` holds while it waits.
type terminalCode struct {
	credential, digest  string
	deviceCode, userURL string
	userCode            string
	// sessionID is the id the hub stores the session under once approved.
	sessionID string
}

// askForCode is a terminal asking the hub for a code.
func (f *deviceFixture) askForCode(t *testing.T) terminalCode {
	t.Helper()
	cred, digest, err := oidcauth.NewCLICredential()
	if err != nil {
		t.Fatal(err)
	}
	status, body := f.post(t, nil, "/api/device/code", map[string]string{"credential_hash": digest, "hostname": "dev-laptop"}, nil)
	if status != http.StatusOK {
		t.Fatalf("POST /api/device/code = %d: %v", status, body)
	}
	tc := terminalCode{credential: cred, digest: digest, sessionID: oidcauth.CLISessionID(digest)}
	tc.deviceCode, _ = body["device_code"].(string)
	tc.userCode, _ = body["user_code"].(string)
	tc.userURL, _ = body["verification_uri_complete"].(string)
	if tc.deviceCode == "" || tc.userCode == "" || !strings.HasSuffix(body["verification_uri"].(string), "/device") {
		t.Fatalf("code answer %v", body)
	}
	return tc
}

// approveIn approves a code in browser, following the identity provider's
// round trip back to the approval page.
func (f *deviceFixture) approveIn(t *testing.T, browser *http.Client, userCode string) {
	t.Helper()
	status, body := f.post(t, browser, "/api/device/approve", map[string]string{"user_code": userCode}, nil)
	if status != http.StatusOK {
		t.Fatalf("POST /api/device/approve = %d: %v", status, body)
	}
	redirect, _ := body["redirect"].(string)
	resp, err := browser.Get(redirect)
	if err != nil {
		t.Fatalf("follow the approval through the provider: %v", err)
	}
	defer resp.Body.Close()
	page, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK || resp.Request.URL.Path != oidcauth.DevicePath {
		t.Fatalf("the approval ended at %s with %d:\n%s", resp.Request.URL, resp.StatusCode, page)
	}
}

// poll is one poll of the token endpoint.
func (f *deviceFixture) poll(t *testing.T, tc terminalCode) (int, map[string]any) {
	t.Helper()
	return f.post(t, nil, "/api/device/token", map[string]string{
		"grant_type": oidcauth.DeviceGrantType, "device_code": tc.deviceCode,
	}, nil)
}

// cliLogin is `cloop login` end to end, approved in browser.
func (f *deviceFixture) cliLogin(t *testing.T, browser *http.Client) terminalCode {
	t.Helper()
	tc := f.askForCode(t)
	f.approveIn(t, browser, tc.userCode)
	status, body := f.poll(t, tc)
	if status != http.StatusOK || body["session_id"] != tc.sessionID {
		t.Fatalf("poll after approval = %d %v, want 200 naming the committed session", status, body)
	}
	return tc
}

func (tc terminalCode) bearer() http.Header { return bearerHeader(tc.credential) }

// ── the whole grant ─────────────────────────────────────────────────────────

func TestDeviceLogin_TerminalSignsInThroughTheBrowser(t *testing.T) {
	f := newDeviceFixture(t, nil)
	root := f.signIn(t, rootEmail, "sub-root")
	alice := f.signIn(t, aliceEmail, "sub-alice", "engineers")

	tc := f.askForCode(t)
	if status, body := f.poll(t, tc); status != http.StatusBadRequest || body["error"] != oidcauth.DeviceErrPending {
		t.Fatalf("poll before approval = %d %v, want authorization_pending", status, body)
	}
	status, view := f.post(t, alice, "/api/device/lookup", map[string]string{"user_code": strings.ToLower(tc.userCode)}, nil)
	if status != http.StatusOK || view["status"] != "pending" || view["client_hostname"] != "dev-laptop" ||
		view["email"] != aliceEmail || view["same_address"] != true {
		t.Fatalf("lookup = %d %v", status, view)
	}
	f.approveIn(t, alice, tc.userCode)
	f.clk.advance(6 * time.Second)
	status, tok := f.poll(t, tc)
	if status != http.StatusOK || tok["session_id"] != tc.sessionID || tok["access_token"] != nil {
		t.Fatalf("poll after approval = %d %v: want the committed session and no credential", status, tok)
	}

	// The terminal is a session: /api/me knows it, by bearer.
	status, me := f.get(t, nil, "/api/me", tc.bearer())
	if status != http.StatusOK || me["email"] != aliceEmail || me["session_kind"] != "cli" || me["role"] != "operator" {
		t.Fatalf("/api/me as the terminal = %d %v", status, me)
	}
	// And it is listed like one.
	var found map[string]any
	for _, row := range sessionsOf(t, root, f.ts.URL) {
		if row["id"] == tc.sessionID {
			found = row
		}
	}
	if found == nil || found["kind"] != "cli" || found["client"] != "dev-laptop" {
		t.Fatalf("Active Sessions row %v", found)
	}
	// The page reads the outcome back.
	if _, view := f.post(t, alice, "/api/device/lookup", map[string]string{"user_code": tc.userCode}, nil); view["status"] != "consumed" ||
		view["decided_by_you"] != true {
		t.Fatalf("lookup after approval = %v", view)
	}

	// Single use.
	if status, body := f.poll(t, tc); status != http.StatusBadRequest || body["error"] != oidcauth.DeviceErrInvalidGrant {
		t.Fatalf("a second exchange = %d %v, want invalid_grant", status, body)
	}

	// `cloop logout`: the terminal ends its own session.
	status, out := f.post(t, nil, oidcauth.LogoutPath, map[string]string{}, tc.bearer())
	if status != http.StatusOK || out["ended"] != true {
		t.Fatalf("logout = %d %v", status, out)
	}
	if status, _ := f.get(t, nil, "/api/me", tc.bearer()); status != http.StatusUnauthorized {
		t.Fatalf("/api/me after logout = %d, want 401", status)
	}
	if status, out := f.post(t, nil, oidcauth.LogoutPath, map[string]string{}, tc.bearer()); status != http.StatusOK || out["ended"] != false {
		t.Fatalf("a second logout = %d %v, want ok with nothing ended", status, out)
	}
}

func TestDeviceEndpoints_AnswerBeforeAuthenticationAndTheRestAfter(t *testing.T) {
	f := newDeviceFixture(t, nil)
	if !servedBeforeAuth(httptest.NewRequest(http.MethodPost, "/api/device/code", nil)) ||
		!servedBeforeAuth(httptest.NewRequest(http.MethodPost, "/api/device/token", nil)) {
		t.Fatal("the terminal's endpoints are not served before authentication")
	}
	for _, r := range []*http.Request{
		httptest.NewRequest(http.MethodGet, "/api/device/code", nil),
		httptest.NewRequest(http.MethodPost, "/api/device/approve", nil),
		httptest.NewRequest(http.MethodGet, "/device", nil),
	} {
		if servedBeforeAuth(r) {
			t.Errorf("%s %s is served before authentication", r.Method, r.URL.Path)
		}
	}
	// No credential at all: the code endpoint answers, the decisions do not.
	f.askForCode(t)
	if status, _ := f.post(t, nil, "/api/device/lookup", map[string]string{"user_code": "BCDFG-HJKLM"}, nil); status != http.StatusUnauthorized {
		t.Errorf("an anonymous lookup = %d, want 401", status)
	}
	// A browser with no session is sent to sign in, and back here.
	req, _ := http.NewRequest(http.MethodGet, f.ts.URL+"/device?code=BCDFG-HJKLM", nil)
	req.Header.Set("Accept", "text/html")
	resp, err := (&http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	loc := resp.Header.Get("Location")
	if resp.StatusCode != http.StatusFound || !strings.HasPrefix(loc, oidcauth.LoginPath+"?return=") ||
		!strings.Contains(loc, url.QueryEscape("/device?code=BCDFG-HJKLM")) {
		t.Fatalf("an anonymous /device = %d → %q, want the sign-in carrying the code back", resp.StatusCode, loc)
	}
}

func TestDevicePage_IsItsOwnDocumentWithItsOwnScript(t *testing.T) {
	f := newDeviceFixture(t, nil)
	alice := f.signIn(t, aliceEmail, "sub-alice", "engineers")
	resp, err := alice.Get(f.ts.URL + "/device")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	page, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("/device = %d", resp.StatusCode)
	}
	html := string(page)
	if !strings.Contains(html, `<script src="/assets/device.`) || strings.Contains(html, "{{asset:") {
		t.Fatalf("the page does not load its hashed script:\n%s", html)
	}
	if strings.Count(html, "<script") != 1 || strings.Contains(strings.ToLower(html), " onclick=") {
		t.Fatal("the approval page carries inline script or an inline handler")
	}
	if !strings.Contains(html, "Only approve a code you started yourself") {
		t.Fatal("the approval page lost its warning")
	}
	csp := resp.Header.Get("Content-Security-Policy")
	scriptSrc := ""
	for _, d := range strings.Split(csp, ";") {
		if d = strings.TrimSpace(d); strings.HasPrefix(d, "script-src ") {
			scriptSrc = d
		}
	}
	if scriptSrc != "script-src 'self'" {
		t.Errorf("the approval page's script-src is %q, want 'self' alone (CSP %q)", scriptSrc, csp)
	}
	// Its maintainers' comments stay in the source and out of the page.
	const comment = "Approve a terminal sign-in (Task 20412)"
	if !strings.Contains(loadAssets().renderedDevice, comment) || strings.Contains(html, comment) {
		t.Error("the approval page's comments were not stripped from what it serves")
	}
	// Off when terminal sign-in is.
	off := newDeviceFixture(t, func(c *oidcauth.Config) { c.DeviceLogin = false })
	b := off.signIn(t, aliceEmail, "sub-alice", "engineers")
	if r2, err := b.Get(off.ts.URL + "/device"); err != nil || r2.StatusCode != http.StatusNotFound {
		t.Fatalf("/device with device_login off = %v %v, want 404", r2.StatusCode, err)
	}
	if status, body := off.post(t, nil, "/api/device/code", map[string]string{"credential_hash": strings.Repeat("a", 64)}, nil); status != http.StatusNotFound ||
		!strings.Contains(body["error_description"].(string), "device_login") {
		t.Fatalf("a code with device_login off = %d %v", status, body)
	}
}

// ── the token endpoint ──────────────────────────────────────────────────────

func TestDeviceToken_AnswersInOAuthsVocabulary(t *testing.T) {
	f := newDeviceFixture(t, nil)
	alice := f.signIn(t, aliceEmail, "sub-alice", "engineers")

	tc := f.askForCode(t)
	if status, body := f.poll(t, tc); status != http.StatusBadRequest || body["error"] != oidcauth.DeviceErrPending {
		t.Fatalf("first poll = %d %v", status, body)
	}
	status, body := f.poll(t, tc)
	if status != http.StatusBadRequest || body["error"] != oidcauth.DeviceErrSlowDown || body["interval"] != float64(10) {
		t.Fatalf("a poll at once = %d %v, want slow_down at 10s", status, body)
	}

	// Denied in the browser.
	if status, out := f.post(t, alice, "/api/device/deny", map[string]string{"user_code": tc.userCode}, nil); status != http.StatusOK {
		t.Fatalf("deny = %d %v", status, out)
	}
	f.clk.advance(11 * time.Second)
	if status, body := f.poll(t, tc); status != http.StatusBadRequest || body["error"] != oidcauth.DeviceErrDenied {
		t.Fatalf("poll after denial = %d %v, want access_denied", status, body)
	}

	// Expired.
	late := f.askForCode(t)
	f.clk.advance(oidcauth.DeviceCodeLifetime + time.Second)
	if status, body := f.poll(t, late); status != http.StatusBadRequest || body["error"] != oidcauth.DeviceErrExpired {
		t.Fatalf("poll after expiry = %d %v, want expired_token", status, body)
	}
	if status, _ := f.post(t, alice, "/api/device/approve", map[string]string{"user_code": late.userCode}, nil); status != http.StatusConflict {
		t.Fatalf("approving an expired code = %d, want 409", status)
	}

	// Unknown, and a grant type this endpoint does not take.
	if status, body := f.post(t, nil, "/api/device/token", map[string]string{"device_code": "made-up"}, nil); status != http.StatusBadRequest ||
		body["error"] != oidcauth.DeviceErrInvalidGrant {
		t.Fatalf("an unknown code = %d %v", status, body)
	}
	if status, body := f.post(t, nil, "/api/device/token", map[string]string{"grant_type": "password", "device_code": tc.deviceCode}, nil); status != http.StatusBadRequest ||
		body["error"] != "unsupported_grant_type" {
		t.Fatalf("grant_type password = %d %v", status, body)
	}
	// JSON only, like every state-changing request (Task 20394).
	req, _ := http.NewRequest(http.MethodPost, f.ts.URL+"/api/device/code", strings.NewReader("credential_hash=x"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnsupportedMediaType {
		t.Fatalf("a form-encoded code request = %d, want 415", resp.StatusCode)
	}
}

func TestDeviceCode_IsRateLimitedPerAddress(t *testing.T) {
	f := newDeviceFixture(t, nil)
	for i := 0; i < deviceCodesPerAddress; i++ {
		f.askForCode(t)
	}
	status, body := f.post(t, nil, "/api/device/code", map[string]string{"credential_hash": strings.Repeat("b", 64)}, nil)
	if status != http.StatusTooManyRequests || body["error"] != "slow_down" {
		t.Fatalf("code %d from one address = %d %v, want 429", deviceCodesPerAddress+1, status, body)
	}
}

// TestDeviceCode_CountsAnIPv6HostByItsSlash64: a host is handed a whole /64,
// and keyed by the full address it would have billions of budgets.
func TestDeviceCode_CountsAnIPv6HostByItsSlash64(t *testing.T) {
	f := newDeviceFixture(t, nil)
	ask := func(remote string) int {
		_, digest, _ := oidcauth.NewCLICredential()
		req := httptest.NewRequest(http.MethodPost, "/api/device/code",
			strings.NewReader(`{"credential_hash":"`+digest+`","hostname":"h"}`))
		req.Header.Set("Content-Type", "application/json")
		req.RemoteAddr = remote
		rec := httptest.NewRecorder()
		f.srv.handleDeviceCode(rec, req)
		return rec.Code
	}
	for i := 0; i < deviceCodesPerAddress; i++ {
		if code := ask(fmt.Sprintf("[2001:db8:1:2::%x]:40000", i+1)); code != http.StatusOK {
			t.Fatalf("code %d = %d", i+1, code)
		}
	}
	if code := ask("[2001:db8:1:2:ffff:ffff:ffff:fffe]:40000"); code != http.StatusTooManyRequests {
		t.Fatalf("another address in the same /64 = %d, want 429", code)
	}
	if code := ask("[2001:db8:1:3::1]:40000"); code != http.StatusOK {
		t.Fatalf("the next /64 = %d, want its own budget", code)
	}

	for in, want := range map[string]string{
		"203.0.113.7":                   "203.0.113.7",
		"::ffff:203.0.113.7":            "203.0.113.7",
		"2001:db8:1:2:3:4:5:6":          "2001:db8:1:2::/64",
		"fe80::1%eth0":                  "fe80::/64",
		"not an address":                "not an address",
		"2001:db8:1:2:ffff:ffff:ffff:1": "2001:db8:1:2::/64",
	} {
		if got := deviceRateKey(in); got != want {
			t.Errorf("deviceRateKey(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestDeviceCode_RecordsTheAddressTheHubBelieves: the approval page puts the
// request's address beside the browser's, so a phisher who could choose it
// could make their request look local. The address is the hub's own view —
// the peer, or a trusted proxy's account — never a header the client wrote.
func TestDeviceCode_RecordsTheAddressTheHubBelieves(t *testing.T) {
	f := newDeviceFixture(t, nil)
	alice := f.signIn(t, aliceEmail, "sub-alice", "engineers")
	_, digest, _ := oidcauth.NewCLICredential()
	req := httptest.NewRequest(http.MethodPost, "/api/device/code",
		strings.NewReader(`{"credential_hash":"`+digest+`","hostname":"evil"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Forwarded-For", "127.0.0.1")
	req.RemoteAddr = "203.0.113.50:40000"
	rec := httptest.NewRecorder()
	f.srv.handleDeviceCode(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("handleDeviceCode = %d %s", rec.Code, rec.Body.String())
	}
	var grant map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &grant)
	_, view := f.post(t, alice, "/api/device/lookup", map[string]any{"user_code": grant["user_code"]}, nil)
	if view["client_ip"] != "203.0.113.50" || view["same_address"] != false {
		t.Fatalf("lookup %v: the request's address should be the peer's, not the header's", view)
	}
}

// ── who may decide ──────────────────────────────────────────────────────────

func TestDeviceDecisions_TakeABrowserSessionOnly(t *testing.T) {
	f := newDeviceFixture(t, nil)
	alice := f.signIn(t, aliceEmail, "sub-alice", "engineers")
	terminal := f.cliLogin(t, alice)
	pending := f.askForCode(t)

	for _, path := range []string{"/api/device/lookup", "/api/device/approve", "/api/device/deny"} {
		status, body := f.post(t, nil, path, map[string]string{"user_code": pending.userCode}, terminal.bearer())
		if status != http.StatusForbidden {
			t.Errorf("%s as a terminal session = %d %v, want 403", path, status, body)
		}
	}
	if _, body := f.post(t, alice, "/api/device/lookup", map[string]string{"user_code": pending.userCode}, nil); body["status"] != "pending" {
		t.Fatalf("the refused attempts changed the code: %v", body)
	}
}

func TestDeviceLookup_MissesAreRateLimited(t *testing.T) {
	f := newDeviceFixture(t, nil)
	alice := f.signIn(t, aliceEmail, "sub-alice", "engineers")
	codes := []string{"BCDFG-HJKLM", "CDFGH-JKLMN", "DFGHJ-KLMNP"}
	for i := 0; i < deviceMissesPerCaller; i++ {
		if status, _ := f.post(t, alice, "/api/device/lookup", map[string]string{"user_code": codes[i%len(codes)]}, nil); status != http.StatusNotFound {
			t.Fatalf("miss %d = %d, want 404", i+1, status)
		}
	}
	if status, _ := f.post(t, alice, "/api/device/lookup", map[string]string{"user_code": "BCDFG-HJKLM"}, nil); status != http.StatusTooManyRequests {
		t.Fatalf("a lookup after %d misses = %d, want 429", deviceMissesPerCaller, status)
	}
}

// ── the CLI session, after ──────────────────────────────────────────────────

// TestCLISession_RevokingItClosesItsLogStreamAndTerminal: what the terminal
// opened with its session — `cloop remote logs --follow` and `cloop task
// attach` — closes when the session is revoked, at once, with the reason.
func TestCLISession_RevokingItClosesItsLogStreamAndTerminal(t *testing.T) {
	setAttachRecheckInterval(t, time.Hour)
	streamTicks(t, time.Hour)
	f := newDeviceFixture(t, nil)
	root := f.signIn(t, rootEmail, "sub-root")
	tc := f.cliLogin(t, root)

	logs := openWSAt(t, f.ts.URL, "/api/ws?project_idx=0", nil, tc.bearer())
	logs.awaitMessage(t, "task_update")
	term := openTerminal(t, f.srv, f.ts.URL, nil, tc.bearer())

	// The streams recorded the terminal's session as their credential.
	var sawSession bool
	for _, c := range f.srv.openStreamCredentials() {
		sawSession = sawSession || c.sessionHash == tc.sessionID
	}
	if !sawSession {
		t.Fatal("the log stream did not record the terminal's session as its credential")
	}

	if code, _ := f.srv.OIDC.RevokeSession(tc.sessionID, rootEmail, ""); !code {
		t.Fatal("RevokeSession found no terminal session")
	}
	for _, ls := range []*liveStream{logs, term} {
		got := ls.awaitEnd(t, 5*time.Second)
		if got.closeReason != streamEndSession {
			t.Errorf("%s ended with %d %q, want %q", ls.kind, got.closeCode, got.closeReason, streamEndSession)
		}
	}
}

// TestCLISession_ADemotionAtTheProviderReachesIt: the terminal's claims are
// re-asserted on the same rule a browser's are. Above operator at once, once
// they are older than max_claim_age; everywhere else at the next background
// revalidation.
func TestCLISession_ADemotionAtTheProviderReachesIt(t *testing.T) {
	t.Run("a privileged action, past max_claim_age", func(t *testing.T) {
		f := newDeviceFixture(t, nil)
		admin := f.signIn(t, aliceEmail, "sub-alice", "owners")
		tc := f.cliLogin(t, admin)
		if status, body := f.get(t, nil, "/api/tasks/1/attach/info", tc.bearer()); status == http.StatusForbidden {
			t.Fatalf("an admin's terminal was refused attach info: %v", body)
		}
		f.idp.groups = []string{"readers"}
		f.clk.advance(6 * time.Minute)
		status, body := f.get(t, nil, "/api/tasks/1/attach/info", tc.bearer())
		if status != http.StatusForbidden {
			t.Fatalf("attach info after the demotion = %d %v, want 403", status, body)
		}
		if status, me := f.get(t, nil, "/api/me", tc.bearer()); status != http.StatusOK || me["session_kind"] != "cli" {
			t.Fatalf("the demoted terminal's session ended rather than narrowed: %d %v", status, me)
		}
	})
	t.Run("an operator action, at the next revalidation", func(t *testing.T) {
		f := newDeviceFixture(t, nil)
		dev := f.signIn(t, aliceEmail, "sub-alice", "engineers")
		tc := f.cliLogin(t, dev)
		if status, body := f.post(t, nil, "/api/tasks?project_idx=0", map[string]string{"title": "from the terminal"}, tc.bearer()); status != http.StatusOK {
			t.Fatalf("an operator's terminal adding a task = %d %v", status, body)
		}
		f.idp.groups = []string{"readers"}
		f.clk.advance(16 * time.Minute)
		f.srv.OIDC.RevalidateDue(context.Background())
		if status, body := f.post(t, nil, "/api/tasks?project_idx=0", map[string]string{"title": "after the demotion"}, tc.bearer()); status != http.StatusForbidden {
			t.Fatalf("a demoted terminal adding a task = %d %v, want 403", status, body)
		}
	})
}

// TestCLISession_OffboardingEndsItAndRefusesTheNext: offboarding the person
// ends their terminal's session, and the deny binding it writes stops a fresh
// approval becoming one.
func TestCLISession_OffboardingEndsItAndRefusesTheNext(t *testing.T) {
	f := newDeviceFixture(t, nil)
	root := f.signIn(t, rootEmail, "sub-root")
	alice := f.signIn(t, aliceEmail, "sub-alice", "engineers")
	tc := f.cliLogin(t, alice)

	status, rep := postOffboard(t, root, f.ts.URL, map[string]any{"identity": aliceEmail, "reason": "left the company, HR-20412"})
	if status != http.StatusOK {
		t.Fatalf("offboard = %d %v", status, rep)
	}
	found := false
	for _, id := range rep["sessions_revoked"].([]any) {
		found = found || id == tc.sessionID
	}
	if !found {
		t.Fatalf("sessions_revoked %v does not include the terminal's", rep["sessions_revoked"])
	}
	if status, _ := f.get(t, nil, "/api/me", tc.bearer()); status != http.StatusUnauthorized {
		t.Fatalf("the offboarded terminal = %d, want 401", status)
	}

	// Signing in again at the provider is possible; turning that into a
	// terminal session is not.
	again := f.signIn(t, aliceEmail, "sub-alice", "engineers")
	next := f.askForCode(t)
	status, body := f.post(t, again, "/api/device/approve", map[string]string{"user_code": next.userCode}, nil)
	if status != http.StatusOK {
		t.Fatalf("approve = %d %v", status, body)
	}
	resp, err := again.Get(body["redirect"].(string))
	if err != nil {
		t.Fatal(err)
	}
	page, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden || !strings.Contains(string(page), "deny binding") {
		t.Fatalf("an offboarded identity's approval = %d:\n%s", resp.StatusCode, page)
	}
	f.clk.advance(6 * time.Second)
	if status, body := f.poll(t, next); status != http.StatusBadRequest || body["error"] != oidcauth.DeviceErrDenied {
		t.Fatalf("poll = %d %v, want access_denied", status, body)
	}
}

// TestOIDCGate_AnEndedTerminalSessionIsToldSo: a revoked terminal credential
// is answered as an ended session, and is not counted toward the address's
// lockout — on a NAT a developer's dead terminal must not lock their browser
// out beside it.
func TestOIDCGate_AnEndedTerminalSessionIsToldSo(t *testing.T) {
	f := newDeviceFixture(t, nil)
	alice := f.signIn(t, aliceEmail, "sub-alice", "engineers")
	tc := f.cliLogin(t, alice)
	if ok, _ := f.srv.OIDC.RevokeSession(tc.sessionID, rootEmail, ""); !ok {
		t.Fatal("RevokeSession")
	}
	for i := 0; i < authMaxFailures+3; i++ {
		status, body := f.get(t, nil, "/api/projects", tc.bearer())
		if status != http.StatusUnauthorized {
			t.Fatalf("request %d with an ended terminal session = %d %v, want 401", i+1, status, body)
		}
		if msg := apiErrorMessage(body); !strings.Contains(msg, "cloop login") {
			t.Fatalf("the refusal %q does not say how to get back in", msg)
		}
	}
	if status, _ := f.get(t, alice, "/api/projects", nil); status != http.StatusOK {
		t.Fatalf("the browser beside the dead terminal = %d, want 200: the dead credential was counted as a guess", status)
	}
}

// TestAuthz_ASessionEndedAfterTheGateGrantsNothing: a request whose session
// resolved at the gate and ended before authorization — expired, idled out or
// revoked in the moment between; a terminal knows its session's expiry to the
// second — must not be read as the static token and granted everything.
func TestAuthz_ASessionEndedAfterTheGateGrantsNothing(t *testing.T) {
	f := newDeviceFixture(t, nil)
	alice := f.signIn(t, aliceEmail, "sub-alice", "engineers")
	tc := f.cliLogin(t, alice)
	base, _ := url.Parse(f.ts.URL)
	var cookie *http.Cookie
	for _, c := range alice.Jar.Cookies(base) {
		if c.Name == oidcauth.SessionCookieName {
			cookie = c
		}
	}
	if cookie == nil {
		t.Fatal("the browser holds no session cookie")
	}
	// Both sessions are live at the gate, so the requests below are what
	// authorization sees of requests the gate admitted a moment earlier.
	for name, present := range map[string]func(*http.Request){
		"terminal": func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+tc.credential) },
		"browser":  func(r *http.Request) { r.AddCookie(cookie) },
	} {
		r := httptest.NewRequest(http.MethodPost, "/api/run", nil)
		present(r)
		if d := f.srv.newGrant(r).decide(authz.GlobalScope); !d.Allows(authz.PermRunStart) || d.Source == authz.SourceStaticToken {
			t.Fatalf("%s, live: %+v, want alice's own engineer grant", name, d)
		}
	}
	for _, id := range []string{tc.sessionID, oidcauth.HashSessionID(cookie.Value)} {
		if ok, err := f.srv.OIDC.RevokeSession(id, rootEmail, ""); !ok || err != nil {
			t.Fatalf("revoke %s: %v %v", id, ok, err)
		}
	}
	for name, present := range map[string]func(*http.Request){
		"terminal": func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+tc.credential) },
		"browser":  func(r *http.Request) { r.AddCookie(cookie) },
	} {
		r := httptest.NewRequest(http.MethodPost, "/api/run", nil)
		present(r)
		d := f.srv.newGrant(r).decide(authz.GlobalScope)
		if d.Source == authz.SourceStaticToken || d.Allows(authz.PermProjectRead) {
			t.Errorf("%s, ended after the gate: %+v, want nothing granted", name, d)
		}
	}
	// What the static token's admission gets is unchanged.
	r := admitStaticToken(httptest.NewRequest(http.MethodPost, "/api/run", nil))
	r.AddCookie(cookie)
	if d := f.srv.newGrant(r).decide(authz.GlobalScope); d.Source != authz.SourceStaticToken {
		t.Errorf("the static token beside an ended cookie: %+v, want the static token's grant", d)
	}
}

// apiErrorMessage reads an apierror body's message.
func apiErrorMessage(body map[string]any) string {
	if e, ok := body["error"].(map[string]any); ok {
		msg, _ := e["message"].(string)
		return msg
	}
	msg, _ := body["error"].(string)
	return msg
}

func TestProjects_IndicesAreReportedWhenAskedFor(t *testing.T) {
	f := newDeviceFixture(t, nil)
	alice := f.signIn(t, aliceEmail, "sub-alice", "engineers")
	tc := f.cliLogin(t, alice)
	_, plain := f.get(t, nil, "/api/projects", tc.bearer())
	if _, ok := plain["indices"]; ok {
		t.Error("the dashboard's payload grew an indices map it did not ask for")
	}
	_, withIdx := f.get(t, nil, "/api/projects?indices=1", tc.bearer())
	idx, ok := withIdx["indices"].(map[string]any)
	if !ok || idx[f.srv.WorkDir] != float64(0) {
		t.Fatalf("indices = %v, want the hub's own project at 0", withIdx["indices"])
	}
}

// TestDeviceEvents_AreAuditedUnderTheCode: the grant's three events land in
// the control plane's trail, filed under the code's public id with the
// terminal's details, and the CLI session's own session.created names its kind
// — through the sink `cloop ui` installs, not a test double. No code and no
// credential appears in any of them.
func TestDeviceEvents_AreAuditedUnderTheCode(t *testing.T) {
	f := newDeviceFixture(t, nil)
	alice := f.signIn(t, aliceEmail, "sub-alice", "engineers")
	tc := f.cliLogin(t, alice)
	denied := f.askForCode(t)
	if status, _ := f.post(t, alice, "/api/device/deny", map[string]string{"user_code": denied.userCode}, nil); status != http.StatusOK {
		t.Fatalf("deny = %d", status)
	}

	db, err := statedb.Open(state.DBPath(f.srv.WorkDir))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	rows := func(action string) []statedb.AuditEvent {
		t.Helper()
		got, _, err := db.ListAuditEvents(statedb.AuditFilter{EventType: action, Limit: 50})
		if err != nil {
			t.Fatal(err)
		}
		return got
	}
	payload := func(e statedb.AuditEvent) map[string]any {
		var m map[string]any
		_ = json.Unmarshal([]byte(e.Payload), &m)
		return m
	}

	issued := rows("device.code_issued")
	if len(issued) != 2 {
		t.Fatalf("%d device.code_issued rows, want 2", len(issued))
	}
	for _, e := range issued {
		p := payload(e)
		if e.EntityType != "device_authorization" || e.EntityID == "" || p["client_hostname"] != "dev-laptop" ||
			p["device_id"] != e.EntityID || e.Actor != "anonymous" {
			t.Errorf("device.code_issued %+v %v", e, p)
		}
	}
	approved := rows("device.approved")
	if len(approved) != 1 {
		t.Fatalf("%d device.approved rows, want 1", len(approved))
	}
	if p := payload(approved[0]); p["session_id"] != tc.sessionID || p["kind"] != "cli" || approved[0].Actor != aliceEmail {
		t.Errorf("device.approved %+v %v", approved[0], p)
	}
	if d := rows("device.denied"); len(d) != 1 || payload(d[0])["reason"] != "denied_at_approval_page" {
		t.Errorf("device.denied rows %+v", d)
	}
	var cli map[string]any
	for _, e := range rows("session.created") {
		if e.EntityID == tc.sessionID {
			cli = payload(e)
		}
	}
	if cli == nil || cli["kind"] != "cli" || cli["client"] != "dev-laptop" || cli["via"] != "device_grant" {
		t.Errorf("the CLI session's session.created payload %v", cli)
	}

	all, _, err := db.ListAuditEvents(statedb.AuditFilter{Limit: 1000})
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range all {
		for _, secret := range []string{tc.credential, tc.deviceCode, denied.deviceCode, strings.ReplaceAll(tc.userCode, "-", "")} {
			if strings.Contains(e.Payload+e.EntityID, secret) {
				t.Fatalf("audit row %s carries a code or the credential: %s", e.EventType, e.Payload)
			}
		}
	}
}

// TestDeviceApproval_IsSubjectToTheOriginRules: a page on another site cannot
// make a signed-in browser approve a code — the forgery guard refuses the
// state-changing request before the handler sees it (Task 20394), and the
// code is left pending.
func TestDeviceApproval_IsSubjectToTheOriginRules(t *testing.T) {
	f := newDeviceFixture(t, nil)
	alice := f.signIn(t, aliceEmail, "sub-alice", "engineers")
	tc := f.askForCode(t)
	for _, path := range []string{"/api/device/approve", "/api/device/deny"} {
		status, body := f.post(t, alice, path, map[string]string{"user_code": tc.userCode}, http.Header{
			"Origin":         {"https://evil.example"},
			"Sec-Fetch-Site": {"cross-site"},
		})
		if status != http.StatusForbidden || !strings.Contains(apiErrorMessage(body), "another") {
			t.Fatalf("a cross-site %s = %d %v, want the forgery guard's 403", path, status, body)
		}
	}
	if _, view := f.post(t, alice, "/api/device/lookup", map[string]string{"user_code": tc.userCode}, nil); view["status"] != "pending" {
		t.Fatalf("a refused cross-site request decided the code: %v", view)
	}
}
