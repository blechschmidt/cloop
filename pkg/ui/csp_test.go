package ui

// The policy the hub sends and the endpoint browsers report to (Task 20408):
// csp.go. The static gates are csp_gate_test.go; the browser regression that
// clicks everything with hostile data on the page is xss_browser_test.go.

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/internal/statedbtest"
	"github.com/blechschmidt/cloop/pkg/authz"
	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/hubmetrics"
	"github.com/blechschmidt/cloop/pkg/oidcauth"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
	"github.com/blechschmidt/cloop/pkg/telemetry"
)

// wantCSP is the policy, written out rather than built from the code that
// builds it: frameSrc is "frame-src 'self'" plus the identity provider on a
// hub with single sign-on, frameAncestors 'none' or, for the two renewal
// documents, 'self'.
func wantCSP(frameSrc, frameAncestors string) string {
	return "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; " +
		"connect-src 'self'; " + frameSrc + "; frame-ancestors " + frameAncestors +
		"; base-uri 'none'; form-action 'self'; object-src 'none'; report-uri /api/csp-report"
}

// assertCSP checks one response's policy exactly.
func assertCSP(t *testing.T, what string, h http.Header, want string) {
	t.Helper()
	if got := h.Get("Content-Security-Policy"); got != want {
		t.Errorf("%s: Content-Security-Policy\n got: %s\nwant: %s", what, got, want)
	}
	// report-to would make a browser that knows it ignore report-uri, and
	// deliver late or never (csp.go).
	if strings.Contains(h.Get("Content-Security-Policy"), "report-to") || h.Get("Reporting-Endpoints") != "" {
		t.Errorf("%s: the policy names a report-to endpoint", what)
	}
	for _, loose := range []string{"'unsafe-inline'", "'unsafe-eval'"} {
		policy := h.Get("Content-Security-Policy")
		if i := strings.Index(policy, "script-src"); i >= 0 {
			if end := strings.Index(policy[i:], ";"); end >= 0 && strings.Contains(policy[i:i+end], loose) {
				t.Errorf("%s: script-src allows %s", what, loose)
			}
		}
	}
}

// servedAssetURL finds the hashed URL a page names for one asset stem.
func servedAssetURL(t *testing.T, page, stem string) string {
	t.Helper()
	m := regexp.MustCompile(`/assets/` + regexp.QuoteMeta(stem) + `\.[0-9a-f]+\.js`).FindString(page)
	if m == "" {
		t.Fatalf("the page names no %s asset", stem)
	}
	return m
}

// TestContentSecurityPolicyOnEveryDocument: the exact policy on every kind
// of document the hub serves — the dashboard, the glasses page, the scripts
// both load, the sign-in machinery's documents and script, an error page,
// JSON — on a hub without single sign-on and on one with it, where frame-src
// names the provider and the two renewal documents may be framed by the hub.
func TestContentSecurityPolicyOnEveryDocument(t *testing.T) {
	open := wantCSP("frame-src 'self'", "'none'")

	t.Run("without single sign-on", func(t *testing.T) {
		dir := setupProjectDir(t, cloopGoal, nil)
		ts := httptest.NewServer(New(dir, 0, "").Handler())
		t.Cleanup(ts.Close)

		get := func(path string) (*http.Response, string) {
			t.Helper()
			resp, err := http.Get(ts.URL + path)
			if err != nil {
				t.Fatalf("GET %s: %v", path, err)
			}
			defer resp.Body.Close()
			b, _ := io.ReadAll(resp.Body)
			return resp, string(b)
		}
		resp, page := get("/")
		assertCSP(t, "the dashboard", resp.Header, open)
		resp, glasses := get("/glasses")
		assertCSP(t, "the glasses page", resp.Header, open)
		for _, p := range []string{servedAssetURL(t, page, "app"), servedAssetURL(t, page, "theme"),
			servedAssetURL(t, glasses, "glasses")} {
			resp, _ = get(p)
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("GET %s = %d", p, resp.StatusCode)
			}
			assertCSP(t, p, resp.Header, open)
		}
		for _, p := range []string{"/auth/renew", oidcauth.ScriptPath, "/api/me", "/favicon.ico", "/no-such-page"} {
			resp, _ = get(p)
			assertCSP(t, p, resp.Header, open)
		}
	})

	t.Run("with single sign-on", func(t *testing.T) {
		f := newRenewFixture(t, nil)
		sso := wantCSP("frame-src 'self' "+f.idp.server.URL, "'none'")
		framed := wantCSP("frame-src 'self' "+f.idp.server.URL, "'self'")

		resp, err := f.c.Get(f.ts.URL + "/")
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		assertCSP(t, "the dashboard", resp.Header, sso)

		// The renewal frame's chain ends on the callback's result document.
		resp, doc := f.renew(t, f.c)
		if renewOutcome(doc) == "" {
			t.Fatalf("the renewal chain did not end on its result document:\n%s", doc)
		}
		assertCSP(t, "the renewal result", resp.Header, framed)

		noRedirect := &http.Client{Jar: f.c.Jar, CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		}}
		for path, want := range map[string]string{
			"/auth/renew":            framed,
			"/auth/login":            sso,
			"/auth/callback?state=x": framed, // the sign-in error page
			oidcauth.ScriptPath:      sso,
		} {
			resp, err := noRedirect.Get(f.ts.URL + path)
			if err != nil {
				t.Fatal(err)
			}
			resp.Body.Close()
			assertCSP(t, path, resp.Header, want)
		}

		// The landing page a browser sees right after signing in, which the
		// hub serves instead of a redirect behind TLS (oidcauth.completeLogin).
		resp, landing := landAfterSignIn(t, f)
		if !strings.Contains(landing, `<a id="continue"`) {
			t.Fatalf("did not reach the landing page:\n%s", landing)
		}
		assertCSP(t, "the landing page", resp.Header, framed)
	})
}

// landAfterSignIn signs a fresh browser in through the fixture's provider, as
// one behind a TLS-terminating proxy on this machine, and returns the response
// the callback gives it: the landing page.
func landAfterSignIn(t *testing.T, f *renewFixture) (*http.Response, string) {
	t.Helper()
	c := jarClient(t)
	c.CheckRedirect = func(req *http.Request, _ []*http.Request) error {
		if req.URL.Host == strings.TrimPrefix(f.ts.URL, "http://") && strings.HasPrefix(req.URL.Path, "/auth/callback") {
			return http.ErrUseLastResponse
		}
		return nil
	}
	resp, err := c.Get(f.ts.URL + oidcauth.LoginPath)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	cb, err := url.Parse(resp.Header.Get("Location"))
	if err != nil || !strings.HasPrefix(cb.Path, "/auth/callback") {
		t.Fatalf("the provider did not send the browser back to the callback: %v %q", err, resp.Header.Get("Location"))
	}
	req, _ := http.NewRequest(http.MethodGet, cb.String(), nil)
	req.Header.Set("X-Forwarded-Proto", "https")
	resp, err = c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp, string(b)
}

// legacyReport is a report-uri report as Chrome and Firefox send one.
func legacyReport(doc, directive, blocked string) string {
	b, _ := json.Marshal(map[string]any{"csp-report": map[string]any{
		"document-uri": doc, "referrer": "", "violated-directive": directive,
		"effective-directive": directive, "original-policy": "script-src 'self'",
		"disposition": "enforce", "blocked-uri": blocked, "line-number": 12, "column-number": 34,
		"source-file": doc, "status-code": 200, "script-sample": "",
	}})
	return string(b)
}

// reportingAPIBatch is a Reporting API delivery of csp-violation reports.
func reportingAPIBatch(reports ...[3]string) string {
	var out []map[string]any
	for _, r := range reports {
		out = append(out, map[string]any{
			"type": "csp-violation", "age": 10, "url": r[0], "user_agent": "test",
			"body": map[string]any{
				"documentURL": r[0], "blockedURL": r[2], "effectiveDirective": r[1],
				"originalPolicy": "script-src 'self'", "sourceFile": r[0], "sample": "",
				"disposition": "enforce", "statusCode": 200, "lineNumber": 1, "columnNumber": 2,
			},
		})
	}
	// Other report types share the endpoint in principle, and are skipped.
	out = append(out, map[string]any{"type": "deprecation", "url": "http://hub/", "body": map[string]any{}})
	b, _ := json.Marshal(out)
	return string(b)
}

// postReport sends one report through the full handler chain, as a browser
// on the hub's own page does.
func postReport(t *testing.T, ts *httptest.Server, ctype, body string, header map[string]string) *http.Response {
	t.Helper()
	return postReportWith(t, http.DefaultClient, ts, ctype, body, header)
}

// postReportWith is postReport from client c — one holding a session cookie,
// as a signed-in browser's report does.
func postReportWith(t *testing.T, c *http.Client, ts *httptest.Server, ctype, body string, header map[string]string) *http.Response {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, ts.URL+cspReportPath, strings.NewReader(body))
	req.Header.Set("Content-Type", ctype)
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	for k, v := range header {
		req.Header.Set(k, v)
	}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	return resp
}

func cspCount(t *testing.T, directive, document string) float64 {
	t.Helper()
	return counterValue(t, hubmetrics.Default.Gather(), "cloop_csp_violations_total",
		`directive="`+directive+`",document="`+document+`"`)
}

// TestCSPReportsAreCountedInBothFormats: a report-uri report and a Reporting
// API batch each count, by directive and by document, and nothing a sender
// writes becomes a label value of its own.
func TestCSPReportsAreCountedInBothFormats(t *testing.T) {
	dir := setupProjectDir(t, cloopGoal, nil)
	ts := httptest.NewServer(New(dir, 0, "").Handler())
	t.Cleanup(ts.Close)

	attrDash := cspCount(t, "script-src-attr", "dashboard")
	elemGlasses := cspCount(t, "script-src-elem", "glasses")
	otherOther := cspCount(t, "other", "other")
	baseSignIn := cspCount(t, "base-uri", "sign-in")

	if resp := postReport(t, ts, "application/csp-report",
		legacyReport(ts.URL+"/?project_idx=2", "script-src-attr", "inline"), nil); resp.StatusCode != http.StatusNoContent {
		t.Fatalf("report-uri report = %d, want 204", resp.StatusCode)
	}
	if resp := postReport(t, ts, "application/reports+json", reportingAPIBatch(
		[3]string{ts.URL + "/glasses", "script-src-elem", "inline"},
		[3]string{ts.URL + "/somewhere/else", "made-up-directive", "https://evil.example/x.js"},
		[3]string{ts.URL + "/auth/sign-in.js", "base-uri", "https://evil.example/"},
	), nil); resp.StatusCode != http.StatusNoContent {
		t.Fatalf("Reporting API batch = %d, want 204", resp.StatusCode)
	}

	for _, c := range []struct {
		directive, document string
		before              float64
	}{
		{"script-src-attr", "dashboard", attrDash},
		{"script-src-elem", "glasses", elemGlasses},
		{"other", "other", otherOther},
		{"base-uri", "sign-in", baseSignIn},
	} {
		if got := cspCount(t, c.directive, c.document); got != c.before+1 {
			t.Errorf("cloop_csp_violations_total{%s,%s} moved by %v, want 1", c.directive, c.document, got-c.before)
		}
	}
	if strings.Contains(hubmetrics.Default.Gather(), "made-up-directive") ||
		strings.Contains(hubmetrics.Default.Gather(), "evil.example") {
		t.Error("a value the sender wrote became a label")
	}
}

// TestCSPReportNeedsNoCredential: on a hub with a static token, a report is
// taken without it — the glasses page and the sign-in documents have nothing
// a browser would attach — while the route next to it still is not.
func TestCSPReportNeedsNoCredential(t *testing.T) {
	dir := setupProjectDir(t, cloopGoal, nil)
	ts := httptest.NewServer(New(dir, 0, "s3cret-token").Handler())
	t.Cleanup(ts.Close)

	if resp := postReport(t, ts, "application/csp-report",
		legacyReport(ts.URL+"/glasses", "script-src-attr", "inline"), nil); resp.StatusCode != http.StatusNoContent {
		t.Fatalf("an unauthenticated report = %d, want 204", resp.StatusCode)
	}
	resp, err := http.Get(ts.URL + cspReportPath)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusNoContent {
		t.Errorf("GET %s = %d: only POST is served before authentication", cspReportPath, resp.StatusCode)
	}
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/client-error", strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("the exemption is wider than the report route: POST /api/client-error = %d, want 401", resp.StatusCode)
	}

	// And the dashboard's own script loads without the token, which it did
	// not before (a token hub served the page and refused its script).
	page, _ := http.Get(ts.URL + "/")
	body, _ := io.ReadAll(page.Body)
	page.Body.Close()
	asset, err := http.Get(ts.URL + servedAssetURL(t, string(body), "app"))
	if err != nil {
		t.Fatal(err)
	}
	asset.Body.Close()
	if asset.StatusCode != http.StatusOK {
		t.Errorf("GET the dashboard's script on a token hub = %d, want 200", asset.StatusCode)
	}
}

// TestCSPReportRefusesWhatABrowserWouldNotSend: the size cap, the media type,
// a page elsewhere, and a body that is no report.
func TestCSPReportRefusesWhatABrowserWouldNotSend(t *testing.T) {
	dir := setupProjectDir(t, cloopGoal, nil)
	ts := httptest.NewServer(New(dir, 0, "").Handler())
	t.Cleanup(ts.Close)

	huge := `{"csp-report":{"document-uri":"` + strings.Repeat("a", int(cspReportMaxBytes)) + `"}}`
	for _, c := range []struct {
		name, ctype, body string
		header            map[string]string
		want              int
	}{
		{"over the size cap", "application/csp-report", huge, nil, http.StatusRequestEntityTooLarge},
		{"a form's media type", "text/plain", legacyReport("/", "script-src", "inline"), nil, http.StatusUnsupportedMediaType},
		{"a page on another site", "application/csp-report", legacyReport("/", "script-src", "inline"),
			map[string]string{"Sec-Fetch-Site": "cross-site", "Origin": "https://evil.example"}, http.StatusForbidden},
		{"not a report", "application/csp-report", `[1, 2`, nil, http.StatusBadRequest},
	} {
		t.Run(c.name, func(t *testing.T) {
			if got := postReport(t, ts, c.ctype, c.body, c.header).StatusCode; got != c.want {
				t.Errorf("status = %d, want %d", got, c.want)
			}
		})
	}
}

// cspTelemetryServer is a hub whose telemetry policy is yaml, under the
// overlay-free config the telemetry tests use.
func cspTelemetryServer(t *testing.T, yaml string) (*Server, *httptest.Server) {
	t.Helper()
	dir := statedbtest.Dir(t)
	if _, err := state.Init(dir, "csp report test", 1); err != nil {
		t.Fatalf("init project: %v", err)
	}
	writeTelemetryConfig(t, dir, true)
	if yaml != "" {
		writeRawConfig(t, dir, yaml)
	}
	srv := New(dir, 0, "")
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return srv, ts
}

// cspRows reads the telemetry rows the endpoint recorded.
func cspRows(t *testing.T, srv *Server) []telemetry.Event {
	t.Helper()
	db, err := srv.controlPlaneDB()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	evs, _, err := db.QueryTelemetry(statedb.TelemetryFilter{Kind: string(telemetry.KindCSP), Limit: 500})
	if err != nil {
		t.Fatal(err)
	}
	return evs
}

// TestCSPReportRecordsWithinItsBudget: where telemetry is on, each report is a
// row — scrubbed like any other — until the burst is spent, while the counter
// keeps every one. On a hub that asks for no credential every report draws on
// the signed-in budget.
func TestCSPReportRecordsWithinItsBudget(t *testing.T) {
	srv, ts := cspTelemetryServer(t, "")
	logged := &captureLogger{}
	srv.Log = logged
	// A stopped clock: under -race on a CI runner forty reports took 2.8 s,
	// long enough for the budget to earn a token back mid-test.
	at := time.Now()
	srv.cspClock = func() time.Time { return at }
	before := cspCount(t, "script-src-attr", "dashboard")

	const sent = cspSignedBurst + 10
	for i := 0; i < sent; i++ {
		// Credentials after an '&', where a JSON encoder's \u0026 would hide
		// the key from the scrubber: a code only its key gives away, and a
		// token the credential registry knows on sight.
		doc := ts.URL + "/?n=" + strconv.Itoa(i) + "&code=oauth-code-leaked&token=cloop_pat_leaked"
		if resp := postReport(t, ts, "application/csp-report", legacyReport(doc, "script-src-attr", "inline"), nil); resp.StatusCode != http.StatusNoContent {
			t.Fatalf("report %d = %d", i, resp.StatusCode)
		}
	}
	if got := cspCount(t, "script-src-attr", "dashboard") - before; got != sent {
		t.Errorf("counted %v of %d reports; the counter is not budgeted", got, sent)
	}
	rows := cspRows(t, srv)
	if len(rows) != cspSignedBurst {
		t.Fatalf("recorded %d rows for %d reports, want the burst of %d", len(rows), sent, cspSignedBurst)
	}
	r := rows[0]
	if r.Source != telemetry.SourceDashboard || r.View != "dashboard" || !strings.Contains(r.Message, "script-src-attr blocked inline") {
		t.Errorf("row = %+v", r)
	}
	var detail map[string]any
	if err := json.Unmarshal([]byte(r.Detail), &detail); err != nil || detail["directive"] != "script-src-attr" {
		t.Errorf("detail = %s (%v)", r.Detail, err)
	}
	if !strings.Contains(r.Detail, "&code=[redacted]") {
		t.Errorf("detail = %s, want the source file's code redacted in place", r.Detail)
	}
	for _, r := range rows {
		if b, _ := json.Marshal(r); strings.Contains(string(b), "leaked") {
			t.Fatalf("a credential in the report was stored: %s", b)
		}
	}
	// The log line is budgeted with the row, and scrubbed like it.
	logged.mu.Lock()
	defer logged.mu.Unlock()
	lines := 0
	for _, e := range logged.entries {
		if e.Event != "csp_violation" {
			continue
		}
		lines++
		if b, _ := json.Marshal(e); strings.Contains(string(b), "leaked") {
			t.Errorf("a credential in the report was logged: %s", b)
		}
	}
	if lines != cspSignedBurst {
		t.Errorf("logged %d violations for %d reports, want the burst of %d", lines, sent, cspSignedBurst)
	}
}

// cspSignOnServer is cspTelemetryServer with single sign-on and roles, and a
// client signed in through it.
func cspSignOnServer(t *testing.T) (*Server, *httptest.Server, *http.Client) {
	t.Helper()
	srv, ts := cspTelemetryServer(t, "")
	idp := newUIFakeIdP(t)
	idp.groups = []string{"owners"}
	auth, err := oidcauth.New(oidcauth.Config{
		Enabled:         true,
		Issuer:          idp.server.URL,
		ClientID:        "cloop-dashboard",
		RedirectURL:     ts.URL + "/auth/callback",
		RefreshInterval: -1,
	})
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
	return srv, ts, c
}

// TestCSPReportBudgetsAnonymousSendersApart: on a hub with sign-on, a report
// without a session draws on the small anonymous budget, so a flood of them
// cannot fill the log, turn the telemetry table over, or crowd out a
// signed-in user's report — which is recorded under that user, as the
// anonymous ones are under nobody. A grant on this pre-auth route would have
// named them the static token.
func TestCSPReportBudgetsAnonymousSendersApart(t *testing.T) {
	srv, ts, signedIn := cspSignOnServer(t)
	logged := &captureLogger{}
	srv.Log = logged
	at := time.Now()
	srv.cspClock = func() time.Time { return at }
	before := cspCount(t, "script-src-attr", "glasses")

	const flood = cspAnonBurst + 15
	for i := 0; i < flood; i++ {
		postReport(t, ts, "application/csp-report", legacyReport(ts.URL+"/glasses", "script-src-attr", "inline"), nil)
	}
	if got := cspCount(t, "script-src-attr", "glasses") - before; got != flood {
		t.Errorf("counted %v of %d anonymous reports; the counter is not budgeted", got, flood)
	}
	rows := cspRows(t, srv)
	if len(rows) != cspAnonBurst {
		t.Fatalf("recorded %d rows for %d anonymous reports, want the anonymous burst of %d", len(rows), flood, cspAnonBurst)
	}
	for _, r := range rows {
		if r.Actor != "" {
			t.Fatalf("an anonymous report was recorded under %q", r.Actor)
		}
	}

	if resp := postReportWith(t, signedIn, ts, "application/csp-report",
		legacyReport(ts.URL+"/", "script-src-attr", "inline"), nil); resp.StatusCode != http.StatusNoContent {
		t.Fatalf("signed-in report = %d", resp.StatusCode)
	}
	rows = cspRows(t, srv)
	if len(rows) != cspAnonBurst+1 {
		t.Fatalf("the anonymous flood crowded out a signed-in user's report: %d rows", len(rows))
	}
	var mine *telemetry.Event
	for i := range rows {
		if rows[i].View == "dashboard" {
			mine = &rows[i]
		}
	}
	if mine == nil || mine.Actor == "" || mine.Actor == "static-token" {
		t.Fatalf("the signed-in report's row = %+v, want it under the signed-in user", mine)
	}

	logged.mu.Lock()
	defer logged.mu.Unlock()
	var actors []string
	for _, e := range logged.entries {
		if e.Event == "csp_violation" {
			actors = append(actors, fmt.Sprint(e.Data["actor"]))
		}
	}
	if len(actors) != cspAnonBurst+1 || actors[len(actors)-1] != mine.Actor {
		t.Errorf("logged actors %q, want %d anonymous and then %q", actors, cspAnonBurst, mine.Actor)
	}
}

// TestCSPReportFollowsTheTelemetryPolicy: a report becomes a row only for a
// front end whose trail is collected (Task 20311), and never with telemetry
// off; it is counted either way.
func TestCSPReportFollowsTheTelemetryPolicy(t *testing.T) {
	srv, ts := cspTelemetryServer(t, "ui:\n  telemetry:\n    enabled: true\n    sources: [glasses]\n")
	postReport(t, ts, "application/reports+json", reportingAPIBatch(
		[3]string{ts.URL + "/", "script-src-attr", "inline"},
		[3]string{ts.URL + "/glasses", "script-src-attr", "inline"},
	), nil)
	rows := cspRows(t, srv)
	if len(rows) != 1 || rows[0].Source != telemetry.SourceGlasses {
		t.Fatalf("rows = %+v, want the glasses report alone", rows)
	}

	off, offTS := cspTelemetryServer(t, "ui:\n  telemetry:\n    enabled: false\n")
	before := cspCount(t, "script-src-attr", "glasses")
	postReport(t, offTS, "application/csp-report", legacyReport(offTS.URL+"/glasses", "script-src-attr", "inline"), nil)
	if rows := cspRows(t, off); len(rows) != 0 {
		t.Errorf("telemetry is off, and %d report(s) were recorded", len(rows))
	}
	if cspCount(t, "script-src-attr", "glasses") != before+1 {
		t.Error("with telemetry off the report was not counted")
	}
}

// TestCSPRecordBudgetRefills: each budget comes back at its own rate, and
// spending one leaves the other alone.
func TestCSPRecordBudgetRefills(t *testing.T) {
	var b cspBudgets
	now := time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC)
	for _, c := range []struct {
		signed           bool
		burst, perMinute int
	}{{false, cspAnonBurst, cspAnonPerMinute}, {true, cspSignedBurst, cspSignedPerMinute}} {
		for i := 0; i < c.burst; i++ {
			if !b.take(c.signed, now) {
				t.Fatalf("signed=%v: take %d refused inside the burst", c.signed, i)
			}
		}
		if b.take(c.signed, now) {
			t.Fatalf("signed=%v: take past the burst admitted", c.signed)
		}
		if !b.take(c.signed, now.Add(time.Minute/time.Duration(c.perMinute))) {
			t.Fatalf("signed=%v: no token back after one refill interval", c.signed)
		}
	}
}

// writeRawConfig replaces the project's config with yaml.
func writeRawConfig(t *testing.T, dir, yaml string) {
	t.Helper()
	if err := os.WriteFile(config.ConfigPath(dir), []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
}
