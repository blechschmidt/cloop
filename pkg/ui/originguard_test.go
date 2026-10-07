package ui

// Tests for the origin guards (Task 20394): a web page must not be able to
// drive the hub.
//
// The sweep is derived from routeTable(), so a route added later is covered
// without anybody remembering to add it here. Refusals are driven through the
// real handler chain — a refused request never reaches a handler, so there is
// nothing for them to set off; admissions are driven through the guards in
// front of a stub, because admitting every state-changing route for real
// would start runs, delete projects and spawn logins.

import (
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/auditaction"
	"github.com/blechschmidt/cloop/pkg/hubmetrics"
	"github.com/blechschmidt/cloop/pkg/oidcauth"
	"github.com/blechschmidt/cloop/pkg/sameorigin"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// routeCall is one state-changing verb on one route, with a path the route's
// pattern matches.
type routeCall struct {
	pattern, method, path string
}

var patternWildcard = regexp.MustCompile(`\{[^}]+\}`)

// unsafeRouteCalls lists every state-changing (method, path) the route table
// serves.
func unsafeRouteCalls(t *testing.T, s *Server) []routeCall {
	t.Helper()
	var out []routeCall
	for _, rs := range s.routeTable() {
		_, path, _ := splitPattern(rs.Pattern)
		path = patternWildcard.ReplaceAllString(path, "1")
		if strings.HasSuffix(path, "/") && path != "/" {
			path += "x"
		}
		for _, m := range rs.methods() {
			if sameorigin.Unsafe(m) {
				out = append(out, routeCall{rs.Pattern, m, path})
			}
		}
	}
	if len(out) < 80 {
		t.Fatalf("found %d state-changing routes; the table walk broke", len(out))
	}
	return out
}

// apiErrorCode is the pkg/apierror code a response carries, "" for none.
func apiErrorCode(body []byte) string {
	var env struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	_ = json.Unmarshal(body, &env)
	return env.Error.Code
}

// guardRefusal reports whether a response is one of the guards' refusals.
func guardRefusal(body []byte) bool {
	switch apiErrorCode(body) {
	case "CROSS_ORIGIN", "UNSUPPORTED_MEDIA_TYPE", "MISDIRECTED_REQUEST":
		return true
	}
	return false
}

// newGuardedHub serves a hub with no sign-in, or with a static token, through
// its whole handler chain; configure, when given, runs before it serves. The
// rate limiter is lifted: the sweep sends a few hundred requests from one
// address.
func newGuardedHub(t *testing.T, token string, configure ...func(*Server)) (*Server, *httptest.Server) {
	t.Helper()
	dir := setupProjectDir(t, cloopGoal, nil)
	srv := New(dir, 0, token)
	srv.RPS, srv.Burst = 1e6, 1_000_000
	for _, c := range configure {
		c(srv)
	}
	ts := newTestServerFor(t, srv)
	return srv, ts
}

// isCIRelay reports the Anthropic relay's subtree, which passes bodies through
// to that API unread and so takes whatever media type it does.
func isCIRelay(path string) bool { return strings.HasPrefix(path, ciMountPath+"/") }

// TestEveryUnsafeRouteRefusesAPageElsewhere is the sweep: every state-changing
// route of the table refuses a request carrying the session cookie from a page
// on another site, one from another origin of the same site — another port of
// the hub's host, which SameSite does not tell apart — and a text/plain body
// such as a form on any page can send. On a hub with no sign-in, which has no
// cookie to withhold, and on one with a token alike.
func TestEveryUnsafeRouteRefusesAPageElsewhere(t *testing.T) {
	for _, token := range []string{"", "t0ken-for-the-sweep"} {
		srv, ts := newGuardedHub(t, token)
		own := ts.URL // http://127.0.0.1:PORT
		sameSite := "http://127.0.0.1:1"
		cases := []struct {
			name     string
			header   map[string]string
			ct, body string
			want     string // the apierror code the guard answers with
		}{
			{"cross-site", map[string]string{"Origin": "https://evil.example", "Sec-Fetch-Site": "cross-site"},
				"application/json", `{}`, "CROSS_ORIGIN"},
			{"same-site, other origin", map[string]string{"Origin": sameSite, "Sec-Fetch-Site": "same-site"},
				"application/json", `{}`, "CROSS_ORIGIN"},
			{"browser without Sec-Fetch-Site, other origin", map[string]string{"Origin": sameSite},
				"application/json", `{}`, "CROSS_ORIGIN"},
			// The classic form: enctype=text/plain, from a browser too old
			// to say where it came from. Only the media type stops it.
			{"text/plain form body", nil, "text/plain", `{"title":"x","pad":"=y"}`, "UNSUPPORTED_MEDIA_TYPE"},
			{"urlencoded form body", map[string]string{"Origin": own}, "application/x-www-form-urlencoded", `a=b`, "UNSUPPORTED_MEDIA_TYPE"},
		}
		for _, call := range unsafeRouteCalls(t, srv) {
			for _, c := range cases {
				if c.want == "UNSUPPORTED_MEDIA_TYPE" && isCIRelay(call.path) {
					// The relay's body is the Anthropic API's, and its
					// credential is a token no browser holds.
					continue
				}
				req, err := http.NewRequest(call.method, ts.URL+call.path+"?project_idx=0", strings.NewReader(c.body))
				if err != nil {
					t.Fatal(err)
				}
				req.Header.Set("Content-Type", c.ct)
				req.AddCookie(&http.Cookie{Name: oidcauth.SessionCookieName, Value: "a-session-the-page-cannot-read"})
				for k, v := range c.header {
					req.Header.Set(k, v)
				}
				resp, err := http.DefaultClient.Do(req)
				if err != nil {
					t.Fatalf("%s %s: %v", call.method, call.path, err)
				}
				body, _ := io.ReadAll(resp.Body)
				resp.Body.Close()
				if got := apiErrorCode(body); got != c.want {
					t.Errorf("token=%v %s %s (%s), %s: answered %d %q (%s), want the guard's %s",
						token != "", call.method, call.path, call.pattern, c.name, resp.StatusCode, got,
						strings.TrimSpace(string(body)), c.want)
				}
			}
		}
	}
}

// TestUnsafeRoutesAdmitTheHubsOwnPagesAndBearerTokens is the other half of the
// sweep: the same routes, through the same guards, admit what the dashboard,
// the glasses page and every non-browser client send.
func TestUnsafeRoutesAdmitTheHubsOwnPagesAndBearerTokens(t *testing.T) {
	srv := &Server{WorkDir: t.TempDir(), ExternalURL: "https://hub.example.com"}
	reached := 0
	guarded := srv.hostGuard(srv.forgeryGuard(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached++
		w.WriteHeader(http.StatusNoContent)
	})))
	cases := []struct {
		name   string
		header map[string]string
		ct     string
	}{
		{"same-origin fetch", map[string]string{"Sec-Fetch-Site": "same-origin", "Origin": "http://127.0.0.1:8081"}, "application/json"},
		{"same-origin, no body type", map[string]string{"Sec-Fetch-Site": "same-origin"}, ""},
		{"browser without Sec-Fetch-Site, own origin", map[string]string{"Origin": "http://127.0.0.1:8081"}, "application/json; charset=utf-8"},
		{"browser without Sec-Fetch-Site, external URL", map[string]string{"Origin": "https://hub.example.com"}, "application/json"},
		{"bearer from anywhere", map[string]string{"Authorization": "Bearer cloop_pat_x", "Sec-Fetch-Site": "cross-site", "Origin": "https://ci.example"}, "application/json"},
		{"CLI", nil, "application/json"},
	}
	for _, call := range unsafeRouteCalls(t, srv) {
		for _, c := range cases {
			r := httptest.NewRequest(call.method, "http://127.0.0.1:8081"+call.path, strings.NewReader(`{}`))
			r.RemoteAddr = "127.0.0.1:50000"
			if c.ct != "" {
				r.Header.Set("Content-Type", c.ct)
			}
			for k, v := range c.header {
				r.Header.Set(k, v)
			}
			before := reached
			rec := httptest.NewRecorder()
			guarded.ServeHTTP(rec, r)
			if reached != before+1 {
				t.Errorf("%s %s, %s: refused (%d %s)", call.method, call.path, c.name, rec.Code, rec.Body.String())
			}
		}
	}

	// The upload routes take their recording as multipart form data; no
	// other route does.
	for _, call := range unsafeRouteCalls(t, srv) {
		r := httptest.NewRequest(call.method, "http://127.0.0.1:8081"+call.path, strings.NewReader("--b--"))
		r.RemoteAddr = "127.0.0.1:50000"
		r.Header.Set("Sec-Fetch-Site", "same-origin")
		r.Header.Set("Content-Type", "multipart/form-data; boundary=b")
		before := reached
		guarded.ServeHTTP(httptest.NewRecorder(), r)
		if got, want := reached == before+1, multipartRoutes[call.path] || isCIRelay(call.path); got != want {
			t.Errorf("%s %s with a multipart body: admitted=%v, want %v", call.method, call.path, got, want)
		}
	}
}

// TestMultipartRoutesAreRoutes keeps the upload list honest: an entry that is
// not a route admits multipart bodies for nothing, and a typo would leave a
// real upload route refusing its own recordings.
func TestMultipartRoutesAreRoutes(t *testing.T) {
	served := map[string]bool{}
	for _, call := range unsafeRouteCalls(t, &Server{}) {
		served[call.path] = true
	}
	for path := range multipartRoutes {
		if !served[path] {
			t.Errorf("multipartRoutes lists %s, which no state-changing route serves", path)
		}
	}
}

// TestCrossSiteWritableRoutesAreJustified: a route a page on another site may
// drive has to be a real route and say why. There are none today (see the
// variable's comment); this keeps an addition from being casual.
func TestCrossSiteWritableRoutesAreJustified(t *testing.T) {
	served := map[string]bool{}
	for _, call := range unsafeRouteCalls(t, &Server{}) {
		served[call.path] = true
	}
	for path, why := range crossSiteWritable {
		if !served[path] {
			t.Errorf("crossSiteWritable lists %s, which no state-changing route serves", path)
		}
		if len(strings.TrimSpace(why)) < 40 {
			t.Errorf("crossSiteWritable[%s] does not say why a page anywhere may drive it", path)
		}
	}
	// The OIDC callback is the one route that would need an entry, under
	// response_mode=form_post. The hub's is a GET.
	srv := &Server{}
	for _, rs := range srv.routeTable() {
		if _, p, _ := splitPattern(rs.Pattern); p == srv.oidcCallbackPath() {
			for _, m := range rs.methods() {
				if sameorigin.Unsafe(m) {
					t.Errorf("the OIDC callback accepts %s; a form_post callback needs a crossSiteWritable entry", m)
				}
			}
		}
	}
}

// TestDNSRebindingIsRefusedOnAnOpenHub: a page on attacker.example that
// re-points its own name at 127.0.0.1 is same-origin with a hub there. The hub
// refuses the name, for reads as well as writes; loopback names and addresses
// still work; a hub with a token does not care, because the rebound name
// carries none of its credentials.
func TestDNSRebindingIsRefusedOnAnOpenHub(t *testing.T) {
	_, open := newGuardedHub(t, "")
	_, port, _ := strings.Cut(strings.TrimPrefix(open.URL, "http://"), ":")
	get := func(ts *httptest.Server, host, path string, hdr map[string]string) (int, []byte) {
		t.Helper()
		req, _ := http.NewRequest(http.MethodGet, ts.URL+path, nil)
		req.Host = host
		for k, v := range hdr {
			req.Header.Set(k, v)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, body
	}

	for _, host := range []string{"attacker.example:" + port, "127.0.0.1.nip.io:" + port, "localhost.attacker.example"} {
		code, body := get(open, host, "/api/state", map[string]string{"Sec-Fetch-Site": "same-origin"})
		if code != http.StatusMisdirectedRequest || apiErrorCode(body) != "MISDIRECTED_REQUEST" {
			t.Errorf("open hub, Host %s: GET /api/state = %d %s, want 421", host, code, body)
		}
		if !strings.Contains(string(body), "ui.allowed_hosts") {
			t.Errorf("the refusal does not name the setting: %s", body)
		}
	}
	for _, host := range []string{"127.0.0.1:" + port, "localhost:" + port, "[::1]:" + port, "hub.localhost:" + port} {
		if code, body := get(open, host, "/api/state", nil); code != http.StatusOK {
			t.Errorf("open hub, Host %s: GET /api/state = %d %s, want 200", host, code, body)
		}
	}
	// The probes answer whatever the name: a load balancer asks by address,
	// and they carry nothing worth rebinding for.
	if code, _ := get(open, "attacker.example:"+port, "/healthz", nil); code != http.StatusOK {
		t.Errorf("/healthz behind a foreign Host = %d, want 200", code)
	}

	// A name the operator gave it.
	_, named := newGuardedHub(t, "", func(s *Server) {
		s.AllowedHosts = []string{"devbox.lan"}
		s.ExternalURL = "http://cloop.internal:8080"
	})
	for _, host := range []string{"devbox.lan:" + port, "cloop.internal:8080"} {
		if code, body := get(named, host, "/api/state", nil); code != http.StatusOK {
			t.Errorf("Host %s from ui.allowed_hosts / ui.external_url = %d %s, want 200", host, code, body)
		}
	}

	_, tokened := newGuardedHub(t, "rebinding-cannot-carry-this")
	if code, body := get(tokened, "attacker.example:"+port, "/api/state", nil); code == http.StatusMisdirectedRequest {
		t.Errorf("a hub with a token refused a Host: %s", body)
	}
}

// TestForwardedHeadersFromAnUntrustedPeerAreIgnored: the origin a request is
// judged against is built from the scheme and host the browser used, which a
// proxy reports in X-Forwarded-Proto and X-Forwarded-Host. Believed from a
// peer that is no proxy, they would let a client choose the origin it is
// compared with.
func TestForwardedHeadersFromAnUntrustedPeerAreIgnored(t *testing.T) {
	srv := &Server{TrustedProxies: sameorigin.MustParseProxies("10.1.0.0/16")}
	guarded := srv.forgeryGuard(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	for _, tc := range []struct {
		remote string
		want   int
	}{
		{"127.0.0.1:5000", http.StatusNoContent},   // a proxy on this machine
		{"10.1.2.3:5000", http.StatusNoContent},    // one in ui.trusted_proxies
		{"203.0.113.9:5000", http.StatusForbidden}, // anybody else
	} {
		// What an old browser without Sec-Fetch-Site sends from the page
		// https://hub.example.com, through a TLS-terminating proxy.
		r := httptest.NewRequest(http.MethodPost, "http://cloop-hub:8080/api/task/add", strings.NewReader(`{}`))
		r.RemoteAddr = tc.remote
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Origin", "https://hub.example.com")
		r.Header.Set("X-Forwarded-Proto", "https")
		r.Header.Set("X-Forwarded-Host", "hub.example.com")
		rec := httptest.NewRecorder()
		guarded.ServeHTTP(rec, r)
		if rec.Code != tc.want {
			t.Errorf("X-Forwarded-* from %s: %d %s, want %d", tc.remote, rec.Code, rec.Body.String(), tc.want)
		}
	}

	// And the client address the lockout counts is not the client's to name.
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "203.0.113.9:5000"
	r.Header.Set("X-Forwarded-For", "198.51.100.1")
	if got := srv.clientIP(r); got != "203.0.113.9" {
		t.Errorf("clientIP believed an untrusted X-Forwarded-For: %s", got)
	}
	r.RemoteAddr = "127.0.0.1:5000"
	r.Header.Set("X-Forwarded-For", "6.6.6.6, 198.51.100.1")
	if got := srv.clientIP(r); got != "198.51.100.1" {
		t.Errorf("clientIP behind a loopback proxy = %s, want the address the proxy appended", got)
	}
}

// TestTheHubGrantsNoCrossOriginRead: the hub sends no CORS headers to anyone,
// so a page elsewhere can neither read an answer nor pass a preflight — which
// is also what makes a bearer token proof that no page elsewhere sent it. The
// loopback Origins listed here were answered with Access-Control-Allow-Origin
// until Task 20394, which let any page on localhost read an open hub.
func TestTheHubGrantsNoCrossOriginRead(t *testing.T) {
	_, ts := newGuardedHub(t, "")
	for _, origin := range []string{"http://localhost:3000", "http://127.0.0.1:9999", "http://[::1]:1", "https://evil.example"} {
		for _, method := range []string{http.MethodGet, http.MethodOptions} {
			req, _ := http.NewRequest(method, ts.URL+"/api/state", nil)
			req.Header.Set("Origin", origin)
			req.Header.Set("Access-Control-Request-Method", "POST")
			req.Header.Set("Access-Control-Request-Headers", "authorization, content-type")
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			resp.Body.Close()
			for _, h := range []string{"Access-Control-Allow-Origin", "Access-Control-Allow-Headers",
				"Access-Control-Allow-Methods", "Access-Control-Allow-Credentials"} {
				if v := resp.Header.Get(h); v != "" {
					t.Errorf("%s %s from %s: %s: %s", method, "/api/state", origin, h, v)
				}
			}
		}
	}
}

// TestRefusalsAreCountedAndAudited: every refusal increments the metric, and
// lands in the hub's own audit chain as the registered action — with the page
// that asked, and whether the browser carried a session cookie.
func TestRefusalsAreCountedAndAudited(t *testing.T) {
	srv, ts := newGuardedHub(t, "")
	before := hubmetrics.Default.Gather()
	baseCross := counterValue(t, before, "cloop_cross_origin_refusals_total", `reason="cross_site"`)
	baseHost := counterValue(t, before, "cloop_cross_origin_refusals_total", `reason="unknown_host"`)

	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/task/add", strings.NewReader(`{"title":"pwned"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "https://evil.example")
	req.Header.Set("Sec-Fetch-Site", "cross-site")
	req.AddCookie(&http.Cookie{Name: oidcauth.SessionCookieName, Value: "x"})
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden || !strings.Contains(string(body), "ui.allowed_origins") {
		t.Fatalf("refusal = %d %s, want 403 naming ui.allowed_origins", resp.StatusCode, body)
	}

	req, _ = http.NewRequest(http.MethodGet, ts.URL+"/api/state", nil)
	req.Host = "attacker.example"
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	after := hubmetrics.Default.Gather()
	if got := counterValue(t, after, "cloop_cross_origin_refusals_total", `reason="cross_site"`); got != baseCross+1 {
		t.Errorf("cross_site refusals went from %v to %v, want +1", baseCross, got)
	}
	if got := counterValue(t, after, "cloop_cross_origin_refusals_total", `reason="unknown_host"`); got != baseHost+1 {
		t.Errorf("unknown_host refusals went from %v to %v, want +1", baseHost, got)
	}

	db, err := statedb.Open(state.DBPath(srv.WorkDir))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for action, check := range map[auditaction.Action]func(map[string]any){
		auditaction.ActionRequestOriginRefused: func(p map[string]any) {
			if p["origin"] != "https://evil.example" || p["sec_fetch_site"] != "cross-site" || p["session"] != true ||
				p["path"] != "/api/task/add" || p["reason"] != "cross_site" || p["open_hub"] != true {
				t.Errorf("origin refusal payload = %v", p)
			}
		},
		auditaction.ActionRequestHostRefused: func(p map[string]any) {
			if p["host"] != "attacker.example" || p["reason"] != "unknown_host" {
				t.Errorf("host refusal payload = %v", p)
			}
		},
	} {
		rows, _, err := db.ListAuditEvents(statedb.AuditFilter{EventType: string(action)})
		if err != nil {
			t.Fatal(err)
		}
		if len(rows) != 1 {
			t.Fatalf("%s: %d rows, want 1", action, len(rows))
		}
		if rows[0].EntityType != "request" {
			t.Errorf("%s: entity %q", action, rows[0].EntityType)
		}
		var p map[string]any
		if err := json.Unmarshal([]byte(rows[0].Payload), &p); err != nil {
			t.Fatal(err)
		}
		check(p)
	}

	// Nothing was written to the plan.
	ps, err := state.Load(srv.WorkDir)
	if err != nil {
		t.Fatal(err)
	}
	if ps.Plan != nil {
		for _, task := range ps.Plan.Tasks {
			if task.Title == "pwned" {
				t.Fatal("a refused request added a task")
			}
		}
	}
}

// TestRefusalAuditIsRateLimited: a page can make a browser send requests in a
// loop; the audit trail takes at most refusalAuditPerMinute of them a minute,
// and the next row says how many it did not take.
func TestRefusalAuditIsRateLimited(t *testing.T) {
	var l refusalLog
	now := time.Unix(1_700_000_000, 0)
	for i := 0; i < refusalAuditPerMinute; i++ {
		if ok, _ := l.admit(now); !ok {
			t.Fatalf("refusal %d of the first minute was not written", i+1)
		}
	}
	for i := 0; i < 5; i++ {
		if ok, _ := l.admit(now.Add(time.Second)); ok {
			t.Fatal("a refusal past the minute's budget was written")
		}
	}
	ok, suppressed := l.admit(now.Add(time.Minute))
	if !ok || suppressed != 5 {
		t.Errorf("the next minute's first row: written=%v suppressed=%d, want true and 5", ok, suppressed)
	}
}

// TestRefusedUpgradesAreCountedToo: a cross-site WebSocket is the same attack
// as a forged POST, and is recorded the same way.
func TestRefusedUpgradesAreCountedToo(t *testing.T) {
	_, ts := newGuardedHub(t, "")
	before := counterValue(t, hubmetrics.Default.Gather(), "cloop_cross_origin_refusals_total", `reason="foreign_origin"`)
	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/ws", nil)
	req.Header.Set("Origin", "http://localhost:3000")
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Sec-WebSocket-Version", "13")
	req.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden || apiErrorCode(body) != "CROSS_ORIGIN" {
		t.Fatalf("a socket from another loopback port = %d %s, want 403 CROSS_ORIGIN", resp.StatusCode, body)
	}
	if got := counterValue(t, hubmetrics.Default.Gather(), "cloop_cross_origin_refusals_total", `reason="foreign_origin"`); got != before+1 {
		t.Errorf("foreign_origin refusals went from %v to %v, want +1", before, got)
	}
}

// TestHandlersReadJSONOnlyThroughTheDecoder is the gate behind "one JSON
// decoder": no handler in pkg/ui or pkg/apiserver hands a request body to
// encoding/json, or reads it whole, except through pkg/jsonbody — which is
// what refuses a form body with 415. The one exception reads a project
// creation's body to route it and puts it back for the handler, which decodes
// it properly.
func TestHandlersReadJSONOnlyThroughTheDecoder(t *testing.T) {
	allowed := map[string]bool{
		"cluster_runs.go:routeNewProject": true,
	}
	var found []string
	for _, dir := range []string{".", filepath.Join("..", "apiserver")} {
		files, err := filepath.Glob(filepath.Join(dir, "*.go"))
		if err != nil {
			t.Fatal(err)
		}
		for _, f := range files {
			if strings.HasSuffix(f, "_test.go") {
				continue
			}
			src, err := os.ReadFile(f)
			if err != nil {
				t.Fatal(err)
			}
			fset := token.NewFileSet()
			file, err := parser.ParseFile(fset, f, src, 0)
			if err != nil {
				t.Fatal(err)
			}
			for _, decl := range file.Decls {
				fn, ok := decl.(*ast.FuncDecl)
				if !ok || fn.Body == nil {
					continue
				}
				ast.Inspect(fn.Body, func(n ast.Node) bool {
					call, ok := n.(*ast.CallExpr)
					if !ok {
						return true
					}
					sel, ok := call.Fun.(*ast.SelectorExpr)
					if !ok {
						return true
					}
					pkg, _ := sel.X.(*ast.Ident)
					if pkg == nil {
						return true
					}
					name := pkg.Name + "." + sel.Sel.Name
					if name != "json.NewDecoder" && name != "io.ReadAll" {
						return true
					}
					if !readsRequestBody(call) {
						return true
					}
					key := filepath.Base(f) + ":" + fn.Name.Name
					if !allowed[key] {
						found = append(found, fset.Position(call.Pos()).String()+" ("+name+" of a request body in "+fn.Name.Name+")")
					}
					return true
				})
			}
		}
	}
	sort.Strings(found)
	for _, f := range found {
		t.Errorf("%s: read it with decodeJSON / jsonbody.Decode, which refuses anything but application/json", f)
	}
}

// readsRequestBody reports whether a call's arguments mention r.Body or
// req.Body.
func readsRequestBody(call *ast.CallExpr) bool {
	hit := false
	for _, arg := range call.Args {
		ast.Inspect(arg, func(n ast.Node) bool {
			if sel, ok := n.(*ast.SelectorExpr); ok && sel.Sel.Name == "Body" {
				if id, ok := sel.X.(*ast.Ident); ok && (id.Name == "r" || id.Name == "req" || id.Name == "request") {
					hit = true
				}
			}
			return !hit
		})
	}
	return hit
}
