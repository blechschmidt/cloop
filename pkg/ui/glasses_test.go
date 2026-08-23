package ui

// Coverage for the per-user display-glasses link (Task 20194).
//
// The claims worth testing are the containment ones, and none of them are
// properties of glasses_api.go alone: they hold because the minted credential
// goes through the same middleware chain, the same route gates, and the same
// project-visibility filter as everything else. So every check below drives a
// real http.Handler with a real token rather than calling a handler directly —
// a regression that moved enforcement out of the gate would still fail here.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/apitoken"
	"github.com/blechschmidt/cloop/pkg/authz"
	"github.com/blechschmidt/cloop/pkg/multiui"
	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/state"
)

// ---------------------------------------------------------------------------
// bundle structure
// ---------------------------------------------------------------------------

// TestDashboard_MainIIFEClosesInLastFragment pins where the front end's single
// IIFE ends.
//
// This is a regression test for a bug found while adding this feature, not a
// hypothetical. 00-core.js opens `(function() { 'use strict';` and every shared
// helper — api, apiMethod, esc, toast, relTime — is a plain function
// declaration inside it, so it is reachable only from code inside the same
// wrapper. The close had drifted to the end of 25-replay.js while two more
// fragments (26-sessions.js, 27-quotas.js) were appended behind it, putting
// both panels at global scope where none of those helpers resolve. Loading the
// assembled bundle in node and calling window.loadSessions() raised
// "ReferenceError: api is not defined" — i.e. the Sessions and Quotas panels
// threw on first open, and nothing in the Go test suite noticed, because every
// existing frontend gate greps for structure rather than scope.
//
// The rule that prevents a repeat is simple enough to check statically: the
// last bundle fragment closes the IIFE, and no earlier one does.
func TestDashboard_MainIIFEClosesInLastFragment(t *testing.T) {
	t.Parallel()

	const closer = "})();"
	lastNonEmptyLine := func(src string) string {
		lines := strings.Split(src, "\n")
		for i := len(lines) - 1; i >= 0; i-- {
			if l := strings.TrimSpace(lines[i]); l != "" {
				return l
			}
		}
		return ""
	}

	for i, path := range bundleFiles {
		b, err := assetFS.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		ends := lastNonEmptyLine(string(b)) == closer
		last := i == len(bundleFiles)-1

		switch {
		case last && !ends:
			t.Errorf("%s is the last bundle fragment but does not end with %q.\n"+
				"It has to close the IIFE that 00-core.js opens — otherwise the wrapper "+
				"is never closed and the bundle is a syntax error.", path, closer)
		case !last && ends:
			t.Errorf("%s ends with %q, which closes the main IIFE early.\n"+
				"Every fragment after it would sit at global scope, where api(), esc(), "+
				"toast() and relTime() are not visible — those panels throw "+
				"ReferenceError the first time a user opens them. Move the closer to the "+
				"last entry of bundleFiles (%s).", path, closer, bundleFiles[len(bundleFiles)-1])
		}
	}
}

// ---------------------------------------------------------------------------
// the wearable's page
// ---------------------------------------------------------------------------

// glassesPageSource is the shell as served.
func glassesPageSource() string { return loadAssets().glassesTmpl }

func TestGlassesPage_ServedWithValidator(t *testing.T) {
	t.Parallel()

	srv := &Server{WorkDir: t.TempDir()}
	rec := httptest.NewRecorder()
	srv.handleGlassesPage(rec, httptest.NewRequest(http.MethodGet, "/glasses", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("GET /glasses = %d, want 200", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Errorf("Content-Type = %q, want text/html", ct)
	}
	if rec.Header().Get("ETag") == "" {
		t.Error("no ETag: the glasses re-open the saved URL on every glance, and without a " +
			"validator each one re-downloads the whole document")
	}
	if body := rec.Body.String(); !strings.HasPrefix(body, "<!DOCTYPE html>") {
		t.Errorf("body does not start with a doctype: %.60q", body)
	}
}

// TestGlassesPage_IsSelfContained keeps the wearable to one round trip. A
// device on a phone's link pays for each request, and the dashboard bundle it
// would otherwise pull is hundreds of kilobytes of panels it cannot render.
func TestGlassesPage_IsSelfContained(t *testing.T) {
	t.Parallel()

	src := glassesPageSource()
	for _, bad := range []string{"<script src=", "<link rel=\"stylesheet\"", "{{asset:", "//cdn.", "http://", "https://"} {
		if strings.Contains(src, bad) {
			t.Errorf("glasses.html references %q — it must be a single self-contained document "+
				"with no external CSS, script or font", bad)
		}
	}
	if !strings.Contains(src, "<style>") || !strings.Contains(src, "<script>") {
		t.Error("glasses.html should carry its own inline <style> and <script>")
	}
}

// TestGlassesPage_APIEndpointsAllRegistered is the drift gate the dashboard
// already has, applied to the second front end: an endpoint the wearable calls
// but the route table does not register is a screen that 404s in the field,
// where nobody can open a console to find out why.
func TestGlassesPage_APIEndpointsAllRegistered(t *testing.T) {
	t.Parallel()

	registered := extractRegisteredRoutes(routesSource)
	if len(registered) == 0 {
		t.Fatal("no routes extracted from routes.go — the check is disabled, not passing")
	}

	// Only literal prefixes: the page builds task paths by concatenation, so
	// match the fixed head of each call and let routeMatches handle wildcards.
	re := regexp.MustCompile(`'(/api/[a-zA-Z0-9/_-]*)`)
	found := map[string]struct{}{}
	for _, m := range re.FindAllStringSubmatch(glassesPageSource(), -1) {
		found[strings.TrimSuffix(m[1], "/")] = struct{}{}
	}
	if len(found) == 0 {
		t.Fatal("no /api/… call sites found in glasses.html — the extraction regex broke")
	}

	for call := range found {
		ok := false
		for route := range registered {
			if routeMatches(call, route) || strings.HasPrefix(route, call+"/") {
				ok = true
				break
			}
		}
		if !ok {
			t.Errorf("glasses.html calls %q, which is not a registered route in routes.go", call)
		}
	}
}

// TestGlassesPage_ElementIDsExist catches the deleted-markup-with-zombie-script
// bug the dashboard test catches, in the file that has no other coverage.
func TestGlassesPage_ElementIDsExist(t *testing.T) {
	t.Parallel()

	src := glassesPageSource()
	declared := map[string]struct{}{}
	for _, m := range regexp.MustCompile(`id="([a-zA-Z0-9_-]+)"`).FindAllStringSubmatch(src, -1) {
		declared[m[1]] = struct{}{}
	}
	for _, m := range regexp.MustCompile(`el\('([a-zA-Z0-9_-]+)'\)`).FindAllStringSubmatch(src, -1) {
		if _, ok := declared[m[1]]; !ok {
			t.Errorf("glasses.html looks up #%s, which no element declares", m[1])
		}
	}
}

// TestGlassesPage_SendsTokenAsHeader keeps the credential off the request line
// of every call after the first. The device can only carry it in the URL it
// saved; that is one request in the proxy log rather than one per refresh.
func TestGlassesPage_SendsTokenAsHeader(t *testing.T) {
	t.Parallel()

	src := glassesPageSource()
	if !strings.Contains(src, "headers['Authorization'] = 'Bearer '") {
		t.Error("glasses.html should send its token in an Authorization header, not re-append " +
			"?token= to every API call")
	}
	if strings.Contains(src, "'?token=' +") || strings.Contains(src, "&token=") {
		t.Error("glasses.html appends the token to an API URL — that puts a live credential in " +
			"the access log of every request instead of just the page load")
	}
}

// ---------------------------------------------------------------------------
// the link, on a single-tenant hub
// ---------------------------------------------------------------------------

// tokenInURL pulls the credential back out of a generated link, which is what
// the glasses do when they open it.
func tokenInURL(t *testing.T, link string) string {
	t.Helper()
	u, err := url.Parse(link)
	if err != nil {
		t.Fatalf("parse link %q: %v", link, err)
	}
	tok := u.Query().Get("token")
	if tok == "" {
		t.Fatalf("link %q carries no token", link)
	}
	if u.Path != "/glasses" {
		t.Fatalf("link path = %q, want /glasses", u.Path)
	}
	return tok
}

// mintLinkVia generates a link through HTTP, the way the panel does.
func mintLinkVia(t *testing.T, f *tokenFixture) string {
	t.Helper()
	code, body := f.do(t, "", http.MethodPost, "/api/glasses/link", "{}")
	if code != http.StatusOK {
		t.Fatalf("POST /api/glasses/link = %d, want 200\nbody: %s", code, body)
	}
	var resp struct {
		URL string `json:"url"`
	}
	if err := json.Unmarshal([]byte(body), &resp); err != nil {
		t.Fatalf("decode mint response: %v\nbody: %s", err, body)
	}
	return resp.URL
}

// TestGlassesLinkAuthenticatesTheWearable is the baseline the whole feature
// exists for: a URL, and nothing else, gets a device to the project list and
// into a project's tasks.
func TestGlassesLinkAuthenticatesTheWearable(t *testing.T) {
	f := newTokenFixture(t)
	tok := tokenInURL(t, mintLinkVia(t, f))

	code, body := f.do(t, tok, http.MethodGet, "/api/glasses/projects", "")
	if code != http.StatusOK {
		t.Fatalf("GET /api/glasses/projects = %d, want 200\nbody: %s", code, body)
	}
	var projects struct {
		Projects []struct {
			Idx   int    `json:"idx"`
			Name  string `json:"name"`
			Total int    `json:"total"`
		} `json:"projects"`
	}
	if err := json.Unmarshal([]byte(body), &projects); err != nil {
		t.Fatalf("decode projects: %v\nbody: %s", err, body)
	}
	if len(projects.Projects) != 2 {
		t.Fatalf("got %d projects, want the fixture's 2\nbody: %s", len(projects.Projects), body)
	}

	// And the second screen: the tasks of one of them.
	idx := projects.Projects[0].Idx
	code, body = f.do(t, tok, http.MethodGet, "/api/glasses/tasks?project_idx="+itoaArch(idx), "")
	if code != http.StatusOK {
		t.Fatalf("GET /api/glasses/tasks = %d, want 200\nbody: %s", code, body)
	}
	if !strings.Contains(body, `"tasks"`) || !strings.Contains(body, `"total"`) {
		t.Errorf("task list is missing its envelope: %s", body)
	}
}

// TestGlassesLinkIsReadOnly is the containment property that makes putting a
// credential in a URL defensible at all.
func TestGlassesLinkIsReadOnly(t *testing.T) {
	f := newTokenFixture(t)
	tok := tokenInURL(t, mintLinkVia(t, f))
	idx := f.idxOf(t, f.dirA)

	for _, tc := range []struct{ method, path, body string }{
		{http.MethodPost, "/api/run?project_idx=" + itoaArch(idx), `{}`},
		{http.MethodPost, "/api/stop?project_idx=" + itoaArch(idx), `{}`},
		{http.MethodPost, "/api/tasks?project_idx=" + itoaArch(idx), `{"title":"x","description":"y"}`},
		{http.MethodPost, "/api/goal?project_idx=" + itoaArch(idx), `{"goal":"hijacked"}`},
		{http.MethodGet, "/api/secrets", ""},
		{http.MethodGet, "/api/audit", ""},
		{http.MethodGet, "/api/tokens", ""},
		{http.MethodGet, "/api/sessions", ""},
	} {
		code, body := f.do(t, tok, tc.method, tc.path, tc.body)
		if code == http.StatusOK {
			t.Errorf("%s %s with a glasses link = 200 — the link must not reach this\nbody: %s",
				tc.method, tc.path, body)
		}
	}
}

// TestGlassesLinkCannotMintAnother closes the loop that would make revocation
// advisory: a leaked URL issuing its own successor with a fresh expiry.
func TestGlassesLinkCannotMintAnother(t *testing.T) {
	f := newTokenFixture(t)
	tok := tokenInURL(t, mintLinkVia(t, f))

	for _, m := range []string{http.MethodGet, http.MethodPost, http.MethodDelete} {
		code, body := f.do(t, tok, m, "/api/glasses/link", "{}")
		if code != http.StatusForbidden {
			t.Errorf("%s /api/glasses/link with a glasses link = %d, want 403 — a token must not "+
				"be able to manage links\nbody: %s", m, code, body)
		}
	}

	// And an ordinary PAT cannot either: the rule is about tokens, not about
	// this one kind of token.
	pat := f.mint(t, apitoken.MintOptions{Roles: []string{"admin"}})
	if code, body := f.do(t, pat, http.MethodPost, "/api/glasses/link", "{}"); code != http.StatusForbidden {
		t.Errorf("POST /api/glasses/link with an admin PAT = %d, want 403\nbody: %s", code, body)
	}
}

// TestGlassesLinkRotationRevokesPrevious: "regenerate" has to also mean
// "revoke what I handed out", or the button answers the wrong question.
func TestGlassesLinkRotationRevokesPrevious(t *testing.T) {
	f := newTokenFixture(t)
	first := tokenInURL(t, mintLinkVia(t, f))

	if code, _ := f.do(t, first, http.MethodGet, "/api/glasses/projects", ""); code != http.StatusOK {
		t.Fatalf("first link should work before rotation, got %d", code)
	}

	second := tokenInURL(t, mintLinkVia(t, f))
	if first == second {
		t.Fatal("rotation returned the same credential")
	}
	if code, body := f.do(t, first, http.MethodGet, "/api/glasses/projects", ""); code != http.StatusUnauthorized {
		t.Errorf("the rotated-out link still authenticates (%d) — regenerating must revoke it\nbody: %s", code, body)
	}
	if code, _ := f.do(t, second, http.MethodGet, "/api/glasses/projects", ""); code != http.StatusOK {
		t.Errorf("the new link does not work: %d", code)
	}

	// Exactly one live link, not a growing pile.
	live := 0
	all, err := f.tokens.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	for i := range all {
		if all[i].Kind == apitoken.KindGlasses && all[i].Active(time.Now()) {
			live++
		}
	}
	if live != 1 {
		t.Errorf("%d live glasses tokens after one rotation, want 1", live)
	}
}

// TestGlassesLinkRevokeStopsIt covers the action a user takes after losing the
// device.
func TestGlassesLinkRevokeStopsIt(t *testing.T) {
	f := newTokenFixture(t)
	tok := tokenInURL(t, mintLinkVia(t, f))

	if code, body := f.do(t, "", http.MethodDelete, "/api/glasses/link", ""); code != http.StatusOK {
		t.Fatalf("DELETE /api/glasses/link = %d, want 200\nbody: %s", code, body)
	}
	if code, body := f.do(t, tok, http.MethodGet, "/api/glasses/projects", ""); code != http.StatusUnauthorized {
		t.Errorf("the revoked link still authenticates (%d)\nbody: %s", code, body)
	}
	// The status endpoint must now agree that there is nothing to revoke.
	_, body := f.do(t, "", http.MethodGet, "/api/glasses/link", "")
	if strings.Contains(body, `"exists":true`) {
		t.Errorf("link status still reports a live link after revocation: %s", body)
	}
}

// TestGlassesLinkStatusNeverReturnsTheSecret: the URL exists in exactly one
// response, and no later read can reconstruct it.
func TestGlassesLinkStatusNeverReturnsTheSecret(t *testing.T) {
	f := newTokenFixture(t)
	link := mintLinkVia(t, f)
	secret := tokenInURL(t, link)

	code, body := f.do(t, "", http.MethodGet, "/api/glasses/link", "")
	if code != http.StatusOK {
		t.Fatalf("GET /api/glasses/link = %d, want 200", code)
	}
	if strings.Contains(body, secret) {
		t.Fatal("GET /api/glasses/link returned the credential — it is stored as a hash and " +
			"must never be recoverable")
	}
	if !strings.Contains(body, `"exists":true`) {
		t.Errorf("status does not report the live link: %s", body)
	}
}

// ---------------------------------------------------------------------------
// payload shape
// ---------------------------------------------------------------------------

// TestGlassesTasksProjectsAwayTheBulk is why these endpoints exist rather than
// reusing /api/tasks: the wearable draws four fields, and the difference on a
// real plan is kilobytes per task.
func TestGlassesTasksProjectsAwayTheBulk(t *testing.T) {
	big := strings.Repeat("x", 40000)
	dir := setupProjectDir(t, "goal", []*pm.Task{
		{ID: 1, Title: "first", Description: big, Result: big, Status: pm.TaskDone},
		{ID: 2, Title: "second", Description: big, Result: big, Status: pm.TaskInProgress},
	})
	srv := New(dir, 0, "")
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(func() { ts.Close(); srv.closeTokenManager() })

	get := func(path string) string {
		resp, err := http.Get(ts.URL + path)
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		defer resp.Body.Close()
		buf := make([]byte, 1<<20)
		n, _ := resp.Body.Read(buf)
		return string(buf[:n])
	}

	glasses := get("/api/glasses/tasks")
	dashboard := get("/api/tasks")
	if strings.Contains(glasses, big) {
		t.Error("the glasses task list carries a full description or result — it must project " +
			"each task down to id, title, status and priority")
	}
	if len(glasses) >= len(dashboard) {
		t.Errorf("glasses payload (%d bytes) is not smaller than the dashboard's (%d)",
			len(glasses), len(dashboard))
	}
	// Running first: what the wearer glanced up to check.
	if i, j := strings.Index(glasses, `"second"`), strings.Index(glasses, `"first"`); i < 0 || j < 0 || i > j {
		t.Errorf("in-progress task is not listed first: %s", glasses)
	}

	// The detail screen may show text, but bounded.
	detail := get("/api/glasses/tasks/1")
	if strings.Contains(detail, big) {
		t.Error("the task detail returns the untruncated result")
	}
	if !strings.Contains(detail, "…") {
		t.Errorf("truncated text is not marked with an ellipsis: %.200s", detail)
	}
}

// TestGlassesTaskDetailRejectsJunk keeps a hand-typed path from reaching the
// plan lookup.
func TestGlassesTaskDetailRejectsJunk(t *testing.T) {
	dir := setupProjectDir(t, "goal", []*pm.Task{{ID: 1, Title: "only", Status: pm.TaskPending}})
	srv := New(dir, 0, "")
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(func() { ts.Close(); srv.closeTokenManager() })

	for _, path := range []string{"/api/glasses/tasks/0", "/api/glasses/tasks/-1", "/api/glasses/tasks/abc", "/api/glasses/tasks/999"} {
		resp, err := http.Get(ts.URL + path)
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			t.Errorf("GET %s = 200, want a refusal", path)
		}
	}
}

// ---------------------------------------------------------------------------
// the multi-tenant properties
// ---------------------------------------------------------------------------

// TestGlassesLinkNeverExceedsItsOwner is the property that lets a viewer-role
// token be safe to hand out: its roles are a *ceiling*, and the floor is
// whatever its owner may currently do.
//
// The token below says `viewer`. Its owner matches no binding under a
// deny-by-default policy, so the intersection is empty and the link reads
// nothing — even though an unbound token carrying the same role would have
// read everything on the hub.
func TestGlassesLinkNeverExceedsItsOwner(t *testing.T) {
	idp := newUIFakeIdP(t)
	srv, ts := newOIDCTestServer(t, idp, "", nil)
	t.Cleanup(srv.closeTokenManager)

	resolver, err := authz.New(authz.Config{
		DefaultRole: authz.RoleNone,
		Bindings: []authz.Binding{
			{Claim: authz.ClaimGroup, Value: "readers", Role: authz.RoleViewer},
		},
	})
	if err != nil {
		t.Fatalf("authz.New: %v", err)
	}
	srv.Authz = resolver

	mgr, err := srv.tokenManager()
	if err != nil {
		t.Fatalf("tokenManager: %v", err)
	}
	mintFor := func(o *apitoken.Owner) string {
		m, merr := mgr.Mint(apitoken.MintOptions{
			Name: glassesTokenName, Roles: []string{"viewer"},
			Kind: apitoken.KindGlasses, Owner: o,
			ExpiresAt: time.Now().Add(time.Hour),
		})
		if merr != nil {
			t.Fatalf("Mint: %v", merr)
		}
		return m.Plaintext
	}

	callPath := func(tok, path string) int {
		req, _ := http.NewRequest(http.MethodGet, ts.URL+path, nil)
		req.Header.Set("Authorization", "Bearer "+tok)
		resp, cerr := http.DefaultClient.Do(req)
		if cerr != nil {
			t.Fatalf("GET: %v", cerr)
		}
		defer resp.Body.Close()
		return resp.StatusCode
	}
	call := func(tok string) int { return callPath(tok, "/api/glasses/projects") }

	mapped := mintFor(&apitoken.Owner{Sub: "sub-alice", Email: "alice@example.com", Groups: []string{"readers"}})
	if got := call(mapped); got != http.StatusOK {
		t.Errorf("a link owned by a mapped viewer = %d, want 200", got)
	}

	unmapped := mintFor(&apitoken.Owner{Sub: "sub-mallory", Email: "mallory@example.com", Groups: []string{"contractors"}})
	if got := call(unmapped); got == http.StatusOK {
		t.Error("a link owned by a user with no role binding was allowed to read — the token's " +
			"roles must be intersected with its owner's live authority, not granted outright")
	}

	// The control: the same roles, with no owner to be bounded by, read
	// everything. It has to be an ordinary PAT rather than an unowned glasses
	// token, because an unowned *link* is refused outright on a hub with
	// sign-on (TestUnownedGlassesLinkRefusedOnceOIDCIsOn) — so this arm proves
	// the intersection is what narrows the bound token, not the kind check.
	plain, perr := mgr.Mint(apitoken.MintOptions{
		Name: "plain", Roles: []string{"viewer"}, ExpiresAt: time.Now().Add(time.Hour),
	})
	if perr != nil {
		t.Fatalf("Mint: %v", perr)
	}
	if got := callPath(plain.Plaintext, "/api/projects"); got != http.StatusOK {
		t.Errorf("an unbound viewer token = %d, want 200 — the fixture is not exercising the "+
			"owner binding", got)
	}
}

// TestGlassesLinkSeesOnlyItsOwnersProjects covers the other half of tenancy:
// ownership, which is recorded per project and is independent of role
// bindings.
func TestGlassesLinkSeesOnlyItsOwnersProjects(t *testing.T) {
	idp := newUIFakeIdP(t)
	srv, ts := newOIDCTestServer(t, idp, "", nil)
	t.Cleanup(srv.closeTokenManager)

	resolver, err := authz.New(authz.Config{DefaultRole: authz.RoleViewer})
	if err != nil {
		t.Fatalf("authz.New: %v", err)
	}
	srv.Authz = resolver

	// Two extra projects, owned by different people, plus the fixture's own
	// unowned one. They go in through the registry rather than srv.Projects:
	// ownership is recorded there, and a path handed to --projects is an
	// operator-supplied project that is shared by construction.
	alice := setupProjectDir(t, "alice's goal", nil)
	bob := setupProjectDir(t, "bob's goal", nil)
	registerOwned(t, alice, "alice@example.com")
	registerOwned(t, bob, "bob@example.com")

	mgr, err := srv.tokenManager()
	if err != nil {
		t.Fatalf("tokenManager: %v", err)
	}
	mintFor := func(o *apitoken.Owner) string {
		m, merr := mgr.Mint(apitoken.MintOptions{
			Name: glassesTokenName, Roles: []string{"viewer"}, Kind: apitoken.KindGlasses,
			Owner: o, ExpiresAt: time.Now().Add(time.Hour),
		})
		if merr != nil {
			t.Fatalf("Mint: %v", merr)
		}
		return m.Plaintext
	}
	listPath := func(tok, path string) string {
		req, _ := http.NewRequest(http.MethodGet, ts.URL+path, nil)
		req.Header.Set("Authorization", "Bearer "+tok)
		resp, rerr := http.DefaultClient.Do(req)
		if rerr != nil {
			t.Fatalf("GET: %v", rerr)
		}
		defer resp.Body.Close()
		buf := make([]byte, 1<<16)
		n, _ := resp.Body.Read(buf)
		return string(buf[:n])
	}
	list := func(tok string) string { return listPath(tok, "/api/glasses/projects") }

	// The control first: an ordinary PAT with the same roles and no owner sees
	// both projects. Without this the assertions below would also pass if the
	// registry were simply empty. It reads /api/projects rather than the
	// glasses route because a plain PAT is not confined to the glasses surface.
	plain, perr := mgr.Mint(apitoken.MintOptions{
		Name: "plain", Roles: []string{"viewer"}, ExpiresAt: time.Now().Add(time.Hour),
	})
	if perr != nil {
		t.Fatalf("Mint: %v", perr)
	}
	if unbound := listPath(plain.Plaintext, "/api/projects"); !strings.Contains(unbound, "bob's goal") {
		t.Fatalf("an unbound viewer token cannot see bob's project — the fixture is not "+
			"exercising the owner filter\nbody: %s", unbound)
	}

	body := list(mintFor(&apitoken.Owner{Sub: "sub-alice", Email: "alice@example.com"}))
	if strings.Contains(body, "bob's goal") {
		t.Errorf("alice's glasses link listed bob's project — an owner-bound token must be "+
			"filtered exactly as its owner's session is\nbody: %s", body)
	}
	if !strings.Contains(body, "alice's goal") {
		t.Errorf("alice's glasses link cannot see her own project\nbody: %s", body)
	}
}

// registerOwned adds a project to the shared registry with an owner, which is
// how the hub records "this is somebody's project" (see multiui). The registry
// lives under $HOME, which TestMain isolates per package run.
func registerOwned(t *testing.T, dir, owner string) {
	t.Helper()
	if err := multiui.AddPathsOwned([]string{dir}, owner); err != nil {
		t.Fatalf("register %s: %v", dir, err)
	}
}

// ---------------------------------------------------------------------------
// helpers that keep the fixtures honest
// ---------------------------------------------------------------------------

// TestGlassesURLUsesExternalURL: a hub behind a proxy sees an internal Host,
// and a link built from it resolves to nothing on the wearer's phone.
func TestGlassesURLUsesExternalURL(t *testing.T) {
	t.Parallel()

	srv := &Server{WorkDir: t.TempDir(), ExternalURL: "https://cloop.example.com/"}
	req := httptest.NewRequest(http.MethodGet, "http://internal-host:8080/api/glasses/link", nil)
	got := srv.glassesURL(req, "cloop_pat_deadbeef_secret")
	if !strings.HasPrefix(got, "https://cloop.example.com/glasses?token=") {
		t.Errorf("glassesURL = %q, want it rooted at ui.external_url", got)
	}
	if strings.Contains(got, "//glasses") {
		t.Errorf("glassesURL doubled the path separator: %q", got)
	}

	bare := &Server{WorkDir: t.TempDir()}
	if got := bare.glassesURL(req, "tok"); !strings.HasPrefix(got, "http://internal-host:8080/glasses?") {
		t.Errorf("without external_url the link should fall back to the request host, got %q", got)
	}
}

func TestTruncateForGlassesIsRuneSafe(t *testing.T) {
	t.Parallel()

	// Multi-byte input cut mid-character would render as a replacement glyph
	// on a display with no way to scroll past it.
	in := strings.Repeat("é", 50)
	got := truncateForGlasses(in, 10)
	if !strings.HasSuffix(got, "…") {
		t.Errorf("truncated text is not marked: %q", got)
	}
	if strings.ContainsRune(got, '�') {
		t.Errorf("truncation split a rune: %q", got)
	}
	if n := len([]rune(strings.TrimSuffix(got, "…"))); n != 10 {
		t.Errorf("kept %d runes, want 10", n)
	}
	if got := truncateForGlasses("short", 100); got != "short" {
		t.Errorf("short input was altered: %q", got)
	}
}

// makeSureStateLoads is a guard on the fixtures above: several tests assert on
// an empty task list, which would also be the answer if the project failed to
// load at all.
func TestGlassesFixtureProjectsActuallyLoad(t *testing.T) {
	dir := setupProjectDir(t, "goal", []*pm.Task{{ID: 1, Title: "t", Status: pm.TaskPending}})
	ps, err := state.Load(dir)
	if err != nil || ps.Plan == nil || len(ps.Plan.Tasks) != 1 {
		t.Fatalf("fixture project did not load: err=%v", err)
	}
	if _, err := os.Stat(dir); err != nil {
		t.Fatalf("fixture dir vanished: %v", err)
	}
}

// ---------------------------------------------------------------------------
// containment rules added after review
// ---------------------------------------------------------------------------

// TestGlassesLinkIsConfinedToItsOwnSurface is the containment the role ladder
// cannot express.
//
// `viewer` carries project.read, and project.read is what GET
// /api/provider-calls/{id} declares — an endpoint that returns an agent call's
// prompt and response verbatim, which on a coding agent routinely contains the
// file contents, tokens and keys it was handed. A credential that lives in a
// URL, and therefore in every proxy access log in front of the hub, must not
// reach them. Path confinement is the only mechanism that says so, because no
// role means "may read task titles but not agent transcripts".
func TestGlassesLinkIsConfinedToItsOwnSurface(t *testing.T) {
	f := newTokenFixture(t)
	tok := tokenInURL(t, mintLinkVia(t, f))
	idx := itoaArch(f.idxOf(t, f.dirA))

	// Reachable: the endpoints built for the wearable.
	for _, path := range []string{
		"/api/glasses/projects",
		"/api/glasses/tasks?project_idx=" + idx,
	} {
		if code, body := f.do(t, tok, http.MethodGet, path, ""); code != http.StatusOK {
			t.Errorf("GET %s with a glasses link = %d, want 200\nbody: %s", path, code, body)
		}
	}

	// Refused: every other read a plain viewer token would be granted.
	for _, path := range []string{
		"/api/provider-calls?project_idx=" + idx,
		"/api/provider-calls/1?project_idx=" + idx,
		"/api/state?project_idx=" + idx,
		"/api/tasks?project_idx=" + idx,
		"/api/steps?project_idx=" + idx,
		"/api/livelog?project_idx=" + idx,
		"/api/event-history?project_idx=" + idx,
		"/api/kb?project_idx=" + idx,
		"/api/projects",
		"/api/me",
	} {
		code, body := f.do(t, tok, http.MethodGet, path, "")
		if code != http.StatusForbidden {
			t.Errorf("GET %s with a glasses link = %d, want 403 — the link must not reach "+
				"anything outside /api/glasses/\nbody: %s", path, code, body)
		}
	}

	// The confinement is specific to the kind: an ordinary viewer PAT is
	// unaffected. Without this the test could pass because the fixture is
	// broken rather than because the rule works.
	plain := f.mint(t, apitoken.MintOptions{Roles: []string{"viewer"}})
	if code, _ := f.do(t, plain, http.MethodGet, "/api/state?project_idx="+idx, ""); code != http.StatusOK {
		t.Errorf("an ordinary viewer PAT was refused /api/state (%d) — the confinement is too broad", code)
	}
}

// TestGlassesShellLoadsForADeadLink: the page that explains a dead link has to
// be able to load, or the wearer sees a JSON error body on a display with no
// address bar.
func TestGlassesShellLoadsForADeadLink(t *testing.T) {
	f := newTokenFixture(t)
	link := mintLinkVia(t, f)
	tok := tokenInURL(t, link)

	if code, _ := f.do(t, "", http.MethodDelete, "/api/glasses/link", ""); code != http.StatusOK {
		t.Fatalf("revoke failed: %d", code)
	}

	// The shell still renders…
	resp, err := http.Get(f.ts.URL + "/glasses?token=" + tok)
	if err != nil {
		t.Fatalf("GET /glasses: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("GET /glasses with a revoked token = %d, want 200 so the page can explain itself",
			resp.StatusCode)
	}

	// …while the data behind it stays refused.
	if code, _ := f.do(t, tok, http.MethodGet, "/api/glasses/projects", ""); code != http.StatusUnauthorized {
		t.Errorf("a revoked link still reads projects (%d)", code)
	}

}

// TestGlassesShellCarveOutIsNarrow bounds what serving the shell before
// authentication actually opened up. The fixture above cannot answer this: it
// runs with no static token, so every path is reachable anyway.
func TestGlassesShellCarveOutIsNarrow(t *testing.T) {
	dir := setupProjectDir(t, "goal", nil)
	srv := New(dir, 0, "the-static-token")
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(func() { ts.Close(); srv.closeTokenManager() })

	// The predicate itself: exactly one path, read verbs only.
	for _, tc := range []struct {
		method, path string
		want         bool
	}{
		{http.MethodGet, "/glasses", true},
		{http.MethodHead, "/glasses", true},
		{http.MethodPost, "/glasses", false},
		{http.MethodGet, "/glasses/", false},
		{http.MethodGet, "/glassesx", false},
		{http.MethodGet, "/api/glasses/projects", false},
		{http.MethodGet, "/api/state", false},
		{http.MethodGet, "/", false},
	} {
		req := httptest.NewRequest(tc.method, "http://x"+tc.path, nil)
		if got := isPublicShell(req); got != tc.want {
			t.Errorf("isPublicShell(%s %s) = %v, want %v", tc.method, tc.path, got, tc.want)
		}
	}

	// And end-to-end against a hub that does require a credential: the shell
	// loads without one, nothing else does.
	get := func(path string) int {
		resp, err := http.Get(ts.URL + path)
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	if code := get("/glasses"); code != http.StatusOK {
		t.Errorf("GET /glasses without a credential = %d, want 200", code)
	}
	for _, path := range []string{"/api/glasses/projects", "/api/glasses/link", "/api/state", "/api/projects"} {
		if code := get(path); code == http.StatusOK {
			t.Errorf("GET %s without a credential = 200 — only the shell is carved out", path)
		}
	}
}

// TestGlassesRotationRevokesEveryLiveLink covers the invariant the store does
// not enforce: a second live link left behind by a racing mint is invisible to
// the panel, and a credential nobody can see is a credential nobody revokes.
func TestGlassesRotationRevokesEveryLiveLink(t *testing.T) {
	f := newTokenFixture(t)

	// Two live links for the same (unowned, single-tenant) caller, as a racing
	// pair of Generate taps would leave behind.
	a := f.mint(t, apitoken.MintOptions{
		Name: glassesTokenName, Roles: []string{"viewer"}, Kind: apitoken.KindGlasses,
		ExpiresAt: time.Now().Add(time.Hour),
	})
	b := f.mint(t, apitoken.MintOptions{
		Name: glassesTokenName, Roles: []string{"viewer"}, Kind: apitoken.KindGlasses,
		ExpiresAt: time.Now().Add(time.Hour),
	})
	for _, tok := range []string{a, b} {
		if code, _ := f.do(t, tok, http.MethodGet, "/api/glasses/projects", ""); code != http.StatusOK {
			t.Fatalf("fixture link does not authenticate: %d", code)
		}
	}

	// One rotation must clear both.
	fresh := tokenInURL(t, mintLinkVia(t, f))
	for i, tok := range []string{a, b} {
		if code, _ := f.do(t, tok, http.MethodGet, "/api/glasses/projects", ""); code != http.StatusUnauthorized {
			t.Errorf("orphaned link %d survived rotation (%d) — rotation must revoke every live "+
				"link, not just the newest", i, code)
		}
	}
	if code, _ := f.do(t, fresh, http.MethodGet, "/api/glasses/projects", ""); code != http.StatusOK {
		t.Errorf("the new link does not work: %d", code)
	}
}

// TestConcurrentGenerateLeavesOneLiveLink is the same invariant under the race
// that produces it.
func TestConcurrentGenerateLeavesOneLiveLink(t *testing.T) {
	f := newTokenFixture(t)

	const n = 6
	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			_, _ = f.do(t, "", http.MethodPost, "/api/glasses/link", "{}")
		}()
	}
	wg.Wait()

	all, err := f.tokens.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	live := 0
	now := time.Now()
	for i := range all {
		if all[i].Kind == apitoken.KindGlasses && all[i].Active(now) {
			live++
		}
	}
	if live != 1 {
		t.Errorf("%d live glasses links after %d concurrent generates, want 1", live, n)
	}
}

// TestUnownedGlassesLinkRefusedOnceOIDCIsOn covers the upgrade path. A link
// minted while the hub was single-tenant carries no owner; if the deployment
// later adds sign-on, that same URL would be filtered by no identity and
// intersected with no authority — a cross-tenant viewer sitting in someone's
// phone.
func TestUnownedGlassesLinkRefusedOnceOIDCIsOn(t *testing.T) {
	idp := newUIFakeIdP(t)
	srv, ts := newOIDCTestServer(t, idp, "", nil)
	t.Cleanup(srv.closeTokenManager)

	mgr, err := srv.tokenManager()
	if err != nil {
		t.Fatalf("tokenManager: %v", err)
	}
	minted, err := mgr.Mint(apitoken.MintOptions{
		Name: glassesTokenName, Roles: []string{"viewer"}, Kind: apitoken.KindGlasses,
		ExpiresAt: time.Now().Add(time.Hour), // Owner deliberately nil
	})
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}

	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/glasses/projects", nil)
	req.Header.Set("Authorization", "Bearer "+minted.Plaintext)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("an unowned glasses link on a hub with OIDC enabled = %d, want 403 — it would "+
			"otherwise read every tenant's projects", resp.StatusCode)
	}
}

// TestOwnerMatchesPrefersTheStableSubject: an IdP that rewrites a user's email
// during a domain migration must not make their own link invisible to them,
// which is how a second live credential gets minted while the panel says there
// is none.
func TestOwnerMatchesPrefersTheStableSubject(t *testing.T) {
	t.Parallel()

	stored := &apitoken.Owner{Sub: "sub-alice", Email: "a.smith@old.example"}
	renamed := &apitoken.Owner{Sub: "sub-alice", Email: "a.smith@new.example"}
	if !ownerMatches(stored, renamed) {
		t.Error("a changed email hid the user's own link; match on sub when both carry one")
	}

	// A recycled address must not hand one person another's link.
	recycled := &apitoken.Owner{Sub: "sub-bob", Email: "a.smith@old.example"}
	if ownerMatches(stored, recycled) {
		t.Error("two different subjects sharing an address were treated as the same person")
	}

	// No subject on either side: fall back to the key.
	if !ownerMatches(&apitoken.Owner{Email: "x@y"}, &apitoken.Owner{Email: "X@Y"}) {
		t.Error("email comparison should be case-insensitive, matching oidcauth.OwnerKey")
	}
	// Unowned matches unowned (single-tenant), and never matches an owner.
	if !ownerMatches(nil, nil) {
		t.Error("the single-tenant operator's own link should match")
	}
	if ownerMatches(nil, stored) || ownerMatches(stored, nil) {
		t.Error("an unowned link must not be claimed by a signed-in user, or vice versa")
	}
}

// TestGlassesPageStopsPollingOnADeadLink pins the client-side half of the
// lockout problem: without a terminal state, a forgotten pair of glasses
// retries every minute forever, and each rejection trips the hub's per-IP
// auth-failure lockout — which, because glasses tether through a phone, is
// shared with every other caller behind that address.
func TestGlassesPageStopsPollingOnADeadLink(t *testing.T) {
	t.Parallel()

	src := glassesPageSource()
	for _, want := range []string{"dead = true", "stopPolling()", "clearInterval("} {
		if !strings.Contains(src, want) {
			t.Errorf("glasses.html does not %q — a revoked link must stop retrying, not poll "+
				"the hub into an auth-failure lockout", want)
		}
	}
	for _, bad := range []string{"sessionStorage.setItem", "localStorage.setItem"} {
		if strings.Contains(src, bad) {
			t.Errorf("glasses.html copies the credential into %s; the device re-opens the saved "+
				"URL every launch, so it buys nothing and leaves a live token where a script "+
				"injection could read it", bad)
		}
	}
}

// TestGlassesLinkWarnsOnPlaintextTransport: a credential travelling in a query
// string over an unencrypted hop is worth one sentence at the moment the user
// decides where to put it, rather than a discovery later. Loopback is exempt —
// there is no network to cross — so the warning stays meaningful instead of
// becoming noise every local operator learns to skip.
func TestGlassesLinkWarnsOnPlaintextTransport(t *testing.T) {
	if !linkHostIsLoopback("http://127.0.0.1:8080/glasses?token=x") ||
		!linkHostIsLoopback("http://localhost:8080/glasses?token=x") {
		t.Error("loopback links should not be flagged")
	}
	if linkHostIsLoopback("http://cloop.example.com/glasses?token=x") {
		t.Error("a routable host was treated as loopback")
	}

	f := newTokenFixture(t)
	f.srv.ExternalURL = "http://cloop.example.com"
	_, body := f.do(t, "", http.MethodPost, "/api/glasses/link", "{}")
	var resp struct {
		URL     string `json:"url"`
		Warning string `json:"warning"`
	}
	if err := json.Unmarshal([]byte(body), &resp); err != nil {
		t.Fatalf("decode: %v\nbody: %s", err, body)
	}
	if !strings.HasPrefix(resp.URL, "http://cloop.example.com/glasses?") {
		t.Fatalf("url = %q", resp.URL)
	}
	if !strings.Contains(resp.Warning, "http link") {
		t.Errorf("no plaintext-transport warning for an http link:\n%s", resp.Warning)
	}

	f.srv.ExternalURL = "https://cloop.example.com"
	_, body = f.do(t, "", http.MethodPost, "/api/glasses/link", "{}")
	if err := json.Unmarshal([]byte(body), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if strings.Contains(resp.Warning, "http link") {
		t.Errorf("https link was warned about anyway:\n%s", resp.Warning)
	}
}
