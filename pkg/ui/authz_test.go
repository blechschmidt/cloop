package ui

// Claim-based RBAC enforcement tests (Task 20164).
//
// Four properties are pinned here:
//
//  1. Route coverage — every route declares a permission, and every
//     mutating route declares a *mutating* one. This is the check that
//     stops a new endpoint from shipping unguarded.
//  2. Disclosure — an unauthorized caller gets 404 for scopes it cannot
//     read and 403 only where it already has read access, so error codes
//     are not an existence oracle.
//  3. Permission resolution end to end — group claims from a real ID token
//     become the permission set the frontend gates on.
//  4. Backwards compatibility — with OIDC disabled, and with OIDC enabled
//     but no policy configured, nothing changes.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/pkg/authz"
	"github.com/blechschmidt/cloop/pkg/eventlog"
)

// mutatingMethods are the HTTP verbs that change state.
var mutatingMethods = map[string]bool{
	http.MethodPost:   true,
	http.MethodPut:    true,
	http.MethodPatch:  true,
	http.MethodDelete: true,
}

// isMutatingPermission reports whether perm gates a state change. Only the
// two read permissions are non-mutating; PermPublic is neither (it means
// "unguarded") and is handled separately by the public allowlist.
func isMutatingPermission(perm authz.Permission) bool {
	switch perm {
	case authz.PermProjectRead, authz.PermExecutorRead, authz.PermPublic, "":
		return false
	}
	return true
}

// splitPattern breaks "POST /api/foo" into its method and path. An empty
// method means the route accepts every verb and does its own checking.
func splitPattern(pattern string) (method, path string) {
	if i := strings.Index(pattern, " "); i > 0 {
		return pattern[:i], strings.TrimSpace(pattern[i+1:])
	}
	return "", pattern
}

// publicRouteAllowlist is the complete set of routes permitted to declare
// authz.PermPublic. Making a route public is a security decision, so it
// requires editing this list — a new unguarded route cannot appear by
// accident or by copy-paste.
var publicRouteAllowlist = map[string]string{
	"/":                      "the SPA shell; authMiddleware already gated whether this caller may load it",
	"/assets/":               "content-hashed CSS/JS served same-origin for the CSP",
	"GET /auth/login":        "login machinery — gating it would require being signed in to sign in",
	"GET /auth/callback":     "login machinery",
	"POST /auth/logout":      "signing out must always be possible",
	"POST /api/session/logout-all": "ends only the caller's own sessions, scoped to their session's subject " +
		"and taking no id — there is no parameter that could reach someone else's, and requiring a " +
		"permission would put an operator in the path of the one action a user must be able to take " +
		"immediately after losing a device",
	"GET /api/me":            "reports the caller's own permissions; the UI cannot render without it",
	"POST /api/client-error": "browser error reports; writes no state and must work for a user with no role",
}

// TestEveryRouteDeclaresAPermission is the route-coverage check: every entry
// in the table passes validation, and no route is public unless it is on the
// reviewed allowlist.
func TestEveryRouteDeclaresAPermission(t *testing.T) {
	t.Parallel()

	srv := &Server{WorkDir: t.TempDir()}
	table := srv.routeTable()
	if len(table) == 0 {
		t.Fatal("routeTable() is empty — the discovery path broke")
	}

	seen := map[string]bool{}
	for _, rs := range table {
		if err := rs.validate(); err != nil {
			t.Errorf("invalid route spec: %v", err)
			continue
		}
		if seen[rs.Pattern] {
			t.Errorf("route %q is registered twice — http.ServeMux would panic", rs.Pattern)
		}
		seen[rs.Pattern] = true

		if rs.Perm == authz.PermPublic {
			if _, ok := publicRouteAllowlist[rs.Pattern]; !ok {
				t.Errorf("route %q declares PermPublic but is not on publicRouteAllowlist.\n"+
					"Making a route unauthenticated is a security decision: add it to the "+
					"allowlist in authz_test.go with a justification, or give it a real permission.",
					rs.Pattern)
			}
		}
	}

	// A stale allowlist entry is a route that was deleted or locked down;
	// leaving it behind would let a future route silently reuse the name.
	for pattern := range publicRouteAllowlist {
		if !seen[pattern] {
			t.Errorf("publicRouteAllowlist names %q, which is no longer registered — remove the stale entry", pattern)
		}
	}
}

// TestMutatingRoutesRequireMutatingPermissions is the property that actually
// prevents privilege escalation: a route that changes state must not be
// gated on a read permission.
//
// Two classes of route are checked:
//
//   - Method-prefixed routes ("POST /api/tasks"): the verb is in the
//     pattern, so the requirement is directly checkable.
//   - Prefix-less routes ("/api/run"): the handler does its own method
//     check, so the handler body is scanned for evidence that it accepts a
//     mutating verb, and the permission that would apply to that verb is
//     the one checked.
func TestMutatingRoutesRequireMutatingPermissions(t *testing.T) {
	t.Parallel()

	srv := &Server{WorkDir: t.TempDir()}
	sources := serverSource + "\n" + providerCallsSource + "\n" + executorsAPISource +
		"\n" + routesSource + "\n" + installScriptSource
	handlerNames := handlerNamesByPattern()

	for _, rs := range srv.routeTable() {
		if rs.Perm == authz.PermPublic {
			continue // covered by the allowlist test
		}
		method, _ := splitPattern(rs.Pattern)

		if method != "" {
			if !mutatingMethods[method] {
				continue
			}
			if !isMutatingPermission(rs.permFor(method)) {
				t.Errorf("route %q is a %s (state-changing) but requires only %q — "+
					"a read permission must not authorize a mutation",
					rs.Pattern, method, rs.permFor(method))
			}
			continue
		}

		// Prefix-less route: find which verbs the handler accepts.
		handler := handlerNames[rs.Pattern]
		if handler == "" {
			t.Errorf("route %q: could not determine its handler name from routes.go — "+
				"the extraction regex in handlerNamesByPattern broke", rs.Pattern)
			continue
		}
		body := handlerBody(sources, handler)
		if body == "" {
			t.Errorf("route %q: handler %s not found in the embedded sources", rs.Pattern, handler)
			continue
		}
		for verb, marker := range map[string][]string{
			http.MethodPost:   {"requirePOST(", "http.MethodPost"},
			http.MethodPut:    {"http.MethodPut"},
			http.MethodPatch:  {"http.MethodPatch"},
			http.MethodDelete: {"http.MethodDelete"},
		} {
			if !containsAnyMarker(body, marker) {
				continue
			}
			if !isMutatingPermission(rs.permFor(verb)) {
				t.Errorf("route %q (handler %s) accepts %s but that verb resolves to %q — "+
					"add a MethodPerms entry or raise Perm",
					rs.Pattern, handler, verb, rs.permFor(verb))
			}
		}
	}
}

// TestRegisterRoutesUsesTheRouteTable is the anti-drift backstop. Enforcement
// lives in gate(), which registerRoutes applies to every table entry; a raw
// mux.HandleFunc would bypass it entirely. The only permitted call site is
// the one inside the table loop.
func TestRegisterRoutesUsesTheRouteTable(t *testing.T) {
	t.Parallel()

	// Any mux.HandleFunc whose first argument is a string literal is a
	// hand-registered route that skipped the permission gate.
	re := regexp.MustCompile(`mux\.HandleFunc\("`)
	for _, src := range []struct{ name, body string }{
		{"routes.go", routesSource},
		{"server.go", serverSource},
		{"executors_api.go", executorsAPISource},
		{"provider_calls.go", providerCallsSource},
	} {
		if loc := re.FindStringIndex(src.body); loc != nil {
			line := 1 + strings.Count(src.body[:loc[0]], "\n")
			t.Errorf("%s:%d registers a route with a literal path via mux.HandleFunc, "+
				"bypassing the permission gate. Add it to routeTable() in routes.go instead.",
				src.name, line)
		}
	}

	// And the table loop must still be the thing that registers.
	if !strings.Contains(routesSource, "mux.HandleFunc(rs.Pattern, s.gate(rs))") {
		t.Error("registerRoutes no longer wires the route table through s.gate — " +
			"permissions would not be enforced")
	}
}

// handlerNamesByPattern maps each route pattern to its handler method name,
// read from the route table source.
func handlerNamesByPattern() map[string]string {
	re := regexp.MustCompile(`Pattern:\s*"([^"]+)",\s*Handler:\s*s\.([a-zA-Z]+),`)
	out := map[string]string{}
	for _, m := range re.FindAllStringSubmatch(routesSource, -1) {
		out[m[1]] = m[2]
	}
	return out
}

// handlerBody returns the source of the named Server method, bounded by the
// next top-level func declaration. Returns "" when not found.
func handlerBody(src, name string) string {
	sig := "func (s *Server) " + name + "("
	i := strings.Index(src, sig)
	if i < 0 {
		return ""
	}
	rest := src[i+len(sig):]
	if rel := strings.Index(rest, "\nfunc "); rel >= 0 {
		return rest[:rel]
	}
	return rest
}

func containsAnyMarker(s string, needles []string) bool {
	for _, n := range needles {
		if strings.Contains(s, n) {
			return true
		}
	}
	return false
}

// ── End-to-end enforcement ──────────────────────────────────────────────────

// rbacFixture is one OIDC-enabled dashboard plus a signed-in client for each
// role under test.
//
// Building a server and driving a full login flow per test is expensive under
// -race — enough that a dozen of them measurably load the machine and flake
// the package's wall-clock deadline tests. One fixture serves every
// enforcement assertion: the policy is fixed, and each client differs only in
// the group claim its ID token carried.
type rbacFixture struct {
	srv *Server
	ts  *httptest.Server

	viewer   *http.Client // group "readers"   → viewer
	operator *http.Client // group "engineers" → operator
	admin    *http.Client // group "owners"    → admin
	unmapped *http.Client // no matching group → deny-by-default
}

// newRBACFixture builds the shared server and logs each client in. The IdP's
// released groups are flipped between logins, which is safe because logins are
// sequential here.
func newRBACFixture(t *testing.T) *rbacFixture {
	t.Helper()

	idp := newUIFakeIdP(t)
	srv, ts := newOIDCTestServer(t, idp, "", nil)

	resolver, err := authz.New(rbacPolicy())
	if err != nil {
		t.Fatalf("authz.New: %v", err)
	}
	srv.Authz = resolver

	loginAs := func(groups []string) *http.Client {
		idp.groups = groups
		c := jarClient(t)
		login(t, c, ts)
		return c
	}
	return &rbacFixture{
		srv:      srv,
		ts:       ts,
		viewer:   loginAs([]string{"readers"}),
		operator: loginAs([]string{"engineers"}),
		// "/owners" exercises the Keycloak group-path form against the
		// bare "owners" binding in one go.
		admin:    loginAs([]string{"/owners"}),
		unmapped: loginAs([]string{"contractors-with-no-binding"}),
	}
}

// rbacPolicy is the policy the shared fixture enforces.
func rbacPolicy() authz.Config {
	return authz.Config{
		Bindings: []authz.Binding{
			{Claim: authz.ClaimGroup, Value: "readers", Role: authz.RoleViewer},
			{Claim: authz.ClaimGroup, Value: "engineers", Role: authz.RoleOperator},
			{Claim: authz.ClaimGroup, Value: "owners", Role: authz.RoleAdmin},
		},
	}
}

// do issues a request with the signed-in jar client and returns the status.
func do(t *testing.T, c *http.Client, method, url string, body string) (int, string) {
	t.Helper()
	var rdr *strings.Reader
	if body == "" {
		rdr = strings.NewReader("")
	} else {
		rdr = strings.NewReader(body)
	}
	req, err := http.NewRequest(method, url, rdr)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, url, err)
	}
	defer resp.Body.Close()
	buf := make([]byte, 4096)
	n, _ := resp.Body.Read(buf)
	return resp.StatusCode, string(buf[:n])
}

// TestEnforcementAcrossRoles drives every role in the ladder against the same
// server, asserting what each may and may not do — and, crucially, which
// status code a denial produces.
func TestEnforcementAcrossRoles(t *testing.T) {
	f := newRBACFixture(t)

	// ── Viewer: can read, cannot act. Denials are 403 because the viewer
	// already has read access, so the resource's existence is not a secret.
	t.Run("viewer reads succeed", func(t *testing.T) {
		if code, body := do(t, f.viewer, http.MethodGet, f.ts.URL+"/api/state", ""); code != http.StatusOK {
			t.Fatalf("viewer GET /api/state = %d, want 200 (body: %s)", code, body)
		}
	})

	viewerDenied := []struct{ method, path, body string }{
		{http.MethodPost, "/api/run", `{}`},
		{http.MethodPost, "/api/stop", `{}`},
		{http.MethodPost, "/api/tasks", `{"title":"x"}`},
		{http.MethodPost, "/api/task/add", `{"title":"x"}`},
		{http.MethodDelete, "/api/tasks/1", ""},
		{http.MethodPost, "/api/options/toggle", `{"flag":"auto_evolve","value":true}`},
		{http.MethodPost, "/api/reset", `{}`},
		{http.MethodPost, "/api/executors/enroll", `{}`},
	}
	for _, m := range viewerDenied {
		t.Run("viewer 403 on "+m.method+" "+m.path, func(t *testing.T) {
			code, body := do(t, f.viewer, m.method, f.ts.URL+m.path, m.body)
			if code != http.StatusForbidden {
				t.Fatalf("= %d, want 403 (body: %s)", code, body)
			}
			var env struct {
				Error struct {
					Code    string         `json:"code"`
					Message string         `json:"message"`
					Details map[string]any `json:"details"`
				} `json:"error"`
			}
			if err := json.Unmarshal([]byte(body), &env); err != nil {
				t.Fatalf("403 body is not the structured error shape: %v (body: %s)", err, body)
			}
			if env.Error.Code != "FORBIDDEN" {
				t.Errorf("error.code = %q, want FORBIDDEN", env.Error.Code)
			}
			if env.Error.Details["required_permission"] == nil {
				t.Error("403 should name the required permission so the UI can explain it")
			}
			// The denial must not echo policy internals back to the caller.
			if strings.Contains(body, "binding") {
				t.Errorf("403 body leaks policy internals: %s", body)
			}
		})
	}

	// ── Operator: drives execution, cannot reconfigure.
	operatorAllowed := []struct{ method, path, body string }{
		{http.MethodGet, "/api/state", ""},
		{http.MethodPost, "/api/tasks", `{"title":"from operator"}`},
	}
	for _, a := range operatorAllowed {
		t.Run("operator allowed "+a.method+" "+a.path, func(t *testing.T) {
			if code, body := do(t, f.operator, a.method, f.ts.URL+a.path, a.body); code == http.StatusForbidden || code == http.StatusNotFound {
				t.Errorf("= %d, want it allowed (body: %s)", code, body)
			}
		})
	}
	operatorDenied := []struct{ method, path, body string }{
		{http.MethodPost, "/api/options/toggle", `{"flag":"auto_evolve","value":true}`},
		{http.MethodPost, "/api/config/set", `{"key":"provider","value":"ollama"}`},
		{http.MethodPost, "/api/executors/enroll", `{}`},
		{http.MethodPost, "/api/reset", `{}`},
	}
	for _, d := range operatorDenied {
		t.Run("operator 403 on "+d.method+" "+d.path, func(t *testing.T) {
			if code, body := do(t, f.operator, d.method, f.ts.URL+d.path, d.body); code != http.StatusForbidden {
				t.Errorf("= %d, want 403 (body: %s)", code, body)
			}
		})
	}

	// ── Unmapped user: must not be able to tell a project it cannot read
	// from one that does not exist.
	unmappedProjectRoutes := []struct{ method, path, body string }{
		{http.MethodGet, "/api/state", ""},
		{http.MethodGet, "/api/tasks", ""},
		{http.MethodPost, "/api/run", `{}`},
		{http.MethodPost, "/api/tasks", `{"title":"x"}`},
		{http.MethodGet, "/api/analytics", ""},
	}
	for _, r := range unmappedProjectRoutes {
		t.Run("unmapped 404 on "+r.method+" "+r.path, func(t *testing.T) {
			code, body := do(t, f.unmapped, r.method, f.ts.URL+r.path, r.body)
			if code != http.StatusNotFound {
				t.Fatalf("= %d, want 404 (body: %s)", code, body)
			}
			// Identical to a genuine miss: no hint that this was an
			// authorization failure.
			low := strings.ToLower(body)
			if strings.Contains(low, "permission") || strings.Contains(low, "role") ||
				strings.Contains(low, "forbidden") {
				t.Errorf("404 body discloses that this is an authorization failure: %s", body)
			}
		})
	}
	t.Run("unmapped 403 on a global scope", func(t *testing.T) {
		// Global scope has no existence to protect, so 403 is correct.
		if code, _ := do(t, f.unmapped, http.MethodPost, f.ts.URL+"/api/executors/enroll", `{}`); code != http.StatusForbidden {
			t.Errorf("= %d, want 403", code)
		}
	})

	// ── An index the caller cannot see is nonexistent, not forbidden.
	for _, idx := range []string{"99", "abc"} {
		t.Run("unreadable project_idx="+idx+" is 404", func(t *testing.T) {
			if code, body := do(t, f.admin, http.MethodGet, f.ts.URL+"/api/state?project_idx="+idx, ""); code != http.StatusNotFound {
				t.Errorf("= %d, want 404 (body: %s)", code, body)
			}
		})
	}

	// ── /api/me is what the frontend gates its controls on.
	t.Run("me reports the viewer permission set", func(t *testing.T) {
		code, body := do(t, f.viewer, http.MethodGet, f.ts.URL+"/api/me", "")
		if code != http.StatusOK {
			t.Fatalf("GET /api/me = %d, want 200", code)
		}
		var me struct {
			OIDCEnabled       bool     `json:"oidc_enabled"`
			Authenticated     bool     `json:"authenticated"`
			Role              string   `json:"role"`
			Permissions       []string `json:"permissions"`
			GlobalPermissions []string `json:"global_permissions"`
		}
		if err := json.Unmarshal([]byte(body), &me); err != nil {
			t.Fatalf("/api/me is not JSON: %v (body: %s)", err, body)
		}
		if !me.OIDCEnabled || !me.Authenticated {
			t.Errorf("oidc_enabled=%v authenticated=%v, want both true", me.OIDCEnabled, me.Authenticated)
		}
		if me.Role != "viewer" {
			t.Errorf("role = %q, want viewer", me.Role)
		}
		sort.Strings(me.Permissions)
		if want := "executor.read,project.read"; strings.Join(me.Permissions, ",") != want {
			t.Errorf("permissions = %v, want [%s]", me.Permissions, want)
		}
		if me.GlobalPermissions == nil {
			t.Error("global_permissions must be present so fleet tabs can be gated")
		}
	})

	// ── Claim-shape end to end: the admin client logged in with the
	// Keycloak group-path form "/owners" against a bare "owners" binding.
	t.Run("keycloak group path matches a bare binding", func(t *testing.T) {
		code, body := do(t, f.admin, http.MethodGet, f.ts.URL+"/api/me", "")
		if code != http.StatusOK {
			t.Fatalf("GET /api/me = %d", code)
		}
		var me struct {
			Role string `json:"role"`
		}
		if err := json.Unmarshal([]byte(body), &me); err != nil {
			t.Fatalf("decode /api/me: %v", err)
		}
		if me.Role != "admin" {
			t.Errorf("role = %q, want admin — '/owners' should match the bare 'owners' binding", me.Role)
		}
	})

	// ── Audit: denials always, privileged grants too, routine reads never.
	t.Run("decisions are audited", func(t *testing.T) {
		log, err := eventlog.Open(f.srv.WorkDir)
		if err != nil {
			t.Fatalf("open event log: %v", err)
		}
		defer log.Close()
		events, _, err := log.List(eventlog.AuditFilter{})
		if err != nil {
			t.Fatalf("list audit events: %v", err)
		}

		var denials, grants, readGrants int
		for _, ev := range events {
			switch ev.EventType {
			case "authz.denied":
				denials++
				if ev.Actor != "alice@example.com" {
					t.Errorf("denial recorded actor %q, want the acting subject", ev.Actor)
				}
				if !strings.Contains(ev.Payload, `"outcome":"denied"`) {
					t.Errorf("denial payload missing outcome: %s", ev.Payload)
				}
			case "authz.granted":
				if strings.Contains(ev.Payload, `"permission":"project.read"`) {
					readGrants++
				}
				if strings.Contains(ev.Payload, `"permission":"task.mutate"`) {
					grants++
					if ev.Actor != "alice@example.com" {
						t.Errorf("grant recorded actor %q, want the acting subject", ev.Actor)
					}
				}
			}
		}
		if denials == 0 {
			t.Error("no authz.denied record was written for the rejected mutations")
		}
		if grants == 0 {
			t.Error("no authz.granted record for the operator's permitted task.mutate")
		}
		if readGrants > 0 {
			t.Errorf("%d routine read grants were audited — the log would drown in dashboard polling", readGrants)
		}
		report, err := log.Verify()
		if err != nil {
			t.Fatalf("verify audit chain: %v", err)
		}
		if !report.OK {
			t.Errorf("audit chain broken after authz appends: %+v", report)
		}
	})
}

// TestScopedBindingEnforcedPerProject drives the scoped-precedence rule
// through the HTTP layer: the same user is an operator on one project and a
// viewer on another, and the API agrees as they switch.
func TestScopedBindingEnforcedPerProject(t *testing.T) {
	dirB := setupProjectDir(t, "project B", nil)

	idp := newUIFakeIdP(t)
	idp.groups = []string{"engineers"}
	srv, ts := newOIDCTestServer(t, idp, "", nil)
	// The server's own workdir is project 0; dirB becomes project 1.
	srv.Projects = []string{dirB}

	absB, err := filepath.Abs(dirB)
	if err != nil {
		t.Fatalf("abs(%s): %v", dirB, err)
	}
	resolver, err := authz.New(authz.Config{
		Bindings: []authz.Binding{
			// Operator everywhere…
			{Claim: authz.ClaimGroup, Value: "engineers", Role: authz.RoleOperator},
			// …but held down to viewer on project B, bound by path.
			{Claim: authz.ClaimGroup, Value: "engineers", Role: authz.RoleViewer, Project: absB},
		},
	})
	if err != nil {
		t.Fatalf("authz.New: %v", err)
	}
	srv.Authz = resolver

	c := jarClient(t)
	login(t, c, ts)

	// Both projects are readable.
	for _, idx := range []string{"0", "1"} {
		if code, body := do(t, c, http.MethodGet, ts.URL+"/api/state?project_idx="+idx, ""); code != http.StatusOK {
			t.Errorf("GET /api/state?project_idx=%s = %d, want 200 (body: %s)", idx, code, body)
		}
	}

	// Project 0: the global operator binding applies.
	if code, body := do(t, c, http.MethodPost, ts.URL+"/api/tasks?project_idx=0", `{"title":"on A"}`); code == http.StatusForbidden {
		t.Errorf("operator POST /api/tasks on project 0 = 403, want allowed (body: %s)", body)
	}
	// Project 1: the path-scoped downgrade to viewer applies.
	if code, body := do(t, c, http.MethodPost, ts.URL+"/api/tasks?project_idx=1", `{"title":"on B"}`); code != http.StatusForbidden {
		t.Errorf("viewer-on-B POST /api/tasks = %d, want 403 (body: %s)", code, body)
	}
}

// TestOIDCDisabledGrantsEverything is the backwards-compatibility guarantee:
// single-tenant local use must not change at all.
func TestOIDCDisabledGrantsEverything(t *testing.T) {
	dir := setupProjectDir(t, cloopGoal, nil)
	srv := New(dir, 0, "")
	// A resolver that would deny everything, to prove it is not consulted.
	resolver, err := authz.New(authz.Config{DefaultRole: authz.RoleNone})
	if err != nil {
		t.Fatalf("authz.New: %v", err)
	}
	srv.Authz = resolver
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	if srv.authzActive() {
		t.Fatal("RBAC must not be active with OIDC disabled")
	}
	for _, path := range []string{"/", "/api/state", "/api/tasks", "/api/executors"} {
		resp, err := http.Get(ts.URL + path)
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		resp.Body.Close()
		if resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusNotFound {
			t.Errorf("GET %s = %d with OIDC disabled — behavior changed", path, resp.StatusCode)
		}
	}

	// /api/me must still report a full permission set so the frontend
	// renders every control locally.
	me := apiGET(t, ts, "/api/me")
	perms, _ := me["permissions"].([]any)
	if len(perms) != len(authz.AllPermissions) {
		t.Errorf("/api/me reported %d permissions with OIDC disabled, want all %d",
			len(perms), len(authz.AllPermissions))
	}
}

// TestOIDCEnabledWithoutPolicyKeepsLegacyBehavior guards the upgrade path:
// a deployment that turned on SSO before RBAC existed has no role_mappings,
// and enforcing an empty policy would lock every user out of their own
// dashboard.
func TestOIDCEnabledWithoutPolicyKeepsLegacyBehavior(t *testing.T) {
	idp := newUIFakeIdP(t)
	srv, ts := newOIDCTestServer(t, idp, "", nil)

	// Exactly what cmd/ui_cmd.go builds when no role_mappings are set.
	resolver, err := authz.New(authz.Config{})
	if err != nil {
		t.Fatalf("authz.New: %v", err)
	}
	srv.Authz = resolver

	if srv.authzActive() {
		t.Fatal("RBAC must not be active without a configured policy")
	}

	c := jarClient(t)
	login(t, c, ts)
	for _, path := range []string{"/api/state", "/api/tasks", "/api/projects"} {
		if code, body := do(t, c, http.MethodGet, ts.URL+path, ""); code != http.StatusOK {
			t.Errorf("GET %s = %d without a configured policy, want 200 (body: %s)", path, code, body)
		}
	}
}

// TestStaticTokenBypassesRBAC keeps API automation working: the bearer token
// is the deployment's own secret, so presenting it is an operator
// credential, exactly as it was before RBAC.
func TestStaticTokenBypassesRBAC(t *testing.T) {
	idp := newUIFakeIdP(t)
	srv, ts := newOIDCTestServer(t, idp, "s3cret", nil)
	resolver, err := authz.New(authz.Config{DefaultRole: authz.RoleNone})
	if err != nil {
		t.Fatalf("authz.New: %v", err)
	}
	srv.Authz = resolver

	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/state", nil)
	req.Header.Set("Authorization", "Bearer s3cret")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("token request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("token-authenticated GET /api/state = %d, want 200", resp.StatusCode)
	}
}

// ── Frontend gating ─────────────────────────────────────────────────────────

// TestFrontendPermissionAttributesAreValid checks that every data-perm /
// data-global-perm attribute in the dashboard names a real permission. A
// typo would silently gate nothing (can() would compare against a string the
// server never emits), leaving a control visible that 403s on click.
func TestFrontendPermissionAttributesAreValid(t *testing.T) {
	t.Parallel()

	valid := map[string]bool{}
	for _, p := range authz.AllPermissions {
		valid[string(p)] = true
	}

	re := regexp.MustCompile(`data-(?:global-)?perm="([^"]+)"`)
	matches := re.FindAllStringSubmatch(dashboardSource, -1)
	if len(matches) == 0 {
		t.Fatal("no data-perm attributes found — the frontend does not gate any control on permissions")
	}
	for _, m := range matches {
		if !valid[m[1]] {
			t.Errorf("dashboard gates a control on %q, which is not a known permission "+
				"(see authz.AllPermissions) — the gate would never deny", m[1])
		}
	}
}

// TestFrontendGatesTheHighRiskControls names the controls that must not be
// clickable by a role that cannot use them. These are the actions that spend
// money, change what code runs, or reshape a project.
func TestFrontendGatesTheHighRiskControls(t *testing.T) {
	t.Parallel()

	required := []struct{ marker, perm, why string }{
		{`id="ctrlRun"`, "run.start", "starting a run spends the token budget"},
		{`id="ctrlStop"`, "run.stop", "stopping a run"},
		{`id="goalEditBtn"`, "project.write", "changing the goal reshapes the project"},
		{`id="instructionsEditBtn"`, "project.write", "changing instructions reshapes the project"},
		{`onclick="submitAddTask()"`, "task.mutate", "adding a task"},
		{`id="suggestBtn"`, "task.mutate", "brainstorming spends provider budget"},
		{`onclick="openEnrollModal()"`, "executor.manage", "enrolling a device lets it run workloads"},
	}
	for _, r := range required {
		t.Run(r.perm+" on "+r.marker, func(t *testing.T) {
			i := strings.Index(dashboardSource, r.marker)
			if i < 0 {
				t.Fatalf("control %s no longer exists in the dashboard — update this test", r.marker)
			}
			// Scan the enclosing tag for the permission attribute.
			start := strings.LastIndex(dashboardSource[:i], "<")
			end := strings.Index(dashboardSource[i:], ">")
			if start < 0 || end < 0 {
				t.Fatalf("could not isolate the tag around %s", r.marker)
			}
			tag := dashboardSource[start : i+end]
			if !strings.Contains(tag, `data-perm="`+r.perm+`"`) &&
				!strings.Contains(tag, `data-global-perm="`+r.perm+`"`) {
				t.Errorf("control %s is not gated on %q (%s).\nTag: %s",
					r.marker, r.perm, r.why, tag)
			}
		})
	}
}

// TestFrontendHandles403Gracefully checks the client degrades instead of
// failing silently when the server denies an action: both API helpers must
// route through the shared response parser, and that parser must explain a
// 403 and re-resolve the permission set (which a policy change may have
// altered under the client).
func TestFrontendHandles403Gracefully(t *testing.T) {
	t.Parallel()

	required := []struct{ snippet, why string }{
		{"function parseAPIResponse(r)", "the shared response parser must exist"},
		{"if (r.status === 403)", "403 must be handled distinctly from other errors"},
		{"function handleForbidden(", "denials need a dedicated explanation path"},
		{"refreshPermissions()", "a 403 means the client's permission view is stale"},
		{"function applyPermissionGating(", "controls must be hidden/disabled by permission"},
		{"return fetch(url, opts).then(parseAPIResponse);", "api() must use the shared parser"},
	}
	for _, r := range required {
		if !strings.Contains(dashboardSource, r.snippet) {
			t.Errorf("dashboard is missing %q — %s", r.snippet, r.why)
		}
	}

	// Neither helper may keep its own 401-only handling, which would let a
	// 403 fall through to .json() and surface as an unexplained failure.
	if strings.Count(dashboardSource, "if (r.status === 401) { showLoginModal(); return Promise.reject(new Error('401')); }") > 1 {
		t.Error("more than one inline 401 handler remains — every API helper should " +
			"route through parseAPIResponse so 403s are handled uniformly")
	}
}

// TestUnresolvableProjectIdxDoesNotFallBackToGlobalScope is a regression
// guard for a fail-open in scope derivation.
//
// The zero authz.Scope *is* the global scope. If an unresolvable {idx} path
// segment produced the zero Scope, the permission would be evaluated against
// the caller's fleet-wide authority — so a user holding a global run.start
// could pass the gate for a project index they cannot see, and only the
// handler's own range check would stop them. The gate must refuse first.
func TestUnresolvableProjectIdxDoesNotFallBackToGlobalScope(t *testing.T) {
	idp := newUIFakeIdP(t)
	idp.groups = []string{"engineers"}
	srv, ts := newOIDCTestServer(t, idp, "", nil)

	// A globally-scoped operator: holds run.start everywhere.
	resolver, err := authz.New(authz.Config{
		Bindings: []authz.Binding{
			{Claim: authz.ClaimGroup, Value: "engineers", Role: authz.RoleOperator},
		},
	})
	if err != nil {
		t.Fatalf("authz.New: %v", err)
	}
	srv.Authz = resolver

	c := jarClient(t)
	login(t, c, ts)

	// Sanity: a resolvable index is not refused. Asserted on a read-only
	// route on purpose — POSTing to .../run would start an actual workload
	// and register a live executor session that outlives this test, which
	// pollutes global fleet state for the rest of the package.
	if code, body := do(t, c, http.MethodGet, ts.URL+"/api/state?project_idx=0", ""); code != http.StatusOK {
		t.Fatalf("GET /api/state?project_idx=0 = %d for a resolvable index (body: %s)", code, body)
	}

	for _, idx := range []string{"99", "-1", "abc"} {
		t.Run("idx="+idx, func(t *testing.T) {
			code, body := do(t, c, http.MethodPost, ts.URL+"/api/projects/"+idx+"/run", `{}`)
			if code != http.StatusNotFound {
				t.Errorf("POST /api/projects/%s/run = %d, want 404 — an unresolvable "+
					"index must not be evaluated against the global scope (body: %s)",
					idx, code, body)
			}
		})
	}
}

// TestScopeForNeverSilentlyWidens asserts the invariant directly, so the
// property survives even if the routes above change shape.
func TestScopeForNeverSilentlyWidens(t *testing.T) {
	t.Parallel()

	srv := &Server{WorkDir: t.TempDir()}
	req := httptest.NewRequest(http.MethodPost, "/api/projects/99/run", nil)
	req.SetPathValue("idx", "99")

	scope, ok := srv.scopeFor(scopeProjectIdx, req)
	if ok {
		t.Fatal("an out-of-range project index reported ok=true")
	}
	if !scope.IsGlobal() {
		t.Fatal("test assumption broken: the unresolved scope is expected to be the zero value")
	}
	// The point: ok=false is the ONLY thing distinguishing this from a
	// legitimate global-scope request, so callers must honour it.
	if globalScope, globalOK := srv.scopeFor(scopeGlobal, req); !globalOK || globalScope != scope {
		t.Error("an unresolved project scope must be indistinguishable from the global " +
			"scope by value alone — which is exactly why gate() must check ok")
	}
}

// TestNoAuditWritesWhenRBACIsInactive pins a behavioural *and* performance
// invariant. With OIDC disabled every request is granted everything, so an
// authz record would say nothing beyond "a request happened" — while costing
// a SQLite open on every mutation. Auditing unconditionally regressed the
// single-tenant hot path (and tripled the package's -race runtime) before
// this guard was added.
func TestNoAuditWritesWhenRBACIsInactive(t *testing.T) {
	dir := setupProjectDir(t, cloopGoal, nil)
	srv := New(dir, 0, "")
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	if srv.authzActive() {
		t.Fatal("test assumption broken: RBAC should be inactive with OIDC disabled")
	}

	// Drive a privileged mutation that would otherwise be audited.
	c := &http.Client{}
	if code, _ := do(t, c, http.MethodPost, ts.URL+"/api/tasks", `{"title":"local task"}`); code >= 500 {
		t.Fatalf("POST /api/tasks failed with %d", code)
	}

	log, err := eventlog.Open(dir)
	if err != nil {
		t.Fatalf("open event log: %v", err)
	}
	defer log.Close()
	events, _, err := log.List(eventlog.AuditFilter{})
	if err != nil {
		t.Fatalf("list audit events: %v", err)
	}
	for _, ev := range events {
		if strings.HasPrefix(ev.EventType, "authz.") {
			t.Errorf("authz record %q written with RBAC inactive — single-tenant "+
				"behavior must be unchanged and the mutation path must not pay "+
				"for an audit open", ev.EventType)
		}
	}
}
