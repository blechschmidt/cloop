package ui

// Proves the runtime deny binding actually bites on the request path
// (Task 20248).
//
// pkg/authz tests that a deny wins the resolution. That is necessary and not
// sufficient: on a hub running without a configured RBAC policy the request
// path never calls Resolve at all — newGrant short-circuits to an allow-all
// bypass — so a deny could be perfectly correct in the resolver and still have
// no effect on any request. That gap is the whole reason DeniedBy is checked
// ahead of the bypass, and it is what these tests hold in place.

import (
	"net/http"
	"testing"

	"github.com/blechschmidt/cloop/pkg/apitoken"
	"github.com/blechschmidt/cloop/pkg/authz"
	"github.com/blechschmidt/cloop/pkg/oidcauth"
)

// denyRuntime is an authz.RuntimeSource over a fixed slice.
type denyRuntime struct{ bindings []authz.Binding }

func (d denyRuntime) RuntimeBindings() []authz.Binding { return d.bindings }

func runtimeDenyResolver(t *testing.T, cfg authz.Config, bindings ...authz.Binding) *authz.Resolver {
	t.Helper()
	normalized := make([]authz.Binding, 0, len(bindings))
	for _, b := range bindings {
		nb, err := authz.NormalizeBinding(b)
		if err != nil {
			t.Fatalf("NormalizeBinding(%+v): %v", b, err)
		}
		normalized = append(normalized, nb)
	}
	cfg.Runtime = denyRuntime{bindings: normalized}
	r, err := authz.New(cfg)
	if err != nil {
		t.Fatalf("authz.New: %v", err)
	}
	return r
}

// TestRuntimeDenyBitesWithoutAConfiguredPolicy is the emergency demotion on
// the deployment shape that most needs it: SSO turned on before RBAC existed,
// so oidc.admin_emails is the only access control and every request takes the
// legacy allow-all path.
func TestRuntimeDenyBitesWithoutAConfiguredPolicy(t *testing.T) {
	idp := newUIFakeIdP(t)
	srv, ts := newOIDCTestServer(t, idp, "", []string{idp.email})

	// Exactly what cmd/ui_cmd.go builds with no role_mappings — plus one deny.
	srv.Authz = runtimeDenyResolver(t, authz.Config{AdminEmails: []string{idp.email}},
		authz.Binding{Claim: authz.ClaimEmail, Value: idp.email, Deny: true})

	if srv.authzActive() {
		t.Fatal("precondition: RBAC must be inactive without a configured policy — " +
			"otherwise this test proves nothing about the bypass")
	}

	c := jarClient(t)
	login(t, c, ts)
	for _, tc := range []struct{ method, path string }{
		{http.MethodGet, "/api/state"},
		{http.MethodPost, "/api/tasks"},
		{http.MethodGet, "/api/sessions"},
		{http.MethodGet, "/api/quotas"},
	} {
		code, body := do(t, c, tc.method, ts.URL+tc.path, `{"title":"x"}`)
		if code == http.StatusOK {
			t.Errorf("%s %s = 200 for a denied identity — the deny did not survive the "+
				"allow-all bypass (body: %s)", tc.method, tc.path, body)
		}
	}
}

// TestRuntimeDenyDeniesOnlyTheNamedIdentity: containment that catches
// bystanders is an outage, and on a hub with no configured policy every other
// user is relying on the same bypass this check runs ahead of.
func TestRuntimeDenyDeniesOnlyTheNamedIdentity(t *testing.T) {
	idp := newUIFakeIdP(t)
	srv, ts := newOIDCTestServer(t, idp, "", nil)

	srv.Authz = runtimeDenyResolver(t, authz.Config{},
		authz.Binding{Claim: authz.ClaimEmail, Value: "someone-else@example.com", Deny: true})

	c := jarClient(t)
	login(t, c, ts)
	for _, path := range []string{"/api/state", "/api/tasks", "/api/projects"} {
		if code, body := do(t, c, http.MethodGet, ts.URL+path, ""); code != http.StatusOK {
			t.Errorf("GET %s = %d for an identity no binding names, want 200 (body: %s)",
				path, code, body)
		}
	}
}

// TestNoRuntimeBindingsLeavesTheBypassAlone: the guard in newGrant costs a
// session lookup, and every hub that has never had an incident must not pay
// it — nor see any behavior change at all.
func TestNoRuntimeBindingsLeavesTheBypassAlone(t *testing.T) {
	idp := newUIFakeIdP(t)
	srv, ts := newOIDCTestServer(t, idp, "", []string{idp.email})
	srv.Authz = runtimeDenyResolver(t, authz.Config{AdminEmails: []string{idp.email}})

	c := jarClient(t)
	login(t, c, ts)
	for _, path := range []string{"/api/state", "/api/tasks", "/api/projects"} {
		if code, body := do(t, c, http.MethodGet, ts.URL+path, ""); code != http.StatusOK {
			t.Errorf("GET %s = %d with an empty runtime layer, want 200 (body: %s)",
				path, code, body)
		}
	}
	if g := srv.newGrant(mustGet(t, ts.URL)); g.subject != nil {
		t.Error("newGrant resolved a session identity with no runtime bindings to match " +
			"it against — the common path is paying for the incident path")
	}
}

// TestRuntimeDenyBeatsAConfiguredAdminOverHTTP is the same precedence pkg/authz
// pins, asserted through the real middleware chain so a regression in how the
// decision reaches require() is caught too.
func TestRuntimeDenyBeatsAConfiguredAdminOverHTTP(t *testing.T) {
	idp := newUIFakeIdP(t)
	idp.groups = []string{"cloop-admins"}
	srv, ts := newOIDCTestServer(t, idp, "", nil)

	adminMapping := authz.Config{
		DefaultRole: authz.RoleViewer,
		Bindings: []authz.Binding{
			{Claim: authz.ClaimGroup, Value: "cloop-admins", Role: authz.RoleAdmin},
		},
	}

	// Without the deny the group mapping grants admin, so /api/sessions —
	// gated on session.admin — is reachable.
	srv.Authz = runtimeDenyResolver(t, adminMapping)
	if !srv.authzActive() {
		t.Fatal("precondition: RBAC must be active with a configured policy")
	}
	c := jarClient(t)
	login(t, c, ts)
	if code, body := do(t, c, http.MethodGet, ts.URL+"/api/sessions", ""); code != http.StatusOK {
		t.Fatalf("precondition: GET /api/sessions = %d for an admin, want 200 (body: %s)", code, body)
	}

	// One deny, and the same signed-in session loses it.
	srv.Authz = runtimeDenyResolver(t, adminMapping,
		authz.Binding{Claim: authz.ClaimEmail, Value: idp.email, Deny: true})
	if code, body := do(t, c, http.MethodGet, ts.URL+"/api/sessions", ""); code == http.StatusOK {
		t.Errorf("GET /api/sessions = 200 after the deny — a demoted admin kept "+
			"session.admin (body: %s)", body)
	}
}

// TestRuntimeBindingDoesNotGrantFleetAdmin is a regression gate on the sharpest
// way this feature could backfire.
//
// requireExecutorAdmin short-circuits on authzActiveFor because a true answer
// there means the route gate already required executor.manage — a richer check
// than the admin_emails list. Runtime bindings must not be folded into that
// predicate: a caller no binding names still resolves through the allow-all
// bypass, so doing it would turn writing one deny about a *third party* into
// fleet-admin for every signed-in user on an admin_emails-only hub. A hardening
// command that escalates privilege when used is the worst outcome available
// here, so it is pinned rather than left to the reading of two predicates.
func TestRuntimeBindingDoesNotGrantFleetAdmin(t *testing.T) {
	idp := newUIFakeIdP(t)
	// The hub trusts somebody else entirely; our user is an ordinary member.
	srv, ts := newOIDCTestServer(t, idp, "", []string{"root@example.com"})
	srv.Authz = runtimeDenyResolver(t, authz.Config{AdminEmails: []string{"root@example.com"}},
		// A deny naming a third party — the operator is tightening, not loosening.
		authz.Binding{Claim: authz.ClaimEmail, Value: "mallory@example.com", Deny: true})

	c := jarClient(t)
	login(t, c, ts)
	for _, tc := range []struct{ method, path, body string }{
		{http.MethodPost, "/api/executors/enroll", `{"name":"rogue"}`},
		{http.MethodDelete, "/api/executors/exec-1", ""},
		{http.MethodPost, "/api/executors/exec-1/cordon", ""},
	} {
		code, body := do(t, c, tc.method, ts.URL+tc.path, tc.body)
		if code != http.StatusForbidden {
			t.Errorf("%s %s = %d for a non-admin, want 403 — writing an unrelated "+
				"runtime binding escalated an ordinary user to fleet admin (body: %s)",
				tc.method, tc.path, code, body)
		}
	}
}

// TestConnectionDeniedCoversBothIdentityShapes. A WebSocket's authority is
// decided once, at upgrade, so the writer loop re-asks this on every ping tick.
// Both shapes a connection can carry have to be covered: the session identity,
// and the owner behind a delegated token — a display-glasses link must not
// outlive the demotion of the person it was minted for.
func TestConnectionDeniedCoversBothIdentityShapes(t *testing.T) {
	dir := setupProjectDir(t, cloopGoal, nil)
	srv := New(dir, 0, "")
	srv.Authz = runtimeDenyResolver(t, authz.Config{},
		authz.Binding{Claim: authz.ClaimEmail, Value: "alice@example.com", Deny: true})

	alice := &oidcauth.Identity{Sub: "sub-alice", Email: "alice@example.com"}
	bob := &oidcauth.Identity{Sub: "sub-bob", Email: "bob@example.com"}

	if b := srv.connectionDenied(alice, nil, dir); b == nil {
		t.Error("a denied identity's open WebSocket was left streaming — containment " +
			"that leaves the data flowing is not containment")
	}
	if b := srv.connectionDenied(bob, nil, dir); b != nil {
		t.Errorf("bob's connection was closed by a binding naming alice: %+v", b)
	}
	if b := srv.connectionDenied(nil,
		&apitoken.Token{Owner: &apitoken.Owner{Sub: alice.Sub, Email: alice.Email}}, dir); b == nil {
		t.Error("a delegated token's connection survived its owner's demotion")
	}
	// A service-account token names no claim, so no binding can match it.
	if b := srv.connectionDenied(nil, &apitoken.Token{}, dir); b != nil {
		t.Errorf("an ownerless token's connection was closed: %+v", b)
	}
	if b := srv.connectionDenied(nil, nil, dir); b != nil {
		t.Error("connectionDenied with no identity returned a binding")
	}
}

// TestConnectionDeniedIsFreeWithoutRuntimeBindings: this runs on every ping of
// every connection, and resolving the scope walks the project registry. A hub
// that has never had an incident must not pay for one.
func TestConnectionDeniedIsFreeWithoutRuntimeBindings(t *testing.T) {
	dir := setupProjectDir(t, cloopGoal, nil)
	srv := New(dir, 0, "")
	srv.Authz = runtimeDenyResolver(t, authz.Config{})

	user := &oidcauth.Identity{Sub: "s", Email: "alice@example.com"}
	if b := srv.connectionDenied(user, nil, dir); b != nil {
		t.Errorf("got %+v with an empty runtime layer, want nil", b)
	}
}

func mustGet(t *testing.T, url string) *http.Request {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	return req
}
