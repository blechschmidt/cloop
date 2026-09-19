package ui

// Who may edit ui.oidc (Task 20308).
//
// These go through the real route table and the real gate rather than calling
// the handlers, because the question is about the gate, and the gate is the part
// that is easy to get subtly wrong: authzActive, authzActiveFor and authzGateFor
// mean three different things, and widening the wrong one has previously granted
// fleet admin.
//
// Two properties, pulling in opposite directions:
//
//	a token-only hub must be able to turn SSO on   — or the feature is
//	                                                 unreachable on exactly the
//	                                                 deployments that need it
//	a non-admin must never be able to touch it      — writing this block is
//	                                                 equivalent to granting
//	                                                 oneself a role

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/blechschmidt/cloop/pkg/authz"
)

// TestOIDCConfig_ReachableOnATokenOnlyHub is the bootstrapping case, and it is
// the one that makes the panel usable at all: a hub with no identity provider
// configured yet has nobody holding user.manage by claim, so if the gate
// resolved to a deny there the only way to enable SSO would still be a shell on
// the box.
//
// It works because RBAC is inactive without an IdP and the request resolves to
// an allow-all bypass — the static bearer token being that deployment's root
// credential. This test exists so that a future change to the bypass rules
// cannot quietly close the door.
func TestOIDCConfig_ReachableOnATokenOnlyHub(t *testing.T) {
	dir := setupProjectDir(t, cloopGoal, nil)
	srv := New(dir, 0, "")
	// A resolver that would deny everything, to prove it is not consulted while
	// OIDC is off.
	resolver, err := authz.New(authz.Config{DefaultRole: authz.RoleNone})
	if err != nil {
		t.Fatalf("authz.New: %v", err)
	}
	srv.Authz = resolver
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	if srv.authzActive() {
		t.Fatal("precondition: RBAC must be inactive with OIDC disabled")
	}

	if code, body := do(t, http.DefaultClient, http.MethodGet, ts.URL+"/api/config/oidc", ""); code != http.StatusOK {
		t.Fatalf("GET /api/config/oidc on a token-only hub = %d, want 200 — "+
			"the panel would be unreachable on exactly the hubs that need it (body: %s)", code, body)
	}

	// And the write works, which is the actual point: this is how SSO gets
	// turned on for the first time.
	body := `{"enabled":true,"issuer":"https://idp.example.com","client_id":"cloop",` +
		`"client_secret":"s3cret","redirect_url":"https://h.example.com/auth/callback",` +
		`"admin_emails":["ops@example.com"]}`
	if code, resp := do(t, http.DefaultClient, http.MethodPut, ts.URL+"/api/config/oidc", body); code != http.StatusOK {
		t.Fatalf("PUT /api/config/oidc on a token-only hub = %d, want 200 (body: %s)", code, resp)
	}
}

// TestOIDCConfig_DeniedToNonAdmins. Once RBAC is in force, the three routes
// must refuse everyone below admin — including a maintainer, who holds
// config.write and could otherwise promote themselves by adding a role mapping.
// That is the whole reason these routes are gated on user.manage rather than on
// the permission every other Settings route uses.
func TestOIDCConfig_DeniedToNonAdmins(t *testing.T) {
	for _, role := range []authz.Role{authz.RoleViewer, authz.RoleOperator, authz.RoleMaintainer} {
		t.Run(string(role), func(t *testing.T) {
			idp := newUIFakeIdP(t)
			idp.groups = []string{"engineers"}
			srv, ts := newOIDCTestServer(t, idp, "", nil)

			resolver, err := authz.New(authz.Config{
				Bindings: []authz.Binding{
					{Claim: authz.ClaimGroup, Value: "engineers", Role: role},
				},
			})
			if err != nil {
				t.Fatalf("authz.New: %v", err)
			}
			srv.Authz = resolver
			if !srv.authzActive() {
				t.Fatal("precondition: RBAC must be active")
			}

			c := jarClient(t)
			login(t, c, ts)

			// The read is gated too: the issuer, client id and redirect URL
			// together are most of what is needed to stand up a convincing fake
			// login page for this hub.
			for _, probe := range []struct{ method, path, body string }{
				{http.MethodGet, "/api/config/oidc", ""},
				{http.MethodPut, "/api/config/oidc", `{"enabled":false}`},
				{http.MethodPost, "/api/config/oidc/test", `{"issuer":"https://idp.example.com"}`},
			} {
				code, respBody := do(t, c, probe.method, ts.URL+probe.path, probe.body)
				// 403 is the refusal; 404 is the narrower refusal the gate uses
				// when the caller cannot read the scope at all. Either is a
				// denial — what must not happen is a 2xx.
				if code != http.StatusForbidden && code != http.StatusNotFound {
					t.Errorf("%s %s as %s = %d, want a denial (body: %s)",
						probe.method, probe.path, role, code, respBody)
				}
			}
		})
	}
}

// TestOIDCConfig_AllowedForAdmins is the other side: the gate must not be so
// tight that the people who are supposed to use it cannot.
func TestOIDCConfig_AllowedForAdmins(t *testing.T) {
	idp := newUIFakeIdP(t)
	idp.groups = []string{"cloop-admins"}
	srv, ts := newOIDCTestServer(t, idp, "", nil)

	resolver, err := authz.New(authz.Config{
		Bindings: []authz.Binding{
			{Claim: authz.ClaimGroup, Value: "cloop-admins", Role: authz.RoleAdmin},
		},
	})
	if err != nil {
		t.Fatalf("authz.New: %v", err)
	}
	srv.Authz = resolver

	c := jarClient(t)
	login(t, c, ts)

	if code, body := do(t, c, http.MethodGet, ts.URL+"/api/config/oidc", ""); code != http.StatusOK {
		t.Errorf("GET /api/config/oidc as admin = %d, want 200 (body: %s)", code, body)
	}
}
