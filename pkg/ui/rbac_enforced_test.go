package ui

// RBAC enforcement as the dashboard reports and changes it (Task 20395).
//
// An SSO hub with no role policy runs with RBAC off: every identity the issuer
// authenticates holds every permission but executor administration. The
// Settings panel said "none — deny by default (recommended)" about such a hub,
// and saving any field of its form wrote default_role: none — switching RBAC
// on, at the next restart, for every identity without a mapping. These tests
// hold the reporters to authz.Enforced, the save path to changing it only on
// request, and the enforce action to keeping every current admin an admin.

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/internal/rbactest"
	"github.com/blechschmidt/cloop/pkg/auditaction"
	"github.com/blechschmidt/cloop/pkg/authz"
	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/eventlog"
	"github.com/blechschmidt/cloop/pkg/oidcauth"
)

// runningHub is a hub whose saved block is o and that runs it, built the way
// `cloop ui` builds its authenticator and resolver at startup.
func runningHub(t *testing.T, o config.OIDCConfig, runtime authz.RuntimeSource) *Server {
	t.Helper()
	srv := oidcTestServer(t, o)
	if o.Enabled {
		auth, err := oidcauth.New(o.AuthConfig())
		if err != nil {
			t.Fatalf("oidcauth.New: %v", err)
		}
		srv.OIDC = auth
	}
	resolver, err := authz.New(o.AuthzConfig(runtime))
	if err != nil {
		t.Fatalf("authz.New: %v", err)
	}
	srv.Authz = resolver
	return srv
}

// meBody calls GET /api/me on srv's handler and decodes it.
func meBody(t *testing.T, srv *Server) map[string]any {
	t.Helper()
	rec := httptest.NewRecorder()
	srv.handleMe(rec, httptest.NewRequest(http.MethodGet, "/api/me", nil))
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode /api/me: %v (%s)", err, rec.Body.String())
	}
	return body
}

// TestRBACReportersAcrossTheMatrix: the Settings view and /api/me give
// authz.Enforced's answer for each of the five blocks, and the view carries the
// saved default_role as it is — unset included — for the select to show.
func TestRBACReportersAcrossTheMatrix(t *testing.T) {
	for _, tc := range rbactest.Matrix() {
		t.Run(tc.Name, func(t *testing.T) {
			srv := runningHub(t, tc.OIDC, nil)
			if srv.authzActive() != tc.Enforced {
				t.Fatalf("authzActive = %v, want %v", srv.authzActive(), tc.Enforced)
			}

			view, err := srv.oidcSettings()
			if err != nil {
				t.Fatalf("read settings: %v", err)
			}
			r := view.RBAC
			if r.Enforced != tc.Enforced || r.SavedEnforced != tc.Enforced {
				t.Errorf("rbac = %+v, want enforced and saved_enforced %v", r, tc.Enforced)
			}
			if view.DefaultRole != tc.OIDC.DefaultRole {
				t.Errorf("default_role = %q, want the saved %q — the select shows the real value",
					view.DefaultRole, tc.OIDC.DefaultRole)
			}
			off := tc.OIDC.Enabled && !tc.Enforced
			if want := config.RBACOff(rbactest.Issuer) + "."; off && r.Warning != want {
				t.Errorf("warning = %q, want %q", r.Warning, want)
			}
			if !off && r.Warning != "" {
				t.Errorf("warning = %q on a hub whose RBAC is not off", r.Warning)
			}
			if r.CanEnforce != off {
				t.Errorf("can_enforce = %v, want %v", r.CanEnforce, off)
			}
			if tc.Enforced && r.DefaultRole != "none" {
				t.Errorf("rbac.default_role = %q, want what an unmapped identity gets: none", r.DefaultRole)
			}
			if view.RestartRequired {
				t.Error("a hub running its saved block asks for a restart")
			}

			if got := meBody(t, srv)["rbac_enforced"]; got != tc.Enforced {
				t.Errorf("/api/me rbac_enforced = %v, want %v", got, tc.Enforced)
			}
		})
	}
}

// formBody is what the Settings form submits for o: every field, the way
// saveOIDCSettings sends them, with defaultRole as its select read.
func formBody(o config.OIDCConfig, defaultRole string) map[string]any {
	return map[string]any{
		"enabled":                  o.Enabled,
		"issuer":                   o.Issuer,
		"client_id":                o.ClientID,
		"redirect_url":             o.RedirectURL,
		"scopes":                   o.Scopes,
		"admin_emails":             o.AdminEmails,
		"default_role":             defaultRole,
		"role_mappings":            o.RoleMappings,
		"session_ttl_hours":        12,
		"idle_timeout_hours":       0,
		"refresh_interval_minutes": 0,
		"max_claim_age_minutes":    0,
		"clock_skew_seconds":       0,
		"require_idp":              false,
		"require_rbac":             false,
		"cookie_secure":            "auto",
	}
}

func savedEnforced(t *testing.T, srv *Server) bool {
	t.Helper()
	enforced, err := savedOIDC(t, srv).RBACEnforced()
	if err != nil {
		t.Fatalf("saved policy: %v", err)
	}
	return enforced
}

// TestOIDCSave_DoesNotSwitchRBACAsASideEffect is the regression test for the
// save side effect. The old panel pre-selected "none" for an unset default role
// and submitted it with every save; on an SSO hub without a policy that put one
// in force and locked out every identity without a mapping at the next restart.
func TestOIDCSave_DoesNotSwitchRBACAsASideEffect(t *testing.T) {
	o := rbactest.Matrix()[2].OIDC // SSO + admin_emails: RBAC off
	srv := oidcTestServer(t, o)

	// The old form's submission: session lifetime changed, "none" riding along.
	rec := putOIDC(t, srv, formBody(o, "none"))
	if rec.Code != http.StatusConflict {
		t.Fatalf("PUT = %d, want 409 — the save would switch RBAC on (%s)", rec.Code, rec.Body.String())
	}
	if env := decodeAPIError(t, rec); env.Error.Details["rbac_change"] != rbacChangeTurnsOn ||
		!strings.Contains(env.Error.Message, "turns RBAC on") {
		t.Errorf("refusal = %+v", env.Error)
	}
	if got := savedOIDC(t, srv); got.DefaultRole != "" || got.SessionTTLHours != 0 {
		t.Errorf("the refused save wrote something: %+v", got)
	}

	// The panel now submits what it shows — unset — and the save keeps RBAC
	// as it was.
	rec = putOIDC(t, srv, formBody(o, ""))
	if rec.Code != http.StatusOK {
		t.Fatalf("PUT = %d, want 200 (%s)", rec.Code, rec.Body.String())
	}
	if got := savedOIDC(t, srv); got.DefaultRole != "" || got.SessionTTLHours != 12 {
		t.Errorf("saved = %+v, want default_role unset and the new lifetime", got)
	}
	if savedEnforced(t, srv) {
		t.Fatal("saving the session lifetime switched RBAC on")
	}

	// Choosing it is a different request: confirmed, it lands.
	body := formBody(o, "none")
	body["confirm_rbac"] = true
	if rec = putOIDC(t, srv, body); rec.Code != http.StatusOK {
		t.Fatalf("confirmed PUT = %d (%s)", rec.Code, rec.Body.String())
	}
	if !savedEnforced(t, srv) {
		t.Error("a confirmed default role did not put RBAC in force")
	}
}

// TestOIDCSave_ConfirmsBeforeLeavingSSOWithoutAPolicy: the other transition.
// Dropping the policy from an enforced hub, or enabling SSO with none, leaves
// every identity the issuer authenticates with full access — so it is asked.
func TestOIDCSave_ConfirmsBeforeLeavingSSOWithoutAPolicy(t *testing.T) {
	enforced := rbactest.Matrix()[4].OIDC // SSO + mappings
	enforced.AdminEmails = []string{"ops@example.com"}
	srv := oidcTestServer(t, enforced)
	rec := putOIDC(t, srv, map[string]any{"role_mappings": []config.RoleMapping{}})
	if rec.Code != http.StatusConflict || decodeAPIError(t, rec).Error.Details["rbac_change"] != rbacChangeStaysOff {
		t.Fatalf("dropping the last mapping = %d (%s), want 409 rbac_off", rec.Code, rec.Body.String())
	}
	if !strings.Contains(decodeAPIError(t, rec).Error.Message, config.RBACOff(rbactest.Issuer)) {
		t.Errorf("the question does not say who gets full access: %s", rec.Body.String())
	}
	if !savedEnforced(t, srv) {
		t.Fatal("the refused save dropped the policy")
	}

	off := rbactest.Matrix()[0].OIDC // SSO off, admin_emails set
	srv = oidcTestServer(t, off)
	if rec = putOIDC(t, srv, map[string]any{"enabled": true}); rec.Code != http.StatusConflict {
		t.Fatalf("enabling SSO without a policy = %d (%s), want 409", rec.Code, rec.Body.String())
	}
	if rec = putOIDC(t, srv, map[string]any{"enabled": true, "confirm_rbac": true}); rec.Code != http.StatusOK {
		t.Fatalf("confirmed = %d (%s)", rec.Code, rec.Body.String())
	}
	if got := savedOIDC(t, srv); !got.Enabled || savedEnforced(t, srv) {
		t.Errorf("saved = %+v", got)
	}
}

// TestOIDCSave_RefusesRequireRBACWithoutAPolicy: a block `cloop ui` refuses to
// start is a block the panel refuses to save.
func TestOIDCSave_RefusesRequireRBACWithoutAPolicy(t *testing.T) {
	srv := oidcTestServer(t, rbactest.Matrix()[2].OIDC)
	rec := putOIDC(t, srv, map[string]any{"require_rbac": true})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("PUT = %d, want 400 (%s)", rec.Code, rec.Body.String())
	}
	if env := decodeAPIError(t, rec); env.Error.Details["field"] != "require_rbac" {
		t.Errorf("blamed %q, want require_rbac: %s", env.Error.Details["field"], env.Error.Message)
	}
	rec = putOIDC(t, srv, map[string]any{"require_rbac": true, "default_role": "none", "confirm_rbac": true})
	if rec.Code != http.StatusOK {
		t.Fatalf("with a policy = %d (%s)", rec.Code, rec.Body.String())
	}
	if got := savedOIDC(t, srv); !got.RequireRBAC || got.DefaultRole != "none" {
		t.Errorf("saved = %+v", got)
	}
}

// TestOIDCView_RestartRequiredWhenEnforcementDiffers: saving deny-by-default
// changes nothing until the hub restarts, and the panel has to say so.
func TestOIDCView_RestartRequiredWhenEnforcementDiffers(t *testing.T) {
	running := rbactest.Matrix()[2].OIDC
	srv := runningHub(t, running, nil)
	if srv.oidcRestartRequired(running) {
		t.Fatal("the running block asks for a restart")
	}
	saved := running
	saved.DefaultRole = "none"
	if !srv.oidcRestartRequired(saved) {
		t.Error("saved deny-by-default on a hub running without a policy must ask for a restart")
	}
	if r := srv.oidcRBACOf(saved); r.Enforced || !r.SavedEnforced || !strings.Contains(r.Warning, "restart the hub") {
		t.Errorf("rbac = %+v", r)
	}
}

// enforceHub is a hub that signs alice in through the fake IdP and runs the
// same SSO block it has saved: issuer, client, admin_emails, and no policy.
func enforceHub(t *testing.T, adminEmails []string, runtime authz.RuntimeSource) (*Server, *httptest.Server, config.OIDCConfig) {
	t.Helper()
	idp := newUIFakeIdP(t)
	srv, ts := newOIDCTestServer(t, idp, "", adminEmails)
	saved := config.OIDCConfig{
		Enabled:      true,
		Issuer:       idp.server.URL,
		ClientID:     "cloop-dashboard",
		ClientSecret: "test-secret",
		RedirectURL:  ts.URL + "/auth/callback",
		AdminEmails:  adminEmails,
	}
	cfg, err := config.Load(srv.WorkDir)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	cfg.UI.OIDC = saved
	if err := config.Save(srv.WorkDir, cfg); err != nil {
		t.Fatalf("save: %v", err)
	}
	resolver, err := authz.New(saved.AuthzConfig(runtime))
	if err != nil {
		t.Fatalf("authz.New: %v", err)
	}
	srv.Authz = resolver
	if srv.authzActive() {
		t.Fatal("precondition: RBAC must be off")
	}
	return srv, ts, saved
}

// postEnforce calls the route through the real handler chain — origin guard,
// route gate, claim freshness — as the signed-in client.
func postEnforce(t *testing.T, c *http.Client, ts *httptest.Server) (int, string) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, ts.URL+"/api/config/oidc/enforce", strings.NewReader("{}"))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(body)
}

// TestOIDCEnforce_KeepsEveryCurrentAdminAnAdmin: the action writes
// deny-by-default and an admin mapping for the caller; every identity that
// administers the hub now — admin_emails, an incident's runtime grant, the
// caller — still does, and an identity with no mapping gets nothing.
func TestOIDCEnforce_KeepsEveryCurrentAdminAnAdmin(t *testing.T) {
	runtime := fixedRuntime{{Claim: authz.ClaimEmail, Value: "responder@example.com", Role: authz.RoleAdmin}}
	srv, ts, _ := enforceHub(t, []string{"boss@example.com"}, runtime)
	c := jarClient(t)
	login(t, c, ts) // alice@example.com, sub-alice

	code, body := postEnforce(t, c, ts)
	if code != http.StatusOK {
		t.Fatalf("enforce = %d (%s)", code, body)
	}
	var view oidcSettingsView
	if err := json.Unmarshal([]byte(body), &view); err != nil {
		t.Fatalf("decode the view: %v", err)
	}
	if !view.RBAC.SavedEnforced || view.RBAC.Enforced || !view.RestartRequired || view.RBAC.CanEnforce {
		t.Errorf("view after enforcing = rbac %+v, restart_required %v", view.RBAC, view.RestartRequired)
	}

	saved := savedOIDC(t, srv)
	if saved.DefaultRole != "none" || len(saved.AdminEmails) != 1 || saved.AdminEmails[0] != "boss@example.com" {
		t.Errorf("saved = %+v", saved)
	}
	want := config.RoleMapping{Claim: "sub", Value: "sub-alice", Role: "admin"}
	if len(saved.RoleMappings) != 1 || saved.RoleMappings[0] != want {
		t.Errorf("role_mappings = %+v, want exactly %+v", saved.RoleMappings, want)
	}

	policy, err := authz.New(saved.AuthzConfig(runtime))
	if err != nil {
		t.Fatalf("the written policy: %v", err)
	}
	if !authz.Enforced(saved.Enabled, policy) {
		t.Fatal("the written block does not enforce RBAC")
	}
	for _, admin := range []*authz.Subject{
		{Sub: "sub-boss", Email: "boss@example.com"},
		{Sub: "sub-alice", Email: "alice@example.com"},
		{Sub: "sub-responder", Email: "responder@example.com"},
	} {
		if d := policy.Resolve(admin, authz.GlobalScope); d.Role != authz.RoleAdmin {
			t.Errorf("%s was an admin and is now %q", admin.Email, d.Role)
		}
	}
	if d := policy.Resolve(&authz.Subject{Sub: "sub-carol", Email: "carol@example.com"}, authz.GlobalScope); d.Allows(authz.PermProjectRead) {
		t.Errorf("an identity with no mapping still reads projects: %q", d.Role)
	}

	rows := oidcAuditRows(t, srv, auditaction.ActionOIDCRBACEnforced)
	if len(rows) != 1 {
		t.Fatalf("%d %s rows, want 1", len(rows), auditaction.ActionOIDCRBACEnforced)
	}
	if !strings.Contains(rows[0].Actor, "alice") || !strings.Contains(rows[0].Payload, `"bound":"sub=sub-alice"`) {
		t.Errorf("audit row = actor %q payload %s", rows[0].Actor, rows[0].Payload)
	}

	// Pressed again: nothing to enforce, and nothing written.
	if code, body = postEnforce(t, c, ts); code != http.StatusConflict {
		t.Errorf("second enforce = %d (%s), want 409", code, body)
	}
	if n := len(oidcAuditRows(t, srv, auditaction.ActionOIDCRBACEnforced)); n != 1 {
		t.Errorf("%d audit rows after a refused second press", n)
	}
}

// TestOIDCEnforce_AnAdminEmailCallerGetsNoSecondRoute: already an admin by
// admin_emails, the caller needs no mapping — one would be dead policy.
func TestOIDCEnforce_AnAdminEmailCallerGetsNoSecondRoute(t *testing.T) {
	srv, ts, _ := enforceHub(t, []string{"alice@example.com"}, nil)
	c := jarClient(t)
	login(t, c, ts)
	if code, body := postEnforce(t, c, ts); code != http.StatusOK {
		t.Fatalf("enforce = %d (%s)", code, body)
	}
	if saved := savedOIDC(t, srv); saved.DefaultRole != "none" || len(saved.RoleMappings) != 0 {
		t.Errorf("saved = %+v, want deny-by-default and no mapping", saved)
	}
	rows := oidcAuditRows(t, srv, auditaction.ActionOIDCRBACEnforced)
	if len(rows) != 1 || !strings.Contains(rows[0].Payload, `"bound":""`) {
		t.Errorf("audit rows = %+v", rows)
	}
}

// TestOIDCEnforce_ReusesTheNoAdministratorGate: with no session to bind and
// nobody in admin_emails, enforcing would lock every user out, and the save
// path's own gate refuses it.
func TestOIDCEnforce_ReusesTheNoAdministratorGate(t *testing.T) {
	srv := oidcTestServer(t, rbactest.Matrix()[1].OIDC) // SSO only
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/config/oidc/enforce", strings.NewReader("{}"))
	req.Header.Set("Content-Type", "application/json")
	srv.handleOIDCEnforce(rec, req)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "no administrator") {
		t.Fatalf("enforce with nobody to administer = %d (%s), want 400 no administrator", rec.Code, rec.Body.String())
	}
	if savedOIDC(t, srv).DefaultRole != "" {
		t.Error("the refused enforce wrote a default role")
	}

	// The static token's caller, with an admin in admin_emails: no mapping.
	srv = oidcTestServer(t, rbactest.Matrix()[2].OIDC)
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/api/config/oidc/enforce", strings.NewReader("{}"))
	req.Header.Set("Content-Type", "application/json")
	srv.handleOIDCEnforce(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("enforce = %d (%s)", rec.Code, rec.Body.String())
	}
	if saved := savedOIDC(t, srv); saved.DefaultRole != "none" || len(saved.RoleMappings) != 0 {
		t.Errorf("saved = %+v", saved)
	}
}

// TestOIDCEnforce_RefusesWithNothingToEnforce: SSO off, or a policy already in
// force, is a 409 that writes nothing.
func TestOIDCEnforce_RefusesWithNothingToEnforce(t *testing.T) {
	for _, tc := range []struct {
		name string
		o    config.OIDCConfig
	}{
		{"SSO off", rbactest.Matrix()[0].OIDC},
		{"already enforced", rbactest.Matrix()[3].OIDC},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := oidcTestServer(t, tc.o)
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPost, "/api/config/oidc/enforce", strings.NewReader("{}"))
			req.Header.Set("Content-Type", "application/json")
			srv.handleOIDCEnforce(rec, req)
			if rec.Code != http.StatusConflict {
				t.Fatalf("enforce = %d (%s), want 409", rec.Code, rec.Body.String())
			}
			if got := savedOIDC(t, srv); got.DefaultRole != tc.o.DefaultRole || len(got.RoleMappings) != len(tc.o.RoleMappings) {
				t.Errorf("a refused enforce changed the block: %+v", got)
			}
		})
	}
}

// oidcAuditRows reads the hub journal's rows for action.
func oidcAuditRows(t *testing.T, srv *Server, action auditaction.Action) []eventlog.AuditEvent {
	t.Helper()
	log, err := eventlog.Open(srv.WorkDir)
	if err != nil {
		t.Fatalf("open event log: %v", err)
	}
	defer log.Close()
	rows, _, err := log.List(eventlog.AuditFilter{EventType: string(action)})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	return rows
}

// TestHub8888AccessIsUnchanged: :8888's ui.oidc, from a copy of its overlay
// loaded the way that hub loads it, keeps exactly the access it had — RBAC in
// force, its one admin an admin, everyone else in the tenant denied — and the
// panel neither warns about it nor asks anything when an unrelated field is
// saved.
func TestHub8888AccessIsUnchanged(t *testing.T) {
	dir := t.TempDir()
	rbactest.WriteHub8888(t, dir)
	cfg, applied, err := config.LoadUIInstance(dir, rbactest.Hub8888Port)
	if err != nil || applied == "" {
		t.Fatalf("LoadUIInstance: %v (overlay %q)", err, applied)
	}
	o := cfg.UI.OIDC
	if !reflect.DeepEqual(o, rbactest.Hub8888(t)) {
		t.Fatalf("the overlay did not load as written:\n got %+v\nwant %+v", o, rbactest.Hub8888(t))
	}

	srv := &Server{WorkDir: dir, Port: rbactest.Hub8888Port}
	auth, err := oidcauth.New(o.AuthConfig())
	if err != nil {
		t.Fatalf("oidcauth.New: %v", err)
	}
	srv.OIDC = auth
	resolver, err := authz.New(o.AuthzConfig(nil))
	if err != nil {
		t.Fatalf("authz.New: %v", err)
	}
	srv.Authz = resolver
	if !srv.authzActive() {
		t.Fatal(":8888's policy is no longer in force")
	}

	admin := &authz.Subject{Sub: "sub-admin", Email: rbactest.Hub8888Admin}
	if d := resolver.Resolve(admin, authz.GlobalScope); d.Role != authz.RoleAdmin || !d.Allows(authz.PermUserManage) {
		t.Errorf("%s resolves to %q", rbactest.Hub8888Admin, d.Role)
	}
	if !auth.IsAdmin(&oidcauth.Identity{Sub: "sub-admin", Email: rbactest.Hub8888Admin}) {
		t.Error("admin_emails no longer names the admin")
	}
	colleague := &authz.Subject{Sub: "sub-colleague", Email: "colleague@blechschmidt.saarland"}
	if d := resolver.Resolve(colleague, authz.GlobalScope); d.Role != authz.RoleNone || d.Allows(authz.PermProjectRead) {
		t.Errorf("a tenant identity with no mapping resolves to %q", d.Role)
	}

	view, err := srv.oidcSettings()
	if err != nil {
		t.Fatalf("read settings: %v", err)
	}
	if r := view.RBAC; !r.Enforced || !r.SavedEnforced || r.Warning != "" || r.CanEnforce || r.DefaultRole != "none" {
		t.Errorf("rbac = %+v", r)
	}
	if view.DefaultRole != "none" || view.RestartRequired {
		t.Errorf("default_role = %q, restart_required = %v", view.DefaultRole, view.RestartRequired)
	}
	if got := meBody(t, srv)["rbac_enforced"]; got != true {
		t.Errorf("/api/me rbac_enforced = %v", got)
	}

	// The form as the panel now submits it for this hub — its real default
	// role, "none" — with only the session lifetime changed: no question, and
	// the policy written back intact, into the overlay the hub reads.
	rec := putOIDC(t, srv, formBody(o, o.DefaultRole))
	if rec.Code != http.StatusOK {
		t.Fatalf("PUT = %d (%s)", rec.Code, rec.Body.String())
	}
	after, _, err := config.LoadUIInstance(dir, rbactest.Hub8888Port)
	if err != nil {
		t.Fatal(err)
	}
	a := after.UI.OIDC
	if a.DefaultRole != "none" || !sameMappings(a.RoleMappings, o.RoleMappings) || !sameStrings(a.AdminEmails, o.AdminEmails) {
		t.Errorf("the save changed :8888's policy: %+v", a)
	}
	if enforced, err := a.RBACEnforced(); err != nil || !enforced {
		t.Errorf("after the save RBACEnforced = %v, %v", enforced, err)
	}
}

// TestAuditNamesTheSignedInUserWhenRBACIsOff: on a single sign-on hub without
// a policy the request's grant is a bypass labelled "local", so every row the
// hub wrote named "local" — on a hub everyone in the directory signs in to. The
// trail names the session's identity instead.
func TestAuditNamesTheSignedInUserWhenRBACIsOff(t *testing.T) {
	srv, ts, saved := enforceHub(t, []string{"boss@example.com"}, nil)
	c := jarClient(t)
	login(t, c, ts)

	body, err := json.Marshal(formBody(saved, ""))
	if err != nil {
		t.Fatal(err)
	}
	if code, resp := do(t, c, http.MethodPut, ts.URL+"/api/config/oidc", string(body)); code != http.StatusOK {
		t.Fatalf("PUT = %d (%s)", code, resp)
	}
	rows := oidcAuditRows(t, srv, auditaction.ActionOIDCConfigUpdated)
	if len(rows) != 1 {
		t.Fatalf("%d %s rows, want 1", len(rows), auditaction.ActionOIDCConfigUpdated)
	}
	if rows[0].Actor != "alice@example.com" {
		t.Errorf("actor = %q, want the signed-in user", rows[0].Actor)
	}
	for _, want := range []string{`"rbac_enforced":false`, `"was_rbac_enforced":false`} {
		if !strings.Contains(rows[0].Payload, want) {
			t.Errorf("payload %s lacks %s", rows[0].Payload, want)
		}
	}
}

// TestOIDCSave_SelfDemotionCheckAsksWhetherRBACIsInForce: a block that leaves
// RBAC off demotes nobody — every signed-in identity keeps user.manage — so a
// user outside admin_emails can save it; the same user turning a policy on that
// does not name them is still refused.
func TestOIDCSave_SelfDemotionCheckAsksWhetherRBACIsInForce(t *testing.T) {
	caller := &authz.Subject{Sub: "sub-alice", Email: "alice@example.com"}
	off := rbactest.Matrix()[2].OIDC // admin_emails: ops@example.com
	if err := validateOIDCConfig(off, caller, nil); err != nil {
		t.Errorf("a save that keeps RBAC off was refused as a self-demotion: %v", err)
	}
	on := off
	on.DefaultRole = "none"
	err := validateOIDCConfig(on, caller, nil)
	if err == nil || !strings.Contains(err.Error(), "your own administrative access") {
		t.Errorf("turning on a policy that strands the caller: %v", err)
	}
}
