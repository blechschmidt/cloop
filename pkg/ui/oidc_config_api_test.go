package ui

// Tests for the OIDC Settings panel's backend (Task 20308).
//
// The thing worth testing here is not that a field round-trips. It is that the
// four ways an admin can brick their own hub with one click are refused:
//
//	a block the next startup would reject   → the hub does not boot
//	SSO on with no administrator            → nobody can administer it
//	a change that demotes the caller        → they cannot change it back
//	a client secret written into the file it was deliberately kept out of
//
// Each has its own test, and each asserts the refusal rather than the absence
// of a crash, because all four fail silently in the direction of "saved fine".

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/pkg/authz"
	"github.com/blechschmidt/cloop/pkg/config"
)

// oidcTestServer builds a hub whose config.yaml holds o.
func oidcTestServer(t *testing.T, o config.OIDCConfig) *Server {
	t.Helper()
	dir := t.TempDir()
	cfg := config.Default()
	cfg.UI.OIDC = o
	if err := config.Save(dir, cfg); err != nil {
		t.Fatalf("seed config: %v", err)
	}
	return &Server{WorkDir: dir}
}

// putOIDC sends a PUT with the given body and returns the recorder.
func putOIDC(t *testing.T, srv *Server, body map[string]any) *httptest.ResponseRecorder {
	t.Helper()
	blob, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal body: %v", err)
	}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPut, "/api/config/oidc", strings.NewReader(string(blob)))
	srv.handleOIDCSettingsSave(rec, req)
	return rec
}

// apiErrorEnvelope is the shape apierror.WriteError emits: the message and the
// machine-readable details are nested under "error", not flat beside it.
type apiErrorEnvelope struct {
	Error struct {
		Code    string            `json:"code"`
		Message string            `json:"message"`
		Details map[string]string `json:"details"`
	} `json:"error"`
}

func decodeAPIError(t *testing.T, rec *httptest.ResponseRecorder) apiErrorEnvelope {
	t.Helper()
	var env apiErrorEnvelope
	if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
		t.Fatalf("decode error response: %v (%s)", err, rec.Body.String())
	}
	return env
}

// savedOIDC reads back what landed in config.yaml.
func savedOIDC(t *testing.T, srv *Server) config.OIDCConfig {
	t.Helper()
	cfg, err := config.Load(srv.WorkDir)
	if err != nil || cfg == nil {
		t.Fatalf("reload config: %v", err)
	}
	return cfg.UI.OIDC
}

// A complete, valid block — the baseline each refusal test breaks one way.
func validOIDC() config.OIDCConfig {
	return config.OIDCConfig{
		Enabled:     true,
		Issuer:      "https://idp.example.com",
		ClientID:    "cloop-dashboard",
		RedirectURL: "https://cloop.example.com/auth/callback",
		AdminEmails: []string{"ops@example.com"},
	}
}

// TestOIDCSave_RefusesConfigThatWouldNotStart is the load-bearing one.
//
// cmd/ui_cmd.go aborts startup on an invalid ui.oidc block, so a panel that
// saves one produces a hub that will not boot — repairable only with a shell on
// the box, which is the situation the panel exists to avoid. Each case here is
// a value oidcauth.New rejects, reached through the same builder startup uses.
func TestOIDCSave_RefusesConfigThatWouldNotStart(t *testing.T) {
	cases := []struct {
		name  string
		body  map[string]any
		field string
	}{
		{
			name:  "no issuer",
			body:  map[string]any{"enabled": true, "issuer": ""},
			field: "issuer",
		},
		{
			// http to a non-loopback host: the ID token would cross the network
			// in clear, so oidcauth.New refuses it.
			name:  "plaintext issuer",
			body:  map[string]any{"enabled": true, "issuer": "http://idp.example.com"},
			field: "issuer",
		},
		{
			name:  "no client id",
			body:  map[string]any{"enabled": true, "client_id": ""},
			field: "client_id",
		},
		{
			name:  "no redirect url",
			body:  map[string]any{"enabled": true, "redirect_url": ""},
			field: "redirect_url",
		},
		{
			name:  "unknown cookie_secure",
			body:  map[string]any{"enabled": true, "cookie_secure": "sometimes"},
			field: "cookie_secure",
		},
		{
			name: "unknown role in a mapping",
			body: map[string]any{"enabled": true, "role_mappings": []map[string]string{
				{"claim": "group", "value": "eng", "role": "superuser"},
			}},
			field: "role_mappings",
		},
		{
			name: "unknown claim kind in a mapping",
			body: map[string]any{"enabled": true, "role_mappings": []map[string]string{
				{"claim": "department", "value": "eng", "role": "admin"},
			}},
			field: "role_mappings",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			base := validOIDC()
			base.ClientSecret = "s3cret"
			srv := oidcTestServer(t, base)

			rec := putOIDC(t, srv, tc.body)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400 — this block would abort the next startup\nbody: %s",
					rec.Code, rec.Body.String())
			}
			// The field is what lets the panel highlight the input rather than
			// only describe the problem.
			resp := decodeAPIError(t, rec)
			if resp.Error.Details["field"] != tc.field {
				t.Errorf("blamed field = %q, want %q (error: %s)",
					resp.Error.Details["field"], tc.field, resp.Error.Message)
			}
			// And nothing was written: a refused save must leave the working
			// configuration exactly as it was.
			if got := savedOIDC(t, srv); got.Issuer != base.Issuer || got.ClientID != base.ClientID {
				t.Errorf("a refused save mutated config.yaml: %+v", got)
			}
		})
	}
}

// TestOIDCSave_RefusesEnablingWithNoAdministrator covers the config that is
// valid and still useless: default_role is "none" unless set, so the natural
// first draft denies every signed-in user everything — including the panel that
// would fix it.
func TestOIDCSave_RefusesEnablingWithNoAdministrator(t *testing.T) {
	base := validOIDC()
	base.ClientSecret = "s3cret"
	base.AdminEmails = nil
	srv := oidcTestServer(t, base)

	rec := putOIDC(t, srv, map[string]any{"enabled": true, "admin_emails": []string{}})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 — this would enable SSO with no admin\nbody: %s",
			rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "no administrator") {
		t.Errorf("error should name the problem, got: %s", rec.Body.String())
	}
}

// TestOIDCSave_AcceptsAdminGrantedByRoleMapping is the other half of the test
// above: an admin granted through a group claim counts exactly as much as an
// entry in admin_emails, because the question is asked of the resolver rather
// than of the field. Without this the refusal would be wrong for every hub that
// maps roles from groups, which is the recommended configuration.
func TestOIDCSave_AcceptsAdminGrantedByRoleMapping(t *testing.T) {
	base := validOIDC()
	base.ClientSecret = "s3cret"
	base.AdminEmails = nil
	srv := oidcTestServer(t, base)

	rec := putOIDC(t, srv, map[string]any{
		"enabled":      true,
		"admin_emails": []string{},
		"role_mappings": []map[string]string{
			{"claim": "group", "value": "cloop-admins", "role": "admin"},
		},
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 — a group mapping granting admin is an administrator\nbody: %s",
			rec.Code, rec.Body.String())
	}
	if got := savedOIDC(t, srv); len(got.RoleMappings) != 1 || got.RoleMappings[0].Role != "admin" {
		t.Errorf("role mapping did not persist: %+v", got.RoleMappings)
	}
}

// TestOIDCSave_RefusesDemotingTheCaller checks the anti-escalation guard
// pointed the other way: an admin editing role mappings is one typo from
// removing their own grant, and the surface that would tell them is the one
// they just lost.
func TestOIDCSave_RefusesDemotingTheCaller(t *testing.T) {
	caller := &authz.Subject{Sub: "u-1", Email: "alice@example.com"}

	// Valid, and grants admin to somebody else.
	o := validOIDC()
	o.AdminEmails = []string{"bob@example.com"}
	resolver, err := authz.New(OIDCAuthzConfig(o, nil))
	if err != nil {
		t.Fatalf("build resolver: %v", err)
	}
	if err := wouldDemoteCaller(resolver, caller); err == nil {
		t.Fatal("expected a refusal: this configuration removes the caller's own admin access")
	} else if !strings.Contains(err.Error(), "alice@example.com") {
		t.Errorf("refusal should name the caller, got: %v", err)
	}

	// Keeping herself in the list is accepted.
	o.AdminEmails = []string{"bob@example.com", "alice@example.com"}
	resolver, err = authz.New(OIDCAuthzConfig(o, nil))
	if err != nil {
		t.Fatalf("build resolver: %v", err)
	}
	if err := wouldDemoteCaller(resolver, caller); err != nil {
		t.Errorf("caller retains admin, so this must be accepted: %v", err)
	}

	// No session — a static-token or service-account caller — has authority
	// this block cannot revoke, so there is nobody to strand.
	if err := wouldDemoteCaller(resolver, nil); err != nil {
		t.Errorf("a caller with no session must not be blocked: %v", err)
	}
}

// TestOIDCSave_AllowsIncompleteBlockWhileDisabled: a half-filled draft with the
// switch off has to stay savable, because that is how an operator stages an
// issuer before turning SSO on. Nothing reads a disabled block, so there is
// nothing to get wrong.
func TestOIDCSave_AllowsIncompleteBlockWhileDisabled(t *testing.T) {
	srv := oidcTestServer(t, config.OIDCConfig{})

	rec := putOIDC(t, srv, map[string]any{
		"enabled": false,
		"issuer":  "https://idp.example.com",
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 — a disabled draft must be savable\nbody: %s",
			rec.Code, rec.Body.String())
	}
	if got := savedOIDC(t, srv); got.Issuer != "https://idp.example.com" || got.Enabled {
		t.Errorf("draft did not persist as disabled: %+v", got)
	}
}

// TestOIDCView_NeverDisclosesTheClientSecret. The GET is readable by anyone
// holding user.manage, which is a wider audience over time than whoever set the
// credential, and a secret in a JSON response is a secret in every proxy log
// and browser cache between here and there.
func TestOIDCView_NeverDisclosesTheClientSecret(t *testing.T) {
	o := validOIDC()
	o.ClientSecret = "super-secret-value"
	srv := oidcTestServer(t, o)

	rec := httptest.NewRecorder()
	srv.handleOIDCSettings(rec, httptest.NewRequest(http.MethodGet, "/api/config/oidc", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "super-secret-value") {
		t.Fatalf("the client secret reached the response body: %s", rec.Body.String())
	}

	var view oidcSettingsView
	if err := json.Unmarshal(rec.Body.Bytes(), &view); err != nil {
		t.Fatalf("decode view: %v", err)
	}
	if !view.ClientSecretSet || view.ClientSecretSource != oidcSecretFile {
		t.Errorf("view should report a stored secret without its value, got set=%v source=%q",
			view.ClientSecretSet, view.ClientSecretSource)
	}
}

// TestOIDCSave_BlankSecretKeepsTheStoredOne. The panel cannot display the
// secret, so it cannot submit it back — which makes blank necessarily mean
// "keep", and clearing necessarily an explicit act. If blank cleared, editing
// the issuer would silently break every sign-in.
func TestOIDCSave_BlankSecretKeepsTheStoredOne(t *testing.T) {
	o := validOIDC()
	o.ClientSecret = "keep-me"
	srv := oidcTestServer(t, o)

	rec := putOIDC(t, srv, map[string]any{"issuer": "https://idp2.example.com", "client_secret": ""})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", rec.Code, rec.Body.String())
	}
	got := savedOIDC(t, srv)
	if got.ClientSecret != "keep-me" {
		t.Errorf("blank client_secret cleared the stored one (got %q)", got.ClientSecret)
	}
	if got.Issuer != "https://idp2.example.com" {
		t.Errorf("issuer did not change: %q", got.Issuer)
	}

	// The explicit flag does clear it.
	rec = putOIDC(t, srv, map[string]any{"clear_client_secret": true, "enabled": false})
	if rec.Code != http.StatusOK {
		t.Fatalf("clear: status = %d: %s", rec.Code, rec.Body.String())
	}
	if got := savedOIDC(t, srv); got.ClientSecret != "" {
		t.Errorf("clear_client_secret left %q behind", got.ClientSecret)
	}
}

// TestOIDCSave_DoesNotCommitAnEnvironmentSuppliedSecret is the leak this task
// found. config.Load overlays CLOOP_OIDC_CLIENT_SECRET, so any load-modify-save
// would write the environment's value into the file — turning a hub whose
// secret lives in a Kubernetes Secret into one whose secret is in the YAML an
// operator commits, the first time anybody changed an unrelated setting.
func TestOIDCSave_DoesNotCommitAnEnvironmentSuppliedSecret(t *testing.T) {
	const envSecret = "secret-from-the-environment"
	t.Setenv(config.EnvOIDCClientSecret, envSecret)

	o := validOIDC()
	// Deliberately empty in the file: the environment is the only source.
	o.ClientSecret = ""
	srv := oidcTestServer(t, o)

	// Change something unrelated.
	rec := putOIDC(t, srv, map[string]any{"session_ttl_hours": 12})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", rec.Code, rec.Body.String())
	}

	raw, err := os.ReadFile(filepath.Join(srv.WorkDir, ".cloop", "config.yaml"))
	if err != nil {
		t.Fatalf("read config.yaml: %v", err)
	}
	if strings.Contains(string(raw), envSecret) {
		t.Fatalf("the environment's client secret was written into config.yaml:\n%s", raw)
	}

	// And the view reports where the credential actually comes from, so the
	// panel can say that a value typed into it would be ignored.
	getRec := httptest.NewRecorder()
	srv.handleOIDCSettings(getRec, httptest.NewRequest(http.MethodGet, "/api/config/oidc", nil))
	var view oidcSettingsView
	if err := json.Unmarshal(getRec.Body.Bytes(), &view); err != nil {
		t.Fatalf("decode view: %v", err)
	}
	if view.ClientSecretSource != oidcSecretEnv {
		t.Errorf("client_secret_source = %q, want %q", view.ClientSecretSource, oidcSecretEnv)
	}
}

// TestOIDCSave_PersistsASecretTypedIntoThePanel is the other side of the test
// above: the restore must not swallow a value somebody actually entered on a
// machine that happens to also export one.
func TestOIDCSave_PersistsASecretTypedIntoThePanel(t *testing.T) {
	t.Setenv(config.EnvOIDCClientSecret, "secret-from-the-environment")

	o := validOIDC()
	srv := oidcTestServer(t, o)

	rec := putOIDC(t, srv, map[string]any{"client_secret": "typed-by-the-operator"})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", rec.Code, rec.Body.String())
	}
	raw, err := os.ReadFile(filepath.Join(srv.WorkDir, ".cloop", "config.yaml"))
	if err != nil {
		t.Fatalf("read config.yaml: %v", err)
	}
	if !strings.Contains(string(raw), "typed-by-the-operator") {
		t.Fatalf("a secret entered in the panel was discarded:\n%s", raw)
	}
}

// TestOIDCSave_NormalisesTheIssuerTrailingSlash. The spec makes the issuer
// string equality-compared against the `iss` claim, so "https://idp/" and
// "https://idp" are different providers and one of them rejects every token.
// It is the classic typo, and it is cheaper to trim than to diagnose.
func TestOIDCSave_NormalisesTheIssuerTrailingSlash(t *testing.T) {
	o := validOIDC()
	o.ClientSecret = "s3cret"
	srv := oidcTestServer(t, o)

	rec := putOIDC(t, srv, map[string]any{"issuer": "https://idp.example.com/"})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", rec.Code, rec.Body.String())
	}
	if got := savedOIDC(t, srv).Issuer; got != "https://idp.example.com" {
		t.Errorf("issuer = %q, want the trailing slash trimmed", got)
	}
}

// TestOIDCSave_DropsBlankRoleMappingRows. The panel's "add mapping" button
// creates an empty row; submitting the form with one still open must not fail
// the whole save on the panel's own artefact.
func TestOIDCSave_DropsBlankRoleMappingRows(t *testing.T) {
	o := validOIDC()
	o.ClientSecret = "s3cret"
	srv := oidcTestServer(t, o)

	rec := putOIDC(t, srv, map[string]any{
		"role_mappings": []map[string]string{
			{"claim": "group", "value": "eng", "role": "operator"},
			{"claim": "", "value": "", "role": ""},
		},
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 — a blank trailing row is not an error\nbody: %s",
			rec.Code, rec.Body.String())
	}
	if got := savedOIDC(t, srv).RoleMappings; len(got) != 1 {
		t.Errorf("expected the blank row to be dropped, got %d mappings: %+v", len(got), got)
	}
}

// TestOIDCView_ReportsRestartRequired. The authenticator is built once at
// startup, so a saved change is inert until the process restarts. This is the
// one genuinely confusing thing about the feature — "I enabled it and nothing
// happened" — and the view has to answer it.
func TestOIDCView_ReportsRestartRequired(t *testing.T) {
	o := validOIDC()
	o.ClientSecret = "s3cret"
	// srv.OIDC is nil: this process is running without SSO, while the file
	// says it is on.
	srv := oidcTestServer(t, o)

	view, err := srv.oidcSettings()
	if err != nil {
		t.Fatalf("read settings: %v", err)
	}
	if !view.RestartRequired {
		t.Error("saved enabled + running disabled must report restart_required")
	}
	if view.Active.Enabled {
		t.Error("active.enabled must describe the running authenticator, not the file")
	}

	// Agreement in the other direction: both off, nothing pending.
	off := oidcTestServer(t, config.OIDCConfig{})
	view, err = off.oidcSettings()
	if err != nil {
		t.Fatalf("read settings: %v", err)
	}
	if view.RestartRequired {
		t.Error("both off: nothing is pending")
	}
}

// TestOIDCView_ServesBoundsAndEnumerations. The frontend renders min/max and
// the role and claim dropdowns from these, rather than hardcoding a second copy
// of constants that already exist in pkg/config and pkg/authz. If they stopped
// being served the panel would silently accept values the next startup rejects.
func TestOIDCView_ServesBoundsAndEnumerations(t *testing.T) {
	srv := oidcTestServer(t, config.OIDCConfig{})
	view, err := srv.oidcSettings()
	if err != nil {
		t.Fatalf("read settings: %v", err)
	}
	if view.Limits.SessionTTLHours.Upper != config.OIDCSessionTTLHoursUpper {
		t.Errorf("session TTL upper bound = %d, want %d",
			view.Limits.SessionTTLHours.Upper, config.OIDCSessionTTLHoursUpper)
	}
	// The two optional behaviours must advertise their disable sentinel, or the
	// panel would render min=1 and refuse the -1 its own label recommends.
	if view.Limits.MaxClaimAgeMinutes.Disable != config.OIDCDisabledSentinel {
		t.Errorf("max claim age disable sentinel = %d, want %d",
			view.Limits.MaxClaimAgeMinutes.Disable, config.OIDCDisabledSentinel)
	}
	if len(view.Roles) != len(authz.AllRoles) {
		t.Errorf("roles = %v, want all %d of them", view.Roles, len(authz.AllRoles))
	}
	if len(view.Claims) != len(authz.AllClaimKinds) {
		t.Errorf("claims = %v, want all %d of them", view.Claims, len(authz.AllClaimKinds))
	}
	// Never null: the frontend renders this as a list and a null would make the
	// first "add a mapping" click a special case.
	if view.RoleMappings == nil {
		t.Error("role_mappings must serialise as [] rather than null")
	}
}

// TestOIDCChangedFields records what the audit row will say. The client secret
// must appear as a name and never as a value — not even a length.
func TestOIDCChangedFields(t *testing.T) {
	was := validOIDC()
	was.ClientSecret = "old"
	now := was
	now.ClientSecret = "new"
	now.Issuer = "https://other.example.com"

	changed := oidcChangedFields(was, now)
	joined := strings.Join(changed, ",")
	if !strings.Contains(joined, "client_secret") || !strings.Contains(joined, "issuer") {
		t.Errorf("changed = %v, want both client_secret and issuer", changed)
	}
	for _, v := range []string{"old", "new"} {
		if strings.Contains(joined, v) {
			t.Errorf("the secret's value leaked into the change list: %v", changed)
		}
	}
	// An unchanged block produces no row at all, so a re-submitted form does
	// not dilute the query this row exists to answer.
	if got := oidcChangedFields(was, was); len(got) != 0 {
		t.Errorf("identical blocks reported changes: %v", got)
	}
}
