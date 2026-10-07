package hubdoctor

// rbac.enforced (Task 20395): whether a role policy is in force, as
// authz.Enforced answers it. An SSO hub with admin_emails and no mapping — the
// Task 20317 instance's shape — runs with RBAC off, and this command reported
// it as `rbac.default_role PASS deny-by-default`.

import (
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/internal/rbactest"
	"github.com/blechschmidt/cloop/pkg/config"
)

// rbacFindings runs the offline diagnosis over a hub whose ui.oidc is o.
func rbacFindings(t *testing.T, o config.OIDCConfig) map[string][]Finding {
	t.Helper()
	cfg := hubCfg()
	cfg.UI.OIDC = o
	return findingsFor(t, t.TempDir(), cfg, Options{Offline: true})
}

func TestRBACEnforcementAcrossTheMatrix(t *testing.T) {
	for _, tc := range rbactest.Matrix() {
		t.Run(tc.Name, func(t *testing.T) {
			got := rbacFindings(t, tc.OIDC)
			switch {
			case !tc.OIDC.Enabled:
				// No identity provider, no claims, no RBAC to report on.
				if fs := got["rbac.enforced"]; len(fs) != 0 {
					t.Errorf("rbac.enforced on a hub without single sign-on: %+v", fs)
				}
			case tc.Enforced:
				f := only(t, got, "rbac.enforced")
				wantSeverity(t, f, SeverityPass)
				if !strings.Contains(f.Message, "RBAC is in force") {
					t.Errorf("rbac.enforced: %q", f.Message)
				}
			default:
				f := only(t, got, "rbac.enforced")
				wantSeverity(t, f, SeverityFail)
				if !strings.Contains(f.Message, config.RBACOff(rbactest.Issuer)) {
					t.Errorf("rbac.enforced does not lead with the RBAC-off sentence naming the issuer: %q", f.Message)
				}
			}

			// The default_role line only where a policy makes default_role mean
			// something. With RBAC off, "deny-by-default" was the misreport.
			if fs := got["rbac.default_role"]; tc.Enforced != (len(fs) == 1) {
				t.Errorf("rbac.default_role findings = %+v, want exactly one only when RBAC is in force", fs)
			}
			for _, f := range got["rbac.default_role"] {
				if !tc.Enforced && strings.Contains(f.Message, "deny-by-default") {
					t.Errorf("an RBAC-off hub reported deny-by-default: %q", f.Message)
				}
			}
		})
	}
}

// TestRBACOffNamesTheIssuerAndTheRemedy: the finding has to say whose
// identities hold full access and how to stop it, in the doctor's own
// remediation field.
func TestRBACOffNamesTheIssuerAndTheRemedy(t *testing.T) {
	o := rbactest.Matrix()[2].OIDC // SSO + admin_emails
	f := only(t, rbacFindings(t, o), "rbac.enforced")
	wantSeverity(t, f, SeverityFail)
	for _, want := range []string{rbactest.Issuer, "every permission except executor administration", "quotas never count"} {
		if !strings.Contains(f.Message, want) {
			t.Errorf("message does not say %q: %q", want, f.Message)
		}
	}
	for _, want := range []string{"Enforce deny-by-default", "default_role: none", "require_rbac"} {
		if !strings.Contains(f.Remediation, want) {
			t.Errorf("remediation does not say %q: %q", want, f.Remediation)
		}
	}
	if f.Details["issuer"] != rbactest.Issuer {
		t.Errorf("details = %v, want the issuer", f.Details)
	}
}

// TestRBACOffAdminLineDoesNotClaimDenial: with RBAC off and nobody in
// admin_emails, the old wording — "every request is denied correctly" — was
// false: every signed-in identity holds everything but executor
// administration.
func TestRBACOffAdminLineDoesNotClaimDenial(t *testing.T) {
	f := only(t, rbacFindings(t, rbactest.Matrix()[1].OIDC), "rbac.admin") // SSO only
	wantSeverity(t, f, SeverityFail)
	if strings.Contains(f.Message, "denied") {
		t.Errorf("an RBAC-off hub's admin line says requests are denied: %q", f.Message)
	}
	if !strings.Contains(f.Message, "executors") || !strings.Contains(f.Remediation, "admin_emails") {
		t.Errorf("rbac.admin: %q / %q", f.Message, f.Remediation)
	}
	// Under a policy, the strict wording still holds.
	f = only(t, rbacFindings(t, rbactest.Matrix()[3].OIDC), "rbac.admin") // SSO + default_role
	if !strings.Contains(f.Message, "denied correctly") {
		t.Errorf("an enforced hub with no admin: %q", f.Message)
	}
}

// TestRequireRBACIsReportedAsAStartThatFails: with ui.oidc.require_rbac set,
// the RBAC-off state is a hub `cloop ui` will not start.
func TestRequireRBACIsReportedAsAStartThatFails(t *testing.T) {
	o := rbactest.Matrix()[2].OIDC
	o.RequireRBAC = true
	f := only(t, rbacFindings(t, o), "rbac.enforced")
	if !strings.Contains(f.Message, "refuse to start") {
		t.Errorf("require_rbac was not reported as a refused start: %q", f.Message)
	}
	// Set on a hub with a policy, it changes nothing.
	o = rbactest.Matrix()[4].OIDC
	o.RequireRBAC = true
	wantSeverity(t, only(t, rbacFindings(t, o), "rbac.enforced"), SeverityPass)
}

// TestHub8888IsReportedEnforced: :8888's own policy — default_role none, an
// email mapping and the same address in admin_emails — is in force, deny by
// default, with one route to admin.
func TestHub8888IsReportedEnforced(t *testing.T) {
	cfg := hubCfg()
	cfg.UI.ExternalURL = "https://aiden.blechschmidt.io:8888"
	cfg.UI.OIDC = rbactest.Hub8888(t)
	got := findingsFor(t, t.TempDir(), cfg, Options{Offline: true})
	wantSeverity(t, only(t, got, "rbac.enforced"), SeverityPass)
	wantSeverity(t, only(t, got, "rbac.default_role"), SeverityPass)
	admin := only(t, got, "rbac.admin")
	wantSeverity(t, admin, SeverityPass)
	if admin.Details["granted_by"] != "email="+rbactest.Hub8888Admin {
		t.Errorf("granted_by = %v", admin.Details["granted_by"])
	}
}
