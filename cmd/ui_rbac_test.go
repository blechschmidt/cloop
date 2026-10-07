package cmd

// What `cloop ui` prints about RBAC at startup (Task 20395), for each of the
// five ui.oidc blocks every reporter is held to. The line used to read
// `RBAC: 0 role mapping(s), default role "none"` on a hub whose RBAC was off.

import (
	"bytes"
	"strings"
	"testing"

	"github.com/fatih/color"

	"github.com/blechschmidt/cloop/internal/rbactest"
	"github.com/blechschmidt/cloop/pkg/authz"
	"github.com/blechschmidt/cloop/pkg/config"
)

// plainColor turns colour off for the test, so assertions read text rather
// than escape codes whatever the terminal.
func plainColor(t *testing.T) {
	t.Helper()
	prev := color.NoColor
	color.NoColor = true
	t.Cleanup(func() { color.NoColor = prev })
}

// startupRBAC runs the reporter over the resolver `cloop ui` builds from o.
func startupRBAC(t *testing.T, o config.OIDCConfig) (stdout, stderr string, err error) {
	t.Helper()
	resolver, rerr := authz.New(o.AuthzConfig(nil))
	if rerr != nil {
		t.Fatalf("authz.New: %v", rerr)
	}
	var out, errw bytes.Buffer
	err = reportRBAC(&out, &errw, o, resolver)
	return out.String(), errw.String(), err
}

func TestReportRBACAcrossTheMatrix(t *testing.T) {
	plainColor(t)
	for _, tc := range rbactest.Matrix() {
		t.Run(tc.Name, func(t *testing.T) {
			stdout, stderr, err := startupRBAC(t, tc.OIDC)
			if err != nil {
				t.Fatalf("reportRBAC refused a start without require_rbac: %v", err)
			}
			switch {
			case !tc.OIDC.Enabled:
				if stdout != "" || stderr != "" {
					t.Errorf("a hub without single sign-on said something about RBAC:\n%s%s", stdout, stderr)
				}
			case tc.Enforced:
				if !strings.HasPrefix(stdout, "RBAC: ") || !strings.Contains(stdout, `default role "none"`) {
					t.Errorf("stdout = %q", stdout)
				}
				if stderr != "" {
					t.Errorf("an enforced hub warned: %q", stderr)
				}
			default:
				// No default role value: printing the "none" an unset role would
				// mean under a policy is the misreport this replaced.
				if !strings.HasPrefix(stdout, "RBAC: off") || strings.Contains(stdout, `default role "`) {
					t.Errorf("stdout = %q, want the off line and no default role value", stdout)
				}
				want := "warning: " + config.RBACOff(rbactest.Issuer) + "."
				if !strings.HasPrefix(stderr, want) {
					t.Errorf("stderr = %q, want it to open with %q", stderr, want)
				}
				for _, part := range []string{"executor administration", "Enforce deny-by-default", "require_rbac"} {
					if !strings.Contains(stderr, part) {
						t.Errorf("the warning does not say %q:\n%s", part, stderr)
					}
				}
			}
		})
	}
}

// TestReportRBACRefusesUnderRequireRBAC: the opt-in refusal, returned before
// the hub serves anything; with a policy it is inert.
func TestReportRBACRefusesUnderRequireRBAC(t *testing.T) {
	plainColor(t)
	off := rbactest.Matrix()[2].OIDC // SSO + admin_emails
	off.RequireRBAC = true
	_, _, err := startupRBAC(t, off)
	if err == nil {
		t.Fatal("require_rbac let an SSO hub without a policy start")
	}
	for _, want := range []string{"ui.oidc.require_rbac is set", config.RBACOff(rbactest.Issuer), "default_role: none"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal does not say %q: %v", want, err)
		}
	}

	on := rbactest.Matrix()[4].OIDC
	on.RequireRBAC = true
	if _, stderr, err := startupRBAC(t, on); err != nil || stderr != "" {
		t.Errorf("require_rbac with a policy: err=%v stderr=%q", err, stderr)
	}
}

// TestReportRBACOnHub8888: :8888's own block, loaded from a copy of its
// overlay the way the hub loads it, starts as it did before this task — the
// same banner line, no warning, no refusal.
func TestReportRBACOnHub8888(t *testing.T) {
	plainColor(t)
	dir := t.TempDir()
	rbactest.WriteHub8888(t, dir)
	cfg, applied, err := config.LoadUIInstance(dir, rbactest.Hub8888Port)
	if err != nil || applied == "" {
		t.Fatalf("LoadUIInstance: %v (overlay %q)", err, applied)
	}
	stdout, stderr, err := startupRBAC(t, cfg.UI.OIDC)
	if err != nil {
		t.Fatalf("refused: %v", err)
	}
	if want := "RBAC: 1 role mapping(s), default role \"none\"\n"; stdout != want {
		t.Errorf("stdout = %q, want %q", stdout, want)
	}
	if stderr != "" {
		t.Errorf("stderr = %q", stderr)
	}
}

// TestConfigSetWarnsWhenItLeavesSSOWithoutAPolicy: `cloop config set` is how a
// provisioning script turns SSO on, so it says what the result means.
func TestConfigSetWarnsWhenItLeavesSSOWithoutAPolicy(t *testing.T) {
	plainColor(t)
	cfg := config.Default()
	for _, kv := range [][2]string{
		{"ui.oidc.issuer", rbactest.Issuer},
		{"ui.oidc.client_id", "cloop"},
		{"ui.oidc.redirect_url", "https://h.example.com/auth/callback"},
		{"ui.oidc.admin_emails", "ops@example.com"},
		{"ui.oidc.enabled", "true"},
	} {
		if err := applyConfigKey(cfg, kv[0], kv[1]); err != nil {
			t.Fatal(err)
		}
	}
	var w bytes.Buffer
	reportOIDCKeyRBAC(&w, "ui.oidc.enabled", cfg.UI.OIDC)
	if !strings.HasPrefix(w.String(), "warning: "+config.RBACOff(rbactest.Issuer)) {
		t.Errorf("enabling SSO without a policy did not warn: %q", w.String())
	}

	w.Reset()
	reportOIDCKeyRBAC(&w, "provider", cfg.UI.OIDC)
	if w.Len() != 0 {
		t.Errorf("a key outside ui.oidc warned: %q", w.String())
	}

	if err := applyConfigKey(cfg, "ui.oidc.default_role", "none"); err != nil {
		t.Fatal(err)
	}
	w.Reset()
	reportOIDCKeyRBAC(&w, "ui.oidc.default_role", cfg.UI.OIDC)
	if w.Len() != 0 {
		t.Errorf("a block with a policy warned: %q", w.String())
	}
}
