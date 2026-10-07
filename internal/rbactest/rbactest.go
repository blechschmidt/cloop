// Package rbactest holds the ui.oidc shapes every RBAC reporter is tested
// against (Task 20395): `cloop hub doctor`, the Settings panel, /api/me and the
// startup log each have to give authz.Enforced's answer for the same five
// blocks, and leave :8888's access exactly as it was.
//
// Test-only (tests/arch/testonly_test.go): it imports "testing".
package rbactest

import (
	_ "embed"
	"os"
	"path/filepath"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/blechschmidt/cloop/pkg/config"
)

// Issuer is the identity provider every Matrix case signs in through.
const Issuer = "https://idp.example.com/realms/main"

// Case is one ui.oidc block and authz.Enforced's verdict on it.
type Case struct {
	Name string
	OIDC config.OIDCConfig
	// Enforced is whether RBAC is in force for a hub running this block.
	Enforced bool
}

// Matrix returns the five blocks the task names, in its order: single sign-on
// off, SSO alone, SSO with admin_emails (the Task 20317 hub's shape), SSO with
// a default_role, and SSO with role mappings. Only the last two write a policy.
func Matrix() []Case {
	base := func() config.OIDCConfig {
		return config.OIDCConfig{
			Enabled:     true,
			Issuer:      Issuer,
			ClientID:    "cloop-hub",
			RedirectURL: "https://cloop.example.com/auth/callback",
		}
	}
	off := base()
	off.Enabled = false
	off.AdminEmails = []string{"ops@example.com"}

	only := base()

	admins := base()
	admins.AdminEmails = []string{"ops@example.com"}

	defaultRole := base()
	defaultRole.DefaultRole = "none"

	mappings := base()
	mappings.Scopes = []string{"openid", "profile", "email", "groups"}
	mappings.RoleMappings = []config.RoleMapping{{Claim: "group", Value: "platform", Role: "admin"}}

	return []Case{
		{Name: "SSO off", OIDC: off, Enforced: false},
		{Name: "SSO only", OIDC: only, Enforced: false},
		{Name: "SSO + admin_emails", OIDC: admins, Enforced: false},
		{Name: "SSO + default_role", OIDC: defaultRole, Enforced: true},
		{Name: "SSO + mappings", OIDC: mappings, Enforced: true},
	}
}

//go:embed hub8888-oidc.yaml
var hub8888 []byte

// Hub8888Port is the --port :8888's hub runs with, which names its overlay.
const Hub8888Port = 8081

// Hub8888Admin is the address :8888's policy makes an administrator.
const Hub8888Admin = "microsoft@blechschmidt.saarland"

// Hub8888Overlay is a copy of :8888's per-port overlay reduced to its ui.oidc
// section — no secret, it has none.
func Hub8888Overlay() []byte { return append([]byte(nil), hub8888...) }

// Hub8888 decodes that section the way config.Load decodes the live file.
func Hub8888(t testing.TB) config.OIDCConfig {
	t.Helper()
	var doc struct {
		UI struct {
			OIDC config.OIDCConfig `yaml:"oidc"`
		} `yaml:"ui"`
	}
	if err := yaml.Unmarshal(hub8888, &doc); err != nil {
		t.Fatalf("decode the :8888 ui.oidc copy: %v", err)
	}
	return doc.UI.OIDC
}

// WriteHub8888 lays the copy down as dir's overlay for Hub8888Port, beside a
// config.yaml with no ui.oidc — the arrangement :8888 runs from — so a test
// can load it through config.LoadUIInstance as the hub does.
func WriteHub8888(t testing.TB, dir string) {
	t.Helper()
	if err := config.Save(dir, config.Default()); err != nil {
		t.Fatalf("seed config.yaml: %v", err)
	}
	path := config.UIInstanceConfigPath(dir, Hub8888Port)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, Hub8888Overlay(), 0o600); err != nil {
		t.Fatalf("write the overlay: %v", err)
	}
}
