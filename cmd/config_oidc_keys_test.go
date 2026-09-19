package cmd

// `cloop config set ui.oidc.*` — the config-file half of Task 20308.
//
// Eight of the fifteen ui.oidc fields had a key; the other seven could only be
// reached by hand-editing config.yaml. That is a poor split for this block in
// particular, because ui.oidc is what a provisioning script configures on a
// fresh hub, and `config set` is what a provisioning script has.
//
// The tests that matter here are the bounds ones. Three of these fields take -1
// as a documented "off" value, which is *below* their lower bound — so a naive
// range check rejects exactly the setting the field's own documentation
// recommends, and the failure looks like the tool not supporting a feature it
// does support.

import (
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/pkg/config"
)

// TestApplyConfigKey_OIDCScalars covers every ui.oidc key end to end: set it,
// read the struct field back. A key that silently does nothing is worse than a
// missing one, because `config set` reports success either way.
func TestApplyConfigKey_OIDCScalars(t *testing.T) {
	cases := []struct {
		key   string
		value string
		check func(config.OIDCConfig) bool
	}{
		{"ui.oidc.enabled", "true", func(o config.OIDCConfig) bool { return o.Enabled }},
		{"ui.oidc.issuer", "https://idp.example.com", func(o config.OIDCConfig) bool {
			return o.Issuer == "https://idp.example.com"
		}},
		{"ui.oidc.client_id", "cloop", func(o config.OIDCConfig) bool { return o.ClientID == "cloop" }},
		{"ui.oidc.client_secret", "s3cret", func(o config.OIDCConfig) bool { return o.ClientSecret == "s3cret" }},
		{"ui.oidc.redirect_url", "https://h/auth/callback", func(o config.OIDCConfig) bool {
			return o.RedirectURL == "https://h/auth/callback"
		}},
		{"ui.oidc.admin_emails", "a@x.com, b@x.com", func(o config.OIDCConfig) bool {
			return len(o.AdminEmails) == 2 && o.AdminEmails[1] == "b@x.com"
		}},
		{"ui.oidc.session_ttl_hours", "48", func(o config.OIDCConfig) bool { return o.SessionTTLHours == 48 }},
		{"ui.oidc.cookie_secure", "always", func(o config.OIDCConfig) bool { return o.CookieSecure == "always" }},

		// The seven that had no key before this task.
		{"ui.oidc.scopes", "openid, email", func(o config.OIDCConfig) bool {
			return len(o.Scopes) == 2 && o.Scopes[0] == "openid"
		}},
		{"ui.oidc.default_role", "viewer", func(o config.OIDCConfig) bool { return o.DefaultRole == "viewer" }},
		{"ui.oidc.idle_timeout_hours", "4", func(o config.OIDCConfig) bool { return o.IdleTimeoutHours == 4 }},
		{"ui.oidc.refresh_interval_minutes", "30", func(o config.OIDCConfig) bool {
			return o.RefreshIntervalMinutes == 30
		}},
		{"ui.oidc.max_claim_age_minutes", "10", func(o config.OIDCConfig) bool { return o.MaxClaimAgeMinutes == 10 }},
		{"ui.oidc.clock_skew_seconds", "120", func(o config.OIDCConfig) bool { return o.ClockSkewSeconds == 120 }},
		{"ui.oidc.require_idp", "true", func(o config.OIDCConfig) bool { return o.RequireIdP }},
	}

	for _, tc := range cases {
		t.Run(tc.key, func(t *testing.T) {
			cfg := config.Default()
			if err := applyConfigKey(cfg, tc.key, tc.value); err != nil {
				t.Fatalf("set %s=%s: %v", tc.key, tc.value, err)
			}
			if !tc.check(cfg.UI.OIDC) {
				t.Errorf("%s=%s did not reach the config: %+v", tc.key, tc.value, cfg.UI.OIDC)
			}
		})
	}
}

// TestApplyConfigKey_OIDCAcceptsDisableSentinel is the bounds case worth having.
// -1 is not out of range for these three, it is the documented way to switch the
// behaviour off — and it sits below each field's lower bound, so a plain range
// check would refuse it.
func TestApplyConfigKey_OIDCAcceptsDisableSentinel(t *testing.T) {
	for _, key := range []string{
		"ui.oidc.refresh_interval_minutes",
		"ui.oidc.max_claim_age_minutes",
		"ui.oidc.clock_skew_seconds",
	} {
		t.Run(key, func(t *testing.T) {
			cfg := config.Default()
			if err := applyConfigKey(cfg, key, "-1"); err != nil {
				t.Errorf("%s=-1 must be accepted (it is the documented off value): %v", key, err)
			}
		})
	}
}

// TestApplyConfigKey_OIDCRejectsOutOfRange: the sentinel exception must not turn
// into "any negative number", and a value above the ceiling has to be caught
// here rather than at the next startup.
func TestApplyConfigKey_OIDCRejectsOutOfRange(t *testing.T) {
	cases := []struct{ key, value string }{
		{"ui.oidc.idle_timeout_hours", "0.5"},
		{"ui.oidc.idle_timeout_hours", "99999"},
		{"ui.oidc.refresh_interval_minutes", "-7"},
		{"ui.oidc.max_claim_age_minutes", "600"},
		{"ui.oidc.clock_skew_seconds", "-7"},
		{"ui.oidc.clock_skew_seconds", "99999"},
		{"ui.oidc.default_role", "superuser"},
		{"ui.oidc.require_idp", "maybe"},
		{"ui.oidc.cookie_secure", "sometimes"},
	}
	for _, tc := range cases {
		t.Run(tc.key+"="+tc.value, func(t *testing.T) {
			cfg := config.Default()
			if err := applyConfigKey(cfg, tc.key, tc.value); err == nil {
				t.Errorf("%s=%s was accepted; it must be refused before it reaches config.yaml",
					tc.key, tc.value)
			}
		})
	}
}

// TestApplyConfigKey_OIDCDefaultRoleNamesTheValidValues: the error has to say
// what is allowed. "superuser is not a known role" without the list sends the
// operator to the source.
func TestApplyConfigKey_OIDCDefaultRoleNamesTheValidValues(t *testing.T) {
	cfg := config.Default()
	err := applyConfigKey(cfg, "ui.oidc.default_role", "superuser")
	if err == nil {
		t.Fatal("expected an error for an unknown role")
	}
	for _, role := range []string{"viewer", "operator", "maintainer", "admin"} {
		if !strings.Contains(err.Error(), role) {
			t.Errorf("the error should list %q as a valid role, got: %v", role, err)
		}
	}
}

// TestApplyConfigKey_OIDCEmptyListClears. Setting a list key to "" is how an
// operator removes the last admin email or reverts to the default scopes; it
// must clear rather than store one empty string, which authz would turn into a
// binding matching an identity with no email claim.
func TestApplyConfigKey_OIDCEmptyListClears(t *testing.T) {
	cfg := config.Default()
	cfg.UI.OIDC.AdminEmails = []string{"a@x.com"}
	cfg.UI.OIDC.Scopes = []string{"openid", "email"}

	if err := applyConfigKey(cfg, "ui.oidc.admin_emails", ""); err != nil {
		t.Fatalf("clear admin_emails: %v", err)
	}
	if err := applyConfigKey(cfg, "ui.oidc.scopes", ""); err != nil {
		t.Fatalf("clear scopes: %v", err)
	}
	if len(cfg.UI.OIDC.AdminEmails) != 0 {
		t.Errorf("admin_emails = %v, want empty", cfg.UI.OIDC.AdminEmails)
	}
	if len(cfg.UI.OIDC.Scopes) != 0 {
		t.Errorf("scopes = %v, want empty", cfg.UI.OIDC.Scopes)
	}
}
