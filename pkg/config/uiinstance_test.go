package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// writeConfigs lays down a project config and, when overlay is non-empty, an
// overlay for port, returning the workdir.
func writeConfigs(t *testing.T, base, overlay string, port int) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, ".cloop"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if base != "" {
		if err := os.WriteFile(ConfigPath(dir), []byte(base), 0o600); err != nil {
			t.Fatalf("write base: %v", err)
		}
	}
	if overlay != "" {
		if err := os.WriteFile(UIInstanceConfigPath(dir, port), []byte(overlay), 0o600); err != nil {
			t.Fatalf("write overlay: %v", err)
		}
	}
	return dir
}

const baseWithoutSSO = `provider: claudecode
anthropic:
    model: claude-opus-4-6
ui:
    telemetry:
        enabled: true
`

// TestOverlayEnablesSSOForOneInstanceOnly is the reason the mechanism exists:
// two hubs share a working directory and only one of them may require a login.
func TestOverlayEnablesSSOForOneInstanceOnly(t *testing.T) {
	dir := writeConfigs(t, baseWithoutSSO, `ui:
    oidc:
        enabled: true
        issuer: https://login.microsoftonline.com/tenant/v2.0
        client_id: abc-123
        redirect_url: https://hub.example:8888/auth/oidc
        default_role: none
`, 8081)

	withSSO, overlay, err := LoadUIInstance(dir, 8081)
	if err != nil {
		t.Fatalf("LoadUIInstance(8081): %v", err)
	}
	if !withSSO.UI.OIDC.Enabled {
		t.Fatal("the hub named by the overlay did not get SSO")
	}
	if overlay != UIInstanceConfigPath(dir, 8081) {
		t.Errorf("overlay path = %q, want the .ui-8081 file so the banner can name it", overlay)
	}

	// The other hub in the same directory, which must be untouched: this is
	// the one that crash-looped when SSO went into the shared file.
	other, otherOverlay, err := LoadUIInstance(dir, 8080)
	if err != nil {
		t.Fatalf("LoadUIInstance(8080): %v", err)
	}
	if other.UI.OIDC.Enabled {
		t.Error("SSO leaked into the hub on :8080 — it has no callback for that redirect_url")
	}
	if otherOverlay != "" {
		t.Errorf("reported overlay %q for a port that has none", otherOverlay)
	}

	// And plain Load — every other cloop command — must still see the project
	// config alone.
	plain, err := Load(dir)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if plain.UI.OIDC.Enabled {
		t.Error("the overlay reached config.Load, so it now applies to every command in the project")
	}
}

func TestOverlayMergesRatherThanReplaces(t *testing.T) {
	dir := writeConfigs(t, baseWithoutSSO, `ui:
    oidc:
        enabled: true
        issuer: https://idp.example/v2.0
        client_id: abc-123
`, 8081)

	cfg, _, err := LoadUIInstance(dir, 8081)
	if err != nil {
		t.Fatalf("LoadUIInstance: %v", err)
	}
	if cfg.Provider != "claudecode" {
		t.Errorf("Provider = %q, want the project value to survive a ui-only overlay", cfg.Provider)
	}
	if cfg.Anthropic.Model != "claude-opus-4-6" {
		t.Errorf("Anthropic.Model = %q, want the project value to survive", cfg.Anthropic.Model)
	}
	// A sibling key under the same `ui` mapping: proof the merge is per-key
	// and not a wholesale replacement of the ui block.
	if cfg.UI.Telemetry.Enabled == nil || !*cfg.UI.Telemetry.Enabled {
		t.Error("ui.telemetry was dropped — the overlay replaced the whole ui block")
	}
}

func TestOverlaySequencesReplace(t *testing.T) {
	dir := writeConfigs(t, `ui:
    oidc:
        scopes: [openid, profile, email, groups]
`, `ui:
    oidc:
        scopes: [openid, offline_access]
`, 8081)

	cfg, _, err := LoadUIInstance(dir, 8081)
	if err != nil {
		t.Fatalf("LoadUIInstance: %v", err)
	}
	want := []string{"openid", "offline_access"}
	if strings.Join(cfg.UI.OIDC.Scopes, ",") != strings.Join(want, ",") {
		t.Errorf("Scopes = %v, want %v — a sequence in an overlay must replace, not append", cfg.UI.OIDC.Scopes, want)
	}
}

func TestNoOverlayIsNotAnError(t *testing.T) {
	dir := writeConfigs(t, baseWithoutSSO, "", 0)
	cfg, overlay, err := LoadUIInstance(dir, 8081)
	if err != nil {
		t.Fatalf("LoadUIInstance with no overlay: %v", err)
	}
	if overlay != "" {
		t.Errorf("overlay = %q, want empty", overlay)
	}
	if cfg.Provider != "claudecode" {
		t.Errorf("Provider = %q, want the project config to load normally", cfg.Provider)
	}
}

// TestMalformedOverlayIsFatal: the overlay carries the setting that decides
// whether anyone needs to log in, so a typo in it must stop the hub rather
// than start it wide open with a line on stderr.
func TestMalformedOverlayIsFatal(t *testing.T) {
	dir := writeConfigs(t, baseWithoutSSO, "ui:\n  oidc:\n   enabled: [unclosed\n", 8081)
	_, _, err := LoadUIInstance(dir, 8081)
	if err == nil {
		t.Fatal("a malformed overlay loaded without error")
	}
	if !strings.Contains(err.Error(), "config.ui-8081.yaml") {
		t.Errorf("error %q does not name the file to fix", err)
	}
}

func TestPortZeroReadsNoOverlay(t *testing.T) {
	dir := writeConfigs(t, baseWithoutSSO, "ui:\n    oidc:\n        enabled: true\n", 0)
	// An unbound port must not invent config.ui-0.yaml, which no operator wrote.
	if _, overlay, err := LoadUIInstance(dir, 0); err != nil || overlay != "" {
		t.Errorf("LoadUIInstance(port 0) = %q, %v; want no overlay and no error", overlay, err)
	}
}

func TestOverlayValuesAreClamped(t *testing.T) {
	// MaxMaxClaimAge is an hour; a day written one file over must not escape a
	// bound that config.yaml cannot escape.
	dir := writeConfigs(t, baseWithoutSSO, `ui:
    oidc:
        enabled: true
        max_claim_age_minutes: 1440
`, 8081)
	cfg, _, err := LoadUIInstance(dir, 8081)
	if err != nil {
		t.Fatalf("LoadUIInstance: %v", err)
	}
	if got := cfg.UI.OIDC.EffectiveMaxClaimAgeMinutes(); got > 60 {
		t.Errorf("max_claim_age_minutes = %d, want it clamped to the same bound config.yaml gets", got)
	}
}

// TestSaveUIInstanceOIDCPreservesTheRestOfTheFile covers the settings panel
// writing back: the overlay is an operator's file, and the panel owns exactly
// one block in it.
func TestSaveUIInstanceOIDCPreservesTheRestOfTheFile(t *testing.T) {
	dir := writeConfigs(t, baseWithoutSSO, `# Why this hub requires a login.
ui:
    # nginx terminates TLS for this one.
    allowed_origins:
        - https://hub.example:8888
    oidc:
        enabled: true
        issuer: https://old.example/v2.0
        client_id: abc-123
`, 8081)
	path := UIInstanceConfigPath(dir, 8081)

	cfg, _, err := LoadUIInstance(dir, 8081)
	if err != nil {
		t.Fatalf("LoadUIInstance: %v", err)
	}
	cfg.UI.OIDC.Issuer = "https://new.example/v2.0"
	if err := SaveUIInstanceOIDC(path, cfg.UI.OIDC); err != nil {
		t.Fatalf("SaveUIInstanceOIDC: %v", err)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if !strings.Contains(string(raw), "Why this hub requires a login") {
		t.Error("the operator's leading comment was lost")
	}
	if !strings.Contains(string(raw), "nginx terminates TLS") {
		t.Error("a comment on an untouched key was lost")
	}

	after, _, err := LoadUIInstance(dir, 8081)
	if err != nil {
		t.Fatalf("LoadUIInstance after save: %v", err)
	}
	if after.UI.OIDC.Issuer != "https://new.example/v2.0" {
		t.Errorf("Issuer = %q, want the saved value", after.UI.OIDC.Issuer)
	}
	if len(after.UI.AllowedOrigins) != 1 || after.UI.AllowedOrigins[0] != "https://hub.example:8888" {
		t.Errorf("AllowedOrigins = %v, want the untouched sibling key intact", after.UI.AllowedOrigins)
	}
	// Nothing from the project config may be copied in: the overlay shadows
	// config.yaml, so a copied API key would freeze at the value it had today.
	var doc map[string]any
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("overlay no longer parses: %v", err)
	}
	if _, leaked := doc["anthropic"]; leaked {
		t.Error("the whole project config was written into the overlay")
	}
	if _, leaked := doc["provider"]; leaked {
		t.Error("the whole project config was written into the overlay")
	}
}

func TestSaveUIInstanceOIDCCreatesTheFileWith0600(t *testing.T) {
	dir := writeConfigs(t, baseWithoutSSO, "", 0)
	path := UIInstanceConfigPath(dir, 8081)

	if err := SaveUIInstanceOIDC(path, OIDCConfig{Enabled: true, Issuer: "https://idp.example/v2.0", ClientID: "abc"}); err != nil {
		t.Fatalf("SaveUIInstanceOIDC: %v", err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	// The block can hold a client secret.
	if perm := fi.Mode().Perm(); perm&0o077 != 0 {
		t.Errorf("overlay mode = %o, want owner-only", perm)
	}
	cfg, overlay, err := LoadUIInstance(dir, 8081)
	if err != nil {
		t.Fatalf("LoadUIInstance: %v", err)
	}
	if overlay == "" || !cfg.UI.OIDC.Enabled {
		t.Error("the created overlay is not picked up by the hub that created it")
	}
}

// TestBaseSaveDoesNotDisturbTheOverlay is the property the whole file-vs-section
// choice rests on: a writer that does not know about the overlay cannot delete
// the block that requires a login.
func TestBaseSaveDoesNotDisturbTheOverlay(t *testing.T) {
	overlay := "ui:\n    oidc:\n        enabled: true\n        issuer: https://idp.example/v2.0\n        client_id: abc\n"
	dir := writeConfigs(t, baseWithoutSSO, overlay, 8081)

	cfg, err := Load(dir)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	cfg.Provider = "anthropic"
	if err := Save(dir, cfg); err != nil {
		t.Fatalf("Save: %v", err)
	}

	got, err := os.ReadFile(UIInstanceConfigPath(dir, 8081))
	if err != nil {
		t.Fatalf("overlay gone after a base save: %v", err)
	}
	if string(got) != overlay {
		t.Errorf("overlay changed after a base save:\n%s", got)
	}
	after, _, err := LoadUIInstance(dir, 8081)
	if err != nil {
		t.Fatalf("LoadUIInstance: %v", err)
	}
	if !after.UI.OIDC.Enabled {
		t.Error("a base config save turned SSO off")
	}
	if after.Provider != "anthropic" {
		t.Errorf("Provider = %q, want the base edit to still be visible through the overlay", after.Provider)
	}
}
