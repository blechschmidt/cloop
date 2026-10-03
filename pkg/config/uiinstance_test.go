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

// TestSaveUIInstanceCIWritesThePanelKeysOnly: the CI block the panel edits
// lands in the overlay, the operator's comments survive, and the relay's
// upstream token, which the panel cannot edit, is not copied out of
// config.yaml into a second file (Task 20364).
func TestSaveUIInstanceCIWritesThePanelKeysOnly(t *testing.T) {
	base := baseWithoutSSO + "    ci:\n        issuer: https://shared.example\n        upstream_auth_token: sk-ant-oat-shared\n"
	dir := writeConfigs(t, base, "# :8081 only.\nui:\n    allowed_origins: [https://hub.example:8888]\n", 8081)
	path := UIInstanceConfigPath(dir, 8081)

	cfg, _, err := LoadUIInstance(dir, 8081)
	if err != nil {
		t.Fatalf("LoadUIInstance: %v", err)
	}
	cfg.UI.CI.Enabled = true
	cfg.UI.CI.Audience = "cloop-8081"
	cfg.UI.CI.DefaultModels = []string{"claude-sonnet-*"}
	if err := SaveUIInstanceCI(path, cfg.UI.CI); err != nil {
		t.Fatalf("SaveUIInstanceCI: %v", err)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if !strings.Contains(string(raw), "# :8081 only.") {
		t.Error("the operator's comment was lost")
	}
	if strings.Contains(string(raw), "sk-ant-oat-shared") {
		t.Errorf("the upstream token was copied into the overlay:\n%s", raw)
	}

	after, _, err := LoadUIInstance(dir, 8081)
	if err != nil {
		t.Fatalf("LoadUIInstance after save: %v", err)
	}
	c := after.UI.CI
	if !c.Enabled || c.Audience != "cloop-8081" || len(c.DefaultModels) != 1 || c.DefaultModels[0] != "claude-sonnet-*" {
		t.Errorf("after the save: %+v", c)
	}
	// The issuer was shown by the panel and saved unchanged, so it is pinned
	// in the overlay. The token was never the panel's, so it still comes from
	// config.yaml.
	if c.Issuer != "https://shared.example" || c.UpstreamAuthToken != "sk-ant-oat-shared" {
		t.Errorf("issuer=%q upstream_auth_token=%q after the save", c.Issuer, c.UpstreamAuthToken)
	}
	if len(after.UI.AllowedOrigins) != 1 {
		t.Errorf("AllowedOrigins = %v, want the untouched sibling key intact", after.UI.AllowedOrigins)
	}
}

// TestSaveUIInstanceCIZeroValuesShadowConfigYAML: a save that turns
// federation off, or clears the issuer, has to say so in the overlay.
// Leaving a zero value out would let config.yaml's value show through, and
// the hub would keep federating after a save that said stop.
func TestSaveUIInstanceCIZeroValuesShadowConfigYAML(t *testing.T) {
	base := baseWithoutSSO + "    ci:\n        enabled: true\n        issuer: https://shared.example\n"
	dir := writeConfigs(t, base, "", 0)
	path := UIInstanceConfigPath(dir, 8081)

	if err := SaveUIInstanceCI(path, CIConfig{}); err != nil {
		t.Fatalf("SaveUIInstanceCI: %v", err)
	}
	after, _, err := LoadUIInstance(dir, 8081)
	if err != nil {
		t.Fatalf("LoadUIInstance: %v", err)
	}
	if after.UI.CI.Enabled || after.UI.CI.Issuer != "" {
		t.Errorf("enabled=%v issuer=%q: config.yaml showed through the overlay's zero values",
			after.UI.CI.Enabled, after.UI.CI.Issuer)
	}
}

// TestSaveUIInstanceSTTKey: the dictation key goes into the overlay, and an
// empty key shadows the one in config.yaml instead of letting it show through.
func TestSaveUIInstanceSTTKey(t *testing.T) {
	base := baseWithoutSSO + "stt:\n    groq_api_key: gsk_shared\n    language: de\n"
	dir := writeConfigs(t, base, "", 0)
	path := UIInstanceConfigPath(dir, 8081)

	if err := SaveUIInstanceSTTKey(path, "gsk_this_hub"); err != nil {
		t.Fatalf("SaveUIInstanceSTTKey: %v", err)
	}
	after, _, err := LoadUIInstance(dir, 8081)
	if err != nil {
		t.Fatalf("LoadUIInstance: %v", err)
	}
	if after.STT.GroqAPIKey != "gsk_this_hub" {
		t.Errorf("GroqAPIKey = %q, want the overlay's", after.STT.GroqAPIKey)
	}
	if after.STT.Language != "de" {
		t.Errorf("Language = %q: writing the key replaced the rest of the stt section", after.STT.Language)
	}

	if err := SaveUIInstanceSTTKey(path, ""); err != nil {
		t.Fatalf("SaveUIInstanceSTTKey(\"\"): %v", err)
	}
	after, _, err = LoadUIInstance(dir, 8081)
	if err != nil {
		t.Fatalf("LoadUIInstance: %v", err)
	}
	if after.STT.GroqAPIKey != "" {
		t.Errorf("GroqAPIKey = %q after clearing: the shared key showed through", after.STT.GroqAPIKey)
	}
	shared, err := Load(dir)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if shared.STT.GroqAPIKey != "gsk_shared" {
		t.Errorf("config.yaml's key is %q, want it untouched", shared.STT.GroqAPIKey)
	}
}

// TestUIInstancePorts lists the hubs in a directory that have overlays, and
// nothing that merely looks like one.
func TestUIInstancePorts(t *testing.T) {
	dir := writeConfigs(t, baseWithoutSSO, "ui: {}\n", 8081)
	for _, name := range []string{
		"config.ui-8080.yaml",  // a second hub
		"config.ui-08082.yaml", // not a name UIInstanceConfigPath produces
		"config.ui-99999.yaml", // not a port
		"config.ui-x.yaml",
		"config.ui-.yaml",
		"config.ui-8083.yml",
	} {
		if err := os.WriteFile(filepath.Join(dir, ".cloop", name), []byte("ui: {}\n"), 0o600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	ports, err := UIInstancePorts(dir)
	if err != nil {
		t.Fatalf("UIInstancePorts: %v", err)
	}
	if len(ports) != 2 || ports[0] != 8080 || ports[1] != 8081 {
		t.Errorf("UIInstancePorts = %v, want [8080 8081]", ports)
	}

	none, err := UIInstancePorts(t.TempDir())
	if err != nil || len(none) != 0 {
		t.Errorf("a directory with no .cloop: ports=%v err=%v, want none and no error", none, err)
	}
}
