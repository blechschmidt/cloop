package config

// Save must not commit a credential that arrived from the environment
// (Task 20308).
//
// applyEnvVars overlays CLOOP_OIDC_CLIENT_SECRET and the provider keys onto the
// loaded config, so every load-modify-save in the codebase — `cloop config
// set`, the Settings panel, config repair — reads a struct whose credential
// fields may hold values that were deliberately kept out of the file. Before
// this, writing any unrelated setting persisted them.
//
// That is not a cosmetic leak. The OIDC client secret's whole reason for having
// an environment override is that config.yaml is the file an operator templates
// into a ConfigMap and commits to a config repo; a hub that writes the secret
// into it has lost the property the override existed to provide, and nothing
// says so.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// readRawConfig returns config.yaml's bytes, which is the only view that
// answers "what would be committed".
func readRawConfig(t *testing.T, dir string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(dir, ".cloop", "config.yaml"))
	if err != nil {
		t.Fatalf("read config.yaml: %v", err)
	}
	return string(raw)
}

func TestSave_DoesNotPersistEnvSuppliedOIDCSecret(t *testing.T) {
	const envSecret = "secret-that-lives-in-a-k8s-secret"
	dir := t.TempDir()

	// The file itself holds no secret: the environment is the only source.
	cfg := Default()
	cfg.UI.OIDC.Enabled = true
	cfg.UI.OIDC.Issuer = "https://idp.example.com"
	if err := Save(dir, cfg); err != nil {
		t.Fatalf("seed: %v", err)
	}

	t.Setenv(EnvOIDCClientSecret, envSecret)

	// The load-modify-save every caller performs.
	loaded, err := Load(dir)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if loaded.UI.OIDC.ClientSecret != envSecret {
		t.Fatalf("precondition: the env override did not apply (got %q)", loaded.UI.OIDC.ClientSecret)
	}
	loaded.UI.OIDC.SessionTTLHours = 12 // something unrelated
	if err := Save(dir, loaded); err != nil {
		t.Fatalf("save: %v", err)
	}

	if raw := readRawConfig(t, dir); strings.Contains(raw, envSecret) {
		t.Fatalf("the environment's client secret was committed to config.yaml:\n%s", raw)
	}
	// The unrelated edit did land — the restore must be surgical, not a veto on
	// the whole write.
	reloaded, err := Load(dir)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if reloaded.UI.OIDC.SessionTTLHours != 12 {
		t.Errorf("session_ttl_hours = %d, want the edit to have been saved", reloaded.UI.OIDC.SessionTTLHours)
	}
	// And the secret still resolves, because the environment still supplies it.
	if reloaded.UI.OIDC.ClientSecret != envSecret {
		t.Errorf("the env secret must still be in force after the save (got %q)",
			reloaded.UI.OIDC.ClientSecret)
	}
}

// TestSave_PersistsASecretTheCallerAssigned is the boundary the restore must
// not cross. "Nobody touched this since Load" and "a caller assigned a new
// value" are distinguished by whether the field still equals what the
// environment supplied — and the second case is somebody typing a credential
// into the Settings panel on a machine that happens to also export one.
func TestSave_PersistsASecretTheCallerAssigned(t *testing.T) {
	dir := t.TempDir()
	if err := Save(dir, Default()); err != nil {
		t.Fatalf("seed: %v", err)
	}
	t.Setenv(EnvOIDCClientSecret, "from-the-environment")

	loaded, err := Load(dir)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	loaded.UI.OIDC.ClientSecret = "typed-by-the-operator"
	if err := Save(dir, loaded); err != nil {
		t.Fatalf("save: %v", err)
	}

	if raw := readRawConfig(t, dir); !strings.Contains(raw, "typed-by-the-operator") {
		t.Fatalf("an explicitly assigned secret was discarded:\n%s", raw)
	}
}

// TestSave_PreservesAFileSecretThatMatchesTheEnvironment. The restore puts back
// what the *file* held, not the empty string — so a deployment that has the
// same value in both places does not silently lose the file's copy and break
// the next time the environment variable is not set.
func TestSave_PreservesAFileSecretThatMatchesTheEnvironment(t *testing.T) {
	const shared = "same-value-in-both-places"
	dir := t.TempDir()

	cfg := Default()
	cfg.UI.OIDC.ClientSecret = shared
	if err := Save(dir, cfg); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if raw := readRawConfig(t, dir); !strings.Contains(raw, shared) {
		t.Fatalf("precondition: the seed did not write the secret:\n%s", raw)
	}

	t.Setenv(EnvOIDCClientSecret, shared)
	loaded, err := Load(dir)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	loaded.MaxParallel = 3
	if err := Save(dir, loaded); err != nil {
		t.Fatalf("save: %v", err)
	}
	if raw := readRawConfig(t, dir); !strings.Contains(raw, shared) {
		t.Fatalf("the file's own secret was removed because it matched the environment:\n%s", raw)
	}
}

// TestSave_DoesNotMutateTheCallersConfig. Save takes a pointer, and the
// restore rewrites a credential field — so a caller that keeps using its
// config after saving must not find the secret blanked underneath it.
func TestSave_DoesNotMutateTheCallersConfig(t *testing.T) {
	const envSecret = "from-the-environment"
	dir := t.TempDir()
	if err := Save(dir, Default()); err != nil {
		t.Fatalf("seed: %v", err)
	}
	t.Setenv(EnvOIDCClientSecret, envSecret)

	loaded, err := Load(dir)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if err := Save(dir, loaded); err != nil {
		t.Fatalf("save: %v", err)
	}
	if loaded.UI.OIDC.ClientSecret != envSecret {
		t.Errorf("Save emptied the caller's in-memory secret (got %q) — "+
			"a long-lived process would stop being able to authenticate",
			loaded.UI.OIDC.ClientSecret)
	}
}

// TestSave_AppliesToEveryEnvSuppliedCredential. The OIDC secret is the one with
// a documented invariant, but the provider keys arrive the same way and leak
// the same way, and one table serves both directions so they cannot drift.
func TestSave_AppliesToEveryEnvSuppliedCredential(t *testing.T) {
	cases := []struct {
		env   string
		value string
	}{
		{EnvOIDCClientSecret, "oidc-env-secret"},
		{"ANTHROPIC_API_KEY", "sk-ant-env-key"},
		{"OPENAI_API_KEY", "sk-openai-env-key"},
		{"GITHUB_TOKEN", "ghp-env-credential"},
	}
	for _, tc := range cases {
		t.Run(tc.env, func(t *testing.T) {
			dir := t.TempDir()
			if err := Save(dir, Default()); err != nil {
				t.Fatalf("seed: %v", err)
			}
			t.Setenv(tc.env, tc.value)

			loaded, err := Load(dir)
			if err != nil {
				t.Fatalf("load: %v", err)
			}
			if err := Save(dir, loaded); err != nil {
				t.Fatalf("save: %v", err)
			}
			if raw := readRawConfig(t, dir); strings.Contains(raw, tc.value) {
				t.Fatalf("%s was committed to config.yaml:\n%s", tc.env, raw)
			}
		})
	}
}
