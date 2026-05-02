package profile_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/profile"
)

// setGlobalDir overrides the HOME so that the profile functions use a temp dir.
func setHome(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	return dir
}

func TestLoadProfiles_Empty(t *testing.T) {
	setHome(t)
	profiles, err := profile.LoadProfiles()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(profiles) != 0 {
		t.Fatalf("expected empty slice, got %d profiles", len(profiles))
	}
}

func TestSaveAndLoadProfiles(t *testing.T) {
	setHome(t)

	want := []profile.Profile{
		{Name: "dev", Provider: "anthropic", Model: "claude-opus-4-6", Description: "dev profile"},
		{Name: "local", Provider: "ollama", Model: "llama3.2", BaseURL: "http://localhost:11434"},
	}

	if err := profile.SaveProfiles(want); err != nil {
		t.Fatalf("save: %v", err)
	}

	got, err := profile.LoadProfiles()
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(got) != len(want) {
		t.Fatalf("expected %d profiles, got %d", len(want), len(got))
	}
	for i, p := range got {
		if p.Name != want[i].Name || p.Provider != want[i].Provider || p.Model != want[i].Model {
			t.Errorf("profile[%d] mismatch: got %+v, want %+v", i, p, want[i])
		}
	}
}

func TestUpsert_Create(t *testing.T) {
	setHome(t)

	p := profile.Profile{Name: "test", Provider: "openai", Model: "gpt-4o"}
	if err := profile.Upsert(p); err != nil {
		t.Fatalf("upsert: %v", err)
	}

	profiles, _ := profile.LoadProfiles()
	if len(profiles) != 1 || profiles[0].Name != "test" {
		t.Fatalf("unexpected profiles: %+v", profiles)
	}
}

func TestUpsert_Overwrite(t *testing.T) {
	setHome(t)

	_ = profile.Upsert(profile.Profile{Name: "p1", Provider: "openai", Model: "gpt-4o"})
	_ = profile.Upsert(profile.Profile{Name: "p1", Provider: "anthropic", Model: "claude-opus-4-6"})

	profiles, _ := profile.LoadProfiles()
	if len(profiles) != 1 {
		t.Fatalf("expected 1 profile, got %d", len(profiles))
	}
	if profiles[0].Provider != "anthropic" {
		t.Errorf("expected provider anthropic, got %s", profiles[0].Provider)
	}
}

func TestDelete(t *testing.T) {
	setHome(t)

	_ = profile.Upsert(profile.Profile{Name: "a", Provider: "openai"})
	_ = profile.Upsert(profile.Profile{Name: "b", Provider: "anthropic"})

	if err := profile.Delete("a"); err != nil {
		t.Fatalf("delete: %v", err)
	}

	profiles, _ := profile.LoadProfiles()
	if len(profiles) != 1 || profiles[0].Name != "b" {
		t.Fatalf("unexpected profiles after delete: %+v", profiles)
	}
}

func TestDelete_NonExistent(t *testing.T) {
	setHome(t)
	// Should not error when deleting a profile that doesn't exist.
	if err := profile.Delete("ghost"); err != nil {
		t.Fatalf("delete non-existent: %v", err)
	}
}

func TestGetActive_None(t *testing.T) {
	setHome(t)
	if got := profile.GetActive(); got != "" {
		t.Fatalf("expected empty active profile, got %q", got)
	}
}

func TestSetAndGetActive(t *testing.T) {
	setHome(t)

	if err := profile.SetActive("dev"); err != nil {
		t.Fatalf("set active: %v", err)
	}
	if got := profile.GetActive(); got != "dev" {
		t.Fatalf("expected active=dev, got %q", got)
	}
}

func TestSetActive_Clear(t *testing.T) {
	home := setHome(t)

	_ = profile.SetActive("dev")
	if err := profile.SetActive(""); err != nil {
		t.Fatalf("clear active: %v", err)
	}
	if got := profile.GetActive(); got != "" {
		t.Fatalf("expected empty after clear, got %q", got)
	}
	// File should be removed.
	_, err := os.Stat(filepath.Join(home, ".cloop", "active_profile"))
	if !os.IsNotExist(err) {
		t.Fatalf("expected active_profile file to be removed")
	}
}

func TestGet_Found(t *testing.T) {
	setHome(t)
	_ = profile.Upsert(profile.Profile{Name: "myprofile", Provider: "ollama", Model: "llama3.2"})

	p, err := profile.Get("myprofile")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if p.Provider != "ollama" {
		t.Errorf("expected provider ollama, got %s", p.Provider)
	}
}

func TestGet_NotFound(t *testing.T) {
	setHome(t)
	_, err := profile.Get("noexist")
	if err == nil {
		t.Fatal("expected error for missing profile")
	}
}

func TestApply_Anthropic(t *testing.T) {
	cfg := config.Default()
	p := profile.Profile{
		Name:     "prod",
		Provider: "anthropic",
		Model:    "claude-haiku-4-5-20251001",
		APIKey:   "sk-test",
		BaseURL:  "https://custom.anthropic.com",
	}
	profile.Apply(p, cfg)

	if cfg.Provider != "anthropic" {
		t.Errorf("expected provider anthropic, got %s", cfg.Provider)
	}
	if cfg.Anthropic.Model != "claude-haiku-4-5-20251001" {
		t.Errorf("unexpected model: %s", cfg.Anthropic.Model)
	}
	if cfg.Anthropic.APIKey != "sk-test" {
		t.Errorf("unexpected api key: %s", cfg.Anthropic.APIKey)
	}
	if cfg.Anthropic.BaseURL != "https://custom.anthropic.com" {
		t.Errorf("unexpected base url: %s", cfg.Anthropic.BaseURL)
	}
}

func TestApply_Ollama(t *testing.T) {
	cfg := config.Default()
	p := profile.Profile{
		Name:     "local",
		Provider: "ollama",
		Model:    "mistral",
		BaseURL:  "http://remote:11434",
	}
	profile.Apply(p, cfg)

	if cfg.Ollama.Model != "mistral" {
		t.Errorf("expected model mistral, got %s", cfg.Ollama.Model)
	}
	if cfg.Ollama.BaseURL != "http://remote:11434" {
		t.Errorf("unexpected base url: %s", cfg.Ollama.BaseURL)
	}
}

func TestApply_EmptyFields(t *testing.T) {
	cfg := config.Default()
	original := cfg.Anthropic.Model

	// Empty model should not override existing config.
	p := profile.Profile{Name: "noop", Provider: "anthropic"}
	profile.Apply(p, cfg)

	if cfg.Anthropic.Model != original {
		t.Errorf("expected model to remain %s, got %s", original, cfg.Anthropic.Model)
	}
}
