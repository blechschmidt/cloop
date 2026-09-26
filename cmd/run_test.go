package cmd

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/state"
)

func TestApplyEnvOverrides_Provider(t *testing.T) {
	t.Setenv("CLOOP_PROVIDER", "openai")
	cfg := config.Default()
	applyEnvOverrides(cfg)
	if cfg.Provider != "openai" {
		t.Errorf("expected provider=openai, got %q", cfg.Provider)
	}
}

func TestApplyEnvOverrides_AnthropicAPIKey(t *testing.T) {
	t.Setenv("CLOOP_ANTHROPIC_API_KEY", "sk-test-123")
	cfg := config.Default()
	applyEnvOverrides(cfg)
	if cfg.Anthropic.APIKey != "sk-test-123" {
		t.Errorf("expected anthropic key to be overridden, got %q", cfg.Anthropic.APIKey)
	}
}

func TestApplyEnvOverrides_AnthropicBaseURL(t *testing.T) {
	t.Setenv("CLOOP_ANTHROPIC_BASE_URL", "https://proxy.example.com")
	cfg := config.Default()
	applyEnvOverrides(cfg)
	if cfg.Anthropic.BaseURL != "https://proxy.example.com" {
		t.Errorf("expected anthropic base url to be overridden, got %q", cfg.Anthropic.BaseURL)
	}
}

func TestApplyEnvOverrides_OpenAIAPIKey(t *testing.T) {
	t.Setenv("CLOOP_OPENAI_API_KEY", "sk-openai-456")
	cfg := config.Default()
	applyEnvOverrides(cfg)
	if cfg.OpenAI.APIKey != "sk-openai-456" {
		t.Errorf("expected openai key to be overridden, got %q", cfg.OpenAI.APIKey)
	}
}

func TestApplyEnvOverrides_OpenAIBaseURL(t *testing.T) {
	t.Setenv("CLOOP_OPENAI_BASE_URL", "https://myazure.openai.azure.com")
	cfg := config.Default()
	applyEnvOverrides(cfg)
	if cfg.OpenAI.BaseURL != "https://myazure.openai.azure.com" {
		t.Errorf("expected openai base url to be overridden, got %q", cfg.OpenAI.BaseURL)
	}
}

func TestApplyEnvOverrides_OllamaBaseURL(t *testing.T) {
	t.Setenv("CLOOP_OLLAMA_BASE_URL", "http://remote:11434")
	cfg := config.Default()
	applyEnvOverrides(cfg)
	if cfg.Ollama.BaseURL != "http://remote:11434" {
		t.Errorf("expected ollama base url to be overridden, got %q", cfg.Ollama.BaseURL)
	}
}

func TestApplyEnvOverrides_UnsetVarsNoChange(t *testing.T) {
	// Ensure none of the CLOOP_* vars are set
	for _, key := range []string{
		"CLOOP_PROVIDER", "CLOOP_ANTHROPIC_API_KEY", "CLOOP_ANTHROPIC_BASE_URL",
		"CLOOP_OPENAI_API_KEY", "CLOOP_OPENAI_BASE_URL", "CLOOP_OLLAMA_BASE_URL",
	} {
		os.Unsetenv(key)
	}

	cfg := config.Default()
	cfg.Provider = "claudecode"
	cfg.Anthropic.APIKey = "existing-key"
	applyEnvOverrides(cfg)

	if cfg.Provider != "claudecode" {
		t.Errorf("provider changed when no env var set, got %q", cfg.Provider)
	}
	if cfg.Anthropic.APIKey != "existing-key" {
		t.Errorf("anthropic key changed when no env var set, got %q", cfg.Anthropic.APIKey)
	}
}

func TestApplyEnvOverrides_MultipleVars(t *testing.T) {
	t.Setenv("CLOOP_PROVIDER", "anthropic")
	t.Setenv("CLOOP_ANTHROPIC_API_KEY", "sk-multi")

	cfg := config.Default()
	applyEnvOverrides(cfg)

	if cfg.Provider != "anthropic" {
		t.Errorf("expected provider=anthropic, got %q", cfg.Provider)
	}
	if cfg.Anthropic.APIKey != "sk-multi" {
		t.Errorf("expected anthropic key=sk-multi, got %q", cfg.Anthropic.APIKey)
	}
}

func TestAutoSelectProvider_CloopAnthropicKey(t *testing.T) {
	// Clear standard keys, set CLOOP_ANTHROPIC_API_KEY
	os.Unsetenv("ANTHROPIC_API_KEY")
	os.Unsetenv("OPENAI_API_KEY")
	os.Unsetenv("CLOOP_OPENAI_API_KEY")
	t.Setenv("CLOOP_ANTHROPIC_API_KEY", "sk-cloop-test")

	got := autoSelectProvider()
	if got != "anthropic" {
		t.Errorf("expected anthropic from CLOOP_ANTHROPIC_API_KEY, got %q", got)
	}
}

func TestAutoSelectProvider_CloopOpenAIKey(t *testing.T) {
	os.Unsetenv("ANTHROPIC_API_KEY")
	os.Unsetenv("OPENAI_API_KEY")
	os.Unsetenv("CLOOP_ANTHROPIC_API_KEY")
	t.Setenv("CLOOP_OPENAI_API_KEY", "sk-cloop-openai")

	got := autoSelectProvider()
	if got != "openai" {
		t.Errorf("expected openai from CLOOP_OPENAI_API_KEY, got %q", got)
	}
}

func TestAutoSelectProvider_FallbackClaudeCode(t *testing.T) {
	for _, key := range []string{
		"ANTHROPIC_API_KEY", "OPENAI_API_KEY",
		"CLOOP_ANTHROPIC_API_KEY", "CLOOP_OPENAI_API_KEY",
	} {
		os.Unsetenv(key)
	}

	got := autoSelectProvider()
	if got != "claudecode" {
		t.Errorf("expected claudecode fallback, got %q", got)
	}
}

// TestPreferProjectChoice covers the one directory where Default() must not
// outrank a project's recorded provider: one with no configuration of its own,
// which is what every project seeded onto a remote executor is (Task 20339).
func TestPreferProjectChoice(t *testing.T) {
	st := &state.ProjectState{Provider: "mock", Model: "the-projects-model"}

	t.Run("no config: the project's choice wins", func(t *testing.T) {
		t.Setenv("CLOOP_PROVIDER", "")
		cfg := config.Default()
		keep := preferProjectChoice(cfg, st, t.TempDir(), "", "")
		if cfg.Provider != "mock" || !keep {
			t.Errorf("provider = %q, keepStateModel = %v; want mock and true", cfg.Provider, keep)
		}
	})
	t.Run("a config file is a choice and still wins", func(t *testing.T) {
		t.Setenv("CLOOP_PROVIDER", "")
		dir := t.TempDir()
		if err := os.MkdirAll(filepath.Join(dir, ".cloop"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, ".cloop", "config.yaml"), []byte("provider: claudecode\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		cfg := config.Default()
		if keep := preferProjectChoice(cfg, st, dir, "", ""); keep || cfg.Provider != "claudecode" {
			t.Errorf("provider = %q, keep = %v; an explicit config must keep winning", cfg.Provider, keep)
		}
	})
	t.Run("flag, env and profile still win", func(t *testing.T) {
		for name, call := range map[string]func(*config.Config) bool{
			"flag":    func(c *config.Config) bool { return preferProjectChoice(c, st, t.TempDir(), "openai", "") },
			"profile": func(c *config.Config) bool { return preferProjectChoice(c, st, t.TempDir(), "", "work") },
		} {
			cfg := config.Default()
			if keep := call(cfg); keep || cfg.Provider != "claudecode" {
				t.Errorf("%s: provider = %q, keep = %v", name, cfg.Provider, keep)
			}
		}
		t.Setenv("CLOOP_PROVIDER", "anthropic")
		cfg := config.Default()
		if keep := preferProjectChoice(cfg, st, t.TempDir(), "", ""); keep {
			t.Error("CLOOP_PROVIDER must keep winning")
		}
	})
	t.Run("a project that chose nothing keeps the defaults", func(t *testing.T) {
		t.Setenv("CLOOP_PROVIDER", "")
		cfg := config.Default()
		if keep := preferProjectChoice(cfg, &state.ProjectState{}, t.TempDir(), "", ""); keep || cfg.Provider != "claudecode" {
			t.Errorf("provider = %q, keep = %v", cfg.Provider, keep)
		}
	})
}
