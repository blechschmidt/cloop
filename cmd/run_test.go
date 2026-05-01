package cmd

import (
	"os"
	"testing"

	"github.com/blechschmidt/cloop/pkg/config"
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
