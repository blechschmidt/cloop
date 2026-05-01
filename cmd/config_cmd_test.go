package cmd

import (
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/pkg/config"
)

// --- applyConfigKey ---

func TestApplyConfigKey_Provider_Valid(t *testing.T) {
	for _, prov := range []string{"anthropic", "openai", "ollama", "claudecode"} {
		cfg := config.Default()
		if err := applyConfigKey(cfg, "provider", prov); err != nil {
			t.Errorf("provider %q: unexpected error: %v", prov, err)
		}
		if cfg.Provider != prov {
			t.Errorf("provider %q: expected %q, got %q", prov, prov, cfg.Provider)
		}
	}
}

func TestApplyConfigKey_Provider_Invalid(t *testing.T) {
	cfg := config.Default()
	err := applyConfigKey(cfg, "provider", "unknown-provider")
	if err == nil {
		t.Error("expected error for unknown provider")
	}
	if !strings.Contains(err.Error(), "unknown provider") {
		t.Errorf("error should mention 'unknown provider', got: %v", err)
	}
}

func TestApplyConfigKey_AnthropicAPIKey(t *testing.T) {
	cfg := config.Default()
	if err := applyConfigKey(cfg, "anthropic.api_key", "sk-ant-test123"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Anthropic.APIKey != "sk-ant-test123" {
		t.Errorf("expected API key %q, got %q", "sk-ant-test123", cfg.Anthropic.APIKey)
	}
}

func TestApplyConfigKey_AnthropicModel(t *testing.T) {
	cfg := config.Default()
	if err := applyConfigKey(cfg, "anthropic.model", "claude-opus-4-6"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Anthropic.Model != "claude-opus-4-6" {
		t.Errorf("expected model %q, got %q", "claude-opus-4-6", cfg.Anthropic.Model)
	}
}

func TestApplyConfigKey_AnthropicBaseURL(t *testing.T) {
	cfg := config.Default()
	if err := applyConfigKey(cfg, "anthropic.base_url", "https://custom.anthropic.com"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Anthropic.BaseURL != "https://custom.anthropic.com" {
		t.Errorf("expected base URL, got %q", cfg.Anthropic.BaseURL)
	}
}

func TestApplyConfigKey_OpenAIAPIKey(t *testing.T) {
	cfg := config.Default()
	if err := applyConfigKey(cfg, "openai.api_key", "sk-oai-test456"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.OpenAI.APIKey != "sk-oai-test456" {
		t.Errorf("expected API key %q, got %q", "sk-oai-test456", cfg.OpenAI.APIKey)
	}
}

func TestApplyConfigKey_OpenAIModel(t *testing.T) {
	cfg := config.Default()
	if err := applyConfigKey(cfg, "openai.model", "gpt-4o"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.OpenAI.Model != "gpt-4o" {
		t.Errorf("expected model %q, got %q", "gpt-4o", cfg.OpenAI.Model)
	}
}

func TestApplyConfigKey_OpenAIBaseURL(t *testing.T) {
	cfg := config.Default()
	if err := applyConfigKey(cfg, "openai.base_url", "https://openai.example.com/v1"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.OpenAI.BaseURL != "https://openai.example.com/v1" {
		t.Errorf("expected base URL, got %q", cfg.OpenAI.BaseURL)
	}
}

func TestApplyConfigKey_OllamaBaseURL(t *testing.T) {
	cfg := config.Default()
	if err := applyConfigKey(cfg, "ollama.base_url", "http://remote:11434"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Ollama.BaseURL != "http://remote:11434" {
		t.Errorf("expected base URL, got %q", cfg.Ollama.BaseURL)
	}
}

func TestApplyConfigKey_OllamaModel(t *testing.T) {
	cfg := config.Default()
	if err := applyConfigKey(cfg, "ollama.model", "llama3.2"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Ollama.Model != "llama3.2" {
		t.Errorf("expected model %q, got %q", "llama3.2", cfg.Ollama.Model)
	}
}

func TestApplyConfigKey_ClaudeCodeModel(t *testing.T) {
	cfg := config.Default()
	if err := applyConfigKey(cfg, "claudecode.model", "claude-sonnet-4-6"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.ClaudeCode.Model != "claude-sonnet-4-6" {
		t.Errorf("expected model %q, got %q", "claude-sonnet-4-6", cfg.ClaudeCode.Model)
	}
}

func TestApplyConfigKey_UnknownKey(t *testing.T) {
	cfg := config.Default()
	err := applyConfigKey(cfg, "unknown.key", "value")
	if err == nil {
		t.Error("expected error for unknown key")
	}
	if !strings.Contains(err.Error(), "unknown config key") {
		t.Errorf("error should mention 'unknown config key', got: %v", err)
	}
}

func TestApplyConfigKey_CaseInsensitive(t *testing.T) {
	// applyConfigKey receives the key already lowercased by the caller (strings.ToLower in RunE),
	// but test that lowercase inputs work correctly.
	cfg := config.Default()
	if err := applyConfigKey(cfg, "anthropic.model", "test-model"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Anthropic.Model != "test-model" {
		t.Errorf("expected model %q, got %q", "test-model", cfg.Anthropic.Model)
	}
}

// --- maskSecret ---

func TestMaskSecret_ShortString(t *testing.T) {
	got := maskSecret("short")
	if got != "****" {
		t.Errorf("expected '****' for short string, got %q", got)
	}
}

func TestMaskSecret_ExactlyEight(t *testing.T) {
	// 8 chars: len <= 8 → "****"
	got := maskSecret("12345678")
	if got != "****" {
		t.Errorf("expected '****' for 8-char string, got %q", got)
	}
}

func TestMaskSecret_LongKey(t *testing.T) {
	// "sk-ant-test1234" → "sk-a" + stars + "1234"
	key := "sk-ant-test1234"
	got := maskSecret(key)
	if !strings.HasPrefix(got, "sk-a") {
		t.Errorf("expected prefix 'sk-a', got %q", got)
	}
	if !strings.HasSuffix(got, "1234") {
		t.Errorf("expected suffix '1234', got %q", got)
	}
	if !strings.Contains(got, "*") {
		t.Errorf("expected masked middle, got %q", got)
	}
}

func TestMaskSecret_PreservesLength(t *testing.T) {
	key := "sk-ant-0123456789abcdef"
	got := maskSecret(key)
	if len(got) != len(key) {
		t.Errorf("expected masked length %d, got %d (%q)", len(key), len(got), got)
	}
}

// --- displayValue ---

func TestDisplayValue_APIKey_Masked(t *testing.T) {
	got := displayValue("anthropic.api_key", "sk-ant-longkeyvalue1234")
	if got == "sk-ant-longkeyvalue1234" {
		t.Error("expected API key to be masked in display")
	}
	if !strings.Contains(got, "*") {
		t.Error("expected masked value to contain '*'")
	}
}

func TestDisplayValue_NonAPIKey_Unchanged(t *testing.T) {
	got := displayValue("anthropic.model", "claude-opus-4-6")
	if got != "claude-opus-4-6" {
		t.Errorf("expected unchanged value %q, got %q", "claude-opus-4-6", got)
	}
}

func TestDisplayValue_Provider_Unchanged(t *testing.T) {
	got := displayValue("provider", "anthropic")
	if got != "anthropic" {
		t.Errorf("expected unchanged value %q, got %q", "anthropic", got)
	}
}

func TestDisplayValue_OpenAIAPIKey_Masked(t *testing.T) {
	got := displayValue("openai.api_key", "sk-oai-someverylongkey1234")
	if got == "sk-oai-someverylongkey1234" {
		t.Error("expected openai API key to be masked")
	}
}
