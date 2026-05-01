package config

import (
	"os"
	"path/filepath"
	"testing"
)

func tempDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "cloop-config-test-*")
	if err != nil {
		t.Fatalf("creating temp dir: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return dir
}

// --- Default ---

func TestDefault_HasClaudeCodeProvider(t *testing.T) {
	cfg := Default()
	if cfg.Provider != "claudecode" {
		t.Errorf("expected default provider 'claudecode', got %q", cfg.Provider)
	}
}

func TestDefault_HasModels(t *testing.T) {
	cfg := Default()
	if cfg.Anthropic.Model == "" {
		t.Error("expected a default Anthropic model")
	}
	if cfg.OpenAI.Model == "" {
		t.Error("expected a default OpenAI model")
	}
	if cfg.Ollama.Model == "" {
		t.Error("expected a default Ollama model")
	}
	if cfg.Ollama.BaseURL == "" {
		t.Error("expected a default Ollama base URL")
	}
}

// --- ConfigPath ---

func TestConfigPath(t *testing.T) {
	got := ConfigPath("/some/project")
	expected := "/some/project/.cloop/config.yaml"
	if got != expected {
		t.Errorf("expected %q, got %q", expected, got)
	}
}

// --- Load ---

func TestLoad_ReturnDefaultsWhenMissing(t *testing.T) {
	dir := tempDir(t)
	cfg, err := Load(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Provider != "claudecode" {
		t.Errorf("expected default provider, got %q", cfg.Provider)
	}
}

func TestLoad_RoundTrip(t *testing.T) {
	dir := tempDir(t)

	cfg := Default()
	cfg.Provider = "anthropic"
	cfg.Anthropic.APIKey = "test-key"
	cfg.Anthropic.Model = "claude-opus-4-6"

	if err := Save(dir, cfg); err != nil {
		t.Fatalf("save error: %v", err)
	}

	loaded, err := Load(dir)
	if err != nil {
		t.Fatalf("load error: %v", err)
	}
	if loaded.Provider != "anthropic" {
		t.Errorf("provider mismatch: got %q", loaded.Provider)
	}
	if loaded.Anthropic.APIKey != "test-key" {
		t.Errorf("api_key mismatch: got %q", loaded.Anthropic.APIKey)
	}
	if loaded.Anthropic.Model != "claude-opus-4-6" {
		t.Errorf("model mismatch: got %q", loaded.Anthropic.Model)
	}
}

func TestLoad_InvalidYAML(t *testing.T) {
	dir := tempDir(t)
	cfgDir := filepath.Join(dir, ".cloop")
	if err := os.MkdirAll(cfgDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(ConfigPath(dir), []byte("provider: [invalid yaml"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	_, err := Load(dir)
	if err == nil {
		t.Error("expected error for invalid YAML")
	}
}

// --- Save ---

func TestSave_CreatesDirectory(t *testing.T) {
	dir := tempDir(t)
	cfg := Default()
	if err := Save(dir, cfg); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, err := os.Stat(ConfigPath(dir)); err != nil {
		t.Errorf("config file not created: %v", err)
	}
}

func TestSave_WritesAllProviders(t *testing.T) {
	dir := tempDir(t)
	cfg := Default()
	cfg.OpenAI.APIKey = "oai-key"
	cfg.OpenAI.BaseURL = "https://custom.openai.com"
	cfg.Ollama.BaseURL = "http://localhost:9999"
	cfg.ClaudeCode.Model = "claude-sonnet-4-6"

	if err := Save(dir, cfg); err != nil {
		t.Fatalf("save error: %v", err)
	}
	loaded, err := Load(dir)
	if err != nil {
		t.Fatalf("load error: %v", err)
	}
	if loaded.OpenAI.APIKey != "oai-key" {
		t.Errorf("openai api_key mismatch: %q", loaded.OpenAI.APIKey)
	}
	if loaded.OpenAI.BaseURL != "https://custom.openai.com" {
		t.Errorf("openai base_url mismatch: %q", loaded.OpenAI.BaseURL)
	}
	if loaded.Ollama.BaseURL != "http://localhost:9999" {
		t.Errorf("ollama base_url mismatch: %q", loaded.Ollama.BaseURL)
	}
	if loaded.ClaudeCode.Model != "claude-sonnet-4-6" {
		t.Errorf("claudecode model mismatch: %q", loaded.ClaudeCode.Model)
	}
}

// --- WriteDefault ---

func TestWriteDefault_CreatesFileIfAbsent(t *testing.T) {
	dir := tempDir(t)
	if err := WriteDefault(dir); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, err := os.Stat(ConfigPath(dir)); err != nil {
		t.Errorf("config file not created: %v", err)
	}
}

func TestWriteDefault_DoesNotOverwriteExisting(t *testing.T) {
	dir := tempDir(t)
	// Write a custom config first
	cfg := Default()
	cfg.Provider = "openai"
	if err := Save(dir, cfg); err != nil {
		t.Fatalf("save error: %v", err)
	}
	// WriteDefault should not clobber it
	if err := WriteDefault(dir); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	loaded, err := Load(dir)
	if err != nil {
		t.Fatalf("load error: %v", err)
	}
	if loaded.Provider != "openai" {
		t.Errorf("WriteDefault overwrote existing config: got provider %q", loaded.Provider)
	}
}

// --- applyEnvVars / env var override ---

func setenv(t *testing.T, key, value string) {
	t.Helper()
	old, hadOld := os.LookupEnv(key)
	os.Setenv(key, value)
	t.Cleanup(func() {
		if hadOld {
			os.Setenv(key, old)
		} else {
			os.Unsetenv(key)
		}
	})
}

func TestLoad_EnvVar_AnthropicAPIKey(t *testing.T) {
	setenv(t, "ANTHROPIC_API_KEY", "env-anthropic-key")
	dir := tempDir(t)
	cfg, err := Load(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Anthropic.APIKey != "env-anthropic-key" {
		t.Errorf("expected env key, got %q", cfg.Anthropic.APIKey)
	}
}

func TestLoad_EnvVar_AnthropicBaseURL(t *testing.T) {
	setenv(t, "ANTHROPIC_BASE_URL", "https://custom.anthropic.com")
	dir := tempDir(t)
	cfg, err := Load(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Anthropic.BaseURL != "https://custom.anthropic.com" {
		t.Errorf("expected env base_url, got %q", cfg.Anthropic.BaseURL)
	}
}

func TestLoad_EnvVar_OpenAIAPIKey(t *testing.T) {
	setenv(t, "OPENAI_API_KEY", "env-openai-key")
	dir := tempDir(t)
	cfg, err := Load(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.OpenAI.APIKey != "env-openai-key" {
		t.Errorf("expected env openai key, got %q", cfg.OpenAI.APIKey)
	}
}

func TestLoad_EnvVar_OpenAIBaseURL(t *testing.T) {
	setenv(t, "OPENAI_BASE_URL", "https://custom.openai.com")
	dir := tempDir(t)
	cfg, err := Load(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.OpenAI.BaseURL != "https://custom.openai.com" {
		t.Errorf("expected env openai base_url, got %q", cfg.OpenAI.BaseURL)
	}
}

func TestLoad_EnvVar_OllamaBaseURL(t *testing.T) {
	setenv(t, "OLLAMA_BASE_URL", "http://remote:11434")
	dir := tempDir(t)
	cfg, err := Load(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Ollama.BaseURL != "http://remote:11434" {
		t.Errorf("expected env ollama base_url, got %q", cfg.Ollama.BaseURL)
	}
}

func TestLoad_EnvVar_CloopProvider(t *testing.T) {
	setenv(t, "CLOOP_PROVIDER", "anthropic")
	dir := tempDir(t)
	cfg, err := Load(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Provider != "anthropic" {
		t.Errorf("expected env provider 'anthropic', got %q", cfg.Provider)
	}
}

func TestLoad_EnvVar_OverridesFileValue(t *testing.T) {
	// Env var should win over config file value
	setenv(t, "ANTHROPIC_API_KEY", "env-wins")
	dir := tempDir(t)

	cfg := Default()
	cfg.Anthropic.APIKey = "file-value"
	if err := Save(dir, cfg); err != nil {
		t.Fatalf("save: %v", err)
	}

	loaded, err := Load(dir)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if loaded.Anthropic.APIKey != "env-wins" {
		t.Errorf("expected env var to override file, got %q", loaded.Anthropic.APIKey)
	}
}

func TestLoad_EnvVar_EmptyDoesNotOverride(t *testing.T) {
	// Unset env var should not clear file value
	os.Unsetenv("ANTHROPIC_API_KEY")
	dir := tempDir(t)

	cfg := Default()
	cfg.Anthropic.APIKey = "file-value"
	if err := Save(dir, cfg); err != nil {
		t.Fatalf("save: %v", err)
	}

	loaded, err := Load(dir)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if loaded.Anthropic.APIKey != "file-value" {
		t.Errorf("expected file value to persist, got %q", loaded.Anthropic.APIKey)
	}
}
