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
