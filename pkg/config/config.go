// Package config manages the .cloop/config.yaml project configuration file.
package config

import (
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

const configFile = ".cloop/config.yaml"

// Config is the project configuration loaded from .cloop/config.yaml.
type Config struct {
	// Default provider: anthropic, openai, ollama, claudecode
	Provider string `yaml:"provider"`

	Anthropic AnthropicConfig `yaml:"anthropic"`
	OpenAI    OpenAIConfig    `yaml:"openai"`
	Ollama    OllamaConfig    `yaml:"ollama"`
	ClaudeCode ClaudeCodeConfig `yaml:"claudecode"`
}

type AnthropicConfig struct {
	// API key (falls back to ANTHROPIC_API_KEY env var)
	APIKey  string `yaml:"api_key"`
	Model   string `yaml:"model"`
	BaseURL string `yaml:"base_url"`
}

type OpenAIConfig struct {
	// API key (falls back to OPENAI_API_KEY env var)
	APIKey  string `yaml:"api_key"`
	Model   string `yaml:"model"`
	// Optional: set for Azure OpenAI or OpenAI-compatible servers
	BaseURL string `yaml:"base_url"`
}

type OllamaConfig struct {
	BaseURL string `yaml:"base_url"`
	Model   string `yaml:"model"`
}

type ClaudeCodeConfig struct {
	Model string `yaml:"model"`
}

// Default returns a Config with sensible defaults.
func Default() *Config {
	return &Config{
		Provider: "claudecode",
		Anthropic: AnthropicConfig{
			Model: "claude-opus-4-6",
		},
		OpenAI: OpenAIConfig{
			Model: "gpt-4o",
		},
		Ollama: OllamaConfig{
			BaseURL: "http://localhost:11434",
			Model:   "llama3.2",
		},
	}
}

// ConfigPath returns the path to the config file.
func ConfigPath(workdir string) string {
	return filepath.Join(workdir, configFile)
}

// Load reads config from .cloop/config.yaml. Returns defaults if missing.
func Load(workdir string) (*Config, error) {
	cfg := Default()
	data, err := os.ReadFile(ConfigPath(workdir))
	if os.IsNotExist(err) {
		return cfg, nil
	}
	if err != nil {
		return nil, err
	}
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}

// Save writes the config to .cloop/config.yaml.
func Save(workdir string, cfg *Config) error {
	dir := filepath.Join(workdir, ".cloop")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	data, err := yaml.Marshal(cfg)
	if err != nil {
		return err
	}
	return os.WriteFile(ConfigPath(workdir), data, 0o644)
}

// WriteDefault creates a default config.yaml if one doesn't exist.
func WriteDefault(workdir string) error {
	path := ConfigPath(workdir)
	if _, err := os.Stat(path); err == nil {
		return nil // already exists
	}
	return Save(workdir, Default())
}
