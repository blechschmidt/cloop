package config

import "testing"

// TestModelForReadsEachProvidersOwnKey pins the mapping every command resolves
// a configured model through: a provider's own section, nothing for one that
// has none, and the provider's name read as the factory reads it.
func TestModelForReadsEachProvidersOwnKey(t *testing.T) {
	cfg := &Config{
		Anthropic:  AnthropicConfig{Model: "a-model"},
		OpenAI:     OpenAIConfig{Model: "o-model"},
		Ollama:     OllamaConfig{Model: "l-model"},
		ClaudeCode: ClaudeCodeConfig{Model: "c-model"},
		Copilot:    CopilotConfig{Model: "g-model"},
	}
	for provider, want := range map[string]string{
		"anthropic":    "a-model",
		"openai":       "o-model",
		"ollama":       "l-model",
		"claudecode":   "c-model",
		" ClaudeCode ": "c-model",
		"copilot":      "g-model",
		"mock":         "",
		"":             "",
		"no-such-one":  "",
	} {
		if got := cfg.ModelFor(provider); got != want {
			t.Errorf("ModelFor(%q) = %q, want %q", provider, got, want)
		}
	}
}
