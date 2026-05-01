package provider

import (
	"fmt"
	"strings"
)

// ProviderConfig holds settings for all providers, used by the factory.
type ProviderConfig struct {
	// Which provider to use
	Name string

	// Anthropic settings
	AnthropicAPIKey  string
	AnthropicBaseURL string

	// OpenAI settings
	OpenAIAPIKey  string
	OpenAIBaseURL string

	// Ollama settings
	OllamaBaseURL string
}

// ProviderFactory is a function that creates a Provider from a ProviderConfig.
type ProviderFactory func(cfg ProviderConfig) (Provider, error)

var registry = map[string]ProviderFactory{}

// Register adds a provider factory to the global registry.
func Register(name string, factory ProviderFactory) {
	registry[strings.ToLower(name)] = factory
}

// Build creates a provider by name using the global registry.
func Build(cfg ProviderConfig) (Provider, error) {
	name := strings.ToLower(cfg.Name)
	factory, ok := registry[name]
	if !ok {
		return nil, fmt.Errorf("unknown provider %q (available: %s)", cfg.Name, Available())
	}
	return factory(cfg)
}

// Available returns a comma-separated list of registered providers.
func Available() string {
	names := make([]string, 0, len(registry))
	for name := range registry {
		names = append(names, name)
	}
	return strings.Join(names, ", ")
}
