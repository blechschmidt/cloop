package cmd

// providers.go registers all built-in AI providers with the factory.
// Importing this file (via the cmd package) registers all providers automatically.

import (
	"github.com/blechschmidt/cloop/pkg/provider"
	"github.com/blechschmidt/cloop/pkg/provider/anthropic"
	"github.com/blechschmidt/cloop/pkg/provider/claudecode"
	mockprovider "github.com/blechschmidt/cloop/pkg/provider/mock"
	"github.com/blechschmidt/cloop/pkg/provider/ollama"
	"github.com/blechschmidt/cloop/pkg/provider/openai"
)

func init() {
	provider.Register(claudecode.ProviderName, func(cfg provider.ProviderConfig) (provider.Provider, error) {
		return claudecode.New(), nil
	})

	provider.Register(anthropic.ProviderName, func(cfg provider.ProviderConfig) (provider.Provider, error) {
		return anthropic.New(cfg.AnthropicAPIKey, cfg.AnthropicBaseURL), nil
	})

	provider.Register(openai.ProviderName, func(cfg provider.ProviderConfig) (provider.Provider, error) {
		return openai.New(cfg.OpenAIAPIKey, cfg.OpenAIBaseURL), nil
	})

	provider.Register(ollama.ProviderName, func(cfg provider.ProviderConfig) (provider.Provider, error) {
		return ollama.New(cfg.OllamaBaseURL), nil
	})

	provider.Register(mockprovider.ProviderName, func(cfg provider.ProviderConfig) (provider.Provider, error) {
		return mockprovider.New(cfg.MockResponsesFile), nil
	})
}
