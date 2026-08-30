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
	"github.com/blechschmidt/cloop/pkg/provideraudit"
	"github.com/blechschmidt/cloop/pkg/ratelimit"
)

func init() {
	// Wire the per-project audit log decorator into provider.Build so every
	// Provider.Complete invocation across the codebase lands in state.db's
	// provider_calls table (Task 20105 / Task 20123 — powers the Web UI's
	// "Provider Calls" inspector panel).
	provider.RegisterAuditDecorator(provideraudit.WithAudit)

	// Let the claudecode provider rotate the Claude Code OAuth credential
	// before retrying a 401 (Task 20204). Wired here rather than imported
	// directly so pkg/provider/claudecode stays a leaf package — pkg/ratelimit
	// transitively depends on the executor and secret-broker trees.
	claudecode.SetCredentialRefresher(ratelimit.ForceCredentialRefresh)

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
