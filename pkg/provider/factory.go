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

	// Mock settings
	MockResponsesFile string
}

// ProviderFactory is a function that creates a Provider from a ProviderConfig.
type ProviderFactory func(cfg ProviderConfig) (Provider, error)

var registry = map[string]ProviderFactory{}

// Register adds a provider factory to the global registry.
func Register(name string, factory ProviderFactory) {
	registry[strings.ToLower(name)] = factory
}

// AuditDecorator, if non-nil, is applied as the outermost wrapper in
// Build so every Provider.Complete call is recorded in the project's
// audit log (Task 20105 / Task 20123). Set by pkg/provideraudit at init
// time via RegisterAuditDecorator. Decoupled this way to avoid an import
// cycle: pkg/provideraudit imports pkg/provider for the interface, and
// pkg/provider needs to invoke audit logic without importing it.
//
// Concurrency: the variable is set exactly once at package init and read
// from Build under no mutex. Init-order ordering is safe because
// pkg/provideraudit's init runs before any cloop command can call Build.
var auditDecorator func(Provider) Provider

// RegisterAuditDecorator installs the audit-log wrapper used by Build.
// Idempotent: calling it twice replaces the prior decorator. Pass nil to
// disable audit logging (useful in tests that don't want a state.db).
func RegisterAuditDecorator(d func(Provider) Provider) {
	auditDecorator = d
}

// Build creates a provider by name using the global registry.
//
// The returned provider is wrapped (innermost → outermost) in:
//
//	real provider → WithPanicSafety → WithRequestIDTracing → audit decorator
//
// so a panic inside the underlying SDK becomes an ordinary error, every
// error returned to the caller is tagged with the request ID carried in
// the call context, and every call (success or failure) lands in the
// per-project audit log. This is the single chokepoint every cloop
// command goes through, so wrapping here gives the behaviour to all 80+
// Complete call sites without touching them.
//
// The audit decorator runs OUTSIDE request-ID tagging so it sees the
// final tagged error message; that message is what ends up in the audit
// row. The decorator is best-effort and can never block the call.
func Build(cfg ProviderConfig) (Provider, error) {
	name := strings.ToLower(cfg.Name)
	factory, ok := registry[name]
	if !ok {
		return nil, fmt.Errorf("unknown provider %q (available: %s)", cfg.Name, Available())
	}
	p, err := factory(cfg)
	if err != nil {
		return nil, err
	}
	wrapped := WithRequestIDTracing(WithPanicSafety(p))
	if auditDecorator != nil {
		wrapped = auditDecorator(wrapped)
	}
	return wrapped, nil
}

// Available returns a comma-separated list of registered providers.
func Available() string {
	names := make([]string, 0, len(registry))
	for name := range registry {
		names = append(names, name)
	}
	return strings.Join(names, ", ")
}

// RegisteredNames returns the names of all registered providers as a slice.
func RegisteredNames() []string {
	names := make([]string, 0, len(registry))
	for name := range registry {
		names = append(names, name)
	}
	return names
}
