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

	// ClaudeCodeBackground tunes the handling of work the claude CLI leaves
	// running after it exits (Task 20205). The zero value detects it, waits
	// for it, and terminates whatever outlives the wait.
	ClaudeCodeBackground BackgroundPolicyConfig
}

// BackgroundPolicyConfig carries pkg/config's background settings to the
// claudecode factory in units the factory can apply directly.
//
// A plain struct here rather than an import of pkg/config because the
// dependency runs the other way round: the provider tree is imported by
// pkg/config's consumers, and a leaf provider must not be made to depend on
// the configuration package to compile.
type BackgroundPolicyConfig struct {
	Disabled     bool
	GraceSeconds int
	WaitMinutes  int
	KeepOrphans  bool
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
//	real provider → WithPanicSafety → WithRequestIDTracing → redaction → audit decorator
//
// so a panic inside the underlying SDK becomes an ordinary error, every
// error returned to the caller is tagged with the request ID carried in
// the call context, a credential this process was lent is scrubbed from
// everything the call returns or streams, and every call (success or
// failure) lands in the per-project audit log. This is the single
// chokepoint every cloop command goes through, so wrapping here gives the
// behaviour to all 80+ Complete call sites without touching them.
//
// The audit decorator runs OUTSIDE request-ID tagging so it sees the
// final tagged error message; that message is what ends up in the audit
// row. The decorator is best-effort and can never block the call.
//
// Redaction is inside the audit decorator, not outside it, and the order is
// the point: the decorator writes the response it receives into
// provider_calls, so it must receive the scrubbed one. With redaction
// outermost — as it was until Task 20378's end-to-end test read the table —
// the caller got a clean response while the audit row kept the credential.
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
	// Scrubbed before anything records it — the provider audit log included —
	// so no row written about this call holds a credential this process was
	// lent. See redaction.go.
	wrapped := withLiveRedaction(WithRequestIDTracing(WithPanicSafety(p)), buildRedactor())
	if auditDecorator != nil {
		wrapped = auditDecorator(wrapped)
	}
	return wrapped, nil
}

// buildRedactor is the scrub set Build applies: this process's own. A var so
// a test can lend the process a credential without changing its environment.
var buildRedactor = processRedactor

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
