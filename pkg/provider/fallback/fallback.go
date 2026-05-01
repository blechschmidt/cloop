// Package fallback provides a Provider that tries a list of providers in order,
// returning the first successful result. This gives automatic failover when a
// primary provider is unavailable, rate-limited, or returns an error.
package fallback

import (
	"context"
	"fmt"
	"strings"

	"github.com/blechschmidt/cloop/pkg/provider"
)

// Provider tries a list of providers in order, using the first one that succeeds.
type Provider struct {
	providers []provider.Provider
}

// New creates a fallback provider from an ordered list of providers.
// The first provider in the list is the primary; subsequent providers are fallbacks.
// Returns an error if the list is empty.
func New(providers []provider.Provider) (*Provider, error) {
	if len(providers) == 0 {
		return nil, fmt.Errorf("fallback provider requires at least one provider")
	}
	return &Provider{providers: providers}, nil
}

// Name returns a combined name showing the full fallback chain.
func (f *Provider) Name() string {
	names := make([]string, len(f.providers))
	for i, p := range f.providers {
		names[i] = p.Name()
	}
	return strings.Join(names, "→")
}

// DefaultModel returns the default model of the primary provider.
func (f *Provider) DefaultModel() string {
	return f.providers[0].DefaultModel()
}

// Complete tries each provider in order, returning the first successful result.
// If the context is cancelled, it stops immediately without trying further fallbacks.
// On a provider error, it logs which provider failed and tries the next one.
// If all providers fail, it returns a combined error.
func (f *Provider) Complete(ctx context.Context, prompt string, opts provider.Options) (*provider.Result, error) {
	var errs []string
	for i, p := range f.providers {
		// Check context before each attempt.
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}

		result, err := p.Complete(ctx, prompt, opts)
		if err == nil {
			if i > 0 {
				// Annotate the result so callers know a fallback was used.
				result.Provider = p.Name() + " (fallback)"
			}
			return result, nil
		}

		// Context cancelled — don't try more providers.
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}

		errs = append(errs, fmt.Sprintf("%s: %v", p.Name(), err))
	}
	return nil, fmt.Errorf("all providers failed: %s", strings.Join(errs, "; "))
}
