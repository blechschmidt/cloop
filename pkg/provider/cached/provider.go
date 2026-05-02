// Package cached provides a CachedProvider decorator that wraps any Provider
// and transparently caches responses to avoid redundant identical API calls.
package cached

import (
	"context"

	"github.com/blechschmidt/cloop/pkg/cache"
	"github.com/blechschmidt/cloop/pkg/provider"
)

// Provider wraps an inner provider and caches Complete responses.
// When OnToken streaming is requested, caching is skipped (streaming
// responses are not suitable for replay).
type Provider struct {
	inner provider.Provider
	cache *cache.Cache
}

// New wraps inner with response caching using the provided cache.
func New(inner provider.Provider, c *cache.Cache) *Provider {
	return &Provider{inner: inner, cache: c}
}

// Name delegates to the inner provider.
func (p *Provider) Name() string { return p.inner.Name() }

// DefaultModel delegates to the inner provider.
func (p *Provider) DefaultModel() string { return p.inner.DefaultModel() }

// Complete checks the cache first. On a hit the cached response is returned
// immediately. On a miss the inner provider is called and the result stored.
// Streaming requests (OnToken != nil) bypass the cache entirely.
func (p *Provider) Complete(ctx context.Context, prompt string, opts provider.Options) (*provider.Result, error) {
	// Don't cache streaming calls — tokens are delivered to OnToken in real time.
	if opts.OnToken != nil {
		return p.inner.Complete(ctx, prompt, opts)
	}

	model := opts.Model
	if model == "" {
		model = p.inner.DefaultModel()
	}

	key := cache.Key(p.inner.Name(), model, prompt)

	if resp, ok := p.cache.Get(key); ok {
		return &provider.Result{
			Output:   resp,
			Provider: p.inner.Name(),
			Model:    model,
		}, nil
	}

	result, err := p.inner.Complete(ctx, prompt, opts)
	if err != nil {
		return nil, err
	}

	// Store in cache (best-effort; cache errors don't fail the call).
	_ = p.cache.Put(key, result.Output, p.inner.Name(), model)

	return result, nil
}
