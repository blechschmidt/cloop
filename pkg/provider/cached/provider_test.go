package cached

import (
	"context"
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/pkg/cache"
	"github.com/blechschmidt/cloop/pkg/provider"
)

type panicProvider struct{}

func (panicProvider) Name() string         { return "panic-inner" }
func (panicProvider) DefaultModel() string { return "model-x" }
func (panicProvider) Complete(ctx context.Context, prompt string, opts provider.Options) (*provider.Result, error) {
	panic("synthetic inner panic")
}

// New() must re-wrap inner in WithPanicSafety so a caller passing a raw
// provider (not built via provider.Build) still gets crash protection.
func TestCached_NewWrapsRawProviderInPanicSafety(t *testing.T) {
	dir := t.TempDir()
	c, err := cache.New(dir, 0, 0)
	if err != nil {
		t.Fatalf("cache.New: %v", err)
	}

	cp := New(panicProvider{}, c)

	res, err := cp.Complete(context.Background(), "hello", provider.Options{})
	if res != nil {
		t.Errorf("expected nil result on panic, got %+v", res)
	}
	if err == nil {
		t.Fatal("expected error from panicking inner provider, got nil — cached.New is not applying panic safety")
	}
	if !strings.Contains(err.Error(), "provider panic") {
		t.Errorf("expected 'provider panic' in error, got %q", err.Error())
	}
}

type countingEmptyProvider struct {
	calls int
	out   string
}

func (p *countingEmptyProvider) Name() string         { return "counting-empty" }
func (p *countingEmptyProvider) DefaultModel() string { return "model-x" }
func (p *countingEmptyProvider) Complete(ctx context.Context, prompt string, opts provider.Options) (*provider.Result, error) {
	p.calls++
	return &provider.Result{Output: p.out, Provider: p.Name(), Model: p.DefaultModel()}, nil
}

// A successful response with empty/whitespace-only output must not be cached.
// Otherwise, a transient inner-provider hiccup would be baked in and silently
// served on every subsequent identical request — and the orchestrator's
// failure gate (which only observes errors) would never get a chance to
// re-trip and recover.
func TestCached_DoesNotCacheEmptyOutput(t *testing.T) {
	for _, out := range []string{"", "   ", "\n\t\n"} {
		t.Run("output_"+strings.ReplaceAll(strings.ReplaceAll(out, "\n", "_"), "\t", "_"), func(t *testing.T) {
			dir := t.TempDir()
			c, err := cache.New(dir, 0, 0)
			if err != nil {
				t.Fatalf("cache.New: %v", err)
			}
			inner := &countingEmptyProvider{out: out}
			cp := New(inner, c)

			for i := 0; i < 3; i++ {
				if _, err := cp.Complete(context.Background(), "same-prompt", provider.Options{}); err != nil {
					t.Fatalf("call %d: %v", i, err)
				}
			}
			if inner.calls != 3 {
				t.Errorf("expected 3 inner calls (no caching of empty output), got %d — empty/whitespace output was cached and re-served, masking transient failures", inner.calls)
			}
		})
	}
}

type countingProvider struct {
	calls int
}

func (p *countingProvider) Name() string         { return "counting" }
func (p *countingProvider) DefaultModel() string { return "model-x" }
func (p *countingProvider) Complete(ctx context.Context, prompt string, opts provider.Options) (*provider.Result, error) {
	p.calls++
	return &provider.Result{Output: "real answer", Provider: p.Name(), Model: p.DefaultModel()}, nil
}

// A pre-existing cache entry on disk with empty/whitespace content (e.g. one
// written before the skip-on-empty-write guard landed, or by an older cloop
// version) must not be served as a hit. Otherwise, the orchestrator would
// receive a useless empty response on every identical call until the entry
// hit its TTL — exactly the silent-failure mode the write-side guard exists
// to prevent. The wrapper falls through to the inner provider, which then
// either succeeds and overwrites the bad entry or surfaces a real error to
// the orchestrator's failure gate.
func TestCached_StaleEmptyEntryTreatedAsMiss(t *testing.T) {
	for _, badOut := range []string{"", "   ", "\n\t\n"} {
		t.Run("bad_"+strings.ReplaceAll(strings.ReplaceAll(badOut, "\n", "_"), "\t", "_"), func(t *testing.T) {
			dir := t.TempDir()
			c, err := cache.New(dir, 0, 0)
			if err != nil {
				t.Fatalf("cache.New: %v", err)
			}

			inner := &countingProvider{}
			cp := New(inner, c)

			// Pre-populate the cache with an empty entry under the exact key
			// the wrapper will compute for this prompt — simulating a stale
			// entry from before the skip-on-write guard.
			model := inner.DefaultModel()
			key := cache.Key(inner.Name(), model, "same-prompt")
			if err := c.Put(key, badOut, inner.Name(), model); err != nil {
				t.Fatalf("seed cache: %v", err)
			}

			res, err := cp.Complete(context.Background(), "same-prompt", provider.Options{})
			if err != nil {
				t.Fatalf("Complete: %v", err)
			}
			if res.Output != "real answer" {
				t.Errorf("stale empty entry was served as a hit; expected fall-through to inner. got output %q", res.Output)
			}
			if inner.calls != 1 {
				t.Errorf("expected inner to be called exactly once after stale-empty miss, got %d", inner.calls)
			}
		})
	}
}

// Companion test: non-empty output is still cached so we don't regress the
// happy path while plugging the empty-output hole.
func TestCached_NonEmptyOutputStillCached(t *testing.T) {
	dir := t.TempDir()
	c, err := cache.New(dir, 0, 0)
	if err != nil {
		t.Fatalf("cache.New: %v", err)
	}
	inner := &countingProvider{}
	cp := New(inner, c)

	for i := 0; i < 3; i++ {
		if _, err := cp.Complete(context.Background(), "same-prompt", provider.Options{}); err != nil {
			t.Fatalf("call %d: %v", i, err)
		}
	}
	if inner.calls != 1 {
		t.Errorf("expected exactly 1 inner call (non-empty output should be cached), got %d", inner.calls)
	}
}
