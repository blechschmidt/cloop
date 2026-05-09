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
