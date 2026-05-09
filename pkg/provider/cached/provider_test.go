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
