package fallback

import (
	"context"
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/pkg/provider"
)

type panicProvider struct{ name string }

func (p panicProvider) Name() string         { return p.name }
func (p panicProvider) DefaultModel() string { return "model-x" }
func (p panicProvider) Complete(ctx context.Context, prompt string, opts provider.Options) (*provider.Result, error) {
	panic("synthetic primary panic")
}

type okProvider struct{ name string }

func (p okProvider) Name() string         { return p.name }
func (p okProvider) DefaultModel() string { return "model-y" }
func (p okProvider) Complete(ctx context.Context, prompt string, opts provider.Options) (*provider.Result, error) {
	return &provider.Result{Output: "ok-from-" + p.name, Provider: p.name}, nil
}

// A primary that panics must not crash the process; the fallback chain must
// observe the panic as an ordinary error and proceed to the next provider.
// This guards the New() constructor's defense-in-depth wrapping for callers
// that pass in raw (non-factory-built) providers.
func TestFallback_NewWrapsRawProviderInPanicSafety(t *testing.T) {
	prim := panicProvider{name: "primary"}
	sec := okProvider{name: "secondary"}

	f, err := New([]provider.Provider{prim, sec})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	res, err := f.Complete(context.Background(), "hi", provider.Options{})
	if err != nil {
		t.Fatalf("expected fallback to succeed via secondary, got %v", err)
	}
	if res == nil || !strings.Contains(res.Output, "ok-from-secondary") {
		t.Fatalf("expected secondary output, got %+v", res)
	}
}

// All providers panicking must surface a combined error rather than crash.
func TestFallback_AllPanicProducesCombinedError(t *testing.T) {
	f, err := New([]provider.Provider{
		panicProvider{name: "p1"},
		panicProvider{name: "p2"},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	res, err := f.Complete(context.Background(), "hi", provider.Options{})
	if res != nil {
		t.Errorf("expected nil result, got %+v", res)
	}
	if err == nil {
		t.Fatal("expected error from all-failing chain")
	}
	if !strings.Contains(err.Error(), "all providers failed") {
		t.Errorf("expected combined error, got %q", err.Error())
	}
}
