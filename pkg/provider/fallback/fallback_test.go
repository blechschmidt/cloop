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

// emptyOutputProvider returns (non-nil, nil) with whitespace-only Output.
// This shape mirrors a transient provider hiccup that previously would have
// short-circuited the fallback chain with a useless empty response.
type emptyOutputProvider struct {
	name string
	out  string
}

func (p emptyOutputProvider) Name() string         { return p.name }
func (p emptyOutputProvider) DefaultModel() string { return "model-x" }
func (p emptyOutputProvider) Complete(ctx context.Context, prompt string, opts provider.Options) (*provider.Result, error) {
	return &provider.Result{Output: p.out, Provider: p.name}, nil
}

// A primary that returns success with empty/whitespace output must not
// short-circuit the fallback chain — the secondary must be tried so the
// fallback actually delivers a useful response.
func TestFallback_PrimaryEmptyOutputFallsThrough(t *testing.T) {
	cases := []struct {
		name string
		out  string
	}{
		{"empty string", ""},
		{"single space", " "},
		{"only whitespace", "  \t\n  "},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			prim := emptyOutputProvider{name: "primary", out: tc.out}
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
			if !strings.Contains(res.Provider, "fallback") {
				t.Errorf("expected provider annotation to mention fallback, got %q", res.Provider)
			}
		})
	}
}

// If every provider returns empty output, the chain must surface a combined
// error rather than silently returning the last empty response — otherwise
// callers can't distinguish "empty answer" from "all backends broken".
func TestFallback_AllEmptyProducesCombinedError(t *testing.T) {
	f, err := New([]provider.Provider{
		emptyOutputProvider{name: "p1", out: ""},
		emptyOutputProvider{name: "p2", out: "  \n"},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	res, err := f.Complete(context.Background(), "hi", provider.Options{})
	if res != nil {
		t.Errorf("expected nil result, got %+v", res)
	}
	if err == nil {
		t.Fatal("expected error when every provider returns empty output")
	}
	if !strings.Contains(err.Error(), "all providers failed") {
		t.Errorf("expected combined error, got %q", err.Error())
	}
	if !strings.Contains(err.Error(), "empty output") {
		t.Errorf("expected error to mention empty output, got %q", err.Error())
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
