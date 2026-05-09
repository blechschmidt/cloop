package orchestrator

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/pkg/provider"
)

// erroringProvider returns a normal error — used to ensure safeComplete
// passes ordinary errors through unchanged.
type erroringProvider struct{ err error }

func (p *erroringProvider) Complete(ctx context.Context, prompt string, opts provider.Options) (*provider.Result, error) {
	return nil, p.err
}
func (p *erroringProvider) Name() string         { return "err-prov" }
func (p *erroringProvider) DefaultModel() string { return "test-model" }

// okSafeProvider returns a successful response — ensures safeComplete is a
// transparent passthrough on the happy path.
type okSafeProvider struct{}

func (p *okSafeProvider) Complete(ctx context.Context, prompt string, opts provider.Options) (*provider.Result, error) {
	return &provider.Result{Output: "hello", InputTokens: 1, OutputTokens: 2}, nil
}
func (p *okSafeProvider) Name() string         { return "ok-prov" }
func (p *okSafeProvider) DefaultModel() string { return "test-model" }

// TestSafeComplete_PanicConvertedToError verifies the contract: a panic
// inside provider.Complete must surface as an ordinary error so the
// caller's existing error-handling branch fires (mark task failed,
// continue the loop) instead of crashing the whole `cloop run` process.
//
// Reuses panickingProvider from orchestrator_test.go (it always panics).
func TestSafeComplete_PanicConvertedToError(t *testing.T) {
	result, err := safeComplete(context.Background(), panickingProvider{}, "anything", provider.Options{})
	if result != nil {
		t.Fatalf("expected nil result on panic, got %+v", result)
	}
	if err == nil {
		t.Fatal("expected non-nil error on panic")
	}
	if !strings.Contains(err.Error(), "provider panic") {
		t.Errorf("expected error to mention 'provider panic', got %q", err.Error())
	}
	if !strings.Contains(err.Error(), "panicking") {
		t.Errorf("expected error to include provider name 'panicking', got %q", err.Error())
	}
}

func TestSafeComplete_OrdinaryErrorPassesThrough(t *testing.T) {
	want := errors.New("rate limited")
	p := &erroringProvider{err: want}
	result, err := safeComplete(context.Background(), p, "anything", provider.Options{})
	if result != nil {
		t.Fatalf("expected nil result, got %+v", result)
	}
	if !errors.Is(err, want) {
		t.Errorf("expected provider error to pass through unchanged, got %v", err)
	}
}

func TestSafeComplete_HappyPathTransparent(t *testing.T) {
	result, err := safeComplete(context.Background(), &okSafeProvider{}, "hi", provider.Options{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == nil || result.Output != "hello" {
		t.Errorf("expected passthrough of provider result, got %+v", result)
	}
}
