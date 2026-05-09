package provider

import (
	"context"
	"errors"
	"strings"
	"testing"
)

type fakePanicProvider struct{}

func (fakePanicProvider) Name() string         { return "fake-panic" }
func (fakePanicProvider) DefaultModel() string { return "fake-model" }
func (fakePanicProvider) Complete(ctx context.Context, prompt string, opts Options) (*Result, error) {
	panic("synthetic provider panic")
}

type fakeOKProvider struct{}

func (fakeOKProvider) Name() string         { return "fake-ok" }
func (fakeOKProvider) DefaultModel() string { return "fake-model" }
func (fakeOKProvider) Complete(ctx context.Context, prompt string, opts Options) (*Result, error) {
	return &Result{Output: "hello", Provider: "fake-ok"}, nil
}

type fakeErrProvider struct{ err error }

func (p fakeErrProvider) Name() string         { return "fake-err" }
func (p fakeErrProvider) DefaultModel() string { return "fake-model" }
func (p fakeErrProvider) Complete(ctx context.Context, prompt string, opts Options) (*Result, error) {
	return nil, p.err
}

func TestWithPanicSafety_PanicConvertedToError(t *testing.T) {
	wrapped := WithPanicSafety(fakePanicProvider{})
	result, err := wrapped.Complete(context.Background(), "anything", Options{})
	if result != nil {
		t.Fatalf("expected nil result on panic, got %+v", result)
	}
	if err == nil {
		t.Fatal("expected non-nil error on panic")
	}
	if !strings.Contains(err.Error(), "provider panic in fake-panic") {
		t.Errorf("expected error to mention provider panic and name, got %q", err.Error())
	}
}

func TestWithPanicSafety_HappyPathTransparent(t *testing.T) {
	wrapped := WithPanicSafety(fakeOKProvider{})
	result, err := wrapped.Complete(context.Background(), "hi", Options{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == nil || result.Output != "hello" {
		t.Errorf("expected passthrough of provider result, got %+v", result)
	}
	if got, want := wrapped.Name(), "fake-ok"; got != want {
		t.Errorf("Name() = %q, want %q", got, want)
	}
	if got, want := wrapped.DefaultModel(), "fake-model"; got != want {
		t.Errorf("DefaultModel() = %q, want %q", got, want)
	}
}

func TestWithPanicSafety_OrdinaryErrorPassesThrough(t *testing.T) {
	want := errors.New("rate limited")
	wrapped := WithPanicSafety(fakeErrProvider{err: want})
	result, err := wrapped.Complete(context.Background(), "hi", Options{})
	if result != nil {
		t.Fatalf("expected nil result, got %+v", result)
	}
	if !errors.Is(err, want) {
		t.Errorf("expected ordinary provider error to pass through unchanged, got %v", err)
	}
}

func TestWithPanicSafety_Idempotent(t *testing.T) {
	once := WithPanicSafety(fakeOKProvider{})
	twice := WithPanicSafety(once)
	if once != twice {
		t.Errorf("WithPanicSafety must be idempotent: double-wrapping should return the same instance, got distinct wrappers")
	}
}

func TestWithPanicSafety_NilInput(t *testing.T) {
	if got := WithPanicSafety(nil); got != nil {
		t.Errorf("WithPanicSafety(nil) = %v, want nil", got)
	}
}

// TestBuild_AppliesPanicSafety ensures the factory wraps every provider it
// returns. We register a panicking provider through the public Register API,
// build it via Build, and assert that calling Complete returns an error
// rather than crashing the test process.
func TestBuild_AppliesPanicSafety(t *testing.T) {
	const name = "test-panic-via-factory"
	Register(name, func(cfg ProviderConfig) (Provider, error) {
		return fakePanicProvider{}, nil
	})

	p, err := Build(ProviderConfig{Name: name})
	if err != nil {
		t.Fatalf("Build returned unexpected error: %v", err)
	}
	if p == nil {
		t.Fatal("Build returned nil provider")
	}

	result, err := p.Complete(context.Background(), "hi", Options{})
	if result != nil {
		t.Errorf("expected nil result on panic, got %+v", result)
	}
	if err == nil {
		t.Fatal("expected error from factory-wrapped panicking provider, got nil — factory is not applying panic safety")
	}
	if !strings.Contains(err.Error(), "provider panic") {
		t.Errorf("expected 'provider panic' in error, got %q", err.Error())
	}
}
