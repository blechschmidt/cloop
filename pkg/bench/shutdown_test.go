package bench

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/provider"
)

// stuckProvider blocks until block is closed or hard expires, ignoring its
// ctx argument. Models a misbehaving SDK that fails to honour ctx.Done() —
// the failure mode benchShutdownGracePeriod is meant to bound.
type stuckProvider struct {
	name  string
	block <-chan struct{}
	hard  time.Duration
}

func (s stuckProvider) Complete(_ context.Context, _ string, _ provider.Options) (*provider.Result, error) {
	select {
	case <-s.block:
	case <-time.After(s.hard):
	}
	return &provider.Result{Output: "late", Provider: s.name, Model: "stuck-model"}, nil
}
func (s stuckProvider) Name() string         { return s.name }
func (s stuckProvider) DefaultModel() string { return "stuck-model" }

// fastProvider returns immediately.
type fastProvider struct{ name string }

func (f fastProvider) Complete(_ context.Context, _ string, _ provider.Options) (*provider.Result, error) {
	return &provider.Result{Output: "fast", Provider: f.name, Model: "fast-model", InputTokens: 1, OutputTokens: 1}, nil
}
func (f fastProvider) Name() string         { return f.name }
func (f fastProvider) DefaultModel() string { return "fast-model" }

// TestRun_HungProvider_HonoursGracePeriod verifies that when the parent ctx
// is cancelled and a provider ignores cancellation, Run returns within the
// configured grace period instead of blocking on wg.Wait() for the full
// per-provider timeout. Missing per-provider rows are filled with ctx.Err()
// so callers still get one entry per requested provider.
func TestRun_HungProvider_HonoursGracePeriod(t *testing.T) {
	prev := benchShutdownGracePeriod
	benchShutdownGracePeriod = 100 * time.Millisecond
	t.Cleanup(func() { benchShutdownGracePeriod = prev })

	block := make(chan struct{})
	t.Cleanup(func() { close(block) })

	builders := map[string]provider.Provider{
		"a": stuckProvider{name: "a", block: block, hard: 10 * time.Second},
		"b": stuckProvider{name: "b", block: block, hard: 10 * time.Second},
	}

	cfg := RunConfig{
		Prompt:    "prompt",
		Providers: []string{"a", "b"},
		Runs:      1,
		Timeout:   5 * time.Second,
	}

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()

	start := time.Now()
	rep, err := Run(ctx, cfg, builders)
	elapsed := time.Since(start)

	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if elapsed > 5*time.Second {
		t.Fatalf("Run blocked for %s — watchdog did not bound wg.Wait", elapsed)
	}
	if rep == nil {
		t.Fatal("expected non-nil report on early-return path")
	}
	if len(rep.Results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(rep.Results))
	}
	for _, r := range rep.Results {
		if r == nil {
			t.Fatal("nil result in report")
		}
		if !strings.Contains(r.Error, context.Canceled.Error()) {
			t.Errorf("result %s: expected context.Canceled error, got %q", r.ProviderName, r.Error)
		}
	}
}

// TestRun_NoCancellation_StillWaitsForCompletion verifies the watchdog does
// NOT fire on the happy path: when ctx is not cancelled, Run waits for
// workers to complete normally even with the grace period set to a tiny
// value.
func TestRun_NoCancellation_StillWaitsForCompletion(t *testing.T) {
	prev := benchShutdownGracePeriod
	benchShutdownGracePeriod = 1 * time.Millisecond
	t.Cleanup(func() { benchShutdownGracePeriod = prev })

	builders := map[string]provider.Provider{
		"a": fastProvider{name: "a"},
		"b": fastProvider{name: "b"},
	}

	cfg := RunConfig{
		Prompt:    "prompt",
		Providers: []string{"a", "b"},
		Runs:      1,
		Timeout:   5 * time.Second,
	}

	rep, err := Run(context.Background(), cfg, builders)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if rep == nil || len(rep.Results) != 2 {
		t.Fatalf("expected 2 results, got %v", rep)
	}
	for _, r := range rep.Results {
		if r.Error != "" {
			t.Errorf("result %s: unexpected error %q", r.ProviderName, r.Error)
		}
		if r.SuccessfulRuns != 1 {
			t.Errorf("result %s: expected 1 successful run, got %d", r.ProviderName, r.SuccessfulRuns)
		}
	}
}
