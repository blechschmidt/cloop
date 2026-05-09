package compare

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/provider"
)

// stuckProvider blocks until block is closed or hard expires, ignoring its
// ctx argument. Models a misbehaving SDK that fails to honour ctx.Done() —
// the failure mode compareShutdownGracePeriod is meant to bound.
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
	return &provider.Result{Output: "fast", Provider: f.name, Model: "fast-model"}, nil
}
func (f fastProvider) Name() string         { return f.name }
func (f fastProvider) DefaultModel() string { return "fast-model" }

// TestRun_HungProvider_HonoursGracePeriod verifies that when the parent ctx
// is cancelled and a provider ignores cancellation, Run returns within the
// configured grace period instead of blocking on wg.Wait() for the full
// per-provider timeout. Unfinished entries are filled with ctx.Err() so
// callers can iterate the slice without nil checks.
func TestRun_HungProvider_HonoursGracePeriod(t *testing.T) {
	prev := compareShutdownGracePeriod
	compareShutdownGracePeriod = 100 * time.Millisecond
	t.Cleanup(func() { compareShutdownGracePeriod = prev })

	block := make(chan struct{})
	t.Cleanup(func() { close(block) })

	a := stuckProvider{name: "a", block: block, hard: 10 * time.Second}
	b := stuckProvider{name: "b", block: block, hard: 10 * time.Second}

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()

	start := time.Now()
	results := Run(ctx, "prompt", []provider.Provider{a, b}, "", 5*time.Second)
	elapsed := time.Since(start)

	if elapsed > 5*time.Second {
		t.Fatalf("Run blocked for %s — watchdog did not bound wg.Wait", elapsed)
	}
	if len(results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(results))
	}
	for i, r := range results {
		if r == nil {
			t.Fatalf("result[%d] is nil — placeholder fill missing", i)
		}
		if !errors.Is(r.Err, context.Canceled) {
			t.Errorf("result[%d]: expected context.Canceled, got %v", i, r.Err)
		}
	}
}

// TestRun_NoCancellation_StillWaitsForCompletion verifies the watchdog does
// NOT fire on the happy path: when ctx is not cancelled, Run waits for
// workers to complete normally even with the grace period set to a tiny
// value.
func TestRun_NoCancellation_StillWaitsForCompletion(t *testing.T) {
	prev := compareShutdownGracePeriod
	compareShutdownGracePeriod = 1 * time.Millisecond
	t.Cleanup(func() { compareShutdownGracePeriod = prev })

	a := fastProvider{name: "a"}
	b := fastProvider{name: "b"}

	results := Run(context.Background(), "prompt", []provider.Provider{a, b}, "", 5*time.Second)
	if len(results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(results))
	}
	for i, r := range results {
		if r == nil {
			t.Fatalf("result[%d] is nil", i)
		}
		if r.Err != nil {
			t.Errorf("result[%d]: unexpected error %v", i, r.Err)
		}
		if r.Output != "fast" {
			t.Errorf("result[%d]: expected fast output, got %q", i, r.Output)
		}
	}
}
