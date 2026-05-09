package consensus

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/provider"
)

// stuckProvider blocks indefinitely (until block is closed or hard expires),
// ignoring its ctx argument. Models a misbehaving third-party SDK that fails
// to honour ctx.Done() — the failure mode consensusShutdownGracePeriod is
// meant to bound.
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

// TestRunConsensus_HungProvider_HonoursGracePeriod verifies that when the
// parent ctx is cancelled and a provider ignores cancellation, RunConsensus
// returns within the configured grace period instead of blocking on
// wg.Wait() for the full provider timeout.
func TestRunConsensus_HungProvider_HonoursGracePeriod(t *testing.T) {
	prev := consensusShutdownGracePeriod
	consensusShutdownGracePeriod = 100 * time.Millisecond
	t.Cleanup(func() { consensusShutdownGracePeriod = prev })

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
	out, rep, err := RunConsensus(
		ctx,
		[]provider.Provider{a, b},
		"prompt",
		provider.Options{Timeout: 5 * time.Second},
		a, "", 2, 1, "test task",
	)
	elapsed := time.Since(start)

	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
	if out != "" {
		t.Errorf("expected empty output on early-return path, got %q", out)
	}
	if rep != nil {
		t.Errorf("expected nil report on early-return path, got %+v", rep)
	}
	// Generous slack: cancel delay (~50ms) + grace (100ms) + scheduler noise.
	// If we exceed 5s the watchdog clearly didn't fire.
	if elapsed > 5*time.Second {
		t.Fatalf("RunConsensus blocked for %s — watchdog did not bound wg.Wait", elapsed)
	}
}

// TestRunConsensus_NoCancellation_StillWaitsForCompletion verifies the
// watchdog does NOT fire on the happy path: when the parent ctx is not
// cancelled, RunConsensus waits for workers to complete normally even with
// the grace period set to a tiny value.
func TestRunConsensus_NoCancellation_StillWaitsForCompletion(t *testing.T) {
	prev := consensusShutdownGracePeriod
	consensusShutdownGracePeriod = 1 * time.Millisecond
	t.Cleanup(func() { consensusShutdownGracePeriod = prev })

	good := &staticProvider{name: "good", output: "valid response"}

	out, _, err := RunConsensus(
		context.Background(),
		[]provider.Provider{good},
		"prompt",
		provider.Options{Timeout: 5 * time.Second},
		good, "", 1, 1, "t",
	)
	if err != nil {
		t.Fatalf("RunConsensus: %v", err)
	}
	if out != "valid response" {
		t.Errorf("expected good provider output, got %q", out)
	}
}
