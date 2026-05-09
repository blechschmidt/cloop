package consensus

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/provider"
)

// staticProvider returns a fixed output without panicking.
type staticProvider struct {
	name   string
	output string
}

func (s *staticProvider) Complete(_ context.Context, _ string, _ provider.Options) (*provider.Result, error) {
	return &provider.Result{Output: s.output, Provider: s.name, Model: "static-model"}, nil
}
func (s *staticProvider) Name() string         { return s.name }
func (s *staticProvider) DefaultModel() string { return "static-model" }

// panicProvider always panics on Complete().
type panicProvider struct{ name string }

func (p *panicProvider) Complete(_ context.Context, _ string, _ provider.Options) (*provider.Result, error) {
	panic("simulated provider crash")
}
func (p *panicProvider) Name() string         { return p.name }
func (p *panicProvider) DefaultModel() string { return "panic-model" }

// TestRunConsensus_PanickingProviderDoesNotCrash verifies that a panic in one
// provider's Complete() during the parallel fan-out is recovered, the panicking
// provider is recorded with an error, and the other provider's response is used
// (no judge needed when only one valid candidate remains). Without the
// recover() in the fan-out goroutine this test would terminate the entire test
// binary with a runtime panic.
func TestRunConsensus_PanickingProviderDoesNotCrash(t *testing.T) {
	good := &staticProvider{name: "good", output: "valid response"}
	bad := &panicProvider{name: "panicker"}

	// Judge isn't reached because only one valid candidate survives.
	winner, _, err := RunConsensus(
		context.Background(),
		[]provider.Provider{good, bad},
		"prompt",
		provider.Options{Timeout: 5 * time.Second},
		good, // judge unused here
		"",
		2,
		1,
		"test task",
	)
	if err != nil {
		t.Fatalf("RunConsensus returned error: %v", err)
	}
	if !strings.Contains(winner, "valid response") {
		t.Errorf("expected good provider's output as winner, got %q", winner)
	}
}

// TestRunConsensus_AllProvidersPanic verifies that when every provider panics,
// the function returns an error rather than crashing the process.
func TestRunConsensus_AllProvidersPanic(t *testing.T) {
	a := &panicProvider{name: "a"}
	b := &panicProvider{name: "b"}

	_, _, err := RunConsensus(
		context.Background(),
		[]provider.Provider{a, b},
		"prompt",
		provider.Options{Timeout: 5 * time.Second},
		a, "", 2, 1, "t",
	)
	if err == nil {
		t.Fatal("expected error when all providers panic, got nil")
	}
	if !strings.Contains(err.Error(), "all providers failed") {
		t.Errorf("expected 'all providers failed' error, got %q", err.Error())
	}
}
