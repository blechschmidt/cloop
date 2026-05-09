package consensus

import (
	"context"
	"errors"
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

// errorProvider returns a fixed error from Complete. Used to verify that
// RunConsensus surfaces a real error in its all-providers-failed message
// rather than reporting candidates[0].Err blindly (which would print "<nil>"
// when only the first candidate succeeded silently with empty output).
type errorProvider struct {
	name string
	err  error
}

func (e *errorProvider) Complete(_ context.Context, _ string, _ provider.Options) (*provider.Result, error) {
	return nil, e.err
}
func (e *errorProvider) Name() string         { return e.name }
func (e *errorProvider) DefaultModel() string { return "error-model" }

// TestRunConsensus_AllProvidersFailed_SurfacesRealErrorNotNil verifies that
// when the first candidate returns nil-error + empty output (filtered out as
// invalid) and a later candidate returns an actual error, the all-failed
// error message reports the real underlying error rather than "<nil>".
//
// Without this fix, an upstream auth/5xx error from a non-zeroth candidate
// would be reported as "first error: <nil>", losing the underlying cause and
// making it harder for operators (and the orchestrator's MaxFailures gate
// reasoning) to attribute the failure correctly.
func TestRunConsensus_AllProvidersFailed_SurfacesRealErrorNotNil(t *testing.T) {
	silent := &staticProvider{name: "silent", output: ""}        // valid filter drops empty output
	authFail := &errorProvider{name: "alpha", err: errors.New("HTTP 401: invalid_api_key")}

	_, _, err := RunConsensus(
		context.Background(),
		[]provider.Provider{silent, authFail},
		"prompt",
		provider.Options{Timeout: 5 * time.Second},
		silent, "", 2, 1, "t",
	)
	if err == nil {
		t.Fatal("expected all-providers-failed error, got nil")
	}
	msg := err.Error()
	if !strings.Contains(msg, "all providers failed") {
		t.Errorf("expected 'all providers failed' in error, got %q", msg)
	}
	if strings.Contains(msg, "<nil>") {
		t.Errorf("error must not contain literal '<nil>'; got %q", msg)
	}
	if !strings.Contains(msg, "HTTP 401") {
		t.Errorf("expected the real HTTP 401 cause to be surfaced, got %q", msg)
	}
	if !errors.Is(err, authFail.err) {
		t.Errorf("expected errors.Is to find wrapped auth error, got %q", msg)
	}
}

// TestRunConsensus_AllProvidersEmpty_DistinctErrorMessage verifies that when
// every candidate returns nil-error + empty output (no real failure, just
// model produced nothing), the error message identifies that distinct failure
// mode rather than confusing it with an actual error.
func TestRunConsensus_AllProvidersEmpty_DistinctErrorMessage(t *testing.T) {
	a := &staticProvider{name: "a", output: ""}
	b := &staticProvider{name: "b", output: ""}

	_, _, err := RunConsensus(
		context.Background(),
		[]provider.Provider{a, b},
		"prompt",
		provider.Options{Timeout: 5 * time.Second},
		a, "", 2, 1, "t",
	)
	if err == nil {
		t.Fatal("expected error when every provider returns empty output, got nil")
	}
	msg := err.Error()
	if !strings.Contains(msg, "empty output") {
		t.Errorf("expected 'empty output' diagnosis, got %q", msg)
	}
	if strings.Contains(msg, "<nil>") {
		t.Errorf("error must not contain literal '<nil>'; got %q", msg)
	}
}
