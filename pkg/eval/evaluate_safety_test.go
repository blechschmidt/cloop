package eval

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/provider"
)

// panickyProvider crashes on every Complete call. Models a third-party SDK
// nil-pointer or malformed-JSON deref — without panic recovery this would
// take down the entire `cloop eval` run and lose every score that the loop
// completed earlier.
type panickyProvider struct{}

func (panickyProvider) Complete(_ context.Context, _ string, _ provider.Options) (*provider.Result, error) {
	panic("simulated provider crash")
}
func (panickyProvider) Name() string         { return "panicky" }
func (panickyProvider) DefaultModel() string { return "panicky-model" }

// scoreCounterProvider returns a fixed valid JSON score and counts how many
// times Complete was invoked. Used to assert the cancellation short-circuit.
type scoreCounterProvider struct {
	calls *int
}

func (s scoreCounterProvider) Complete(ctx context.Context, _ string, _ provider.Options) (*provider.Result, error) {
	*s.calls++
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return &provider.Result{Output: `{"score": 7, "rationale": "ok"}`, Provider: "counter", Model: "counter-model"}, nil
}
func (scoreCounterProvider) Name() string         { return "counter" }
func (scoreCounterProvider) DefaultModel() string { return "counter-model" }

// TestEvaluate_PanickingProviderIsRecovered verifies that a panic inside the
// provider becomes a returned error instead of crashing the test process.
// Without scoreOneCriterionSafe's recover() this test would terminate with
// "panic: simulated provider crash" rather than reporting a normal failure.
func TestEvaluate_PanickingProviderIsRecovered(t *testing.T) {
	dir := t.TempDir()
	task := &pm.Task{ID: 1, Title: "panicky task"}
	rubric := Rubric{Criteria: []Criterion{
		{Name: "Correctness", Weight: 1.0, Description: "Is it correct?"},
	}}

	_, err := Evaluate(context.Background(), panickyProvider{}, "", time.Second, dir, task, "task output", rubric)
	if err == nil {
		t.Fatalf("expected error from panicking provider, got nil")
	}
	if !strings.Contains(err.Error(), "provider panic") {
		t.Fatalf("expected wrapped panic error, got: %v", err)
	}
	if !strings.Contains(err.Error(), "panicky") {
		t.Fatalf("expected provider name in error, got: %v", err)
	}
}

// TestEvaluate_CancelledCtxBailsBeforeNextCriterion verifies that when the
// caller's ctx is cancelled mid-rubric, Evaluate returns at the next
// iteration boundary rather than running every remaining criterion. Without
// the ctx.Err() guard this loop would call scoreOneCriterion N more times.
func TestEvaluate_CancelledCtxBailsBeforeNextCriterion(t *testing.T) {
	dir := t.TempDir()
	task := &pm.Task{ID: 2, Title: "cancellable"}
	rubric := Rubric{Criteria: []Criterion{
		{Name: "C1", Weight: 0.25, Description: "first"},
		{Name: "C2", Weight: 0.25, Description: "second"},
		{Name: "C3", Weight: 0.25, Description: "third"},
		{Name: "C4", Weight: 0.25, Description: "fourth"},
	}}

	calls := 0
	prov := scoreCounterProvider{calls: &calls}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := Evaluate(ctx, prov, "", time.Second, dir, task, "task output", rubric)
	if err == nil {
		t.Fatalf("expected ctx-cancelled error, got nil")
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected ctx.Canceled in error chain, got: %v", err)
	}
	if calls != 0 {
		t.Fatalf("expected 0 provider calls after pre-cancellation, got %d (loop kept running past ctx.Err())", calls)
	}
}
