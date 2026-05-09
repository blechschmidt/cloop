package multiagent

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/provider"
)

// panickingMultiagentProvider crashes on every Complete call. Models a
// third-party SDK nil-pointer or malformed-JSON deref — without panic
// recovery this would take down the whole `cloop run` process during the
// multi-agent pipeline and lose every queued task.
type panickingMultiagentProvider struct{}

func (panickingMultiagentProvider) Complete(_ context.Context, _ string, _ provider.Options) (*provider.Result, error) {
	panic("simulated provider crash mid-pipeline")
}
func (panickingMultiagentProvider) Name() string         { return "panicky-ma" }
func (panickingMultiagentProvider) DefaultModel() string { return "panicky-model" }

// callCounterProvider returns a fixed valid response and counts how many
// times Complete was invoked. Used to assert the cancellation short-circuit
// between passes — the second/third call must not happen when ctx is already
// done.
type callCounterProvider struct {
	calls *atomic.Int32
}

func (c callCounterProvider) Complete(ctx context.Context, _ string, _ provider.Options) (*provider.Result, error) {
	c.calls.Add(1)
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return &provider.Result{Output: "TASK_DONE", Provider: "counter", Model: "counter-model"}, nil
}
func (callCounterProvider) Name() string         { return "counter" }
func (callCounterProvider) DefaultModel() string { return "counter-model" }

// TestRunTask_PanickingProviderIsRecovered verifies that a panic during the
// architect pass becomes a returned error instead of crashing the test
// process. Without safeComplete's recover() this test would terminate with
// "panic: simulated provider crash mid-pipeline" rather than reporting a
// normal failure, and in production the orchestrator would die mid-run.
func TestRunTask_PanickingProviderIsRecovered(t *testing.T) {
	task := &pm.Task{ID: 1, Title: "panicky task", Description: "do thing"}

	_, err := RunTask(
		context.Background(),
		panickingMultiagentProvider{},
		"some-model",
		time.Second,
		task,
		"goal",
		"instructions",
		"",
	)
	if err == nil {
		t.Fatalf("expected error from panicking provider, got nil")
	}
	if !strings.Contains(err.Error(), "provider panic") {
		t.Fatalf("expected wrapped panic error, got: %v", err)
	}
	if !strings.Contains(err.Error(), "panicky-ma") {
		t.Fatalf("expected provider name in error, got: %v", err)
	}
	if !strings.Contains(err.Error(), "architect pass") {
		t.Fatalf("expected pass-name wrapper, got: %v", err)
	}
}

// TestRunTask_CancelledCtxBailsBeforeNextPass verifies that when the
// caller's ctx is cancelled before the pipeline starts, RunTask returns at
// the first guard rather than running every remaining pass. Without the
// ctx.Err() guards each pass would still fire, ignoring cancellation for
// tens of minutes of provider time.
func TestRunTask_CancelledCtxBailsBeforeNextPass(t *testing.T) {
	task := &pm.Task{ID: 2, Title: "cancellable", Description: "do thing"}

	var calls atomic.Int32
	prov := callCounterProvider{calls: &calls}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := RunTask(ctx, prov, "some-model", time.Second, task, "goal", "instructions", "")
	if err == nil {
		t.Fatalf("expected ctx-cancelled error, got nil")
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected ctx.Canceled in error chain, got: %v", err)
	}
	if got := calls.Load(); got != 0 {
		t.Fatalf("expected 0 provider calls after pre-cancellation, got %d (pipeline kept running past ctx.Err())", got)
	}
}
