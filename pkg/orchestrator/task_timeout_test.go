package orchestrator

// Integration tests for per-task wall-clock timeout enforcement (Task 20108).
//
// The orchestrator is supposed to bound every task with a per-task budget that
// resolves through a three-layer fallback chain:
//
//   task.MaxMinutes > state.DefaultMaxMinutes > config.Orchestrator.TaskTimeoutMinutes
//
// When the deadline fires the per-task context must be cancelled (which the
// provider's HTTP/exec call honours via context propagation, Task 20081),
// the task must be marked TaskTimedOut, a final timeout artifact line must
// be written, and a webhook event must be emitted.
//
// To keep the suite fast the tests install a millisecond unit via
// withTaskTimeoutUnit so that "1 minute of budget" resolves to 1 ms. The
// hangingProvider blocks on its ctx until cancellation, modelling a
// well-behaved provider whose HTTP call is bound by the deadline. The
// stubborn variant ignores cancellation and waits on its own release
// channel, modelling a misbehaving SDK; it is used only by the negative
// test that verifies the watchdog/grace-period path is not the one
// responsible for the timeout marker (the per-task ctx deadline is).

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/provider"
	"github.com/blechschmidt/cloop/pkg/state"
)

// hangingProvider blocks Complete() on ctx.Done() and returns ctx.Err() when
// cancelled. Models a provider whose HTTP call honours context cancellation
// (Task 20081 made all built-in providers do this). callCount is incremented
// on entry so tests can assert the provider was actually invoked at least once.
type hangingProvider struct {
	calls int32
}

func (p *hangingProvider) Complete(ctx context.Context, _ string, _ provider.Options) (*provider.Result, error) {
	atomic.AddInt32(&p.calls, 1)
	<-ctx.Done()
	return nil, ctx.Err()
}
func (*hangingProvider) Name() string         { return "hanging" }
func (*hangingProvider) DefaultModel() string { return "hanging-model" }

// TestTaskTimeout_PerTaskBudget asserts that a task with task.MaxMinutes=1
// (1 ms under the test unit) is cancelled and marked timed_out within a tight
// budget, that the task's FailureDiagnosis carries the timeout reason, and
// that a final artifact line is written even though the provider produced
// no partial output.
func TestTaskTimeout_PerTaskBudget(t *testing.T) {
	defer withTaskTimeoutUnit(time.Millisecond)()

	dir := tempDir(t)
	s := initState(t, dir, "goal", 0)
	s.PMMode = true
	s.Plan = &pm.Plan{
		Goal: "goal",
		Tasks: []*pm.Task{
			{ID: 1, Title: "Hangs", Priority: 1, Status: pm.TaskPending, MaxMinutes: 50},
		},
	}
	if err := s.Save(); err != nil {
		t.Fatalf("save: %v", err)
	}

	prov := &hangingProvider{}
	// NoHeal disables the auto-heal loop so the timeout terminates the task
	// immediately (otherwise we'd wait for HealRetries additional rounds,
	// each blocking another 50ms — slow and irrelevant to this assertion).
	o := newOrchestrator(t, dir, Config{WorkDir: dir, PMMode: true, NoHeal: true}, prov)

	// Tight wall-clock budget: 50ms unit-budget × at most a couple of retries
	// + bookkeeping overhead. If the timeout machinery breaks, the test will
	// hit the t.Fatal below long before this expires.
	hardDeadline := 5 * time.Second
	ctx, cancel := context.WithTimeout(context.Background(), hardDeadline)
	defer cancel()

	start := time.Now()
	if err := o.runPM(ctx); err != nil && !errors.Is(err, context.DeadlineExceeded) {
		t.Logf("runPM returned: %v", err)
	}
	elapsed := time.Since(start)

	if elapsed >= hardDeadline {
		t.Fatalf("runPM exceeded hard deadline %s (elapsed %s) — per-task timeout did not fire", hardDeadline, elapsed)
	}
	if atomic.LoadInt32(&prov.calls) == 0 {
		t.Fatalf("provider was never called")
	}

	final, err := state.Load(dir)
	if err != nil {
		t.Fatalf("state.Load: %v", err)
	}
	if len(final.Plan.Tasks) != 1 {
		t.Fatalf("expected 1 task, got %d", len(final.Plan.Tasks))
	}
	task := final.Plan.Tasks[0]
	if task.Status != pm.TaskTimedOut {
		t.Fatalf("expected status %q, got %q", pm.TaskTimedOut, task.Status)
	}
	if !strings.Contains(strings.ToLower(task.FailureDiagnosis), "timed out") {
		t.Errorf("expected FailureDiagnosis to mention timeout, got %q", task.FailureDiagnosis)
	}
	// Final artifact line: handleTaskTimeout always writes one (Task 20108
	// requirement), even when the provider returned no partial output.
	if task.ArtifactPath == "" {
		t.Fatalf("expected ArtifactPath to be set on timeout")
	}
	// ArtifactPath is stored relative to workDir; join before reading.
	body, rerr := os.ReadFile(filepath.Join(dir, task.ArtifactPath))
	if rerr != nil {
		t.Fatalf("read artifact: %v", rerr)
	}
	if !strings.Contains(string(body), "TIMEOUT") {
		t.Errorf("expected artifact to contain TIMEOUT marker, got:\n%s", string(body))
	}
	if !strings.Contains(string(body), "TASK_FAILED") {
		t.Errorf("expected artifact to contain TASK_FAILED marker, got:\n%s", string(body))
	}
	// Annotation should also describe the budget. AddAnnotation appends to
	// the slice so the timeout note is the last entry.
	if len(task.Annotations) == 0 {
		t.Fatalf("expected at least one timeout annotation")
	}
	last := task.Annotations[len(task.Annotations)-1]
	if !strings.Contains(strings.ToLower(last.Text), "timed out") {
		t.Errorf("expected last annotation to mention timeout, got %q", last.Text)
	}
}

// TestTaskTimeout_GlobalDefault asserts the third-tier fallback works:
// when neither the task nor the project state has a budget, the
// process-wide config.Orchestrator.TaskTimeoutMinutes wins.
func TestTaskTimeout_GlobalDefault(t *testing.T) {
	defer withTaskTimeoutUnit(time.Millisecond)()

	dir := tempDir(t)
	s := initState(t, dir, "goal", 0)
	s.PMMode = true
	s.Plan = &pm.Plan{
		Goal: "goal",
		Tasks: []*pm.Task{
			// MaxMinutes not set — must inherit from config.
			{ID: 1, Title: "Hangs", Priority: 1, Status: pm.TaskPending},
		},
	}
	if err := s.Save(); err != nil {
		t.Fatalf("save: %v", err)
	}

	prov := &hangingProvider{}
	o := newOrchestrator(t, dir, Config{
		WorkDir:            dir,
		PMMode:             true,
		NoHeal:             true,
		TaskTimeoutMinutes: 30, // 30 ms under the test unit
	}, prov)

	hardDeadline := 5 * time.Second
	ctx, cancel := context.WithTimeout(context.Background(), hardDeadline)
	defer cancel()

	start := time.Now()
	_ = o.runPM(ctx)
	elapsed := time.Since(start)

	if elapsed >= hardDeadline {
		t.Fatalf("runPM exceeded hard deadline %s — global default did not fire", hardDeadline)
	}

	final, err := state.Load(dir)
	if err != nil {
		t.Fatalf("state.Load: %v", err)
	}
	task := final.Plan.Tasks[0]
	if task.Status != pm.TaskTimedOut {
		t.Fatalf("expected status %q, got %q", pm.TaskTimedOut, task.Status)
	}
}

// TestTaskTimeout_ProjectDefault asserts the second-tier fallback works:
// state.DefaultMaxMinutes overrides the global config when set.
func TestTaskTimeout_ProjectDefault(t *testing.T) {
	defer withTaskTimeoutUnit(time.Millisecond)()

	dir := tempDir(t)
	s := initState(t, dir, "goal", 0)
	s.PMMode = true
	s.DefaultMaxMinutes = 25 // 25 ms under the test unit; below the global below
	s.Plan = &pm.Plan{
		Goal: "goal",
		Tasks: []*pm.Task{
			{ID: 1, Title: "Hangs", Priority: 1, Status: pm.TaskPending},
		},
	}
	if err := s.Save(); err != nil {
		t.Fatalf("save: %v", err)
	}

	prov := &hangingProvider{}
	o := newOrchestrator(t, dir, Config{
		WorkDir:            dir,
		PMMode:             true,
		NoHeal:             true,
		TaskTimeoutMinutes: 60_000, // very large; should be shadowed by the project default
	}, prov)

	hardDeadline := 2 * time.Second
	ctx, cancel := context.WithTimeout(context.Background(), hardDeadline)
	defer cancel()

	start := time.Now()
	_ = o.runPM(ctx)
	elapsed := time.Since(start)

	// 25 ms unit + bookkeeping should comfortably fit inside 2 s. If the
	// project-level value were ignored and the global won, the run would
	// take roughly 60 seconds and trip the hard deadline.
	if elapsed >= hardDeadline {
		t.Fatalf("runPM exceeded %s — project DefaultMaxMinutes was not honoured (elapsed %s)", hardDeadline, elapsed)
	}

	final, err := state.Load(dir)
	if err != nil {
		t.Fatalf("state.Load: %v", err)
	}
	if final.Plan.Tasks[0].Status != pm.TaskTimedOut {
		t.Fatalf("expected timed_out, got %q", final.Plan.Tasks[0].Status)
	}
}

// TestEffectiveTaskBudgetMinutes covers the resolution helper directly so a
// regression in lookup-order priority is caught without spinning up a full
// orchestrator run.
func TestEffectiveTaskBudgetMinutes(t *testing.T) {
	dir := tempDir(t)
	s := initState(t, dir, "goal", 0)
	s.Plan = &pm.Plan{Goal: "goal"}
	if err := s.Save(); err != nil {
		t.Fatalf("save: %v", err)
	}
	o := newOrchestrator(t, dir, Config{WorkDir: dir, TaskTimeoutMinutes: 7}, &mockProvider{name: "m"})

	// All three layers populated → task wins.
	o.state.DefaultMaxMinutes = 5
	got := o.effectiveTaskBudgetMinutes(&pm.Task{MaxMinutes: 3})
	if got != 3 {
		t.Errorf("task layer: expected 3, got %d", got)
	}
	// Task zero, project set → project wins.
	got = o.effectiveTaskBudgetMinutes(&pm.Task{MaxMinutes: 0})
	if got != 5 {
		t.Errorf("project layer: expected 5, got %d", got)
	}
	// Task zero, project zero → config wins.
	o.state.DefaultMaxMinutes = 0
	got = o.effectiveTaskBudgetMinutes(&pm.Task{MaxMinutes: 0})
	if got != 7 {
		t.Errorf("config layer: expected 7, got %d", got)
	}
	// All zero → no timeout (Task 20148: tasks have no default timeout).
	o.config.TaskTimeoutMinutes = 0
	got = o.effectiveTaskBudgetMinutes(&pm.Task{MaxMinutes: 0})
	if got != 0 {
		t.Errorf("no budget set: expected 0 (no timeout), got %d", got)
	}
	// Out-of-band config value (negative or > 1 week) is ignored and, with no
	// other layer set, also resolves to no timeout rather than arming a bogus
	// deadline.
	o.config.TaskTimeoutMinutes = -5
	if got := o.effectiveTaskBudgetMinutes(&pm.Task{MaxMinutes: 0}); got != 0 {
		t.Errorf("out-of-band negative: expected 0 (no timeout), got %d", got)
	}
	o.config.TaskTimeoutMinutes = 99_999_999
	if got := o.effectiveTaskBudgetMinutes(&pm.Task{MaxMinutes: 0}); got != 0 {
		t.Errorf("out-of-band huge: expected 0 (no timeout), got %d", got)
	}
}

// TestTaskContextWithTimeout_NoBudgetHasNoDeadline is the regression for
// Task 20148: with no explicit per-task / per-project / process budget set,
// taskContextWithTimeout must return a context with NO wall-clock deadline so
// a long-running task is never killed for taking a while. An explicit
// per-task budget must still arm a deadline (the opt-in path).
//
// Uses task.ID == 0 so the context routes through the plain
// context.WithCancel / context.WithTimeout branches (not liveDeadlines, which
// uses an external timer + WithCancelCause and so never reports a Deadline()).
func TestTaskContextWithTimeout_NoBudgetHasNoDeadline(t *testing.T) {
	dir := tempDir(t)
	s := initState(t, dir, "goal", 0)
	s.Plan = &pm.Plan{Goal: "goal"}
	if err := s.Save(); err != nil {
		t.Fatalf("save: %v", err)
	}
	// No TaskTimeoutMinutes, no DefaultMaxMinutes → no timeout.
	o := newOrchestrator(t, dir, Config{WorkDir: dir}, &mockProvider{name: "m"})

	ctx := context.Background()
	taskCtx, cancel := o.taskContextWithTimeout(ctx, &pm.Task{ID: 0, Title: "t"})
	defer cancel()
	if dl, ok := taskCtx.Deadline(); ok {
		t.Fatalf("expected no deadline with no budget set, got deadline %s", dl)
	}

	// Explicit per-task budget still arms a deadline.
	taskCtx2, cancel2 := o.taskContextWithTimeout(ctx, &pm.Task{ID: 0, Title: "t2", MaxMinutes: 30})
	defer cancel2()
	if _, ok := taskCtx2.Deadline(); !ok {
		t.Fatalf("expected a deadline when MaxMinutes is set, got none")
	}
}

// TestStartTaskDeadline_ZeroBudgetArmsNoTimer verifies that the live-deadline
// registry registers a zero-budget entry without arming a timer (Task 20148),
// so the returned context is never cancelled by a deadline — only by release
// or a later poller-driven adjust that opts the task into a budget.
func TestStartTaskDeadline_ZeroBudgetArmsNoTimer(t *testing.T) {
	r := newLiveDeadlineRegistry()
	ctx, cancel := r.startTaskDeadline(context.Background(), 7, 0, time.Millisecond)
	defer cancel()

	r.mu.Lock()
	entry := r.entries[7]
	r.mu.Unlock()
	if entry == nil {
		t.Fatalf("expected entry to be registered even with zero budget")
	}
	if entry.timer != nil {
		t.Fatalf("expected no timer armed for a zero budget")
	}

	// Context must not be cancelled by a deadline. Give the (absent) timer
	// ample time to (not) fire.
	select {
	case <-ctx.Done():
		t.Fatalf("context cancelled despite no timeout: %v", context.Cause(ctx))
	case <-time.After(20 * time.Millisecond):
		// Expected: still running.
	}

	// A later adjust() to a positive budget must arm a timer and eventually
	// cancel the context with DeadlineExceeded.
	if !r.adjust(7, 1, time.Millisecond) {
		t.Fatalf("expected adjust to apply a positive budget")
	}
	select {
	case <-ctx.Done():
		if !errors.Is(context.Cause(ctx), context.DeadlineExceeded) {
			t.Fatalf("expected DeadlineExceeded cause, got %v", context.Cause(ctx))
		}
	case <-time.After(time.Second):
		t.Fatalf("expected context to fire after adjust armed a budget")
	}
}

// TestTaskTimeout_WebhookEvent asserts that the structured webhook event
// fires with status="timed_out" when the per-task deadline trips. Uses an
// httptest server to capture the POST body without external dependencies.
func TestTaskTimeout_WebhookEvent(t *testing.T) {
	defer withTaskTimeoutUnit(time.Millisecond)()

	gotTimedOut := make(chan struct{}, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Capture the body and look for the timed_out marker. We don't parse
		// the JSON strictly here — string match is enough to prove the
		// payload made it through.
		buf := make([]byte, 4096)
		n, _ := r.Body.Read(buf)
		body := string(buf[:n])
		if strings.Contains(body, "timed_out") {
			select {
			case gotTimedOut <- struct{}{}:
			default:
			}
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)

	dir := tempDir(t)
	s := initState(t, dir, "goal", 0)
	s.PMMode = true
	s.Plan = &pm.Plan{
		Goal: "goal",
		Tasks: []*pm.Task{
			{ID: 1, Title: "Hangs", Priority: 1, Status: pm.TaskPending, MaxMinutes: 30},
		},
	}
	if err := s.Save(); err != nil {
		t.Fatalf("save: %v", err)
	}

	prov := &hangingProvider{}
	o := newOrchestrator(t, dir, Config{
		WorkDir:    dir,
		PMMode:     true,
		NoHeal:     true,
		WebhookURL: srv.URL,
	}, prov)

	hardDeadline := 5 * time.Second
	ctx, cancel := context.WithTimeout(context.Background(), hardDeadline)
	defer cancel()
	_ = o.runPM(ctx)

	select {
	case <-gotTimedOut:
		// Pass.
	case <-time.After(2 * time.Second):
		t.Fatalf("expected webhook event with status=timed_out, got none")
	}

	// Belt-and-braces: artifact path also exists on disk.
	final, _ := state.Load(dir)
	if final.Plan.Tasks[0].ArtifactPath == "" {
		t.Errorf("expected artifact path to be set on timeout")
	}
	if _, statErr := os.Stat(filepath.Join(dir, final.Plan.Tasks[0].ArtifactPath)); statErr != nil {
		t.Errorf("expected artifact file to exist: %v", statErr)
	}
}
