package orchestrator

// Tests for Task 20348: stopping a run puts the task it was executing back to
// pending, so resuming the project picks it up again.
//
// The stop is delivered from inside the provider call — the provider cancels
// the run and then waits for its own context, as the claude CLI wrapper does —
// so every test stops the run at a known point rather than racing a timer
// against the orchestrator.

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/pausereason"
	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/provider"
	"github.com/blechschmidt/cloop/pkg/state"
)

// stopHere, as a scripted output, marks the provider call during which the run
// is stopped.
const stopHere = "\x00stop"

// scriptedStopProvider answers calls from a script. The call scripted as
// stopHere cancels the run from inside the provider and then behaves like a
// well-behaved provider: it returns once its context is cancelled, with the
// error the claude CLI wrapper returns. Calls past the end of the script
// report success.
type scriptedStopProvider struct {
	mu     sync.Mutex
	script []string
	stop   context.CancelFunc
	calls  int
}

func (p *scriptedStopProvider) Complete(ctx context.Context, _ string, _ provider.Options) (*provider.Result, error) {
	p.mu.Lock()
	i := p.calls
	p.calls++
	out := "finished\nTASK_DONE"
	if i < len(p.script) {
		out = p.script[i]
	}
	p.mu.Unlock()

	if out == stopHere {
		p.stop()
		<-ctx.Done()
		return nil, fmt.Errorf("claude CLI cancelled: %w", ctx.Err())
	}
	return &provider.Result{Output: out, Provider: "scripted"}, nil
}
func (p *scriptedStopProvider) Name() string         { return "scripted" }
func (p *scriptedStopProvider) DefaultModel() string { return "scripted-model" }

// stopWhenAllStarted blocks every call until its context is cancelled, and
// stops the run once n calls are in flight — a parallel batch stopped with all
// of its tasks running.
//
// With ignore set it models a provider that does not honour cancellation: its
// calls block until ignore is closed, whatever happens to their context.
type stopWhenAllStarted struct {
	mu      sync.Mutex
	n       int
	started int
	stop    context.CancelFunc
	ignore  <-chan struct{}
}

func (p *stopWhenAllStarted) Complete(ctx context.Context, _ string, _ provider.Options) (*provider.Result, error) {
	p.mu.Lock()
	p.started++
	if p.started == p.n {
		p.stop()
	}
	p.mu.Unlock()
	if p.ignore != nil {
		<-p.ignore
		return &provider.Result{Output: "late\nTASK_DONE", Provider: "blocking"}, nil
	}
	<-ctx.Done()
	return nil, fmt.Errorf("claude CLI cancelled: %w", ctx.Err())
}
func (p *stopWhenAllStarted) Name() string         { return "blocking" }
func (p *stopWhenAllStarted) DefaultModel() string { return "blocking-model" }

// sessionDeadline is a run context whose deadline passes when expire is
// called: a --timeout that runs out at the moment the test chooses, rather
// than at a moment the scheduler chooses. Contexts derived from it see
// context.DeadlineExceeded, exactly as under context.WithTimeout.
type sessionDeadline struct {
	context.Context
	done chan struct{}
	once sync.Once
	mu   sync.Mutex
	err  error
}

func newSessionDeadline() *sessionDeadline {
	return &sessionDeadline{Context: context.Background(), done: make(chan struct{})}
}

func (c *sessionDeadline) Deadline() (time.Time, bool) { return time.Now().Add(time.Hour), true }
func (c *sessionDeadline) Done() <-chan struct{}       { return c.done }
func (c *sessionDeadline) Err() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.err
}
func (c *sessionDeadline) expire() {
	c.once.Do(func() {
		c.mu.Lock()
		c.err = context.DeadlineExceeded
		c.mu.Unlock()
		close(c.done)
	})
}

// chainPlan seeds a project whose second task depends on the first. The
// dependency is what makes a stop destructive when it is filed as a failure:
// the dependent is then skipped as permanently blocked.
func chainPlan(t *testing.T) string {
	t.Helper()
	dir := tempDir(t)
	s := initState(t, dir, "goal", 0)
	s.PMMode = true
	s.Plan = &pm.Plan{Goal: "goal", Tasks: []*pm.Task{
		{ID: 1, Title: "Build the thing", Priority: 1, Status: pm.TaskPending},
		{ID: 2, Title: "Test the thing", Priority: 2, Status: pm.TaskPending, DependsOn: []int{1}},
	}}
	if err := s.Save(); err != nil {
		t.Fatalf("save plan: %v", err)
	}
	return dir
}

func loadPlan(t *testing.T, dir string) *state.ProjectState {
	t.Helper()
	st, err := state.Load(dir)
	if err != nil {
		t.Fatalf("state.Load: %v", err)
	}
	return st
}

func taskByID(t *testing.T, st *state.ProjectState, id int) *pm.Task {
	t.Helper()
	for _, task := range st.Plan.Tasks {
		if task.ID == id {
			return task
		}
	}
	t.Fatalf("task %d not in plan", id)
	return nil
}

// assertInterrupted checks everything a stop must leave behind for one task:
// pending, not failed, with the reason in its notes and the event journal.
func assertInterrupted(t *testing.T, dir string, st *state.ProjectState, id int, stage string) {
	t.Helper()
	task := taskByID(t, st, id)
	if task.Status != pm.TaskPending {
		t.Fatalf("task %d status = %s after the run was stopped, want pending — the next run would not pick it up",
			id, task.Status)
	}
	if task.FailCount != 0 {
		t.Errorf("task %d fail_count = %d, want 0 — a stop is not a failure", id, task.FailCount)
	}
	if task.CompletedAt != nil {
		t.Errorf("task %d has completed_at set after an interrupted execution", id)
	}
	if !hasAnnotation(task, "Interrupted "+stage) {
		var notes []string
		for _, a := range task.Annotations {
			notes = append(notes, a.Text)
		}
		t.Errorf("task %d carries no note saying it was interrupted %s; notes: %q", id, stage, notes)
	}
	if hasAnnotation(task, "Task failed") {
		t.Errorf("task %d was annotated as failed", id)
	}

	events, _, err := state.ListEvents(dir, 0, 200)
	if err != nil {
		t.Fatalf("list events: %v", err)
	}
	found := false
	for _, e := range events {
		if e.TaskID == id && e.Type == state.EventTaskInterrupted {
			found = true
		}
		if e.TaskID == id && (e.Type == state.EventTaskFailed || e.Type == state.EventTaskKilled) {
			t.Errorf("journal records task %d as %s: %s", id, e.Type, e.Message)
		}
	}
	if !found {
		t.Errorf("journal has no %s row for task %d", state.EventTaskInterrupted, id)
	}
}

func assertPausedByStop(t *testing.T, st *state.ProjectState) {
	t.Helper()
	if !st.PausedFor(pausereason.CodeCancelled) {
		reason := "<none>"
		if st.PauseReason != nil {
			reason = string(st.PauseReason.Code) + ": " + st.PauseReason.Detail
		}
		t.Errorf("project status = %q (reason %s), want paused for %q", st.Status, reason, pausereason.CodeCancelled)
	}
}

// resumeToCompletion runs the project again with a provider that finishes
// every task, and asserts the whole plan — including the task the stop
// interrupted and the one waiting on it — gets done.
func resumeToCompletion(t *testing.T, dir string, parallel bool) {
	t.Helper()
	prov := &safeProvider{name: "resume", output: "did the work\nTASK_DONE"}
	o := newOrchestrator(t, dir, Config{WorkDir: dir, PMMode: true, Parallel: parallel}, prov)
	if err := o.Run(context.Background()); err != nil {
		t.Fatalf("resumed run: %v", err)
	}
	st := loadPlan(t, dir)
	for _, task := range st.Plan.Tasks {
		if task.Status != pm.TaskDone {
			t.Errorf("after resuming, task %d is %s, want done", task.ID, task.Status)
		}
	}
}

// TestStopReturnsRunningTaskToPending is the reported bug: the task a stopped
// run was executing must be the one the next run picks up.
//
// Before the fix the sequential loop filed the cancellation as a provider
// error and marked the task failed. The resumed run then never started it,
// skipped the task depending on it, and reported the plan complete.
func TestStopReturnsRunningTaskToPending(t *testing.T) {
	dir := chainPlan(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	prov := &scriptedStopProvider{script: []string{stopHere}, stop: cancel}
	o := newOrchestrator(t, dir, Config{WorkDir: dir, PMMode: true}, prov)

	if err := o.Run(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("Run = %v, want context.Canceled", err)
	}

	st := loadPlan(t, dir)
	assertInterrupted(t, dir, st, 1, "while the agent was working on it")
	if got := taskByID(t, st, 2).Status; got != pm.TaskPending {
		t.Errorf("dependent task status = %s, want pending", got)
	}
	assertPausedByStop(t, st)

	resumeToCompletion(t, dir, false)
}

// TestSessionTimeoutReturnsTaskToPending: a --timeout expiring mid-task ends
// the run, not the task. The task context inherits the session deadline, so
// this used to read as a task timeout and leave the task timed_out — as
// terminal as failed.
func TestSessionTimeoutReturnsTaskToPending(t *testing.T) {
	dir := chainPlan(t)
	ctx := newSessionDeadline()
	defer ctx.expire()
	prov := &scriptedStopProvider{script: []string{stopHere}, stop: ctx.expire}
	o := newOrchestrator(t, dir, Config{WorkDir: dir, PMMode: true}, prov)

	if err := o.Run(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Run = %v, want context.DeadlineExceeded", err)
	}

	st := loadPlan(t, dir)
	assertInterrupted(t, dir, st, 1, "while the agent was working on it")
	assertPausedByStop(t, st)
}

// TestStopDuringHealReturnsTaskToPending: the agent reported TASK_FAILED and
// the run was stopped while auto-heal was diagnosing it. The failure is not
// the task's final word — the retries that would have decided it never ran —
// so it goes back to pending rather than staying failed.
func TestStopDuringHealReturnsTaskToPending(t *testing.T) {
	dir := chainPlan(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	prov := &scriptedStopProvider{
		// Call 1 is the task, call 2 the heal's failure diagnosis.
		script: []string{"could not get the build green\nTASK_FAILED", stopHere},
		stop:   cancel,
	}
	o := newOrchestrator(t, dir, Config{WorkDir: dir, PMMode: true}, prov)

	if err := o.Run(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("Run = %v, want context.Canceled", err)
	}

	st := loadPlan(t, dir)
	assertInterrupted(t, dir, st, 1, "during an auto-heal retry")
	if hasAnnotation(taskByID(t, st, 1), "[HEAL] Exhausted") {
		t.Error("an interrupted heal was recorded as exhausted")
	}
	assertPausedByStop(t, st)

	resumeToCompletion(t, dir, false)
}

// TestStopDuringClarificationReturnsTaskToPending: the agent asked questions
// instead of working, and the run was stopped during the re-prompt that would
// have answered them. Left alone, the fail-closed reroute would have marked
// the task failed for questions nobody got to answer.
func TestStopDuringClarificationReturnsTaskToPending(t *testing.T) {
	dir := chainPlan(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	prov := &scriptedStopProvider{
		script: []string{"Before I proceed: should I use Postgres or SQLite?", stopHere},
		stop:   cancel,
	}
	o := newOrchestrator(t, dir, Config{WorkDir: dir, PMMode: true}, prov)

	if err := o.Run(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("Run = %v, want context.Canceled", err)
	}

	st := loadPlan(t, dir)
	assertInterrupted(t, dir, st, 1, "while re-prompting after clarification questions")
	if hasAnnotation(taskByID(t, st, 1), "Clarification auto-resolve") {
		t.Error("an interrupted re-prompt was recorded as a clarification outcome")
	}
	assertPausedByStop(t, st)
}

// TestFinishedTaskKeepsItsOutcomeWhenStoppedAfterward: the stop only concerns
// the execution it interrupts. A task whose agent had already finished keeps
// its result, and the stop lands on the next task instead.
func TestFinishedTaskKeepsItsOutcomeWhenStoppedAfterward(t *testing.T) {
	dir := chainPlan(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	prov := &scriptedStopProvider{script: []string{"built it\nTASK_DONE", stopHere}, stop: cancel}
	o := newOrchestrator(t, dir, Config{WorkDir: dir, PMMode: true}, prov)

	if err := o.Run(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("Run = %v, want context.Canceled", err)
	}

	st := loadPlan(t, dir)
	if got := taskByID(t, st, 1).Status; got != pm.TaskDone {
		t.Errorf("task 1 status = %s, want done — a stop must not undo finished work", got)
	}
	assertInterrupted(t, dir, st, 2, "while the agent was working on it")
}

// TestStopReturnsParallelBatchToPending: a stop with a whole parallel batch in
// flight returns every task in it to pending. The parallel loop used to return
// the moment it saw the cancellation, leaving the batch in_progress — shown as
// running with nothing running it — until a later recovery pass noticed.
func TestStopReturnsParallelBatchToPending(t *testing.T) {
	dir := tempDir(t)
	s := initState(t, dir, "goal", 0)
	s.PMMode = true
	s.Plan = &pm.Plan{Goal: "goal", Tasks: []*pm.Task{
		{ID: 1, Title: "A", Priority: 1, Status: pm.TaskPending},
		{ID: 2, Title: "B", Priority: 1, Status: pm.TaskPending},
		{ID: 3, Title: "C", Priority: 2, Status: pm.TaskPending, DependsOn: []int{1, 2}},
	}}
	if err := s.Save(); err != nil {
		t.Fatalf("save plan: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	prov := &stopWhenAllStarted{n: 2, stop: cancel}
	o := newOrchestrator(t, dir, Config{WorkDir: dir, PMMode: true, Parallel: true}, prov)

	if err := o.Run(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("Run = %v, want context.Canceled", err)
	}

	st := loadPlan(t, dir)
	assertInterrupted(t, dir, st, 1, "while the agent was working on it")
	assertInterrupted(t, dir, st, 2, "while the agent was working on it")
	if got := taskByID(t, st, 3).Status; got != pm.TaskPending {
		t.Errorf("dependent task status = %s, want pending", got)
	}
	assertPausedByStop(t, st)

	resumeToCompletion(t, dir, true)
}

// TestParallelStopRequeuesTasksWhoseProviderIgnoresCancellation: when a
// provider does not honour the stop, the grace period ends the wait — and the
// tasks it abandons go back to pending instead of staying in_progress.
func TestParallelStopRequeuesTasksWhoseProviderIgnoresCancellation(t *testing.T) {
	prev := parallelShutdownGracePeriod
	parallelShutdownGracePeriod = 100 * time.Millisecond
	t.Cleanup(func() { parallelShutdownGracePeriod = prev })

	dir := tempDir(t)
	s := initState(t, dir, "goal", 0)
	s.PMMode = true
	s.Plan = &pm.Plan{Goal: "goal", Tasks: []*pm.Task{
		{ID: 1, Title: "A", Priority: 1, Status: pm.TaskPending},
		{ID: 2, Title: "B", Priority: 1, Status: pm.TaskPending},
	}}
	if err := s.Save(); err != nil {
		t.Fatalf("save plan: %v", err)
	}

	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	prov := &stopWhenAllStarted{n: 2, stop: cancel, ignore: release}
	o := newOrchestrator(t, dir, Config{WorkDir: dir, PMMode: true, Parallel: true}, prov)

	if err := o.Run(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("Run = %v, want context.Canceled", err)
	}

	st := loadPlan(t, dir)
	assertInterrupted(t, dir, st, 1, "while the agent was working on it")
	assertInterrupted(t, dir, st, 2, "while the agent was working on it")
	assertPausedByStop(t, st)
}

// TestTaskTimeoutIsStillATimeout guards the boundary the fix draws: only the
// run ending is an interruption. A task that overruns its own budget, in a
// run that carries on, is still judged timed out.
func TestTaskTimeoutIsStillATimeout(t *testing.T) {
	t.Cleanup(withTaskTimeoutUnit(50 * time.Millisecond))

	dir := tempDir(t)
	s := initState(t, dir, "goal", 0)
	s.PMMode = true
	s.Plan = &pm.Plan{Goal: "goal", Tasks: []*pm.Task{
		{ID: 1, Title: "slow", Priority: 1, Status: pm.TaskPending, MaxMinutes: 1},
	}}
	if err := s.Save(); err != nil {
		t.Fatalf("save plan: %v", err)
	}
	// Blocks until the task's own deadline; the run is never stopped.
	prov := &scriptedStopProvider{script: []string{stopHere}, stop: func() {}}
	o := newOrchestrator(t, dir, Config{WorkDir: dir, PMMode: true}, prov)

	_ = o.Run(context.Background())

	st := loadPlan(t, dir)
	if got := taskByID(t, st, 1).Status; got != pm.TaskTimedOut {
		t.Errorf("task status = %s, want timed_out — a task's own deadline is not a stop", got)
	}
}
