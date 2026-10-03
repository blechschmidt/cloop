// Tests for the persistence policy (Task 20362): a run must not report an
// outcome it never stored.
//
// The defect these pin down was not a crash. It was a run that printed a pause
// reason, set Paused in memory and returned nil — or marked a task done,
// journalled it and carried on — while the write underneath had failed and the
// database still said running or in progress. The operator saw one story, the
// next start acted on the other, and the task ran a second time.
//
// Each test fails the one write under examination and lets every other write
// through, so the run reaches the path being tested with everything before it
// genuinely stored. What is asserted is what a reader could be told: the run's
// returned error, the event journal, the activity queue, the stored status —
// and, for the abort itself, that the reason reaches all of them.
package orchestrator

import (
	"context"
	"encoding/json"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/logger"
	"github.com/blechschmidt/cloop/pkg/pausereason"
	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/provider"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/taskqueue"
)

// errSaveInjected is what the injected store returns. It is deliberately not
// ErrStateNotPersisted: the tests assert the orchestrator adds its own sentinel
// on the way out, not merely that some error propagated.
var errSaveInjected = errors.New("injected: database or disk is full")

// withFailingSave makes saveState fail for exactly the writes matching when,
// and perform the real write otherwise, until the test ends. The predicate
// sees the state as the orchestrator is about to write it, and how, which is
// how a test targets "the write that carries the pause" rather than "the
// fifth write". It reports how many writes it failed.
func withFailingSave(t *testing.T, when func(s *state.ProjectState, mode saveMode) bool) *int {
	t.Helper()
	failed := new(int)
	var mu sync.Mutex
	prev := saveState
	t.Cleanup(func() { saveState = prev })
	saveState = func(s *state.ProjectState, mode saveMode) error {
		if when(s, mode) {
			mu.Lock()
			*failed++
			mu.Unlock()
			return errSaveInjected
		}
		return prev(s, mode)
	}
	return failed
}

// hasTaskStatus reports whether any task in the state about to be written has
// one of the given statuses.
func hasTaskStatus(s *state.ProjectState, statuses ...pm.TaskStatus) bool {
	if s.Plan == nil {
		return false
	}
	for _, t := range s.Plan.Tasks {
		for _, st := range statuses {
			if t.Status == st {
				return true
			}
		}
	}
	return false
}

// persistFixture is a project of n pending tasks the stub provider completes,
// and the orchestrator for it.
func persistFixture(t *testing.T, parallel bool, n int, cfg Config) (*Orchestrator, string) {
	t.Helper()
	dir := tempDir(t)
	s := initState(t, dir, "persistence fixture", 0)
	s.PMMode = true
	s.Parallel = parallel
	s.Plan = pm.NewPlan(s.Goal)
	for i := 1; i <= n; i++ {
		s.Plan.Tasks = append(s.Plan.Tasks, &pm.Task{
			ID: i, Title: "task " + string(rune('A'-1+i)), Description: "do it", Priority: 1, Status: pm.TaskPending,
		})
	}
	if parallel {
		s.MaxParallel = 4
	}
	if err := s.Save(); err != nil {
		t.Fatalf("Save: %v", err)
	}
	cfg.WorkDir, cfg.PMMode = dir, true
	if parallel {
		cfg.Parallel, cfg.MaxParallel = true, 4
	}
	return newOrchestrator(t, dir, cfg, &gateDiffProvider{}), dir
}

// eachPath runs fn for both loops. They keep separate copies of every
// terminal branch, so a fix made in one and not the other is exactly the drift
// worth catching.
func eachPath(t *testing.T, fn func(t *testing.T, parallel bool)) {
	t.Helper()
	for _, parallel := range []bool{false, true} {
		name := "sequential"
		if parallel {
			name = "parallel"
		}
		t.Run(name, func(t *testing.T) { fn(t, parallel) })
	}
}

func runBounded(t *testing.T, o *Orchestrator) error {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	return o.Run(ctx)
}

// reload reads the state back from disk: the only thing that outlives the
// process, and so the only thing the next run will act on.
func reload(t *testing.T, dir string) *state.ProjectState {
	t.Helper()
	s, err := state.Load(dir)
	if err != nil {
		t.Fatalf("state.Load: %v", err)
	}
	return s
}

// journal returns the project's event rows, oldest first.
func journal(t *testing.T, dir string) []state.EventRow {
	t.Helper()
	rows, _, err := state.ListEvents(dir, 0, 500)
	if err != nil {
		t.Fatalf("ListEvents: %v", err)
	}
	for i, j := 0, len(rows)-1; i < j; i, j = i+1, j-1 {
		rows[i], rows[j] = rows[j], rows[i]
	}
	return rows
}

func journalRows(t *testing.T, dir string, typ state.EventType, taskID int) []state.EventRow {
	t.Helper()
	var out []state.EventRow
	for _, r := range journal(t, dir) {
		if r.Type == typ && (taskID == 0 || r.TaskID == taskID) {
			out = append(out, r)
		}
	}
	return out
}

// queueStatuses returns the activity-queue statuses recorded for a task.
func queueStatuses(t *testing.T, dir string, taskID int) []taskqueue.Status {
	t.Helper()
	q, err := taskqueue.Open(dir)
	if err != nil {
		t.Fatalf("taskqueue.Open: %v", err)
	}
	defer q.Close()
	entries, err := q.List(taskqueue.ListOptions{TaskID: taskID, Kind: taskqueue.KindTask})
	if err != nil {
		t.Fatalf("queue list: %v", err)
	}
	var out []taskqueue.Status
	for _, e := range entries {
		out = append(out, e.Status)
	}
	return out
}

// assertStoppedOnPersistence checks the error a run returns when a write it
// could not do without failed: identifiable, carrying its cause, naming what
// was lost.
func assertStoppedOnPersistence(t *testing.T, err error, mentions ...string) {
	t.Helper()
	if err == nil {
		t.Fatal("the run returned nil after a write it reports on failed: " +
			"the operator is told one thing while the database holds another")
	}
	if !errors.Is(err, ErrStateNotPersisted) {
		t.Fatalf("the error does not identify itself as a persistence failure: %v", err)
	}
	if !errors.Is(err, errSaveInjected) {
		t.Errorf("the error lost its cause: %v", err)
	}
	for _, m := range mentions {
		if !strings.Contains(err.Error(), m) {
			t.Errorf("the error does not name what was lost (want %q): %v", m, err)
		}
	}
}

// assertAbortRecorded checks that the stop reached the run status and the
// event journal — what the dashboard's badge, its Event History and `cloop
// status` show.
func assertAbortRecorded(t *testing.T, dir string, detailMentions string) {
	t.Helper()
	got := reload(t, dir)
	if got.Status != "paused" || got.PauseReason == nil || got.PauseReason.Code != pausereason.CodeStateNotPersisted {
		t.Fatalf("stored status = %q, reason = %+v; want paused for state_not_persisted", got.Status, got.PauseReason)
	}
	if !strings.Contains(got.PauseReason.Detail, detailMentions) || !strings.Contains(got.PauseReason.Detail, "disk is full") {
		t.Errorf("pause detail %q does not say what was lost (%q) and why", got.PauseReason.Detail, detailMentions)
	}
	rows := journalRows(t, dir, state.EventSessionFailed, 0)
	if len(rows) != 1 {
		t.Fatalf("session_failed rows = %d, want the one the stop wrote", len(rows))
	}
	var details map[string]any
	if err := json.Unmarshal([]byte(rows[0].Details), &details); err != nil {
		t.Fatalf("session_failed details: %v", err)
	}
	if details["cause"] != string(pausereason.CodeStateNotPersisted) || details["status_recorded"] != true {
		t.Errorf("session_failed details = %v", details)
	}
	if !strings.Contains(rows[0].Message, detailMentions) {
		t.Errorf("session_failed message %q does not say what was lost (%q)", rows[0].Message, detailMentions)
	}
}

// A task's outcome that did not reach the database must not be announced:
// not in the journal, not in the activity queue — and the run must stop, so
// it does not go on to execute work it can no longer account for.
func TestRun_DoesNotReportATaskOutcomeItDidNotStore(t *testing.T) {
	eachPath(t, func(t *testing.T, parallel bool) {
		o, dir := persistFixture(t, parallel, 1, Config{})
		failed := withFailingSave(t, func(s *state.ProjectState, mode saveMode) bool {
			return mode == mergeExternal && hasTaskStatus(s, pm.TaskDone, pm.TaskFailed, pm.TaskSkipped)
		})

		err := runBounded(t, o)
		assertStoppedOnPersistence(t, err, "task #1", "completion")
		if *failed != 1 {
			t.Errorf("the injected store failed %d writes, want exactly the outcome's", *failed)
		}

		task := reload(t, dir).Plan.TaskByID(1)
		if task.Status != pm.TaskInProgress {
			t.Fatalf("stored status = %q: the start should be stored and the outcome not — "+
				"otherwise the test is not exercising the path it claims to", task.Status)
		}
		if rows := journalRows(t, dir, state.EventTaskStarted, 1); len(rows) != 1 {
			t.Errorf("task_started rows = %d, want 1 (the start was stored, so it may be announced)", len(rows))
		}
		if rows := journalRows(t, dir, state.EventTaskDone, 1); len(rows) != 0 {
			t.Errorf("the journal announces task #1 done although the database never held it: %+v", rows)
		}
		for _, st := range queueStatuses(t, dir, 1) {
			if st == taskqueue.StatusDone {
				t.Error("the activity queue shows task #1 done although the database never held it")
			}
		}
		assertAbortRecorded(t, dir, "task #1")
	})
}

// A pause that did not reach the database must not be reported as one: the
// run's nil return is what told a caller it had paused cleanly.
func TestRun_DoesNotReportAPauseItDidNotStore(t *testing.T) {
	eachPath(t, func(t *testing.T, parallel bool) {
		o, dir := persistFixture(t, parallel, 2, Config{StepsLimit: 1})
		failed := withFailingSave(t, func(s *state.ProjectState, mode saveMode) bool {
			return mode == mergeExternal && s.PausedFor(pausereason.CodeStepLimit)
		})

		err := runBounded(t, o)
		assertStoppedOnPersistence(t, err, "pause", "--steps limit")
		if *failed != 1 {
			t.Errorf("the injected store failed %d writes, want exactly the pause's", *failed)
		}

		got := reload(t, dir)
		if got.PausedFor(pausereason.CodeStepLimit) {
			t.Fatal("the step-limit pause is stored: the write was supposed to fail")
		}
		// The work before the pause was stored and announced as usual.
		if task := got.Plan.TaskByID(1); task.Status != pm.TaskDone {
			t.Errorf("task #1 = %q, want done: only the pause's write was failed", task.Status)
		}
		assertAbortRecorded(t, dir, "--steps limit")
	})
}

// "complete" is the other terminal report a run makes, and the sequential loop
// journals plan_complete on the strength of it.
func TestRun_DoesNotReportCompletionItDidNotStore(t *testing.T) {
	eachPath(t, func(t *testing.T, parallel bool) {
		o, dir := persistFixture(t, parallel, 1, Config{})
		withFailingSave(t, func(s *state.ProjectState, mode saveMode) bool {
			return mode == mergeExternal && s.Status == "complete"
		})

		err := runBounded(t, o)
		assertStoppedOnPersistence(t, err, "complete")
		if rows := journalRows(t, dir, state.EventPlanComplete, 0); len(rows) != 0 {
			t.Errorf("plan_complete was journalled although the run's completion was never stored: %+v", rows)
		}
		assertAbortRecorded(t, dir, "complete")
	})
}

// The positive control for the three tests above: without it, a change that
// made every run fail would satisfy them.
func TestRun_StoresWhatItReports(t *testing.T) {
	eachPath(t, func(t *testing.T, parallel bool) {
		o, dir := persistFixture(t, parallel, 1, Config{})
		if err := runBounded(t, o); err != nil {
			t.Fatalf("Run: %v", err)
		}
		got := reload(t, dir)
		if got.Status != "complete" {
			t.Errorf("stored status = %q, want complete", got.Status)
		}
		if task := got.Plan.TaskByID(1); task.Status != pm.TaskDone {
			t.Errorf("stored task status = %q, want done", task.Status)
		}
		if rows := journalRows(t, dir, state.EventTaskDone, 1); len(rows) != 1 {
			t.Errorf("task_done rows = %d, want 1", len(rows))
		}
		if st := queueStatuses(t, dir, 1); len(st) != 1 || st[0] != taskqueue.StatusDone {
			t.Errorf("queue statuses = %v, want one done entry", st)
		}
		if rows := journalRows(t, dir, state.EventSessionFailed, 0); len(rows) != 0 {
			t.Errorf("a clean run journalled a failure: %+v", rows)
		}
	})
}

// The other side of the triage: a write classified best-effort carries state
// the run can do without, so losing it must not stop the run — otherwise the
// fix trades silent divergence for runs that die on a display state.
//
// The evolving status, and an evolve round's bookkeeping, are written while
// the run's status reads "evolving"; the stub's answer to the discovery prompt
// parses to nothing, so the run evolves three times and then completes.
func TestPersistBestEffort_DoesNotStopTheRun(t *testing.T) {
	eachPath(t, func(t *testing.T, parallel bool) {
		o, dir := persistFixture(t, parallel, 1, Config{NoDedup: true})
		if err := o.SetAutoEvolve(true); err != nil {
			t.Fatalf("SetAutoEvolve: %v", err)
		}
		failed := withFailingSave(t, func(s *state.ProjectState, mode saveMode) bool {
			return s.Status == "evolving"
		})

		if err := runBounded(t, o); err != nil {
			t.Fatalf("a best-effort write failure stopped the run: %v", err)
		}
		if *failed == 0 {
			t.Fatal("no best-effort write was failed; the test proves nothing")
		}
		got := reload(t, dir)
		if got.Status != "complete" {
			t.Errorf("stored status = %q, want complete — the run should have finished as usual", got.Status)
		}
		if task := got.Plan.TaskByID(1); task.Status != pm.TaskDone {
			t.Errorf("stored task status = %q, want done", task.Status)
		}
	})
}

// When the database takes nothing — not even the run's own account of why it
// stopped — the run still stops, says so, and leaves the journal row the
// dashboard can show beside the hub's own reconciliation.
func TestRun_StopsEvenWhenTheStopCannotBeRecorded(t *testing.T) {
	o, dir := persistFixture(t, false, 1, Config{})
	withFailingSave(t, func(s *state.ProjectState, mode saveMode) bool {
		return mode == statusOnly || hasTaskStatus(s, pm.TaskDone)
	})

	err := runBounded(t, o)
	assertStoppedOnPersistence(t, err, "task #1")
	if got := reload(t, dir); got.Status != "running" {
		t.Errorf("stored status = %q, want the last status that did land (running)", got.Status)
	}
	rows := journalRows(t, dir, state.EventSessionFailed, 0)
	if len(rows) != 1 || !strings.Contains(rows[0].Details, `"status_recorded":false`) {
		t.Errorf("session_failed rows = %+v, want one saying the status was not recorded", rows)
	}
}

// A run that leaves its round early must not leave its other workers running:
// what they finish can no longer be recorded, and nothing of the round may
// still touch the state while the run records why it stopped.
func TestParallel_StoppingOnAFailedWriteStopsTheRestOfTheRound(t *testing.T) {
	prev := parallelShutdownGracePeriod
	parallelShutdownGracePeriod = 20 * time.Second
	t.Cleanup(func() { parallelShutdownGracePeriod = prev })

	dir := tempDir(t)
	s := initState(t, dir, "round", 0)
	s.PMMode, s.Parallel, s.MaxParallel = true, true, 4
	s.Plan = pm.NewPlan(s.Goal)
	s.Plan.Tasks = []*pm.Task{
		{ID: 1, Title: "fast", Description: "finishes", Priority: 1, Status: pm.TaskPending},
		{ID: 2, Title: "slow", Description: "blocks", Priority: 1, Status: pm.TaskPending},
	}
	if err := s.Save(); err != nil {
		t.Fatal(err)
	}
	prov := &roundProvider{slowCancelled: make(chan struct{})}
	o := newOrchestrator(t, dir, Config{WorkDir: dir, PMMode: true, Parallel: true, MaxParallel: 4}, prov)
	withFailingSave(t, func(s *state.ProjectState, mode saveMode) bool {
		return mode == mergeExternal && s.Plan.TaskByID(1).Status == pm.TaskDone
	})

	start := time.Now()
	err := runBounded(t, o)
	assertStoppedOnPersistence(t, err, "task #1")
	select {
	case <-prov.slowCancelled:
	default:
		t.Fatal("the slow task's worker was never cancelled: the run left it running")
	}
	if took := time.Since(start); took >= parallelShutdownGracePeriod {
		t.Errorf("the run took %s to stop, the whole grace period: the round was waited out, not stopped", took)
	}
}

// roundProvider finishes task 1 at once and blocks task 2 until its context
// is cancelled.
type roundProvider struct {
	slowCancelled chan struct{}
	once          sync.Once
}

func (p *roundProvider) Complete(ctx context.Context, prompt string, _ provider.Options) (*provider.Result, error) {
	if strings.Contains(prompt, "**Task 2: ") {
		<-ctx.Done()
		p.once.Do(func() { close(p.slowCancelled) })
		return nil, ctx.Err()
	}
	return &provider.Result{Output: "Made the change.\nTASK_DONE", Provider: "round"}, nil
}
func (p *roundProvider) Name() string         { return "round" }
func (p *roundProvider) DefaultModel() string { return "round-model" }

// The kill poller cannot stop the run, but it must not clear the operator's
// request before the status it carries is stored: a row cleared first is the
// operator's decision silently undone. It tries again on the next tick.
func TestKillPoller_KeepsTheRequestUntilTheChosenStatusIsStored(t *testing.T) {
	o := newTestOrchestrator(t)
	_, task := addInProgressTask(t, o, 7, "killed")
	requestKill(t, o, task, "skipped")
	o.processPendingKills() // phase 1: observed running, cancel fired
	drainWorker(task)       // the worker records its own terminal status

	failing := true
	prev := saveState
	t.Cleanup(func() { saveState = prev })
	saveState = func(s *state.ProjectState, mode saveMode) error {
		if failing {
			return errSaveInjected
		}
		return prev(s, mode)
	}

	o.processPendingKills()
	if rows, _ := o.statedb.PendingKills(); len(rows) != 1 {
		t.Fatalf("pending kill rows = %d after a failed write, want the request kept", len(rows))
	}

	failing = false
	o.processPendingKills()
	if rows, _ := o.statedb.PendingKills(); len(rows) != 0 {
		t.Fatalf("pending kill rows = %d once the write landed, want the request cleared", len(rows))
	}
	if got := reload(t, o.config.WorkDir).Plan.TaskByID(7); got.Status != pm.TaskSkipped {
		t.Errorf("stored status = %q, want the operator's skipped", got.Status)
	}
}

// The message is what an operator acts on. A bare SQLite error does not say
// which task will run again.
func TestPersistFailure_NamesWhatWasLost(t *testing.T) {
	o := &Orchestrator{log: logger.NewWithWriter(nil, false)}
	s := &state.ProjectState{}
	prev := saveState
	t.Cleanup(func() { saveState = prev })
	saveState = func(*state.ProjectState, saveMode) error { return errSaveInjected }

	err := o.persistOutcome(s, &pm.Task{ID: 42, Status: pm.TaskFailed}, "failure (provider error)", agentWhy(pm.TaskFailed))
	if err == nil {
		t.Fatal("persistOutcome returned nil on a failing store")
	}
	for _, want := range []string{"task #42's failure (provider error)", "status failed", "disk is full", "stopping the run"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("message %q does not contain %q", err.Error(), want)
		}
	}
	if !errors.Is(err, ErrStateNotPersisted) || !errors.Is(err, errSaveInjected) {
		t.Errorf("error is not matchable against both: %v", err)
	}

	// persist covers state that is not one task's; it must not invent one.
	err = o.persist(s, "the pause (token budget reached)")
	if err == nil || strings.Contains(err.Error(), "task #") || !strings.Contains(err.Error(), "token budget") {
		t.Errorf("persist error = %v", err)
	}

	// A best-effort failure is reported, not returned, and does not claim to
	// stop the run.
	o.persistBestEffort(s, "a priority boost", "the deadline check recomputes it")
	pf := &persistFailure{what: "a priority boost", why: "the deadline check recomputes it", err: errSaveInjected}
	if errors.Is(pf, ErrStateNotPersisted) {
		t.Error("a tolerated failure matches ErrStateNotPersisted: a caller could mistake it for one that stops the run")
	}
	if msg := pf.Error(); !strings.Contains(msg, "carrying on") || !strings.Contains(msg, "recomputes it") {
		t.Errorf("best-effort message %q does not say the run carries on, and why", msg)
	}
}

// SetAutoEvolve on a project that already has a plan used to write the stored
// setting straight back: the merging write copies the stored toggles over the
// ones in memory before it saves, so `cloop run --auto-evolve` never switched
// auto-evolve on for a project that had tasks.
func TestSetAutoEvolve_SurvivesTheMergeWithAStoredPlan(t *testing.T) {
	dir := tempDir(t)
	s := initState(t, dir, "goal", 0)
	s.Plan = pm.NewPlan(s.Goal)
	s.Plan.Tasks = []*pm.Task{{ID: 1, Title: "t", Status: pm.TaskPending, Priority: 1}}
	if err := s.Save(); err != nil {
		t.Fatal(err)
	}
	o := newOrchestrator(t, dir, Config{WorkDir: dir}, &mockProvider{name: "mock"})
	if err := o.SetAutoEvolve(true); err != nil {
		t.Fatalf("SetAutoEvolve: %v", err)
	}
	if !reload(t, dir).AutoEvolve {
		t.Fatal("auto-evolve is off on disk after SetAutoEvolve(true)")
	}
	// And a sync — what the loop does at every iteration — keeps it.
	o.state.SyncFromDisk()
	if !o.state.AutoEvolve {
		t.Error("the loop's first sync switched auto-evolve back off")
	}
}

// TestNoBareSaveCallsInOrchestrator keeps the triage from decaying.
//
// The whole defect class was invisible because a Save whose error is thrown
// away — `s.Save()` as a statement, or `_ = s.Save()` — is legal Go that go
// vet does not flag, so a new one reads exactly like the hundred-odd that were
// wrong. The same goes for the activity queue's Mark calls. Every state write
// in this package goes through persist, persistOutcome or persistBestEffort,
// and every queue write through the queue* helpers, which report a failure.
func TestNoBareSaveCallsInOrchestrator(t *testing.T) {
	// The detector itself, against code that holds each shape: a gate that
	// finds nothing in a clean package must also be shown to find something.
	const fixture = `package x
func f(s *S, o *O) error {
	s.Save()
	_ = s.SaveDirect()
	o.queue.MarkDone(1, "x")
	_ = o.queue.MarkFailed(1, "y")
	if err := s.Save(); err != nil { return err }
	return s.SaveDirect()
}`
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "fixture.go", fixture, 0)
	if err != nil {
		t.Fatal(err)
	}
	if got := discardedWrites(fset, f); len(got) != 4 {
		t.Fatalf("the detector found %d discarded writes in the fixture, want 4: %v", len(got), got)
	}

	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	var offenders []string
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, filepath.Join(".", name), nil, 0)
		if err != nil {
			t.Fatalf("parsing %s: %v", name, err)
		}
		offenders = append(offenders, discardedWrites(fset, f)...)
	}
	if len(offenders) > 0 {
		t.Errorf("a state or queue write's error is thrown away at:\n  %s\n\n"+
			"Write state through o.persist or o.persistOutcome when the run reports or returns on it, "+
			"or o.persistBestEffort with the reason losing it is safe; write the activity queue through "+
			"o.queueRunning/queueDone/queueFailed/queueSkipped (see persist.go).",
			strings.Join(offenders, "\n  "))
	}
}

// discardedWrites returns the positions of every Save, SaveDirect or
// SaveRunStatus call, and every Mark call on a field named queue, whose error
// is thrown away: used as a statement, or assigned only to blanks.
func discardedWrites(fset *token.FileSet, f *ast.File) []string {
	isWrite := func(e ast.Expr) bool {
		call, ok := e.(*ast.CallExpr)
		if !ok {
			return false
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return false
		}
		switch name := sel.Sel.Name; {
		case name == "Save" || name == "SaveDirect" || name == "SaveRunStatus":
			return true
		case strings.HasPrefix(name, "Mark"):
			recv, ok := sel.X.(*ast.SelectorExpr)
			return ok && recv.Sel.Name == "queue"
		}
		return false
	}
	var out []string
	ast.Inspect(f, func(n ast.Node) bool {
		switch st := n.(type) {
		case *ast.ExprStmt:
			if isWrite(st.X) {
				out = append(out, fset.Position(st.Pos()).String())
			}
		case *ast.AssignStmt:
			blanks := true
			for _, l := range st.Lhs {
				if id, ok := l.(*ast.Ident); !ok || id.Name != "_" {
					blanks = false
				}
			}
			if blanks && len(st.Rhs) == 1 && isWrite(st.Rhs[0]) {
				out = append(out, fset.Position(st.Pos()).String())
			}
		}
		return true
	})
	return out
}
