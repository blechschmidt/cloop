package orchestrator

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/provider"
	"github.com/blechschmidt/cloop/pkg/state"
)

// evolveMarker is the opening line of pm.EvolveDiscoverPrompt. Its presence in
// a prompt is how these tests tell an evolve round from ordinary task work —
// the distinction the whole sweep exists to enforce.
const evolveMarker = "AUTO-EVOLVE mode"

// recordingProvider keeps every prompt it was asked to complete so a test can
// assert on what the orchestrator *did not* ask for.
type recordingProvider struct {
	mu      sync.Mutex
	name    string
	results []*provider.Result
	prompts []string
	calls   int
}

func (r *recordingProvider) Complete(_ context.Context, prompt string, _ provider.Options) (*provider.Result, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.prompts = append(r.prompts, prompt)
	i := r.calls
	r.calls++
	if i < len(r.results) {
		return r.results[i], nil
	}
	return &provider.Result{Output: "default output", Provider: r.name}, nil
}

func (r *recordingProvider) Name() string         { return r.name }
func (r *recordingProvider) DefaultModel() string { return "mock-model" }

func (r *recordingProvider) callCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.calls
}

func (r *recordingProvider) evolvePrompts() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	for _, p := range r.prompts {
		if strings.Contains(p, evolveMarker) {
			n++
		}
	}
	return n
}

// ledgerPlan builds a one-task plan whose single task is recorded as done with
// the given stored summary — the shape of this project's own tasks 193–197.
func ledgerPlan(summary string) *pm.Plan {
	completed := time.Now().Add(-time.Hour)
	return &pm.Plan{
		Goal: "goal",
		Tasks: []*pm.Task{{
			ID:            1,
			Title:         "Task A",
			Priority:      1,
			Status:        pm.TaskDone,
			Result:        summary,
			CompletedAt:   &completed,
			ActualMinutes: 7,
		}},
	}
}

func hasAnnotation(task *pm.Task, needle string) bool {
	for _, a := range task.Annotations {
		if strings.Contains(a.Text, needle) {
			return true
		}
	}
	return false
}

// TestRunPM_LedgerRefusal_BlocksCompletionAndEvolve is the regression test for
// Task 20224.
//
// The plan's only task is recorded as done, so before this fix the loop found
// nothing pending, declared the plan complete, and — with auto-evolve on —
// immediately asked the provider to discover more work to build on top of it.
// The "work" it was building on was the string "You've hit your limit". That is
// how features 194, 195 and 196 stayed missing from the tree for roughly a
// hundred iterations.
//
// The plan must not be reported complete and no evolve round may be issued.
func TestRunPM_LedgerRefusal_BlocksCompletionAndEvolve(t *testing.T) {
	for _, tt := range []struct {
		name      string
		summary   string
		wantClass AbortClass
	}{
		{"usage limit", limitResetAfternoon, AbortUsageLimit},
		{"weekly limit", weeklyLimitDated, AbortUsageLimit},
		{"org monthly quota", orgMonthlyQuota, AbortQuotaExceeded},
		{"harness refused under root", harnessRootRefusal, AbortHarnessRefusal},
	} {
		t.Run(tt.name, func(t *testing.T) {
			dir := tempDir(t)
			s := initState(t, dir, "goal", 0)
			s.PMMode = true
			s.AutoEvolve = true
			s.Plan = ledgerPlan(tt.summary)
			s.Save()

			// The reopened task is re-run and refuses again with a hard quota,
			// which is not retryable — so the run pauses instead of spinning,
			// with no dependence on the wall clock.
			prov := &recordingProvider{
				name:    "mock",
				results: []*provider.Result{{Output: orgMonthlyQuota, Provider: "mock"}},
			}
			o := newOrchestrator(t, dir, Config{WorkDir: dir, PMMode: true, NoHeal: true}, prov)
			o.testAbortWaitCeiling = time.Nanosecond

			if err := o.runPM(context.Background()); err != nil {
				t.Fatalf("runPM: %v", err)
			}

			// The headline guarantee.
			if n := prov.evolvePrompts(); n != 0 {
				t.Errorf("auto-evolve ran %d discovery round(s) on top of a task that never ran", n)
			}
			if o.state.Status == "complete" {
				t.Error("session reported complete; a plan may not finish on the strength of an error message")
			}
			if o.state.Plan.IsComplete() {
				t.Error("Plan.IsComplete() is true although its only task never ran")
			}

			task := o.state.Plan.Tasks[0]
			if task.Status == pm.TaskDone {
				t.Fatalf("task is still DONE with summary %q — the ledger sweep did not reopen it", tt.summary)
			}
			if task.Status != pm.TaskPending {
				t.Errorf("status = %q, want %q: the task never ran, so it is retryable", task.Status, pm.TaskPending)
			}
			if task.CompletedAt != nil || task.ActualMinutes != 0 {
				t.Error("CompletedAt/ActualMinutes must be cleared — nothing completed")
			}
			if !hasAnnotation(task, "Reopened by the ledger sweep") {
				t.Errorf("no sweep annotation recorded; annotations = %+v", task.Annotations)
			}

			// The classification must be persisted rather than left to be
			// re-derived from prose by whoever asks next.
			if task.Abort == nil {
				t.Fatal("no abort record persisted on the task")
			}
			if task.Abort.Class != string(tt.wantClass) {
				t.Errorf("abort class = %q, want %q", task.Abort.Class, tt.wantClass)
			}
			if task.Abort.Evidence == "" {
				t.Error("abort record carries no evidence excerpt")
			}
			if task.Abort.SummaryFingerprint != pm.FingerprintSummary(tt.summary) {
				t.Error("abort record is not bound to the summary it describes")
			}

			// And the reason has to reach the journal under its own type.
			events := abortEventsFor(t, dir, 1)
			if len(events) == 0 {
				t.Fatal("no task_aborted event journalled for the sweep")
			}
			var sawSweep bool
			for _, e := range events {
				if strings.Contains(e.Details, "ledger-sweep") {
					sawSweep = true
				}
			}
			if !sawSweep {
				t.Errorf("no event attributes the reopen to the ledger sweep; events = %+v", events)
			}
		})
	}
}

// TestRunPM_ClearedLedgerRefusal_CountsAsComplete is the other half of the
// contract. Nine of this project's fourteen corrupted entries were quietly
// re-implemented by later tasks: the refusal summary is genuine but the work
// exists. Triage records that verdict on the task, and from then on the entry
// stays visible without reopening finished work.
//
// This also pins the persistence requirement. A cleared record only survives if
// the sweep *reuses* it; re-deriving the classification from the summary each
// time would rediscover the refusal, lose the verdict, and reopen the task on
// every single iteration.
func TestRunPM_ClearedLedgerRefusal_CountsAsComplete(t *testing.T) {
	dir := tempDir(t)
	s := initState(t, dir, "goal", 0)
	s.PMMode = true
	s.Plan = ledgerPlan(limitResetAfternoon)
	s.Plan.Tasks[0].Abort = &pm.TaskAbort{
		Class:              string(AbortUsageLimit),
		Reason:             "subscription limit reached",
		Evidence:           limitResetAfternoon,
		DetectedAt:         time.Now().UTC(),
		SummaryFingerprint: pm.FingerprintSummary(limitResetAfternoon),
	}
	s.Plan.Tasks[0].Abort.Clear("triage", "re-landed by Task 9999")
	s.Save()

	prov := &recordingProvider{name: "mock"}
	o := newOrchestrator(t, dir, Config{WorkDir: dir, PMMode: true, NoHeal: true}, prov)

	if err := o.runPM(context.Background()); err != nil {
		t.Fatalf("runPM: %v", err)
	}

	if got := o.state.Plan.Tasks[0].Status; got != pm.TaskDone {
		t.Errorf("status = %q, want %q: a cleared record must not reopen the task", got, pm.TaskDone)
	}
	if o.state.Status != "complete" {
		t.Errorf("session status = %q, want complete", o.state.Status)
	}
	if n := prov.callCount(); n != 0 {
		t.Errorf("provider called %d times; a cleared plan has no work left to do", n)
	}
	// The record stays — the ledger entry is still wrong, and a reader of
	// project history deserves to see why it was allowed to stand.
	rec := o.state.Plan.Tasks[0].Abort
	if rec == nil {
		t.Fatal("cleared abort record was discarded; the bad ledger entry is invisible again")
	}
	if !rec.Cleared || rec.ClearedNote == "" {
		t.Errorf("clearance did not survive the sweep: %+v", rec)
	}
}

// TestSweepAbortedOutcomes_StaleRecordDropped covers the self-healing edge: a
// reopened task that runs again and produces real work must shed its record,
// verdict and all. The digest is what detects this — the summary it described
// no longer exists.
func TestSweepAbortedOutcomes_StaleRecordDropped(t *testing.T) {
	dir := tempDir(t)
	s := initState(t, dir, "goal", 0)
	s.PMMode = true
	s.Plan = ledgerPlan("Implemented the feature and added tests.")
	s.Plan.Tasks[0].Abort = &pm.TaskAbort{
		Class:              string(AbortUsageLimit),
		Reason:             "subscription limit reached",
		SummaryFingerprint: pm.FingerprintSummary(limitResetAfternoon), // the *old* summary
	}
	s.Save()

	o := newOrchestrator(t, dir, Config{WorkDir: dir, PMMode: true}, &recordingProvider{name: "mock"})
	if n := o.sweepAbortedOutcomes(s); n != 0 {
		t.Fatalf("sweep reopened %d task(s); the task carries real work now", n)
	}
	if s.Plan.Tasks[0].Abort != nil {
		t.Error("stale abort record survived a summary that is no longer a refusal")
	}
	if s.Plan.Tasks[0].Status != pm.TaskDone {
		t.Errorf("status = %q, want done", s.Plan.Tasks[0].Status)
	}
}

// TestSweepAbortedOutcomes_LeavesGenuineWorkAlone guards the expensive failure
// mode in the other direction: a sweep that reopens finished work would undo
// hundreds of completed tasks. An empty summary is the case that matters —
// dozens of this project's genuinely-shipped tasks have one, so absence of
// evidence must never be treated as evidence of absence.
func TestSweepAbortedOutcomes_LeavesGenuineWorkAlone(t *testing.T) {
	for _, tt := range []struct {
		name    string
		summary string
	}{
		{"empty summary", ""},
		{"whitespace summary", "   \n\t "},
		{"ordinary work", "Added pkg/foo and wired it into cmd/root.go.\n\nTASK_DONE"},
		// A completed task is allowed to *discuss* rate limits; several in
		// this project do. Only a refusal that is the whole response counts.
		{"task about rate limits", "Implemented rate limit handling: on 429 the client now backs off.\nTASK_DONE"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			dir := tempDir(t)
			s := initState(t, dir, "goal", 0)
			s.PMMode = true
			s.Plan = ledgerPlan(tt.summary)
			s.Save()

			o := newOrchestrator(t, dir, Config{WorkDir: dir, PMMode: true}, &recordingProvider{name: "mock"})
			if n := o.sweepAbortedOutcomes(s); n != 0 {
				t.Fatalf("sweep reopened %d genuinely-completed task(s)", n)
			}
			if got := s.Plan.Tasks[0].Status; got != pm.TaskDone {
				t.Errorf("status = %q, want done", got)
			}
			if s.Plan.Tasks[0].Abort != nil {
				t.Errorf("abort record invented for a non-refusal summary: %+v", s.Plan.Tasks[0].Abort)
			}
		})
	}
}

// TestSweepAbortedOutcomes_SurvivesReload pins requirement (b): the finding is
// persisted on the task, so it is still there — with its evidence — after the
// state has been written and read back.
func TestSweepAbortedOutcomes_SurvivesReload(t *testing.T) {
	dir := tempDir(t)
	s := initState(t, dir, "goal", 0)
	s.PMMode = true
	s.Plan = ledgerPlan(limitResetAfternoon)
	s.Save()

	o := newOrchestrator(t, dir, Config{WorkDir: dir, PMMode: true}, &recordingProvider{name: "mock"})
	if n := o.sweepAbortedOutcomes(s); n != 1 {
		t.Fatalf("sweep reopened %d task(s), want 1", n)
	}

	reloaded, err := state.Load(dir)
	if err != nil {
		t.Fatalf("state.Load: %v", err)
	}
	task := reloaded.Plan.TaskByID(1)
	if task == nil {
		t.Fatal("task 1 missing after reload")
	}
	if task.Status != pm.TaskPending {
		t.Errorf("status = %q after reload, want pending", task.Status)
	}
	if task.Abort == nil {
		t.Fatal("abort record did not survive the reload")
	}
	if task.Abort.Class != string(AbortUsageLimit) || task.Abort.Evidence == "" {
		t.Errorf("abort record lost detail across the reload: %+v", task.Abort)
	}
}
