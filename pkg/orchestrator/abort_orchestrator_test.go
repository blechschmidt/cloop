package orchestrator

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/provider"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// abortEventsFor returns the task_aborted rows the run journalled for a task.
func abortEventsFor(t *testing.T, dir string, taskID int) []statedb.EventRow {
	t.Helper()
	rows, _, err := state.ListEvents(dir, 0, 500)
	if err != nil {
		t.Fatalf("reading events: %v", err)
	}
	var out []statedb.EventRow
	for _, r := range rows {
		if r.Type == state.EventTaskAborted && r.TaskID == taskID {
			out = append(out, r)
		}
	}
	return out
}

// mustWriteEmptyArtifact creates a zero-byte artifact file and returns its path.
func mustWriteEmptyArtifact(t *testing.T, dir string) string {
	t.Helper()
	tasksDir := filepath.Join(dir, ".cloop", "tasks")
	if err := os.MkdirAll(tasksDir, 0o755); err != nil {
		t.Fatalf("mkdir artifacts: %v", err)
	}
	p := filepath.Join(tasksDir, "1-task-a.md")
	if err := os.WriteFile(p, nil, 0o644); err != nil {
		t.Fatalf("writing zero-byte artifact: %v", err)
	}
	return p
}

// TestRunPM_AbortedAgent_LeavesTaskPending is the regression test for the bug
// that corrupted this project's own ledger: five tasks in a row (193–197) were
// recorded as done whose entire stored summary was "You've hit your limit".
// The agent process exited, the output carried no TASK_* signal, and the
// `default:` arm of the signal switch promoted it to done.
//
// The task must come back pending — not done, and not failed either: it never
// ran, so it is retryable rather than judged.
func TestRunPM_AbortedAgent_LeavesTaskPending(t *testing.T) {
	tests := []struct {
		name      string
		output    string
		wantClass AbortClass
	}{
		// Only clock-independent messages belong here: a dated reset like
		// weeklyLimitDated lands in the past or the future depending on when
		// the suite runs, so its parsing is pinned in TestParseResetTime with
		// an injected clock instead.
		{"usage limit with reset", limitResetAfternoon, AbortUsageLimit},
		{"org monthly quota", orgMonthlyQuota, AbortQuotaExceeded},
		{"harness refused under root", harnessRootRefusal, AbortHarnessRefusal},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := tempDir(t)
			s := initState(t, dir, "goal", 0)
			s.PMMode = true
			s.Plan = &pm.Plan{
				Goal:  "goal",
				Tasks: []*pm.Task{{ID: 1, Title: "Task A", Priority: 1, Status: pm.TaskPending}},
			}
			s.Save()

			prov := &mockProvider{
				name:    "mock",
				results: []*provider.Result{{Output: tt.output, Provider: "mock"}},
			}
			o := newOrchestrator(t, dir, Config{WorkDir: dir, PMMode: true, NoHeal: true}, prov)
			// Any retryable wait pauses instead of sleeping, so the run ends
			// deterministically at the first abort.
			o.testAbortWaitCeiling = time.Nanosecond

			if err := o.runPM(context.Background()); err != nil {
				t.Fatalf("runPM: %v", err)
			}

			task := o.state.Plan.Tasks[0]
			if task.Status == pm.TaskDone {
				t.Fatalf("task was marked DONE on a provider refusal (%q) — the ledger-corruption bug is back", tt.output)
			}
			if task.Status != pm.TaskPending {
				t.Errorf("status = %q, want %q: an aborted task never ran, so it must be retryable", task.Status, pm.TaskPending)
			}
			if task.CompletedAt != nil {
				t.Error("CompletedAt must be cleared — nothing completed")
			}

			// The reason has to be in the journal under its own type, or the
			// abort is invisible to anyone reading task history.
			events := abortEventsFor(t, dir, 1)
			if len(events) == 0 {
				t.Fatal("no task_aborted event journalled")
			}
			if !strings.Contains(events[0].Details, string(tt.wantClass)) {
				t.Errorf("event details %q do not name the abort class %q", events[0].Details, tt.wantClass)
			}

			// And the run must stop rather than spin on the same wall.
			if o.state.Status != "paused" {
				t.Errorf("session status = %q, want paused", o.state.Status)
			}
			if prov.calls != 1 {
				t.Errorf("provider called %d times; the run must not retry into the same limit", prov.calls)
			}
		})
	}
}

// TestRunPM_AbortedTask_CompletesOnRetry is the other half of the contract:
// pending must mean genuinely retryable. A task aborted by a usage limit whose
// window has already reopened is picked straight back up, and a real response
// completes it normally — no operator intervention, no lost work.
func TestRunPM_AbortedTask_CompletesOnRetry(t *testing.T) {
	dir := tempDir(t)
	s := initState(t, dir, "goal", 0)
	s.PMMode = true
	s.Plan = &pm.Plan{
		Goal:  "goal",
		Tasks: []*pm.Task{{ID: 1, Title: "Task A", Priority: 1, Status: pm.TaskPending}},
	}
	s.Save()

	prov := &mockProvider{
		name: "mock",
		results: []*provider.Result{
			// A rate-limit refusal that names no reset time, so the run backs
			// off and retries rather than pausing for an operator.
			{Output: "Error: rate limit exceeded", Provider: "mock"},
			{Output: "Implemented it.\nTASK_DONE", Provider: "mock"},
		},
	}
	o := newOrchestrator(t, dir, Config{WorkDir: dir, PMMode: true, NoHeal: true}, prov)
	o.testAbortBackoff = time.Millisecond

	if err := o.runPM(context.Background()); err != nil {
		t.Fatalf("runPM: %v", err)
	}
	if got := o.state.Plan.Tasks[0].Status; got != pm.TaskDone {
		t.Errorf("status = %q, want %q — an aborted task must stay retryable", got, pm.TaskDone)
	}
	if len(abortEventsFor(t, dir, 1)) != 1 {
		t.Error("the first attempt's abort should still be in the journal")
	}
}

// TestRunPMParallel_AbortedAgent_LeavesTaskPending is the parallel-mode
// counterpart. The two loops have independently written `default:` arms —
// which is how the parallel path acquired the same fail-open bug — so both
// need their own guard and their own test.
func TestRunPMParallel_AbortedAgent_LeavesTaskPending(t *testing.T) {
	dir := tempDir(t)
	s := initState(t, dir, "goal", 0)
	s.PMMode = true
	s.Plan = &pm.Plan{
		Goal:  "goal",
		Tasks: []*pm.Task{{ID: 1, Title: "Task A", Priority: 1, Status: pm.TaskPending}},
	}
	s.Save()

	prov := &safeProvider{name: "mock", output: orgMonthlyQuota}
	o := newOrchestrator(t, dir, Config{WorkDir: dir, PMMode: true, Parallel: true, NoHeal: true}, prov)
	o.testAbortWaitCeiling = time.Nanosecond

	if err := o.Run(context.Background()); err != nil {
		t.Fatalf("Run: %v", err)
	}

	final, err := state.Load(dir)
	if err != nil {
		t.Fatalf("final load: %v", err)
	}
	task := final.Plan.Tasks[0]
	if task.Status == pm.TaskDone {
		t.Fatal("parallel mode marked a quota refusal DONE")
	}
	if task.Status != pm.TaskPending {
		t.Errorf("status = %q, want %q", task.Status, pm.TaskPending)
	}
	if len(abortEventsFor(t, dir, 1)) == 0 {
		t.Error("no task_aborted event journalled in parallel mode")
	}
}

// TestRunPM_NoEvidence_LeavesTaskPending covers the half of the rule the
// classifier cannot: output nobody recognises, with nothing to show for it.
// A task reaches done on a TASK_DONE signal or on a summary plus a diff or an
// artifact — an empty response that happened to survive the empty-output
// watchdog is neither.
func TestRunPM_NoEvidence_LeavesTaskPending(t *testing.T) {
	dir := tempDir(t)
	s := initState(t, dir, "goal", 0)
	s.PMMode = true
	s.Plan = &pm.Plan{
		Goal:  "goal",
		Tasks: []*pm.Task{{ID: 1, Title: "Task A", Priority: 1, Status: pm.TaskPending}},
	}
	s.Save()

	// A zero-byte artifact left by a previous phase: the run was recorded,
	// and recorded nothing.
	s.Plan.Tasks[0].ArtifactPath = mustWriteEmptyArtifact(t, dir)
	s.Save()

	prov := &mockProvider{
		name:    "mock",
		results: []*provider.Result{{Output: "I did some work but forgot to emit a signal.", Provider: "mock"}},
	}
	o := newOrchestrator(t, dir, Config{WorkDir: dir, PMMode: true, NoHeal: true}, prov)
	o.testAbortWaitCeiling = time.Nanosecond

	if err := o.runPM(context.Background()); err != nil {
		t.Fatalf("runPM: %v", err)
	}
	if got := o.state.Plan.Tasks[0].Status; got != pm.TaskPending {
		t.Errorf("status = %q, want %q — a zero-byte artifact is not evidence of work", got, pm.TaskPending)
	}
}

// TestAbortWait pins the retry-scheduling policy without sleeping through it.
func TestAbortWait(t *testing.T) {
	now := time.Date(2026, time.August, 27, 13, 0, 0, 0, time.UTC)
	const ceiling = 90 * time.Minute
	const backoff = 60 * time.Second

	tests := []struct {
		name      string
		ab        Abort
		wantWait  time.Duration
		wantPause bool
	}{
		{
			name:      "quota needs an operator",
			ab:        Abort{Class: AbortQuotaExceeded},
			wantPause: true,
		},
		{
			name:      "rejected credential needs an operator",
			ab:        Abort{Class: AbortAuth},
			wantPause: true,
		},
		{
			name:      "harness refusal needs an operator",
			ab:        Abort{Class: AbortHarnessRefusal},
			wantPause: true,
		},
		{
			name:     "usage window inside the ceiling is waited out",
			ab:       Abort{Class: AbortUsageLimit, RetryAfter: now.Add(20 * time.Minute)},
			wantWait: 20 * time.Minute,
		},
		{
			name:      "weekly window beyond the ceiling pauses instead of blocking for days",
			ab:        Abort{Class: AbortUsageLimit, RetryAfter: now.Add(6 * 24 * time.Hour)},
			wantWait:  6 * 24 * time.Hour,
			wantPause: true,
		},
		{
			name:     "reset already passed: retry immediately",
			ab:       Abort{Class: AbortUsageLimit, RetryAfter: now.Add(-time.Hour)},
			wantWait: 0,
		},
		{
			name:     "retryable with no parseable reset falls back to backoff",
			ab:       Abort{Class: AbortUsageLimit},
			wantWait: backoff,
		},
		{
			name:     "empty output backs off rather than spinning",
			ab:       Abort{Class: AbortEmptyOutput},
			wantWait: backoff,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wait, pause := abortWait(tt.ab, now, ceiling, backoff)
			if pause != tt.wantPause {
				t.Errorf("pause = %v, want %v", pause, tt.wantPause)
			}
			if !tt.wantPause && wait != tt.wantWait {
				t.Errorf("wait = %s, want %s", wait, tt.wantWait)
			}
		})
	}
}
