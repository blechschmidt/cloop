package orchestrator

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/logger"
	"github.com/blechschmidt/cloop/pkg/pausereason"
	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/provider"
	"github.com/blechschmidt/cloop/pkg/ratelimit"
	"github.com/blechschmidt/cloop/pkg/state"
)

// budget.block_extra_usage holds a run out of a Claude Code window that is used
// up, because the next request would be billed as extra usage. It used to do
// that from inside budget.Enforce, whose plain error paused the run as a spent
// budget: no reset time, and a kind of pause the hub must never resume on a
// timer. On :8888 a project paused at 23:26 "to avoid extra usage" stayed
// paused past its window's 23:30 reset until its owner pressed Run at 23:39
// (Task 20440). These pin the replacement: the hold is a usage cap like any
// other, carrying the window's reset.

// exhaustedFiveHour is a usage snapshot whose five-hour window is used up.
func exhaustedFiveHour(resetsAt time.Time) *ratelimit.ClaudeUsage {
	return &ratelimit.ClaudeUsage{
		FiveHour: &ratelimit.UsageDetail{Utilization: 100, ResetsAt: resetsAt},
		SevenDay: &ratelimit.UsageDetail{Utilization: 41, ResetsAt: resetsAt.Add(4 * 24 * time.Hour)},
	}
}

// extraUsageOrchestrator is capOrchestrator for a claudecode run with the
// default budget settings, reading usage from the snapshot given.
func extraUsageOrchestrator(now time.Time, usage *ratelimit.ClaudeUsage) *Orchestrator {
	o := capOrchestrator(now)
	o.config.ProviderName = "claudecode"
	o.state = &state.ProjectState{}
	o.testUsage = func() (*ratelimit.ClaudeUsage, error) { return usage, nil }
	return o
}

func TestAnExhaustedWindowIsAUsageCapCarryingItsReset(t *testing.T) {
	now := time.Date(2026, 10, 24, 23, 26, 51, 0, time.UTC)
	reset := now.Add(3 * time.Hour) // beyond the 90-minute wait ceiling
	o := extraUsageOrchestrator(now, exhaustedFiveHour(reset))
	s := capState(t)

	capErr := o.enforceClaudeCodeLimits()
	var capped *ratelimit.CapExceededError
	if !errors.As(capErr, &capped) {
		t.Fatalf("enforceClaudeCodeLimits = %T (%v), want *ratelimit.CapExceededError — "+
			"block_extra_usage is on by default and the five-hour window is at 100%%", capErr, capErr)
	}

	if stop := mustHandleUsageCap(t, o, s, capErr); !stop {
		t.Fatal("a window three hours from its reset did not stop the run")
	}
	if !s.PausedFor(pausereason.CodeUsageCap) {
		t.Fatalf("paused for %+v, want usage_cap: a budget pause is one the hub never resumes", s.PauseReason)
	}
	if s.PauseReason.ResumesAt == nil || !s.PauseReason.ResumesAt.Equal(reset) {
		t.Fatalf("resumes_at = %v, want the window's reset %v", s.PauseReason.ResumesAt, reset)
	}
	if got, want := s.PauseReason.Label(), "5-hour window exhausted"; got != want {
		t.Errorf("label = %q, want %q", got, want)
	}
	// What the hub's sweep asks: not before the reset, and as soon as it.
	if s.PauseReason.AutoResumable(reset.Add(-time.Second)) {
		t.Error("judged resumable before the window reopened")
	}
	if !s.PauseReason.AutoResumable(reset.Add(time.Second)) {
		t.Error("not resumable after the window reopened — the run would stay paused, the bug this replaces")
	}
}

func TestAnExhaustedWindowAboutToReopenIsWaitedOut(t *testing.T) {
	now := time.Date(2026, 10, 24, 23, 29, 59, 0, time.UTC)
	// One second to the reset: the run waits it out in place and carries on
	// rather than pausing for the hub to restart it.
	o := extraUsageOrchestrator(now, exhaustedFiveHour(now.Add(time.Second)))
	s := capState(t)

	capErr := o.enforceClaudeCodeLimits()
	if capErr == nil {
		t.Fatal("an exhausted window was not reported")
	}
	if stop := mustHandleUsageCap(t, o, s, capErr); stop {
		t.Fatalf("stopped the run one second before its window reopened; reason=%+v", s.PauseReason)
	}
	if s.Status == "paused" {
		t.Errorf("status = paused (%+v), want the run carrying on", s.PauseReason)
	}
}

func TestAWindowWhoseResetPassedNoLongerHoldsTheRun(t *testing.T) {
	now := time.Date(2026, 10, 24, 23, 31, 0, 0, time.UTC)
	// The snapshot predates the rollover — the one-minute cache, a usage API
	// lagging the reset, or one that has failed since and keeps serving the
	// last snapshot. The window it describes is gone.
	o := extraUsageOrchestrator(now, exhaustedFiveHour(now.Add(-time.Minute)))

	if err := o.enforceClaudeCodeLimits(); err != nil {
		t.Errorf("enforceClaudeCodeLimits = %v; a window whose reset has passed has reopened", err)
	}
}

func TestBlockExtraUsageOffLetsAnExhaustedWindowThrough(t *testing.T) {
	now := time.Date(2026, 10, 24, 23, 26, 51, 0, time.UTC)
	o := extraUsageOrchestrator(now, exhaustedFiveHour(now.Add(3*time.Hour)))
	off := false
	o.config.Budget = config.BudgetConfig{BlockExtraUsage: &off}

	if err := o.enforceClaudeCodeLimits(); err != nil {
		t.Errorf("enforceClaudeCodeLimits = %v with block_extra_usage: false", err)
	}
}

func TestExtraUsageConcernsOnlyClaudeCodeRuns(t *testing.T) {
	now := time.Date(2026, 10, 24, 23, 26, 51, 0, time.UTC)
	// An API-key provider bills per token whatever the subscription says, so
	// an exhausted Claude Code window is no reason to stop it.
	o := extraUsageOrchestrator(now, exhaustedFiveHour(now.Add(3*time.Hour)))
	o.config.ProviderName = "anthropic"
	o.testUsage = func() (*ratelimit.ClaudeUsage, error) {
		t.Error("read the Claude Code usage for a run that does not use Claude Code")
		return nil, nil
	}

	if err := o.enforceClaudeCodeLimits(); err != nil {
		t.Errorf("enforceClaudeCodeLimits = %v for an anthropic run", err)
	}
}

func TestUnreadableUsageNeitherHoldsTheRunNorWarnsWithoutCaps(t *testing.T) {
	now := time.Date(2026, 10, 24, 23, 26, 51, 0, time.UTC)
	o := extraUsageOrchestrator(now, nil)
	var logged bytes.Buffer
	o.log = logger.NewWithWriter(&logged, true)
	o.testUsage = func() (*ratelimit.ClaudeUsage, error) {
		return nil, errors.New("usage API unreachable")
	}

	// block_extra_usage is on for every project that never mentions it,
	// including ones signed in with an API key, which have no subscription
	// usage to read. That is not a warning anyone can act on.
	if err := o.enforceClaudeCodeLimits(); err != nil {
		t.Errorf("enforceClaudeCodeLimits = %v; unreadable usage must not stop work", err)
	}
	if logged.Len() != 0 {
		t.Errorf("warned with no cap configured: %s", logged.String())
	}

	// A cap someone configured is another matter: say it is not applied.
	o.config.ClaudeCode = config.ClaudeCodeConfig{MaxFiveHourPct: 80}
	if err := o.enforceClaudeCodeLimits(); err != nil {
		t.Errorf("enforceClaudeCodeLimits = %v; unreadable usage must not stop work", err)
	}
	if logged.Len() == 0 {
		t.Error("no warning that a configured cap is not being enforced")
	}
}

// TestRunPM_ExhaustedWindowPausesForTheHubToResume runs the loop itself, both
// of them: a plan with work left, a claudecode run, the five-hour window used
// up three hours before its reset. The run must dispatch nothing and end
// paused in the form the hub's auto-resume acts on.
func TestRunPM_ExhaustedWindowPausesForTheHubToResume(t *testing.T) {
	for _, parallel := range []bool{false, true} {
		name := "sequential"
		if parallel {
			name = "parallel"
		}
		t.Run(name, func(t *testing.T) {
			dir := tempDir(t)
			s := initState(t, dir, "goal", 0)
			s.PMMode = true
			s.Plan = &pm.Plan{
				Goal:  "goal",
				Tasks: []*pm.Task{{ID: 1, Title: "Task A", Priority: 1, Status: pm.TaskPending}},
			}
			if err := s.Save(); err != nil {
				t.Fatalf("save: %v", err)
			}

			prov := &mockProvider{name: "mock"}
			o := newOrchestrator(t, dir, Config{
				WorkDir: dir, PMMode: true, NoHeal: true,
				ProviderName: "claudecode", Parallel: parallel,
			}, prov)
			reset := time.Now().Add(3 * time.Hour).Truncate(time.Second).UTC()
			o.testUsage = func() (*ratelimit.ClaudeUsage, error) { return exhaustedFiveHour(reset), nil }

			err := o.runPM(context.Background())
			var capped *ratelimit.CapExceededError
			if !errors.As(err, &capped) {
				t.Fatalf("runPM = %v, want the run to end on the exhausted window", err)
			}
			if prov.calls != 0 {
				t.Errorf("provider called %d times: a task was dispatched into an exhausted window", prov.calls)
			}

			// What a fresh load sees is what the hub's sweep sees.
			got, lerr := state.LoadLite(dir)
			if lerr != nil {
				t.Fatalf("load: %v", lerr)
			}
			if !got.PausedFor(pausereason.CodeUsageCap) {
				t.Fatalf("stored status=%q reason=%+v, want a usage_cap pause", got.Status, got.PauseReason)
			}
			if got.PauseReason.ResumesAt == nil || !got.PauseReason.ResumesAt.Equal(reset) {
				t.Fatalf("stored resumes_at = %v, want %v", got.PauseReason.ResumesAt, reset)
			}
			if !got.PauseReason.AutoResumable(reset.Add(time.Minute)) {
				t.Error("the stored pause is not one the hub resumes after the reset")
			}
			if got.Plan.Tasks[0].Status != pm.TaskPending {
				t.Errorf("task status = %q, want pending", got.Plan.Tasks[0].Status)
			}
		})
	}
}

// evolveProject is a project whose plan has drained, with auto-evolve on.
func evolveProject(t *testing.T) string {
	t.Helper()
	dir := tempDir(t)
	s := initState(t, dir, "goal", 0)
	s.PMMode = true
	s.AutoEvolve = true
	s.Plan = &pm.Plan{
		Goal:  "goal",
		Tasks: []*pm.Task{{ID: 1, Title: "Done already", Priority: 1, Status: pm.TaskDone, Result: "Implemented it."}},
	}
	if err := s.Save(); err != nil {
		t.Fatalf("save: %v", err)
	}
	return dir
}

// TestRunPM_ExhaustedWindowHoldsAnEvolveRound: an evolve round asks the
// provider for work like a task does. A plan that drained just as its window
// ran out used to send the round into the wall, get the limit message back,
// and after three such rounds close the run as complete, which nothing
// resumes. It must instead pause, in the form the hub resumes, without asking
// the provider anything or announcing the plan's completion.
func TestRunPM_ExhaustedWindowHoldsAnEvolveRound(t *testing.T) {
	for _, parallel := range []bool{false, true} {
		t.Run(fmt.Sprintf("parallel=%v", parallel), func(t *testing.T) {
			dir := evolveProject(t)
			prov := &mockProvider{name: "mock"}
			o := newOrchestrator(t, dir, Config{
				WorkDir: dir, PMMode: true, NoHeal: true,
				ProviderName: "claudecode", Parallel: parallel,
			}, prov)
			reset := time.Now().Add(3 * time.Hour).Truncate(time.Second).UTC()
			o.testUsage = func() (*ratelimit.ClaudeUsage, error) { return exhaustedFiveHour(reset), nil }

			err := o.runPM(context.Background())
			var capped *ratelimit.CapExceededError
			if !errors.As(err, &capped) {
				t.Fatalf("runPM = %v, want the run to end on the exhausted window", err)
			}
			if prov.calls != 0 {
				t.Errorf("the provider was asked for an evolve round %d time(s) into an exhausted window", prov.calls)
			}
			got, lerr := state.LoadLite(dir)
			if lerr != nil {
				t.Fatalf("load: %v", lerr)
			}
			if !got.PausedFor(pausereason.CodeUsageCap) || got.PauseReason.ResumesAt == nil ||
				!got.PauseReason.ResumesAt.Equal(reset) {
				t.Fatalf("stored status=%q reason=%+v, want a usage_cap pause resuming at %v", got.Status, got.PauseReason, reset)
			}
			if rows := eventsOf(t, dir, state.EventPlanComplete); len(rows) != 0 {
				t.Errorf("the plan's completion was announced %d time(s) before the run could evolve", len(rows))
			}
		})
	}
}

// TestRunPM_EvolveRoundTheLimitRefusedPausesInsteadOfCompleting: the window
// runs out during the round itself, or the usage API has not caught up, so
// the provider answers the round with the limit message. That is not a
// project with nothing left to do: the run must stop resumably on the reset
// the message names, not count its way to "complete".
func TestRunPM_EvolveRoundTheLimitRefusedPausesInsteadOfCompleting(t *testing.T) {
	for _, parallel := range []bool{false, true} {
		t.Run(fmt.Sprintf("parallel=%v", parallel), func(t *testing.T) {
			dir := evolveProject(t)
			prov := &mockProvider{name: "mock", results: []*provider.Result{{Output: sessionLimitLate, Provider: "mock"}}}
			o := newOrchestrator(t, dir, Config{
				WorkDir: dir, PMMode: true, NoHeal: true,
				ProviderName: "claudecode", Parallel: parallel,
			}, prov)
			// The window reads as open, so the round goes out.
			o.testUsage = func() (*ratelimit.ClaudeUsage, error) {
				return &ratelimit.ClaudeUsage{FiveHour: &ratelimit.UsageDetail{Utilization: 97}}, nil
			}
			// Any wait pauses instead of sleeping, so the run ends at the
			// refusal whatever time of day the suite runs.
			o.testAbortWaitCeiling = time.Nanosecond

			if err := o.runPM(context.Background()); err != nil {
				t.Fatalf("runPM: %v", err)
			}
			if prov.calls != 1 {
				t.Errorf("provider called %d times, want the one refused round", prov.calls)
			}
			got, lerr := state.LoadLite(dir)
			if lerr != nil {
				t.Fatalf("load: %v", lerr)
			}
			if got.Status == "complete" {
				t.Fatal("the run was closed as complete on a limit message — nothing resumes a completed run")
			}
			if !got.PausedFor(pausereason.CodeUsageCap) || got.PauseReason.ResumesAt == nil {
				t.Fatalf("stored status=%q reason=%+v, want a usage_cap pause carrying the message's reset", got.Status, got.PauseReason)
			}
			if h := got.PauseReason.ResumesAt.UTC(); h.Hour() != 23 || h.Minute() != 30 {
				t.Errorf("resumes_at = %v, want the 23:30 UTC the message names", h)
			}
		})
	}
}
