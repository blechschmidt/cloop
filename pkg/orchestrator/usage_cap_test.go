package orchestrator

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/logger"
	"github.com/blechschmidt/cloop/pkg/pausereason"
	"github.com/blechschmidt/cloop/pkg/ratelimit"
	"github.com/blechschmidt/cloop/pkg/state"
)

// The cap path used to bypass the abort machinery entirely: it printed the
// error, wrote a bare "paused" and returned, so a project stopped indefinitely
// even though the exact instant it could continue was already in the snapshot
// that stopped it (Task 20285).
//
// Everything here drives the decision with an injected clock. Sleeping out a
// real five-hour window is not a test, and shortening the window to make it
// sleepable would test a different policy than the one that ships.

// capOrchestrator builds the minimum Orchestrator the cap path touches, with
// its clock frozen at now.
func capOrchestrator(now time.Time) *Orchestrator {
	return &Orchestrator{
		log:                  logger.NewWithWriter(nil, false),
		testNow:              func() time.Time { return now },
		testAbortWaitCeiling: 90 * time.Minute,
		testAbortBackoff:     time.Second,
	}
}

func capError(window string, resetsAt time.Time) error {
	return &ratelimit.CapExceededError{Violations: []ratelimit.LimitViolation{{
		Window:      window,
		Utilization: 95,
		Cap:         90,
		ResetsAt:    resetsAt,
	}}}
}

func TestDistantCapPausesAndRecordsWhenItResumes(t *testing.T) {
	now := time.Date(2026, 9, 15, 10, 0, 0, 0, time.UTC)
	// Claude's weekly window: days away, far beyond the 90-minute ceiling.
	// Blocking a worker that long is worse than pausing, so this must pause —
	// but it must pause *with* the reset, which is what lets the hub restart
	// it later without a human.
	reset := now.Add(5 * 24 * time.Hour)

	o := capOrchestrator(now)
	s := &state.ProjectState{Status: "running"}

	if stop := o.handleUsageCap(context.Background(), s, capError("weekly", reset)); !stop {
		t.Fatal("handleUsageCap returned stop=false for a window five days out")
	}
	if s.Status != "paused" {
		t.Fatalf("status = %q, want paused", s.Status)
	}
	if s.PauseReason == nil {
		t.Fatal("paused with no reason — this is the silent stall the task exists to end")
	}
	if s.PauseReason.Code != pausereason.CodeUsageCap {
		t.Errorf("code = %q, want %q", s.PauseReason.Code, pausereason.CodeUsageCap)
	}
	if s.PauseReason.ResumesAt == nil {
		t.Fatal("no resumes_at recorded: the reset was known and is what makes auto-resume possible")
	}
	if !s.PauseReason.ResumesAt.Equal(reset) {
		t.Errorf("resumes_at = %v, want %v", s.PauseReason.ResumesAt, reset)
	}
	if got, want := s.PauseReason.Summary(time.UTC), "weekly cap reached"; !strings.Contains(got, want) {
		t.Errorf("summary = %q, want it to contain %q", got, want)
	}
}

func TestNearCapIsWaitedOutRatherThanEndingTheRun(t *testing.T) {
	now := time.Date(2026, 9, 15, 10, 0, 0, 0, time.UTC)
	// A five-hour window that already reopened. abortWait returns wait<=0, so
	// the run carries straight on instead of stopping — the in-process half of
	// auto-resume.
	o := capOrchestrator(now)
	s := &state.ProjectState{Status: "running"}

	stop := o.handleUsageCap(context.Background(), s, capError("five_hour", now.Add(-time.Minute)))
	if stop {
		t.Error("handleUsageCap stopped the run for a window that had already reopened")
	}
	if s.Status == "paused" {
		t.Errorf("run was paused despite the window having reopened; reason=%+v", s.PauseReason)
	}
}

func TestCapWithNoKnownResetPausesWithoutInventingOne(t *testing.T) {
	now := time.Date(2026, 9, 15, 10, 0, 0, 0, time.UTC)

	// The usage API reported no reset for the tripped window. Force the pause
	// branch — backoff beyond the ceiling — so the assertion is about what a
	// pause records rather than about whether one happens.
	o := capOrchestrator(now)
	o.testAbortWaitCeiling = time.Second
	o.testAbortBackoff = time.Hour
	s := &state.ProjectState{Status: "running"}

	if stop := o.handleUsageCap(context.Background(), s, capError("five_hour", time.Time{})); !stop {
		t.Fatal("handleUsageCap did not stop the run despite a backoff beyond the ceiling")
	}
	if s.Status != "paused" || s.PauseReason == nil {
		t.Fatalf("status=%q reason=%+v, want a paused run carrying a reason", s.Status, s.PauseReason)
	}
	if s.PauseReason.Code != pausereason.CodeUsageCap {
		t.Errorf("code = %q, want usage_cap", s.PauseReason.Code)
	}
	// The whole point: a resume time nobody reported must not be invented.
	// The hub would otherwise restart the run into the same wall on a timer.
	if s.PauseReason.ResumesAt != nil {
		t.Errorf("invented a resume time %v for a window that reported none",
			s.PauseReason.ResumesAt)
	}
	if s.PauseReason.AutoResumable(now.Add(365 * 24 * time.Hour)) {
		t.Error("a cap with no known reset was judged auto-resumable")
	}
}

func TestStaleResetDoesNotHotLoop(t *testing.T) {
	now := time.Date(2026, 9, 15, 10, 0, 0, 0, time.UTC)

	// The snapshot says the cap is tripped but that its window already
	// reopened — the usage API lagging, or our own one-minute cache. Taken at
	// face value that yields a zero wait, and the caller's `continue` would
	// re-read the same cached snapshot and land straight back here: a hot loop
	// for as long as the staleness lasts.
	//
	// Forcing the pause branch (backoff beyond the ceiling) is how the test
	// observes which path was taken: if the stale reset had been honoured,
	// abortWait would have returned wait=0 and no pause at all.
	o := capOrchestrator(now)
	o.testAbortWaitCeiling = time.Second
	o.testAbortBackoff = time.Hour
	s := &state.ProjectState{Status: "running"}

	stop := o.handleUsageCap(context.Background(), s, capError("five_hour", now.Add(-10*time.Minute)))
	if !stop {
		t.Fatal("a stale reset was honoured as a real one — the run would spin re-checking the same snapshot")
	}
	if s.Status != "paused" {
		t.Fatalf("status = %q, want paused", s.Status)
	}
	// And it must not advertise the elapsed instant as a resume time, or the
	// hub's sweep would restart the run into the same wall immediately.
	if s.PauseReason != nil && s.PauseReason.ResumesAt != nil {
		t.Errorf("recorded an already-elapsed resume time %v", s.PauseReason.ResumesAt)
	}
}

func TestUntypedCapErrorStillPauses(t *testing.T) {
	now := time.Date(2026, 9, 15, 10, 0, 0, 0, time.UTC)
	o := capOrchestrator(now)
	s := &state.ProjectState{Status: "running"}

	// If enforcement ever grows a failure mode that is not a CapExceededError,
	// it must pause rather than be mistaken for a window that reopens on its
	// own — a wrong guess here would auto-resume into a wall forever.
	if stop := o.handleUsageCap(context.Background(), s, errors.New("usage API unreachable")); !stop {
		t.Fatal("an untyped cap error did not stop the run")
	}
	if s.Status != "paused" || s.PauseReason == nil {
		t.Fatalf("status=%q reason=%+v, want a paused run carrying a reason", s.Status, s.PauseReason)
	}
	if s.PauseReason.ResumesAt != nil {
		t.Errorf("claimed a resume time %v for an error carrying no window", s.PauseReason.ResumesAt)
	}
}

func TestAbortPauseReasonSeparatesRetryableFromOperatorWork(t *testing.T) {
	reset := time.Date(2026, 9, 15, 14, 50, 0, 0, time.UTC)

	// A usage window reopens by itself, so it is the one class that may carry
	// a resume time and be restarted unattended.
	usage := abortPauseReason(Abort{Class: AbortUsageLimit, Reason: "5-hour limit", RetryAfter: reset})
	if usage.Code != pausereason.CodeUsageCap {
		t.Errorf("usage limit mapped to %q, want usage_cap", usage.Code)
	}
	if usage.ResumesAt == nil || !usage.ResumesAt.Equal(reset) {
		t.Errorf("usage limit lost its reset: %v", usage.ResumesAt)
	}

	// The classes that need a human must never look auto-resumable, or the
	// hub would restart a run into a rejected credential every five minutes.
	for _, class := range []AbortClass{AbortQuotaExceeded, AbortAuth, AbortHarnessRefusal} {
		got := abortPauseReason(Abort{Class: class, Reason: string(class), RetryAfter: reset})
		if got.Code != pausereason.CodeAbort {
			t.Errorf("%s mapped to %q, want abort", class, got.Code)
		}
		if got.AutoResumable(reset.Add(time.Hour)) {
			t.Errorf("%s was judged auto-resumable; it needs an operator", class)
		}
	}
}
