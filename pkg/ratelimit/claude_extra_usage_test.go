package ratelimit

import (
	"errors"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/config"
)

// budget.block_extra_usage keeps a run out of a window that is used up, where
// Claude Code would start billing extra usage. It used to be a plain error from
// the daily budget check, which threw the window's reset away and so filed the
// hold as a spent budget no timer may lift (Task 20440). These pin it as a
// violation like the caps: typed, and carrying the reset.

func TestAnExhaustedWindowCarriesItsReset(t *testing.T) {
	reset := time.Date(2026, 10, 24, 23, 30, 0, 0, time.UTC)
	usage := &ClaudeUsage{
		FiveHour: &UsageDetail{Utilization: 100, ResetsAt: reset},
		SevenDay: &UsageDetail{Utilization: 41, ResetsAt: reset.Add(96 * time.Hour)},
	}

	err := EnforceSubscriptionLimits(config.ClaudeCodeConfig{}, true, usage)
	var capped *CapExceededError
	if !errors.As(err, &capped) {
		t.Fatalf("EnforceSubscriptionLimits = %T (%v), want *CapExceededError", err, err)
	}
	if len(capped.Violations) != 1 {
		t.Fatalf("violations = %+v, want just the five-hour window", capped.Violations)
	}
	v := capped.Violations[0]
	if v.Window != "five_hour" || !v.ExtraUsage {
		t.Errorf("violation = %+v, want the five-hour window marked ExtraUsage", v)
	}
	if got := capped.ResumesAt(); !got.Equal(reset) {
		t.Errorf("ResumesAt() = %v, want %v", got, reset)
	}
	if got, want := capped.Label(), "5-hour window exhausted"; got != want {
		t.Errorf("Label() = %q, want %q", got, want)
	}
	// No "usage cap reached" in front: nobody configured a cap.
	want := "Claude Code 5-hour window exhausted (100%) — holding the run to avoid extra usage (set budget.block_extra_usage: false to allow)"
	if err.Error() != want {
		t.Errorf("Error() = %q,\nwant %q", err.Error(), want)
	}
}

func TestExhaustedWindowsAreTheOnesThatBillExtraUsage(t *testing.T) {
	reset := time.Date(2026, 10, 24, 23, 30, 0, 0, time.UTC)
	full := func() *UsageDetail { return &UsageDetail{Utilization: 100, ResetsAt: reset} }

	tests := []struct {
		name  string
		usage *ClaudeUsage
		want  []string
	}{
		{"nil snapshot", nil, nil},
		{"nothing reported", &ClaudeUsage{}, nil},
		{"just under", &ClaudeUsage{FiveHour: &UsageDetail{Utilization: 99.5, ResetsAt: reset}}, nil},
		{"over 100 counts", &ClaudeUsage{FiveHour: &UsageDetail{Utilization: 103, ResetsAt: reset}}, []string{"five_hour"}},
		{"weekly", &ClaudeUsage{SevenDay: full()}, []string{"weekly"}},
		{"weekly Sonnet", &ClaudeUsage{SevenDaySonnet: full()}, []string{"weekly_sonnet"}},
		// Running out of Opus moves Claude Code to another model, not onto
		// extra usage — the check this replaces never looked at it either.
		{"weekly Opus is not a wall", &ClaudeUsage{SevenDayOpus: full()}, nil},
		{"several, in the caps' order", &ClaudeUsage{FiveHour: full(), SevenDay: full(), SevenDaySonnet: full()},
			[]string{"weekly", "five_hour", "weekly_sonnet"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := CheckExhaustedWindows(tt.usage)
			if len(got) != len(tt.want) {
				t.Fatalf("CheckExhaustedWindows = %+v, want windows %v", got, tt.want)
			}
			for i, v := range got {
				if v.Window != tt.want[i] || !v.ExtraUsage || v.Cap != 100 {
					t.Errorf("violation %d = %+v, want window %q marked ExtraUsage at cap 100", i, v, tt.want[i])
				}
			}
		})
	}
}

func TestBlockExtraUsageOffIgnoresExhaustedWindows(t *testing.T) {
	usage := &ClaudeUsage{FiveHour: &UsageDetail{Utilization: 100}}
	if err := EnforceSubscriptionLimits(config.ClaudeCodeConfig{}, false, usage); err != nil {
		t.Errorf("EnforceSubscriptionLimits = %v with block_extra_usage off", err)
	}
	// And EnforceClaudeCodeLimits is the caps alone, as it always was.
	if err := EnforceClaudeCodeLimits(config.ClaudeCodeConfig{}, usage); err != nil {
		t.Errorf("EnforceClaudeCodeLimits = %v with no caps configured", err)
	}
}

func TestAWindowOverItsCapAndExhaustedIsReportedOnce(t *testing.T) {
	reset := time.Date(2026, 10, 24, 23, 30, 0, 0, time.UTC)
	usage := &ClaudeUsage{FiveHour: &UsageDetail{Utilization: 100, ResetsAt: reset}}
	cfg := config.ClaudeCodeConfig{MaxFiveHourPct: 90}

	var capped *CapExceededError
	if !errors.As(EnforceSubscriptionLimits(cfg, true, usage), &capped) {
		t.Fatal("expected a *CapExceededError")
	}
	if len(capped.Violations) != 1 || capped.Violations[0].ExtraUsage {
		t.Fatalf("violations = %+v, want one, the configured cap", capped.Violations)
	}
	if got, want := capped.Label(), "5-hour cap reached"; got != want {
		t.Errorf("Label() = %q, want %q", got, want)
	}
}

func TestLabelsNameCapsAndExhaustedWindowsApart(t *testing.T) {
	reset := time.Date(2026, 10, 24, 23, 30, 0, 0, time.UTC)

	// A configured weekly cap and an exhausted five-hour window.
	mixed := &ClaudeUsage{
		SevenDay: &UsageDetail{Utilization: 95, ResetsAt: reset.Add(72 * time.Hour)},
		FiveHour: &UsageDetail{Utilization: 100, ResetsAt: reset},
	}
	var capped *CapExceededError
	if !errors.As(EnforceSubscriptionLimits(config.ClaudeCodeConfig{MaxWeeklyPct: 90}, true, mixed), &capped) {
		t.Fatal("expected a *CapExceededError")
	}
	if got, want := capped.Label(), "weekly cap reached and 5-hour window exhausted"; got != want {
		t.Errorf("Label() = %q, want %q", got, want)
	}
	// The cap's prefix stays, since one was configured; and the later reset
	// is the one that frees the run.
	if want := "claudecode usage cap reached: "; len(capped.Error()) < len(want) || capped.Error()[:len(want)] != want {
		t.Errorf("Error() = %q, want it to start %q", capped.Error(), want)
	}
	if got := capped.ResumesAt(); !got.Equal(reset.Add(72 * time.Hour)) {
		t.Errorf("ResumesAt() = %v, want the weekly reset", got)
	}

	both := &ClaudeUsage{
		SevenDay: &UsageDetail{Utilization: 100, ResetsAt: reset.Add(72 * time.Hour)},
		FiveHour: &UsageDetail{Utilization: 100, ResetsAt: reset},
	}
	if !errors.As(EnforceSubscriptionLimits(config.ClaudeCodeConfig{}, true, both), &capped) {
		t.Fatal("expected a *CapExceededError")
	}
	if got, want := capped.Label(), "weekly and 5-hour windows exhausted"; got != want {
		t.Errorf("Label() = %q, want %q", got, want)
	}
}

func TestAtDropsWindowsThatHaveRolledOver(t *testing.T) {
	now := time.Date(2026, 10, 24, 23, 31, 0, 0, time.UTC)
	usage := &ClaudeUsage{
		FiveHour:       &UsageDetail{Utilization: 100, ResetsAt: now.Add(-time.Minute)},
		SevenDay:       &UsageDetail{Utilization: 100, ResetsAt: now.Add(time.Hour)},
		SevenDaySonnet: &UsageDetail{Utilization: 100}, // no reset reported
		SevenDayOpus:   &UsageDetail{Utilization: 50, ResetsAt: now},
		FetchedAt:      now.Add(-2 * time.Minute),
	}

	got := usage.At(now)
	if got.FiveHour != nil {
		t.Errorf("kept the five-hour window whose reset passed: %+v", got.FiveHour)
	}
	if got.SevenDayOpus != nil {
		t.Errorf("kept a window resetting exactly now: %+v", got.SevenDayOpus)
	}
	if got.SevenDay == nil {
		t.Error("dropped the weekly window, which has an hour to go")
	}
	if got.SevenDaySonnet == nil {
		t.Error("dropped a window that reported no reset: nothing says it rolled over")
	}
	if !got.FetchedAt.Equal(usage.FetchedAt) {
		t.Errorf("FetchedAt = %v, want %v", got.FetchedAt, usage.FetchedAt)
	}
	// The receiver may be the shared cached snapshot; it is not edited.
	if usage.FiveHour == nil || usage.SevenDayOpus == nil {
		t.Error("At modified its receiver")
	}
	if (*ClaudeUsage)(nil).At(now) != nil {
		t.Error("At on a nil snapshot should be nil")
	}

	// Which is what keeps a stale snapshot from holding a run past a reset.
	if err := EnforceSubscriptionLimits(config.ClaudeCodeConfig{MaxFiveHourPct: 90}, true,
		(&ClaudeUsage{FiveHour: usage.FiveHour}).At(now)); err != nil {
		t.Errorf("a rolled-over window still tripped: %v", err)
	}
}
