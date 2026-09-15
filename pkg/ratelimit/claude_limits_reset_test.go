package ratelimit

import (
	"errors"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/config"
)

// The reset time a cap violation carries is what lets a paused run be resumed
// without a human (Task 20285). Before this it was parsed from the OAuth usage
// API and thrown away at the first layer that could have used it.

func TestViolationCarriesTheWindowReset(t *testing.T) {
	fiveHour := time.Date(2026, 9, 15, 14, 50, 0, 0, time.UTC)
	weekly := time.Date(2026, 9, 20, 9, 0, 0, 0, time.UTC)

	usage := &ClaudeUsage{
		FiveHour: &UsageDetail{Utilization: 91, ResetsAt: fiveHour},
		SevenDay: &UsageDetail{Utilization: 40, ResetsAt: weekly},
	}
	cfg := config.ClaudeCodeConfig{MaxFiveHourPct: 90, MaxWeeklyPct: 90}

	got := CheckClaudeCodeLimits(cfg, usage)
	if len(got) != 1 {
		t.Fatalf("expected exactly the five-hour window to trip, got %d violations: %+v", len(got), got)
	}
	if got[0].Window != "five_hour" {
		t.Errorf("tripped window = %q, want five_hour", got[0].Window)
	}
	if !got[0].ResetsAt.Equal(fiveHour) {
		t.Errorf("ResetsAt = %v, want %v — the reset must survive from the snapshot to the violation",
			got[0].ResetsAt, fiveHour)
	}
}

func TestResumesAtIsTheLatestViolatedWindow(t *testing.T) {
	fiveHour := time.Date(2026, 9, 15, 14, 50, 0, 0, time.UTC)
	weekly := time.Date(2026, 9, 20, 9, 0, 0, 0, time.UTC)

	// Both caps tripped. Resuming when the *five-hour* window reopens would
	// pause the run again on its first task, because the weekly cap is still
	// over — and a fleet that rediscovers this every five hours is no better
	// off than one that stalled. So the answer is the later of the two.
	usage := &ClaudeUsage{
		FiveHour: &UsageDetail{Utilization: 95, ResetsAt: fiveHour},
		SevenDay: &UsageDetail{Utilization: 99, ResetsAt: weekly},
	}
	cfg := config.ClaudeCodeConfig{MaxFiveHourPct: 90, MaxWeeklyPct: 90}

	err := EnforceClaudeCodeLimits(cfg, usage)
	var capped *CapExceededError
	if !errors.As(err, &capped) {
		t.Fatalf("EnforceClaudeCodeLimits returned %T (%v), want *CapExceededError", err, err)
	}
	if len(capped.Violations) != 2 {
		t.Fatalf("expected both windows to trip, got %+v", capped.Violations)
	}
	if got := capped.ResumesAt(); !got.Equal(weekly) {
		t.Errorf("ResumesAt() = %v, want the later window %v", got, weekly)
	}
}

func TestResumesAtIsUnknownWhenAnyWindowDidNotReportOne(t *testing.T) {
	known := time.Date(2026, 9, 15, 14, 50, 0, 0, time.UTC)

	// One window reports a reset, the other does not. Answering with the
	// known one would promise a resume that the silent window can veto, so
	// the honest answer is "nobody knows" — and the hub then leaves it for a
	// human instead of restarting into the same wall.
	usage := &ClaudeUsage{
		FiveHour: &UsageDetail{Utilization: 95, ResetsAt: known},
		SevenDay: &UsageDetail{Utilization: 99}, // zero ResetsAt
	}
	cfg := config.ClaudeCodeConfig{MaxFiveHourPct: 90, MaxWeeklyPct: 90}

	err := EnforceClaudeCodeLimits(cfg, usage)
	var capped *CapExceededError
	if !errors.As(err, &capped) {
		t.Fatalf("EnforceClaudeCodeLimits returned %T, want *CapExceededError", err)
	}
	if got := capped.ResumesAt(); !got.IsZero() {
		t.Errorf("ResumesAt() = %v, want the zero time: one violated window reported no reset", got)
	}
}

func TestCapErrorKeepsItsMessageAndNamesTheWindows(t *testing.T) {
	usage := &ClaudeUsage{FiveHour: &UsageDetail{Utilization: 95}}
	cfg := config.ClaudeCodeConfig{MaxFiveHourPct: 90}

	err := EnforceClaudeCodeLimits(cfg, usage)
	if err == nil {
		t.Fatal("expected a cap violation")
	}
	// The wording is what an operator already recognises from the terminal;
	// switching to a typed error must not have changed it.
	want := "claudecode usage cap reached: claudecode 5-hour utilization 95% has reached the configured project cap of 90%"
	if err.Error() != want {
		t.Errorf("Error() = %q,\nwant %q", err.Error(), want)
	}

	var capped *CapExceededError
	_ = errors.As(err, &capped)
	if got, want := capped.Label(), "5-hour cap reached"; got != want {
		t.Errorf("Label() = %q, want %q", got, want)
	}
}

func TestCapLabelNamesEveryTrippedWindow(t *testing.T) {
	usage := &ClaudeUsage{
		FiveHour: &UsageDetail{Utilization: 95},
		SevenDay: &UsageDetail{Utilization: 99},
	}
	cfg := config.ClaudeCodeConfig{MaxFiveHourPct: 90, MaxWeeklyPct: 90}

	var capped *CapExceededError
	if !errors.As(EnforceClaudeCodeLimits(cfg, usage), &capped) {
		t.Fatal("expected a *CapExceededError")
	}
	// Order follows CheckClaudeCodeLimits' check sequence (weekly, then
	// five-hour), which is fixed rather than dependent on map iteration — so
	// the same pair of tripped caps always renders the same sentence.
	if got, want := capped.Label(), "weekly and 5-hour caps reached"; got != want {
		t.Errorf("Label() = %q, want %q", got, want)
	}
}

func TestNoViolationReturnsNilError(t *testing.T) {
	usage := &ClaudeUsage{FiveHour: &UsageDetail{Utilization: 10}}
	cfg := config.ClaudeCodeConfig{MaxFiveHourPct: 90}
	if err := EnforceClaudeCodeLimits(cfg, usage); err != nil {
		t.Errorf("EnforceClaudeCodeLimits = %v, want nil below the cap", err)
	}
}
