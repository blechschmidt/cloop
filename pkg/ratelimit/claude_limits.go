// Package ratelimit - claude_limits.go enforces per-project caps on the
// global Claude Code subscription utilization (5-hour and weekly windows).
package ratelimit

import (
	"fmt"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/config"
)

// LimitViolation describes a single tripped per-project claudecode cap.
type LimitViolation struct {
	Window      string  // "weekly", "five_hour", "weekly_opus", "weekly_sonnet"
	Utilization float64 // current global utilization 0-100
	Cap         float64 // configured per-project cap 0-100
	// ResetsAt is when this window rolls over, as reported by the OAuth
	// usage API. Zero when the API did not say — the snapshot omits the
	// window's reset, or it was served from a cache written before the
	// field existed. A caller must treat zero as "unknown", never as "now".
	ResetsAt time.Time
}

func (v LimitViolation) Error() string {
	return fmt.Sprintf(
		"claudecode %s utilization %.0f%% has reached the configured project cap of %.0f%%",
		humanWindow(v.Window), v.Utilization, v.Cap,
	)
}

// Label is the short operator-facing phrase for this violation, the form that
// reads well after "Paused:" — "5-hour cap reached".
func (v LimitViolation) Label() string {
	return fmt.Sprintf("%s cap reached", humanWindow(v.Window))
}

func humanWindow(w string) string {
	switch w {
	case "weekly":
		return "weekly"
	case "five_hour":
		return "5-hour"
	case "weekly_opus":
		return "weekly Opus"
	case "weekly_sonnet":
		return "weekly Sonnet"
	default:
		return w
	}
}

// CheckClaudeCodeLimits compares the configured per-project caps against a
// usage snapshot and returns the list of windows whose configured cap has
// been reached. Returns nil when no caps are tripped (or no caps configured).
//
// usage may be nil — in that case CheckClaudeCodeLimits returns nil
// (no enforcement when usage data is unavailable).
func CheckClaudeCodeLimits(cfg config.ClaudeCodeConfig, usage *ClaudeUsage) []LimitViolation {
	if usage == nil {
		return nil
	}
	var out []LimitViolation
	check := func(name string, capPct float64, w *UsageDetail) {
		if capPct <= 0 || w == nil {
			return
		}
		if w.Utilization >= capPct {
			out = append(out, LimitViolation{
				Window:      name,
				Utilization: w.Utilization,
				Cap:         capPct,
				ResetsAt:    w.ResetsAt,
			})
		}
	}
	check("weekly", cfg.MaxWeeklyPct, usage.SevenDay)
	check("five_hour", cfg.MaxFiveHourPct, usage.FiveHour)
	check("weekly_opus", cfg.MaxWeeklyOpusPct, usage.SevenDayOpus)
	check("weekly_sonnet", cfg.MaxWeeklySonnetPct, usage.SevenDaySonnet)
	return out
}

// CapExceededError is the error EnforceClaudeCodeLimits returns when a cap has
// been reached. It carries the violations themselves so the caller can record
// when the run may resume instead of only being able to print why it stopped.
type CapExceededError struct {
	Violations []LimitViolation
}

func (e *CapExceededError) Error() string {
	parts := make([]string, 0, len(e.Violations))
	for _, v := range e.Violations {
		parts = append(parts, v.Error())
	}
	return "claudecode usage cap reached: " + strings.Join(parts, "; ")
}

// ResumesAt is the instant every violated window has rolled over, or the zero
// time when that cannot be known.
//
// It is the *latest* reset among the violations, not the earliest: resuming
// when the 5-hour window reopens while the weekly cap is still tripped would
// pause the run again on its first task, and a fleet that does that every five
// hours is no better off than one that stalled. A single violation whose reset
// the API did not report makes the whole answer unknown for the same reason —
// a guess here parks a project for hours or hot-loops it against the wall.
func (e *CapExceededError) ResumesAt() time.Time {
	var latest time.Time
	for _, v := range e.Violations {
		if v.ResetsAt.IsZero() {
			return time.Time{}
		}
		if v.ResetsAt.After(latest) {
			latest = v.ResetsAt
		}
	}
	return latest
}

// Label names the tripped windows in the short form an operator reads on a
// project card: "5-hour cap reached", or "5-hour and weekly caps reached".
func (e *CapExceededError) Label() string {
	switch len(e.Violations) {
	case 0:
		return "subscription usage cap reached"
	case 1:
		return e.Violations[0].Label()
	}
	names := make([]string, 0, len(e.Violations))
	for _, v := range e.Violations {
		names = append(names, humanWindow(v.Window))
	}
	last := len(names) - 1
	return strings.Join(names[:last], ", ") + " and " + names[last] + " caps reached"
}

// EnforceClaudeCodeLimits returns a non-nil *CapExceededError when any of the
// per-project caps configured in cfg has been reached. Caller is responsible
// for fetching the usage snapshot (so that this check can be done without a
// network call when fresh cached data is available).
func EnforceClaudeCodeLimits(cfg config.ClaudeCodeConfig, usage *ClaudeUsage) error {
	violations := CheckClaudeCodeLimits(cfg, usage)
	if len(violations) == 0 {
		return nil
	}
	return &CapExceededError{Violations: violations}
}
