// Package ratelimit - claude_limits.go enforces per-project caps on the
// global Claude Code subscription utilization (5-hour and weekly windows),
// and keeps a run out of a window that is exhausted outright, where Claude
// Code would start billing extra usage.
package ratelimit

import (
	"fmt"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/config"
)

// LimitViolation describes a single tripped per-project claudecode cap, or a
// window exhausted outright while budget.block_extra_usage is on.
type LimitViolation struct {
	Window      string  // "weekly", "five_hour", "weekly_opus", "weekly_sonnet"
	Utilization float64 // current global utilization 0-100
	Cap         float64 // configured per-project cap 0-100; 100 for ExtraUsage
	// ResetsAt is when this window rolls over, as reported by the OAuth
	// usage API. Zero when the API did not say — the snapshot omits the
	// window's reset, or it was served from a cache written before the
	// field existed. A caller must treat zero as "unknown", never as "now".
	ResetsAt time.Time
	// ExtraUsage marks a window that is not over a configured cap but used
	// up entirely, so the next request would be billed as extra usage. See
	// CheckExhaustedWindows.
	ExtraUsage bool
}

func (v LimitViolation) Error() string {
	if v.ExtraUsage {
		// The wording an operator already knows from the budget check this
		// used to be (Task 20440), with "holding" for "pausing": the run now
		// waits out a window that reopens soon instead of always pausing.
		return fmt.Sprintf(
			"Claude Code %s window exhausted (%.0f%%) — holding the run to avoid extra usage (set budget.block_extra_usage: false to allow)",
			humanWindow(v.Window), v.Utilization,
		)
	}
	return fmt.Sprintf(
		"claudecode %s utilization %.0f%% has reached the configured project cap of %.0f%%",
		humanWindow(v.Window), v.Utilization, v.Cap,
	)
}

// Label is the short operator-facing phrase for this violation, the form that
// reads well after "Paused:" — "5-hour cap reached", or "5-hour window
// exhausted" for one budget.block_extra_usage stopped.
func (v LimitViolation) Label() string {
	if v.ExtraUsage {
		return fmt.Sprintf("%s window exhausted", humanWindow(v.Window))
	}
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

// At returns the snapshot as it stands at now: a window whose reported reset
// has already passed is left out, because the figure describes a window that
// has since rolled over. The receiver, which may be the shared cached
// snapshot, is not modified.
//
// Without it a tripped window outlives its own reset whenever the snapshot is
// older than the reset — the one-minute cache, a usage API that lags the
// rollover, or one that keeps failing, in which case the cache keeps serving
// the last snapshot it had. A run would then hold off on every check after the
// window reopened, for as long as the API stayed unreadable (Task 20440). A
// window with no reported reset is kept: nothing says it rolled over.
func (u *ClaudeUsage) At(now time.Time) *ClaudeUsage {
	if u == nil {
		return nil
	}
	out := *u
	current := func(w *UsageDetail) *UsageDetail {
		if w != nil && !w.ResetsAt.IsZero() && !now.Before(w.ResetsAt) {
			return nil
		}
		return w
	}
	out.FiveHour = current(u.FiveHour)
	out.SevenDay = current(u.SevenDay)
	out.SevenDayOpus = current(u.SevenDayOpus)
	out.SevenDaySonnet = current(u.SevenDaySonnet)
	return &out
}

// CheckExhaustedWindows returns the windows a usage snapshot shows used up —
// at 100% or more — which is where Claude Code stops drawing on the
// subscription and starts billing extra usage. budget.block_extra_usage (on by
// default) holds a run out of exactly these.
//
// The weekly Opus window is not among them: running out of it moves Claude
// Code to another model rather than onto extra usage, which is why the budget
// check this replaces never looked at it.
//
// usage may be nil, in which case nothing is exhausted that anyone knows of.
func CheckExhaustedWindows(usage *ClaudeUsage) []LimitViolation {
	if usage == nil {
		return nil
	}
	var out []LimitViolation
	check := func(name string, w *UsageDetail) {
		if w == nil || w.Utilization < 100 {
			return
		}
		out = append(out, LimitViolation{
			Window:      name,
			Utilization: w.Utilization,
			Cap:         100,
			ResetsAt:    w.ResetsAt,
			ExtraUsage:  true,
		})
	}
	// The same order as CheckClaudeCodeLimits, so a label naming several
	// windows reads the same whichever check found them.
	check("weekly", usage.SevenDay)
	check("five_hour", usage.FiveHour)
	check("weekly_sonnet", usage.SevenDaySonnet)
	return out
}

// CapExceededError is the error EnforceClaudeCodeLimits and
// EnforceSubscriptionLimits return when a cap has been reached or a window is
// exhausted. It carries the violations themselves so the caller can record
// when the run may resume instead of only being able to print why it stopped.
type CapExceededError struct {
	Violations []LimitViolation
}

func (e *CapExceededError) Error() string {
	parts := make([]string, 0, len(e.Violations))
	capped := false
	for _, v := range e.Violations {
		parts = append(parts, v.Error())
		capped = capped || !v.ExtraUsage
	}
	msg := strings.Join(parts, "; ")
	if !capped {
		// An exhausted window says what happened on its own; "usage cap
		// reached" in front of it would name a cap nobody configured.
		return msg
	}
	return "claudecode usage cap reached: " + msg
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
// project card: "5-hour cap reached", "5-hour and weekly caps reached", or —
// for windows budget.block_extra_usage stopped — "5-hour window exhausted".
func (e *CapExceededError) Label() string {
	switch len(e.Violations) {
	case 0:
		return "subscription usage cap reached"
	case 1:
		return e.Violations[0].Label()
	}
	names := make([]string, 0, len(e.Violations))
	labels := make([]string, 0, len(e.Violations))
	caps, exhausted := 0, 0
	for _, v := range e.Violations {
		names = append(names, humanWindow(v.Window))
		labels = append(labels, v.Label())
		if v.ExtraUsage {
			exhausted++
		} else {
			caps++
		}
	}
	switch {
	case exhausted == 0:
		return joinAnd(names) + " caps reached"
	case caps == 0:
		return joinAnd(names) + " windows exhausted"
	}
	// One of each kind: each says what it is.
	return joinAnd(labels)
}

// joinAnd renders "a", "a and b", "a, b and c".
func joinAnd(items []string) string {
	if len(items) < 2 {
		return strings.Join(items, "")
	}
	last := len(items) - 1
	return strings.Join(items[:last], ", ") + " and " + items[last]
}

// EnforceClaudeCodeLimits returns a non-nil *CapExceededError when any of the
// per-project caps configured in cfg has been reached. Caller is responsible
// for fetching the usage snapshot (so that this check can be done without a
// network call when fresh cached data is available).
func EnforceClaudeCodeLimits(cfg config.ClaudeCodeConfig, usage *ClaudeUsage) error {
	return EnforceSubscriptionLimits(cfg, false, usage)
}

// EnforceSubscriptionLimits is the check a run makes before each task to stay
// inside the Claude Code subscription: the per-project caps configured in cfg
// and, when blockExtra (budget.block_extra_usage) is set, every window
// CheckExhaustedWindows finds used up.
//
// The two used to be separate. The exhausted-window half lived in the daily
// budget check and stopped a run with a plain error, so the run was recorded
// as a budget pause with no reset time — and the hub, which restarts only
// usage-cap pauses whose window has rolled over, left it paused until somebody
// pressed Run (Task 20440). Returned together, both carry their windows'
// resets, and the caller treats them the same way.
//
// A window that is both over its cap and exhausted is reported once, as the
// cap: a cap is at most 100%, so it trips first and says more.
func EnforceSubscriptionLimits(cfg config.ClaudeCodeConfig, blockExtra bool, usage *ClaudeUsage) error {
	violations := CheckClaudeCodeLimits(cfg, usage)
	if blockExtra {
		capped := make(map[string]bool, len(violations))
		for _, v := range violations {
			capped[v.Window] = true
		}
		for _, v := range CheckExhaustedWindows(usage) {
			if !capped[v.Window] {
				violations = append(violations, v)
			}
		}
	}
	if len(violations) == 0 {
		return nil
	}
	return &CapExceededError{Violations: violations}
}
