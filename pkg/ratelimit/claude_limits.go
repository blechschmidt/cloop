// Package ratelimit - claude_limits.go enforces per-project caps on the
// global Claude Code subscription utilization (5-hour and weekly windows).
package ratelimit

import (
	"fmt"
	"strings"

	"github.com/blechschmidt/cloop/pkg/config"
)

// LimitViolation describes a single tripped per-project claudecode cap.
type LimitViolation struct {
	Window      string  // "weekly", "five_hour", "weekly_opus", "weekly_sonnet"
	Utilization float64 // current global utilization 0-100
	Cap         float64 // configured per-project cap 0-100
}

func (v LimitViolation) Error() string {
	return fmt.Sprintf(
		"claudecode %s utilization %.0f%% has reached the configured project cap of %.0f%%",
		humanWindow(v.Window), v.Utilization, v.Cap,
	)
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
			})
		}
	}
	check("weekly", cfg.MaxWeeklyPct, usage.SevenDay)
	check("five_hour", cfg.MaxFiveHourPct, usage.FiveHour)
	check("weekly_opus", cfg.MaxWeeklyOpusPct, usage.SevenDayOpus)
	check("weekly_sonnet", cfg.MaxWeeklySonnetPct, usage.SevenDaySonnet)
	return out
}

// EnforceClaudeCodeLimits returns a non-nil error when any of the per-project
// caps configured in cfg has been reached. Caller is responsible for fetching
// the usage snapshot (so that this check can be done without a network call
// when fresh cached data is available).
func EnforceClaudeCodeLimits(cfg config.ClaudeCodeConfig, usage *ClaudeUsage) error {
	violations := CheckClaudeCodeLimits(cfg, usage)
	if len(violations) == 0 {
		return nil
	}
	parts := make([]string, 0, len(violations))
	for _, v := range violations {
		parts = append(parts, v.Error())
	}
	return fmt.Errorf("claudecode usage cap reached: %s", strings.Join(parts, "; "))
}
