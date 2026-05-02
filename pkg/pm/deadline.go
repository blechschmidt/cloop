// Package pm — deadline and SLA helpers.
package pm

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// ParseDeadline parses a deadline string into an absolute time.Time.
// Accepted formats:
//   - Relative: "2h", "30m", "3d", "1w"  (hours, minutes, days, weeks from now)
//   - RFC3339:  "2025-12-31T23:59:00Z" or "2025-12-31T23:59:00+01:00"
//   - Date only: "2025-12-31" (interpreted as midnight UTC on that date)
func ParseDeadline(s string) (time.Time, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}, fmt.Errorf("empty deadline string")
	}

	// Try RFC3339 / date-only first.
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t, nil
	}
	if t, err := time.Parse("2006-01-02", s); err == nil {
		// Midnight UTC on that calendar day.
		return time.Date(t.Year(), t.Month(), t.Day(), 23, 59, 59, 0, time.UTC), nil
	}

	// Relative: <number><unit>  e.g. "3d", "2h", "30m", "1w"
	unit := s[len(s)-1:]
	numStr := s[:len(s)-1]
	n, err := strconv.Atoi(numStr)
	if err != nil || n <= 0 {
		return time.Time{}, fmt.Errorf("cannot parse deadline %q: use relative (e.g. '2h', '3d', '1w') or RFC3339", s)
	}
	now := time.Now()
	switch strings.ToLower(unit) {
	case "m":
		return now.Add(time.Duration(n) * time.Minute), nil
	case "h":
		return now.Add(time.Duration(n) * time.Hour), nil
	case "d":
		return now.AddDate(0, 0, n), nil
	case "w":
		return now.AddDate(0, 0, n*7), nil
	default:
		return time.Time{}, fmt.Errorf("unknown deadline unit %q: use m (minutes), h (hours), d (days), w (weeks)", unit)
	}
}

// IsOverdue returns true if the task has a deadline that has passed and the task
// is still pending or in-progress (done/skipped tasks are excluded).
func IsOverdue(t *Task) bool {
	if t.Deadline == nil {
		return false
	}
	if t.Status == TaskDone || t.Status == TaskSkipped {
		return false
	}
	return time.Now().After(*t.Deadline)
}

// TimeUntilDeadline returns the duration remaining until the task's deadline and
// whether the task has a deadline at all.  A negative value means overdue.
func TimeUntilDeadline(t *Task) (time.Duration, bool) {
	if t.Deadline == nil {
		return 0, false
	}
	return time.Until(*t.Deadline), true
}

// TimeUntilDeadlineD is a convenience wrapper that returns the raw duration
// (positive = time remaining, negative = overdue).  Returns 0 if no deadline.
func TimeUntilDeadlineD(t *Task) time.Duration {
	d, _ := TimeUntilDeadline(t)
	return d
}

// FormatCountdown formats a duration as a concise human-readable string.
//
//	Positive: "2d 3h", "4h 30m", "45m"
//	Zero / overdue: "OVERDUE (2h ago)"
func FormatCountdown(d time.Duration) string {
	if d <= 0 {
		ago := -d
		return "OVERDUE (" + formatDur(ago) + " ago)"
	}
	return "in " + formatDur(d)
}

// formatDur formats a positive duration with the two most significant units.
func formatDur(d time.Duration) string {
	d = d.Round(time.Minute)
	days := int(d.Hours()) / 24
	hours := int(d.Hours()) % 24
	mins := int(d.Minutes()) % 60

	if days >= 1 {
		if hours > 0 {
			return fmt.Sprintf("%dd %dh", days, hours)
		}
		return fmt.Sprintf("%dd", days)
	}
	if hours >= 1 {
		if mins > 0 {
			return fmt.Sprintf("%dh %dm", hours, mins)
		}
		return fmt.Sprintf("%dh", hours)
	}
	return fmt.Sprintf("%dm", mins)
}

// OverdueResult holds the result of an overdue check on a single task.
type OverdueResult struct {
	Task    *Task
	Overdue bool
	// OldPriority is the priority before boosting (0 if not boosted).
	OldPriority int
	// Boosted is true when the priority was changed.
	Boosted bool
}

// CheckAndBoostOverdue examines all tasks in the plan for missed deadlines.
// For each overdue task it:
//  1. Boosts priority to 1 (highest) if not already P1.
//  2. Returns the result so callers can fire notifications.
//
// The plan is mutated in place; callers should persist state after calling this.
func CheckAndBoostOverdue(plan *Plan) []OverdueResult {
	var results []OverdueResult
	if plan == nil {
		return nil
	}
	for _, t := range plan.Tasks {
		if !IsOverdue(t) {
			continue
		}
		r := OverdueResult{Task: t, Overdue: true}
		if t.Priority != 1 {
			r.OldPriority = t.Priority
			r.Boosted = true
			t.Priority = 1 // auto-boost to P1 (highest)
		}
		results = append(results, r)
	}
	return results
}

// SLAStats computes deadline compliance statistics for a plan.
type SLAStats struct {
	// Total number of tasks that had a deadline.
	Total int
	// Met is the number of tasks completed (done/skipped) before or by their deadline.
	Met int
	// Missed is the number of tasks that failed or are overdue past their deadline.
	Missed int
	// ComplianceRatio is Met/Total (NaN when Total==0).
	ComplianceRatio float64
}

// ComputeSLAStats calculates SLA compliance for a plan.
func ComputeSLAStats(plan *Plan) SLAStats {
	if plan == nil {
		return SLAStats{}
	}
	var stats SLAStats
	for _, t := range plan.Tasks {
		if t.Deadline == nil {
			continue
		}
		stats.Total++
		switch t.Status {
		case TaskDone, TaskSkipped:
			// Use CompletedAt if available; fall back to "now" (already done).
			completedAt := time.Now()
			if t.CompletedAt != nil {
				completedAt = *t.CompletedAt
			}
			if !completedAt.After(*t.Deadline) {
				stats.Met++
			} else {
				stats.Missed++
			}
		default:
			// Pending/in-progress/failed — if deadline passed, count as missed.
			if time.Now().After(*t.Deadline) {
				stats.Missed++
			}
		}
	}
	if stats.Total > 0 {
		stats.ComplianceRatio = float64(stats.Met) / float64(stats.Total)
	}
	return stats
}
