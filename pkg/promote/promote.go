// Package promote implements deadline-aware automatic priority escalation.
// It examines pending/in-progress tasks with deadlines and escalates their
// priority by 1 when the deadline is within the configured threshold (days).
// Tasks that block overdue tasks are also escalated.
package promote

import (
	"fmt"
	"time"

	"github.com/blechschmidt/cloop/pkg/pm"
)

// Promotion records a single priority escalation event.
type Promotion struct {
	TaskID      int
	Title       string
	OldPriority int
	NewPriority int
	Reason      string
}

// Run evaluates the plan and returns the list of promotions.
// When dryRun is false the task priorities in the plan are mutated in place;
// callers must persist state afterwards.
// thresholdDays is the number of days-remaining at which escalation is
// triggered (default 3; any task whose deadline is within this window and
// whose priority > 1 is promoted).
func Run(plan *pm.Plan, thresholdDays int, dryRun bool) []Promotion {
	if plan == nil || len(plan.Tasks) == 0 {
		return nil
	}
	if thresholdDays <= 0 {
		thresholdDays = 3
	}

	now := time.Now()
	threshold := time.Duration(thresholdDays) * 24 * time.Hour

	// Build a set of task IDs that are overdue (deadline < now, still active).
	overdueIDs := make(map[int]bool)
	for _, t := range plan.Tasks {
		if t.Deadline == nil {
			continue
		}
		if t.Status == pm.TaskDone || t.Status == pm.TaskSkipped {
			continue
		}
		if now.After(*t.Deadline) {
			overdueIDs[t.ID] = true
		}
	}

	// Index tasks by ID for dependency lookups.
	byID := make(map[int]*pm.Task, len(plan.Tasks))
	for _, t := range plan.Tasks {
		byID[t.ID] = t
	}

	// Collect promotions (de-duplicate by task ID).
	seen := make(map[int]bool)
	var promotions []Promotion

	for _, t := range plan.Tasks {
		if t.Status == pm.TaskDone || t.Status == pm.TaskSkipped ||
			t.Status == pm.TaskFailed || t.Status == pm.TaskTimedOut {
			continue
		}
		if t.Priority <= 1 {
			// Already at highest priority.
			continue
		}

		var reason string

		// Rule 1: task has a deadline within the threshold window.
		if t.Deadline != nil {
			remaining := t.Deadline.Sub(now)
			if remaining <= threshold {
				if now.After(*t.Deadline) {
					reason = fmt.Sprintf("overdue by %s", formatDur(-remaining))
				} else {
					reason = fmt.Sprintf("deadline in %s (within %dd threshold)", formatDur(remaining), thresholdDays)
				}
			}
		}

		// Rule 2: this task is a direct prerequisite (dependency) of an overdue task.
		// i.e. some overdue task has this task's ID in its DependsOn list.
		if reason == "" {
			for overdueID := range overdueIDs {
				overdueTsk := byID[overdueID]
				if overdueTsk == nil {
					continue
				}
				for _, depID := range overdueTsk.DependsOn {
					if depID == t.ID {
						reason = fmt.Sprintf("blocks overdue task #%d (%s)", overdueID, overdueTsk.Title)
						break
					}
				}
				if reason != "" {
					break
				}
			}
		}

		if reason == "" || seen[t.ID] {
			continue
		}
		seen[t.ID] = true

		p := Promotion{
			TaskID:      t.ID,
			Title:       t.Title,
			OldPriority: t.Priority,
			NewPriority: t.Priority - 1,
			Reason:      reason,
		}
		promotions = append(promotions, p)

		if !dryRun {
			t.Priority = p.NewPriority
		}
	}

	return promotions
}

// formatDur formats a positive duration as a compact human-readable string.
func formatDur(d time.Duration) string {
	d = d.Round(time.Minute)
	if d < 0 {
		d = -d
	}
	days := int(d.Hours()) / 24
	hours := int(d.Hours()) % 24
	mins := int(d.Minutes()) % 60

	if days >= 1 {
		if hours > 0 {
			return fmt.Sprintf("%dd%dh", days, hours)
		}
		return fmt.Sprintf("%dd", days)
	}
	if hours >= 1 {
		if mins > 0 {
			return fmt.Sprintf("%dh%dm", hours, mins)
		}
		return fmt.Sprintf("%dh", hours)
	}
	return fmt.Sprintf("%dm", mins)
}
