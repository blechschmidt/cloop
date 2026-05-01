// Package report generates rich project reports from cloop state.
package report

import (
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/cost"
	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/state"
)

// Format controls the output format of the report.
type Format string

const (
	FormatTerminal Format = "terminal"
	FormatMarkdown Format = "markdown"
)

// Options controls report generation.
type Options struct {
	Format      Format
	ShowOutputs bool // include step/task output excerpts
}

// Generate writes a project report to w based on the given state.
func Generate(w io.Writer, s *state.ProjectState, opts Options) {
	if opts.Format == FormatMarkdown {
		generateMarkdown(w, s, opts)
	} else {
		generateTerminal(w, s, opts)
	}
}

// statusEmoji maps status strings to visual indicators.
func statusEmoji(status string) string {
	switch status {
	case "complete":
		return "DONE"
	case "failed":
		return "FAIL"
	case "paused":
		return "PAUSED"
	case "running":
		return "RUNNING"
	default:
		return strings.ToUpper(status)
	}
}

func taskStatusEmoji(status pm.TaskStatus) string {
	switch status {
	case pm.TaskDone:
		return "[done]"
	case pm.TaskFailed:
		return "[fail]"
	case pm.TaskSkipped:
		return "[skip]"
	case pm.TaskInProgress:
		return "[...]"
	default:
		return "[ ]"
	}
}

func generateTerminal(w io.Writer, s *state.ProjectState, opts Options) {
	sep := strings.Repeat("─", 60)

	fmt.Fprintf(w, "\n%s\n", sep)
	fmt.Fprintf(w, "  cloop Project Report\n")
	fmt.Fprintf(w, "%s\n\n", sep)

	// Header
	fmt.Fprintf(w, "Goal:       %s\n", s.Goal)
	fmt.Fprintf(w, "Status:     %s\n", statusEmoji(s.Status))
	if s.Provider != "" {
		fmt.Fprintf(w, "Provider:   %s\n", s.Provider)
	}
	if s.Model != "" {
		fmt.Fprintf(w, "Model:      %s\n", s.Model)
	}
	fmt.Fprintf(w, "Created:    %s\n", s.CreatedAt.Format("2006-01-02 15:04:05"))
	fmt.Fprintf(w, "Updated:    %s\n", s.UpdatedAt.Format("2006-01-02 15:04:05"))
	elapsed := s.UpdatedAt.Sub(s.CreatedAt).Round(time.Second)
	fmt.Fprintf(w, "Duration:   %s\n", elapsed)

	// Token usage
	if s.TotalInputTokens > 0 || s.TotalOutputTokens > 0 {
		fmt.Fprintf(w, "Tokens:     %d in / %d out", s.TotalInputTokens, s.TotalOutputTokens)
		if s.Model != "" {
			if usd, ok := cost.Estimate(s.Model, s.TotalInputTokens, s.TotalOutputTokens); ok {
				fmt.Fprintf(w, " (~%s)", cost.FormatCost(usd))
			}
		}
		fmt.Fprintf(w, "\n")
	}

	// PM task summary
	if s.PMMode && s.Plan != nil && len(s.Plan.Tasks) > 0 {
		done, failed := s.Plan.CountByStatus()
		skipped := 0
		for _, t := range s.Plan.Tasks {
			if t.Status == pm.TaskSkipped {
				skipped++
				done-- // CountByStatus includes skipped in done
			}
		}
		total := len(s.Plan.Tasks)
		fmt.Fprintf(w, "\n%s\n", sep)
		fmt.Fprintf(w, "  Task Summary: %d/%d completed", done, total)
		if failed > 0 {
			fmt.Fprintf(w, ", %d failed", failed)
		}
		if skipped > 0 {
			fmt.Fprintf(w, ", %d skipped", skipped)
		}
		fmt.Fprintf(w, "\n%s\n\n", sep)

		// Sort tasks by ID for display
		tasks := make([]*pm.Task, len(s.Plan.Tasks))
		copy(tasks, s.Plan.Tasks)
		sort.Slice(tasks, func(i, j int) bool { return tasks[i].ID < tasks[j].ID })

		for _, t := range tasks {
			marker := taskStatusEmoji(t.Status)
			fmt.Fprintf(w, "  %s  [P%d] Task %d: %s\n", marker, t.Priority, t.ID, t.Title)
			if t.Description != "" {
				fmt.Fprintf(w, "           %s\n", truncate(t.Description, 100))
			}
			if t.StartedAt != nil && t.CompletedAt != nil {
				dur := t.CompletedAt.Sub(*t.StartedAt).Round(time.Second)
				fmt.Fprintf(w, "           Duration: %s\n", dur)
			}
			if opts.ShowOutputs && t.Result != "" {
				fmt.Fprintf(w, "           Result: %s\n", truncate(t.Result, 200))
			}
		}
	} else {
		// Loop mode: show steps
		fmt.Fprintf(w, "\n%s\n", sep)
		fmt.Fprintf(w, "  Steps: %d\n", s.CurrentStep)
		fmt.Fprintf(w, "%s\n", sep)

		if opts.ShowOutputs {
			for _, step := range s.Steps {
				fmt.Fprintf(w, "\nStep %d (%s): %s\n", step.Step+1, step.Duration,
					truncate(firstMeaningfulLine(step.Output), 120))
			}
		}
	}

	// Timeline
	if s.CreatedAt != (time.Time{}) {
		fmt.Fprintf(w, "\n%s\n", sep)
		fmt.Fprintf(w, "  Timeline\n")
		fmt.Fprintf(w, "%s\n", sep)
		fmt.Fprintf(w, "  %s  Project initialized\n", s.CreatedAt.Format("15:04:05"))
		if s.PMMode && s.Plan != nil {
			tasks := make([]*pm.Task, 0, len(s.Plan.Tasks))
			for _, t := range s.Plan.Tasks {
				if t.StartedAt != nil {
					tasks = append(tasks, t)
				}
			}
			sort.Slice(tasks, func(i, j int) bool {
				return tasks[i].StartedAt.Before(*tasks[j].StartedAt)
			})
			for _, t := range tasks {
				status := "started"
				ts := t.StartedAt
				if t.CompletedAt != nil {
					status = string(t.Status)
					ts = t.CompletedAt
				}
				fmt.Fprintf(w, "  %s  Task %d %s: %s\n", ts.Format("15:04:05"), t.ID, status, t.Title)
			}
		}
		fmt.Fprintf(w, "  %s  Last updated\n", s.UpdatedAt.Format("15:04:05"))
	}

	fmt.Fprintf(w, "\n%s\n\n", sep)
}

func generateMarkdown(w io.Writer, s *state.ProjectState, opts Options) {
	fmt.Fprintf(w, "# cloop Project Report\n\n")
	fmt.Fprintf(w, "**Goal:** %s\n\n", s.Goal)

	// Metadata table
	fmt.Fprintf(w, "| Field | Value |\n|---|---|\n")
	fmt.Fprintf(w, "| Status | %s |\n", s.Status)
	if s.Provider != "" {
		fmt.Fprintf(w, "| Provider | %s |\n", s.Provider)
	}
	if s.Model != "" {
		fmt.Fprintf(w, "| Model | %s |\n", s.Model)
	}
	fmt.Fprintf(w, "| Created | %s |\n", s.CreatedAt.Format("2006-01-02 15:04:05"))
	fmt.Fprintf(w, "| Updated | %s |\n", s.UpdatedAt.Format("2006-01-02 15:04:05"))
	elapsed := s.UpdatedAt.Sub(s.CreatedAt).Round(time.Second)
	fmt.Fprintf(w, "| Duration | %s |\n", elapsed)
	if s.TotalInputTokens > 0 || s.TotalOutputTokens > 0 {
		tokenStr := fmt.Sprintf("%d in / %d out", s.TotalInputTokens, s.TotalOutputTokens)
		if s.Model != "" {
			if usd, ok := cost.Estimate(s.Model, s.TotalInputTokens, s.TotalOutputTokens); ok {
				tokenStr += fmt.Sprintf(" (~%s)", cost.FormatCost(usd))
			}
		}
		fmt.Fprintf(w, "| Tokens | %s |\n", tokenStr)
	}
	fmt.Fprintf(w, "\n")

	// PM task table
	if s.PMMode && s.Plan != nil && len(s.Plan.Tasks) > 0 {
		done, failed := s.Plan.CountByStatus()
		skipped := 0
		for _, t := range s.Plan.Tasks {
			if t.Status == pm.TaskSkipped {
				skipped++
				done--
			}
		}
		total := len(s.Plan.Tasks)

		fmt.Fprintf(w, "## Task Summary\n\n")
		fmt.Fprintf(w, "**%d/%d completed**", done, total)
		if failed > 0 {
			fmt.Fprintf(w, " | **%d failed**", failed)
		}
		if skipped > 0 {
			fmt.Fprintf(w, " | %d skipped", skipped)
		}
		fmt.Fprintf(w, "\n\n")

		fmt.Fprintf(w, "| # | Priority | Status | Task | Duration |\n|---|---|---|---|---|\n")
		tasks := make([]*pm.Task, len(s.Plan.Tasks))
		copy(tasks, s.Plan.Tasks)
		sort.Slice(tasks, func(i, j int) bool { return tasks[i].ID < tasks[j].ID })
		for _, t := range tasks {
			dur := ""
			if t.StartedAt != nil && t.CompletedAt != nil {
				dur = t.CompletedAt.Sub(*t.StartedAt).Round(time.Second).String()
			}
			statusStr := string(t.Status)
			fmt.Fprintf(w, "| %d | P%d | %s | %s | %s |\n", t.ID, t.Priority, statusStr, t.Title, dur)
		}
		fmt.Fprintf(w, "\n")

		if opts.ShowOutputs {
			fmt.Fprintf(w, "## Task Details\n\n")
			for _, t := range tasks {
				fmt.Fprintf(w, "### Task %d: %s\n\n", t.ID, t.Title)
				if t.Description != "" {
					fmt.Fprintf(w, "**Description:** %s\n\n", t.Description)
				}
				fmt.Fprintf(w, "**Status:** %s\n\n", t.Status)
				if t.Result != "" {
					fmt.Fprintf(w, "**Result:**\n```\n%s\n```\n\n", truncate(t.Result, 500))
				}
			}
		}
	} else {
		fmt.Fprintf(w, "## Steps\n\n")
		fmt.Fprintf(w, "Total steps completed: **%d**\n\n", s.CurrentStep)
		if opts.ShowOutputs && len(s.Steps) > 0 {
			fmt.Fprintf(w, "| Step | Duration | Summary |\n|---|---|---|\n")
			for _, step := range s.Steps {
				fmt.Fprintf(w, "| %d | %s | %s |\n", step.Step+1, step.Duration,
					truncate(firstMeaningfulLine(step.Output), 80))
			}
			fmt.Fprintf(w, "\n")
		}
	}

	// Timeline
	if s.PMMode && s.Plan != nil && len(s.Plan.Tasks) > 0 {
		fmt.Fprintf(w, "## Timeline\n\n")
		fmt.Fprintf(w, "| Time | Event |\n|---|---|\n")
		fmt.Fprintf(w, "| %s | Project initialized |\n", s.CreatedAt.Format("15:04:05"))

		tasks := make([]*pm.Task, 0, len(s.Plan.Tasks))
		for _, t := range s.Plan.Tasks {
			if t.StartedAt != nil {
				tasks = append(tasks, t)
			}
		}
		sort.Slice(tasks, func(i, j int) bool {
			return tasks[i].StartedAt.Before(*tasks[j].StartedAt)
		})
		for _, t := range tasks {
			if t.CompletedAt != nil {
				fmt.Fprintf(w, "| %s | Task %d **%s**: %s |\n",
					t.CompletedAt.Format("15:04:05"), t.ID, t.Status, t.Title)
			}
		}
		fmt.Fprintf(w, "| %s | Last updated |\n", s.UpdatedAt.Format("15:04:05"))
		fmt.Fprintf(w, "\n")
	}

	fmt.Fprintf(w, "---\n*Generated by cloop*\n")
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

// firstMeaningfulLine returns the last non-empty, non-signal line from output.
func firstMeaningfulLine(output string) string {
	signals := map[string]bool{
		"GOAL_COMPLETE": true, "TASK_DONE": true, "TASK_SKIPPED": true, "TASK_FAILED": true,
	}
	lines := strings.Split(strings.TrimSpace(output), "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		line := strings.TrimSpace(lines[i])
		if line != "" && !signals[line] {
			return line
		}
	}
	return ""
}
