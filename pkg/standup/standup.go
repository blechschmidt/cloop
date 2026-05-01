// Package standup generates AI-powered daily standup reports for cloop projects.
// It analyzes recent task activity, current blockers, and upcoming work to produce
// a concise standup report suitable for sharing with stakeholders or posting to Slack.
package standup

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/insights"
	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/provider"
	"github.com/blechschmidt/cloop/pkg/state"
)

// Report holds a generated standup.
type Report struct {
	GeneratedAt time.Time
	WindowHours int

	// Tasks active in the window
	CompletedTasks  []*pm.Task
	FailedTasks     []*pm.Task
	StartedTasks    []*pm.Task
	InProgressTasks []*pm.Task
	BlockedTasks    []*pm.Task
	NextTasks       []*pm.Task // top pending, not blocked

	// Metrics
	Metrics *insights.Metrics

	// AI-generated narrative
	AIText string
}

// Sections are the parsed sections of a standup.
type Sections struct {
	Yesterday string
	Today     string
	Blockers  string
	Forecast  string
}

// Build computes a standup report from the current project state.
// windowHours controls how far back "yesterday" looks (default 24).
func Build(s *state.ProjectState, windowHours int) *Report {
	if windowHours <= 0 {
		windowHours = 24
	}
	cutoff := time.Now().Add(-time.Duration(windowHours) * time.Hour)

	r := &Report{
		GeneratedAt: time.Now(),
		WindowHours: windowHours,
		Metrics:     insights.Analyze(s),
	}

	if s.Plan == nil {
		return r
	}

	idToTask := make(map[int]*pm.Task, len(s.Plan.Tasks))
	for _, t := range s.Plan.Tasks {
		idToTask[t.ID] = t
	}

	for _, t := range s.Plan.Tasks {
		switch t.Status {
		case pm.TaskDone:
			if t.CompletedAt != nil && t.CompletedAt.After(cutoff) {
				r.CompletedTasks = append(r.CompletedTasks, t)
			}
		case pm.TaskFailed:
			if t.CompletedAt != nil && t.CompletedAt.After(cutoff) {
				r.FailedTasks = append(r.FailedTasks, t)
			}
		case pm.TaskInProgress:
			r.InProgressTasks = append(r.InProgressTasks, t)
			if t.StartedAt != nil && t.StartedAt.After(cutoff) {
				r.StartedTasks = append(r.StartedTasks, t)
			}
		case pm.TaskPending:
			if s.Plan.PermanentlyBlocked(t) {
				r.BlockedTasks = append(r.BlockedTasks, t)
			} else {
				r.NextTasks = append(r.NextTasks, t)
			}
		}
	}

	// Cap next tasks at top 5 by priority
	if len(r.NextTasks) > 5 {
		r.NextTasks = r.NextTasks[:5]
	}

	return r
}

// BuildPrompt creates the AI prompt for standup generation.
func BuildPrompt(goal string, r *Report, windowHours int) string {
	var b strings.Builder

	b.WriteString("You are an AI product manager writing a concise daily standup report.\n")
	b.WriteString("Use the project data below to produce a clear, factual standup.\n\n")

	b.WriteString(fmt.Sprintf("## PROJECT GOAL\n%s\n\n", goal))

	b.WriteString(fmt.Sprintf("## REPORTING WINDOW\nLast %d hours\n\n", windowHours))

	// Metrics
	m := r.Metrics
	b.WriteString("## PROJECT METRICS\n")
	b.WriteString(fmt.Sprintf("- Completion: %d%% (%d/%d tasks done)\n", m.CompletionPct(), m.DoneTasks, m.TotalTasks))
	if m.VelocityPerDay > 0 {
		b.WriteString(fmt.Sprintf("- Velocity: %.1f tasks/day\n", m.VelocityPerDay))
	}
	if m.EstimatedDaysRemaining >= 0 {
		b.WriteString(fmt.Sprintf("- Estimated days remaining: %.1f\n", m.EstimatedDaysRemaining))
	}
	b.WriteString(fmt.Sprintf("- Risk: %s (%d/100)\n", m.RiskLabel(), m.RiskScore))
	b.WriteString("\n")

	// Completed in window
	if len(r.CompletedTasks) > 0 {
		b.WriteString(fmt.Sprintf("## COMPLETED IN LAST %dh\n", windowHours))
		for _, t := range r.CompletedTasks {
			dur := ""
			if t.StartedAt != nil && t.CompletedAt != nil {
				dur = fmt.Sprintf(" [%s]", t.CompletedAt.Sub(*t.StartedAt).Round(time.Second))
			}
			b.WriteString(fmt.Sprintf("- Task %d [%s]%s: %s\n", t.ID, string(t.Role), dur, t.Title))
			if t.Result != "" {
				s := t.Result
				if len(s) > 120 {
					s = s[:120] + "..."
				}
				b.WriteString(fmt.Sprintf("  Result: %s\n", strings.ReplaceAll(s, "\n", " ")))
			}
		}
		b.WriteString("\n")
	}

	// Failed in window
	if len(r.FailedTasks) > 0 {
		b.WriteString(fmt.Sprintf("## FAILED IN LAST %dh\n", windowHours))
		for _, t := range r.FailedTasks {
			b.WriteString(fmt.Sprintf("- Task %d: %s\n", t.ID, t.Title))
			if t.Result != "" {
				s := t.Result
				if len(s) > 120 {
					s = s[:120] + "..."
				}
				b.WriteString(fmt.Sprintf("  Reason: %s\n", strings.ReplaceAll(s, "\n", " ")))
			}
		}
		b.WriteString("\n")
	}

	// In progress
	if len(r.InProgressTasks) > 0 {
		b.WriteString("## CURRENTLY IN PROGRESS\n")
		for _, t := range r.InProgressTasks {
			dur := ""
			if t.StartedAt != nil {
				dur = fmt.Sprintf(" (running %s)", time.Since(*t.StartedAt).Round(time.Minute))
			}
			b.WriteString(fmt.Sprintf("- Task %d [%s]%s: %s\n", t.ID, string(t.Role), dur, t.Title))
		}
		b.WriteString("\n")
	}

	// Blocked
	if len(r.BlockedTasks) > 0 {
		b.WriteString("## BLOCKED TASKS\n")
		for _, t := range r.BlockedTasks {
			b.WriteString(fmt.Sprintf("- Task %d: %s (blocked by failed dependencies)\n", t.ID, t.Title))
		}
		b.WriteString("\n")
	}

	// Next up
	if len(r.NextTasks) > 0 {
		b.WriteString("## NEXT PLANNED TASKS\n")
		for _, t := range r.NextTasks {
			b.WriteString(fmt.Sprintf("- Task %d [P%d, %s]: %s\n", t.ID, t.Priority, string(t.Role), t.Title))
		}
		b.WriteString("\n")
	}

	b.WriteString("## STANDUP FORMAT\n")
	b.WriteString("Write a concise daily standup report with EXACTLY these four sections.\n")
	b.WriteString("Each section should be 1-3 bullet points. Be specific, not generic.\n\n")
	b.WriteString("**Yesterday:**\n[What was accomplished in the reporting window]\n\n")
	b.WriteString("**Today:**\n[What the AI PM will focus on next — specific tasks]\n\n")
	b.WriteString("**Blockers:**\n[Any impediments, failed tasks, or risks — or 'None' if clear]\n\n")
	b.WriteString("**Forecast:**\n[One sentence on delivery timeline and confidence]\n")

	return b.String()
}

// ParseSections extracts the four standup sections from AI output.
func ParseSections(text string) Sections {
	var s Sections
	lines := strings.Split(text, "\n")

	var current *string
	var buf strings.Builder

	flush := func() {
		if current != nil {
			*current = strings.TrimSpace(buf.String())
		}
		buf.Reset()
	}

	for _, line := range lines {
		lower := strings.ToLower(strings.TrimSpace(line))
		switch {
		case strings.HasPrefix(lower, "**yesterday") || strings.HasPrefix(lower, "yesterday"):
			flush()
			current = &s.Yesterday
		case strings.HasPrefix(lower, "**today") || strings.HasPrefix(lower, "today"):
			flush()
			current = &s.Today
		case strings.HasPrefix(lower, "**blocker") || strings.HasPrefix(lower, "blocker"):
			flush()
			current = &s.Blockers
		case strings.HasPrefix(lower, "**forecast") || strings.HasPrefix(lower, "forecast"):
			flush()
			current = &s.Forecast
		default:
			if current != nil {
				buf.WriteString(line)
				buf.WriteString("\n")
			}
		}
	}
	flush()
	return s
}

// Generate calls the AI provider to produce a standup report.
func Generate(ctx context.Context, p provider.Provider, s *state.ProjectState, model string, windowHours int, timeout time.Duration, onToken func(string)) (*Report, error) {
	r := Build(s, windowHours)
	prompt := BuildPrompt(s.Goal, r, windowHours)

	result, err := p.Complete(ctx, prompt, provider.Options{
		Model:   model,
		Timeout: timeout,
		OnToken: onToken,
	})
	if err != nil {
		return nil, fmt.Errorf("standup: %w", err)
	}

	r.AIText = result.Output
	return r, nil
}

// FormatText renders the standup as plain text.
func FormatText(r *Report, goal string, windowHours int) string {
	var b strings.Builder

	b.WriteString(fmt.Sprintf("Daily Standup — %s\n", r.GeneratedAt.Format("Mon Jan 2, 2006 15:04")))
	b.WriteString(fmt.Sprintf("Project: %s\n", goal))
	b.WriteString(fmt.Sprintf("Window:  Last %dh\n\n", windowHours))
	b.WriteString(strings.Repeat("─", 60))
	b.WriteString("\n\n")
	b.WriteString(r.AIText)
	b.WriteString("\n\n")
	b.WriteString(strings.Repeat("─", 60))
	b.WriteString("\n")

	m := r.Metrics
	b.WriteString(fmt.Sprintf("Progress: %d%% • Velocity: %.1f tasks/day • Risk: %s\n",
		m.CompletionPct(), m.VelocityPerDay, m.RiskLabel()))

	return b.String()
}

// FormatSlack renders the standup for Slack (plain text, emoji-friendly).
func FormatSlack(r *Report, goal string, windowHours int) string {
	sections := ParseSections(r.AIText)
	var b strings.Builder

	m := r.Metrics

	b.WriteString(fmt.Sprintf(":clipboard: *Daily Standup* — %s\n", r.GeneratedAt.Format("Mon Jan 2")))
	b.WriteString(fmt.Sprintf("*Project:* %s\n", goal))
	b.WriteString(fmt.Sprintf("*Progress:* %d%% complete | Velocity: %.1f tasks/day | Risk: %s\n\n", m.CompletionPct(), m.VelocityPerDay, m.RiskLabel()))

	if sections.Yesterday != "" {
		b.WriteString(":white_check_mark: *Yesterday*\n")
		b.WriteString(indentLines(sections.Yesterday, "> "))
		b.WriteString("\n\n")
	}
	if sections.Today != "" {
		b.WriteString(":arrow_forward: *Today*\n")
		b.WriteString(indentLines(sections.Today, "> "))
		b.WriteString("\n\n")
	}
	if sections.Blockers != "" {
		b.WriteString(":warning: *Blockers*\n")
		b.WriteString(indentLines(sections.Blockers, "> "))
		b.WriteString("\n\n")
	}
	if sections.Forecast != "" {
		b.WriteString(":crystal_ball: *Forecast*\n")
		b.WriteString(indentLines(sections.Forecast, "> "))
		b.WriteString("\n")
	}

	return b.String()
}

func indentLines(text, prefix string) string {
	lines := strings.Split(strings.TrimSpace(text), "\n")
	var out []string
	for _, l := range lines {
		if strings.TrimSpace(l) != "" {
			out = append(out, prefix+strings.TrimSpace(l))
		}
	}
	return strings.Join(out, "\n")
}
