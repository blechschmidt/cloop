// Package retro provides AI-powered sprint retrospective analysis for cloop sessions.
// After a PM session completes (or at any point), it analyzes execution patterns,
// surfaces insights, and suggests concrete process improvements.
package retro

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/provider"
	"github.com/blechschmidt/cloop/pkg/state"
)

// Analysis is the structured output of a retrospective.
type Analysis struct {
	// HealthScore is an overall project health score from 1-10.
	HealthScore float64 `json:"health_score"`

	// Summary is a 1-2 sentence high-level assessment.
	Summary string `json:"summary"`

	// WentWell lists things that worked effectively.
	WentWell []string `json:"went_well"`

	// WentWrong lists failures, blockers, or inefficiencies.
	WentWrong []string `json:"went_wrong"`

	// Bottlenecks lists specific slow or blocked areas.
	Bottlenecks []string `json:"bottlenecks"`

	// Insights lists key learnings from the session.
	Insights []string `json:"insights"`

	// NextActions lists concrete recommended follow-up steps.
	NextActions []string `json:"next_actions"`

	// VelocityNotes is a human-readable assessment of task throughput.
	VelocityNotes string `json:"velocity_notes"`
}

// SessionStats holds computed metrics about a session.
type SessionStats struct {
	TotalTasks    int
	DoneTasks     int
	FailedTasks   int
	SkippedTasks  int
	PendingTasks  int
	AvgTaskDur    time.Duration
	TotalDuration time.Duration
	InputTokens   int
	OutputTokens  int
}

// ComputeStats derives session statistics from state.
func ComputeStats(s *state.ProjectState) SessionStats {
	stats := SessionStats{
		InputTokens:  s.TotalInputTokens,
		OutputTokens: s.TotalOutputTokens,
	}

	if s.Plan != nil {
		for _, t := range s.Plan.Tasks {
			stats.TotalTasks++
			switch t.Status {
			case pm.TaskDone:
				stats.DoneTasks++
			case pm.TaskFailed:
				stats.FailedTasks++
			case pm.TaskSkipped:
				stats.SkippedTasks++
			case pm.TaskPending, pm.TaskInProgress:
				stats.PendingTasks++
			}

			if t.StartedAt != nil && t.CompletedAt != nil {
				dur := t.CompletedAt.Sub(*t.StartedAt)
				stats.TotalDuration += dur
			}
		}

		if stats.DoneTasks+stats.FailedTasks+stats.SkippedTasks > 0 {
			completed := stats.DoneTasks + stats.FailedTasks + stats.SkippedTasks
			stats.AvgTaskDur = stats.TotalDuration / time.Duration(completed)
		}
	}

	return stats
}

// BuildPrompt constructs the retrospective analysis prompt.
func BuildPrompt(s *state.ProjectState, stats SessionStats) string {
	var b strings.Builder

	b.WriteString("You are an expert engineering manager performing a sprint retrospective.\n")
	b.WriteString("Analyze the following AI-driven project session and provide structured insights.\n\n")

	b.WriteString(fmt.Sprintf("## PROJECT GOAL\n%s\n\n", s.Goal))

	if s.Instructions != "" {
		b.WriteString(fmt.Sprintf("## CONSTRAINTS\n%s\n\n", s.Instructions))
	}

	// Session metrics
	b.WriteString("## SESSION METRICS\n")
	b.WriteString(fmt.Sprintf("- Status: %s\n", s.Status))
	b.WriteString(fmt.Sprintf("- Provider: %s\n", s.Provider))
	if s.Model != "" {
		b.WriteString(fmt.Sprintf("- Model: %s\n", s.Model))
	}
	b.WriteString(fmt.Sprintf("- Total steps: %d\n", s.CurrentStep))
	b.WriteString(fmt.Sprintf("- Input tokens: %d\n", stats.InputTokens))
	b.WriteString(fmt.Sprintf("- Output tokens: %d\n", stats.OutputTokens))
	if stats.TotalTasks > 0 {
		b.WriteString(fmt.Sprintf("- Tasks: %d total, %d done, %d failed, %d skipped, %d pending\n",
			stats.TotalTasks, stats.DoneTasks, stats.FailedTasks, stats.SkippedTasks, stats.PendingTasks))
		if stats.AvgTaskDur > 0 {
			b.WriteString(fmt.Sprintf("- Avg task duration: %s\n", stats.AvgTaskDur.Round(time.Second)))
		}
		if stats.TotalDuration > 0 {
			b.WriteString(fmt.Sprintf("- Total task time: %s\n", stats.TotalDuration.Round(time.Second)))
		}
	}
	b.WriteString("\n")

	// Task breakdown
	if s.Plan != nil && len(s.Plan.Tasks) > 0 {
		b.WriteString("## TASK BREAKDOWN\n")
		for _, t := range s.Plan.Tasks {
			statusIcon := map[pm.TaskStatus]string{
				pm.TaskDone:       "[DONE]",
				pm.TaskFailed:     "[FAIL]",
				pm.TaskSkipped:    "[SKIP]",
				pm.TaskPending:    "[PEND]",
				pm.TaskInProgress: "[PROG]",
			}[t.Status]

			durStr := ""
			if t.StartedAt != nil && t.CompletedAt != nil {
				dur := t.CompletedAt.Sub(*t.StartedAt).Round(time.Second)
				durStr = fmt.Sprintf(" (%s)", dur)
			}

			b.WriteString(fmt.Sprintf("- %s Task %d [P%d]: %s%s\n", statusIcon, t.ID, t.Priority, t.Title, durStr))

			if t.Result != "" {
				summary := t.Result
				if len(summary) > 200 {
					summary = summary[:200] + "..."
				}
				b.WriteString(fmt.Sprintf("  Result: %s\n", strings.ReplaceAll(summary, "\n", " ")))
			}
		}
		b.WriteString("\n")
	}

	// Recent step outputs for context
	if len(s.Steps) > 0 {
		recent := s.Steps
		if len(recent) > 5 {
			recent = recent[len(recent)-5:]
		}
		b.WriteString("## RECENT STEP OUTPUTS (last 5)\n")
		for _, step := range recent {
			output := step.Output
			if len(output) > 300 {
				output = output[:300] + "..."
			}
			b.WriteString(fmt.Sprintf("### %s (%s)\n%s\n\n", step.Task, step.Duration, output))
		}
	}

	b.WriteString("## ANALYSIS INSTRUCTIONS\n")
	b.WriteString("Perform a thorough retrospective analysis. Consider:\n")
	b.WriteString("- What execution patterns led to success or failure?\n")
	b.WriteString("- Were there any tasks that should have been broken down differently?\n")
	b.WriteString("- Did the task ordering/priority make sense?\n")
	b.WriteString("- What would improve the next run of this type of project?\n")
	b.WriteString("- Any patterns in failures that reveal systemic issues?\n\n")
	b.WriteString("Output ONLY valid JSON (no explanation, no markdown fence):\n")
	b.WriteString(`{`)
	b.WriteString(`"health_score":8.5,`)
	b.WriteString(`"summary":"One to two sentence overall assessment",`)
	b.WriteString(`"went_well":["specific thing 1","specific thing 2"],`)
	b.WriteString(`"went_wrong":["issue 1","issue 2"],`)
	b.WriteString(`"bottlenecks":["bottleneck 1"],`)
	b.WriteString(`"insights":["key learning 1","key learning 2"],`)
	b.WriteString(`"next_actions":["concrete step 1","concrete step 2"],`)
	b.WriteString(`"velocity_notes":"Assessment of task throughput and time distribution"`)
	b.WriteString(`}`)
	b.WriteString("\n\nProvide 2-5 items per list. Be specific and actionable, not generic.")
	return b.String()
}

// Analyze calls the provider to generate a retrospective analysis.
func Analyze(ctx context.Context, p provider.Provider, model string, timeout time.Duration, s *state.ProjectState) (*Analysis, error) {
	stats := ComputeStats(s)
	prompt := BuildPrompt(s, stats)

	result, err := p.Complete(ctx, prompt, provider.Options{
		Model:   model,
		Timeout: timeout,
	})
	if err != nil {
		return nil, fmt.Errorf("retro analysis: %w", err)
	}

	return ParseAnalysis(result.Output)
}

// ParseAnalysis extracts an Analysis from the AI's JSON response.
func ParseAnalysis(output string) (*Analysis, error) {
	start := strings.Index(output, "{")
	end := strings.LastIndex(output, "}")
	if start == -1 || end == -1 || end <= start {
		return nil, fmt.Errorf("no JSON found in response")
	}
	jsonStr := output[start : end+1]

	var a Analysis
	if err := json.Unmarshal([]byte(jsonStr), &a); err != nil {
		return nil, fmt.Errorf("parsing retro analysis: %w", err)
	}
	return &a, nil
}

// FormatMarkdown renders the analysis as a markdown report.
func FormatMarkdown(a *Analysis, s *state.ProjectState) string {
	var b strings.Builder

	b.WriteString("# Sprint Retrospective\n\n")
	b.WriteString(fmt.Sprintf("**Goal:** %s\n\n", s.Goal))
	b.WriteString(fmt.Sprintf("**Health Score:** %.1f/10\n\n", a.HealthScore))
	b.WriteString(fmt.Sprintf("**Summary:** %s\n\n", a.Summary))

	if len(a.WentWell) > 0 {
		b.WriteString("## What Went Well\n\n")
		for _, item := range a.WentWell {
			b.WriteString(fmt.Sprintf("- %s\n", item))
		}
		b.WriteString("\n")
	}

	if len(a.WentWrong) > 0 {
		b.WriteString("## What Went Wrong\n\n")
		for _, item := range a.WentWrong {
			b.WriteString(fmt.Sprintf("- %s\n", item))
		}
		b.WriteString("\n")
	}

	if len(a.Bottlenecks) > 0 {
		b.WriteString("## Bottlenecks\n\n")
		for _, item := range a.Bottlenecks {
			b.WriteString(fmt.Sprintf("- %s\n", item))
		}
		b.WriteString("\n")
	}

	if a.VelocityNotes != "" {
		b.WriteString("## Velocity\n\n")
		b.WriteString(a.VelocityNotes)
		b.WriteString("\n\n")
	}

	if len(a.Insights) > 0 {
		b.WriteString("## Key Insights\n\n")
		for _, item := range a.Insights {
			b.WriteString(fmt.Sprintf("- %s\n", item))
		}
		b.WriteString("\n")
	}

	if len(a.NextActions) > 0 {
		b.WriteString("## Recommended Next Actions\n\n")
		for i, item := range a.NextActions {
			b.WriteString(fmt.Sprintf("%d. %s\n", i+1, item))
		}
		b.WriteString("\n")
	}

	return b.String()
}
