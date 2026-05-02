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

// SLASection renders SLA compliance stats for inclusion in retro output.
// Returns empty string when there are no tasks with deadlines.
func SLASection(plan *pm.Plan) string {
	stats := pm.ComputeSLAStats(plan)
	if stats.Total == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString(fmt.Sprintf("- SLA tasks: %d total, %d met, %d missed (compliance: %.0f%%)\n",
		stats.Total, stats.Met, stats.Missed, stats.ComplianceRatio*100))
	return b.String()
}

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

	// LessonsLearned is an AI-written narrative of lessons learned.
	LessonsLearned string `json:"lessons_learned"`

	// ProcessImprovements is an AI-written narrative of suggested process improvements.
	ProcessImprovements string `json:"process_improvements"`
}

// TaskTimeComparison holds per-task estimated vs actual time data.
type TaskTimeComparison struct {
	TaskID           int
	Title            string
	Status           pm.TaskStatus
	EstimatedMinutes int
	ActualMinutes    int
	// WallClockMinutes is derived from StartedAt/CompletedAt when ActualMinutes is 0.
	WallClockMinutes int
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

// ComputeTimeComparisons builds per-task estimated vs actual time data.
func ComputeTimeComparisons(plan *pm.Plan) []TaskTimeComparison {
	if plan == nil {
		return nil
	}
	var out []TaskTimeComparison
	for _, t := range plan.Tasks {
		tc := TaskTimeComparison{
			TaskID:           t.ID,
			Title:            t.Title,
			Status:           t.Status,
			EstimatedMinutes: t.EstimatedMinutes,
			ActualMinutes:    t.ActualMinutes,
		}
		if tc.ActualMinutes == 0 && t.StartedAt != nil && t.CompletedAt != nil {
			tc.WallClockMinutes = int(t.CompletedAt.Sub(*t.StartedAt).Minutes())
		}
		out = append(out, tc)
	}
	return out
}

// BuildPrompt constructs the retrospective analysis prompt.
func BuildPrompt(s *state.ProjectState, stats SessionStats) string {
	var plan *pm.Plan
	if s != nil {
		plan = s.Plan
	}
	return buildPromptInternal(s, stats, plan, "")
}

// buildPromptInternal is the shared prompt builder for both Analyze and Generate.
func buildPromptInternal(s *state.ProjectState, stats SessionStats, plan *pm.Plan, costSummary string) string {
	var b strings.Builder

	b.WriteString("You are an expert engineering manager performing a sprint retrospective.\n")
	b.WriteString("Analyze the following AI-driven project session and provide structured insights.\n\n")

	if s != nil {
		b.WriteString(fmt.Sprintf("## PROJECT GOAL\n%s\n\n", s.Goal))
		if s.Instructions != "" {
			b.WriteString(fmt.Sprintf("## CONSTRAINTS\n%s\n\n", s.Instructions))
		}
	} else if plan != nil {
		b.WriteString(fmt.Sprintf("## PROJECT GOAL\n%s\n\n", plan.Goal))
	}

	// Session metrics
	b.WriteString("## SESSION METRICS\n")
	if s != nil {
		b.WriteString(fmt.Sprintf("- Status: %s\n", s.Status))
		b.WriteString(fmt.Sprintf("- Provider: %s\n", s.Provider))
		if s.Model != "" {
			b.WriteString(fmt.Sprintf("- Model: %s\n", s.Model))
		}
		b.WriteString(fmt.Sprintf("- Total steps: %d\n", s.CurrentStep))
		b.WriteString(fmt.Sprintf("- Input tokens: %d\n", stats.InputTokens))
		b.WriteString(fmt.Sprintf("- Output tokens: %d\n", stats.OutputTokens))
	}
	if stats.TotalTasks > 0 {
		pct := func(n int) string {
			if stats.TotalTasks == 0 {
				return "0%"
			}
			return fmt.Sprintf("%.0f%%", float64(n)/float64(stats.TotalTasks)*100)
		}
		b.WriteString(fmt.Sprintf("- Tasks: %d total, %d done (%s), %d failed (%s), %d skipped (%s), %d pending (%s)\n",
			stats.TotalTasks,
			stats.DoneTasks, pct(stats.DoneTasks),
			stats.FailedTasks, pct(stats.FailedTasks),
			stats.SkippedTasks, pct(stats.SkippedTasks),
			stats.PendingTasks, pct(stats.PendingTasks),
		))
		if stats.AvgTaskDur > 0 {
			b.WriteString(fmt.Sprintf("- Avg task duration: %s\n", stats.AvgTaskDur.Round(time.Second)))
		}
		if stats.TotalDuration > 0 {
			b.WriteString(fmt.Sprintf("- Total task time: %s\n", stats.TotalDuration.Round(time.Second)))
		}
	}
	if costSummary != "" {
		b.WriteString(fmt.Sprintf("- Cost: %s\n", costSummary))
	}
	// SLA compliance
	if plan != nil {
		if slaStr := SLASection(plan); slaStr != "" {
			b.WriteString(slaStr)
		}
	}
	b.WriteString("\n")

	// Task breakdown with estimated vs actual time
	if plan != nil && len(plan.Tasks) > 0 {
		b.WriteString("## TASK BREAKDOWN (with time estimates)\n")
		hasTimeData := false
		for _, t := range plan.Tasks {
			if t.EstimatedMinutes > 0 || t.ActualMinutes > 0 {
				hasTimeData = true
				break
			}
		}
		for _, t := range plan.Tasks {
			statusIcon := map[pm.TaskStatus]string{
				pm.TaskDone:       "[DONE]",
				pm.TaskFailed:     "[FAIL]",
				pm.TaskSkipped:    "[SKIP]",
				pm.TaskPending:    "[PEND]",
				pm.TaskInProgress: "[PROG]",
			}[t.Status]

			var timeParts []string
			if hasTimeData {
				if t.EstimatedMinutes > 0 {
					timeParts = append(timeParts, fmt.Sprintf("est=%dm", t.EstimatedMinutes))
				}
				actual := t.ActualMinutes
				if actual == 0 && t.StartedAt != nil && t.CompletedAt != nil {
					actual = int(t.CompletedAt.Sub(*t.StartedAt).Minutes())
				}
				if actual > 0 {
					timeParts = append(timeParts, fmt.Sprintf("actual=%dm", actual))
					if t.EstimatedMinutes > 0 {
						delta := actual - t.EstimatedMinutes
						if delta > 0 {
							timeParts = append(timeParts, fmt.Sprintf("over=%dm", delta))
						} else if delta < 0 {
							timeParts = append(timeParts, fmt.Sprintf("under=%dm", -delta))
						}
					}
				}
			} else if t.StartedAt != nil && t.CompletedAt != nil {
				dur := t.CompletedAt.Sub(*t.StartedAt).Round(time.Second)
				timeParts = append(timeParts, fmt.Sprintf("dur=%s", dur))
			}

			timeStr := ""
			if len(timeParts) > 0 {
				timeStr = " (" + strings.Join(timeParts, ", ") + ")"
			}

			b.WriteString(fmt.Sprintf("- %s Task %d [P%d]: %s%s\n", statusIcon, t.ID, t.Priority, t.Title, timeStr))

			if t.Result != "" {
				summary := t.Result
				if len(summary) > 200 {
					summary = summary[:200] + "..."
				}
				b.WriteString(fmt.Sprintf("  Result: %s\n", strings.ReplaceAll(summary, "\n", " ")))
			}
			if t.FailureDiagnosis != "" {
				b.WriteString(fmt.Sprintf("  Diagnosis: %s\n", strings.ReplaceAll(t.FailureDiagnosis[:min(len(t.FailureDiagnosis), 150)], "\n", " ")))
			}
			if len(t.Links) > 0 {
				for _, lnk := range t.Links {
					label := lnk.Label
					if label == "" {
						label = lnk.URL
					}
					b.WriteString(fmt.Sprintf("  Link [%s]: %s\n", lnk.Kind, label))
				}
			}
		}
		b.WriteString("\n")
	}

	// Recent step outputs for context
	if s != nil && len(s.Steps) > 0 {
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

	// SLA section in the AI prompt
	if plan != nil {
		if slaStr := SLASection(plan); slaStr != "" {
			b.WriteString("## SLA COMPLIANCE\n")
			b.WriteString(slaStr)
			b.WriteString("\n")
		}
	}

	b.WriteString("## ANALYSIS INSTRUCTIONS\n")
	b.WriteString("Perform a thorough retrospective analysis. Consider:\n")
	b.WriteString("- What execution patterns led to success or failure?\n")
	b.WriteString("- Were there any tasks that should have been broken down differently?\n")
	b.WriteString("- Did the task ordering/priority make sense?\n")
	b.WriteString("- Were estimated times accurate? What caused overruns or underruns?\n")
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
	b.WriteString(`"velocity_notes":"Assessment of task throughput and time distribution",`)
	b.WriteString(`"lessons_learned":"Multi-sentence narrative of the key lessons learned from this plan execution",`)
	b.WriteString(`"process_improvements":"Multi-sentence narrative of concrete process improvements for the next run"`)
	b.WriteString(`}`)
	b.WriteString("\n\nProvide 2-5 items per list. Be specific and actionable, not generic.")
	return b.String()
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// Analyze calls the provider to generate a retrospective analysis from full session state.
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

// Generate produces a retrospective report from a plan and an optional cost summary string.
// It is the primary entry point when the full session state is unavailable.
func Generate(ctx context.Context, p provider.Provider, model string, timeout time.Duration, plan *pm.Plan, costSummary string) (*Analysis, error) {
	// Build synthetic stats from the plan alone.
	stats := SessionStats{}
	for _, t := range plan.Tasks {
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
			stats.TotalDuration += t.CompletedAt.Sub(*t.StartedAt)
		}
	}
	if stats.DoneTasks+stats.FailedTasks+stats.SkippedTasks > 0 {
		completed := stats.DoneTasks + stats.FailedTasks + stats.SkippedTasks
		stats.AvgTaskDur = stats.TotalDuration / time.Duration(completed)
	}

	prompt := buildPromptInternal(nil, stats, plan, costSummary)

	result, err := p.Complete(ctx, prompt, provider.Options{
		Model:   model,
		Timeout: timeout,
	})
	if err != nil {
		return nil, fmt.Errorf("retro generate: %w", err)
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

// FormatMarkdown renders the analysis as a comprehensive markdown retrospective report.
// plan is optional; when non-nil a task time comparison table is included.
// costSummary is optional; when non-empty a cost section is included.
func FormatMarkdown(a *Analysis, s *state.ProjectState) string {
	var plan *pm.Plan
	var goal string
	if s != nil {
		plan = s.Plan
		goal = s.Goal
	}
	return FormatMarkdownFull(a, goal, plan, "")
}

// FormatMarkdownFull is the full renderer used by both Analyze (state-based) and Generate (plan-based).
// journalSummaries is an optional map of task ID string → AI-generated journal summary.
func FormatMarkdownFull(a *Analysis, goal string, plan *pm.Plan, costSummary string) string {
	return FormatMarkdownFullWithJournal(a, goal, plan, costSummary, nil)
}

// FormatMarkdownFullWithJournal is like FormatMarkdownFull but also renders per-task journal summaries.
// journalSummaries maps task ID string → AI-generated narrative summary from the journal.
func FormatMarkdownFullWithJournal(a *Analysis, goal string, plan *pm.Plan, costSummary string, journalSummaries map[string]string) string {
	var b strings.Builder

	b.WriteString("# Plan Retrospective\n\n")
	if goal != "" {
		b.WriteString(fmt.Sprintf("**Goal:** %s\n\n", goal))
	}
	b.WriteString(fmt.Sprintf("**Health Score:** %.1f / 10\n\n", a.HealthScore))

	if a.Summary != "" {
		b.WriteString("## Executive Summary\n\n")
		b.WriteString(a.Summary)
		b.WriteString("\n\n")
	}

	// Task breakdown table
	if plan != nil && len(plan.Tasks) > 0 {
		var done, failed, skipped, pending int
		for _, t := range plan.Tasks {
			switch t.Status {
			case pm.TaskDone:
				done++
			case pm.TaskFailed:
				failed++
			case pm.TaskSkipped:
				skipped++
			default:
				pending++
			}
		}
		total := len(plan.Tasks)
		pct := func(n int) string {
			return fmt.Sprintf("%.0f%%", float64(n)/float64(total)*100)
		}
		b.WriteString("## Task Summary\n\n")
		b.WriteString(fmt.Sprintf("| Status | Count | %% |\n|--------|-------|----|\n"))
		b.WriteString(fmt.Sprintf("| Done | %d | %s |\n", done, pct(done)))
		b.WriteString(fmt.Sprintf("| Failed | %d | %s |\n", failed, pct(failed)))
		b.WriteString(fmt.Sprintf("| Skipped | %d | %s |\n", skipped, pct(skipped)))
		b.WriteString(fmt.Sprintf("| Pending | %d | %s |\n", pending, pct(pending)))
		b.WriteString(fmt.Sprintf("| **Total** | **%d** | **100%%** |\n", total))
		b.WriteString("\n")

		// Time comparison table (only if any task has time data)
		comparisons := ComputeTimeComparisons(plan)
		hasTime := false
		for _, tc := range comparisons {
			if tc.EstimatedMinutes > 0 || tc.ActualMinutes > 0 || tc.WallClockMinutes > 0 {
				hasTime = true
				break
			}
		}
		if hasTime {
			b.WriteString("## Estimated vs Actual Time\n\n")
			b.WriteString("| Task | Status | Est (min) | Actual (min) | Delta |\n")
			b.WriteString("|------|--------|-----------|--------------|-------|\n")
			for _, tc := range comparisons {
				actual := tc.ActualMinutes
				if actual == 0 {
					actual = tc.WallClockMinutes
				}
				deltaStr := "—"
				if tc.EstimatedMinutes > 0 && actual > 0 {
					delta := actual - tc.EstimatedMinutes
					if delta > 0 {
						deltaStr = fmt.Sprintf("+%dm", delta)
					} else if delta < 0 {
						deltaStr = fmt.Sprintf("%dm", delta)
					} else {
						deltaStr = "on time"
					}
				}
				estStr := "—"
				if tc.EstimatedMinutes > 0 {
					estStr = fmt.Sprintf("%d", tc.EstimatedMinutes)
				}
				actualStr := "—"
				if actual > 0 {
					actualStr = fmt.Sprintf("%d", actual)
				}
				b.WriteString(fmt.Sprintf("| Task %d: %s | %s | %s | %s | %s |\n",
					tc.TaskID, truncateMd(tc.Title, 40), tc.Status, estStr, actualStr, deltaStr))
			}
			b.WriteString("\n")
		}
	}

	// Per-task journal summaries
	if len(journalSummaries) > 0 && plan != nil {
		b.WriteString("## Task Decision Journals\n\n")
		for _, t := range plan.Tasks {
			key := fmt.Sprintf("%d", t.ID)
			summary, ok := journalSummaries[key]
			if !ok || summary == "" || summary == "(no journal entries)" {
				continue
			}
			b.WriteString(fmt.Sprintf("### Task %d: %s\n\n", t.ID, t.Title))
			b.WriteString(summary)
			b.WriteString("\n\n")
		}
	}

	// SLA compliance
	if plan != nil {
		sla := pm.ComputeSLAStats(plan)
		if sla.Total > 0 {
			pct := int(sla.ComplianceRatio * 100)
			b.WriteString("## SLA Compliance\n\n")
			b.WriteString(fmt.Sprintf("| Metric | Value |\n|--------|-------|\n"))
			b.WriteString(fmt.Sprintf("| Tasks with deadlines | %d |\n", sla.Total))
			b.WriteString(fmt.Sprintf("| Met on time | %d |\n", sla.Met))
			b.WriteString(fmt.Sprintf("| Missed | %d |\n", sla.Missed))
			b.WriteString(fmt.Sprintf("| Compliance ratio | **%d%%** |\n", pct))
			b.WriteString("\n")
		}
	}

	// Cost summary
	if costSummary != "" {
		b.WriteString("## Provider Cost\n\n")
		b.WriteString(costSummary)
		b.WriteString("\n\n")
	}

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

	if a.LessonsLearned != "" {
		b.WriteString("## Lessons Learned\n\n")
		b.WriteString(a.LessonsLearned)
		b.WriteString("\n\n")
	}

	if a.ProcessImprovements != "" {
		b.WriteString("## Process Improvements\n\n")
		b.WriteString(a.ProcessImprovements)
		b.WriteString("\n\n")
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

func truncateMd(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}
