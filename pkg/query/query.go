// Package query provides natural-language plan search powered by an AI provider.
// It serialises the current plan into a compact context block and submits the
// user's question to the provider, returning a plain-text answer.
package query

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/provider"
)

// Query answers a natural-language question about the given plan.
// plan must not be nil. question is the free-form user query.
// model may be empty (the provider will use its default).
// The raw provider response is returned as-is (trimmed of leading/trailing whitespace).
func Query(ctx context.Context, p provider.Provider, model string, plan *pm.Plan, question string) (string, error) {
	if plan == nil {
		return "", fmt.Errorf("no plan loaded")
	}
	if strings.TrimSpace(question) == "" {
		return "", fmt.Errorf("question must not be empty")
	}

	prompt := buildPrompt(plan, question)
	result, err := p.Complete(ctx, prompt, provider.Options{
		Model:   model,
		Timeout: 2 * time.Minute,
	})
	if err != nil {
		return "", fmt.Errorf("query: %w", err)
	}
	return strings.TrimSpace(result.Output), nil
}

// buildPrompt serialises the plan into a compact context block and appends the question.
func buildPrompt(plan *pm.Plan, question string) string {
	var b strings.Builder

	b.WriteString("You are an expert project manager assistant. ")
	b.WriteString("The following is a structured description of the current task plan. ")
	b.WriteString("Answer the user's question based solely on this information.\n\n")

	b.WriteString("## PLAN GOAL\n")
	b.WriteString(plan.Goal)
	b.WriteString("\n\n")

	b.WriteString("## TASKS\n")
	for _, t := range plan.Tasks {
		// Status + ID + title line
		b.WriteString(fmt.Sprintf("[%s] #%d (P%d) %s", statusLabel(t.Status), t.ID, t.Priority, t.Title))
		if t.Role != "" {
			b.WriteString(fmt.Sprintf(" [role:%s]", t.Role))
		}
		b.WriteString("\n")

		if t.Description != "" {
			b.WriteString(fmt.Sprintf("  desc: %s\n", singleLine(t.Description, 200)))
		}
		if len(t.DependsOn) > 0 {
			parts := make([]string, 0, len(t.DependsOn))
			for _, depID := range t.DependsOn {
				parts = append(parts, fmt.Sprintf("#%d", depID))
			}
			b.WriteString(fmt.Sprintf("  depends_on: %s\n", strings.Join(parts, ", ")))
		}
		if len(t.Tags) > 0 {
			b.WriteString(fmt.Sprintf("  tags: %s\n", strings.Join(t.Tags, ", ")))
		}
		if t.FailCount > 0 {
			b.WriteString(fmt.Sprintf("  fail_count: %d\n", t.FailCount))
		}
		if t.FailureDiagnosis != "" {
			b.WriteString(fmt.Sprintf("  failure_diagnosis: %s\n", singleLine(t.FailureDiagnosis, 200)))
		}
		if t.EstimatedMinutes > 0 {
			b.WriteString(fmt.Sprintf("  estimated_minutes: %d\n", t.EstimatedMinutes))
		}
		if t.ActualMinutes > 0 {
			b.WriteString(fmt.Sprintf("  actual_minutes: %d\n", t.ActualMinutes))
		}
		if len(t.Annotations) > 0 {
			b.WriteString(fmt.Sprintf("  annotations (%d):\n", len(t.Annotations)))
			for _, a := range t.Annotations {
				b.WriteString(fmt.Sprintf("    [%s] %s: %s\n", a.Timestamp.Format("2006-01-02 15:04"), a.Author, singleLine(a.Text, 150)))
			}
		}
		if t.Result != "" {
			b.WriteString(fmt.Sprintf("  result_summary: %s\n", singleLine(t.Result, 200)))
		}
	}
	b.WriteString("\n")

	b.WriteString("## QUESTION\n")
	b.WriteString(question)
	b.WriteString("\n\n")
	b.WriteString("Answer concisely and directly. Use plain text (no markdown headers). ")
	b.WriteString("Reference task IDs by number (e.g. #3) where relevant.\n")

	return b.String()
}

func statusLabel(s pm.TaskStatus) string {
	switch s {
	case pm.TaskDone:
		return "done"
	case pm.TaskSkipped:
		return "skipped"
	case pm.TaskFailed:
		return "failed"
	case pm.TaskInProgress:
		return "in_progress"
	default:
		return "pending"
	}
}

// singleLine collapses newlines to spaces and truncates to maxLen runes.
func singleLine(s string, maxLen int) string {
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "\r", "")
	runes := []rune(strings.TrimSpace(s))
	if len(runes) <= maxLen {
		return string(runes)
	}
	return string(runes[:maxLen]) + "..."
}
