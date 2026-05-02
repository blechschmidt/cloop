// Package diagnosis provides AI-powered failure analysis for PM tasks.
// When a task fails, it calls the provider to analyze what went wrong and
// suggest a concrete fix strategy for the next attempt.
package diagnosis

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/provider"
)

// AnalyzeFailure asks the provider to diagnose why a task failed and suggest
// what should be tried differently on the next attempt.
// The failureOutput is the full AI response that contained TASK_FAILED.
// Returns a concise diagnosis string suitable for injecting into retry prompts.
func AnalyzeFailure(ctx context.Context, p provider.Provider, model string, timeout time.Duration, task *pm.Task, failureOutput string) (string, error) {
	prompt := buildDiagnosisPrompt(task, failureOutput)
	result, err := p.Complete(ctx, prompt, provider.Options{
		Model:   model,
		Timeout: timeout,
	})
	if err != nil {
		return "", fmt.Errorf("failure diagnosis: %w", err)
	}
	return strings.TrimSpace(result.Output), nil
}

// buildDiagnosisPrompt constructs a focused prompt that asks the AI to identify
// the root cause of a task failure and propose a concrete fix strategy.
func buildDiagnosisPrompt(task *pm.Task, failureOutput string) string {
	var b strings.Builder
	b.WriteString("You are a senior engineering advisor performing a post-mortem on a failed AI task.\n")
	b.WriteString("Your job is to identify the root cause and provide a concrete, actionable fix strategy.\n\n")

	b.WriteString("## FAILED TASK\n")
	b.WriteString(fmt.Sprintf("**Task %d: %s**\n", task.ID, task.Title))
	if task.Description != "" {
		b.WriteString(fmt.Sprintf("Description: %s\n", task.Description))
	}
	b.WriteString("\n")

	b.WriteString("## FAILURE OUTPUT\n")
	// Truncate very long outputs to focus on the relevant parts
	output := failureOutput
	if len(output) > 3000 {
		b.WriteString(output[:1500])
		b.WriteString("\n...(middle truncated)...\n")
		b.WriteString(output[len(output)-1500:])
	} else {
		b.WriteString(output)
	}
	b.WriteString("\n\n")

	b.WriteString("## INSTRUCTIONS\n")
	b.WriteString("Analyze the failure and provide:\n")
	b.WriteString("1. **Root cause** — what specifically went wrong (1-2 sentences)\n")
	b.WriteString("2. **Fix strategy** — concrete steps to try differently next time (2-4 bullet points)\n\n")
	b.WriteString("Be specific and actionable. Focus on what the next attempt should do differently.\n")
	b.WriteString("Keep your response concise (under 200 words). Do not repeat the failure output back.\n")

	return b.String()
}
