// Package condition evaluates task execution conditions before a task is run.
// Conditions gate whether a task should proceed or be skipped.
//
// Two modes are supported:
//   - Shell: condition starts with "$" — the remainder is run as a shell command.
//     Exit 0 means proceed; non-zero means skip.
//   - AI: any other string — the condition text is sent to the AI provider with
//     task context for a yes/no evaluation. "yes" means proceed; "no" means skip.
package condition

import (
	"context"
	"fmt"
	"os/exec"
	"strings"

	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/provider"
)

// Result is the outcome of evaluating a task condition.
type Result struct {
	// Proceed is true when the condition passes and the task should run.
	Proceed bool
	// Reason is a short human-readable explanation of the outcome.
	Reason string
}

// Evaluate checks the task's Condition field and returns whether the task
// should proceed. Returns (proceed=true, reason="no condition") when the
// task has no condition set.
//
// Shell conditions: condition begins with "$". The text after "$" (trimmed) is
// passed to "sh -c". Exit code 0 → proceed; non-zero → skip.
//
// AI conditions: any other non-empty string. The condition is sent to the
// provider with task context. The response is parsed for a leading YES/NO.
func Evaluate(ctx context.Context, task *pm.Task, plan *pm.Plan, p provider.Provider, opts provider.Options, workDir string) (Result, error) {
	if task.Condition == "" {
		return Result{Proceed: true, Reason: "no condition"}, nil
	}

	if strings.HasPrefix(task.Condition, "$") {
		return evalShell(task)
	}
	return evalAI(ctx, task, plan, p, opts)
}

// evalShell runs the shell command derived from the condition and returns
// proceed=true when it exits with code 0.
func evalShell(task *pm.Task) (Result, error) {
	cmdStr := strings.TrimSpace(strings.TrimPrefix(task.Condition, "$"))
	if cmdStr == "" {
		return Result{Proceed: false, Reason: "empty shell condition"}, nil
	}

	cmd := exec.Command("sh", "-c", cmdStr)
	out, err := cmd.CombinedOutput()
	outStr := strings.TrimSpace(string(out))

	if err != nil {
		// Non-zero exit — skip the task.
		reason := fmt.Sprintf("shell condition failed (exit non-zero): %s", cmdStr)
		if outStr != "" {
			reason += fmt.Sprintf(" — output: %s", truncate(outStr, 200))
		}
		return Result{Proceed: false, Reason: reason}, nil
	}

	reason := fmt.Sprintf("shell condition passed: %s", cmdStr)
	if outStr != "" {
		reason += fmt.Sprintf(" — output: %s", truncate(outStr, 200))
	}
	return Result{Proceed: true, Reason: reason}, nil
}

// evalAI sends the condition to the AI provider with task context and parses
// its YES/NO response.
func evalAI(ctx context.Context, task *pm.Task, plan *pm.Plan, p provider.Provider, opts provider.Options) (Result, error) {
	prompt := buildAIPrompt(task, plan)
	result, err := p.Complete(ctx, prompt, opts)
	if err != nil {
		// On provider error, default to proceeding so a transient API failure
		// does not silently skip tasks. The caller should log the error.
		return Result{Proceed: true, Reason: fmt.Sprintf("AI condition check failed (defaulting to proceed): %v", err)}, err
	}

	answer := strings.TrimSpace(result.Output)
	upper := strings.ToUpper(answer)

	// Accept YES/NO as a prefix so the model can add punctuation or a sentence.
	if strings.HasPrefix(upper, "YES") {
		return Result{Proceed: true, Reason: fmt.Sprintf("AI condition YES: %s", truncate(answer, 200))}, nil
	}
	if strings.HasPrefix(upper, "NO") {
		return Result{Proceed: false, Reason: fmt.Sprintf("AI condition NO: %s", truncate(answer, 200))}, nil
	}

	// Ambiguous — search for YES/NO anywhere in the first 5 lines.
	lines := strings.Split(answer, "\n")
	check := lines
	if len(check) > 5 {
		check = check[:5]
	}
	for _, line := range check {
		l := strings.TrimSpace(strings.ToUpper(line))
		if strings.Contains(l, "YES") {
			return Result{Proceed: true, Reason: fmt.Sprintf("AI condition YES (inferred): %s", truncate(answer, 200))}, nil
		}
		if strings.Contains(l, "NO") {
			return Result{Proceed: false, Reason: fmt.Sprintf("AI condition NO (inferred): %s", truncate(answer, 200))}, nil
		}
	}

	// Default: proceed if ambiguous to avoid erroneously skipping work.
	return Result{Proceed: true, Reason: fmt.Sprintf("AI condition ambiguous (defaulting to proceed): %s", truncate(answer, 200))}, nil
}

// buildAIPrompt constructs the yes/no question prompt for an AI condition.
func buildAIPrompt(task *pm.Task, plan *pm.Plan) string {
	var b strings.Builder
	b.WriteString("You are evaluating a pre-execution condition for a task in an AI project management system.\n\n")

	if plan != nil {
		b.WriteString(fmt.Sprintf("## PROJECT GOAL\n%s\n\n", plan.Goal))
	}

	b.WriteString("## TASK\n")
	b.WriteString(fmt.Sprintf("**Task %d: %s**\n", task.ID, task.Title))
	if task.Description != "" {
		b.WriteString(fmt.Sprintf("%s\n", task.Description))
	}
	b.WriteString("\n")

	b.WriteString("## CONDITION TO EVALUATE\n")
	b.WriteString(task.Condition)
	b.WriteString("\n\n")

	if plan != nil {
		// Summarise completed tasks to give the AI relevant context.
		var done []*pm.Task
		for _, t := range plan.Tasks {
			if t.Status == pm.TaskDone || t.Status == pm.TaskSkipped {
				done = append(done, t)
			}
		}
		if len(done) > 0 {
			b.WriteString("## COMPLETED TASKS (for context)\n")
			for _, t := range done {
				marker := "[x]"
				if t.Status == pm.TaskSkipped {
					marker = "[-]"
				}
				b.WriteString(fmt.Sprintf("- %s Task %d: %s\n", marker, t.ID, t.Title))
			}
			b.WriteString("\n")
		}
	}

	b.WriteString("## INSTRUCTIONS\n")
	b.WriteString("Based on the above context, evaluate whether the condition is currently true.\n")
	b.WriteString("You may inspect the file system or run read-only commands to check.\n")
	b.WriteString("Respond with a single word on the first line:\n")
	b.WriteString("  YES — the condition is met; the task should proceed\n")
	b.WriteString("  NO  — the condition is not met; the task should be skipped\n")
	b.WriteString("Optionally add a brief explanation after the YES/NO.\n")
	return b.String()
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
