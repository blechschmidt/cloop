// Package explain generates human-readable pre-execution narrations of task plans.
// For each pending task (or a specific task), it asks the AI provider to narrate
// what the task will do: estimated files to touch, commands likely to run, risks,
// and success criteria. The output is a numbered list per task with a final summary.
package explain

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/provider"
)

// Explain generates a narration of what the given tasks will do.
//
// If taskID is non-empty it must be a numeric task ID; only that task is narrated.
// If taskID is empty, all pending tasks are narrated.
// model may be empty (the provider will use its default).
//
// The returned string is a formatted, human-readable walkthrough suitable for
// printing directly to a terminal.
func Explain(ctx context.Context, p provider.Provider, model string, plan *pm.Plan, taskID string) (string, error) {
	if plan == nil {
		return "", fmt.Errorf("no plan loaded")
	}

	tasks, err := selectTasks(plan, taskID)
	if err != nil {
		return "", err
	}
	if len(tasks) == 0 {
		return "No pending tasks to explain.", nil
	}

	prompt := buildPrompt(plan, tasks)
	result, err := p.Complete(ctx, prompt, provider.Options{
		Model:   model,
		Timeout: 3 * time.Minute,
	})
	if err != nil {
		return "", fmt.Errorf("explain: %w", err)
	}
	return strings.TrimSpace(result.Output), nil
}

// selectTasks returns the tasks to explain.
// If taskID is non-empty, returns the single matching task.
// Otherwise returns all pending tasks.
func selectTasks(plan *pm.Plan, taskID string) ([]*pm.Task, error) {
	if taskID != "" {
		id, err := strconv.Atoi(taskID)
		if err != nil {
			return nil, fmt.Errorf("invalid task ID %q: must be a number", taskID)
		}
		for _, t := range plan.Tasks {
			if t.ID == id {
				return []*pm.Task{t}, nil
			}
		}
		return nil, fmt.Errorf("task #%d not found", id)
	}

	var pending []*pm.Task
	for _, t := range plan.Tasks {
		if t.Status == pm.TaskPending || t.Status == pm.TaskInProgress {
			pending = append(pending, t)
		}
	}
	return pending, nil
}

// buildPrompt constructs the AI prompt for the explain call.
func buildPrompt(plan *pm.Plan, tasks []*pm.Task) string {
	var b strings.Builder

	b.WriteString("You are an expert software project manager and senior engineer. ")
	b.WriteString("Your job is to narrate what each listed task will do BEFORE it is executed. ")
	b.WriteString("This gives the team a clear pre-execution preview to review before any code runs.\n\n")

	b.WriteString("## PROJECT GOAL\n")
	b.WriteString(plan.Goal)
	b.WriteString("\n\n")

	// Include a brief plan summary for context.
	total := len(plan.Tasks)
	done := 0
	for _, t := range plan.Tasks {
		if t.Status == pm.TaskDone || t.Status == pm.TaskSkipped {
			done++
		}
	}
	b.WriteString(fmt.Sprintf("## PLAN CONTEXT\nTotal tasks: %d | Completed: %d | Remaining: %d\n\n", total, done, total-done))

	b.WriteString("## TASKS TO EXPLAIN\n")
	for _, t := range tasks {
		b.WriteString(fmt.Sprintf("### Task #%d — %s\n", t.ID, t.Title))
		b.WriteString(fmt.Sprintf("Priority: %d | Status: %s", t.Priority, t.Status))
		if t.Role != "" {
			b.WriteString(fmt.Sprintf(" | Role: %s", t.Role))
		}
		if t.EstimatedMinutes > 0 {
			b.WriteString(fmt.Sprintf(" | Estimated: %d min", t.EstimatedMinutes))
		}
		b.WriteString("\n")
		if t.Description != "" {
			b.WriteString(fmt.Sprintf("Description: %s\n", t.Description))
		}
		if len(t.DependsOn) > 0 {
			parts := make([]string, len(t.DependsOn))
			for i, dep := range t.DependsOn {
				parts[i] = fmt.Sprintf("#%d", dep)
			}
			b.WriteString(fmt.Sprintf("Depends on: %s\n", strings.Join(parts, ", ")))
		}
		if len(t.Tags) > 0 {
			b.WriteString(fmt.Sprintf("Tags: %s\n", strings.Join(t.Tags, ", ")))
		}
		b.WriteString("\n")
	}

	b.WriteString("## INSTRUCTIONS\n")
	b.WriteString("For each task listed above, produce a numbered section with this structure:\n\n")
	b.WriteString("**N. Task #ID — Title**\n")
	b.WriteString("- **Files likely to be touched:** list specific files or directories that will probably be created or modified\n")
	b.WriteString("- **Commands likely to run:** shell commands, build steps, test runners, or API calls expected\n")
	b.WriteString("- **Risks:** potential pitfalls, side effects, irreversible operations, or blockers\n")
	b.WriteString("- **Success criteria:** concrete, observable signals that the task completed correctly\n\n")
	b.WriteString("After all tasks, add a **Summary** section (2-4 sentences) covering:\n")
	b.WriteString("- The overall execution sequence\n")
	b.WriteString("- Highest-risk step and why\n")
	b.WriteString("- Any cross-task dependencies the executor should be aware of\n\n")
	b.WriteString("Be specific and concrete. Use the project goal and task descriptions to make informed inferences. ")
	b.WriteString("Keep each task section concise (under 200 words). Use plain markdown — no raw HTML.\n")

	return b.String()
}
