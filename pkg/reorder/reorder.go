// Package reorder implements AI-powered task priority re-ranking for PM mode.
// It asks the AI to analyze the current plan state (completed tasks, project
// history, dependency graph) and return an optimal execution order for all
// pending tasks.
package reorder

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/provider"
)

// RankedTask is one entry in the AI's reorder response.
type RankedTask struct {
	ID        int    `json:"id"`
	Rationale string `json:"rationale"`
}

// ReorderResponse is the full JSON structure returned by the AI.
type ReorderResponse struct {
	Order []RankedTask `json:"order"`
}

// ReorderPrompt builds the prompt sent to the AI provider.
// It includes: goal, completed task summaries, pending task descriptions,
// dependency graph, and git history context (passed in as gitLog).
func ReorderPrompt(plan *pm.Plan, gitLog string) string {
	var b strings.Builder

	b.WriteString("You are an AI project manager. Your job is to re-rank all pending tasks in the optimal execution order given the current project state.\n\n")

	b.WriteString(fmt.Sprintf("## PROJECT GOAL\n%s\n\n", plan.Goal))

	// Completed tasks summary
	var done []*pm.Task
	for _, t := range plan.Tasks {
		if t.Status == pm.TaskDone || t.Status == pm.TaskSkipped {
			done = append(done, t)
		}
	}
	if len(done) > 0 {
		b.WriteString("## COMPLETED TASKS\n")
		for _, t := range done {
			status := "done"
			if t.Status == pm.TaskSkipped {
				status = "skipped"
			}
			result := strings.TrimSpace(t.Result)
			if len(result) > 200 {
				result = result[:200] + "..."
			}
			b.WriteString(fmt.Sprintf("- [%s] #%d %s", status, t.ID, t.Title))
			if result != "" {
				b.WriteString(fmt.Sprintf(": %s", result))
			}
			b.WriteString("\n")
		}
		b.WriteString("\n")
	}

	// Failed tasks
	var failed []*pm.Task
	for _, t := range plan.Tasks {
		if t.Status == pm.TaskFailed {
			failed = append(failed, t)
		}
	}
	if len(failed) > 0 {
		b.WriteString("## FAILED TASKS\n")
		for _, t := range failed {
			b.WriteString(fmt.Sprintf("- #%d %s (failed %d time(s))\n", t.ID, t.Title, t.FailCount))
			if t.FailureDiagnosis != "" {
				b.WriteString(fmt.Sprintf("  Diagnosis: %s\n", truncate(t.FailureDiagnosis, 200)))
			}
		}
		b.WriteString("\n")
	}

	// Pending tasks
	var pending []*pm.Task
	for _, t := range plan.Tasks {
		if t.Status == pm.TaskPending || t.Status == pm.TaskInProgress {
			pending = append(pending, t)
		}
	}
	if len(pending) == 0 {
		b.WriteString("## PENDING TASKS\n(none)\n\n")
	} else {
		b.WriteString("## PENDING TASKS (to be re-ranked)\n")
		for _, t := range pending {
			b.WriteString(fmt.Sprintf("- #%d [P%d] %s", t.ID, t.Priority, t.Title))
			if t.Role != "" {
				b.WriteString(fmt.Sprintf(" [role: %s]", t.Role))
			}
			if t.Description != "" {
				b.WriteString(fmt.Sprintf("\n  Description: %s", truncate(t.Description, 150)))
			}
			if len(t.DependsOn) > 0 {
				deps := make([]string, len(t.DependsOn))
				for i, depID := range t.DependsOn {
					deps[i] = fmt.Sprintf("#%d", depID)
				}
				b.WriteString(fmt.Sprintf("\n  Depends on: %s", strings.Join(deps, ", ")))
			}
			if len(t.Tags) > 0 {
				b.WriteString(fmt.Sprintf("\n  Tags: %s", strings.Join(t.Tags, ", ")))
			}
			b.WriteString("\n")
		}
		b.WriteString("\n")
	}

	// Dependency graph summary
	hasDeps := false
	for _, t := range plan.Tasks {
		if len(t.DependsOn) > 0 {
			hasDeps = true
			break
		}
	}
	if hasDeps {
		b.WriteString("## DEPENDENCY GRAPH\n")
		for _, t := range plan.Tasks {
			if len(t.DependsOn) > 0 {
				deps := make([]string, len(t.DependsOn))
				for i, depID := range t.DependsOn {
					deps[i] = fmt.Sprintf("#%d", depID)
				}
				b.WriteString(fmt.Sprintf("  #%d depends on: %s\n", t.ID, strings.Join(deps, ", ")))
			}
		}
		b.WriteString("\n")
	}

	// Git log context
	if gitLog != "" {
		b.WriteString("## RECENT PROJECT ACTIVITY (git log)\n")
		b.WriteString(gitLog)
		b.WriteString("\n\n")
	}

	b.WriteString("## INSTRUCTIONS\n")
	b.WriteString("Re-rank ALL pending tasks (including in_progress) in optimal execution order considering:\n")
	b.WriteString("1. Task dependencies (a task must appear AFTER all its dependencies in the order)\n")
	b.WriteString("2. What has already been completed and what builds on it\n")
	b.WriteString("3. Risk and complexity (tackle risky/blocking items early)\n")
	b.WriteString("4. Logical sequencing (infrastructure before features, tests after implementation)\n")
	b.WriteString("5. Recent project activity from git history\n\n")
	b.WriteString("Return ONLY a JSON object with this exact structure (no markdown fences, no extra text):\n")
	b.WriteString(`{"order": [{"id": <task-id>, "rationale": "<brief reason>"}, ...]}` + "\n\n")
	b.WriteString("Include ALL pending task IDs in the array. The first element is highest priority.\n")

	return b.String()
}

// Reorder calls the AI provider to re-rank all pending tasks in the plan.
// Returns the ordered list of RankedTask entries.
func Reorder(ctx context.Context, prov provider.Provider, opts provider.Options, plan *pm.Plan, gitLog string) ([]RankedTask, error) {
	prompt := ReorderPrompt(plan, gitLog)

	var response strings.Builder
	callOpts := opts
	callOpts.OnToken = func(tok string) {
		response.WriteString(tok)
	}

	if _, err := prov.Complete(ctx, prompt, callOpts); err != nil {
		return nil, fmt.Errorf("AI call failed: %w", err)
	}

	raw := strings.TrimSpace(response.String())
	// Strip markdown fences if present
	if strings.HasPrefix(raw, "```") {
		lines := strings.SplitN(raw, "\n", 2)
		if len(lines) == 2 {
			raw = lines[1]
		}
		if idx := strings.LastIndex(raw, "```"); idx != -1 {
			raw = raw[:idx]
		}
		raw = strings.TrimSpace(raw)
	}

	var result ReorderResponse
	if err := json.Unmarshal([]byte(raw), &result); err != nil {
		return nil, fmt.Errorf("parsing AI response: %w\nraw: %s", err, truncate(raw, 500))
	}

	if len(result.Order) == 0 {
		return nil, fmt.Errorf("AI returned empty order")
	}

	return result.Order, nil
}

// ApplyOrder reassigns priorities to pending tasks based on the AI-provided
// order. Tasks are assigned priorities 1, 2, 3, ... in the given order.
// Non-pending tasks (done/skipped/failed) are left unchanged.
// Returns an error if any ID in orderedIDs is not found in the plan.
func ApplyOrder(plan *pm.Plan, rankedTasks []RankedTask) error {
	// Build lookup for pending tasks
	pendingByID := make(map[int]*pm.Task, len(plan.Tasks))
	for _, t := range plan.Tasks {
		if t.Status == pm.TaskPending || t.Status == pm.TaskInProgress {
			pendingByID[t.ID] = t
		}
	}

	// Validate all IDs exist
	for _, rt := range rankedTasks {
		if _, ok := pendingByID[rt.ID]; !ok {
			return fmt.Errorf("task ID %d from AI response not found among pending tasks", rt.ID)
		}
	}

	// Assign new priorities
	for i, rt := range rankedTasks {
		if t, ok := pendingByID[rt.ID]; ok {
			t.Priority = i + 1
		}
	}

	return nil
}

// OrderedPendingIDs returns the IDs of all pending tasks sorted by current priority.
func OrderedPendingIDs(plan *pm.Plan) []int {
	var pending []*pm.Task
	for _, t := range plan.Tasks {
		if t.Status == pm.TaskPending || t.Status == pm.TaskInProgress {
			pending = append(pending, t)
		}
	}
	sort.SliceStable(pending, func(i, j int) bool {
		return pending[i].Priority < pending[j].Priority
	})
	ids := make([]int, len(pending))
	for i, t := range pending {
		ids[i] = t.ID
	}
	return ids
}

func truncate(s string, n int) string {
	runes := []rune(s)
	if len(runes) <= n {
		return s
	}
	return string(runes[:n]) + "..."
}
