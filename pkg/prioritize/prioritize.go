// Package prioritize provides AI-powered task reprioritization for cloop PM mode.
// It analyzes the current task plan, dependency graph, blockers, and risk factors,
// then uses an AI provider to suggest an optimal new priority ordering.
package prioritize

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/provider"
)

// Suggestion holds a recommended priority for a single task.
type Suggestion struct {
	TaskID      int    `json:"task_id"`
	NewPriority int    `json:"new_priority"`
	Reason      string `json:"reason"`
}

// Result is the full AI reprioritization output.
type Result struct {
	Suggestions []Suggestion `json:"suggestions"`
	Summary     string       `json:"summary"`
	GeneratedAt time.Time
}

// BuildPrompt creates the reprioritization prompt.
func BuildPrompt(goal string, plan *pm.Plan) string {
	var b strings.Builder

	b.WriteString("You are an expert AI project manager optimizing task execution order.\n")
	b.WriteString("Analyze the task plan and suggest the optimal priority ordering for pending tasks.\n\n")

	b.WriteString(fmt.Sprintf("## PROJECT GOAL\n%s\n\n", goal))

	b.WriteString("## CURRENT TASK PLAN\n")
	for _, t := range plan.Tasks {
		statusStr := string(t.Status)
		roleStr := ""
		if t.Role != "" {
			roleStr = fmt.Sprintf(" [%s]", t.Role)
		}
		depsStr := ""
		if len(t.DependsOn) > 0 {
			depsStr = fmt.Sprintf(" (depends on: %v)", t.DependsOn)
		}
		resultStr := ""
		if t.Result != "" && (t.Status == pm.TaskFailed || t.Status == pm.TaskDone) {
			s := t.Result
			if len(s) > 80 {
				s = s[:80] + "..."
			}
			resultStr = fmt.Sprintf("\n  Result: %s", strings.ReplaceAll(s, "\n", " "))
		}
		b.WriteString(fmt.Sprintf("- Task %d [P%d, %s]%s%s: %s%s\n",
			t.ID, t.Priority, statusStr, roleStr, depsStr, t.Title, resultStr))
		if t.Description != "" {
			desc := t.Description
			if len(desc) > 100 {
				desc = desc[:100] + "..."
			}
			b.WriteString(fmt.Sprintf("  Desc: %s\n", desc))
		}
	}
	b.WriteString("\n")

	// Identify issues
	var blocked, failed, inProgress []int
	for _, t := range plan.Tasks {
		switch t.Status {
		case pm.TaskFailed:
			failed = append(failed, t.ID)
		case pm.TaskInProgress:
			inProgress = append(inProgress, t.ID)
		case pm.TaskPending:
			if plan.PermanentlyBlocked(t) {
				blocked = append(blocked, t.ID)
			}
		}
	}

	if len(failed) > 0 {
		b.WriteString(fmt.Sprintf("## FAILED TASKS\nTasks %v have failed and may be blocking others.\n\n", failed))
	}
	if len(blocked) > 0 {
		b.WriteString(fmt.Sprintf("## BLOCKED TASKS\nTasks %v are permanently blocked by failed dependencies.\n\n", blocked))
	}
	if len(inProgress) > 0 {
		b.WriteString(fmt.Sprintf("## IN PROGRESS\nTasks %v are currently executing.\n\n", inProgress))
	}

	b.WriteString("## REPRIORITIZATION RULES\n")
	b.WriteString("1. Only suggest new priorities for PENDING tasks (status=pending) that are NOT permanently blocked\n")
	b.WriteString("2. Respect dependency constraints — a task cannot be prioritized above its dependencies\n")
	b.WriteString("3. Consider: critical path, risk reduction, value delivery, unblocking downstream tasks\n")
	b.WriteString("4. Assign priorities as consecutive integers starting from 1 (1=highest)\n")
	b.WriteString("5. Provide a brief reason for each change from the current priority\n\n")

	b.WriteString("## RESPONSE FORMAT\n")
	b.WriteString("Output ONLY valid JSON. No markdown, no explanation outside the JSON:\n")
	b.WriteString(`{
  "suggestions": [
    {"task_id": 3, "new_priority": 1, "reason": "Critical path — unblocks 4 downstream tasks"},
    {"task_id": 7, "new_priority": 2, "reason": "High value, no dependencies, quick win"}
  ],
  "summary": "One to two sentence explanation of the overall reprioritization strategy"
}`)
	b.WriteString("\n\nOnly include tasks whose priority should CHANGE. Skip tasks that are already optimally ordered.")

	return b.String()
}

// Parse extracts a Result from the AI's JSON response.
func Parse(output string) (*Result, error) {
	start := strings.Index(output, "{")
	end := strings.LastIndex(output, "}")
	if start == -1 || end == -1 || end <= start {
		return nil, fmt.Errorf("no JSON found in response")
	}
	jsonStr := output[start : end+1]

	var r Result
	if err := json.Unmarshal([]byte(jsonStr), &r); err != nil {
		return nil, fmt.Errorf("parsing reprioritization: %w", err)
	}
	r.GeneratedAt = time.Now()
	return &r, nil
}

// Apply updates task priorities in the plan based on suggestions.
// Returns the number of tasks updated.
func Apply(plan *pm.Plan, result *Result) int {
	idToTask := make(map[int]*pm.Task, len(plan.Tasks))
	for _, t := range plan.Tasks {
		idToTask[t.ID] = t
	}

	count := 0
	for _, s := range result.Suggestions {
		t, ok := idToTask[s.TaskID]
		if !ok {
			continue
		}
		if t.Status != pm.TaskPending {
			continue // only change pending tasks
		}
		if plan.PermanentlyBlocked(t) {
			continue // don't touch blocked tasks
		}
		if t.Priority != s.NewPriority {
			t.Priority = s.NewPriority
			count++
		}
	}
	return count
}

// Generate calls the AI provider to produce reprioritization suggestions.
func Generate(ctx context.Context, p provider.Provider, goal string, plan *pm.Plan, model string, timeout time.Duration) (*Result, error) {
	prompt := BuildPrompt(goal, plan)

	result, err := p.Complete(ctx, prompt, provider.Options{
		Model:   model,
		Timeout: timeout,
	})
	if err != nil {
		return nil, fmt.Errorf("prioritize: %w", err)
	}

	return Parse(result.Output)
}
