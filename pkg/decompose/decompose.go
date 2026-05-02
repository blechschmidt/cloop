// Package decompose implements recursive AI sub-task expansion for a single task.
package decompose

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/provider"
)

// DecomposePrompt builds a prompt asking the AI to break a complex task into 3-7 sub-tasks.
// depth indicates how many more levels of recursion are intended (for informational framing only).
func DecomposePrompt(task *pm.Task, depth int) string {
	var b strings.Builder
	b.WriteString("You are an AI product manager. A task needs to be recursively decomposed into concrete sub-tasks.\n\n")

	b.WriteString("## TASK TO DECOMPOSE\n")
	if task.Role != "" {
		b.WriteString(fmt.Sprintf("**Task %d: %s** [role: %s]\n", task.ID, task.Title, task.Role))
	} else {
		b.WriteString(fmt.Sprintf("**Task %d: %s**\n", task.ID, task.Title))
	}
	if task.Description != "" {
		b.WriteString(fmt.Sprintf("Description: %s\n", task.Description))
	}
	if len(task.Tags) > 0 {
		b.WriteString(fmt.Sprintf("Tags: %s\n", strings.Join(task.Tags, ", ")))
	}
	if task.Assignee != "" {
		b.WriteString(fmt.Sprintf("Assignee: %s\n", task.Assignee))
	}

	b.WriteString("\n## INSTRUCTIONS\n")
	b.WriteString("Decompose this task into 3-7 smaller, concrete sub-tasks.\n")
	b.WriteString("Each sub-task must be:\n")
	b.WriteString("- Independently executable by an AI agent\n")
	b.WriteString("- Smaller and more focused than the parent task\n")
	b.WriteString("- Together they must cover ALL the work of the parent task\n")
	b.WriteString("- Ordered by logical sequence (earlier sub-tasks first)\n")
	if depth > 1 {
		b.WriteString(fmt.Sprintf("- At a granularity appropriate for %d more levels of decomposition\n", depth-1))
	}
	b.WriteString("\nOutput ONLY valid JSON array (no explanation, no markdown fences):\n")
	b.WriteString(`[{"title":"short title","description":"detailed description","priority":1,"role":"backend","estimated_minutes":30},`)
	b.WriteString(`{"title":"another sub-task","description":"details","priority":2,"role":"testing","estimated_minutes":20}]`)
	b.WriteString("\n\nFor role, choose one of: backend, frontend, testing, security, devops, data, docs, review, or empty string.\n")
	b.WriteString("priority is the relative order within the sub-tasks (1 = do first).\n")
	b.WriteString("estimated_minutes is your best estimate of how long the sub-task will take.")
	return b.String()
}

// decomposeItem is the raw JSON structure returned by the AI for a single sub-task.
type decomposeItem struct {
	Title            string       `json:"title"`
	Description      string       `json:"description"`
	Priority         int          `json:"priority"`
	Role             pm.AgentRole `json:"role"`
	EstimatedMinutes int          `json:"estimated_minutes"`
}

// ParseSubTasks parses the AI's JSON response into sub-tasks.
// The returned tasks have no IDs set (caller assigns IDs).
// Tags and Assignee from the parent are inherited by all sub-tasks.
// The first sub-task's DependsOn is set to []int{parentID}.
// Subsequent sub-tasks depend on the previous sub-task sequentially.
func ParseSubTasks(response string, parent *pm.Task) ([]*pm.Task, error) {
	// Find JSON array in the response.
	start := strings.Index(response, "[")
	end := strings.LastIndex(response, "]")
	if start == -1 || end == -1 || end <= start {
		return nil, fmt.Errorf("no JSON array found in decompose response")
	}
	jsonStr := response[start : end+1]

	var items []decomposeItem
	if err := json.Unmarshal([]byte(jsonStr), &items); err != nil {
		return nil, fmt.Errorf("parsing decompose response: %w", err)
	}
	if len(items) == 0 {
		return nil, fmt.Errorf("decompose produced no sub-tasks")
	}
	// Clamp to max 7.
	if len(items) > 7 {
		items = items[:7]
	}

	tasks := make([]*pm.Task, 0, len(items))
	for i, item := range items {
		if item.Title == "" {
			continue
		}
		priority := item.Priority
		if priority == 0 {
			priority = i + 1
		}

		// Inherit parent tags (defensive copy).
		var tags []string
		if len(parent.Tags) > 0 {
			tags = append([]string{}, parent.Tags...)
		}

		t := &pm.Task{
			// ID is left as zero — caller assigns IDs after dedup.
			Title:            item.Title,
			Description:      item.Description,
			Priority:         parent.Priority,
			Role:             item.Role,
			Status:           pm.TaskPending,
			Tags:             tags,
			Assignee:         parent.Assignee,
			EstimatedMinutes: item.EstimatedMinutes,
		}

		// First sub-task depends on the parent (which will be marked skipped).
		// Subsequent sub-tasks depend on the previous one.
		if i == 0 {
			t.DependsOn = []int{parent.ID}
		}
		// Note: sequential dep wiring (sub[i] depends on sub[i-1]) is applied
		// by the caller after IDs are assigned so we can use real IDs.

		tasks = append(tasks, t)
	}

	if len(tasks) == 0 {
		return nil, fmt.Errorf("decompose produced no valid sub-tasks")
	}
	return tasks, nil
}

// DecomposeResult holds the output of a single decompose call.
type DecomposeResult struct {
	Parent   *pm.Task
	SubTasks []*pm.Task
}

// Decompose calls the AI to break a single task into sub-tasks, deduplicates
// against existing plan tasks, and returns the result without modifying the plan.
// Callers must assign IDs and inject into the plan themselves.
func Decompose(ctx context.Context, p provider.Provider, opts provider.Options, plan *pm.Plan, taskID int) (*DecomposeResult, error) {
	var task *pm.Task
	for _, t := range plan.Tasks {
		if t.ID == taskID {
			task = t
			break
		}
	}
	if task == nil {
		return nil, fmt.Errorf("task %d not found in plan", taskID)
	}

	prompt := DecomposePrompt(task, 1)
	result, err := p.Complete(ctx, prompt, opts)
	if err != nil {
		return nil, fmt.Errorf("decompose: provider error: %w", err)
	}

	subTasks, err := ParseSubTasks(result.Output, task)
	if err != nil {
		return nil, fmt.Errorf("decompose: parse error: %w", err)
	}

	// Deduplicate against existing plan tasks (fail-open).
	filtered, _ := pm.DeduplicateTasks(ctx, p, opts, plan.Tasks, subTasks)

	return &DecomposeResult{Parent: task, SubTasks: filtered}, nil
}

// InjectSubTasks applies a DecomposeResult to the plan:
//  1. Parent is marked skipped with annotation 'Decomposed into sub-tasks'.
//  2. Sub-tasks are assigned IDs as maxID+1, maxID+2, ... and wired sequentially.
//  3. Sub-tasks are appended after the parent task in the plan slice.
//
// Returns the assigned sub-tasks.
func InjectSubTasks(plan *pm.Plan, res *DecomposeResult) []*pm.Task {
	// Find the highest existing ID.
	maxID := 0
	for _, t := range plan.Tasks {
		if t.ID > maxID {
			maxID = t.ID
		}
	}

	// Assign IDs and wire sequential dependencies.
	for i, st := range res.SubTasks {
		st.ID = maxID + 1 + i
		// First sub-task already has DependsOn = [parentID] from ParseSubTasks.
		// Sub-tasks 2+ depend on the previous sub-task.
		if i > 0 {
			st.DependsOn = []int{maxID + i} // previous sub-task
		}
	}

	// Mark parent as skipped and annotate.
	res.Parent.Status = pm.TaskSkipped
	pm.AddAnnotation(res.Parent, "ai", "Decomposed into sub-tasks")

	// Insert sub-tasks immediately after the parent in the slice.
	parentIdx := -1
	for i, t := range plan.Tasks {
		if t.ID == res.Parent.ID {
			parentIdx = i
			break
		}
	}

	if parentIdx == -1 {
		// Parent not found — just append.
		plan.Tasks = append(plan.Tasks, res.SubTasks...)
	} else {
		before := plan.Tasks[:parentIdx+1]
		after := plan.Tasks[parentIdx+1:]
		newTasks := make([]*pm.Task, 0, len(plan.Tasks)+len(res.SubTasks))
		newTasks = append(newTasks, before...)
		newTasks = append(newTasks, res.SubTasks...)
		newTasks = append(newTasks, after...)
		plan.Tasks = newTasks
	}

	return res.SubTasks
}
