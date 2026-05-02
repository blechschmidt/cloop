package pm

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/blechschmidt/cloop/pkg/provider"
)

// SplitPrompt builds a prompt asking the AI to break a task into 2-5 concrete subtasks.
func SplitPrompt(task *Task, reason string) string {
	var b strings.Builder
	b.WriteString("You are an AI product manager. A task is too large or complex and needs to be broken down.\n\n")

	b.WriteString("## TASK TO SPLIT\n")
	if task.Role != "" {
		b.WriteString(fmt.Sprintf("**Task %d: %s** [role: %s]\n", task.ID, task.Title, task.Role))
	} else {
		b.WriteString(fmt.Sprintf("**Task %d: %s**\n", task.ID, task.Title))
	}
	if task.Description != "" {
		b.WriteString(fmt.Sprintf("Description: %s\n", task.Description))
	}
	if reason != "" {
		b.WriteString(fmt.Sprintf("\n## REASON FOR SPLITTING\n%s\n", reason))
	}

	b.WriteString("\n## INSTRUCTIONS\n")
	b.WriteString("Decompose this task into 2-5 smaller, concrete subtasks.\n")
	b.WriteString("Each subtask must be:\n")
	b.WriteString("- Independently executable by an AI agent\n")
	b.WriteString("- Smaller and more focused than the original task\n")
	b.WriteString("- Together they must cover all the work of the original task\n")
	b.WriteString("- Ordered by logical sequence (earlier subtasks first)\n\n")
	b.WriteString("Output ONLY valid JSON (no explanation, no markdown):\n")
	b.WriteString(`[{"title":"short title","description":"detailed description","priority":1,"role":"backend"},`)
	b.WriteString(`{"title":"another subtask","description":"details","priority":2,"role":"testing"}]`)
	b.WriteString("\n\nFor role, choose: backend, frontend, testing, security, devops, data, docs, review, or empty string.\n")
	b.WriteString("Priority is relative order within the subtasks (1 = do first).")
	return b.String()
}

// splitItem is the raw JSON structure returned by the AI for a single subtask.
type splitItem struct {
	Title       string    `json:"title"`
	Description string    `json:"description"`
	Priority    int       `json:"priority"`
	Role        AgentRole `json:"role"`
}

// ParseSplitResponse parses the AI's JSON response into subtasks.
// New IDs are assigned as parentID + suffix (e.g. task 5 becomes 5a, 5b, etc.).
// IDs are assigned sequentially starting from nextID.
func ParseSplitResponse(response string, parentTask *Task, nextID int) ([]*Task, error) {
	// Find JSON array in the response
	start := strings.Index(response, "[")
	end := strings.LastIndex(response, "]")
	if start == -1 || end == -1 || end <= start {
		return nil, fmt.Errorf("no JSON array found in response")
	}
	jsonStr := response[start : end+1]

	var items []splitItem
	if err := json.Unmarshal([]byte(jsonStr), &items); err != nil {
		return nil, fmt.Errorf("parsing split response: %w", err)
	}
	if len(items) == 0 {
		return nil, fmt.Errorf("split produced no subtasks")
	}
	if len(items) > 5 {
		items = items[:5]
	}

	tasks := make([]*Task, 0, len(items))
	for i, item := range items {
		if item.Title == "" {
			continue
		}
		priority := item.Priority
		if priority == 0 {
			priority = i + 1
		}
		t := &Task{
			ID:          nextID + i,
			Title:       item.Title,
			Description: item.Description,
			Priority:    parentTask.Priority, // inherit parent priority
			Role:        item.Role,
			Status:      TaskPending,
			DependsOn:   parentTask.DependsOn, // inherit parent dependencies
		}
		// Subtasks depend on each other sequentially (each depends on the previous).
		if i > 0 {
			t.DependsOn = append(append([]int{}, parentTask.DependsOn...), nextID+i-1)
		}
		tasks = append(tasks, t)
	}

	return tasks, nil
}

// SplitTask orchestrates an AI-driven task split:
//  1. Calls the AI with SplitPrompt
//  2. Parses the response into subtasks
//  3. Removes the original task from the plan
//  4. Inserts subtasks at the same position with the same priority
//  5. Remaps any tasks that depended on the original task to depend on the last subtask
//
// Returns the new subtasks on success.
func SplitTask(ctx context.Context, p provider.Provider, opts provider.Options, plan *Plan, taskID int, reason string) ([]*Task, error) {
	// Find the task to split
	var task *Task
	taskIdx := -1
	for i, t := range plan.Tasks {
		if t.ID == taskID {
			task = t
			taskIdx = i
			break
		}
	}
	if task == nil {
		return nil, fmt.Errorf("task %d not found in plan", taskID)
	}

	// Find highest existing ID
	maxID := 0
	for _, t := range plan.Tasks {
		if t.ID > maxID {
			maxID = t.ID
		}
	}
	nextID := maxID + 1

	// Call the AI
	prompt := SplitPrompt(task, reason)
	result, err := p.Complete(ctx, prompt, opts)
	if err != nil {
		return nil, fmt.Errorf("split: provider error: %w", err)
	}

	subtasks, err := ParseSplitResponse(result.Output, task, nextID)
	if err != nil {
		return nil, fmt.Errorf("split: parse error: %w", err)
	}

	lastSubtaskID := subtasks[len(subtasks)-1].ID

	// Remap dependencies: any task that depended on the original task now depends on the last subtask.
	for _, t := range plan.Tasks {
		for i, depID := range t.DependsOn {
			if depID == taskID {
				t.DependsOn[i] = lastSubtaskID
			}
		}
	}

	// Replace the original task with subtasks at the same position.
	before := make([]*Task, taskIdx)
	copy(before, plan.Tasks[:taskIdx])
	after := make([]*Task, len(plan.Tasks)-taskIdx-1)
	copy(after, plan.Tasks[taskIdx+1:])

	plan.Tasks = append(before, append(subtasks, after...)...)

	return subtasks, nil
}
