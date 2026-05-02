package pm

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/blechschmidt/cloop/pkg/provider"
)

// ClonePrompt builds a prompt asking the AI to adapt a task's title and description
// for a new context. adaptContext describes what should change (e.g. "for module Y
// instead of module X").
func ClonePrompt(original *Task, adaptContext string) string {
	var b strings.Builder
	b.WriteString("You are an AI product manager. A task needs to be cloned and adapted for a new context.\n\n")

	b.WriteString("## ORIGINAL TASK\n")
	if original.Role != "" {
		b.WriteString(fmt.Sprintf("**Task %d: %s** [role: %s]\n", original.ID, original.Title, original.Role))
	} else {
		b.WriteString(fmt.Sprintf("**Task %d: %s**\n", original.ID, original.Title))
	}
	if original.Description != "" {
		b.WriteString(fmt.Sprintf("Description: %s\n", original.Description))
	}

	b.WriteString("\n## ADAPTATION CONTEXT\n")
	b.WriteString(adaptContext)
	b.WriteString("\n\n")

	b.WriteString("## INSTRUCTIONS\n")
	b.WriteString("Produce an adapted version of this task for the new context.\n")
	b.WriteString("- Keep the same structure, scope, and intent as the original\n")
	b.WriteString("- Change only what is necessary to fit the new context\n")
	b.WriteString("- Title should be concise and accurate for the new context\n")
	b.WriteString("- Description should be thorough and self-contained\n\n")
	b.WriteString("Output ONLY valid JSON (no explanation, no markdown):\n")
	b.WriteString(`{"title":"adapted task title","description":"adapted description"}`)
	b.WriteString("\n")
	return b.String()
}

// cloneItem is the raw JSON structure returned by the AI for the adapted task.
type cloneItem struct {
	Title       string `json:"title"`
	Description string `json:"description"`
}

// Clone duplicates a task and optionally uses the AI to adapt its title/description
// for a new context (adaptContext). Without adaptContext, the task is copied verbatim
// with " (copy)" appended to the title.
//
// The cloned task:
//   - Gets the next available ID in the plan
//   - Inherits all fields (priority, role, tags, deps) from the original
//   - Has status reset to pending
//   - Has timing fields (StartedAt, CompletedAt, etc.) cleared
//
// The caller is responsible for saving state after Clone returns.
func Clone(ctx context.Context, p provider.Provider, opts provider.Options, plan *Plan, taskID int, adaptContext string) (*Task, error) {
	// Find the source task
	var original *Task
	for _, t := range plan.Tasks {
		if t.ID == taskID {
			original = t
			break
		}
	}
	if original == nil {
		return nil, fmt.Errorf("task %d not found in plan", taskID)
	}

	// Determine next available ID
	maxID := 0
	for _, t := range plan.Tasks {
		if t.ID > maxID {
			maxID = t.ID
		}
	}
	newID := maxID + 1

	// Shallow-copy inherited fields
	newTask := &Task{
		ID:          newID,
		Title:       original.Title,
		Description: original.Description,
		Priority:    original.Priority,
		Role:        original.Role,
		Status:      TaskPending,
	}
	if original.DependsOn != nil {
		newTask.DependsOn = append([]int{}, original.DependsOn...)
	}
	if original.Tags != nil {
		newTask.Tags = append([]string{}, original.Tags...)
	}
	if original.EstimatedMinutes != 0 {
		newTask.EstimatedMinutes = original.EstimatedMinutes
	}

	if adaptContext == "" {
		// Simple copy: append "(copy)" suffix
		newTask.Title = original.Title + " (copy)"
		plan.Tasks = append(plan.Tasks, newTask)
		return newTask, nil
	}

	// AI-driven adaptation
	prompt := ClonePrompt(original, adaptContext)
	result, err := p.Complete(ctx, prompt, opts)
	if err != nil {
		return nil, fmt.Errorf("clone: provider error: %w", err)
	}

	adapted, err := parseCloneResponse(result.Output)
	if err != nil {
		return nil, fmt.Errorf("clone: parse error: %w", err)
	}

	newTask.Title = adapted.Title
	newTask.Description = adapted.Description

	plan.Tasks = append(plan.Tasks, newTask)
	return newTask, nil
}

// parseCloneResponse extracts the adapted task JSON from the AI response.
func parseCloneResponse(response string) (*cloneItem, error) {
	start := strings.Index(response, "{")
	end := strings.LastIndex(response, "}")
	if start == -1 || end == -1 || end <= start {
		return nil, fmt.Errorf("no JSON object found in response")
	}
	jsonStr := response[start : end+1]

	var item cloneItem
	if err := json.Unmarshal([]byte(jsonStr), &item); err != nil {
		return nil, fmt.Errorf("parsing clone response: %w", err)
	}
	if item.Title == "" {
		return nil, fmt.Errorf("clone produced a task with no title")
	}
	return &item, nil
}
