package pm

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/provider"
)

// MergePrompt builds an AI prompt to synthesise a single merged task from multiple input tasks.
func MergePrompt(tasks []*Task) string {
	var b strings.Builder
	b.WriteString("You are an AI product manager. Multiple related tasks need to be combined into one cohesive task.\n\n")
	b.WriteString("## TASKS TO MERGE\n\n")

	for _, t := range tasks {
		if t.Role != "" {
			b.WriteString(fmt.Sprintf("### Task %d: %s [role: %s]\n", t.ID, t.Title, t.Role))
		} else {
			b.WriteString(fmt.Sprintf("### Task %d: %s\n", t.ID, t.Title))
		}
		if t.Description != "" {
			b.WriteString(fmt.Sprintf("Description: %s\n", t.Description))
		}
		if len(t.Tags) > 0 {
			b.WriteString(fmt.Sprintf("Tags: %s\n", strings.Join(t.Tags, ", ")))
		}
		if len(t.Annotations) > 0 {
			b.WriteString("Notes:\n")
			for _, a := range t.Annotations {
				b.WriteString(fmt.Sprintf("  - [%s] %s\n", a.Author, a.Text))
			}
		}
		b.WriteString("\n")
	}

	b.WriteString("## INSTRUCTIONS\n")
	b.WriteString("Synthesise these tasks into a single merged task that:\n")
	b.WriteString("- Has a concise, accurate title that captures the combined scope\n")
	b.WriteString("- Has a thorough description covering all work from the input tasks\n")
	b.WriteString("- Selects the most appropriate role for the merged work\n\n")
	b.WriteString("Output ONLY valid JSON (no explanation, no markdown):\n")
	b.WriteString(`{"title":"merged task title","description":"full description covering all work","role":"backend"}`)
	b.WriteString("\n\nFor role, choose: backend, frontend, testing, security, devops, data, docs, review, or empty string.\n")
	return b.String()
}

// mergeItem is the raw JSON structure returned by the AI for the merged task.
type mergeItem struct {
	Title       string    `json:"title"`
	Description string    `json:"description"`
	Role        AgentRole `json:"role"`
}

// MergeOptions controls the behaviour of Merge.
type MergeOptions struct {
	// Provider options forwarded to the AI call.
	Provider provider.Options
}

// Merge synthesises a new task from the identified input tasks using an AI provider:
//  1. Validates all IDs exist in the plan.
//  2. Calls the AI with MergePrompt to produce title/description/role.
//  3. Builds the merged task with union deps/tags, highest priority, earliest deadline.
//  4. Appends the merged task to the plan.
//  5. Marks all input tasks as skipped.
//
// The caller is responsible for saving state after Merge returns.
func Merge(ctx context.Context, p provider.Provider, opts MergeOptions, plan *Plan, ids []string) (*Task, error) {
	if len(ids) < 2 {
		return nil, fmt.Errorf("merge requires at least 2 task IDs")
	}

	// Resolve tasks
	tasks := make([]*Task, 0, len(ids))
	seen := make(map[int]bool, len(ids))
	for _, idStr := range ids {
		var id int
		if _, err := fmt.Sscanf(idStr, "%d", &id); err != nil {
			return nil, fmt.Errorf("invalid task ID %q: must be a number", idStr)
		}
		if seen[id] {
			return nil, fmt.Errorf("duplicate task ID %d", id)
		}
		seen[id] = true
		var found *Task
		for _, t := range plan.Tasks {
			if t.ID == id {
				found = t
				break
			}
		}
		if found == nil {
			return nil, fmt.Errorf("task %d not found in plan", id)
		}
		tasks = append(tasks, found)
	}

	// Call the AI
	prompt := MergePrompt(tasks)
	result, err := p.Complete(ctx, prompt, opts.Provider)
	if err != nil {
		return nil, fmt.Errorf("merge: provider error: %w", err)
	}

	// Parse AI response
	merged, err := parseMergeResponse(result.Output)
	if err != nil {
		return nil, fmt.Errorf("merge: parse error: %w", err)
	}

	// Compute inherited attributes from all input tasks
	highestPriority := tasks[0].Priority
	var earliestDeadline *time.Time
	depsSet := make(map[int]bool)
	tagsSet := make(map[string]bool)

	inputIDSet := make(map[int]bool, len(tasks))
	for _, t := range tasks {
		inputIDSet[t.ID] = true
	}

	for _, t := range tasks {
		if t.Priority < highestPriority {
			highestPriority = t.Priority
		}
		if t.Deadline != nil {
			if earliestDeadline == nil || t.Deadline.Before(*earliestDeadline) {
				dl := *t.Deadline
				earliestDeadline = &dl
			}
		}
		for _, depID := range t.DependsOn {
			// Only inherit deps that point outside the merge set
			if !inputIDSet[depID] {
				depsSet[depID] = true
			}
		}
		for _, tag := range t.Tags {
			tagsSet[tag] = true
		}
	}

	// Build union slices
	deps := make([]int, 0, len(depsSet))
	for id := range depsSet {
		deps = append(deps, id)
	}
	tags := make([]string, 0, len(tagsSet))
	for tag := range tagsSet {
		tags = append(tags, tag)
	}

	// Assign next available ID
	maxID := 0
	for _, t := range plan.Tasks {
		if t.ID > maxID {
			maxID = t.ID
		}
	}
	newID := maxID + 1

	newTask := &Task{
		ID:          newID,
		Title:       merged.Title,
		Description: merged.Description,
		Priority:    highestPriority,
		Role:        merged.Role,
		Status:      TaskPending,
		DependsOn:   deps,
		Tags:        tags,
		Deadline:    earliestDeadline,
	}

	// Append merged task to plan
	plan.Tasks = append(plan.Tasks, newTask)

	// Mark input tasks as skipped
	for _, t := range tasks {
		t.Status = TaskSkipped
	}

	// Remap any external task's dependency on a merged task to the new merged task
	for _, t := range plan.Tasks {
		if t.ID == newID {
			continue
		}
		for i, depID := range t.DependsOn {
			if inputIDSet[depID] {
				t.DependsOn[i] = newID
			}
		}
	}

	return newTask, nil
}

// parseMergeResponse extracts the merged task JSON from the AI response.
func parseMergeResponse(response string) (*mergeItem, error) {
	start := strings.Index(response, "{")
	end := strings.LastIndex(response, "}")
	if start == -1 || end == -1 || end <= start {
		return nil, fmt.Errorf("no JSON object found in response")
	}
	jsonStr := response[start : end+1]

	var item mergeItem
	if err := json.Unmarshal([]byte(jsonStr), &item); err != nil {
		return nil, fmt.Errorf("parsing merge response: %w", err)
	}
	if item.Title == "" {
		return nil, fmt.Errorf("merge produced a task with no title")
	}
	return &item, nil
}
