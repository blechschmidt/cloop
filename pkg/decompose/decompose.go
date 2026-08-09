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
	b.WriteString("\nOutput ONLY a valid JSON array of at least 3 sub-task objects (no explanation, no markdown fences):\n")
	b.WriteString(`[{"title":"short title","description":"detailed description","priority":1,"role":"backend","estimated_minutes":30},`)
	b.WriteString(`{"title":"another sub-task","description":"details","priority":2,"role":"testing","estimated_minutes":20}]`)
	b.WriteString("\n\nFor role, choose one of: backend, frontend, testing, security, devops, data, docs, review, or empty string.\n")
	b.WriteString("priority is the relative order within the sub-tasks (1 = do first).\n")
	b.WriteString("estimated_minutes is your best estimate of how long the sub-task will take.")
	return b.String()
}

// retryInstruction is appended to the prompt when a first attempt produced an
// unusable or degenerate answer (nothing parseable, or fewer than 2 sub-tasks).
const retryInstruction = "\n\nIMPORTANT: A previous attempt did not produce a usable answer. " +
	"You MUST respond with ONLY a JSON array of 3 to 7 sub-task objects in the exact format shown above. " +
	"Splitting into a single sub-task is not acceptable. " +
	"Your entire response must start with '[' and end with ']' — no prose, no markdown."

// decomposeItem is the raw JSON structure returned by the AI for a single sub-task.
type decomposeItem struct {
	Title            string       `json:"title"`
	Description      string       `json:"description"`
	Priority         int          `json:"priority"`
	Role             pm.AgentRole `json:"role"`
	EstimatedMinutes int          `json:"estimated_minutes"`
}

// extractSubtaskItems finds the first parseable JSON array of sub-task objects
// in an AI response. Models frequently surround the JSON with narration,
// markdown fences, or wrap it in an envelope object, so a naive
// first-'['-to-last-']' substring is not reliable: any '[' in the preamble
// (e.g. "[analysis]") corrupts it. Instead, every '[' position is tried with a
// json.Decoder, which reads exactly one complete JSON value and ignores
// trailing text. As a last resort a lone sub-task object is accepted.
func extractSubtaskItems(response string) ([]decomposeItem, error) {
	for i := 0; i < len(response); i++ {
		if response[i] != '[' {
			continue
		}
		dec := json.NewDecoder(strings.NewReader(response[i:]))
		var items []decomposeItem
		if err := dec.Decode(&items); err == nil && len(items) > 0 {
			return items, nil
		}
	}
	// Fallback: a single object without array brackets.
	for i := 0; i < len(response); i++ {
		if response[i] != '{' {
			continue
		}
		dec := json.NewDecoder(strings.NewReader(response[i:]))
		var item decomposeItem
		if err := dec.Decode(&item); err == nil && item.Title != "" {
			return []decomposeItem{item}, nil
		}
	}
	return nil, fmt.Errorf("no JSON sub-task array found in decompose response")
}

// ParseSubTasks parses the AI's JSON response into sub-tasks.
// The returned tasks have no IDs set (caller assigns IDs).
// Tags and Assignee from the parent are inherited by all sub-tasks.
// The first sub-task's DependsOn is set to []int{parentID}.
// Subsequent sub-tasks depend on the previous sub-task sequentially.
func ParseSubTasks(response string, parent *pm.Task) ([]*pm.Task, error) {
	items, err := extractSubtaskItems(response)
	if err != nil {
		return nil, err
	}
	// Clamp to max 7.
	if len(items) > 7 {
		items = items[:7]
	}

	tasks := make([]*pm.Task, 0, len(items))
	for _, item := range items {
		if strings.TrimSpace(item.Title) == "" {
			continue
		}

		// Inherit parent tags (defensive copy).
		var tags []string
		if len(parent.Tags) > 0 {
			tags = append([]string{}, parent.Tags...)
		}

		t := &pm.Task{
			// ID is left as zero — caller assigns IDs.
			Title:            item.Title,
			Description:      item.Description,
			Priority:         parent.Priority,
			Role:             item.Role,
			Status:           pm.TaskPending,
			Tags:             tags,
			Assignee:         parent.Assignee,
			EstimatedMinutes: item.EstimatedMinutes,
		}

		// First kept sub-task depends on the parent (which will be marked
		// skipped). Sequential dep wiring for the rest (sub[i] depends on
		// sub[i-1]) is applied by the caller after IDs are assigned.
		if len(tasks) == 0 {
			t.DependsOn = []int{parent.ID}
		}

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

// Decompose calls the AI to break a single task into sub-tasks and returns the
// result without modifying the plan. Callers must assign IDs and inject into
// the plan themselves (see InjectSubTasks).
//
// The proposed sub-tasks are deliberately NOT semantically deduplicated
// against the plan: sub-tasks are a refinement of the parent and by
// construction cover the same work, so dedup against a plan that contains the
// parent classifies them all as duplicates and silently discards them. Since
// applying a decomposition marks the parent skipped, any dropped sub-task
// would be silently lost work. Both consumers (UI modal, CLI preview) have a
// human review step instead.
//
// A degenerate first answer (unparseable, or fewer than 2 sub-tasks) gets one
// retry with a firmer instruction; provider transport errors are returned
// immediately.
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

	subTasks, parseErr := ParseSubTasks(result.Output, task)
	if parseErr != nil || len(subTasks) < 2 {
		retryResult, retryErr := p.Complete(ctx, prompt+retryInstruction, opts)
		if retryErr == nil {
			retryTasks, retryParseErr := ParseSubTasks(retryResult.Output, task)
			if retryParseErr == nil && len(retryTasks) > len(subTasks) {
				subTasks = retryTasks
				parseErr = nil
			}
		}
		if len(subTasks) == 0 {
			if parseErr != nil {
				return nil, fmt.Errorf("decompose: parse error: %w", parseErr)
			}
			return nil, fmt.Errorf("decompose produced no sub-tasks")
		}
	}

	return &DecomposeResult{Parent: task, SubTasks: subTasks}, nil
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
