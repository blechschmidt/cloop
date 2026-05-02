// Package autodeps provides AI-powered automatic dependency inference for task plans.
// It analyses all pending/in-progress task titles and descriptions and suggests
// which tasks naturally depend on which others.
package autodeps

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/provider"
)

// InferPrompt builds the AI prompt that asks the model to return a JSON map of
// {task_id: [dependency_ids]} for the active (pending/in-progress) tasks in the plan.
// Completed, skipped, failed, and timed-out tasks are included as context but the
// model is told not to suggest new deps for them.
func InferPrompt(plan *pm.Plan) string {
	var sb strings.Builder

	sb.WriteString("You are an expert software project manager. ")
	sb.WriteString("Given the task list below, analyse the LOGICAL dependencies between tasks: ")
	sb.WriteString("which tasks must be completed before another task can start? ")
	sb.WriteString("Focus on tasks whose status is 'pending' or 'in_progress'. ")
	sb.WriteString("Only suggest a dependency when it is clearly required — do not add speculative deps.\n\n")

	sb.WriteString("## Project goal\n")
	sb.WriteString(plan.Goal)
	sb.WriteString("\n\n")

	sb.WriteString("## Tasks\n")
	sb.WriteString("Format: ID | Status | Title — Description\n\n")

	// Collect tasks sorted by ID for deterministic output.
	sorted := make([]*pm.Task, len(plan.Tasks))
	copy(sorted, plan.Tasks)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].ID < sorted[j].ID })

	for _, t := range sorted {
		desc := t.Description
		if desc == "" {
			desc = "(no description)"
		}
		sb.WriteString(fmt.Sprintf("  %d | %s | %s — %s\n", t.ID, t.Status, t.Title, desc))
	}

	sb.WriteString("\n## Instructions\n")
	sb.WriteString("Return ONLY a JSON object (no markdown, no explanation) mapping each task ID ")
	sb.WriteString("(as a string key) to an array of integer IDs it depends on. ")
	sb.WriteString("Only include tasks with at least one dependency. ")
	sb.WriteString("Do NOT suggest dependencies that already exist. ")
	sb.WriteString("Do NOT create circular dependencies. ")
	sb.WriteString("Tasks that are already done/skipped/failed should NOT appear as keys.\n\n")
	sb.WriteString("Example response format:\n")
	sb.WriteString(`{"3": [1, 2], "5": [3]}`)
	sb.WriteString("\n\nRespond with ONLY the JSON object:")

	return sb.String()
}

// Suggestion holds the inferred dependencies for a single task.
type Suggestion struct {
	TaskID int
	DepIDs []int
}

// Infer calls the AI provider with the plan and returns the suggested dependency map.
// The returned map keys are task IDs; values are slices of dependency IDs.
func Infer(ctx context.Context, prov provider.Provider, opts provider.Options, plan *pm.Plan) (map[int][]int, error) {
	prompt := InferPrompt(plan)

	result, err := prov.Complete(ctx, prompt, opts)
	if err != nil {
		return nil, fmt.Errorf("provider error: %w", err)
	}

	// Strip markdown fences if the model wrapped the JSON.
	raw := strings.TrimSpace(result.Output)
	if idx := strings.Index(raw, "{"); idx > 0 {
		raw = raw[idx:]
	}
	if idx := strings.LastIndex(raw, "}"); idx >= 0 && idx < len(raw)-1 {
		raw = raw[:idx+1]
	}

	// The model returns string keys; unmarshal into map[string][]int first.
	var strMap map[string][]int
	if err := json.Unmarshal([]byte(raw), &strMap); err != nil {
		return nil, fmt.Errorf("parsing AI response as JSON: %w\nRaw response:\n%s", err, result.Output)
	}

	deps := make(map[int][]int, len(strMap))
	for k, v := range strMap {
		var id int
		if _, scanErr := fmt.Sscanf(k, "%d", &id); scanErr != nil {
			return nil, fmt.Errorf("invalid task ID key %q in AI response", k)
		}
		deps[id] = v
	}
	return deps, nil
}

// Apply merges the suggested dependency map into the plan, skipping deps that
// already exist, pointing to non-existent tasks, or would create cycles.
// It returns the number of new dependencies actually added.
//
// The plan is mutated in-place; the caller is responsible for saving state.
func Apply(plan *pm.Plan, deps map[int][]int) (added int, skipped []string) {
	// Build an ID set for fast existence checks.
	taskByID := make(map[int]*pm.Task, len(plan.Tasks))
	for _, t := range plan.Tasks {
		taskByID[t.ID] = t
	}

	// Process suggestions in deterministic order.
	taskIDs := make([]int, 0, len(deps))
	for id := range deps {
		taskIDs = append(taskIDs, id)
	}
	sort.Ints(taskIDs)

	for _, taskID := range taskIDs {
		depIDs := deps[taskID]
		task, ok := taskByID[taskID]
		if !ok {
			skipped = append(skipped, fmt.Sprintf("task %d not found", taskID))
			continue
		}

		// Build existing-dep set for this task.
		existingDeps := make(map[int]bool, len(task.DependsOn))
		for _, d := range task.DependsOn {
			existingDeps[d] = true
		}

		for _, depID := range depIDs {
			if _, exists := taskByID[depID]; !exists {
				skipped = append(skipped, fmt.Sprintf("dep %d for task %d: task not found", depID, taskID))
				continue
			}
			if existingDeps[depID] {
				skipped = append(skipped, fmt.Sprintf("dep %d for task %d: already exists", depID, taskID))
				continue
			}
			if depID == taskID {
				skipped = append(skipped, fmt.Sprintf("dep %d for task %d: self-dependency", depID, taskID))
				continue
			}

			// Cycle check: temporarily add the dep and test.
			task.DependsOn = append(task.DependsOn, depID)
			if hasCycle(plan, taskByID) {
				task.DependsOn = task.DependsOn[:len(task.DependsOn)-1]
				skipped = append(skipped, fmt.Sprintf("dep %d for task %d: would create cycle", depID, taskID))
				continue
			}

			existingDeps[depID] = true
			added++
		}

		sort.Ints(task.DependsOn)
	}

	return added, skipped
}

// hasCycle performs a DFS over the plan's dependency graph and returns true if
// a cycle is detected. It is safe to call after a candidate edge has been added.
func hasCycle(plan *pm.Plan, taskByID map[int]*pm.Task) bool {
	// 0=unvisited, 1=in-stack, 2=done
	color := make(map[int]int, len(plan.Tasks))

	var dfs func(id int) bool
	dfs = func(id int) bool {
		if color[id] == 1 {
			return true // back-edge → cycle
		}
		if color[id] == 2 {
			return false
		}
		color[id] = 1
		t, ok := taskByID[id]
		if ok {
			for _, dep := range t.DependsOn {
				if dfs(dep) {
					return true
				}
			}
		}
		color[id] = 2
		return false
	}

	for _, t := range plan.Tasks {
		if color[t.ID] == 0 {
			if dfs(t.ID) {
				return true
			}
		}
	}
	return false
}
