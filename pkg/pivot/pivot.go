// Package pivot implements AI-powered goal pivot and plan re-generation.
// Given an old goal and a new goal, it asks the AI to classify existing tasks
// as keep/skip and generate new tasks to fulfil the new goal.
package pivot

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/provider"
)

// SkipDirective tells the AI which pending task to skip and why.
type SkipDirective struct {
	ID     int    `json:"id"`
	Reason string `json:"reason"`
}

// NewTaskSpec is a task the AI wants to add to fulfil the new goal.
type NewTaskSpec struct {
	Title            string      `json:"title"`
	Description      string      `json:"description"`
	Priority         int         `json:"priority"`
	Role             pm.AgentRole `json:"role,omitempty"`
	EstimatedMinutes int         `json:"estimated_minutes,omitempty"`
	Tags             []string    `json:"tags,omitempty"`
}

// PivotResult is the structured JSON returned by the AI during a pivot.
type PivotResult struct {
	// Keep lists IDs of completed/in_progress/pending tasks that are still
	// relevant to the new goal and should be preserved unchanged.
	Keep []int `json:"keep"`

	// Skip lists pending tasks that are no longer relevant.
	Skip []SkipDirective `json:"skip"`

	// Add lists brand-new tasks required to fulfil the new goal.
	Add []NewTaskSpec `json:"add"`

	// Rationale is a short human-readable explanation of the pivot decisions.
	Rationale string `json:"rationale"`
}

// PivotPrompt builds the AI prompt that asks for a JSON pivot plan.
// oldGoal and newGoal are the project goals before and after the pivot.
// plan is the current task plan (may include done, in_progress, and pending tasks).
func PivotPrompt(oldGoal, newGoal string, plan *pm.Plan) string {
	var b strings.Builder

	b.WriteString("You are an expert AI project manager performing a plan pivot.\n")
	b.WriteString("A project is changing direction. You must surgically update the existing task plan.\n\n")

	b.WriteString("## OLD GOAL\n")
	b.WriteString(oldGoal)
	b.WriteString("\n\n")

	b.WriteString("## NEW GOAL\n")
	b.WriteString(newGoal)
	b.WriteString("\n\n")

	b.WriteString("## CURRENT PLAN\n")
	for _, t := range plan.Tasks {
		b.WriteString(fmt.Sprintf("- ID %d | %s | status=%s | priority=%d",
			t.ID, t.Title, t.Status, t.Priority))
		if t.Role != "" {
			b.WriteString(fmt.Sprintf(" | role=%s", t.Role))
		}
		if t.Description != "" {
			desc := t.Description
			if len(desc) > 120 {
				desc = desc[:120] + "..."
			}
			b.WriteString(fmt.Sprintf("\n  desc: %s", desc))
		}
		b.WriteString("\n")
	}
	b.WriteString("\n")

	b.WriteString("## YOUR JOB\n")
	b.WriteString("Analyse each task and decide:\n")
	b.WriteString("1. KEEP — tasks that are still useful for the NEW goal (all done/in_progress tasks must always be kept; relevant pending tasks may also be kept)\n")
	b.WriteString("2. SKIP — pending tasks that are no longer relevant; provide a concise reason per task\n")
	b.WriteString("3. ADD — new tasks required to fulfil the new goal that don't already exist\n\n")
	b.WriteString("Rules:\n")
	b.WriteString("- Every existing task ID must appear in exactly one of keep or skip (never both, never neither).\n")
	b.WriteString("- Tasks with status done, in_progress, or failed MUST be in keep (never skip them).\n")
	b.WriteString("- New tasks in add must have unique titles not already in the plan.\n")
	b.WriteString("- Priority 1 is highest. Assign realistic priorities to added tasks.\n")
	b.WriteString("- Keep the number of new tasks focused — add only what is genuinely needed.\n\n")

	b.WriteString("## OUTPUT FORMAT\n")
	b.WriteString("Respond with ONLY a single JSON object — no markdown fences, no prose before or after:\n\n")
	b.WriteString(`{
  "keep": [<id>, ...],
  "skip": [{"id": <id>, "reason": "<why>"}, ...],
  "add": [
    {
      "title": "<title>",
      "description": "<description>",
      "priority": <1-10>,
      "role": "<backend|frontend|testing|security|devops|data|docs|review>",
      "estimated_minutes": <int>,
      "tags": ["<tag>", ...]
    }
  ],
  "rationale": "<2-3 sentence summary of the pivot decisions>"
}`)
	b.WriteString("\n")

	return b.String()
}

// Pivot sends the current plan and both goals to the AI provider and applies
// the returned JSON diff to produce an updated plan.
//
// The plan passed in is modified in place:
//   - Pending tasks in the skip list are marked TaskSkipped with the AI reason.
//   - New tasks from the add list are appended with fresh IDs.
//   - plan.Goal is updated to newGoal.
//
// The plan is returned for convenience.
func Pivot(ctx context.Context, p provider.Provider, model string, oldGoal, newGoal string, plan *pm.Plan) (*PivotResult, error) {
	if plan == nil {
		return nil, fmt.Errorf("no plan to pivot")
	}

	prompt := PivotPrompt(oldGoal, newGoal, plan)

	result, err := p.Complete(ctx, prompt, provider.Options{
		Model:   model,
		Timeout: 5 * time.Minute,
	})
	if err != nil {
		return nil, fmt.Errorf("pivot AI call: %w", err)
	}

	raw := strings.TrimSpace(result.Output)
	// Strip markdown code fences if the model wrapped the JSON anyway.
	raw = stripFences(raw)

	var pr PivotResult
	if err := json.Unmarshal([]byte(raw), &pr); err != nil {
		return nil, fmt.Errorf("pivot: parse AI response: %w\nraw:\n%s", err, raw)
	}

	// Validate: every existing task ID must be accounted for.
	if err := validateResult(plan, &pr); err != nil {
		return nil, fmt.Errorf("pivot: invalid AI response: %w", err)
	}

	// Apply skips.
	skipReasons := make(map[int]string, len(pr.Skip))
	for _, s := range pr.Skip {
		skipReasons[s.ID] = s.Reason
	}
	for _, t := range plan.Tasks {
		if reason, skip := skipReasons[t.ID]; skip {
			t.Status = pm.TaskSkipped
			if reason != "" {
				pm.AddAnnotation(t, "ai", "Skipped during pivot: "+reason)
			}
		}
	}

	// Determine next free ID.
	maxID := 0
	for _, t := range plan.Tasks {
		if t.ID > maxID {
			maxID = t.ID
		}
	}

	// Append new tasks.
	for _, spec := range pr.Add {
		maxID++
		t := &pm.Task{
			ID:               maxID,
			Title:            spec.Title,
			Description:      spec.Description,
			Priority:         spec.Priority,
			Status:           pm.TaskPending,
			Role:             spec.Role,
			EstimatedMinutes: spec.EstimatedMinutes,
			Tags:             spec.Tags,
		}
		if t.Priority <= 0 {
			t.Priority = 5
		}
		plan.Tasks = append(plan.Tasks, t)
	}

	// Update goal.
	plan.Goal = newGoal

	return &pr, nil
}

// validateResult checks that every task ID in the plan is covered by exactly
// one of keep or skip in the PivotResult, and that done/in_progress/failed
// tasks are not in the skip list.
func validateResult(plan *pm.Plan, pr *PivotResult) error {
	keepSet := make(map[int]bool, len(pr.Keep))
	for _, id := range pr.Keep {
		keepSet[id] = true
	}
	skipSet := make(map[int]bool, len(pr.Skip))
	for _, s := range pr.Skip {
		skipSet[s.ID] = true
	}

	for _, t := range plan.Tasks {
		inKeep := keepSet[t.ID]
		inSkip := skipSet[t.ID]

		if inKeep && inSkip {
			return fmt.Errorf("task #%d appears in both keep and skip", t.ID)
		}
		if !inKeep && !inSkip {
			return fmt.Errorf("task #%d is not accounted for (must be in keep or skip)", t.ID)
		}
		// Completed/in-progress tasks must not be skipped.
		if inSkip && (t.Status == pm.TaskDone || t.Status == pm.TaskInProgress || t.Status == pm.TaskFailed) {
			return fmt.Errorf("task #%d has status %q and must not be skipped", t.ID, t.Status)
		}
	}
	return nil
}

// stripFences removes optional ```json ... ``` wrapping that some models add.
func stripFences(s string) string {
	if strings.HasPrefix(s, "```") {
		// Remove first line (```json or ```)
		idx := strings.Index(s, "\n")
		if idx >= 0 {
			s = s[idx+1:]
		}
		// Remove trailing ```
		if end := strings.LastIndex(s, "```"); end >= 0 {
			s = s[:end]
		}
		s = strings.TrimSpace(s)
	}
	return s
}
