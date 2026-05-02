// Package planedit provides AI-powered natural-language plan mutation.
// It allows users to describe changes to the task plan in plain English
// and have the AI apply those changes, returning a modified plan JSON
// that can be reviewed and confirmed before writing.
package planedit

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/provider"
)

// EditResult holds the modified plan and metadata about what changed.
type EditResult struct {
	// ModifiedPlan is the new plan produced by the AI.
	ModifiedPlan *pm.Plan
	// RemovedTasks contains tasks that the AI tried to remove.
	// These are surfaced separately so callers can require explicit confirmation.
	RemovedTasks []*pm.Task
}

// BuildEditPrompt constructs the AI prompt for natural-language plan mutation.
// It embeds the full plan JSON and the user instruction, asking the AI to return
// a modified plan JSON with only the requested changes applied.
func BuildEditPrompt(plan *pm.Plan, instruction string) string {
	planJSON, err := json.MarshalIndent(compactPlan(plan), "", "  ")
	if err != nil {
		planJSON = []byte(`{"goal":"","tasks":[]}`)
	}

	var sb strings.Builder
	sb.WriteString("You are a project management assistant. Your job is to mutate a task plan in response to a natural-language instruction.\n\n")
	sb.WriteString("## Rules\n")
	sb.WriteString("1. Apply ONLY the changes described in the instruction. Leave everything else unchanged.\n")
	sb.WriteString("2. Preserve all existing task IDs. Never renumber tasks.\n")
	sb.WriteString("3. Preserve task status (pending/in_progress/done/skipped/failed). Do not change status unless explicitly told to.\n")
	sb.WriteString("4. If the instruction asks you to add new tasks, assign them IDs that continue from the highest existing ID.\n")
	sb.WriteString("5. Only remove tasks if the instruction explicitly says to remove or delete them.\n")
	sb.WriteString("6. Return ONLY valid JSON — no explanation, no markdown fences, no preamble.\n")
	sb.WriteString("7. The JSON must be a complete plan object with the same structure as the input.\n\n")

	sb.WriteString("## Current plan JSON\n")
	sb.WriteString(string(planJSON))
	sb.WriteString("\n\n## Instruction\n")
	sb.WriteString(instruction)
	sb.WriteString("\n\n## Response (modified plan JSON only)\n")
	return sb.String()
}

// compactPlan returns a lightweight representation of the plan suitable for the prompt.
// It strips runtime-only fields (artifact paths, internal timestamps) to keep the
// prompt focused on the structural data the AI needs to reason about.
type compactTask struct {
	ID          int            `json:"id"`
	Title       string         `json:"title"`
	Description string         `json:"description,omitempty"`
	Priority    int            `json:"priority"`
	Status      pm.TaskStatus  `json:"status"`
	Role        pm.AgentRole   `json:"role,omitempty"`
	DependsOn   []int          `json:"depends_on,omitempty"`
	Tags        []string       `json:"tags,omitempty"`
	EstMinutes  int            `json:"estimated_minutes,omitempty"`
	MaxMinutes  int            `json:"max_minutes,omitempty"`
	Assignee    string         `json:"assignee,omitempty"`
	Condition   string         `json:"condition,omitempty"`
}

type compactPlanDTO struct {
	Goal  string         `json:"goal"`
	Tasks []*compactTask `json:"tasks"`
}

func compactPlan(plan *pm.Plan) *compactPlanDTO {
	out := &compactPlanDTO{Goal: plan.Goal, Tasks: make([]*compactTask, 0, len(plan.Tasks))}
	for _, t := range plan.Tasks {
		out.Tasks = append(out.Tasks, &compactTask{
			ID:          t.ID,
			Title:       t.Title,
			Description: t.Description,
			Priority:    t.Priority,
			Status:      t.Status,
			Role:        t.Role,
			DependsOn:   t.DependsOn,
			Tags:        t.Tags,
			EstMinutes:  t.EstimatedMinutes,
			MaxMinutes:  t.MaxMinutes,
			Assignee:    t.Assignee,
			Condition:   t.Condition,
		})
	}
	return out
}

// EditPlan calls the AI provider with the edit prompt and returns an EditResult.
// The caller is responsible for reviewing and confirming the changes before
// writing the modified plan to disk.
func EditPlan(ctx context.Context, p provider.Provider, opts provider.Options, plan *pm.Plan, instruction string) (*EditResult, error) {
	prompt := BuildEditPrompt(plan, instruction)
	result, err := p.Complete(ctx, prompt, opts)
	if err != nil {
		return nil, fmt.Errorf("planedit: AI call failed: %w", err)
	}
	return ParseEditResponse(plan, result.Output)
}

// ParseEditResponse parses the AI response (which should be a plan JSON) and
// returns an EditResult that describes what changed relative to the original plan.
//
// The function is lenient about JSON embedded in prose: it searches for the
// outermost { ... } block if the response contains surrounding text.
//
// Validation:
//   - The modified plan must have at least as many tasks as the original
//     (removed tasks are allowed but surfaced in EditResult.RemovedTasks).
//   - Tasks that exist in the original keep their non-structural fields
//     (artifact path, result, timing, etc.) — only the "editable" fields
//     from the AI response are applied.
func ParseEditResponse(original *pm.Plan, aiResponse string) (*EditResult, error) {
	raw := extractJSON(aiResponse)
	if raw == "" {
		return nil, fmt.Errorf("planedit: no JSON found in AI response")
	}

	var dto compactPlanDTO
	if err := json.Unmarshal([]byte(raw), &dto); err != nil {
		return nil, fmt.Errorf("planedit: invalid JSON in AI response: %w", err)
	}
	if dto.Goal == "" && len(dto.Tasks) == 0 {
		return nil, fmt.Errorf("planedit: AI returned an empty plan")
	}

	// Build a map of original tasks by ID so we can merge fields.
	origByID := make(map[int]*pm.Task, len(original.Tasks))
	for _, t := range original.Tasks {
		origByID[t.ID] = t
	}

	// Build a map of new tasks by ID.
	newByID := make(map[int]*compactTask, len(dto.Tasks))
	for _, t := range dto.Tasks {
		newByID[t.ID] = t
	}

	// Identify removed tasks.
	var removed []*pm.Task
	for _, t := range original.Tasks {
		if _, exists := newByID[t.ID]; !exists {
			removed = append(removed, t)
		}
	}

	// Determine max ID across both old and new for assigning IDs to brand-new tasks.
	maxID := 0
	for _, t := range original.Tasks {
		if t.ID > maxID {
			maxID = t.ID
		}
	}
	for _, t := range dto.Tasks {
		if t.ID > maxID {
			maxID = t.ID
		}
	}

	// Build the merged task list preserving original non-editable fields.
	merged := make([]*pm.Task, 0, len(dto.Tasks))
	for _, ct := range dto.Tasks {
		if orig, exists := origByID[ct.ID]; exists {
			// Merge: start from original, apply editable fields from AI.
			updated := *orig // copy
			updated.Title = ct.Title
			updated.Description = ct.Description
			updated.Priority = ct.Priority
			updated.Role = ct.Role
			updated.DependsOn = ct.DependsOn
			updated.Tags = ct.Tags
			updated.EstimatedMinutes = ct.EstMinutes
			updated.MaxMinutes = ct.MaxMinutes
			updated.Assignee = ct.Assignee
			updated.Condition = ct.Condition
			// Status is preserved from original unless explicitly changed
			// (the AI was instructed to preserve status, but respect if it changed it).
			updated.Status = ct.Status
			merged = append(merged, &updated)
		} else {
			// Brand-new task added by the AI.
			now := time.Now()
			_ = now
			newTask := &pm.Task{
				ID:               ct.ID,
				Title:            ct.Title,
				Description:      ct.Description,
				Priority:         ct.Priority,
				Status:           ct.Status,
				Role:             ct.Role,
				DependsOn:        ct.DependsOn,
				Tags:             ct.Tags,
				EstimatedMinutes: ct.EstMinutes,
				MaxMinutes:       ct.MaxMinutes,
				Assignee:         ct.Assignee,
				Condition:        ct.Condition,
			}
			if newTask.Status == "" {
				newTask.Status = pm.TaskPending
			}
			merged = append(merged, newTask)
		}
	}

	modifiedPlan := &pm.Plan{
		Goal:    dto.Goal,
		Tasks:   merged,
		Version: original.Version,
	}
	if modifiedPlan.Goal == "" {
		modifiedPlan.Goal = original.Goal
	}

	return &EditResult{
		ModifiedPlan: modifiedPlan,
		RemovedTasks: removed,
	}, nil
}

// extractJSON finds and returns the outermost JSON object in s.
// Returns empty string if no valid JSON object is found.
func extractJSON(s string) string {
	start := strings.Index(s, "{")
	if start == -1 {
		return ""
	}
	// Find the matching closing brace.
	depth := 0
	inString := false
	escape := false
	for i := start; i < len(s); i++ {
		c := s[i]
		if escape {
			escape = false
			continue
		}
		if c == '\\' && inString {
			escape = true
			continue
		}
		if c == '"' {
			inString = !inString
			continue
		}
		if inString {
			continue
		}
		if c == '{' {
			depth++
		} else if c == '}' {
			depth--
			if depth == 0 {
				return s[start : i+1]
			}
		}
	}
	return ""
}
