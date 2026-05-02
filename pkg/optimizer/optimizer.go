// Package optimizer provides AI-driven plan optimization before execution.
// It reviews the full task list and suggests structural improvements:
// reordering for better dependency flow, splitting large tasks, merging
// small related tasks, and flagging contradictory or redundant work.
package optimizer

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/provider"
)

// SuggestionType classifies what kind of improvement is suggested.
type SuggestionType string

const (
	SuggestionReorder   SuggestionType = "reorder"   // change execution order
	SuggestionSplit     SuggestionType = "split"      // break one task into multiple
	SuggestionMerge     SuggestionType = "merge"      // combine two or more tasks
	SuggestionFlag      SuggestionType = "flag"       // contradictory, redundant, or risky
	SuggestionDependency SuggestionType = "dependency" // missing or wrong dependency
)

// Severity indicates urgency level of a suggestion.
type Severity string

const (
	SeverityInfo    Severity = "info"
	SeverityWarning Severity = "warning"
	SeverityError   Severity = "error"
)

// Suggestion is a single optimization recommendation.
type Suggestion struct {
	Type        SuggestionType `json:"type"`
	Description string         `json:"description"`
	TaskIDs     []int          `json:"task_ids,omitempty"` // affected task IDs
	Severity    Severity       `json:"severity"`
}

// SplitSpec describes how one task should be broken into sub-tasks.
type SplitSpec struct {
	OriginalID int      `json:"original_id"`
	NewTasks   []string `json:"new_tasks"` // titles of the replacement tasks
}

// MergeSpec describes which tasks should be combined.
type MergeSpec struct {
	TaskIDs      []int  `json:"task_ids"`
	MergedTitle  string `json:"merged_title"`
}

// OptimizeResult is the full output of the optimization pass.
type OptimizeResult struct {
	// Suggestions is the ordered list of improvement recommendations.
	Suggestions []Suggestion `json:"suggestions"`

	// ReorderedIDs lists all task IDs in the AI-suggested execution order.
	// Applying this reordering will update task Priority fields accordingly.
	// An empty slice means no reordering is suggested.
	ReorderedIDs []int `json:"reordered_ids,omitempty"`

	// Splits are tasks the AI recommends breaking into smaller pieces.
	Splits []SplitSpec `json:"splits,omitempty"`

	// Merges are groups of tasks the AI recommends combining.
	Merges []MergeSpec `json:"merges,omitempty"`

	// Summary is a short human-readable overview of what was found.
	Summary string `json:"summary"`
}

// HasActionable returns true if there are any reorders, splits, or merges to apply.
func (r *OptimizeResult) HasActionable() bool {
	return len(r.ReorderedIDs) > 0 || len(r.Splits) > 0 || len(r.Merges) > 0
}

// aiResponse is the raw JSON structure returned by the AI.
type aiResponse struct {
	Summary      string       `json:"summary"`
	Suggestions  []Suggestion `json:"suggestions"`
	ReorderedIDs []int        `json:"reordered_ids"`
	Splits       []SplitSpec  `json:"splits"`
	Merges       []MergeSpec  `json:"merges"`
}

// Optimize performs an AI review of the plan and returns optimization suggestions.
// It does NOT modify the plan — callers decide whether to apply changes.
func Optimize(ctx context.Context, prov provider.Provider, model string, timeout time.Duration, plan *pm.Plan) (*OptimizeResult, error) {
	if plan == nil || len(plan.Tasks) == 0 {
		return &OptimizeResult{Summary: "No tasks to optimize."}, nil
	}

	prompt := buildOptimizePrompt(plan)

	opts := provider.Options{
		Model:   model,
		Timeout: timeout,
	}

	result, err := prov.Complete(ctx, prompt, opts)
	if err != nil {
		return nil, fmt.Errorf("optimizer: provider call failed: %w", err)
	}

	return parseResponse(result.Output, plan)
}

// buildOptimizePrompt constructs the AI prompt for plan analysis.
func buildOptimizePrompt(plan *pm.Plan) string {
	var sb strings.Builder

	sb.WriteString("You are an expert AI project manager reviewing a task plan before execution.\n")
	sb.WriteString("Analyze the following task list and suggest structural improvements.\n\n")

	sb.WriteString(fmt.Sprintf("GOAL: %s\n\n", plan.Goal))
	sb.WriteString("TASK LIST:\n")
	for _, t := range plan.Tasks {
		sb.WriteString(fmt.Sprintf("  Task %d [P%d]: %s\n", t.ID, t.Priority, t.Title))
		if t.Description != "" {
			sb.WriteString(fmt.Sprintf("    Description: %s\n", t.Description))
		}
		if len(t.DependsOn) > 0 {
			deps := make([]string, len(t.DependsOn))
			for i, d := range t.DependsOn {
				deps[i] = fmt.Sprintf("%d", d)
			}
			sb.WriteString(fmt.Sprintf("    Depends on: [%s]\n", strings.Join(deps, ", ")))
		}
		if t.EstimatedMinutes > 0 {
			sb.WriteString(fmt.Sprintf("    Estimated: %d min\n", t.EstimatedMinutes))
		}
	}

	sb.WriteString(`
INSTRUCTIONS:
Analyze the task list for:
1. REORDERING: Are tasks in the best execution order? Consider dependencies, risk (risky tasks early), and logical flow.
2. SPLITTING: Are any tasks too large or mixing concerns? Suggest splitting if a task has multiple unrelated sub-goals.
3. MERGING: Are any tasks trivially small or closely related enough to merge without losing clarity?
4. FLAGS: Are any tasks contradictory, redundant, ambiguous, or potentially dangerous?
5. DEPENDENCIES: Are there implicit dependencies not captured in depends_on? Missing ones block execution.

Respond ONLY with a JSON object in this exact structure (no markdown, no extra text):
{
  "summary": "1-2 sentence overview of what you found",
  "suggestions": [
    {
      "type": "reorder|split|merge|flag|dependency",
      "description": "Clear explanation of the suggestion",
      "task_ids": [1, 2],
      "severity": "info|warning|error"
    }
  ],
  "reordered_ids": [3, 1, 2, 4],
  "splits": [
    {
      "original_id": 5,
      "new_tasks": ["Sub-task A title", "Sub-task B title"]
    }
  ],
  "merges": [
    {
      "task_ids": [2, 3],
      "merged_title": "Combined task title"
    }
  ]
}

Rules:
- reordered_ids must list ALL task IDs (even unchanged ones) in the new suggested order.
- If no reordering is needed, omit reordered_ids or return an empty array.
- If no splits are suggested, omit splits or return an empty array.
- If no merges are suggested, omit merges or return an empty array.
- Keep suggestions concise and actionable. Aim for 3-8 total suggestions.
- severity "error" = plan will likely fail without fixing this.
- severity "warning" = meaningful improvement available.
- severity "info" = minor optimization.
`)

	return sb.String()
}

// parseResponse extracts the OptimizeResult from the raw AI output.
func parseResponse(output string, plan *pm.Plan) (*OptimizeResult, error) {
	// Strip markdown code fences if present.
	cleaned := strings.TrimSpace(output)
	if idx := strings.Index(cleaned, "{"); idx > 0 {
		cleaned = cleaned[idx:]
	}
	if idx := strings.LastIndex(cleaned, "}"); idx >= 0 && idx < len(cleaned)-1 {
		cleaned = cleaned[:idx+1]
	}

	var raw aiResponse
	if err := json.Unmarshal([]byte(cleaned), &raw); err != nil {
		// Return a degraded result with the raw text as the summary.
		return &OptimizeResult{
			Summary: fmt.Sprintf("Could not parse optimizer response: %v\n\nRaw output:\n%s", err, output),
		}, nil
	}

	// Validate reordered_ids: must contain all task IDs.
	if len(raw.ReorderedIDs) > 0 {
		if !validateReorder(raw.ReorderedIDs, plan) {
			raw.ReorderedIDs = nil // discard invalid reordering
		}
	}

	return &OptimizeResult{
		Summary:      raw.Summary,
		Suggestions:  raw.Suggestions,
		ReorderedIDs: raw.ReorderedIDs,
		Splits:       raw.Splits,
		Merges:       raw.Merges,
	}, nil
}

// validateReorder checks that reorderedIDs contains exactly the same task IDs as the plan.
func validateReorder(ids []int, plan *pm.Plan) bool {
	if len(ids) != len(plan.Tasks) {
		return false
	}
	planIDs := make(map[int]bool, len(plan.Tasks))
	for _, t := range plan.Tasks {
		planIDs[t.ID] = true
	}
	seen := make(map[int]bool, len(ids))
	for _, id := range ids {
		if !planIDs[id] {
			return false
		}
		if seen[id] {
			return false // duplicate
		}
		seen[id] = true
	}
	return true
}

// ApplyReorder updates the Priority field of each task in the plan to match
// the suggested order. Priority 1 = first in the reordered list.
// It does NOT save state — the caller is responsible for persisting changes.
func ApplyReorder(plan *pm.Plan, orderedIDs []int) {
	idToPriority := make(map[int]int, len(orderedIDs))
	for i, id := range orderedIDs {
		idToPriority[id] = i + 1
	}
	for _, t := range plan.Tasks {
		if p, ok := idToPriority[t.ID]; ok {
			t.Priority = p
		}
	}
}
