// Package health provides AI-driven plan quality evaluation before execution.
// It sends the full task list to the provider and asks it to rate the plan
// on task clarity, dependency correctness, scope creep risk, and estimated
// success probability, returning a numeric health score and actionable feedback.
package health

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/provider"
)

// HealthReport is the result of a plan health evaluation.
type HealthReport struct {
	// Score is 0-100 representing overall plan quality.
	// 90-100 = excellent, 70-89 = good, 50-69 = fair, <50 = poor.
	Score int `json:"score"`

	// Issues is a list of concrete problems found in the plan
	// (e.g. "Task 3 has no clear success criterion").
	Issues []string `json:"issues,omitempty"`

	// Suggestions is a list of improvement recommendations.
	Suggestions []string `json:"suggestions,omitempty"`

	// Summary is a brief human-readable explanation of the score.
	Summary string `json:"summary"`
}

// Grade returns a short letter grade for the health score.
func (r HealthReport) Grade() string {
	switch {
	case r.Score >= 90:
		return "A"
	case r.Score >= 80:
		return "B"
	case r.Score >= 70:
		return "C"
	case r.Score >= 60:
		return "D"
	default:
		return "F"
	}
}

// Score evaluates the quality of a plan by sending it to the AI provider and
// asking it to rate task clarity, dependency correctness, scope creep risk,
// and estimated success probability. Returns a HealthReport with a 0-100 score,
// a list of concrete issues, and a list of improvement suggestions.
func Score(ctx context.Context, prov provider.Provider, model string, timeout time.Duration, plan *pm.Plan) (HealthReport, error) {
	if plan == nil || len(plan.Tasks) == 0 {
		return HealthReport{
			Score:   100,
			Summary: "No tasks to evaluate.",
		}, nil
	}

	prompt := buildPrompt(plan)

	opts := provider.Options{
		Model:   model,
		Timeout: timeout,
	}

	result, err := prov.Complete(ctx, prompt, opts)
	if err != nil {
		return HealthReport{}, fmt.Errorf("health: provider call failed: %w", err)
	}

	return parseResponse(result.Output)
}

// buildPrompt constructs the AI evaluation prompt for plan health scoring.
func buildPrompt(plan *pm.Plan) string {
	var sb strings.Builder

	sb.WriteString("You are an expert AI project manager evaluating the quality of a task plan before execution.\n")
	sb.WriteString("Your goal is to give an honest, actionable health assessment so the team can improve the plan.\n\n")

	sb.WriteString(fmt.Sprintf("GOAL: %s\n\n", plan.Goal))
	sb.WriteString("TASK LIST:\n")
	for _, t := range plan.Tasks {
		sb.WriteString(fmt.Sprintf("  Task %d [P%d, status=%s]: %s\n", t.ID, t.Priority, t.Status, t.Title))
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
		if len(t.Tags) > 0 {
			sb.WriteString(fmt.Sprintf("    Tags: %s\n", strings.Join(t.Tags, ", ")))
		}
	}

	sb.WriteString(`
EVALUATION CRITERIA:
1. TASK CLARITY (0-25): Are tasks specific, actionable, and unambiguous? Does each task have a clear success criterion?
2. DEPENDENCY CORRECTNESS (0-25): Are task dependencies accurate and complete? Are there circular dependencies or missing edges?
3. SCOPE CREEP RISK (0-25): Is the scope well-controlled? Are tasks focused or do they mix multiple unrelated concerns?
4. SUCCESS PROBABILITY (0-25): Given the task definitions, how likely is this plan to succeed end-to-end without major rework?

TOTAL SCORE = sum of the four criteria above (0-100).

Respond ONLY with a JSON object in this exact structure (no markdown, no extra text):
{
  "score": 82,
  "summary": "1-2 sentence overall assessment",
  "issues": [
    "Task 3 has no clear success criterion — it's unclear when the task is done",
    "Task 7 depends on Task 5 but Task 5 is not in the plan"
  ],
  "suggestions": [
    "Add explicit acceptance criteria to Task 3 (e.g. 'unit tests pass', 'API returns 200')",
    "Break Task 9 into two tasks: one for schema design and one for data migration"
  ]
}

Rules:
- score must be an integer between 0 and 100.
- issues must be concrete, specific, and reference task IDs where applicable.
- suggestions must be actionable improvements directly tied to the issues.
- If the plan is excellent, issues and suggestions may be empty arrays.
- Aim for 1-5 issues and 1-5 suggestions. Do not pad with trivial observations.
- Be honest: a poorly defined plan should score below 60.
`)

	return sb.String()
}

// aiResponse is the raw JSON structure returned by the AI.
type aiResponse struct {
	Score       int      `json:"score"`
	Summary     string   `json:"summary"`
	Issues      []string `json:"issues"`
	Suggestions []string `json:"suggestions"`
}

// parseResponse extracts a HealthReport from the raw AI output.
func parseResponse(output string) (HealthReport, error) {
	// Strip markdown code fences or leading text before the JSON object.
	cleaned := strings.TrimSpace(output)
	if idx := strings.Index(cleaned, "{"); idx > 0 {
		cleaned = cleaned[idx:]
	}
	if idx := strings.LastIndex(cleaned, "}"); idx >= 0 && idx < len(cleaned)-1 {
		cleaned = cleaned[:idx+1]
	}

	var raw aiResponse
	if err := json.Unmarshal([]byte(cleaned), &raw); err != nil {
		// Return a degraded report with the raw output as the summary.
		return HealthReport{
			Score:   50,
			Summary: fmt.Sprintf("Could not parse health response: %v\n\nRaw output:\n%s", err, output),
		}, nil
	}

	// Clamp score to valid range.
	if raw.Score < 0 {
		raw.Score = 0
	}
	if raw.Score > 100 {
		raw.Score = 100
	}

	return HealthReport{
		Score:       raw.Score,
		Summary:     raw.Summary,
		Issues:      raw.Issues,
		Suggestions: raw.Suggestions,
	}, nil
}
