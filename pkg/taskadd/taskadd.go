// Package taskadd provides AI-powered natural language task creation.
// It converts a free-form description into a fully structured Task
// with title, description, priority, estimated minutes, tags, and
// suggested dependencies derived from the existing plan.
package taskadd

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/provider"
)

// TaskSpec holds the AI-structured representation of a new task.
type TaskSpec struct {
	Title              string    `json:"title"`
	Description        string    `json:"description"`
	Priority           int       `json:"priority"`
	Role               string    `json:"role"`
	EstimatedMinutes   int       `json:"estimated_minutes"`
	Tags               []string  `json:"tags"`
	SuggestedDependsOn []int     `json:"suggested_depends_on"`
	Rationale          string    `json:"rationale"`
}

// GenerateTaskPrompt builds the AI prompt that converts a free-form task
// description into a structured TaskSpec. existingPlan may be nil when no
// plan exists yet.
func GenerateTaskPrompt(description string, existingPlan *pm.Plan) string {
	var b strings.Builder

	b.WriteString("You are an AI product manager. Convert the following free-form task description into a fully structured task.\n\n")

	b.WriteString("## FREE-FORM DESCRIPTION\n")
	b.WriteString(description)
	b.WriteString("\n\n")

	if existingPlan != nil && len(existingPlan.Tasks) > 0 {
		b.WriteString("## EXISTING PLAN CONTEXT\n")
		b.WriteString(fmt.Sprintf("Goal: %s\n\n", existingPlan.Goal))
		b.WriteString("Existing tasks (for dependency suggestions):\n")
		for _, t := range existingPlan.Tasks {
			b.WriteString(fmt.Sprintf("  #%d [P%d] %s — %s\n", t.ID, t.Priority, t.Title, t.Status))
		}
		b.WriteString("\n")
	}

	b.WriteString("## INSTRUCTIONS\n")
	b.WriteString("Produce a JSON object with these fields:\n")
	b.WriteString("- title: short, imperative task title (max 80 chars)\n")
	b.WriteString("- description: clear, detailed description of what needs to be done (1-3 sentences)\n")
	b.WriteString("- priority: integer 1-10, where 1 is highest priority (infer from urgency/importance in description)\n")
	b.WriteString("- role: one of backend, frontend, testing, security, devops, data, docs, review — choose the best fit, or empty string\n")
	b.WriteString("- estimated_minutes: realistic integer estimate of how long this task will take\n")
	b.WriteString("- tags: array of 1-3 relevant lowercase tags (e.g. [\"auth\", \"api\", \"performance\"])\n")

	if existingPlan != nil && len(existingPlan.Tasks) > 0 {
		b.WriteString("- suggested_depends_on: array of task IDs from the existing plan that this new task logically depends on (empty array if none)\n")
	} else {
		b.WriteString("- suggested_depends_on: empty array []\n")
	}

	b.WriteString("- rationale: one sentence explaining your structuring decisions\n\n")
	b.WriteString("Output ONLY valid JSON with no explanation, no markdown code fences, no extra text.\n\n")
	b.WriteString(`Example output: {"title":"Refactor auth module to use JWT","description":"Replace the current session-based authentication with JWT tokens. Update all protected endpoints to validate Bearer tokens and remove legacy session middleware.","priority":3,"role":"backend","estimated_minutes":120,"tags":["auth","refactor","jwt"],"suggested_depends_on":[],"rationale":"Classified as backend with medium-high priority since it touches security-critical code that multiple features depend on."}`)

	return b.String()
}

// ParseTaskResponse parses the AI's JSON response into a TaskSpec.
// It tolerates leading/trailing whitespace and extracts the first JSON
// object it finds in the response.
func ParseTaskResponse(response string) (*TaskSpec, error) {
	// Find the JSON object in the response
	start := strings.Index(response, "{")
	end := strings.LastIndex(response, "}")
	if start == -1 || end == -1 || end <= start {
		return nil, fmt.Errorf("no JSON object found in response")
	}
	jsonStr := response[start : end+1]

	var spec TaskSpec
	if err := json.Unmarshal([]byte(jsonStr), &spec); err != nil {
		return nil, fmt.Errorf("parsing task spec: %w", err)
	}

	if spec.Title == "" {
		return nil, fmt.Errorf("AI returned empty task title")
	}

	// Clamp priority to valid range
	if spec.Priority < 1 {
		spec.Priority = 1
	}
	if spec.Priority > 10 {
		spec.Priority = 10
	}

	// Clamp estimated minutes to a sane range
	if spec.EstimatedMinutes < 0 {
		spec.EstimatedMinutes = 0
	}

	return &spec, nil
}

// Enrich calls the AI provider to convert a free-form description into a
// structured TaskSpec using the existing plan for dependency context.
func Enrich(ctx context.Context, p provider.Provider, opts provider.Options, description string, existingPlan *pm.Plan) (*TaskSpec, error) {
	prompt := GenerateTaskPrompt(description, existingPlan)
	result, err := p.Complete(ctx, prompt, opts)
	if err != nil {
		return nil, fmt.Errorf("taskadd: provider error: %w", err)
	}
	spec, err := ParseTaskResponse(result.Output)
	if err != nil {
		return nil, fmt.Errorf("taskadd: parse error: %w", err)
	}
	return spec, nil
}
