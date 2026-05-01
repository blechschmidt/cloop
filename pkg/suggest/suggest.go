// Package suggest implements AI-driven feature idea generation.
// It brainstorms concrete feature suggestions for a project and returns
// them in a structured format suitable for interactive user review.
package suggest

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/provider"
)

// Category classifies the type of a suggestion.
type Category string

const (
	CategoryFeature     Category = "feature"
	CategoryUX          Category = "ux"
	CategoryPerformance Category = "performance"
	CategorySecurity    Category = "security"
	CategoryDX          Category = "dx"         // developer experience
	CategoryIntegration Category = "integration"
	CategoryDocs        Category = "docs"
)

// Effort is a rough implementation size estimate.
type Effort string

const (
	EffortXS Effort = "xs" // < 1 hour
	EffortS  Effort = "s"  // 1–4 hours
	EffortM  Effort = "m"  // 4–16 hours
	EffortL  Effort = "l"  // 1–5 days
	EffortXL Effort = "xl" // > 1 week
)

// Suggestion is a single AI-brainstormed feature idea.
type Suggestion struct {
	ID          int      `json:"id"`
	Title       string   `json:"title"`
	Description string   `json:"description"`
	Rationale   string   `json:"rationale"`
	Category    Category `json:"category"`
	Effort      Effort   `json:"effort"`
}

// Result holds all AI-generated suggestions and an optional summary.
type Result struct {
	Suggestions []*Suggestion `json:"suggestions"`
	Summary     string        `json:"summary"`
}

// BuildPrompt constructs the prompt for generating feature suggestions.
func BuildPrompt(goal, instructions, fileTree, recentLog, memCtx, existingTasks string, count int) string {
	var b strings.Builder
	b.WriteString("You are a senior product manager and software architect brainstorming feature ideas.\n")
	b.WriteString("Your role is to suggest concrete, high-value features that are directly relevant to this project.\n\n")

	b.WriteString(fmt.Sprintf("## PROJECT GOAL\n%s\n\n", goal))

	if instructions != "" {
		b.WriteString(fmt.Sprintf("## CONSTRAINTS\n%s\n\n", instructions))
	}

	if existingTasks != "" {
		b.WriteString(fmt.Sprintf("## EXISTING TASKS (do NOT suggest duplicates)\n%s\n\n", existingTasks))
	}

	if fileTree != "" {
		b.WriteString(fmt.Sprintf("## PROJECT STRUCTURE\n```\n%s\n```\n\n", fileTree))
	}

	if recentLog != "" {
		b.WriteString(fmt.Sprintf("## RECENT ACTIVITY\n%s\n\n", recentLog))
	}

	if memCtx != "" {
		b.WriteString(fmt.Sprintf("## PROJECT MEMORY\n%s\n\n", memCtx))
	}

	b.WriteString(fmt.Sprintf("## TASK\n"))
	b.WriteString(fmt.Sprintf("Generate exactly %d feature/improvement ideas for this project.\n\n", count))
	b.WriteString("Requirements for each suggestion:\n")
	b.WriteString("- Must be directly relevant to the project goal and existing codebase\n")
	b.WriteString("- Must be concrete and actionable (implementable by an AI agent)\n")
	b.WriteString("- Must not duplicate existing tasks listed above\n")
	b.WriteString("- Should deliver genuine user or developer value\n")
	b.WriteString("- Vary the categories and effort levels for a diverse set\n\n")
	b.WriteString("For category, choose from: feature, ux, performance, security, dx, integration, docs\n")
	b.WriteString("For effort, choose from: xs (<1h), s (1-4h), m (4-16h), l (1-5d), xl (>1wk)\n\n")
	b.WriteString("Output ONLY valid JSON, no explanation, no markdown:\n")
	b.WriteString(`{"summary":"one sentence overview of the suggestion set","suggestions":[`)
	b.WriteString(`{"id":1,"title":"short title","description":"what to build and how","rationale":"why this matters","category":"feature","effort":"m"},`)
	b.WriteString(`{"id":2,"title":"...","description":"...","rationale":"...","category":"ux","effort":"s"}`)
	b.WriteString(`]}`)

	return b.String()
}

// Parse extracts a Result from the AI's JSON response.
func Parse(output string) (*Result, error) {
	start := strings.Index(output, "{")
	end := strings.LastIndex(output, "}")
	if start == -1 || end == -1 || end <= start {
		return nil, fmt.Errorf("no JSON found in response")
	}
	jsonStr := output[start : end+1]

	var result Result
	if err := json.Unmarshal([]byte(jsonStr), &result); err != nil {
		return nil, fmt.Errorf("parsing suggestions: %w", err)
	}

	// Assign sequential IDs if missing
	for i, s := range result.Suggestions {
		if s.ID == 0 {
			s.ID = i + 1
		}
	}

	return &result, nil
}

// Generate calls the provider to brainstorm feature suggestions.
func Generate(ctx context.Context, p provider.Provider, prompt, model string, timeout time.Duration) (*Result, error) {
	result, err := p.Complete(ctx, prompt, provider.Options{
		Model:   model,
		Timeout: timeout,
	})
	if err != nil {
		return nil, fmt.Errorf("suggest: %w", err)
	}
	return Parse(result.Output)
}

// EffortLabel returns a human-readable effort label.
func EffortLabel(e Effort) string {
	switch e {
	case EffortXS:
		return "XS  <1h"
	case EffortS:
		return "S   1–4h"
	case EffortM:
		return "M   4–16h"
	case EffortL:
		return "L   1–5d"
	case EffortXL:
		return "XL  >1wk"
	default:
		return string(e)
	}
}

// CategoryLabel returns a human-readable category label.
func CategoryLabel(c Category) string {
	switch c {
	case CategoryFeature:
		return "feature"
	case CategoryUX:
		return "ux"
	case CategoryPerformance:
		return "perf"
	case CategorySecurity:
		return "security"
	case CategoryDX:
		return "dx"
	case CategoryIntegration:
		return "integration"
	case CategoryDocs:
		return "docs"
	default:
		return string(c)
	}
}
