// Package backlog implements AI-driven product backlog generation.
// It analyzes a project's codebase and surfaces prioritized improvements,
// features, bugs, and tech debt organized by impact and effort.
package backlog

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/provider"
)

// ItemType categorizes a backlog item.
type ItemType string

const (
	TypeFeature     ItemType = "feature"
	TypeBug         ItemType = "bug"
	TypeTechDebt    ItemType = "tech_debt"
	TypePerformance ItemType = "performance"
	TypeSecurity    ItemType = "security"
	TypeDocs        ItemType = "docs"
)

// Impact rates the business/user value of a backlog item.
type Impact string

const (
	ImpactHigh   Impact = "high"
	ImpactMedium Impact = "medium"
	ImpactLow    Impact = "low"
)

// Effort rates the implementation complexity of a backlog item.
type Effort string

const (
	EffortXS Effort = "xs" // < 1 hour
	EffortS  Effort = "s"  // 1–4 hours
	EffortM  Effort = "m"  // 4–16 hours (half to 2 days)
	EffortL  Effort = "l"  // 16–40 hours (2–5 days)
	EffortXL Effort = "xl" // > 40 hours (> 1 week)
)

// Item is a single entry in the product backlog.
type Item struct {
	ID          int      `json:"id"`
	Title       string   `json:"title"`
	Type        ItemType `json:"type"`
	Impact      Impact   `json:"impact"`
	Effort      Effort   `json:"effort"`
	Description string   `json:"description"`
	Rationale   string   `json:"rationale"`
}

// Score returns a priority score for sorting (lower = higher priority).
// Maximizes impact-to-effort ratio: high impact + low effort ranks first.
func (item *Item) Score() int {
	impactScore := map[Impact]int{ImpactHigh: 1, ImpactMedium: 2, ImpactLow: 3}
	effortScore := map[Effort]int{EffortXS: 1, EffortS: 2, EffortM: 3, EffortL: 4, EffortXL: 5}
	i := impactScore[item.Impact]
	if i == 0 {
		i = 2
	}
	e := effortScore[item.Effort]
	if e == 0 {
		e = 3
	}
	return i*10 + e
}

// EffortLabel returns a human-readable effort label.
func EffortLabel(e Effort) string {
	switch e {
	case EffortXS:
		return "XS (<1h)"
	case EffortS:
		return "S  (1-4h)"
	case EffortM:
		return "M  (4-16h)"
	case EffortL:
		return "L  (16-40h)"
	case EffortXL:
		return "XL (>40h)"
	default:
		return string(e)
	}
}

// Analysis is the complete result of a backlog analysis run.
type Analysis struct {
	Items     []*Item
	Summary   string
	Timestamp time.Time
}

// SortByScore sorts items in-place by their priority score (best first).
func (a *Analysis) SortByScore() {
	sort.Slice(a.Items, func(i, j int) bool {
		return a.Items[i].Score() < a.Items[j].Score()
	})
}

// FormatMarkdown returns a markdown representation of the backlog.
func (a *Analysis) FormatMarkdown() string {
	var b strings.Builder
	b.WriteString("# Product Backlog\n\n")
	if a.Summary != "" {
		b.WriteString(fmt.Sprintf("**Summary:** %s\n\n", a.Summary))
	}
	b.WriteString(fmt.Sprintf("*Generated: %s — %d items*\n\n", a.Timestamp.Format("2006-01-02 15:04"), len(a.Items)))
	b.WriteString("| # | Type | Impact | Effort | Title |\n")
	b.WriteString("|---|------|--------|--------|-------|\n")
	for i, item := range a.Items {
		b.WriteString(fmt.Sprintf("| %d | %s | %s | %s | **%s** |\n",
			i+1,
			string(item.Type),
			string(item.Impact),
			string(item.Effort),
			item.Title,
		))
	}
	b.WriteString("\n## Details\n\n")
	for i, item := range a.Items {
		b.WriteString(fmt.Sprintf("### %d. %s\n\n", i+1, item.Title))
		b.WriteString(fmt.Sprintf("- **Type:** %s | **Impact:** %s | **Effort:** %s\n", item.Type, item.Impact, item.Effort))
		if item.Description != "" {
			b.WriteString(fmt.Sprintf("- **What:** %s\n", item.Description))
		}
		if item.Rationale != "" {
			b.WriteString(fmt.Sprintf("- **Why:** %s\n", item.Rationale))
		}
		b.WriteString("\n")
	}
	return b.String()
}

// BuildPrompt constructs the AI prompt for backlog generation.
// Pass empty strings for any context that is not available.
func BuildPrompt(goal, instructions, fileTree, gitLog, memory, existingPlan string) string {
	var b strings.Builder
	b.WriteString("You are an AI product manager performing a backlog analysis.\n")
	b.WriteString("Scan this software project and identify the most valuable improvements,\n")
	b.WriteString("organized as a prioritized product backlog.\n\n")

	if goal != "" {
		b.WriteString(fmt.Sprintf("## PROJECT GOAL\n%s\n\n", goal))
	}
	if instructions != "" {
		b.WriteString(fmt.Sprintf("## CONSTRAINTS\n%s\n\n", instructions))
	}
	if fileTree != "" {
		b.WriteString(fmt.Sprintf("## PROJECT STRUCTURE\n```\n%s\n```\n\n", fileTree))
	}
	if gitLog != "" {
		b.WriteString(fmt.Sprintf("## RECENT COMMITS\n```\n%s\n```\n\n", gitLog))
	}
	if memory != "" {
		b.WriteString(fmt.Sprintf("## PAST LEARNINGS\n%s\n\n", memory))
	}
	if existingPlan != "" {
		b.WriteString(fmt.Sprintf("## EXISTING TASK PLAN (already planned/completed)\n%s\n\n", existingPlan))
	}

	b.WriteString("## INSTRUCTIONS\n")
	b.WriteString("Generate a prioritized backlog of 8–15 items that represent the highest-value\n")
	b.WriteString("improvements not already covered by the existing plan.\n\n")
	b.WriteString("For each item assign:\n")
	b.WriteString("- type: feature | bug | tech_debt | performance | security | docs\n")
	b.WriteString("- impact: high (business-critical or unblocks major value) | medium | low (minor polish)\n")
	b.WriteString("- effort: xs (<1h) | s (1-4h) | m (4-16h) | l (16-40h) | xl (>40h)\n")
	b.WriteString("- description: what to build/fix (1-2 sentences)\n")
	b.WriteString("- rationale: why this matters now (1 sentence)\n\n")
	b.WriteString("Also write a 2-3 sentence executive summary of the project's biggest gaps.\n\n")
	b.WriteString("Prioritize items with the best impact-to-effort ratio.\n")
	b.WriteString("Do NOT suggest items that are already in the existing plan.\n\n")
	b.WriteString("Output ONLY valid JSON — no explanation, no markdown fences:\n")
	b.WriteString(`{"summary":"...","items":[{"id":1,"title":"...","type":"feature","impact":"high","effort":"m","description":"...","rationale":"..."}]}`)
	return b.String()
}

// Parse extracts an Analysis from the AI's JSON response.
func Parse(output string) (*Analysis, error) {
	start := strings.Index(output, "{")
	end := strings.LastIndex(output, "}")
	if start == -1 || end == -1 || end <= start {
		return nil, fmt.Errorf("no JSON found in response")
	}
	jsonStr := output[start : end+1]

	var raw struct {
		Summary string  `json:"summary"`
		Items   []*Item `json:"items"`
	}
	if err := json.Unmarshal([]byte(jsonStr), &raw); err != nil {
		return nil, fmt.Errorf("parsing backlog: %w", err)
	}

	// Re-number items sequentially.
	for i, item := range raw.Items {
		if item.ID == 0 {
			item.ID = i + 1
		}
	}

	return &Analysis{
		Items:     raw.Items,
		Summary:   raw.Summary,
		Timestamp: time.Now(),
	}, nil
}

// Analyze calls the provider to generate a product backlog analysis.
func Analyze(ctx context.Context, p provider.Provider, model string, timeout time.Duration, prompt string) (*Analysis, error) {
	result, err := p.Complete(ctx, prompt, provider.Options{
		Model:   model,
		Timeout: timeout,
	})
	if err != nil {
		return nil, fmt.Errorf("backlog analysis: %w", err)
	}
	return Parse(result.Output)
}
