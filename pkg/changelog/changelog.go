// Package changelog implements AI-generated CHANGELOG synthesis from task history.
// It reads the completed task list and step history from state, builds a prompt,
// calls the configured provider, and returns a human-readable CHANGELOG in markdown
// or JSON format.
package changelog

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/milestone"
	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/provider"
	"github.com/blechschmidt/cloop/pkg/state"
)

// Entry is a single changelog item synthesized by the AI.
type Entry struct {
	// Version or milestone label (e.g. "v0.1", "Sprint 1", "Unreleased").
	Version string `json:"version"`
	// Date of the milestone / release, or zero value when unknown.
	Date time.Time `json:"date,omitempty"`
	// Brief section heading (e.g. "Added", "Fixed", "Changed").
	Section string `json:"section"`
	// Items is the list of bullet-point change descriptions.
	Items []string `json:"items"`
}

// Result holds the full AI-synthesized changelog.
type Result struct {
	Goal    string   `json:"goal"`
	Entries []*Entry `json:"entries"`
	Summary string   `json:"summary"`
}

// BuildPrompt constructs the prompt sent to the AI provider.
// It injects:
//   - the project goal and instructions
//   - completed / skipped / failed tasks (filtered by sinceStep)
//   - recent step output excerpts
//   - milestone groupings if present
//
// format is "markdown" or "json" — tells the AI which output format to use.
func BuildPrompt(s *state.ProjectState, sinceStep int, format string) string {
	var b strings.Builder

	b.WriteString("You are a technical writer generating a CHANGELOG for a software project.\n")
	b.WriteString("Your job is to synthesize a clear, human-readable CHANGELOG from the\n")
	b.WriteString("completed task list and execution history provided below.\n\n")

	// Project context
	b.WriteString("## PROJECT GOAL\n")
	b.WriteString(s.Goal + "\n\n")

	if s.Instructions != "" {
		b.WriteString("## CONSTRAINTS / INSTRUCTIONS\n")
		b.WriteString(s.Instructions + "\n\n")
	}

	// Milestones — used for grouping if present
	if len(s.Milestones) > 0 {
		b.WriteString("## MILESTONES\n")
		b.WriteString("Group changelog entries by these milestones:\n")
		for _, ms := range s.Milestones {
			dl := ""
			if ms.Deadline != nil {
				dl = " (deadline: " + ms.Deadline.Format("2006-01-02") + ")"
			}
			b.WriteString(fmt.Sprintf("- **%s**%s: task IDs %v\n", ms.Name, dl, ms.TaskIDs))
			if ms.Description != "" {
				b.WriteString(fmt.Sprintf("  %s\n", ms.Description))
			}
		}
		b.WriteString("\n")
	}

	// Task list
	if s.Plan != nil && len(s.Plan.Tasks) > 0 {
		b.WriteString("## COMPLETED TASKS\n")
		wrote := false
		for _, t := range s.Plan.Tasks {
			if t.Status != pm.TaskDone && t.Status != pm.TaskSkipped && t.Status != pm.TaskFailed {
				continue
			}
			wrote = true
			statusTag := string(t.Status)
			b.WriteString(fmt.Sprintf("- [%s] Task %d: %s\n", statusTag, t.ID, t.Title))
			if t.Description != "" {
				b.WriteString(fmt.Sprintf("  Description: %s\n", t.Description))
			}
			if t.Result != "" {
				// Truncate long results to avoid bloating the prompt
				result := t.Result
				if len(result) > 400 {
					result = result[:400] + "…"
				}
				b.WriteString(fmt.Sprintf("  Result: %s\n", result))
			}
			if t.CompletedAt != nil {
				b.WriteString(fmt.Sprintf("  Completed: %s\n", t.CompletedAt.Format("2006-01-02")))
			}
		}
		if !wrote {
			b.WriteString("  (no completed tasks yet)\n")
		}
		b.WriteString("\n")
	}

	// Step excerpts (after sinceStep)
	steps := filterSteps(s.Steps, sinceStep)
	if len(steps) > 0 {
		b.WriteString("## RECENT EXECUTION LOG (excerpts)\n")
		for _, step := range steps {
			b.WriteString(fmt.Sprintf("Step %d (%s): %s\n", step.Step+1, step.Time.Format("2006-01-02"), step.Task))
			if step.Output != "" {
				excerpt := step.Output
				if len(excerpt) > 300 {
					excerpt = excerpt[:300] + "…"
				}
				b.WriteString("  " + strings.ReplaceAll(excerpt, "\n", "\n  ") + "\n")
			}
		}
		b.WriteString("\n")
	}

	// Output instructions
	b.WriteString("## YOUR TASK\n")
	b.WriteString("Write a CHANGELOG synthesizing the above work.\n\n")
	b.WriteString("Rules:\n")
	b.WriteString("- Group entries by milestone if milestones are provided, otherwise use 'Unreleased'\n")
	b.WriteString("- Within each group, use standard Keep-a-Changelog sections: Added, Changed, Fixed, Removed, Security, Deprecated\n")
	b.WriteString("- Write bullet points from a user / developer perspective — describe the impact, not the implementation detail\n")
	b.WriteString("- Keep each bullet point concise (one sentence)\n")
	b.WriteString("- Skip tasks that are failed or skipped unless they represent a deliberate change\n")
	b.WriteString("- Infer reasonable version labels from milestone names (e.g. 'v0.1.0', 'v1.0.0') or use 'Unreleased'\n\n")

	if format == "json" {
		b.WriteString("Output ONLY valid JSON — no explanation, no markdown fences:\n")
		b.WriteString(`{`)
		b.WriteString(`"summary":"one-sentence project summary","entries":[`)
		b.WriteString(`{"version":"Unreleased","date":"2024-01-15","section":"Added","items":["Feature X was added","Feature Y was added"]},`)
		b.WriteString(`{"version":"Unreleased","date":"2024-01-15","section":"Fixed","items":["Bug Z was fixed"]}`)
		b.WriteString(`]}`)
		b.WriteString("\n\nThe date field should be the ISO-8601 date of the most recent task in that group, or today's date if unknown.\n")
	} else {
		b.WriteString("Output ONLY valid markdown — no explanation outside the markdown:\n\n")
		b.WriteString("## [Unreleased] — YYYY-MM-DD\n\n")
		b.WriteString("### Added\n- …\n\n")
		b.WriteString("### Fixed\n- …\n\n")
		b.WriteString("Start directly with the first `## [Version]` heading. Do not include a top-level `# CHANGELOG` heading.\n")
	}

	return b.String()
}

// filterSteps returns steps with index >= sinceStep, capped at 20 most recent.
func filterSteps(steps []state.StepResult, sinceStep int) []state.StepResult {
	var filtered []state.StepResult
	for _, s := range steps {
		if s.Step >= sinceStep {
			filtered = append(filtered, s)
		}
	}
	// Cap to most recent 20 to keep prompt size reasonable
	if len(filtered) > 20 {
		filtered = filtered[len(filtered)-20:]
	}
	return filtered
}

// Generate calls the provider with the prompt and returns the raw AI output.
func Generate(ctx context.Context, p provider.Provider, prompt, model string, timeout time.Duration) (string, error) {
	result, err := p.Complete(ctx, prompt, provider.Options{
		Model:   model,
		Timeout: timeout,
	})
	if err != nil {
		return "", fmt.Errorf("changelog: %w", err)
	}
	return result.Output, nil
}

// ParseJSON parses the AI JSON response into a Result.
// It extracts the JSON object even when surrounded by markdown fences.
func ParseJSON(output string) (*Result, error) {
	// Strip markdown fences
	raw := output
	if idx := strings.Index(raw, "```json"); idx != -1 {
		raw = raw[idx+7:]
		if end := strings.Index(raw, "```"); end != -1 {
			raw = raw[:end]
		}
	} else if idx := strings.Index(raw, "```"); idx != -1 {
		raw = raw[idx+3:]
		if end := strings.Index(raw, "```"); end != -1 {
			raw = raw[:end]
		}
	}
	raw = strings.TrimSpace(raw)

	start := strings.Index(raw, "{")
	end := strings.LastIndex(raw, "}")
	if start == -1 || end == -1 || end <= start {
		return nil, fmt.Errorf("no JSON object found in AI response")
	}
	raw = raw[start : end+1]

	// The AI returns dates as plain strings; we unmarshal into a helper struct.
	type entryRaw struct {
		Version string   `json:"version"`
		Date    string   `json:"date"`
		Section string   `json:"section"`
		Items   []string `json:"items"`
	}
	type resultRaw struct {
		Goal    string     `json:"goal"`
		Summary string     `json:"summary"`
		Entries []entryRaw `json:"entries"`
	}

	var rr resultRaw
	if err := json.Unmarshal([]byte(raw), &rr); err != nil {
		return nil, fmt.Errorf("parsing changelog JSON: %w", err)
	}

	result := &Result{
		Goal:    rr.Goal,
		Summary: rr.Summary,
	}
	for _, e := range rr.Entries {
		entry := &Entry{
			Version: e.Version,
			Section: e.Section,
			Items:   e.Items,
		}
		if e.Date != "" {
			if t, err := time.Parse("2006-01-02", e.Date); err == nil {
				entry.Date = t
			}
		}
		result.Entries = append(result.Entries, entry)
	}
	return result, nil
}

// FormatMarkdownFromJSON converts a parsed JSON Result into markdown CHANGELOG format.
func FormatMarkdownFromJSON(r *Result) string {
	var b strings.Builder

	// Group entries by version
	type group struct {
		version string
		date    time.Time
		entries []*Entry
	}

	var groups []group
	versionIndex := map[string]int{}

	for _, e := range r.Entries {
		idx, ok := versionIndex[e.Version]
		if !ok {
			idx = len(groups)
			versionIndex[e.Version] = idx
			groups = append(groups, group{version: e.Version, date: e.Date})
		}
		groups[idx].entries = append(groups[idx].entries, e)
	}

	for _, g := range groups {
		dateStr := g.date.Format("2006-01-02")
		if g.date.IsZero() {
			dateStr = time.Now().Format("2006-01-02")
		}
		b.WriteString(fmt.Sprintf("## [%s] — %s\n\n", g.version, dateStr))
		for _, e := range g.entries {
			b.WriteString(fmt.Sprintf("### %s\n", e.Section))
			for _, item := range e.Items {
				b.WriteString(fmt.Sprintf("- %s\n", item))
			}
			b.WriteString("\n")
		}
	}

	return b.String()
}

// MilestoneTaskIDs builds a map from milestone name to its task ID set for quick lookup.
func MilestoneTaskIDs(milestones []*milestone.Milestone) map[string]map[int]bool {
	m := make(map[string]map[int]bool, len(milestones))
	for _, ms := range milestones {
		set := make(map[int]bool, len(ms.TaskIDs))
		for _, id := range ms.TaskIDs {
			set[id] = true
		}
		m[ms.Name] = set
	}
	return m
}
