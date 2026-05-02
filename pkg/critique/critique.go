// Package critique provides an AI adversarial plan review ("devil's advocate")
// that pressure-tests the current plan before execution. Unlike health scoring
// or risk assessment, critique actively argues against the plan, surfaces
// overconfident assumptions, flags logical gaps, and proposes alternatives.
package critique

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/provider"
)

// CritiqueReport holds the full adversarial review of a plan.
type CritiqueReport struct {
	// Assumptions are stated or unstated assumptions the plan relies on.
	Assumptions []string `json:"assumptions"`

	// Gaps are missing tasks or steps the plan forgot to include.
	Gaps []string `json:"gaps"`

	// Ordering lists sequencing issues — tasks that appear in the wrong order
	// or whose dependencies create logical conflicts.
	Ordering []string `json:"ordering"`

	// Alternatives are other approaches worth considering instead of the current plan.
	Alternatives []string `json:"alternatives"`

	// Verdict is the overall adversarial verdict: a short, punchy conclusion.
	Verdict string `json:"verdict"`
}

// Critique runs an adversarial plan review using the AI provider.
// model may be empty (the provider will use its default).
func Critique(ctx context.Context, p provider.Provider, model string, plan *pm.Plan, goal string) (*CritiqueReport, error) {
	if plan == nil || len(plan.Tasks) == 0 {
		return nil, fmt.Errorf("no plan loaded — run 'cloop run --pm --plan-only' to create one")
	}

	prompt := buildPrompt(plan, goal)

	result, err := p.Complete(ctx, prompt, provider.Options{
		Model:   model,
		Timeout: 3 * time.Minute,
	})
	if err != nil {
		return nil, fmt.Errorf("critique: %w", err)
	}

	return parseReport(result.Output)
}

// buildPrompt constructs the adversarial system + user prompt.
func buildPrompt(plan *pm.Plan, goal string) string {
	var b strings.Builder

	b.WriteString("You are a skeptical senior engineer reviewing a project plan for the FIRST TIME. ")
	b.WriteString("Your job is to play devil's advocate: argue against this plan, expose its weaknesses, ")
	b.WriteString("and force the team to confront problems they have ignored or glossed over.\n\n")

	b.WriteString("Be direct and specific. Do not soften your criticism. Do not celebrate successes.\n")
	b.WriteString("This is an ADVERSARIAL review — your goal is to find every flaw.\n\n")

	b.WriteString("## PROJECT GOAL\n")
	b.WriteString(goal)
	b.WriteString("\n\n")

	b.WriteString("## CURRENT PLAN\n")
	b.WriteString(fmt.Sprintf("Total tasks: %d\n\n", len(plan.Tasks)))

	// Categorize tasks by status.
	var pending, inProgress, done, other []*pm.Task
	for _, t := range plan.Tasks {
		switch t.Status {
		case pm.TaskPending:
			pending = append(pending, t)
		case pm.TaskInProgress:
			inProgress = append(inProgress, t)
		case pm.TaskDone:
			done = append(done, t)
		default:
			other = append(other, t)
		}
	}

	if len(done) > 0 {
		b.WriteString("### Completed tasks\n")
		for _, t := range done {
			b.WriteString(fmt.Sprintf("- [#%d P%d] %s", t.ID, t.Priority, t.Title))
			if t.Description != "" {
				b.WriteString(fmt.Sprintf(": %s", truncate(t.Description, 100)))
			}
			b.WriteString("\n")
		}
		b.WriteString("\n")
	}

	if len(inProgress) > 0 {
		b.WriteString("### In-progress tasks\n")
		for _, t := range inProgress {
			b.WriteString(fmt.Sprintf("- [#%d P%d] %s", t.ID, t.Priority, t.Title))
			if t.Description != "" {
				b.WriteString(fmt.Sprintf(": %s", truncate(t.Description, 100)))
			}
			b.WriteString("\n")
		}
		b.WriteString("\n")
	}

	if len(pending) > 0 {
		b.WriteString("### Pending tasks\n")
		for _, t := range pending {
			depStr := ""
			if len(t.DependsOn) > 0 {
				deps := make([]string, len(t.DependsOn))
				for i, d := range t.DependsOn {
					deps[i] = fmt.Sprintf("#%d", d)
				}
				depStr = fmt.Sprintf(" [depends: %s]", strings.Join(deps, ", "))
			}
			roleStr := ""
			if t.Role != "" {
				roleStr = fmt.Sprintf(" [role: %s]", t.Role)
			}
			b.WriteString(fmt.Sprintf("- [#%d P%d]%s%s %s", t.ID, t.Priority, roleStr, depStr, t.Title))
			if t.Description != "" {
				b.WriteString(fmt.Sprintf(": %s", truncate(t.Description, 120)))
			}
			b.WriteString("\n")
		}
		b.WriteString("\n")
	}

	if len(other) > 0 {
		b.WriteString("### Other tasks (failed/skipped)\n")
		for _, t := range other {
			b.WriteString(fmt.Sprintf("- [#%d %s] %s\n", t.ID, t.Status, t.Title))
		}
		b.WriteString("\n")
	}

	b.WriteString(`## YOUR TASK

Produce an adversarial critique with EXACTLY these five sections. Be specific and actionable.

Return ONLY a JSON object — no prose, no markdown fences:
{
  "assumptions": [
    "Unstated or overconfident assumption the plan relies on, e.g.: 'Assumes the database schema is already stable, but no migration tasks are present.'"
  ],
  "gaps": [
    "A task or step the plan is missing, e.g.: 'No rollback plan if the deployment fails mid-way.'"
  ],
  "ordering": [
    "A sequencing issue or dependency conflict, e.g.: 'Task #5 (write tests) comes after #6 (ship to production) — tests should precede release.'"
  ],
  "alternatives": [
    "An alternative approach worth considering, e.g.: 'Instead of building a custom auth system, use an existing identity provider to reduce scope.'"
  ],
  "verdict": "A single punchy verdict sentence, e.g.: 'This plan is optimistic, under-specified, and will almost certainly slip.'"
}

Rules:
- Each array should have 2-5 items. An empty array [] is acceptable only if genuinely nothing applies.
- Be specific — reference task IDs and titles where relevant.
- Do not repeat the same point in multiple sections.
- verdict must be a single sentence.
- Return ONLY the JSON object. No additional text.
`)

	return b.String()
}

// parseReport extracts the JSON object from the AI response.
func parseReport(output string) (*CritiqueReport, error) {
	start := strings.Index(output, "{")
	end := strings.LastIndex(output, "}")
	if start == -1 || end == -1 || end <= start {
		// Graceful fallback: return empty report rather than hard error.
		return &CritiqueReport{
			Verdict: "(The AI returned an unexpected response format.)",
		}, nil
	}

	raw := output[start : end+1]
	var report CritiqueReport
	if err := json.Unmarshal([]byte(raw), &report); err != nil {
		return nil, fmt.Errorf("parsing critique report: %w (raw: %s)", err, truncate(raw, 300))
	}
	return &report, nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
