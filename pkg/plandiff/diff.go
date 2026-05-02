// Package plandiff provides AI-narrated comparison of plan snapshots.
// It wraps the structural diff computed by pkg/pm and asks the AI provider
// to generate a plain-English narrative explaining what the changes mean
// for the project direction.
package plandiff

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/provider"
)

// NarrateInput holds everything needed to generate an AI narrative for a diff.
type NarrateInput struct {
	Snap1 *pm.Snapshot
	Snap2 *pm.Snapshot
	Diff  pm.PlanDiff
}

// Narrate calls the AI provider to produce a 1-2 paragraph plain-English
// explanation of what the plan changes mean for the project direction.
// model may be empty (provider uses its default).
func Narrate(ctx context.Context, p provider.Provider, model string, input NarrateInput) (string, error) {
	prompt := buildNarratePrompt(input)
	result, err := p.Complete(ctx, prompt, provider.Options{
		Model:   model,
		Timeout: 2 * time.Minute,
	})
	if err != nil {
		return "", fmt.Errorf("plandiff narrate: %w", err)
	}
	return strings.TrimSpace(result.Output), nil
}

// buildNarratePrompt constructs the AI prompt for the narrative.
func buildNarratePrompt(input NarrateInput) string {
	var sb strings.Builder

	sb.WriteString("You are a technical project manager. Below is a structural diff between two versions of an AI-managed task plan.\n")
	sb.WriteString("Write 1-2 paragraphs of plain English explaining what these changes mean for the project direction, priorities, and overall progress.\n")
	sb.WriteString("Be concise and specific. Focus on the strategic implications, not just listing the changes.\n\n")

	// Header info
	ts1 := input.Snap1.Timestamp.UTC().Format("2006-01-02 15:04 UTC")
	ts2 := input.Snap2.Timestamp.UTC().Format("2006-01-02 15:04 UTC")
	fmt.Fprintf(&sb, "Plan goal: %s\n\n", input.Snap1.Plan.Goal)
	fmt.Fprintf(&sb, "Version A: v%d (%s) — %d tasks\n", input.Snap1.Version, ts1, len(input.Snap1.Plan.Tasks))
	fmt.Fprintf(&sb, "Version B: v%d (%s) — %d tasks\n\n", input.Snap2.Version, ts2, len(input.Snap2.Plan.Tasks))

	diff := input.Diff

	if len(diff.Added) > 0 {
		sb.WriteString("## Added tasks\n")
		for _, t := range diff.Added {
			fmt.Fprintf(&sb, "- #%d [P%d] %s", t.ID, t.Priority, t.Title)
			if t.Description != "" {
				desc := t.Description
				if len([]rune(desc)) > 120 {
					desc = string([]rune(desc)[:120]) + "..."
				}
				fmt.Fprintf(&sb, ": %s", desc)
			}
			sb.WriteString("\n")
		}
		sb.WriteString("\n")
	}

	if len(diff.Removed) > 0 {
		sb.WriteString("## Removed tasks\n")
		for _, t := range diff.Removed {
			fmt.Fprintf(&sb, "- #%d [P%d] %s\n", t.ID, t.Priority, t.Title)
		}
		sb.WriteString("\n")
	}

	if len(diff.Changed) > 0 {
		sb.WriteString("## Modified tasks\n")
		for _, td := range diff.Changed {
			fmt.Fprintf(&sb, "- #%d %s:\n", td.ID, td.Title)
			for _, fc := range td.Changes {
				fmt.Fprintf(&sb, "  - %s: %q → %q\n", fc.Field, fc.OldValue, fc.NewValue)
			}
		}
		sb.WriteString("\n")
	}

	sb.WriteString("Please write your 1-2 paragraph narrative now:")
	return sb.String()
}
