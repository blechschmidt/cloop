// Package microstandup generates focused per-task micro-standup cards with
// blocker detection. Unlike plan-level standups, each card is scoped to a
// single in-progress task and includes time tracking, heal attempt info, and
// a 1-5 confidence score with reasoning.
package microstandup

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/checkpoint"
	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/provider"
	"github.com/blechschmidt/cloop/pkg/replay"
)

// TaskContext holds all gathered context for a single in-progress task.
type TaskContext struct {
	Task           *pm.Task
	Goal           string
	RecentSteps    []string // last 20 step log lines
	CheckpointDiff string   // human-readable diff between last two checkpoints
	ElapsedMinutes int      // minutes since task.StartedAt (0 if unknown)
	EstimatedMinutes int    // from task.EstimatedMinutes
	HealAttempts   int      // from task.HealAttempts
	Links          []pm.Link
	GitHubIssue    int
}

// Card is the AI-generated micro-standup for one task.
type Card struct {
	TaskID           int
	TaskTitle        string
	Yesterday        string // what was accomplished
	Today            string // next 3 steps
	Blockers         string // specific blockers or "None"
	Confidence       int    // 1-5
	ConfidenceReason string
	ElapsedMinutes   int
	EstimatedMinutes int
	HealAttempts     int
}

// aiResponse is the expected JSON shape from the AI.
type aiResponse struct {
	Yesterday        string `json:"yesterday"`
	Today            string `json:"today"`
	Blockers         string `json:"blockers"`
	Confidence       int    `json:"confidence"`
	ConfidenceReason string `json:"confidence_reason"`
}

// Collect gathers all available context for the given task.
func Collect(workDir string, task *pm.Task, goal string) (*TaskContext, error) {
	ctx := &TaskContext{
		Task:             task,
		Goal:             goal,
		EstimatedMinutes: task.EstimatedMinutes,
		HealAttempts:     task.HealAttempts,
		Links:            task.Links,
		GitHubIssue:      task.GitHubIssue,
	}

	// Time elapsed.
	if task.StartedAt != nil {
		ctx.ElapsedMinutes = int(time.Since(*task.StartedAt).Minutes())
	}

	// Recent step log lines from the replay log.
	entries, err := replay.Load(workDir, task.ID)
	if err == nil && len(entries) > 0 {
		// Take the last 20 entries.
		start := 0
		if len(entries) > 20 {
			start = len(entries) - 20
		}
		for _, e := range entries[start:] {
			line := strings.TrimSpace(e.Content)
			if line != "" {
				ctx.RecentSteps = append(ctx.RecentSteps, line)
			}
		}
	} else {
		// Fall back to reading the task artifact file if available.
		if task.ArtifactPath != "" {
			data, readErr := os.ReadFile(filepath.Join(workDir, task.ArtifactPath))
			if readErr == nil {
				lines := strings.Split(string(data), "\n")
				start := 0
				if len(lines) > 20 {
					start = len(lines) - 20
				}
				for _, l := range lines[start:] {
					l = strings.TrimSpace(l)
					if l != "" {
						ctx.RecentSteps = append(ctx.RecentSteps, l)
					}
				}
			}
		}
	}

	// Checkpoint diff: compare the last two history entries.
	history, histErr := checkpoint.ListHistory(workDir, task.ID)
	if histErr == nil && len(history) >= 2 {
		prev := history[len(history)-2].Checkpoint
		curr := history[len(history)-1].Checkpoint
		ctx.CheckpointDiff = buildCheckpointDiff(prev, curr)
	} else if histErr == nil && len(history) == 1 {
		cp := history[0].Checkpoint
		ctx.CheckpointDiff = fmt.Sprintf("Single checkpoint: event=%s step=%d output_length=%d",
			cp.Event, cp.StepNumber, cp.OutputLength)
	}

	return ctx, nil
}

// buildCheckpointDiff returns a concise human-readable diff between two checkpoints.
func buildCheckpointDiff(prev, curr *checkpoint.Checkpoint) string {
	var parts []string

	// Events.
	if prev.Event != curr.Event {
		parts = append(parts, fmt.Sprintf("event: %s → %s", prev.Event, curr.Event))
	}
	// Step progression.
	if curr.StepNumber != prev.StepNumber {
		parts = append(parts, fmt.Sprintf("steps: %d → %d (+%d)", prev.StepNumber, curr.StepNumber, curr.StepNumber-prev.StepNumber))
	}
	// Output growth.
	delta := curr.OutputLength - prev.OutputLength
	if delta != 0 {
		sign := "+"
		if delta < 0 {
			sign = ""
		}
		parts = append(parts, fmt.Sprintf("output_length: %d → %d (%s%d bytes)", prev.OutputLength, curr.OutputLength, sign, delta))
	}
	// Time between checkpoints.
	if !prev.Timestamp.IsZero() && !curr.Timestamp.IsZero() {
		elapsed := curr.Timestamp.Sub(prev.Timestamp).Round(time.Second)
		parts = append(parts, fmt.Sprintf("time_between: %s", elapsed))
	}
	if len(parts) == 0 {
		return "No significant change between last two checkpoints."
	}
	return strings.Join(parts, " | ")
}

// BuildPrompt constructs the AI prompt for a single task's micro-standup.
func BuildPrompt(c *TaskContext) string {
	var b strings.Builder

	b.WriteString("You are generating a focused micro-standup card for a single in-progress software task.\n\n")
	b.WriteString("## TASK CONTEXT\n\n")
	b.WriteString(fmt.Sprintf("Task #%d: %s\n", c.Task.ID, c.Task.Title))
	if c.Task.Description != "" {
		b.WriteString(fmt.Sprintf("Description: %s\n", c.Task.Description))
	}
	if c.Goal != "" {
		b.WriteString(fmt.Sprintf("Project goal: %s\n", c.Goal))
	}
	b.WriteString(fmt.Sprintf("Status: %s\n", c.Task.Status))

	if c.ElapsedMinutes > 0 {
		b.WriteString(fmt.Sprintf("Time elapsed: %d min", c.ElapsedMinutes))
		if c.EstimatedMinutes > 0 {
			b.WriteString(fmt.Sprintf(" (estimated: %d min, delta: %+d min)", c.EstimatedMinutes, c.ElapsedMinutes-c.EstimatedMinutes))
		}
		b.WriteByte('\n')
	}

	if c.HealAttempts > 0 {
		b.WriteString(fmt.Sprintf("Failed heal attempts: %d (auto-heal retries after failure)\n", c.HealAttempts))
	}

	// Linked issues / PRs.
	var linkParts []string
	if c.GitHubIssue > 0 {
		linkParts = append(linkParts, fmt.Sprintf("GitHub Issue #%d", c.GitHubIssue))
	}
	for _, l := range c.Links {
		label := l.Label
		if label == "" {
			label = l.URL
		}
		linkParts = append(linkParts, fmt.Sprintf("[%s] %s", l.Kind, label))
	}
	if len(linkParts) > 0 {
		b.WriteString(fmt.Sprintf("Linked: %s\n", strings.Join(linkParts, ", ")))
	}

	if len(c.RecentSteps) > 0 {
		b.WriteString("\n## RECENT ACTIVITY (last step log lines)\n\n")
		for _, line := range c.RecentSteps {
			b.WriteString("  " + line + "\n")
		}
	}

	if c.CheckpointDiff != "" {
		b.WriteString("\n## LAST CHECKPOINT DIFF\n\n")
		b.WriteString("  " + c.CheckpointDiff + "\n")
	}

	b.WriteString(`
## INSTRUCTIONS

Based on the context above, generate a micro-standup card with EXACTLY these fields.
Return a raw JSON object (no markdown fences):

{
  "yesterday": "1-2 sentences: what was accomplished or attempted",
  "today": "Next 3 specific steps as a bullet list (use • as the bullet)",
  "blockers": "Specific things preventing progress. Say 'None' if there are no blockers.",
  "confidence": <integer 1-5 where 1=completely stuck, 3=making progress, 5=clear path to done>,
  "confidence_reason": "1 sentence explaining the confidence score"
}

Be concrete and task-specific. Do not use generic platitudes.
`)

	return b.String()
}

// Generate calls the AI provider to produce a standup card for the given context.
func Generate(ctx context.Context, prov provider.Provider, opts provider.Options, c *TaskContext) (*Card, error) {
	prompt := BuildPrompt(c)

	result, err := prov.Complete(ctx, prompt, opts)
	if err != nil {
		return nil, fmt.Errorf("AI call failed: %w", err)
	}

	// Extract JSON — strip any surrounding markdown fences.
	raw := strings.TrimSpace(result.Output)
	if idx := strings.Index(raw, "{"); idx > 0 {
		raw = raw[idx:]
	}
	if idx := strings.LastIndex(raw, "}"); idx >= 0 && idx < len(raw)-1 {
		raw = raw[:idx+1]
	}

	var resp aiResponse
	if err := json.Unmarshal([]byte(raw), &resp); err != nil {
		// Fallback: use raw text as yesterday.
		return &Card{
			TaskID:           c.Task.ID,
			TaskTitle:        c.Task.Title,
			Yesterday:        strings.TrimSpace(result.Output),
			Today:            "(parsing failed — see raw output above)",
			Blockers:         "Unknown",
			Confidence:       0,
			ConfidenceReason: "AI response could not be parsed",
			ElapsedMinutes:   c.ElapsedMinutes,
			EstimatedMinutes: c.EstimatedMinutes,
			HealAttempts:     c.HealAttempts,
		}, nil
	}

	if resp.Confidence < 1 {
		resp.Confidence = 1
	}
	if resp.Confidence > 5 {
		resp.Confidence = 5
	}

	return &Card{
		TaskID:           c.Task.ID,
		TaskTitle:        c.Task.Title,
		Yesterday:        resp.Yesterday,
		Today:            resp.Today,
		Blockers:         resp.Blockers,
		Confidence:       resp.Confidence,
		ConfidenceReason: resp.ConfidenceReason,
		ElapsedMinutes:   c.ElapsedMinutes,
		EstimatedMinutes: c.EstimatedMinutes,
		HealAttempts:     c.HealAttempts,
	}, nil
}

// FormatCard renders a Card as a compact, ≤15 line terminal card.
func FormatCard(card *Card) string {
	var b strings.Builder

	// Separator width.
	const w = 64
	sep := strings.Repeat("─", w)
	top := "┌" + sep + "┐"
	bot := "└" + sep + "┘"
	mid := "├" + sep + "┤"

	padLine := func(s string) string {
		runes := []rune(s)
		if len(runes) > w-2 {
			runes = append(runes[:w-5], []rune("...")...)
		}
		return "│ " + string(runes) + strings.Repeat(" ", w-1-len([]rune(string(runes)))) + "│"
	}

	b.WriteString(top + "\n")

	// Header.
	header := fmt.Sprintf("STANDUP  Task #%d — %s", card.TaskID, card.TaskTitle)
	b.WriteString(padLine(header) + "\n")

	// Status line.
	var statusParts []string
	if card.ElapsedMinutes > 0 {
		statusParts = append(statusParts, fmt.Sprintf("elapsed %dm", card.ElapsedMinutes))
	}
	if card.EstimatedMinutes > 0 {
		statusParts = append(statusParts, fmt.Sprintf("est %dm", card.EstimatedMinutes))
	}
	if card.HealAttempts > 0 {
		statusParts = append(statusParts, fmt.Sprintf("heals %d", card.HealAttempts))
	}
	if len(statusParts) > 0 {
		b.WriteString(padLine(strings.Join(statusParts, " | ")) + "\n")
	}

	// Yesterday.
	b.WriteString(mid + "\n")
	b.WriteString(padLine("YESTERDAY") + "\n")
	for _, line := range wrapText(card.Yesterday, w-4) {
		b.WriteString(padLine("  "+line) + "\n")
	}

	// Today.
	b.WriteString(mid + "\n")
	b.WriteString(padLine("TODAY — next steps") + "\n")
	for _, line := range wrapText(card.Today, w-4) {
		b.WriteString(padLine("  "+line) + "\n")
	}

	// Blockers.
	b.WriteString(mid + "\n")
	b.WriteString(padLine("BLOCKERS") + "\n")
	for _, line := range wrapText(card.Blockers, w-4) {
		b.WriteString(padLine("  "+line) + "\n")
	}

	// Confidence.
	b.WriteString(mid + "\n")
	confidenceLine := fmt.Sprintf("CONFIDENCE  %d/5", card.Confidence)
	if card.ConfidenceReason != "" {
		confidenceLine += " — " + card.ConfidenceReason
	}
	for _, line := range wrapText(confidenceLine, w-2) {
		b.WriteString(padLine(line) + "\n")
	}

	b.WriteString(bot + "\n")
	return b.String()
}

// FormatSlack formats a Card as a Slack-friendly plain text message.
func FormatSlack(card *Card) string {
	var b strings.Builder
	b.WriteString(fmt.Sprintf("*Micro-standup: Task #%d — %s*\n\n", card.TaskID, card.TaskTitle))

	var meta []string
	if card.ElapsedMinutes > 0 {
		meta = append(meta, fmt.Sprintf("elapsed %dm", card.ElapsedMinutes))
	}
	if card.EstimatedMinutes > 0 {
		meta = append(meta, fmt.Sprintf("est %dm", card.EstimatedMinutes))
	}
	if card.HealAttempts > 0 {
		meta = append(meta, fmt.Sprintf("heals %d", card.HealAttempts))
	}
	if len(meta) > 0 {
		b.WriteString("_" + strings.Join(meta, " | ") + "_\n\n")
	}

	b.WriteString("*Yesterday:* " + card.Yesterday + "\n\n")
	b.WriteString("*Today:* " + card.Today + "\n\n")
	b.WriteString("*Blockers:* " + card.Blockers + "\n\n")
	b.WriteString(fmt.Sprintf("*Confidence:* %d/5 — %s\n", card.Confidence, card.ConfidenceReason))
	return b.String()
}

// wrapText splits text into lines of at most maxWidth runes, breaking on spaces.
// Existing newlines are always honoured.
func wrapText(text string, maxWidth int) []string {
	if maxWidth <= 0 {
		maxWidth = 60
	}
	var out []string
	for _, paragraph := range strings.Split(text, "\n") {
		paragraph = strings.TrimSpace(paragraph)
		if paragraph == "" {
			continue
		}
		runes := []rune(paragraph)
		for len(runes) > maxWidth {
			// Find last space at or before maxWidth.
			cut := maxWidth
			for cut > 0 && runes[cut] != ' ' {
				cut--
			}
			if cut == 0 {
				cut = maxWidth // no space found — hard break
			}
			out = append(out, strings.TrimSpace(string(runes[:cut])))
			runes = []rune(strings.TrimSpace(string(runes[cut:])))
		}
		if len(runes) > 0 {
			out = append(out, string(runes))
		}
	}
	if len(out) == 0 {
		out = []string{"(none)"}
	}
	return out
}
