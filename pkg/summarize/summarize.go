// Package summarize generates AI executive summaries of completed work for
// stakeholder communication. Unlike retro (retrospective/lessons) and report
// (status-focused), this targets non-technical stakeholder audiences.
package summarize

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/provider"
)

// Summary is the structured output of an executive summary.
type Summary struct {
	// HighLevel is a one-paragraph narrative overview of what was accomplished.
	HighLevel string `json:"high_level"`

	// Accomplishments groups completed work by theme.
	Accomplishments []ThemeGroup `json:"accomplishments"`

	// Decisions lists notable architectural or product decisions made during execution.
	Decisions []string `json:"decisions"`

	// Risks lists remaining risks or open concerns after the work is complete.
	Risks []string `json:"risks"`
}

// ThemeGroup is a cluster of related accomplishments under a common theme.
type ThemeGroup struct {
	Theme string   `json:"theme"`
	Items []string `json:"items"`
}

// TaskContext holds the data collected for a single completed task.
type TaskContext struct {
	ID          int
	Title       string
	Description string
	Status      pm.TaskStatus
	Role        string
	Tags        []string
	Result      string
	ArtifactContent string
	Annotations []pm.Annotation
	CompletedAt *time.Time
}

// CollectTaskContexts gathers all relevant task data for tasks that are done,
// optionally filtering to those completed after a given snapshot version.
func CollectTaskContexts(workDir string, plan *pm.Plan, sinceVersion int) []TaskContext {
	if plan == nil {
		return nil
	}

	var baseline map[int]pm.TaskStatus
	if sinceVersion > 0 {
		snap, err := pm.LoadSnapshot(workDir, sinceVersion)
		if err == nil && snap.Plan != nil {
			baseline = make(map[int]pm.TaskStatus, len(snap.Plan.Tasks))
			for _, t := range snap.Plan.Tasks {
				baseline[t.ID] = t.Status
			}
		}
	}

	var out []TaskContext
	for _, t := range plan.Tasks {
		if t.Status != pm.TaskDone {
			continue
		}
		// If --since is provided, only include tasks that were NOT done in the baseline.
		if baseline != nil {
			if prev, exists := baseline[t.ID]; exists && prev == pm.TaskDone {
				continue
			}
		}

		tc := TaskContext{
			ID:          t.ID,
			Title:       t.Title,
			Description: t.Description,
			Status:      t.Status,
			Role:        string(t.Role),
			Tags:        t.Tags,
			Result:      t.Result,
			Annotations: t.Annotations,
			CompletedAt: t.CompletedAt,
		}

		// Try to load artifact content for richer context.
		if t.ArtifactPath != "" {
			data, err := os.ReadFile(filepath.Join(workDir, t.ArtifactPath))
			if err == nil {
				content := string(data)
				// Trim very long artifacts to keep prompt manageable.
				if len(content) > 1500 {
					content = content[:1500] + "\n...(truncated)"
				}
				tc.ArtifactContent = content
			}
		}

		out = append(out, tc)
	}
	return out
}

// BuildPrompt constructs the executive summary prompt from task contexts and goal.
func BuildPrompt(goal string, tasks []TaskContext, sinceLabel string) string {
	var b strings.Builder

	b.WriteString("You are a senior technical program manager producing an executive summary for stakeholders.\n")
	b.WriteString("Your audience is non-technical: product owners, executives, and investors.\n")
	b.WriteString("Focus on business value, outcomes, and impact — avoid implementation details unless crucial.\n\n")

	b.WriteString(fmt.Sprintf("## PROJECT GOAL\n%s\n\n", goal))

	if sinceLabel != "" {
		b.WriteString(fmt.Sprintf("## SCOPE\nThis summary covers work completed since snapshot %s.\n\n", sinceLabel))
	}

	b.WriteString(fmt.Sprintf("## COMPLETED WORK (%d tasks)\n\n", len(tasks)))
	for _, tc := range tasks {
		rolePart := ""
		if tc.Role != "" {
			rolePart = fmt.Sprintf(" [%s]", tc.Role)
		}
		tagPart := ""
		if len(tc.Tags) > 0 {
			tagPart = fmt.Sprintf(" (tags: %s)", strings.Join(tc.Tags, ", "))
		}
		b.WriteString(fmt.Sprintf("### Task %d%s: %s%s\n", tc.ID, rolePart, tc.Title, tagPart))

		if tc.Description != "" {
			desc := tc.Description
			if len(desc) > 300 {
				desc = desc[:300] + "..."
			}
			b.WriteString(fmt.Sprintf("Description: %s\n", desc))
		}

		if tc.Result != "" {
			result := tc.Result
			if len(result) > 400 {
				result = result[:400] + "..."
			}
			b.WriteString(fmt.Sprintf("Result: %s\n", result))
		}

		if tc.ArtifactContent != "" && tc.Result == "" {
			// Only include artifact if there's no result summary (avoid duplication).
			b.WriteString(fmt.Sprintf("Output excerpt:\n%s\n", tc.ArtifactContent))
		}

		for _, ann := range tc.Annotations {
			if ann.Author == "user" || ann.Author == "ai-reviewer" {
				text := ann.Text
				if len(text) > 200 {
					text = text[:200] + "..."
				}
				b.WriteString(fmt.Sprintf("Note [%s]: %s\n", ann.Author, text))
			}
		}

		b.WriteString("\n")
	}

	b.WriteString("## INSTRUCTIONS\n")
	b.WriteString("Produce an executive summary in the following JSON structure.\n\n")
	b.WriteString("Rules:\n")
	b.WriteString("- high_level: ONE paragraph (3-5 sentences) that a CEO could read in 30 seconds\n")
	b.WriteString("- accomplishments: group related tasks into 2-5 meaningful themes (e.g. 'Infrastructure', 'User Experience', 'Security'); each theme has 1-5 bullet items\n")
	b.WriteString("- decisions: 2-5 notable architectural, product, or technical decisions that were made and have lasting impact\n")
	b.WriteString("- risks: 2-4 remaining risks, open questions, or concerns that stakeholders should be aware of\n\n")
	b.WriteString("Output ONLY valid JSON (no explanation, no markdown fences):\n")
	b.WriteString(`{"high_level":"...","accomplishments":[{"theme":"Infrastructure","items":["item1","item2"]}],"decisions":["decision1"],"risks":["risk1"]}`)
	b.WriteString("\n")

	return b.String()
}

// Generate calls the provider and produces a structured Summary.
func Generate(ctx context.Context, p provider.Provider, model string, timeout time.Duration, goal string, tasks []TaskContext, sinceLabel string) (*Summary, error) {
	prompt := BuildPrompt(goal, tasks, sinceLabel)

	result, err := p.Complete(ctx, prompt, provider.Options{
		Model:   model,
		Timeout: timeout,
	})
	if err != nil {
		return nil, fmt.Errorf("summarize: %w", err)
	}

	return ParseSummary(result.Output)
}

// ParseSummary extracts a Summary from the AI's JSON response.
func ParseSummary(output string) (*Summary, error) {
	start := strings.Index(output, "{")
	end := strings.LastIndex(output, "}")
	if start == -1 || end == -1 || end <= start {
		return nil, fmt.Errorf("no JSON found in AI response")
	}
	jsonStr := output[start : end+1]

	var s Summary
	if err := json.Unmarshal([]byte(jsonStr), &s); err != nil {
		return nil, fmt.Errorf("parsing summary JSON: %w", err)
	}
	return &s, nil
}

// FormatMarkdown renders a Summary as a Markdown document.
func FormatMarkdown(s *Summary, goal string, taskCount int, sinceLabel string) string {
	var b strings.Builder

	b.WriteString("# Executive Summary\n\n")
	if goal != "" {
		b.WriteString(fmt.Sprintf("**Project:** %s\n\n", goal))
	}
	b.WriteString(fmt.Sprintf("**Generated:** %s\n", time.Now().UTC().Format("2006-01-02 15:04 UTC")))
	if sinceLabel != "" {
		b.WriteString(fmt.Sprintf("**Since snapshot:** v%s\n", sinceLabel))
	}
	b.WriteString(fmt.Sprintf("**Completed tasks covered:** %d\n\n", taskCount))
	b.WriteString("---\n\n")

	if s.HighLevel != "" {
		b.WriteString("## Overview\n\n")
		b.WriteString(s.HighLevel)
		b.WriteString("\n\n")
	}

	if len(s.Accomplishments) > 0 {
		b.WriteString("## Key Accomplishments\n\n")
		for _, group := range s.Accomplishments {
			b.WriteString(fmt.Sprintf("### %s\n\n", group.Theme))
			for _, item := range group.Items {
				b.WriteString(fmt.Sprintf("- %s\n", item))
			}
			b.WriteString("\n")
		}
	}

	if len(s.Decisions) > 0 {
		b.WriteString("## Notable Decisions\n\n")
		for i, d := range s.Decisions {
			b.WriteString(fmt.Sprintf("%d. %s\n", i+1, d))
		}
		b.WriteString("\n")
	}

	if len(s.Risks) > 0 {
		b.WriteString("## Remaining Risks\n\n")
		for _, r := range s.Risks {
			b.WriteString(fmt.Sprintf("- %s\n", r))
		}
		b.WriteString("\n")
	}

	return b.String()
}

// FormatHTML renders a Summary as a self-contained HTML document.
func FormatHTML(s *Summary, goal string, taskCount int, sinceLabel string) string {
	var b strings.Builder

	esc := func(t string) string {
		t = strings.ReplaceAll(t, "&", "&amp;")
		t = strings.ReplaceAll(t, "<", "&lt;")
		t = strings.ReplaceAll(t, ">", "&gt;")
		t = strings.ReplaceAll(t, "\"", "&quot;")
		return t
	}

	b.WriteString(`<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">`)
	b.WriteString(`<meta name="viewport" content="width=device-width, initial-scale=1.0">`)
	b.WriteString(`<title>Executive Summary</title>`)
	b.WriteString(`<style>
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;max-width:860px;margin:40px auto;padding:0 20px;color:#1a1a2e;line-height:1.6}
h1{color:#16213e;border-bottom:3px solid #0f3460;padding-bottom:10px}
h2{color:#0f3460;margin-top:2em}
h3{color:#533483}
.meta{color:#555;font-size:.9em;margin-bottom:2em}
.overview{background:#f0f4ff;border-left:4px solid #0f3460;padding:16px 20px;border-radius:4px;margin:1em 0}
.group{background:#fafafa;border:1px solid #e0e0e0;border-radius:6px;padding:16px 20px;margin:12px 0}
.group h3{margin:0 0 8px}
ul{margin:8px 0;padding-left:1.4em}
.decisions ol{padding-left:1.4em}
.risks ul li{color:#c0392b}
footer{margin-top:3em;font-size:.8em;color:#888;border-top:1px solid #eee;padding-top:1em}
</style></head><body>`)

	b.WriteString(`<h1>Executive Summary</h1>`)
	b.WriteString(`<div class="meta">`)
	if goal != "" {
		b.WriteString(fmt.Sprintf("<strong>Project:</strong> %s<br>", esc(goal)))
	}
	b.WriteString(fmt.Sprintf("<strong>Generated:</strong> %s<br>", time.Now().UTC().Format("2006-01-02 15:04 UTC")))
	if sinceLabel != "" {
		b.WriteString(fmt.Sprintf("<strong>Since snapshot:</strong> v%s<br>", esc(sinceLabel)))
	}
	b.WriteString(fmt.Sprintf("<strong>Completed tasks covered:</strong> %d", taskCount))
	b.WriteString(`</div>`)

	if s.HighLevel != "" {
		b.WriteString(`<h2>Overview</h2>`)
		b.WriteString(fmt.Sprintf(`<div class="overview">%s</div>`, esc(s.HighLevel)))
	}

	if len(s.Accomplishments) > 0 {
		b.WriteString(`<h2>Key Accomplishments</h2>`)
		for _, group := range s.Accomplishments {
			b.WriteString(`<div class="group">`)
			b.WriteString(fmt.Sprintf(`<h3>%s</h3><ul>`, esc(group.Theme)))
			for _, item := range group.Items {
				b.WriteString(fmt.Sprintf("<li>%s</li>", esc(item)))
			}
			b.WriteString(`</ul></div>`)
		}
	}

	if len(s.Decisions) > 0 {
		b.WriteString(`<h2>Notable Decisions</h2><div class="decisions"><ol>`)
		for _, d := range s.Decisions {
			b.WriteString(fmt.Sprintf("<li>%s</li>", esc(d)))
		}
		b.WriteString(`</ol></div>`)
	}

	if len(s.Risks) > 0 {
		b.WriteString(`<h2>Remaining Risks</h2><div class="risks"><ul>`)
		for _, r := range s.Risks {
			b.WriteString(fmt.Sprintf("<li>%s</li>", esc(r)))
		}
		b.WriteString(`</ul></div>`)
	}

	b.WriteString(`<footer>Generated by cloop &mdash; AI Product Manager</footer>`)
	b.WriteString(`</body></html>`)
	return b.String()
}

// FormatJSON returns the Summary as indented JSON.
func FormatJSON(s *Summary) string {
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return "{}"
	}
	return string(data)
}

// SaveToFile writes the summary content to .cloop/summaries/<timestamp>.<ext>.
// Returns the absolute path where the file was written.
func SaveToFile(workDir, content, ext string) (string, error) {
	dir := filepath.Join(workDir, ".cloop", "summaries")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", fmt.Errorf("create summaries dir: %w", err)
	}
	ts := time.Now().UTC().Format("20060102-150405")
	filename := fmt.Sprintf("%s.%s", ts, ext)
	absPath := filepath.Join(dir, filename)
	if err := os.WriteFile(absPath, []byte(content), 0o644); err != nil {
		return "", fmt.Errorf("write summary: %w", err)
	}
	return absPath, nil
}

// CopyToClipboard copies content to the system clipboard using xclip (Linux) or pbcopy (macOS).
// Returns an error if neither tool is available or the copy fails.
func CopyToClipboard(content string) error {
	// Try xclip first (Linux), then xsel, then pbcopy (macOS).
	tools := []struct {
		cmd  string
		args []string
	}{
		{"xclip", []string{"-selection", "clipboard"}},
		{"xsel", []string{"--clipboard", "--input"}},
		{"pbcopy", nil},
	}

	for _, tool := range tools {
		if path, err := lookPath(tool.cmd); err == nil {
			return runWithStdin(path, tool.args, content)
		}
	}
	return fmt.Errorf("no clipboard tool found (install xclip, xsel, or pbcopy)")
}
