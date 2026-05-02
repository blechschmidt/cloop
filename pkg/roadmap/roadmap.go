// Package roadmap generates AI-powered quarterly milestone roadmaps from a task plan.
// It clusters tasks into quarters with milestone groupings and per-quarter narratives,
// then renders the roadmap as ASCII timeline, Markdown, or HTML.
package roadmap

import (
	"context"
	"encoding/json"
	"fmt"
	"html"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/provider"
)

// Format specifies the output format for the roadmap.
type Format string

const (
	FormatASCII    Format = "ascii"
	FormatMarkdown Format = "markdown"
	FormatHTML     Format = "html"
)

// TaskRef is a lightweight reference to a task within a roadmap.
type TaskRef struct {
	ID    int    `json:"id"`
	Title string `json:"title"`
	Role  string `json:"role,omitempty"`
}

// Milestone groups related tasks under a named milestone within a quarter.
type Milestone struct {
	Name  string    `json:"name"`
	Tasks []TaskRef `json:"tasks"`
}

// Quarter represents a single quarterly block in the roadmap.
type Quarter struct {
	Number     int         `json:"number"`     // 1-based quarter number
	Theme      string      `json:"theme"`      // short theme label, e.g. "Foundation"
	Narrative  string      `json:"narrative"`  // 2-3 sentence explanation
	Milestones []Milestone `json:"milestones"` // grouped task clusters
}

// Roadmap is the complete AI-generated quarterly roadmap.
type Roadmap struct {
	Goal      string     `json:"goal"`
	Quarters  []*Quarter `json:"quarters"`
	CreatedAt time.Time  `json:"created_at"`
}

// aiResponse is the JSON envelope returned by the AI provider.
type aiResponse struct {
	Quarters []*Quarter `json:"quarters"`
}

// BuildPrompt constructs the prompt sent to the AI provider.
func BuildPrompt(plan *pm.Plan, numQuarters int) string {
	var b strings.Builder

	b.WriteString("You are an expert technical product manager creating a quarterly roadmap from a task plan.\n")
	b.WriteString("Cluster the tasks below into quarters and milestones.\n\n")

	b.WriteString("## INSTRUCTIONS\n")
	fmt.Fprintf(&b, "- Produce exactly %d quarter(s). Number them Q1 through Q%d.\n", numQuarters, numQuarters)
	b.WriteString("- Each quarter must have:\n")
	b.WriteString("  - \"number\": integer (1-based)\n")
	b.WriteString("  - \"theme\": 2-4 word label summarizing the quarter's focus\n")
	b.WriteString("  - \"narrative\": 2-3 sentences explaining the theme, what will be built, and expected outcomes\n")
	b.WriteString("  - \"milestones\": array of milestone objects, each with:\n")
	b.WriteString("      - \"name\": short milestone name\n")
	b.WriteString("      - \"tasks\": array of {\"id\": int, \"title\": string, \"role\": string} task refs\n")
	b.WriteString("- Group logically related tasks under a shared milestone name.\n")
	b.WriteString("- Distribute tasks roughly evenly across quarters. Earlier quarters should contain foundational tasks.\n")
	b.WriteString("- Every task from the list must appear in exactly one milestone.\n")
	b.WriteString("- Return ONLY valid JSON matching the schema below. No markdown fences, no commentary.\n\n")

	b.WriteString("## SCHEMA\n")
	b.WriteString(`{"quarters":[{"number":1,"theme":"...","narrative":"...","milestones":[{"name":"...","tasks":[{"id":1,"title":"...","role":"..."}]}]}]}`)
	b.WriteString("\n\n")

	b.WriteString("## PROJECT GOAL\n")
	b.WriteString(plan.Goal)
	b.WriteString("\n\n")

	b.WriteString("## TASKS\n")
	for _, t := range plan.Tasks {
		role := string(t.Role)
		if role == "" {
			role = "general"
		}
		fmt.Fprintf(&b, "- id:%d [P%d][%s][%s] %s\n", t.ID, t.Priority, t.Status, role, t.Title)
		if t.Description != "" {
			short := t.Description
			if len(short) > 120 {
				short = short[:120] + "..."
			}
			fmt.Fprintf(&b, "  %s\n", short)
		}
	}

	return b.String()
}

// Build calls the provider with the full plan and returns a structured Roadmap.
func Build(ctx context.Context, p provider.Provider, model string, plan *pm.Plan, numQuarters int) (*Roadmap, error) {
	if plan == nil || len(plan.Tasks) == 0 {
		return nil, fmt.Errorf("plan has no tasks")
	}
	if numQuarters < 1 {
		numQuarters = 4
	}

	prompt := BuildPrompt(plan, numQuarters)

	result, err := p.Complete(ctx, prompt, provider.Options{
		Model: model,
	})
	if err != nil {
		return nil, fmt.Errorf("roadmap generation: %w", err)
	}

	raw := strings.TrimSpace(result.Output)
	// Strip markdown code fences if the model wrapped the JSON.
	raw = stripFences(raw)

	var resp aiResponse
	if err := json.Unmarshal([]byte(raw), &resp); err != nil {
		return nil, fmt.Errorf("parsing roadmap JSON: %w\nraw output: %s", err, truncate(raw, 400))
	}
	if len(resp.Quarters) == 0 {
		return nil, fmt.Errorf("AI returned no quarters")
	}

	return &Roadmap{
		Goal:      plan.Goal,
		Quarters:  resp.Quarters,
		CreatedAt: time.Now(),
	}, nil
}

// Save writes the roadmap to .cloop/roadmaps/ and returns the path.
func Save(workDir string, rm *Roadmap, format Format) (string, error) {
	dir := filepath.Join(workDir, ".cloop", "roadmaps")
	if err := os.MkdirAll(dir, 0755); err != nil {
		return "", fmt.Errorf("creating roadmaps dir: %w", err)
	}

	ext := "md"
	switch format {
	case FormatHTML:
		ext = "html"
	case FormatASCII:
		ext = "txt"
	}

	ts := rm.CreatedAt.UTC().Format("20060102-150405")
	filename := fmt.Sprintf("roadmap-%s.%s", ts, ext)
	path := filepath.Join(dir, filename)

	var content string
	switch format {
	case FormatHTML:
		content = RenderHTML(rm)
	case FormatMarkdown:
		content = RenderMarkdown(rm)
	default:
		content = RenderASCII(rm)
	}

	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		return "", fmt.Errorf("writing roadmap: %w", err)
	}
	return path, nil
}

// RenderASCII renders the roadmap as a visual ASCII timeline for the terminal.
func RenderASCII(rm *Roadmap) string {
	var b strings.Builder

	titleLine := fmt.Sprintf("QUARTERLY ROADMAP — %s", truncate(rm.Goal, 60))
	b.WriteString(strings.Repeat("═", 78))
	b.WriteString("\n")
	b.WriteString(centerPad(titleLine, 78))
	b.WriteString("\n")
	b.WriteString(strings.Repeat("═", 78))
	b.WriteString("\n\n")

	for _, q := range rm.Quarters {
		// Quarter header bar
		header := fmt.Sprintf(" Q%d: %s ", q.Number, q.Theme)
		b.WriteString(fmt.Sprintf("┌%s┐\n", padRight(header, 76, '─')))

		// Narrative (word-wrapped at ~72 chars)
		for _, line := range wordWrap(q.Narrative, 72) {
			b.WriteString(fmt.Sprintf("│  %s\n", line))
		}
		b.WriteString("│\n")

		// Milestones
		for mi, ms := range q.Milestones {
			connector := "├"
			if mi == len(q.Milestones)-1 {
				connector = "└"
			}
			msBar := strings.Repeat("▪", clamp(len(ms.Tasks), 1, 20))
			b.WriteString(fmt.Sprintf("%s── ◆ %s  [%s]\n", connector, ms.Name, msBar))
			for ti, t := range ms.Tasks {
				tConnector := "│   ├"
				if mi == len(q.Milestones)-1 {
					tConnector = "    ├"
				}
				if ti == len(ms.Tasks)-1 {
					tConnector = strings.Replace(tConnector, "├", "└", 1)
				}
				role := t.Role
				if role == "" {
					role = "general"
				}
				b.WriteString(fmt.Sprintf("%s─ #%-3d [%-8s] %s\n", tConnector, t.ID, role, truncate(t.Title, 50)))
			}
		}

		b.WriteString(strings.Repeat("─", 78))
		b.WriteString("\n\n")
	}

	b.WriteString(fmt.Sprintf("Generated: %s\n", rm.CreatedAt.Local().Format("2006-01-02 15:04")))
	return b.String()
}

// RenderMarkdown renders the roadmap as GitHub-flavored Markdown.
func RenderMarkdown(rm *Roadmap) string {
	var b strings.Builder

	b.WriteString("# Quarterly Roadmap\n\n")
	b.WriteString(fmt.Sprintf("**Goal:** %s\n\n", rm.Goal))
	b.WriteString(fmt.Sprintf("*Generated: %s*\n\n", rm.CreatedAt.Local().Format("2006-01-02 15:04")))
	b.WriteString("---\n\n")

	for _, q := range rm.Quarters {
		b.WriteString(fmt.Sprintf("## Q%d — %s\n\n", q.Number, q.Theme))
		b.WriteString(q.Narrative)
		b.WriteString("\n\n")

		for _, ms := range q.Milestones {
			b.WriteString(fmt.Sprintf("### ◆ %s\n\n", ms.Name))
			for _, t := range ms.Tasks {
				role := t.Role
				if role == "" {
					role = "general"
				}
				b.WriteString(fmt.Sprintf("- **#%d** `[%s]` %s\n", t.ID, role, t.Title))
			}
			b.WriteString("\n")
		}
	}

	return b.String()
}

// RenderHTML renders the roadmap as a self-contained styled HTML page.
func RenderHTML(rm *Roadmap) string {
	var body strings.Builder

	for _, q := range rm.Quarters {
		qColors := []string{"#0f5132", "#084298", "#6f1a07", "#5c3317"}
		color := qColors[(q.Number-1)%len(qColors)]

		body.WriteString(fmt.Sprintf(`<div class="quarter" style="border-left:4px solid %s">`, color))
		body.WriteString(fmt.Sprintf(`<h2 style="color:%s">Q%d &mdash; %s</h2>`, color, q.Number, html.EscapeString(q.Theme)))
		body.WriteString(fmt.Sprintf(`<p class="narrative">%s</p>`, html.EscapeString(q.Narrative)))

		for _, ms := range q.Milestones {
			body.WriteString(`<div class="milestone">`)
			body.WriteString(fmt.Sprintf(`<h3>&#9670; %s</h3>`, html.EscapeString(ms.Name)))
			body.WriteString(`<ul>`)
			for _, t := range ms.Tasks {
				role := t.Role
				if role == "" {
					role = "general"
				}
				body.WriteString(fmt.Sprintf(`<li><strong>#%d</strong> <span class="tag">%s</span> %s</li>`,
					t.ID, html.EscapeString(role), html.EscapeString(t.Title)))
			}
			body.WriteString(`</ul></div>`)
		}
		body.WriteString(`</div>`)
	}

	return fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Quarterly Roadmap — %s</title>
<style>
  body { font-family: system-ui, sans-serif; max-width: 900px; margin: 40px auto; padding: 0 20px; color: #1a1a1a; line-height: 1.6; }
  h1 { color: #1a1a1a; border-bottom: 3px solid #dee2e6; padding-bottom: 8px; }
  .meta { color: #6c757d; font-size: 0.85em; margin-bottom: 2em; }
  .quarter { background: #f8f9fa; border-radius: 8px; margin-bottom: 2em; padding: 1.2em 1.5em; }
  .quarter h2 { margin-top: 0; }
  .narrative { color: #495057; font-style: italic; }
  .milestone { margin: 1em 0 0.5em 0; }
  .milestone h3 { margin: 0 0 0.4em 0; font-size: 1em; color: #343a40; }
  ul { margin: 0; padding-left: 1.4em; }
  li { margin: 3px 0; }
  .tag { display: inline-block; background: #e9ecef; border-radius: 3px; padding: 1px 6px; font-size: 0.75em; font-family: monospace; color: #495057; }
  strong { color: #212529; }
</style>
</head>
<body>
<h1>Quarterly Roadmap</h1>
<div class="meta"><strong>Goal:</strong> %s &nbsp;&bull;&nbsp; Generated %s</div>
%s
</body>
</html>`,
		html.EscapeString(truncate(rm.Goal, 60)),
		html.EscapeString(rm.Goal),
		rm.CreatedAt.Local().Format("2006-01-02 15:04"),
		body.String())
}

// ── helpers ──────────────────────────────────────────────────────────────────

func stripFences(s string) string {
	// Remove ```json ... ``` or ``` ... ``` wrappers.
	if idx := strings.Index(s, "```"); idx >= 0 {
		s = s[idx:]
		s = strings.TrimPrefix(s, "```json")
		s = strings.TrimPrefix(s, "```")
		if end := strings.LastIndex(s, "```"); end >= 0 {
			s = s[:end]
		}
	}
	// Find first '{' in case there's leading text.
	if start := strings.Index(s, "{"); start >= 0 {
		s = s[start:]
	}
	return strings.TrimSpace(s)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

func wordWrap(s string, width int) []string {
	var lines []string
	words := strings.Fields(s)
	var cur strings.Builder
	for _, w := range words {
		if cur.Len() > 0 && cur.Len()+1+len(w) > width {
			lines = append(lines, cur.String())
			cur.Reset()
		}
		if cur.Len() > 0 {
			cur.WriteByte(' ')
		}
		cur.WriteString(w)
	}
	if cur.Len() > 0 {
		lines = append(lines, cur.String())
	}
	return lines
}

func padRight(s string, n int, pad rune) string {
	for len([]rune(s)) < n {
		s += string(pad)
	}
	return s
}

func centerPad(s string, width int) string {
	if len(s) >= width {
		return s
	}
	totalPad := width - len(s)
	left := totalPad / 2
	right := totalPad - left
	return strings.Repeat(" ", left) + s + strings.Repeat(" ", right)
}

func clamp(v, min, max int) int {
	if v < min {
		return min
	}
	if v > max {
		return max
	}
	return v
}
