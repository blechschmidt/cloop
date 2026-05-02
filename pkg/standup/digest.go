package standup

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"html"
	"net/http"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/microstandup"
	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/provider"
	"github.com/blechschmidt/cloop/pkg/state"
)

// DigestCard bundles a micro-standup card with the originating task.
type DigestCard struct {
	Task    *pm.Task
	TaskCtx *microstandup.TaskContext // populated during collection; nil on error
	Card    *microstandup.Card        // populated after AI generation; nil on error
}

// Digest is a team-facing roll-up standup for all active tasks in a window.
type Digest struct {
	GeneratedAt time.Time
	WindowHours int
	Goal        string
	Cards       []DigestCard

	// Tasks active in the window but with no micro-standup (completed/failed)
	CompletedTasks []*pm.Task
	FailedTasks    []*pm.Task

	// AI-generated narrative
	AIText string
}

// CollectDigest gathers DigestCards for every task updated in the given window.
// In-progress tasks get a full micro-standup card; completed/failed tasks in the
// window are listed without a card (they are included in the narrative prompt).
func CollectDigest(ctx context.Context, workDir string, s *state.ProjectState, windowHours int) (*Digest, error) {
	if windowHours <= 0 {
		windowHours = 24
	}
	cutoff := time.Now().Add(-time.Duration(windowHours) * time.Hour)

	d := &Digest{
		GeneratedAt: time.Now(),
		WindowHours: windowHours,
		Goal:        s.Goal,
	}

	if s.Plan == nil {
		return d, nil
	}

	for _, t := range s.Plan.Tasks {
		switch t.Status {
		case pm.TaskDone:
			if t.CompletedAt != nil && t.CompletedAt.After(cutoff) {
				d.CompletedTasks = append(d.CompletedTasks, t)
			}
		case pm.TaskFailed:
			if t.CompletedAt != nil && t.CompletedAt.After(cutoff) {
				d.FailedTasks = append(d.FailedTasks, t)
			}
		case pm.TaskInProgress:
			taskCtx, err := microstandup.Collect(workDir, t, s.Goal)
			if err != nil {
				// Include task without a card on error
				d.Cards = append(d.Cards, DigestCard{Task: t})
				continue
			}
			d.Cards = append(d.Cards, DigestCard{Task: t, TaskCtx: taskCtx})
		}
	}

	return d, nil
}

// GenerateDigest collects per-task context, calls the AI once for a roll-up
// narrative, and returns a populated *Digest.
func GenerateDigest(
	ctx context.Context,
	prov provider.Provider,
	opts provider.Options,
	workDir string,
	s *state.ProjectState,
	windowHours int,
) (*Digest, error) {
	d, err := CollectDigest(ctx, workDir, s, windowHours)
	if err != nil {
		return nil, err
	}

	// Generate micro-standup cards for in-progress tasks.
	for i := range d.Cards {
		dc := &d.Cards[i]
		if dc.TaskCtx == nil {
			continue
		}
		cardCtx, cancel := context.WithTimeout(ctx, opts.Timeout)
		card, genErr := microstandup.Generate(cardCtx, prov, opts, dc.TaskCtx)
		cancel()
		if genErr == nil {
			dc.Card = card
		}
	}

	// Build the AI prompt and call for the digest narrative.
	prompt := BuildDigestPrompt(d)
	result, err := prov.Complete(ctx, prompt, opts)
	if err != nil {
		return nil, fmt.Errorf("digest AI call: %w", err)
	}
	d.AIText = result.Output
	return d, nil
}

// BuildDigestPrompt builds the AI prompt for the team digest.
func BuildDigestPrompt(d *Digest) string {
	var b strings.Builder

	b.WriteString("You are an engineering team lead writing a concise team-facing standup digest.\n")
	b.WriteString("Summarize what was accomplished, what is in progress, any blockers, and the top next priorities.\n")
	b.WriteString("Be specific and factual. Avoid filler phrases. Keep the total digest under 300 words.\n\n")

	b.WriteString(fmt.Sprintf("## PROJECT GOAL\n%s\n\n", d.Goal))
	b.WriteString(fmt.Sprintf("## REPORTING WINDOW\nLast %d hours\n\n", d.WindowHours))

	// Completed tasks
	if len(d.CompletedTasks) > 0 {
		b.WriteString("## COMPLETED IN WINDOW\n")
		for _, t := range d.CompletedTasks {
			dur := ""
			if t.StartedAt != nil && t.CompletedAt != nil {
				dur = fmt.Sprintf(" [%s]", t.CompletedAt.Sub(*t.StartedAt).Round(time.Second))
			}
			b.WriteString(fmt.Sprintf("- Task %d [%s]%s: %s\n", t.ID, t.Role, dur, t.Title))
			if t.Result != "" {
				s := t.Result
				if len(s) > 150 {
					s = s[:150] + "..."
				}
				b.WriteString(fmt.Sprintf("  Result: %s\n", strings.ReplaceAll(s, "\n", " ")))
			}
		}
		b.WriteString("\n")
	}

	// Failed tasks
	if len(d.FailedTasks) > 0 {
		b.WriteString("## FAILED IN WINDOW\n")
		for _, t := range d.FailedTasks {
			b.WriteString(fmt.Sprintf("- Task %d: %s\n", t.ID, t.Title))
			if t.Result != "" {
				s := t.Result
				if len(s) > 100 {
					s = s[:100] + "..."
				}
				b.WriteString(fmt.Sprintf("  Reason: %s\n", strings.ReplaceAll(s, "\n", " ")))
			}
		}
		b.WriteString("\n")
	}

	// In-progress with micro-standup cards
	if len(d.Cards) > 0 {
		b.WriteString("## IN PROGRESS — PER-TASK MICRO-STANDUPS\n")
		for _, dc := range d.Cards {
			b.WriteString(fmt.Sprintf("\n### Task %d: %s\n", dc.Task.ID, dc.Task.Title))
			if dc.Card != nil {
				b.WriteString(fmt.Sprintf("- Yesterday: %s\n", dc.Card.Yesterday))
				b.WriteString(fmt.Sprintf("- Today: %s\n", dc.Card.Today))
				b.WriteString(fmt.Sprintf("- Blockers: %s\n", dc.Card.Blockers))
				b.WriteString(fmt.Sprintf("- Confidence: %d/5 — %s\n", dc.Card.Confidence, dc.Card.ConfidenceReason))
			} else {
				b.WriteString(fmt.Sprintf("- Status: %s\n", dc.Task.Status))
				if dc.Task.Description != "" {
					b.WriteString(fmt.Sprintf("- Description: %s\n", dc.Task.Description))
				}
			}
		}
		b.WriteString("\n")
	}

	b.WriteString("## OUTPUT FORMAT\n")
	b.WriteString("Write the digest with EXACTLY these four sections:\n\n")
	b.WriteString("**Done:**\n[Bullet list of what was completed — be specific about outcomes]\n\n")
	b.WriteString("**In Progress:**\n[Bullet list of active work with status and confidence]\n\n")
	b.WriteString("**Blockers:**\n[Bullet list of impediments — or 'None' if everything is clear]\n\n")
	b.WriteString("**Next Priorities:**\n[Top 2-3 things the team should focus on next]\n")

	return b.String()
}

// FormatDigestMarkdown renders the digest as GitHub-flavored Markdown.
func FormatDigestMarkdown(d *Digest) string {
	var b strings.Builder
	b.WriteString(fmt.Sprintf("# Team Standup Digest — %s\n\n", d.GeneratedAt.Format("Mon Jan 2, 2006 15:04")))
	b.WriteString(fmt.Sprintf("**Project:** %s  \n", d.Goal))
	b.WriteString(fmt.Sprintf("**Window:** Last %dh  \n", d.WindowHours))
	b.WriteString(fmt.Sprintf("**Tasks:** %d completed, %d failed, %d in progress\n\n",
		len(d.CompletedTasks), len(d.FailedTasks), len(d.Cards)))
	b.WriteString("---\n\n")
	b.WriteString(d.AIText)
	b.WriteString("\n\n---\n\n")
	b.WriteString(fmt.Sprintf("*Generated by cloop at %s*\n", d.GeneratedAt.Format("2006-01-02 15:04:05")))
	return b.String()
}

// FormatDigestSlack renders the digest as a Slack Block Kit JSON payload.
func FormatDigestSlack(d *Digest) string {
	sections := parseDigestSections(d.AIText)

	type textObject struct {
		Type string `json:"type"`
		Text string `json:"text"`
	}
	type sectionBlock struct {
		Type string      `json:"type"`
		Text *textObject `json:"text,omitempty"`
	}
	type contextBlock struct {
		Type     string       `json:"type"`
		Elements []textObject `json:"elements"`
	}
	type dividerBlock struct {
		Type string `json:"type"`
	}

	// blocks is []interface{} to allow mixing block types.
	var blocks []interface{}

	// Header block
	blocks = append(blocks, sectionBlock{
		Type: "header",
		Text: &textObject{
			Type: "plain_text",
			Text: fmt.Sprintf("Team Standup Digest — %s", d.GeneratedAt.Format("Mon Jan 2")),
		},
	})

	// Context: project + window
	blocks = append(blocks, sectionBlock{
		Type: "section",
		Text: &textObject{
			Type: "mrkdwn",
			Text: fmt.Sprintf("*Project:* %s | *Window:* last %dh | *Tasks:* %d done, %d failed, %d in-progress",
				d.Goal, d.WindowHours, len(d.CompletedTasks), len(d.FailedTasks), len(d.Cards)),
		},
	})

	// Divider
	blocks = append(blocks, dividerBlock{Type: "divider"})

	// Done section
	if sections["done"] != "" {
		blocks = append(blocks, sectionBlock{
			Type: "section",
			Text: &textObject{Type: "mrkdwn", Text: ":white_check_mark: *Done*\n" + sections["done"]},
		})
	}

	// In Progress section
	if sections["in_progress"] != "" {
		blocks = append(blocks, sectionBlock{
			Type: "section",
			Text: &textObject{Type: "mrkdwn", Text: ":arrows_counterclockwise: *In Progress*\n" + sections["in_progress"]},
		})
	}

	// Blockers section
	if sections["blockers"] != "" {
		blocks = append(blocks, sectionBlock{
			Type: "section",
			Text: &textObject{Type: "mrkdwn", Text: ":warning: *Blockers*\n" + sections["blockers"]},
		})
	}

	// Next Priorities section
	if sections["next"] != "" {
		blocks = append(blocks, sectionBlock{
			Type: "section",
			Text: &textObject{Type: "mrkdwn", Text: ":dart: *Next Priorities*\n" + sections["next"]},
		})
	}

	// Footer
	blocks = append(blocks, dividerBlock{Type: "divider"})
	blocks = append(blocks, contextBlock{
		Type: "context",
		Elements: []textObject{{
			Type: "mrkdwn",
			Text: fmt.Sprintf("Generated by cloop at %s", d.GeneratedAt.Format("2006-01-02 15:04:05")),
		}},
	})

	payload := map[string]interface{}{"blocks": blocks}
	out, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return `{"blocks":[{"type":"section","text":{"type":"mrkdwn","text":"Error rendering Block Kit payload"}}]}`
	}
	return string(out)
}

// FormatDigestEmail renders the digest as an HTML email body.
func FormatDigestEmail(d *Digest) string {
	sections := parseDigestSections(d.AIText)

	var b strings.Builder
	b.WriteString(`<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<style>
body{font-family:Arial,Helvetica,sans-serif;font-size:14px;color:#1a1a1a;max-width:680px;margin:0 auto;padding:24px}
h1{color:#1a1a1a;font-size:20px;margin:0 0 4px}
.meta{color:#666;font-size:12px;margin:0 0 20px}
.section{margin:18px 0}
.section h2{font-size:15px;margin:0 0 8px;color:#2d5a8e;border-bottom:1px solid #e0e0e0;padding-bottom:4px}
.section p,.section ul{margin:0;padding:0;line-height:1.6}
ul{padding-left:20px}
li{margin:3px 0}
.footer{margin-top:28px;font-size:11px;color:#999;border-top:1px solid #e0e0e0;padding-top:10px}
.badge{display:inline-block;padding:2px 8px;border-radius:3px;font-size:11px;font-weight:bold}
.badge-done{background:#d4edda;color:#155724}
.badge-fail{background:#f8d7da;color:#721c24}
.badge-wip{background:#fff3cd;color:#856404}
</style>
</head>
<body>
`)
	b.WriteString(fmt.Sprintf("<h1>Team Standup Digest — %s</h1>\n", html.EscapeString(d.GeneratedAt.Format("Mon Jan 2, 2006 15:04"))))
	b.WriteString(fmt.Sprintf("<p class=\"meta\"><strong>Project:</strong> %s &nbsp;|&nbsp; <strong>Window:</strong> Last %dh &nbsp;|&nbsp; ",
		html.EscapeString(d.Goal), d.WindowHours))
	b.WriteString(fmt.Sprintf("<span class=\"badge badge-done\">%d done</span> &nbsp;"+
		"<span class=\"badge badge-fail\">%d failed</span> &nbsp;"+
		"<span class=\"badge badge-wip\">%d in-progress</span></p>\n",
		len(d.CompletedTasks), len(d.FailedTasks), len(d.Cards)))

	renderSection := func(title, icon, key string) {
		content := sections[key]
		if content == "" {
			return
		}
		b.WriteString(fmt.Sprintf("<div class=\"section\"><h2>%s %s</h2>", icon, html.EscapeString(title)))
		// Convert bullet lines to <ul><li>
		lines := strings.Split(strings.TrimSpace(content), "\n")
		hasBullets := false
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "- ") || strings.HasPrefix(line, "• ") || strings.HasPrefix(line, "* ") {
				if !hasBullets {
					b.WriteString("<ul>")
					hasBullets = true
				}
				text := strings.TrimPrefix(strings.TrimPrefix(strings.TrimPrefix(line, "- "), "• "), "* ")
				b.WriteString(fmt.Sprintf("<li>%s</li>", html.EscapeString(text)))
			} else if line != "" {
				if hasBullets {
					b.WriteString("</ul>")
					hasBullets = false
				}
				b.WriteString(fmt.Sprintf("<p>%s</p>", html.EscapeString(line)))
			}
		}
		if hasBullets {
			b.WriteString("</ul>")
		}
		b.WriteString("</div>\n")
	}

	renderSection("Done", "✅", "done")
	renderSection("In Progress", "🔄", "in_progress")
	renderSection("Blockers", "⚠️", "blockers")
	renderSection("Next Priorities", "🎯", "next")

	b.WriteString(fmt.Sprintf("<div class=\"footer\">Generated by cloop at %s</div>\n",
		html.EscapeString(d.GeneratedAt.Format("2006-01-02 15:04:05"))))
	b.WriteString("</body>\n</html>\n")
	return b.String()
}

// PostDigestToSlack posts the Block Kit payload to the given Slack webhook URL.
func PostDigestToSlack(ctx context.Context, webhookURL string, d *Digest) error {
	payload := FormatDigestSlack(d)
	req, err := http.NewRequestWithContext(ctx, "POST", webhookURL, bytes.NewBufferString(payload))
	if err != nil {
		return fmt.Errorf("building request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "cloop/1.0")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("posting to Slack: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("Slack webhook returned status %d", resp.StatusCode)
	}
	return nil
}

// parseDigestSections extracts Done / In Progress / Blockers / Next Priorities
// from the AI-generated text (which uses **Section:** headers).
func parseDigestSections(text string) map[string]string {
	result := map[string]string{
		"done":        "",
		"in_progress": "",
		"blockers":    "",
		"next":        "",
	}

	var current string
	var buf strings.Builder

	flush := func() {
		if current != "" {
			result[current] = strings.TrimSpace(buf.String())
		}
		buf.Reset()
	}

	for _, line := range strings.Split(text, "\n") {
		lower := strings.ToLower(strings.TrimSpace(line))
		// Strip leading ** and trailing **:
		stripped := strings.Trim(strings.TrimSuffix(strings.TrimPrefix(lower, "**"), "**"), ":")
		stripped = strings.TrimSpace(stripped)

		switch {
		case strings.HasPrefix(stripped, "done"):
			flush()
			current = "done"
		case strings.HasPrefix(stripped, "in progress") || strings.HasPrefix(stripped, "in_progress"):
			flush()
			current = "in_progress"
		case strings.HasPrefix(stripped, "blocker"):
			flush()
			current = "blockers"
		case strings.HasPrefix(stripped, "next priorit") || strings.HasPrefix(stripped, "next priority") || stripped == "next":
			flush()
			current = "next"
		default:
			if current != "" {
				buf.WriteString(line)
				buf.WriteByte('\n')
			}
		}
	}
	flush()
	return result
}
