// Package brief generates one-page AI executive project briefs for stakeholder updates.
// It gathers signals from forecast, health, risk, and retro packages, then calls the
// provider once to synthesize a concise brief in Markdown, HTML, or Slack block-kit JSON.
package brief

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/forecast"
	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/provider"
	"github.com/blechschmidt/cloop/pkg/risk"
	"github.com/blechschmidt/cloop/pkg/state"
)

// Format specifies the output format for the brief.
type Format string

const (
	FormatMarkdown Format = "markdown"
	FormatHTML     Format = "html"
	FormatSlack    Format = "slack"
)

// BriefMeta stores metadata about a saved brief file.
type BriefMeta struct {
	Filename  string
	CreatedAt time.Time
	Format    Format
	// first line of the brief (after the # heading)
	Preview string
}

// Brief is the generated executive brief.
type Brief struct {
	Goal        string
	GeneratedAt time.Time
	Format      Format
	Content     string // rendered content in the requested format
}

// Input holds all pre-computed context for brief generation.
type Input struct {
	State    *state.ProjectState
	Plan     *pm.Plan
	Forecast *forecast.Forecast
	// Top-N risk findings (derived locally from task RiskScore fields)
	TopRisks []*risk.Finding
	// Simple heuristic health score (0-100)
	HealthScore int
	// Retro highlights (last 3 went_well / went_wrong / next_actions)
	RetroWentWell   []string
	RetroWentWrong  []string
	RetroNextAction []string
}

// buildContext assembles the Input from state without making any AI calls.
func buildContext(s *state.ProjectState) Input {
	inp := Input{
		State: s,
	}
	if s.Plan != nil {
		inp.Plan = s.Plan
	}

	// Build forecast (pure computation).
	inp.Forecast = forecast.Build(s)

	// Derive a simple health score from task completion data.
	if inp.Plan != nil && len(inp.Plan.Tasks) > 0 {
		total := len(inp.Plan.Tasks)
		done, failed, skipped := 0, 0, 0
		for _, t := range inp.Plan.Tasks {
			switch t.Status {
			case pm.TaskDone:
				done++
			case pm.TaskFailed:
				failed++
			case pm.TaskSkipped:
				skipped++
			}
		}
		// score = done% - 2*(failed%)
		donePct := float64(done) / float64(total) * 100
		failedPct := float64(failed) / float64(total) * 100
		score := int(donePct - 2*failedPct)
		if score < 0 {
			score = 0
		}
		if score > 100 {
			score = 100
		}
		inp.HealthScore = score

		// Extract top-3 risks: tasks with highest RiskScore that are pending/in-progress.
		type taskRisk struct {
			t    *pm.Task
			rScore int
		}
		var riskTasks []taskRisk
		for _, t := range inp.Plan.Tasks {
			if t.Status == pm.TaskPending || t.Status == pm.TaskInProgress {
				riskTasks = append(riskTasks, taskRisk{t: t, rScore: t.RiskScore})
			}
		}
		sort.Slice(riskTasks, func(i, j int) bool {
			return riskTasks[i].rScore > riskTasks[j].rScore
		})
		max := 3
		if len(riskTasks) < max {
			max = len(riskTasks)
		}
		for i := 0; i < max; i++ {
			t := riskTasks[i].t
			lvl := risk.LevelMedium
			if t.RiskScore >= 8 {
				lvl = risk.LevelCritical
			} else if t.RiskScore >= 6 {
				lvl = risk.LevelHigh
			} else if t.RiskScore <= 2 {
				lvl = risk.LevelLow
			}
			inp.TopRisks = append(inp.TopRisks, &risk.Finding{
				Level:      lvl,
				Category:   risk.CategoryExternalDependency,
				Rationale:  fmt.Sprintf("Task #%d '%s' has risk score %d", t.ID, t.Title, t.RiskScore),
				Mitigation: t.Description,
			})
		}
	}

	return inp
}

// buildPrompt constructs the AI prompt for brief generation.
func buildPrompt(inp Input) string {
	var b strings.Builder

	b.WriteString("You are an expert engineering manager writing a one-page executive project brief for stakeholders.\n")
	b.WriteString("Synthesize the data below into a concise, professional executive brief.\n\n")
	b.WriteString("## INSTRUCTIONS\n")
	b.WriteString("- Length: ~400-600 words. One page. No padding.\n")
	b.WriteString("- Tone: confident, data-driven, stakeholder-facing.\n")
	b.WriteString("- Structure your response with exactly these Markdown sections:\n")
	b.WriteString("  1. # Executive Brief: <Project Title>\n")
	b.WriteString("  2. ## Summary  (2-3 sentence executive overview)\n")
	b.WriteString("  3. ## Progress  (completion stats, velocity, key milestones)\n")
	b.WriteString("  4. ## Top Risks  (up to 3, with one-line mitigation each)\n")
	b.WriteString("  5. ## Outlook  (expected completion, confidence level)\n")
	b.WriteString("  6. ## Recommended Actions  (2-4 bullet points)\n")
	b.WriteString("- Return ONLY the brief content. No extra commentary.\n\n")

	// Goal
	goal := ""
	if inp.State != nil {
		goal = inp.State.Goal
	} else if inp.Plan != nil {
		goal = inp.Plan.Goal
	}
	b.WriteString(fmt.Sprintf("## PROJECT GOAL\n%s\n\n", goal))

	// Task completion stats
	if inp.Forecast != nil {
		f := inp.Forecast
		b.WriteString("## COMPLETION STATS\n")
		b.WriteString(fmt.Sprintf("- Total tasks: %d\n", f.TotalTasks))
		b.WriteString(fmt.Sprintf("- Done: %d (%.0f%%)\n", f.DoneTasks,
			pct(f.DoneTasks, f.TotalTasks)))
		b.WriteString(fmt.Sprintf("- In progress: %d\n", f.InProgressTasks))
		b.WriteString(fmt.Sprintf("- Pending: %d\n", f.PendingTasks))
		b.WriteString(fmt.Sprintf("- Failed: %d\n", f.FailedTasks))
		b.WriteString(fmt.Sprintf("- Skipped: %d\n", f.SkippedTasks))

		// Velocity
		b.WriteString("\n## VELOCITY TREND\n")
		if f.MinuteDataPoints > 0 {
			b.WriteString(fmt.Sprintf("- Velocity ratio (actual/estimated): %.2f (1.0 = on track)\n", f.VelocityRatio))
			b.WriteString(fmt.Sprintf("- Data points: %d tasks with time tracking\n", f.MinuteDataPoints))
		} else if f.BaseVelocityPerDay > 0 {
			b.WriteString(fmt.Sprintf("- Base velocity: %.1f tasks/day\n", f.BaseVelocityPerDay))
		} else {
			b.WriteString("- Velocity data not yet available (no completed tasks)\n")
		}

		// Completion forecast
		b.WriteString("\n## COMPLETION FORECAST\n")
		if f.Expected.DaysRemaining >= 0 {
			b.WriteString(fmt.Sprintf("- Expected completion: %s (%.0f days remaining, confidence: %s)\n",
				f.Expected.CompletionDate.Format("2006-01-02"),
				f.Expected.DaysRemaining,
				f.Expected.Confidence))
			b.WriteString(fmt.Sprintf("- Optimistic: %s\n", f.Optimistic.CompletionDate.Format("2006-01-02")))
			b.WriteString(fmt.Sprintf("- Pessimistic: %s\n", f.Pessimistic.CompletionDate.Format("2006-01-02")))
		} else {
			b.WriteString("- Cannot forecast completion: no velocity data yet\n")
		}
	}

	// Health score
	b.WriteString(fmt.Sprintf("\n## PLAN HEALTH SCORE\n%d/100\n", inp.HealthScore))

	// Top risks
	b.WriteString("\n## TOP RISKS\n")
	if len(inp.TopRisks) == 0 {
		b.WriteString("- No high-risk pending tasks identified\n")
	} else {
		for _, r := range inp.TopRisks {
			b.WriteString(fmt.Sprintf("- [%s] %s\n", r.Level, r.Rationale))
			if r.Mitigation != "" {
				short := r.Mitigation
				if len(short) > 120 {
					short = short[:120] + "..."
				}
				b.WriteString(fmt.Sprintf("  Mitigation: %s\n", short))
			}
		}
	}

	// Retro highlights (if provided)
	if len(inp.RetroWentWell) > 0 || len(inp.RetroWentWrong) > 0 || len(inp.RetroNextAction) > 0 {
		b.WriteString("\n## RETRO HIGHLIGHTS\n")
		for _, w := range inp.RetroWentWell {
			b.WriteString(fmt.Sprintf("- [+] %s\n", w))
		}
		for _, w := range inp.RetroWentWrong {
			b.WriteString(fmt.Sprintf("- [-] %s\n", w))
		}
		for _, a := range inp.RetroNextAction {
			b.WriteString(fmt.Sprintf("- [>] %s\n", a))
		}
	}

	return b.String()
}

// pct computes an integer percentage, avoiding division by zero.
func pct(n, total int) float64 {
	if total == 0 {
		return 0
	}
	return float64(n) / float64(total) * 100
}

// Generate calls the provider to create an executive brief, then renders it
// in the requested format. The brief is also saved to .cloop/briefs/.
func Generate(ctx context.Context, p provider.Provider, model string, timeout time.Duration,
	s *state.ProjectState, format Format,
	retroWentWell, retroWentWrong, retroNextAction []string,
) (*Brief, error) {

	inp := buildContext(s)
	inp.RetroWentWell = retroWentWell
	inp.RetroWentWrong = retroWentWrong
	inp.RetroNextAction = retroNextAction

	prompt := buildPrompt(inp)

	result, err := p.Complete(ctx, prompt, provider.Options{
		Model:   model,
		Timeout: timeout,
	})
	if err != nil {
		return nil, fmt.Errorf("brief generation: %w", err)
	}

	mdContent := strings.TrimSpace(result.Output)

	brief := &Brief{
		GeneratedAt: time.Now(),
		Format:      format,
	}
	if s != nil {
		brief.Goal = s.Goal
	}

	switch format {
	case FormatHTML:
		brief.Content = renderHTML(mdContent, brief.Goal, brief.GeneratedAt)
	case FormatSlack:
		brief.Content = renderSlack(mdContent, brief.Goal, brief.GeneratedAt)
	default:
		brief.Content = mdContent
	}

	return brief, nil
}

// Save writes the brief to .cloop/briefs/brief-<timestamp>.<ext> and returns the path.
func Save(workDir string, b *Brief) (string, error) {
	dir := filepath.Join(workDir, ".cloop", "briefs")
	if err := os.MkdirAll(dir, 0755); err != nil {
		return "", fmt.Errorf("creating briefs dir: %w", err)
	}

	ext := "md"
	switch b.Format {
	case FormatHTML:
		ext = "html"
	case FormatSlack:
		ext = "json"
	}

	ts := b.GeneratedAt.UTC().Format("20060102-150405")
	filename := fmt.Sprintf("brief-%s.%s", ts, ext)
	path := filepath.Join(dir, filename)

	if err := os.WriteFile(path, []byte(b.Content), 0644); err != nil {
		return "", fmt.Errorf("writing brief: %w", err)
	}
	return path, nil
}

// ListBriefs returns metadata for all saved briefs, newest first.
func ListBriefs(workDir string) ([]BriefMeta, error) {
	dir := filepath.Join(workDir, ".cloop", "briefs")
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}

	var metas []BriefMeta
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.HasPrefix(name, "brief-") {
			continue
		}

		info, err := e.Info()
		if err != nil {
			continue
		}

		format := FormatMarkdown
		switch filepath.Ext(name) {
		case ".html":
			format = FormatHTML
		case ".json":
			format = FormatSlack
		}

		// Parse timestamp from filename: brief-20060102-150405.*
		preview := ""
		full := filepath.Join(dir, name)
		data, rerr := os.ReadFile(full)
		if rerr == nil {
			lines := strings.SplitN(string(data), "\n", 5)
			for _, l := range lines {
				l = strings.TrimSpace(l)
				if l != "" {
					preview = l
					break
				}
			}
			if len(preview) > 80 {
				preview = preview[:80] + "..."
			}
		}

		metas = append(metas, BriefMeta{
			Filename:  name,
			CreatedAt: info.ModTime(),
			Format:    format,
			Preview:   preview,
		})
	}

	// Sort newest first.
	sort.Slice(metas, func(i, j int) bool {
		return metas[i].CreatedAt.After(metas[j].CreatedAt)
	})
	return metas, nil
}

// renderHTML wraps Markdown content in a minimal self-contained HTML page.
func renderHTML(md, goal string, ts time.Time) string {
	// Simple Markdown → HTML conversion (headings, bold, bullets, paragraphs).
	html := mdToHTML(md)

	return fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Executive Brief — %s</title>
<style>
  body { font-family: system-ui, sans-serif; max-width: 800px; margin: 40px auto; padding: 0 20px; color: #1a1a1a; line-height: 1.6; }
  h1 { color: #0f5132; border-bottom: 3px solid #0f5132; padding-bottom: 8px; }
  h2 { color: #0a3622; margin-top: 2em; }
  ul { padding-left: 1.4em; }
  li { margin: 4px 0; }
  .meta { color: #6c757d; font-size: 0.85em; margin-bottom: 2em; }
  .badge { display: inline-block; background: #d1e7dd; color: #0f5132; border-radius: 4px; padding: 2px 8px; font-size: 0.8em; }
</style>
</head>
<body>
<div class="meta">Generated %s &nbsp;<span class="badge">Executive Brief</span></div>
%s
</body>
</html>`, htmlEscape(goal), ts.Local().Format("2006-01-02 15:04"), html)
}

// renderSlack converts the Markdown brief into a Slack Block Kit JSON payload.
func renderSlack(md, goal string, ts time.Time) string {
	// Parse sections from the Markdown.
	sections := parseSections(md)

	var blocks []map[string]interface{}

	// Header block.
	blocks = append(blocks, map[string]interface{}{
		"type": "header",
		"text": map[string]interface{}{
			"type": "plain_text",
			"text": "Executive Brief",
		},
	})

	// Context block: goal + timestamp.
	blocks = append(blocks, map[string]interface{}{
		"type": "context",
		"elements": []map[string]interface{}{
			{
				"type": "mrkdwn",
				"text": fmt.Sprintf("*Goal:* %s  •  Generated %s", goal, ts.Local().Format("2006-01-02 15:04")),
			},
		},
	})

	blocks = append(blocks, map[string]interface{}{"type": "divider"})

	for _, sec := range sections {
		if sec.heading != "" {
			blocks = append(blocks, map[string]interface{}{
				"type": "section",
				"text": map[string]interface{}{
					"type": "mrkdwn",
					"text": fmt.Sprintf("*%s*\n%s", sec.heading, sec.body),
				},
			})
		}
	}

	payload := map[string]interface{}{"blocks": blocks}
	data, _ := json.MarshalIndent(payload, "", "  ")
	return string(data)
}

type section struct {
	heading string
	body    string
}

// parseSections splits Markdown into heading+body pairs.
func parseSections(md string) []section {
	var secs []section
	var cur section
	for _, line := range strings.Split(md, "\n") {
		if strings.HasPrefix(line, "## ") {
			if cur.heading != "" || cur.body != "" {
				secs = append(secs, cur)
			}
			cur = section{heading: strings.TrimPrefix(line, "## ")}
		} else if strings.HasPrefix(line, "# ") {
			if cur.heading != "" || cur.body != "" {
				secs = append(secs, cur)
			}
			cur = section{heading: strings.TrimPrefix(line, "# ")}
		} else {
			if cur.body != "" {
				cur.body += "\n"
			}
			cur.body += line
		}
	}
	if cur.heading != "" || strings.TrimSpace(cur.body) != "" {
		secs = append(secs, cur)
	}
	return secs
}

// mdToHTML is a minimal Markdown-to-HTML converter for headings, bullets, and paragraphs.
func mdToHTML(md string) string {
	var out strings.Builder
	lines := strings.Split(md, "\n")
	inList := false
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(trimmed, "# "):
			if inList {
				out.WriteString("</ul>\n")
				inList = false
			}
			out.WriteString("<h1>" + htmlEscape(strings.TrimPrefix(trimmed, "# ")) + "</h1>\n")
		case strings.HasPrefix(trimmed, "## "):
			if inList {
				out.WriteString("</ul>\n")
				inList = false
			}
			out.WriteString("<h2>" + htmlEscape(strings.TrimPrefix(trimmed, "## ")) + "</h2>\n")
		case strings.HasPrefix(trimmed, "### "):
			if inList {
				out.WriteString("</ul>\n")
				inList = false
			}
			out.WriteString("<h3>" + htmlEscape(strings.TrimPrefix(trimmed, "### ")) + "</h3>\n")
		case strings.HasPrefix(trimmed, "- ") || strings.HasPrefix(trimmed, "* "):
			if !inList {
				out.WriteString("<ul>\n")
				inList = true
			}
			content := strings.TrimPrefix(trimmed, "- ")
			content = strings.TrimPrefix(content, "* ")
			out.WriteString("<li>" + htmlEscape(content) + "</li>\n")
		case trimmed == "":
			if inList {
				out.WriteString("</ul>\n")
				inList = false
			}
			out.WriteString("<br>\n")
		default:
			if inList {
				out.WriteString("</ul>\n")
				inList = false
			}
			out.WriteString("<p>" + htmlEscape(trimmed) + "</p>\n")
		}
	}
	if inList {
		out.WriteString("</ul>\n")
	}
	return out.String()
}

func htmlEscape(s string) string {
	s = strings.ReplaceAll(s, "&", "&amp;")
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	s = strings.ReplaceAll(s, "\"", "&quot;")
	return s
}
