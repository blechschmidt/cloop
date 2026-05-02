// Package narrative generates polished executive-level project story reports
// aimed at non-technical stakeholders. Unlike retro (team retrospective) or
// standup (daily sync), a narrative is a flowing prose "project story" with an
// introduction, chapters per completed task cluster, current state, and what's next.
package narrative

import (
	"context"
	"fmt"
	"html"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/provider"
	"github.com/blechschmidt/cloop/pkg/state"
)

// Format controls the output format of the narrative.
type Format string

const (
	FormatMarkdown Format = "markdown"
	FormatHTML     Format = "html"
)

// Metrics holds key project metrics collected for the narrative.
type Metrics struct {
	TotalTasks      int
	DoneTasks       int
	InProgressTasks int
	PendingTasks    int
	FailedTasks     int
	SkippedTasks    int
	TotalDuration   time.Duration
	EstimatedTotal  int // total estimated minutes across all tasks
	ActualTotal     int // total actual minutes across completed tasks
}

// CollectMetrics computes project metrics from a plan.
func CollectMetrics(plan *pm.Plan) Metrics {
	var m Metrics
	if plan == nil {
		return m
	}
	for _, t := range plan.Tasks {
		m.TotalTasks++
		switch t.Status {
		case pm.TaskDone:
			m.DoneTasks++
		case pm.TaskInProgress:
			m.InProgressTasks++
		case pm.TaskFailed:
			m.FailedTasks++
		case pm.TaskSkipped:
			m.SkippedTasks++
		default:
			m.PendingTasks++
		}
		if t.EstimatedMinutes > 0 {
			m.EstimatedTotal += t.EstimatedMinutes
		}
		if t.ActualMinutes > 0 {
			m.ActualTotal += t.ActualMinutes
		} else if t.StartedAt != nil && t.CompletedAt != nil {
			m.ActualTotal += int(t.CompletedAt.Sub(*t.StartedAt).Minutes())
			m.TotalDuration += t.CompletedAt.Sub(*t.StartedAt)
		}
	}
	return m
}

// BuildPrompt constructs the AI prompt for narrative generation.
func BuildPrompt(s *state.ProjectState) string {
	var plan *pm.Plan
	goal := ""
	if s != nil {
		plan = s.Plan
		goal = s.Goal
	}
	return buildPromptFromPlan(goal, plan)
}

// BuildPromptFromPlan builds the prompt from just a plan (when full state is unavailable).
func BuildPromptFromPlan(goal string, plan *pm.Plan) string {
	return buildPromptFromPlan(goal, plan)
}

func buildPromptFromPlan(goal string, plan *pm.Plan) string {
	var b strings.Builder
	m := CollectMetrics(plan)

	b.WriteString("You are a skilled technical writer creating a project narrative for non-technical stakeholders.\n")
	b.WriteString("Write a polished, flowing prose 'project story' — NOT a bullet list, NOT a retrospective, NOT a standup.\n")
	b.WriteString("This is an executive briefing that tells the story of what the team set out to do and where things stand.\n\n")

	b.WriteString("## PROJECT CONTEXT\n")
	if goal != "" {
		b.WriteString(fmt.Sprintf("Goal: %s\n\n", goal))
	}

	// Key metrics
	b.WriteString("## KEY METRICS\n")
	b.WriteString(fmt.Sprintf("- Total tasks: %d\n", m.TotalTasks))
	b.WriteString(fmt.Sprintf("- Completed: %d\n", m.DoneTasks))
	b.WriteString(fmt.Sprintf("- In progress: %d\n", m.InProgressTasks))
	b.WriteString(fmt.Sprintf("- Pending: %d\n", m.PendingTasks))
	if m.FailedTasks > 0 {
		b.WriteString(fmt.Sprintf("- Failed: %d\n", m.FailedTasks))
	}
	if m.SkippedTasks > 0 {
		b.WriteString(fmt.Sprintf("- Skipped: %d\n", m.SkippedTasks))
	}
	if m.EstimatedTotal > 0 {
		b.WriteString(fmt.Sprintf("- Estimated effort: %d minutes\n", m.EstimatedTotal))
	}
	if m.ActualTotal > 0 {
		b.WriteString(fmt.Sprintf("- Actual effort logged: %d minutes\n", m.ActualTotal))
	}
	if m.TotalDuration > 0 {
		b.WriteString(fmt.Sprintf("- Total wall-clock time: %s\n", m.TotalDuration.Round(time.Second)))
	}
	b.WriteString("\n")

	// Completed tasks — grouped into clusters by priority band
	if plan != nil && m.DoneTasks > 0 {
		b.WriteString("## COMPLETED WORK\n")
		for _, t := range plan.Tasks {
			if t.Status != pm.TaskDone {
				continue
			}
			b.WriteString(fmt.Sprintf("- [P%d] %s", t.Priority, t.Title))
			if t.Description != "" {
				desc := t.Description
				if len(desc) > 150 {
					desc = desc[:147] + "..."
				}
				b.WriteString(fmt.Sprintf(": %s", strings.ReplaceAll(desc, "\n", " ")))
			}
			if t.Result != "" {
				result := t.Result
				if len(result) > 200 {
					result = result[:197] + "..."
				}
				b.WriteString(fmt.Sprintf(" [outcome: %s]", strings.ReplaceAll(result, "\n", " ")))
			}
			for _, lnk := range t.Links {
				label := lnk.Label
				if label == "" {
					label = lnk.URL
				}
				b.WriteString(fmt.Sprintf(" [%s: %s]", lnk.Kind, label))
			}
			b.WriteString("\n")
		}
		b.WriteString("\n")
	}

	// In-progress tasks
	if plan != nil && m.InProgressTasks > 0 {
		b.WriteString("## CURRENTLY IN PROGRESS\n")
		for _, t := range plan.Tasks {
			if t.Status != pm.TaskInProgress {
				continue
			}
			b.WriteString(fmt.Sprintf("- [P%d] %s", t.Priority, t.Title))
			if t.Description != "" {
				desc := t.Description
				if len(desc) > 120 {
					desc = desc[:117] + "..."
				}
				b.WriteString(fmt.Sprintf(": %s", strings.ReplaceAll(desc, "\n", " ")))
			}
			b.WriteString("\n")
		}
		b.WriteString("\n")
	}

	// Upcoming tasks (first 5 pending by priority)
	if plan != nil && m.PendingTasks > 0 {
		b.WriteString("## WHAT'S NEXT (upcoming pending tasks)\n")
		count := 0
		for _, t := range plan.Tasks {
			if t.Status != pm.TaskPending || count >= 5 {
				continue
			}
			b.WriteString(fmt.Sprintf("- [P%d] %s\n", t.Priority, t.Title))
			count++
		}
		b.WriteString("\n")
	}

	// Narrative instructions
	b.WriteString("## NARRATIVE INSTRUCTIONS\n")
	b.WriteString("Write 3 to 5 paragraphs of flowing, engaging prose narrative. Structure it as:\n")
	b.WriteString("1. Introduction paragraph: what the project is and why it matters\n")
	b.WriteString("2. One or two chapter paragraphs: group completed work into meaningful themes or milestones,\n")
	b.WriteString("   describing what was built and why it's significant — avoid listing individual task names,\n")
	b.WriteString("   weave them into a coherent story\n")
	b.WriteString("3. Current state paragraph: what is being worked on right now and its significance\n")
	b.WriteString("4. Forward-looking paragraph: what is planned next and what outcome it will deliver\n\n")
	b.WriteString("Tone: confident, clear, non-technical. Suitable for a board update, investor briefing, or executive summary.\n")
	b.WriteString("Avoid technical jargon, task IDs, priority numbers, and internal process language.\n")
	b.WriteString("Do not use bullet points. Write only paragraphs. Do not add headers or section titles.\n")
	b.WriteString("Output ONLY the narrative prose text — no preamble, no commentary, no markdown fences.\n")

	return b.String()
}

// Generate calls the AI provider to produce a narrative and returns the raw prose.
func Generate(ctx context.Context, p provider.Provider, model string, timeout time.Duration, s *state.ProjectState) (string, error) {
	prompt := BuildPrompt(s)
	result, err := p.Complete(ctx, prompt, provider.Options{
		Model:   model,
		Timeout: timeout,
	})
	if err != nil {
		return "", fmt.Errorf("narrative generation: %w", err)
	}
	return strings.TrimSpace(result.Output), nil
}

// GenerateFromPlan calls the AI provider using only a plan (no full session state).
func GenerateFromPlan(ctx context.Context, p provider.Provider, model string, timeout time.Duration, goal string, plan *pm.Plan) (string, error) {
	prompt := BuildPromptFromPlan(goal, plan)
	result, err := p.Complete(ctx, prompt, provider.Options{
		Model:   model,
		Timeout: timeout,
	})
	if err != nil {
		return "", fmt.Errorf("narrative generation: %w", err)
	}
	return strings.TrimSpace(result.Output), nil
}

// RenderMarkdown wraps the narrative prose in a Markdown document.
func RenderMarkdown(prose, goal string, m Metrics) string {
	var b strings.Builder

	b.WriteString("# Project Narrative\n\n")
	if goal != "" {
		b.WriteString(fmt.Sprintf("**Goal:** %s\n\n", goal))
	}

	// Metrics summary table
	b.WriteString("## At a Glance\n\n")
	b.WriteString("| Metric | Value |\n|--------|-------|\n")
	b.WriteString(fmt.Sprintf("| Total tasks | %d |\n", m.TotalTasks))
	if m.TotalTasks > 0 {
		pct := int(float64(m.DoneTasks) / float64(m.TotalTasks) * 100)
		b.WriteString(fmt.Sprintf("| Completed | %d (%d%%) |\n", m.DoneTasks, pct))
	}
	if m.InProgressTasks > 0 {
		b.WriteString(fmt.Sprintf("| In progress | %d |\n", m.InProgressTasks))
	}
	if m.PendingTasks > 0 {
		b.WriteString(fmt.Sprintf("| Remaining | %d |\n", m.PendingTasks))
	}
	if m.FailedTasks > 0 {
		b.WriteString(fmt.Sprintf("| Failed | %d |\n", m.FailedTasks))
	}
	if m.EstimatedTotal > 0 && m.ActualTotal > 0 {
		b.WriteString(fmt.Sprintf("| Est. effort | %dm |\n", m.EstimatedTotal))
		b.WriteString(fmt.Sprintf("| Actual effort | %dm |\n", m.ActualTotal))
	}
	b.WriteString("\n")

	b.WriteString("## The Story\n\n")
	b.WriteString(prose)
	b.WriteString("\n\n")
	b.WriteString(fmt.Sprintf("---\n*Generated by cloop on %s*\n", time.Now().Format("2006-01-02")))

	return b.String()
}

// RenderHTML wraps the narrative prose in a self-contained HTML document with clean typography.
func RenderHTML(prose, goal string, m Metrics) string {
	var b strings.Builder

	title := "Project Narrative"
	if goal != "" {
		t := goal
		if len(t) > 60 {
			t = t[:57] + "..."
		}
		title = t + " — Project Narrative"
	}

	pct := 0
	if m.TotalTasks > 0 {
		pct = int(float64(m.DoneTasks) / float64(m.TotalTasks) * 100)
	}

	// Build metrics rows HTML
	var metricsRows strings.Builder
	metricsRows.WriteString(fmt.Sprintf("<tr><td>Total tasks</td><td>%d</td></tr>\n", m.TotalTasks))
	metricsRows.WriteString(fmt.Sprintf("<tr><td>Completed</td><td>%d (%d%%)</td></tr>\n", m.DoneTasks, pct))
	if m.InProgressTasks > 0 {
		metricsRows.WriteString(fmt.Sprintf("<tr><td>In progress</td><td>%d</td></tr>\n", m.InProgressTasks))
	}
	if m.PendingTasks > 0 {
		metricsRows.WriteString(fmt.Sprintf("<tr><td>Remaining</td><td>%d</td></tr>\n", m.PendingTasks))
	}
	if m.FailedTasks > 0 {
		metricsRows.WriteString(fmt.Sprintf("<tr><td>Failed</td><td>%d</td></tr>\n", m.FailedTasks))
	}
	if m.EstimatedTotal > 0 {
		metricsRows.WriteString(fmt.Sprintf("<tr><td>Est. effort</td><td>%d min</td></tr>\n", m.EstimatedTotal))
	}
	if m.ActualTotal > 0 {
		metricsRows.WriteString(fmt.Sprintf("<tr><td>Actual effort</td><td>%d min</td></tr>\n", m.ActualTotal))
	}

	// Convert prose paragraphs to <p> tags
	paragraphs := strings.Split(prose, "\n\n")
	var parasHTML strings.Builder
	for _, para := range paragraphs {
		para = strings.TrimSpace(para)
		if para == "" {
			continue
		}
		parasHTML.WriteString(fmt.Sprintf("<p>%s</p>\n", html.EscapeString(para)))
	}

	goalHTML := ""
	if goal != "" {
		goalHTML = fmt.Sprintf(`<p class="goal"><strong>Goal:</strong> %s</p>`, html.EscapeString(goal))
	}

	progressWidth := pct

	b.WriteString(fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>%s</title>
<style>
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    font-family: Georgia, 'Times New Roman', serif;
    font-size: 18px;
    line-height: 1.75;
    color: #1a1a1a;
    background: #fafaf8;
    max-width: 820px;
    margin: 0 auto;
    padding: 48px 32px 80px;
  }
  header {
    border-bottom: 3px solid #1a1a1a;
    padding-bottom: 24px;
    margin-bottom: 40px;
  }
  h1 {
    font-size: 2rem;
    font-weight: 700;
    letter-spacing: -0.02em;
    margin-bottom: 8px;
    color: #111;
  }
  .goal {
    font-size: 1rem;
    color: #555;
    font-style: italic;
    margin-top: 8px;
  }
  .metrics {
    background: #f0efe9;
    border-radius: 6px;
    padding: 20px 24px;
    margin-bottom: 40px;
  }
  .metrics h2 {
    font-size: 0.75rem;
    text-transform: uppercase;
    letter-spacing: 0.1em;
    color: #888;
    margin-bottom: 14px;
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
  }
  .metrics table {
    border-collapse: collapse;
    width: 100%%;
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
    font-size: 0.9rem;
  }
  .metrics td { padding: 4px 8px 4px 0; color: #333; }
  .metrics td:last-child { font-weight: 600; color: #111; text-align: right; }
  .progress-bar {
    height: 6px;
    background: #ddd;
    border-radius: 3px;
    margin-top: 14px;
    overflow: hidden;
  }
  .progress-fill {
    height: 100%%;
    background: #2563eb;
    border-radius: 3px;
    width: %d%%;
  }
  .narrative h2 {
    font-size: 0.75rem;
    text-transform: uppercase;
    letter-spacing: 0.1em;
    color: #888;
    margin-bottom: 24px;
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
  }
  .narrative p {
    margin-bottom: 1.5em;
    text-align: justify;
    hyphens: auto;
  }
  footer {
    margin-top: 56px;
    padding-top: 20px;
    border-top: 1px solid #ddd;
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
    font-size: 0.8rem;
    color: #aaa;
  }
</style>
</head>
<body>
<header>
  <h1>Project Narrative</h1>
  %s
</header>

<div class="metrics">
  <h2>At a Glance</h2>
  <table>%s</table>
  <div class="progress-bar"><div class="progress-fill"></div></div>
</div>

<div class="narrative">
  <h2>The Story</h2>
  %s
</div>

<footer>Generated by cloop &middot; %s</footer>
</body>
</html>
`, html.EscapeString(title), progressWidth, goalHTML, metricsRows.String(), parasHTML.String(), time.Now().Format("2006-01-02")))

	return b.String()
}
