// Package report generates rich project reports from cloop state.
package report

import (
	"fmt"
	"html"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/cost"
	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/state"
)

// Format controls the output format of the report.
type Format string

const (
	FormatTerminal Format = "terminal"
	FormatMarkdown Format = "markdown"
	FormatHTML     Format = "html"
)

// Options controls report generation.
type Options struct {
	Format      Format
	ShowOutputs bool // include step/task output excerpts
}

// Generate writes a project report to w based on the given state.
func Generate(w io.Writer, s *state.ProjectState, opts Options) {
	switch opts.Format {
	case FormatMarkdown:
		generateMarkdown(w, s, opts)
	case FormatHTML:
		generateHTML(w, s, opts)
	default:
		generateTerminal(w, s, opts)
	}
}

// statusEmoji maps status strings to visual indicators.
func statusEmoji(status string) string {
	switch status {
	case "complete":
		return "DONE"
	case "failed":
		return "FAIL"
	case "paused":
		return "PAUSED"
	case "running":
		return "RUNNING"
	default:
		return strings.ToUpper(status)
	}
}

func taskStatusEmoji(status pm.TaskStatus) string {
	switch status {
	case pm.TaskDone:
		return "[done]"
	case pm.TaskFailed:
		return "[fail]"
	case pm.TaskSkipped:
		return "[skip]"
	case pm.TaskInProgress:
		return "[...]"
	default:
		return "[ ]"
	}
}

// taskCounts returns done (excluding skipped), skipped, failed, pending, inProgress counts.
func taskCounts(tasks []*pm.Task) (done, skipped, failed, pending, inProgress int) {
	for _, t := range tasks {
		switch t.Status {
		case pm.TaskDone:
			done++
		case pm.TaskSkipped:
			skipped++
		case pm.TaskFailed:
			failed++
		case pm.TaskPending:
			pending++
		case pm.TaskInProgress:
			inProgress++
		}
	}
	return
}

func progressBar(done, total int, width int) string {
	if total == 0 {
		return strings.Repeat("░", width)
	}
	filled := done * width / total
	if filled > width {
		filled = width
	}
	return strings.Repeat("█", filled) + strings.Repeat("░", width-filled)
}

func generateTerminal(w io.Writer, s *state.ProjectState, opts Options) {
	sep := strings.Repeat("─", 60)

	fmt.Fprintf(w, "\n%s\n", sep)
	fmt.Fprintf(w, "  cloop Project Report\n")
	fmt.Fprintf(w, "%s\n\n", sep)

	// Header
	fmt.Fprintf(w, "Goal:       %s\n", s.Goal)
	fmt.Fprintf(w, "Status:     %s\n", statusEmoji(s.Status))
	if s.Provider != "" {
		fmt.Fprintf(w, "Provider:   %s\n", s.Provider)
	}
	if s.Model != "" {
		fmt.Fprintf(w, "Model:      %s\n", s.Model)
	}
	fmt.Fprintf(w, "Created:    %s\n", s.CreatedAt.Format("2006-01-02 15:04:05"))
	fmt.Fprintf(w, "Updated:    %s\n", s.UpdatedAt.Format("2006-01-02 15:04:05"))
	elapsed := s.UpdatedAt.Sub(s.CreatedAt).Round(time.Second)
	fmt.Fprintf(w, "Duration:   %s\n", elapsed)

	// Token usage
	if s.TotalInputTokens > 0 || s.TotalOutputTokens > 0 {
		fmt.Fprintf(w, "Tokens:     %d in / %d out", s.TotalInputTokens, s.TotalOutputTokens)
		if s.Model != "" {
			if usd, ok := cost.Estimate(s.Model, s.TotalInputTokens, s.TotalOutputTokens); ok {
				fmt.Fprintf(w, " (~%s)", cost.FormatCost(usd))
			}
		}
		fmt.Fprintf(w, "\n")
	}

	// PM task summary
	if s.PMMode && s.Plan != nil && len(s.Plan.Tasks) > 0 {
		done, skipped, failed, _, _ := taskCounts(s.Plan.Tasks)
		total := len(s.Plan.Tasks)
		pct := 0
		if total > 0 {
			pct = (done + skipped) * 100 / total
		}

		fmt.Fprintf(w, "\n%s\n", sep)
		fmt.Fprintf(w, "  Progress: %s %d%% (%d/%d)\n", progressBar(done+skipped, total, 30), pct, done+skipped, total)
		fmt.Fprintf(w, "  Completed: %d  Skipped: %d  Failed: %d  Remaining: %d\n",
			done, skipped, failed, total-done-skipped-failed)
		fmt.Fprintf(w, "%s\n\n", sep)

		// Sort tasks by ID for display
		tasks := make([]*pm.Task, len(s.Plan.Tasks))
		copy(tasks, s.Plan.Tasks)
		sort.Slice(tasks, func(i, j int) bool { return tasks[i].ID < tasks[j].ID })

		for _, t := range tasks {
			marker := taskStatusEmoji(t.Status)
			fmt.Fprintf(w, "  %s  [P%d] Task %d: %s\n", marker, t.Priority, t.ID, t.Title)
			if t.Description != "" {
				fmt.Fprintf(w, "           %s\n", truncate(t.Description, 100))
			}
			if t.StartedAt != nil && t.CompletedAt != nil {
				dur := t.CompletedAt.Sub(*t.StartedAt).Round(time.Second)
				estStr := ""
				if t.EstimatedMinutes > 0 {
					estStr = fmt.Sprintf(" (est %dm)", t.EstimatedMinutes)
				}
				fmt.Fprintf(w, "           Duration: %s%s\n", dur, estStr)
			} else if t.EstimatedMinutes > 0 {
				fmt.Fprintf(w, "           Estimate: %dm\n", t.EstimatedMinutes)
			}
			if opts.ShowOutputs && t.Result != "" {
				fmt.Fprintf(w, "           Result: %s\n", truncate(t.Result, 200))
			}
		}

		// Blockers
		var blockers []*pm.Task
		for _, t := range tasks {
			if t.Status == pm.TaskFailed {
				blockers = append(blockers, t)
			}
		}
		if len(blockers) > 0 {
			fmt.Fprintf(w, "\n%s\n  Blockers\n%s\n", sep, sep)
			for _, t := range blockers {
				fmt.Fprintf(w, "  [FAIL] Task %d: %s\n", t.ID, t.Title)
				if t.FailureDiagnosis != "" {
					fmt.Fprintf(w, "         %s\n", truncate(t.FailureDiagnosis, 120))
				}
			}
		}

		// Upcoming
		var upcoming []*pm.Task
		for _, t := range tasks {
			if t.Status == pm.TaskPending {
				upcoming = append(upcoming, t)
				if len(upcoming) >= 5 {
					break
				}
			}
		}
		if len(upcoming) > 0 {
			fmt.Fprintf(w, "\n%s\n  Upcoming Tasks\n%s\n", sep, sep)
			for _, t := range upcoming {
				est := ""
				if t.EstimatedMinutes > 0 {
					est = fmt.Sprintf(" (~%dm)", t.EstimatedMinutes)
				}
				fmt.Fprintf(w, "  [ ] Task %d: %s%s\n", t.ID, t.Title, est)
			}
		}
	} else {
		// Loop mode: show steps
		fmt.Fprintf(w, "\n%s\n", sep)
		fmt.Fprintf(w, "  Steps: %d\n", s.CurrentStep)
		fmt.Fprintf(w, "%s\n", sep)

		if opts.ShowOutputs {
			for _, step := range s.Steps {
				fmt.Fprintf(w, "\nStep %d (%s): %s\n", step.Step+1, step.Duration,
					truncate(firstMeaningfulLine(step.Output), 120))
			}
		}
	}

	// Timeline
	if s.CreatedAt != (time.Time{}) {
		fmt.Fprintf(w, "\n%s\n", sep)
		fmt.Fprintf(w, "  Timeline\n")
		fmt.Fprintf(w, "%s\n", sep)
		fmt.Fprintf(w, "  %s  Project initialized\n", s.CreatedAt.Format("15:04:05"))
		if s.PMMode && s.Plan != nil {
			tasks := make([]*pm.Task, 0, len(s.Plan.Tasks))
			for _, t := range s.Plan.Tasks {
				if t.StartedAt != nil {
					tasks = append(tasks, t)
				}
			}
			sort.Slice(tasks, func(i, j int) bool {
				return tasks[i].StartedAt.Before(*tasks[j].StartedAt)
			})
			for _, t := range tasks {
				status := "started"
				ts := t.StartedAt
				if t.CompletedAt != nil {
					status = string(t.Status)
					ts = t.CompletedAt
				}
				fmt.Fprintf(w, "  %s  Task %d %s: %s\n", ts.Format("15:04:05"), t.ID, status, t.Title)
			}
		}
		fmt.Fprintf(w, "  %s  Last updated\n", s.UpdatedAt.Format("15:04:05"))
	}

	fmt.Fprintf(w, "\n%s\n\n", sep)
}

func generateMarkdown(w io.Writer, s *state.ProjectState, opts Options) {
	fmt.Fprintf(w, "# cloop Project Report\n\n")
	fmt.Fprintf(w, "**Goal:** %s\n\n", s.Goal)

	// Metadata table
	fmt.Fprintf(w, "| Field | Value |\n|---|---|\n")
	fmt.Fprintf(w, "| Status | %s |\n", s.Status)
	if s.Provider != "" {
		fmt.Fprintf(w, "| Provider | %s |\n", s.Provider)
	}
	if s.Model != "" {
		fmt.Fprintf(w, "| Model | %s |\n", s.Model)
	}
	fmt.Fprintf(w, "| Created | %s |\n", s.CreatedAt.Format("2006-01-02 15:04:05"))
	fmt.Fprintf(w, "| Updated | %s |\n", s.UpdatedAt.Format("2006-01-02 15:04:05"))
	elapsed := s.UpdatedAt.Sub(s.CreatedAt).Round(time.Second)
	fmt.Fprintf(w, "| Duration | %s |\n", elapsed)

	// Cost summary
	var costStr string
	if s.TotalInputTokens > 0 || s.TotalOutputTokens > 0 {
		costStr = fmt.Sprintf("%d in / %d out", s.TotalInputTokens, s.TotalOutputTokens)
		if s.Model != "" {
			if usd, ok := cost.Estimate(s.Model, s.TotalInputTokens, s.TotalOutputTokens); ok {
				costStr += fmt.Sprintf(" (~%s)", cost.FormatCost(usd))
			}
		}
		fmt.Fprintf(w, "| Tokens | %s |\n", costStr)
	}
	fmt.Fprintf(w, "\n")

	// PM task table
	if s.PMMode && s.Plan != nil && len(s.Plan.Tasks) > 0 {
		done, skipped, failed, pending, _ := taskCounts(s.Plan.Tasks)
		total := len(s.Plan.Tasks)
		completed := done + skipped
		pct := 0
		if total > 0 {
			pct = completed * 100 / total
		}

		fmt.Fprintf(w, "## Progress\n\n")

		// ASCII progress bar for markdown
		barWidth := 40
		filled := completed * barWidth / total
		if total == 0 {
			filled = 0
		}
		bar := "`" + strings.Repeat("█", filled) + strings.Repeat("░", barWidth-filled) + "`"
		fmt.Fprintf(w, "%s **%d%%** (%d/%d tasks complete)\n\n", bar, pct, completed, total)

		fmt.Fprintf(w, "| Metric | Count |\n|---|---|\n")
		fmt.Fprintf(w, "| ✅ Completed | %d |\n", done)
		fmt.Fprintf(w, "| ⏭️ Skipped | %d |\n", skipped)
		if failed > 0 {
			fmt.Fprintf(w, "| ❌ Failed | %d |\n", failed)
		}
		fmt.Fprintf(w, "| ⏳ Pending | %d |\n", pending)
		fmt.Fprintf(w, "\n")

		tasks := make([]*pm.Task, len(s.Plan.Tasks))
		copy(tasks, s.Plan.Tasks)
		sort.Slice(tasks, func(i, j int) bool { return tasks[i].ID < tasks[j].ID })

		fmt.Fprintf(w, "## Task Details\n\n")
		fmt.Fprintf(w, "| # | Priority | Status | Task | Est. (min) | Actual |\n|---|---|---|---|---|---|\n")
		for _, t := range tasks {
			actual := ""
			if t.StartedAt != nil && t.CompletedAt != nil {
				actual = t.CompletedAt.Sub(*t.StartedAt).Round(time.Second).String()
			} else if t.ActualMinutes > 0 {
				actual = fmt.Sprintf("%dm", t.ActualMinutes)
			}
			est := ""
			if t.EstimatedMinutes > 0 {
				est = fmt.Sprintf("%d", t.EstimatedMinutes)
			}
			statusMd := mdStatusBadge(t.Status)
			fmt.Fprintf(w, "| %d | P%d | %s | %s | %s | %s |\n",
				t.ID, t.Priority, statusMd, t.Title, est, actual)
		}
		fmt.Fprintf(w, "\n")

		// Blockers section
		var blockers []*pm.Task
		for _, t := range tasks {
			if t.Status == pm.TaskFailed {
				blockers = append(blockers, t)
			}
		}
		if len(blockers) > 0 {
			fmt.Fprintf(w, "## Blockers\n\n")
			for _, t := range blockers {
				fmt.Fprintf(w, "### ❌ Task %d: %s\n\n", t.ID, t.Title)
				if t.FailureDiagnosis != "" {
					fmt.Fprintf(w, "> %s\n\n", t.FailureDiagnosis)
				} else if t.Description != "" {
					fmt.Fprintf(w, "> %s\n\n", truncate(t.Description, 200))
				}
			}
		}

		// Upcoming section (pending tasks)
		var upcoming []*pm.Task
		for _, t := range tasks {
			if t.Status == pm.TaskPending {
				upcoming = append(upcoming, t)
				if len(upcoming) >= 5 {
					break
				}
			}
		}
		if len(upcoming) > 0 {
			fmt.Fprintf(w, "## Upcoming Tasks\n\n")
			for _, t := range upcoming {
				est := ""
				if t.EstimatedMinutes > 0 {
					est = fmt.Sprintf(" _(~%d min)_", t.EstimatedMinutes)
				}
				fmt.Fprintf(w, "- **Task %d:** %s%s\n", t.ID, t.Title, est)
			}
			fmt.Fprintf(w, "\n")
		}

		if opts.ShowOutputs {
			fmt.Fprintf(w, "## Task Outputs\n\n")
			for _, t := range tasks {
				if t.Result == "" {
					continue
				}
				fmt.Fprintf(w, "### Task %d: %s\n\n", t.ID, t.Title)
				if t.Description != "" {
					fmt.Fprintf(w, "**Description:** %s\n\n", t.Description)
				}
				fmt.Fprintf(w, "**Status:** %s\n\n", t.Status)
				fmt.Fprintf(w, "**Result:**\n```\n%s\n```\n\n", truncate(t.Result, 500))
			}
		}
	} else {
		fmt.Fprintf(w, "## Steps\n\n")
		fmt.Fprintf(w, "Total steps completed: **%d**\n\n", s.CurrentStep)
		if opts.ShowOutputs && len(s.Steps) > 0 {
			fmt.Fprintf(w, "| Step | Duration | Summary |\n|---|---|---|\n")
			for _, step := range s.Steps {
				fmt.Fprintf(w, "| %d | %s | %s |\n", step.Step+1, step.Duration,
					truncate(firstMeaningfulLine(step.Output), 80))
			}
			fmt.Fprintf(w, "\n")
		}
	}

	// Timeline
	if s.PMMode && s.Plan != nil && len(s.Plan.Tasks) > 0 {
		fmt.Fprintf(w, "## Timeline\n\n")
		fmt.Fprintf(w, "| Time | Event |\n|---|---|\n")
		fmt.Fprintf(w, "| %s | Project initialized |\n", s.CreatedAt.Format("15:04:05"))

		tl := make([]*pm.Task, 0, len(s.Plan.Tasks))
		for _, t := range s.Plan.Tasks {
			if t.StartedAt != nil {
				tl = append(tl, t)
			}
		}
		sort.Slice(tl, func(i, j int) bool {
			return tl[i].StartedAt.Before(*tl[j].StartedAt)
		})
		for _, t := range tl {
			if t.CompletedAt != nil {
				fmt.Fprintf(w, "| %s | Task %d **%s**: %s |\n",
					t.CompletedAt.Format("15:04:05"), t.ID, t.Status, t.Title)
			}
		}
		fmt.Fprintf(w, "| %s | Last updated |\n", s.UpdatedAt.Format("15:04:05"))
		fmt.Fprintf(w, "\n")
	}

	fmt.Fprintf(w, "---\n*Generated by [cloop](https://github.com/blechschmidt/cloop) on %s*\n",
		time.Now().Format("2006-01-02"))
}

func mdStatusBadge(status pm.TaskStatus) string {
	switch status {
	case pm.TaskDone:
		return "✅ done"
	case pm.TaskFailed:
		return "❌ failed"
	case pm.TaskSkipped:
		return "⏭️ skipped"
	case pm.TaskInProgress:
		return "🔄 in_progress"
	default:
		return "⏳ pending"
	}
}

func generateHTML(w io.Writer, s *state.ProjectState, opts Options) {
	tasks := []*pm.Task{}
	if s.PMMode && s.Plan != nil {
		tasks = make([]*pm.Task, len(s.Plan.Tasks))
		copy(tasks, s.Plan.Tasks)
		sort.Slice(tasks, func(i, j int) bool { return tasks[i].ID < tasks[j].ID })
	}

	done, skipped, failed, pending, _ := taskCounts(tasks)
	total := len(tasks)
	completed := done + skipped
	pct := 0
	if total > 0 {
		pct = completed * 100 / total
	}

	elapsed := s.UpdatedAt.Sub(s.CreatedAt).Round(time.Second)

	var costLine string
	if s.TotalInputTokens > 0 || s.TotalOutputTokens > 0 {
		costLine = fmt.Sprintf("%d in / %d out tokens", s.TotalInputTokens, s.TotalOutputTokens)
		if s.Model != "" {
			if usd, ok := cost.Estimate(s.Model, s.TotalInputTokens, s.TotalOutputTokens); ok {
				costLine += fmt.Sprintf(" &mdash; estimated cost %s", cost.FormatCost(usd))
			}
		}
	}

	fmt.Fprintf(w, `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>cloop Report &mdash; %s</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Oxygen,sans-serif;background:#f5f7fa;color:#1a1a2e;line-height:1.6}
.container{max-width:960px;margin:0 auto;padding:32px 24px}
header{background:linear-gradient(135deg,#1a1a2e 0%%,#16213e 50%%,#0f3460 100%%);color:#fff;border-radius:12px;padding:32px;margin-bottom:28px;box-shadow:0 4px 20px rgba(0,0,0,.2)}
header h1{font-size:1.6rem;font-weight:700;margin-bottom:6px;letter-spacing:-.5px}
header .goal{font-size:1.05rem;opacity:.85;margin-bottom:18px}
.meta-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:12px;margin-top:16px}
.meta-item{background:rgba(255,255,255,.1);border-radius:8px;padding:10px 14px}
.meta-item .label{font-size:.7rem;text-transform:uppercase;letter-spacing:.08em;opacity:.7;margin-bottom:2px}
.meta-item .value{font-size:.95rem;font-weight:600}
.section{background:#fff;border-radius:12px;padding:24px;margin-bottom:20px;box-shadow:0 2px 10px rgba(0,0,0,.06)}
.section h2{font-size:1.1rem;font-weight:700;color:#0f3460;margin-bottom:16px;padding-bottom:8px;border-bottom:2px solid #e8ecf0}
.progress-bar-wrap{background:#e8ecf0;border-radius:999px;height:18px;overflow:hidden;margin-bottom:8px}
.progress-bar-fill{height:100%%;border-radius:999px;background:linear-gradient(90deg,#0f3460,#e94560);transition:width .4s ease}
.progress-label{font-size:.85rem;color:#555;margin-bottom:16px}
.stat-chips{display:flex;flex-wrap:wrap;gap:8px;margin-bottom:16px}
.chip{display:inline-flex;align-items:center;gap:5px;font-size:.78rem;font-weight:600;padding:4px 10px;border-radius:999px}
.chip-done{background:#d4edda;color:#155724}
.chip-skip{background:#e2e3e5;color:#383d41}
.chip-fail{background:#f8d7da;color:#721c24}
.chip-pend{background:#fff3cd;color:#856404}
table{width:100%%;border-collapse:collapse;font-size:.85rem}
th{text-align:left;padding:8px 10px;background:#f0f4f8;color:#555;font-weight:600;font-size:.75rem;text-transform:uppercase;letter-spacing:.06em}
td{padding:8px 10px;border-top:1px solid #e8ecf0;vertical-align:top}
tr:hover td{background:#fafbfc}
.badge{display:inline-block;font-size:.7rem;font-weight:700;padding:2px 7px;border-radius:4px;letter-spacing:.04em}
.badge-done{background:#d4edda;color:#155724}
.badge-failed{background:#f8d7da;color:#721c24}
.badge-skipped{background:#e2e3e5;color:#383d41}
.badge-pending{background:#fff3cd;color:#856404}
.badge-in_progress{background:#cce5ff;color:#004085}
.blocker{background:#fff5f5;border-left:4px solid #e94560;border-radius:0 8px 8px 0;padding:12px 16px;margin-bottom:12px}
.blocker h3{font-size:.9rem;font-weight:700;color:#c0392b;margin-bottom:4px}
.blocker p{font-size:.82rem;color:#666}
.upcoming-list{list-style:none;padding:0}
.upcoming-list li{display:flex;align-items:baseline;gap:10px;padding:7px 0;border-bottom:1px solid #f0f4f8;font-size:.88rem}
.upcoming-list li:last-child{border-bottom:none}
.upcoming-list .task-id{font-size:.72rem;font-weight:700;color:#0f3460;background:#e8ecf0;padding:1px 6px;border-radius:4px;white-space:nowrap}
.upcoming-list .task-est{font-size:.75rem;color:#888;margin-left:auto;white-space:nowrap}
.tl-table td:first-child{white-space:nowrap;color:#888;font-size:.78rem;font-family:monospace;width:80px}
footer{text-align:center;font-size:.75rem;color:#999;margin-top:24px}
</style>
</head>
<body>
<div class="container">
<header>
  <h1>cloop Project Report</h1>
  <div class="goal">%s</div>
  <div class="meta-grid">
    <div class="meta-item"><div class="label">Status</div><div class="value">%s</div></div>
    <div class="meta-item"><div class="label">Created</div><div class="value">%s</div></div>
    <div class="meta-item"><div class="label">Duration</div><div class="value">%s</div></div>
`,
		html.EscapeString(s.Goal),
		html.EscapeString(s.Goal),
		html.EscapeString(strings.ToUpper(s.Status)),
		html.EscapeString(s.CreatedAt.Format("2006-01-02 15:04")),
		html.EscapeString(elapsed.String()),
	)

	if s.Provider != "" {
		fmt.Fprintf(w, `    <div class="meta-item"><div class="label">Provider</div><div class="value">%s</div></div>`+"\n",
			html.EscapeString(s.Provider))
	}
	if s.Model != "" {
		fmt.Fprintf(w, `    <div class="meta-item"><div class="label">Model</div><div class="value">%s</div></div>`+"\n",
			html.EscapeString(s.Model))
	}
	if costLine != "" {
		fmt.Fprintf(w, `    <div class="meta-item"><div class="label">Cost</div><div class="value">%s</div></div>`+"\n",
			costLine) // costLine already HTML-safe (numbers + literals)
	}

	fmt.Fprintf(w, "  </div>\n</header>\n\n")

	// Progress section
	if s.PMMode && total > 0 {
		fmt.Fprintf(w, `<div class="section">
  <h2>Progress</h2>
  <div class="progress-bar-wrap"><div class="progress-bar-fill" style="width:%d%%"></div></div>
  <div class="progress-label"><strong>%d%%</strong> complete &mdash; %d of %d tasks done</div>
  <div class="stat-chips">
    <span class="chip chip-done">&#10003; %d completed</span>
    <span class="chip chip-skip">&#10233; %d skipped</span>
`, pct, pct, completed, total, done, skipped)
		if failed > 0 {
			fmt.Fprintf(w, `    <span class="chip chip-fail">&#10007; %d failed</span>`+"\n", failed)
		}
		fmt.Fprintf(w, `    <span class="chip chip-pend">&#9203; %d pending</span>`+"\n", pending)
		fmt.Fprintf(w, "  </div>\n</div>\n\n")
	}

	// Task table
	if s.PMMode && len(tasks) > 0 {
		fmt.Fprintf(w, `<div class="section">
  <h2>Tasks</h2>
  <table>
    <thead><tr><th>#</th><th>Task</th><th>Priority</th><th>Status</th><th>Est.</th><th>Actual</th></tr></thead>
    <tbody>
`)
		for _, t := range tasks {
			actual := "&mdash;"
			if t.StartedAt != nil && t.CompletedAt != nil {
				actual = t.CompletedAt.Sub(*t.StartedAt).Round(time.Second).String()
			} else if t.ActualMinutes > 0 {
				actual = fmt.Sprintf("%dm", t.ActualMinutes)
			}
			est := "&mdash;"
			if t.EstimatedMinutes > 0 {
				est = fmt.Sprintf("%dm", t.EstimatedMinutes)
			}
			badge := htmlStatusBadge(t.Status)
			desc := ""
			if t.Description != "" {
				desc = fmt.Sprintf(`<br><span style="color:#888;font-size:.78rem">%s</span>`,
					html.EscapeString(truncate(t.Description, 120)))
			}
			fmt.Fprintf(w, "      <tr><td>%d</td><td>%s%s</td><td>P%d</td><td>%s</td><td>%s</td><td>%s</td></tr>\n",
				t.ID, html.EscapeString(t.Title), desc, t.Priority, badge, est, actual)
		}
		fmt.Fprintf(w, "    </tbody>\n  </table>\n</div>\n\n")
	}

	// Blockers
	var blockers []*pm.Task
	for _, t := range tasks {
		if t.Status == pm.TaskFailed {
			blockers = append(blockers, t)
		}
	}
	if len(blockers) > 0 {
		fmt.Fprintf(w, `<div class="section">
  <h2>Blockers</h2>
`)
		for _, t := range blockers {
			diag := t.FailureDiagnosis
			if diag == "" {
				diag = t.Description
			}
			fmt.Fprintf(w, `  <div class="blocker">
    <h3>Task %d: %s</h3>
`, t.ID, html.EscapeString(t.Title))
			if diag != "" {
				fmt.Fprintf(w, `    <p>%s</p>`+"\n", html.EscapeString(truncate(diag, 300)))
			}
			fmt.Fprintf(w, "  </div>\n")
		}
		fmt.Fprintf(w, "</div>\n\n")
	}

	// Upcoming
	var upcoming []*pm.Task
	for _, t := range tasks {
		if t.Status == pm.TaskPending {
			upcoming = append(upcoming, t)
			if len(upcoming) >= 5 {
				break
			}
		}
	}
	if len(upcoming) > 0 {
		fmt.Fprintf(w, `<div class="section">
  <h2>Upcoming Tasks</h2>
  <ul class="upcoming-list">
`)
		for _, t := range upcoming {
			est := ""
			if t.EstimatedMinutes > 0 {
				est = fmt.Sprintf(`<span class="task-est">~%dm</span>`, t.EstimatedMinutes)
			}
			fmt.Fprintf(w, `    <li><span class="task-id">%d</span> %s %s</li>`+"\n",
				t.ID, html.EscapeString(t.Title), est)
		}
		fmt.Fprintf(w, "  </ul>\n</div>\n\n")
	}

	// Timeline
	if s.PMMode && len(tasks) > 0 {
		tl := make([]*pm.Task, 0, len(tasks))
		for _, t := range tasks {
			if t.StartedAt != nil {
				tl = append(tl, t)
			}
		}
		sort.Slice(tl, func(i, j int) bool {
			return tl[i].StartedAt.Before(*tl[j].StartedAt)
		})
		if len(tl) > 0 {
			fmt.Fprintf(w, `<div class="section">
  <h2>Timeline</h2>
  <table class="tl-table">
    <tbody>
      <tr><td>%s</td><td>Project initialized</td></tr>
`, s.CreatedAt.Format("15:04:05"))
			for _, t := range tl {
				if t.CompletedAt != nil {
					fmt.Fprintf(w, "      <tr><td>%s</td><td>Task %d <strong>%s</strong>: %s</td></tr>\n",
						t.CompletedAt.Format("15:04:05"), t.ID,
						html.EscapeString(string(t.Status)), html.EscapeString(t.Title))
				}
			}
			fmt.Fprintf(w, "      <tr><td>%s</td><td>Last updated</td></tr>\n", s.UpdatedAt.Format("15:04:05"))
			fmt.Fprintf(w, "    </tbody>\n  </table>\n</div>\n\n")
		}
	}

	// Optional task outputs
	if opts.ShowOutputs && len(tasks) > 0 {
		fmt.Fprintf(w, `<div class="section">
  <h2>Task Outputs</h2>
`)
		for _, t := range tasks {
			if t.Result == "" {
				continue
			}
			fmt.Fprintf(w, `  <details><summary><strong>Task %d:</strong> %s</summary>
  <pre style="background:#f5f7fa;border-radius:6px;padding:12px;overflow-x:auto;font-size:.8rem;margin-top:8px">%s</pre>
  </details>
`, t.ID, html.EscapeString(t.Title), html.EscapeString(truncate(t.Result, 1000)))
		}
		fmt.Fprintf(w, "</div>\n\n")
	}

	fmt.Fprintf(w, `<footer>Generated by <a href="https://github.com/blechschmidt/cloop">cloop</a> on %s</footer>
</div>
</body>
</html>
`, time.Now().Format("2006-01-02 15:04:05"))
}

func htmlStatusBadge(status pm.TaskStatus) string {
	cls := "badge-" + string(status)
	label := string(status)
	return fmt.Sprintf(`<span class="badge %s">%s</span>`, cls, html.EscapeString(label))
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

// firstMeaningfulLine returns the last non-empty, non-signal line from output.
func firstMeaningfulLine(output string) string {
	signals := map[string]bool{
		"GOAL_COMPLETE": true, "TASK_DONE": true, "TASK_SKIPPED": true, "TASK_FAILED": true,
	}
	lines := strings.Split(strings.TrimSpace(output), "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		line := strings.TrimSpace(lines[i])
		if line != "" && !signals[line] {
			return line
		}
	}
	return ""
}
