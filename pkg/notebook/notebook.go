// Package notebook generates a rich, shareable project notebook from a cloop
// plan. The notebook captures the full project story: goal, plan health, task
// list with status/priority/tags, per-task output excerpts from persisted
// artifacts, time estimates vs actuals, and a retrospective summary.
//
// Two output formats are supported:
//   - "md"   / "markdown" — GitHub-flavoured Markdown
//   - "html"              — self-contained single-file HTML (inline CSS, no
//     external dependencies) with collapsible sections per task
package notebook

import (
	"fmt"
	"html"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/state"
)

// Build generates the notebook document for the project rooted at workDir.
// plan may be nil (in which case plan-specific sections are omitted).
// format must be "md", "markdown", or "html"; anything else defaults to "md".
func Build(workDir string, s *state.ProjectState, format string) (string, error) {
	switch strings.ToLower(format) {
	case "html", "htm":
		return buildHTML(workDir, s)
	default:
		return buildMarkdown(workDir, s)
	}
}

// ─── helpers ──────────────────────────────────────────────────────────────────

// healthScore computes a simple heuristic health score (0-100) from the plan
// without calling an AI provider, so the notebook is always offline-capable.
func healthScore(plan *pm.Plan) int {
	if plan == nil || len(plan.Tasks) == 0 {
		return 0
	}
	tasks := plan.Tasks
	total := len(tasks)

	var done, failed, skipped int
	var noDescription, noEstimate int
	for _, t := range tasks {
		switch t.Status {
		case pm.TaskDone:
			done++
		case pm.TaskFailed:
			failed++
		case pm.TaskSkipped:
			skipped++
		}
		if strings.TrimSpace(t.Description) == "" {
			noDescription++
		}
		if t.EstimatedMinutes == 0 {
			noEstimate++
		}
	}

	score := 100

	// Penalise failed tasks heavily
	if total > 0 {
		failRatio := float64(failed) / float64(total)
		score -= int(failRatio * 40)
	}

	// Penalise missing descriptions
	if total > 0 {
		descMissing := float64(noDescription) / float64(total)
		score -= int(descMissing * 20)
	}

	// Penalise missing estimates
	if total > 0 {
		estMissing := float64(noEstimate) / float64(total)
		score -= int(estMissing * 10)
	}

	// Bonus for high completion ratio
	completed := done + skipped
	if total > 0 {
		compRatio := float64(completed) / float64(total)
		bonus := int(compRatio * 15)
		score += bonus
	}

	if score < 0 {
		score = 0
	}
	if score > 100 {
		score = 100
	}
	return score
}

func healthGrade(score int) string {
	switch {
	case score >= 90:
		return "A"
	case score >= 80:
		return "B"
	case score >= 70:
		return "C"
	case score >= 60:
		return "D"
	default:
		return "F"
	}
}

func statusSymbol(st pm.TaskStatus) string {
	switch st {
	case pm.TaskDone:
		return "✓"
	case pm.TaskFailed:
		return "✗"
	case pm.TaskSkipped:
		return "⊘"
	case pm.TaskInProgress:
		return "●"
	default:
		return "○"
	}
}

func priorityLabel(p int) string {
	switch p {
	case 1:
		return "P1 (critical)"
	case 2:
		return "P2 (high)"
	case 3:
		return "P3 (medium)"
	default:
		return fmt.Sprintf("P%d", p)
	}
}

func fmtDuration(minutes int) string {
	if minutes <= 0 {
		return "—"
	}
	h := minutes / 60
	m := minutes % 60
	if h > 0 {
		return fmt.Sprintf("%dh %02dm", h, m)
	}
	return fmt.Sprintf("%dm", m)
}

// readArtifact reads the artifact file for a task and returns its body
// (everything after the YAML frontmatter). Returns empty string on error.
func readArtifact(workDir string, t *pm.Task) string {
	if t.ArtifactPath == "" {
		return ""
	}
	absPath := filepath.Join(workDir, t.ArtifactPath)
	data, err := os.ReadFile(absPath)
	if err != nil {
		return ""
	}
	content := string(data)
	// Strip YAML frontmatter (--- … ---)
	if strings.HasPrefix(content, "---\n") {
		end := strings.Index(content[4:], "\n---\n")
		if end >= 0 {
			content = content[4+end+5:]
		}
	}
	return strings.TrimSpace(content)
}

// excerpt returns up to maxLines lines of text, with a trailing note if truncated.
func excerpt(text string, maxLines int) string {
	if text == "" {
		return ""
	}
	lines := strings.Split(text, "\n")
	if len(lines) <= maxLines {
		return text
	}
	return strings.Join(lines[:maxLines], "\n") + fmt.Sprintf("\n\n…(%d more lines)", len(lines)-maxLines)
}

// retroSummary builds a plain-language retrospective without AI.
func retroSummary(plan *pm.Plan) string {
	if plan == nil || len(plan.Tasks) == 0 {
		return "No tasks recorded."
	}
	var done, failed, skipped, pending int
	var totalEst, totalActual int
	var overrun, underrun int
	for _, t := range plan.Tasks {
		switch t.Status {
		case pm.TaskDone:
			done++
		case pm.TaskFailed:
			failed++
		case pm.TaskSkipped:
			skipped++
		default:
			pending++
		}
		if t.EstimatedMinutes > 0 && t.ActualMinutes > 0 {
			totalEst += t.EstimatedMinutes
			totalActual += t.ActualMinutes
			if t.ActualMinutes > t.EstimatedMinutes {
				overrun++
			} else {
				underrun++
			}
		}
	}
	total := len(plan.Tasks)
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("The plan contained **%d tasks**: %d completed, %d failed, %d skipped, %d pending.\n\n",
		total, done, failed, skipped, pending))

	if done+failed+skipped > 0 {
		doneRate := 100 * done / (done + failed + skipped)
		sb.WriteString(fmt.Sprintf("Completion rate (done / finished): **%d%%**.\n\n", doneRate))
	}

	if totalEst > 0 && totalActual > 0 {
		ratio := float64(totalActual) / float64(totalEst)
		sb.WriteString(fmt.Sprintf("Time accuracy: estimated %s, actual %s (ratio %.2fx). ",
			fmtDuration(totalEst), fmtDuration(totalActual), ratio))
		if ratio > 1.2 {
			sb.WriteString("Estimates were generally optimistic — consider adding buffer in future plans.")
		} else if ratio < 0.8 {
			sb.WriteString("Estimates were conservative — velocity was higher than expected.")
		} else {
			sb.WriteString("Estimates were reasonably accurate.")
		}
		sb.WriteString("\n\n")
	}

	if failed > 0 {
		sb.WriteString(fmt.Sprintf("**%d task(s) failed** — review failure diagnoses and consider retrying or splitting those tasks.\n\n", failed))
	}
	if pending > 0 {
		sb.WriteString(fmt.Sprintf("**%d task(s) remain pending** — run `cloop run --pm` to continue execution.\n\n", pending))
	}

	return strings.TrimSpace(sb.String())
}

// ─── Markdown format ──────────────────────────────────────────────────────────

func buildMarkdown(workDir string, s *state.ProjectState) (string, error) {
	var sb strings.Builder

	now := time.Now().UTC().Format("2006-01-02 15:04 UTC")
	sb.WriteString(fmt.Sprintf("# Project Notebook\n\n_Generated: %s_\n\n---\n\n", now))

	// Goal
	goal := "(no goal set)"
	if s.Plan != nil && s.Plan.Goal != "" {
		goal = s.Plan.Goal
	}
	sb.WriteString(fmt.Sprintf("## Goal\n\n%s\n\n", goal))

	// Plan health
	score := healthScore(s.Plan)
	grade := healthGrade(score)
	sb.WriteString(fmt.Sprintf("## Plan Health\n\n**Score:** %d / 100  (**%s**)\n\n", score, grade))

	// Task summary table
	if s.Plan != nil && len(s.Plan.Tasks) > 0 {
		var done, failed, skipped, pending int
		for _, t := range s.Plan.Tasks {
			switch t.Status {
			case pm.TaskDone:
				done++
			case pm.TaskFailed:
				failed++
			case pm.TaskSkipped:
				skipped++
			default:
				pending++
			}
		}
		total := len(s.Plan.Tasks)
		sb.WriteString(fmt.Sprintf("| Total | Done | Failed | Skipped | Pending |\n"))
		sb.WriteString("|-------|------|--------|---------|--------|\n")
		sb.WriteString(fmt.Sprintf("| %d | %d | %d | %d | %d |\n\n", total, done, failed, skipped, pending))
	}

	// Task list
	if s.Plan != nil && len(s.Plan.Tasks) > 0 {
		sb.WriteString("## Tasks\n\n")
		sb.WriteString("| # | Status | Priority | Role | Title | Est | Actual | Tags |\n")
		sb.WriteString("|---|--------|----------|------|-------|-----|--------|------|\n")
		for _, t := range s.Plan.Tasks {
			tags := strings.Join(t.Tags, ", ")
			sb.WriteString(fmt.Sprintf("| %d | %s %s | %s | %s | %s | %s | %s | %s |\n",
				t.ID,
				statusSymbol(t.Status), string(t.Status),
				priorityLabel(t.Priority),
				string(t.Role),
				t.Title,
				fmtDuration(t.EstimatedMinutes),
				fmtDuration(t.ActualMinutes),
				tags,
			))
		}
		sb.WriteString("\n")
	}

	// Per-task detail sections
	if s.Plan != nil && len(s.Plan.Tasks) > 0 {
		sb.WriteString("## Task Details\n\n")
		for _, t := range s.Plan.Tasks {
			sb.WriteString(fmt.Sprintf("### %d. %s\n\n", t.ID, t.Title))
			sb.WriteString(fmt.Sprintf("**Status:** %s %s  \n", statusSymbol(t.Status), string(t.Status)))
			sb.WriteString(fmt.Sprintf("**Priority:** %s  \n", priorityLabel(t.Priority)))
			if t.Role != "" {
				sb.WriteString(fmt.Sprintf("**Role:** %s  \n", string(t.Role)))
			}
			if len(t.Tags) > 0 {
				sb.WriteString(fmt.Sprintf("**Tags:** %s  \n", strings.Join(t.Tags, ", ")))
			}
			if t.EstimatedMinutes > 0 || t.ActualMinutes > 0 {
				sb.WriteString(fmt.Sprintf("**Time:** estimated %s, actual %s  \n",
					fmtDuration(t.EstimatedMinutes), fmtDuration(t.ActualMinutes)))
			}
			if t.StartedAt != nil {
				sb.WriteString(fmt.Sprintf("**Started:** %s  \n", t.StartedAt.UTC().Format("2006-01-02 15:04 UTC")))
			}
			if t.CompletedAt != nil {
				sb.WriteString(fmt.Sprintf("**Completed:** %s  \n", t.CompletedAt.UTC().Format("2006-01-02 15:04 UTC")))
			}
			if len(t.DependsOn) > 0 {
				deps := make([]string, len(t.DependsOn))
				for i, d := range t.DependsOn {
					deps[i] = fmt.Sprintf("#%d", d)
				}
				sb.WriteString(fmt.Sprintf("**Depends on:** %s  \n", strings.Join(deps, ", ")))
			}
			sb.WriteString("\n")

			if t.Description != "" {
				sb.WriteString(fmt.Sprintf("**Description:**\n\n%s\n\n", t.Description))
			}

			if t.FailureDiagnosis != "" {
				sb.WriteString(fmt.Sprintf("**Failure Diagnosis:**\n\n%s\n\n", t.FailureDiagnosis))
			}

			// Artifact output excerpt
			art := readArtifact(workDir, t)
			if art != "" {
				sb.WriteString("<details>\n<summary>Output excerpt</summary>\n\n")
				sb.WriteString("```\n")
				sb.WriteString(excerpt(art, 60))
				sb.WriteString("\n```\n\n</details>\n\n")
			}

			// Annotations
			if len(t.Annotations) > 0 {
				sb.WriteString("**Annotations:**\n\n")
				for _, a := range t.Annotations {
					sb.WriteString(fmt.Sprintf("- [%s] **%s**: %s\n",
						a.Timestamp.UTC().Format("2006-01-02 15:04"), a.Author, a.Text))
				}
				sb.WriteString("\n")
			}

			sb.WriteString("---\n\n")
		}
	}

	// Retrospective
	sb.WriteString("## Retrospective\n\n")
	sb.WriteString(retroSummary(s.Plan))
	sb.WriteString("\n")

	return sb.String(), nil
}

// ─── HTML format ──────────────────────────────────────────────────────────────

func buildHTML(workDir string, s *state.ProjectState) (string, error) {
	md, err := buildMarkdown(workDir, s)
	if err != nil {
		return "", err
	}
	_ = md // used below as fallback reference

	goal := "(no goal set)"
	if s.Plan != nil && s.Plan.Goal != "" {
		goal = s.Plan.Goal
	}
	score := healthScore(s.Plan)
	grade := healthGrade(score)
	now := time.Now().UTC().Format("2006-01-02 15:04 UTC")

	var sb strings.Builder

	// ---- HTML preamble ----
	sb.WriteString(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>cloop Project Notebook</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;
     background:#0d1117;color:#c9d1d9;line-height:1.6;padding:2rem}
a{color:#58a6ff}
h1{font-size:2rem;margin-bottom:.25rem;color:#f0f6fc}
h2{font-size:1.4rem;margin:2rem 0 .75rem;color:#f0f6fc;border-bottom:1px solid #30363d;padding-bottom:.25rem}
h3{font-size:1.1rem;margin:1.25rem 0 .5rem;color:#e6edf3}
.meta{color:#8b949e;font-size:.875rem;margin-bottom:2rem}
.card{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:1.25rem;margin-bottom:1rem}
table{width:100%;border-collapse:collapse;margin:.75rem 0;font-size:.9rem}
th{background:#21262d;color:#8b949e;padding:.5rem .75rem;text-align:left;border-bottom:2px solid #30363d}
td{padding:.45rem .75rem;border-bottom:1px solid #21262d;vertical-align:top}
tr:last-child td{border-bottom:none}
.badge{display:inline-block;padding:.15rem .55rem;border-radius:999px;font-size:.75rem;font-weight:600}
.done{background:#1a4731;color:#3fb950}
.failed{background:#4c0c0c;color:#f85149}
.skipped{background:#2d2d2d;color:#8b949e}
.pending{background:#1c2128;color:#8b949e}
.in_progress{background:#1a3048;color:#58a6ff}
.timed_out{background:#3d2800;color:#d29922}
.score{font-size:2.5rem;font-weight:700;color:#58a6ff}
.grade{font-size:1.25rem;margin-left:.5rem;color:#d29922}
.health-bar{background:#21262d;border-radius:4px;height:10px;margin:.5rem 0 1rem}
.health-fill{height:10px;border-radius:4px;background:linear-gradient(90deg,#f85149,#d29922,#3fb950)}
details{margin-top:.75rem}
summary{cursor:pointer;color:#58a6ff;font-size:.875rem;user-select:none}
summary:hover{text-decoration:underline}
pre{background:#0d1117;border:1px solid #30363d;border-radius:6px;padding:1rem;
    overflow:auto;font-size:.8rem;line-height:1.45;max-height:400px;margin:.5rem 0}
code{font-family:"SFMono-Regular",Consolas,"Liberation Mono",Menlo,monospace}
.label{font-weight:600;color:#8b949e;font-size:.85rem;text-transform:uppercase;
       letter-spacing:.05em;margin-right:.5rem}
.retro{white-space:pre-wrap;background:#161b22;border-left:3px solid #58a6ff;
       padding:1rem 1.25rem;border-radius:4px;font-size:.9rem}
.tag{background:#1c2128;border:1px solid #30363d;border-radius:4px;
     padding:.1rem .4rem;font-size:.75rem;margin-right:.3rem;color:#8b949e}
.dep{color:#8b949e;font-size:.85rem}
.annotation{background:#21262d;border-radius:4px;padding:.35rem .6rem;margin:.3rem 0;font-size:.85rem}
.ann-author{color:#d29922;font-weight:600;margin-right:.4rem}
.ann-time{color:#8b949e;font-size:.75rem}
.time-col{font-variant-numeric:tabular-nums}
</style>
</head>
<body>
`)

	// ---- Header ----
	sb.WriteString(fmt.Sprintf("<h1>Project Notebook</h1>\n<p class=\"meta\">Generated: %s</p>\n\n", html.EscapeString(now)))

	// ---- Goal ----
	sb.WriteString("<h2>Goal</h2>\n")
	sb.WriteString(fmt.Sprintf("<div class=\"card\">%s</div>\n\n", html.EscapeString(goal)))

	// ---- Health score ----
	sb.WriteString("<h2>Plan Health</h2>\n<div class=\"card\">\n")
	sb.WriteString(fmt.Sprintf("<span class=\"score\">%d</span><span class=\"grade\">%s</span><span style=\"color:#8b949e;font-size:.9rem\"> / 100</span>\n",
		score, html.EscapeString(grade)))
	fillPct := score
	sb.WriteString(fmt.Sprintf("<div class=\"health-bar\"><div class=\"health-fill\" style=\"width:%d%%\"></div></div>\n", fillPct))
	sb.WriteString("</div>\n\n")

	// ---- Summary table ----
	if s.Plan != nil && len(s.Plan.Tasks) > 0 {
		var done, failed, skipped, pending int
		for _, t := range s.Plan.Tasks {
			switch t.Status {
			case pm.TaskDone:
				done++
			case pm.TaskFailed:
				failed++
			case pm.TaskSkipped:
				skipped++
			default:
				pending++
			}
		}
		total := len(s.Plan.Tasks)
		sb.WriteString("<h2>Summary</h2>\n<table>\n")
		sb.WriteString("<tr><th>Total</th><th>Done</th><th>Failed</th><th>Skipped</th><th>Pending</th></tr>\n")
		sb.WriteString(fmt.Sprintf("<tr><td>%d</td><td>%d</td><td>%d</td><td>%d</td><td>%d</td></tr>\n",
			total, done, failed, skipped, pending))
		sb.WriteString("</table>\n\n")
	}

	// ---- Task table ----
	if s.Plan != nil && len(s.Plan.Tasks) > 0 {
		sb.WriteString("<h2>Tasks</h2>\n<table>\n")
		sb.WriteString("<tr><th>#</th><th>Status</th><th>Priority</th><th>Role</th><th>Title</th><th>Est</th><th>Actual</th><th>Tags</th></tr>\n")
		for _, t := range s.Plan.Tasks {
			statusClass := strings.ReplaceAll(string(t.Status), "_", "_")
			var tagHTML strings.Builder
			for _, tg := range t.Tags {
				tagHTML.WriteString(fmt.Sprintf("<span class=\"tag\">%s</span>", html.EscapeString(tg)))
			}
			sb.WriteString(fmt.Sprintf(
				"<tr><td>%d</td><td><span class=\"badge %s\">%s</span></td><td>%s</td><td>%s</td><td>%s</td><td class=\"time-col\">%s</td><td class=\"time-col\">%s</td><td>%s</td></tr>\n",
				t.ID,
				html.EscapeString(statusClass),
				html.EscapeString(string(t.Status)),
				html.EscapeString(priorityLabel(t.Priority)),
				html.EscapeString(string(t.Role)),
				html.EscapeString(t.Title),
				html.EscapeString(fmtDuration(t.EstimatedMinutes)),
				html.EscapeString(fmtDuration(t.ActualMinutes)),
				tagHTML.String(),
			))
		}
		sb.WriteString("</table>\n\n")
	}

	// ---- Per-task detail sections ----
	if s.Plan != nil && len(s.Plan.Tasks) > 0 {
		sb.WriteString("<h2>Task Details</h2>\n")
		for _, t := range s.Plan.Tasks {
			statusClass := string(t.Status)
			sb.WriteString("<div class=\"card\">\n")
			sb.WriteString(fmt.Sprintf("<h3>%d. %s <span class=\"badge %s\" style=\"font-size:.75rem\">%s</span></h3>\n",
				t.ID,
				html.EscapeString(t.Title),
				html.EscapeString(statusClass),
				html.EscapeString(string(t.Status)),
			))

			// Metadata row
			sb.WriteString("<p style=\"font-size:.875rem;color:#8b949e;margin:.4rem 0\">")
			sb.WriteString(fmt.Sprintf("<span class=\"label\">Priority</span>%s", html.EscapeString(priorityLabel(t.Priority))))
			if t.Role != "" {
				sb.WriteString(fmt.Sprintf(" &nbsp;|&nbsp; <span class=\"label\">Role</span>%s", html.EscapeString(string(t.Role))))
			}
			if t.EstimatedMinutes > 0 || t.ActualMinutes > 0 {
				sb.WriteString(fmt.Sprintf(" &nbsp;|&nbsp; <span class=\"label\">Time</span>est %s / actual %s",
					html.EscapeString(fmtDuration(t.EstimatedMinutes)),
					html.EscapeString(fmtDuration(t.ActualMinutes))))
			}
			if t.StartedAt != nil {
				sb.WriteString(fmt.Sprintf(" &nbsp;|&nbsp; <span class=\"label\">Started</span>%s",
					html.EscapeString(t.StartedAt.UTC().Format("2006-01-02 15:04"))))
			}
			if t.CompletedAt != nil {
				sb.WriteString(fmt.Sprintf(" &nbsp;|&nbsp; <span class=\"label\">Completed</span>%s",
					html.EscapeString(t.CompletedAt.UTC().Format("2006-01-02 15:04"))))
			}
			sb.WriteString("</p>\n")

			// Tags
			if len(t.Tags) > 0 {
				sb.WriteString("<p style=\"margin:.3rem 0\">")
				for _, tg := range t.Tags {
					sb.WriteString(fmt.Sprintf("<span class=\"tag\">%s</span>", html.EscapeString(tg)))
				}
				sb.WriteString("</p>\n")
			}

			// Deps
			if len(t.DependsOn) > 0 {
				deps := make([]string, len(t.DependsOn))
				for i, d := range t.DependsOn {
					deps[i] = fmt.Sprintf("#%d", d)
				}
				sb.WriteString(fmt.Sprintf("<p class=\"dep\" style=\"margin:.3rem 0\"><span class=\"label\">Depends on</span>%s</p>\n",
					html.EscapeString(strings.Join(deps, ", "))))
			}

			// Description
			if t.Description != "" {
				sb.WriteString(fmt.Sprintf("<p style=\"margin:.75rem 0\">%s</p>\n", html.EscapeString(t.Description)))
			}

			// Failure diagnosis
			if t.FailureDiagnosis != "" {
				sb.WriteString(fmt.Sprintf("<p style=\"color:#f85149;margin:.5rem 0\"><span class=\"label\">Failure:</span>%s</p>\n",
					html.EscapeString(t.FailureDiagnosis)))
			}

			// Artifact output (collapsible)
			art := readArtifact(workDir, t)
			if art != "" {
				sb.WriteString("<details>\n<summary>Full artifact output</summary>\n")
				sb.WriteString(fmt.Sprintf("<pre><code>%s</code></pre>\n", html.EscapeString(art)))
				sb.WriteString("</details>\n")
			}

			// Annotations
			if len(t.Annotations) > 0 {
				sb.WriteString("<details style=\"margin-top:.5rem\">\n<summary>Annotations</summary>\n<div style=\"margin-top:.5rem\">")
				for _, a := range t.Annotations {
					sb.WriteString(fmt.Sprintf("<div class=\"annotation\"><span class=\"ann-time\">%s</span> <span class=\"ann-author\">%s</span>%s</div>\n",
						html.EscapeString(a.Timestamp.UTC().Format("2006-01-02 15:04")),
						html.EscapeString(a.Author),
						html.EscapeString(a.Text),
					))
				}
				sb.WriteString("</div></details>\n")
			}

			sb.WriteString("</div>\n")
		}
		sb.WriteString("\n")
	}

	// ---- Retrospective ----
	sb.WriteString("<h2>Retrospective</h2>\n")
	retro := retroSummary(s.Plan)
	sb.WriteString(fmt.Sprintf("<div class=\"retro\">%s</div>\n\n", html.EscapeString(retro)))

	sb.WriteString("</body>\n</html>\n")
	return sb.String(), nil
}
