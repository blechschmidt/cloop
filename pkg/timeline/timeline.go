// Package timeline builds and renders Gantt charts for cloop task plans.
package timeline

import (
	"fmt"
	"html"
	"math"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/blechschmidt/cloop/pkg/pm"
)

// Bar represents a single task's time slot on the Gantt chart.
type Bar struct {
	TaskID int
	Title  string
	Start  time.Time
	End    time.Time
	Status pm.TaskStatus
}

// Build computes the Gantt bars for a plan given an optional start time.
// Tasks are scheduled in topological order; each task starts after all its
// dependencies end and no earlier than planStart.
// Duration = ActualMinutes (if set) else EstimatedMinutes (if set) else 30 min.
func Build(plan *pm.Plan, planStart time.Time) []Bar {
	if plan == nil || len(plan.Tasks) == 0 {
		return nil
	}

	// Map task ID → end time (used for dependency scheduling).
	endOf := make(map[int]time.Time)

	// Topological sort via DFS so we can schedule in dependency order.
	visited := make(map[int]bool)
	var order []*pm.Task

	var visit func(t *pm.Task)
	visit = func(t *pm.Task) {
		if visited[t.ID] {
			return
		}
		visited[t.ID] = true
		for _, depID := range t.DependsOn {
			if dep := plan.TaskByID(depID); dep != nil {
				visit(dep)
			}
		}
		order = append(order, t)
	}
	for _, t := range plan.Tasks {
		visit(t)
	}

	bars := make([]Bar, 0, len(order))
	for _, t := range order {
		// Start after all dependencies end.
		start := planStart
		for _, depID := range t.DependsOn {
			if e, ok := endOf[depID]; ok && e.After(start) {
				start = e
			}
		}

		// If we have actual timing data, anchor to that.
		if t.StartedAt != nil && !t.StartedAt.IsZero() {
			if t.StartedAt.After(start) {
				start = *t.StartedAt
			}
		}

		// Determine duration.
		minutes := 30 // default
		if t.ActualMinutes > 0 {
			minutes = t.ActualMinutes
		} else if t.EstimatedMinutes > 0 {
			minutes = t.EstimatedMinutes
		}

		end := start.Add(time.Duration(minutes) * time.Minute)

		// If we have a real completion time, use it.
		if t.CompletedAt != nil && !t.CompletedAt.IsZero() && t.CompletedAt.After(start) {
			end = *t.CompletedAt
		}

		endOf[t.ID] = end
		bars = append(bars, Bar{
			TaskID: t.ID,
			Title:  t.Title,
			Start:  start,
			End:    end,
			Status: t.Status,
		})
	}
	return bars
}

// ─── ASCII rendering ──────────────────────────────────────────────────────────

const (
	titleWidth  = 28  // chars reserved for task title column
	colMinutes  = 30  // minutes per grid column
	gridWidth   = 50  // total number of time columns
	blockChar   = "█"
	emptyChar   = " "
	colorReset  = "\033[0m"
	colorGreen  = "\033[32m"
	colorYellow = "\033[33m"
	colorRed    = "\033[31m"
	colorGray   = "\033[37m"
	colorDark   = "\033[90m"
)

func statusColor(s pm.TaskStatus) string {
	switch s {
	case pm.TaskDone:
		return colorGreen
	case pm.TaskInProgress:
		return colorYellow
	case pm.TaskFailed, pm.TaskTimedOut:
		return colorRed
	case pm.TaskSkipped:
		return colorDark
	default:
		return colorGray
	}
}

func statusLabel(s pm.TaskStatus) string {
	switch s {
	case pm.TaskDone:
		return "done"
	case pm.TaskInProgress:
		return "running"
	case pm.TaskFailed:
		return "failed"
	case pm.TaskTimedOut:
		return "timeout"
	case pm.TaskSkipped:
		return "skipped"
	default:
		return "pending"
	}
}

// truncate shortens s to max runes, padding with spaces if shorter.
func truncate(s string, max int) string {
	runes := []rune(s)
	if len(runes) > max {
		return string(runes[:max-1]) + "…"
	}
	// pad to max
	return s + strings.Repeat(" ", max-utf8.RuneCountInString(s))
}

// RenderASCII renders a fixed-width Gantt chart to a string with ANSI color.
// useColor=false strips ANSI codes (for file output).
func RenderASCII(bars []Bar, useColor bool) string {
	if len(bars) == 0 {
		return "No tasks to display.\n"
	}

	// Find overall time range.
	earliest := bars[0].Start
	latest := bars[0].End
	for _, b := range bars {
		if b.Start.Before(earliest) {
			earliest = b.Start
		}
		if b.End.After(latest) {
			latest = b.End
		}
	}

	// Snap earliest to 30-min boundary.
	earliest = earliest.Truncate(time.Duration(colMinutes) * time.Minute)

	totalMinutes := int(math.Ceil(latest.Sub(earliest).Minutes()))
	cols := totalMinutes / colMinutes
	if cols < gridWidth {
		cols = gridWidth
	}
	// Cap at a reasonable width.
	if cols > 120 {
		cols = 120
	}

	color := func(c, s string) string {
		if !useColor {
			return s
		}
		return c + s + colorReset
	}

	var sb strings.Builder

	// Header: time labels every 2 hours (4 cols).
	sb.WriteString(strings.Repeat(" ", titleWidth+1))
	labelInterval := 4 // columns between labels (= 2 hours)
	for i := 0; i < cols; i++ {
		if i%labelInterval == 0 {
			t := earliest.Add(time.Duration(i*colMinutes) * time.Minute)
			label := t.Format("15:04")
			if i+len(label) < cols {
				sb.WriteString(label)
				i += len(label) - 1
			} else {
				sb.WriteString("|")
			}
		} else {
			sb.WriteString("-")
		}
	}
	sb.WriteString("\n")

	// Separator.
	sb.WriteString(strings.Repeat("-", titleWidth+1+cols))
	sb.WriteString("\n")

	// One row per task.
	for _, b := range bars {
		// Title column.
		title := fmt.Sprintf("[%d] %s", b.TaskID, b.Title)
		sb.WriteString(truncate(title, titleWidth))
		sb.WriteString(" ")

		startCol := int(b.Start.Sub(earliest).Minutes()) / colMinutes
		endCol := int(math.Ceil(b.End.Sub(earliest).Minutes())) / colMinutes
		if startCol < 0 {
			startCol = 0
		}
		if endCol > cols {
			endCol = cols
		}
		if endCol <= startCol {
			endCol = startCol + 1
		}

		// Pre-bar empty space.
		sb.WriteString(strings.Repeat(emptyChar, startCol))

		// Colored bar.
		barLen := endCol - startCol
		if barLen < 1 {
			barLen = 1
		}
		bar := strings.Repeat(blockChar, barLen)
		sb.WriteString(color(statusColor(b.Status), bar))

		// Post-bar empty space + status label.
		remaining := cols - endCol
		if remaining > 0 {
			sb.WriteString(strings.Repeat(emptyChar, remaining))
		}
		sb.WriteString(" ")
		sb.WriteString(color(statusColor(b.Status), statusLabel(b.Status)))
		sb.WriteString("\n")
	}

	// Legend.
	sb.WriteString("\n")
	sb.WriteString("Legend: ")
	sb.WriteString(color(colorGreen, blockChar+"done"))
	sb.WriteString("  ")
	sb.WriteString(color(colorYellow, blockChar+"running"))
	sb.WriteString("  ")
	sb.WriteString(color(colorGray, blockChar+"pending"))
	sb.WriteString("  ")
	sb.WriteString(color(colorRed, blockChar+"failed"))
	sb.WriteString("  ")
	sb.WriteString(color(colorDark, blockChar+"skipped"))
	sb.WriteString("\n")

	return sb.String()
}

// ─── HTML rendering ───────────────────────────────────────────────────────────

// RenderHTML generates a self-contained HTML file with an SVG Gantt chart and
// inline JavaScript for tooltip hover.
func RenderHTML(bars []Bar, title string) string {
	if len(bars) == 0 {
		return "<html><body><p>No tasks to display.</p></body></html>"
	}

	// Time range.
	earliest := bars[0].Start
	latest := bars[0].End
	for _, b := range bars {
		if b.Start.Before(earliest) {
			earliest = b.Start
		}
		if b.End.After(latest) {
			latest = b.End
		}
	}
	earliest = earliest.Truncate(time.Duration(colMinutes) * time.Minute)
	latest = latest.Add(time.Duration(colMinutes) * time.Minute).Truncate(time.Duration(colMinutes) * time.Minute)
	totalDuration := latest.Sub(earliest)
	if totalDuration < time.Hour {
		totalDuration = time.Hour
	}

	// SVG dimensions.
	const (
		svgPaddingLeft  = 220.0
		svgPaddingRight = 20.0
		svgPaddingTop   = 40.0
		rowHeight       = 36.0
		rowPad          = 6.0
		headerHeight    = 50.0
		tickInterval    = 30 * time.Minute
		svgBarHeight    = rowHeight - rowPad*2
	)

	svgWidth := svgPaddingLeft + 900.0 + svgPaddingRight
	svgHeight := headerHeight + float64(len(bars))*rowHeight + 20.0

	totalSecs := totalDuration.Seconds()
	pxPerSec := 900.0 / totalSecs

	xOf := func(t time.Time) float64 {
		return svgPaddingLeft + t.Sub(earliest).Seconds()*pxPerSec
	}

	barColor := func(s pm.TaskStatus) string {
		switch s {
		case pm.TaskDone:
			return "#22c55e"
		case pm.TaskInProgress:
			return "#eab308"
		case pm.TaskFailed, pm.TaskTimedOut:
			return "#ef4444"
		case pm.TaskSkipped:
			return "#6b7280"
		default:
			return "#9ca3af"
		}
	}

	var sb strings.Builder

	sb.WriteString(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>`)
	sb.WriteString(html.EscapeString(title))
	sb.WriteString(`</title>
<style>
  body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; background:#111827; color:#f9fafb; margin:0; padding:20px; }
  h1   { font-size:1.3rem; color:#f9fafb; margin-bottom:16px; }
  .chart-wrap { overflow-x:auto; }
  svg  { display:block; }
  .task-label { font-size:13px; fill:#d1d5db; }
  .tick-label { font-size:11px; fill:#6b7280; }
  .grid-line  { stroke:#374151; stroke-width:1; }
  .bar        { rx:4; ry:4; cursor:pointer; opacity:0.9; transition:opacity .15s; }
  .bar:hover  { opacity:1; }
  #tooltip {
    position:fixed; pointer-events:none; display:none;
    background:#1f2937; border:1px solid #374151; border-radius:6px;
    padding:10px 14px; font-size:13px; color:#f9fafb;
    box-shadow:0 4px 12px rgba(0,0,0,.5); max-width:300px; z-index:999;
  }
  #tooltip strong { display:block; margin-bottom:4px; color:#f9fafb; }
  #tooltip .meta  { color:#9ca3af; font-size:12px; }
  .legend { display:flex; gap:16px; margin-top:16px; flex-wrap:wrap; }
  .legend-item { display:flex; align-items:center; gap:6px; font-size:13px; color:#9ca3af; }
  .legend-dot  { width:12px; height:12px; border-radius:2px; flex-shrink:0; }
</style>
</head>
<body>
<h1>`)
	sb.WriteString(html.EscapeString(title))
	sb.WriteString("</h1>\n<div class=\"chart-wrap\">\n")

	// SVG.
	sb.WriteString(fmt.Sprintf(`<svg width="%.0f" height="%.0f" xmlns="http://www.w3.org/2000/svg">`, svgWidth, svgHeight))
	sb.WriteString("\n")

	// Background.
	sb.WriteString(fmt.Sprintf(`<rect width="%.0f" height="%.0f" fill="#111827"/>`, svgWidth, svgHeight))
	sb.WriteString("\n")

	// Grid tick marks and labels.
	for tick := earliest; !tick.After(latest); tick = tick.Add(tickInterval) {
		x := xOf(tick)
		// Vertical grid line.
		sb.WriteString(fmt.Sprintf(`<line x1="%.2f" y1="%.0f" x2="%.2f" y2="%.0f" class="grid-line"/>`,
			x, headerHeight, x, svgHeight-10))
		sb.WriteString("\n")
		// Time label.
		label := tick.Format("15:04")
		sb.WriteString(fmt.Sprintf(`<text x="%.2f" y="%.0f" class="tick-label" text-anchor="middle">%s</text>`,
			x, headerHeight-8, html.EscapeString(label)))
		sb.WriteString("\n")
	}

	// Date label at top-left of chart area.
	dateLabel := earliest.Format("2006-01-02")
	sb.WriteString(fmt.Sprintf(`<text x="%.0f" y="%.0f" font-size="12" fill="#6b7280">%s</text>`,
		svgPaddingLeft, 18.0, html.EscapeString(dateLabel)))
	sb.WriteString("\n")

	// Task rows.
	for i, b := range bars {
		y := headerHeight + float64(i)*rowHeight

		// Row background (alternating).
		rowFill := "#1a2234"
		if i%2 == 1 {
			rowFill = "#111827"
		}
		sb.WriteString(fmt.Sprintf(`<rect x="0" y="%.2f" width="%.0f" height="%.0f" fill="%s"/>`,
			y, svgWidth, rowHeight, rowFill))
		sb.WriteString("\n")

		// Task label.
		labelText := fmt.Sprintf("[%d] %s", b.TaskID, b.Title)
		if len([]rune(labelText)) > 28 {
			labelText = string([]rune(labelText)[:27]) + "…"
		}
		sb.WriteString(fmt.Sprintf(`<text x="%.0f" y="%.2f" class="task-label" text-anchor="end">%s</text>`,
			svgPaddingLeft-8, y+rowHeight/2+4, html.EscapeString(labelText)))
		sb.WriteString("\n")

		// Bar.
		bx := xOf(b.Start)
		bw := xOf(b.End) - bx
		if bw < 4 {
			bw = 4
		}
		by := y + rowPad
		color := barColor(b.Status)

		// Tooltip data attributes.
		dur := b.End.Sub(b.Start)
		durStr := fmt.Sprintf("%dh %02dm", int(dur.Hours()), int(dur.Minutes())%60)
		startStr := b.Start.Format("15:04")
		endStr := b.End.Format("15:04")
		tipTitle := html.EscapeString(fmt.Sprintf("[%d] %s", b.TaskID, b.Title))
		tipMeta := html.EscapeString(fmt.Sprintf("%s → %s (%s) | %s", startStr, endStr, durStr, statusLabel(b.Status)))

		sb.WriteString(fmt.Sprintf(
			`<rect class="bar" x="%.2f" y="%.2f" width="%.2f" height="%.0f" fill="%s" data-title="%s" data-meta="%s"/>`,
			bx, by, bw, svgBarHeight, color, tipTitle, tipMeta))
		sb.WriteString("\n")
	}

	sb.WriteString("</svg>\n</div>\n")

	// Legend.
	sb.WriteString(`<div class="legend">`)
	legendItems := []struct{ color, label string }{
		{"#22c55e", "Done"},
		{"#eab308", "In Progress"},
		{"#9ca3af", "Pending"},
		{"#ef4444", "Failed"},
		{"#6b7280", "Skipped"},
	}
	for _, li := range legendItems {
		sb.WriteString(fmt.Sprintf(
			`<div class="legend-item"><div class="legend-dot" style="background:%s"></div>%s</div>`,
			li.color, li.label))
	}
	sb.WriteString("</div>\n")

	// Tooltip div + JS.
	sb.WriteString(`<div id="tooltip"></div>
<script>
(function(){
  var tip = document.getElementById('tooltip');
  document.querySelectorAll('.bar').forEach(function(bar){
    bar.addEventListener('mouseenter', function(e){
      tip.innerHTML = '<strong>' + bar.dataset.title + '</strong><span class="meta">' + bar.dataset.meta + '</span>';
      tip.style.display = 'block';
    });
    bar.addEventListener('mousemove', function(e){
      var x = e.clientX + 14, y = e.clientY - 10;
      var tw = tip.offsetWidth, ww = window.innerWidth;
      if (x + tw > ww) x = e.clientX - tw - 14;
      tip.style.left = x + 'px';
      tip.style.top  = y + 'px';
    });
    bar.addEventListener('mouseleave', function(){
      tip.style.display = 'none';
    });
  });
})();
</script>
</body>
</html>
`)

	return sb.String()
}
