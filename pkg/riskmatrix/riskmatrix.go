// Package riskmatrix combines impact scoring (pkg/impact) and risk assessment
// (pkg/risk) to produce a 2D quadrant visualization of all pending tasks.
// Tasks are placed in one of four quadrants based on their risk level (Y axis,
// 1-10) and strategic impact (X axis, 1-10):
//
//	Critical  — high risk + high impact  (risk≥6, impact≥6)
//	Mitigate  — high risk + low impact   (risk≥6, impact<6)
//	Leverage  — low risk  + high impact  (risk<6,  impact≥6)
//	Defer     — low risk  + low impact   (risk<6,  impact<6)
package riskmatrix

import (
	"context"
	"fmt"
	"html/template"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/impact"
	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/provider"
	"github.com/blechschmidt/cloop/pkg/risk"
)

// Quadrant names.
const (
	QuadrantCritical = "Critical"  // high risk, high impact
	QuadrantMitigate = "Mitigate"  // high risk, low impact
	QuadrantLeverage = "Leverage"  // low risk,  high impact
	QuadrantDefer    = "Defer"     // low risk,  low impact
)

// quadrantThreshold is the mid-point split (scores ≥ this = "high").
const quadrantThreshold = 6

// MatrixEntry is a single task's position on the 2D risk/impact matrix.
type MatrixEntry struct {
	TaskID      int    `json:"task_id"`
	TaskTitle   string `json:"task_title"`
	RiskScore   int    `json:"risk_score"`   // 1-10 (1=low risk, 10=critical)
	ImpactScore int    `json:"impact_score"` // 1-10 (1=low impact, 10=high impact)
	Quadrant    string `json:"quadrant"`     // Critical/Mitigate/Leverage/Defer
}

// classifyQuadrant returns the quadrant name for the given scores.
func classifyQuadrant(riskScore, impactScore int) string {
	highRisk := riskScore >= quadrantThreshold
	highImpact := impactScore >= quadrantThreshold
	switch {
	case highRisk && highImpact:
		return QuadrantCritical
	case highRisk && !highImpact:
		return QuadrantMitigate
	case !highRisk && highImpact:
		return QuadrantLeverage
	default:
		return QuadrantDefer
	}
}

// riskLevelToScore converts a risk.Level to a numeric 1-10 score.
func riskLevelToScore(level risk.Level) int {
	switch level {
	case risk.LevelLow:
		return 2
	case risk.LevelMedium:
		return 5
	case risk.LevelHigh:
		return 7
	case risk.LevelCritical:
		return 9
	default:
		return 2
	}
}

// Build scores all pending/in-progress tasks using the AI provider and returns
// a slice of MatrixEntry. If a task already has both RiskScore and ImpactScore
// cached (non-zero), those cached values are used without calling the AI.
// When apply is true, the computed scores are written back to each task in the
// plan (caller is responsible for saving state).
func Build(ctx context.Context, prov provider.Provider, opts provider.Options, plan *pm.Plan, apply bool) ([]MatrixEntry, error) {
	if plan == nil || len(plan.Tasks) == 0 {
		return nil, nil
	}

	// Collect active tasks.
	var active []*pm.Task
	for _, t := range plan.Tasks {
		if t.Status == pm.TaskPending || t.Status == pm.TaskInProgress {
			active = append(active, t)
		}
	}
	if len(active) == 0 {
		return nil, nil
	}

	// Separate tasks with cached scores from those needing AI scoring.
	var needScoring []*pm.Task
	cached := make(map[int][2]int) // taskID → [riskScore, impactScore]
	for _, t := range active {
		if t.RiskScore > 0 && t.ImpactScore > 0 {
			cached[t.ID] = [2]int{t.RiskScore, t.ImpactScore}
		} else {
			needScoring = append(needScoring, t)
		}
	}

	// For tasks that need AI scoring: run impact and risk in parallel by
	// first getting impact scores (1 call for all tasks), then risk per task.
	impactByID := make(map[int]int)
	riskByID := make(map[int]int)

	if len(needScoring) > 0 {
		// Impact scoring: one AI call for all tasks.
		impactScores, err := impact.Score(ctx, prov, opts, plan)
		if err != nil {
			return nil, fmt.Errorf("impact scoring: %w", err)
		}
		for _, s := range impactScores {
			impactByID[s.TaskID] = s.ImpactScore
		}

		// Risk assessment: one AI call per task (as the risk package requires).
		for _, t := range needScoring {
			report, err := risk.AssessTask(ctx, prov, opts.Model, plan, t)
			if err != nil {
				return nil, fmt.Errorf("risk assessment for task #%d: %w", t.ID, err)
			}
			riskByID[t.ID] = riskLevelToScore(report.OverallLevel)
		}
	}

	// Build entries.
	entries := make([]MatrixEntry, 0, len(active))
	for _, t := range active {
		var rs, is int
		if c, ok := cached[t.ID]; ok {
			rs = c[0]
			is = c[1]
		} else {
			rs = riskByID[t.ID]
			is = impactByID[t.ID]
			if rs == 0 {
				rs = 2 // default to low risk if AI didn't score it
			}
			if is == 0 {
				is = 3 // default to low impact if AI didn't score it
			}
		}
		// Clamp to 1-10.
		if rs < 1 {
			rs = 1
		}
		if rs > 10 {
			rs = 10
		}
		if is < 1 {
			is = 1
		}
		if is > 10 {
			is = 10
		}

		if apply {
			t.RiskScore = rs
			t.ImpactScore = is
		}

		entries = append(entries, MatrixEntry{
			TaskID:      t.ID,
			TaskTitle:   t.Title,
			RiskScore:   rs,
			ImpactScore: is,
			Quadrant:    classifyQuadrant(rs, is),
		})
	}

	return entries, nil
}

// BuildFromCache returns matrix entries for all active tasks using only cached
// scores. Tasks without cached scores are included with score 0. This is used
// by the API endpoint to avoid blocking on AI calls.
func BuildFromCache(plan *pm.Plan) []MatrixEntry {
	if plan == nil {
		return nil
	}
	var entries []MatrixEntry
	for _, t := range plan.Tasks {
		if t.Status != pm.TaskPending && t.Status != pm.TaskInProgress {
			continue
		}
		rs := t.RiskScore
		is := t.ImpactScore
		q := ""
		if rs > 0 && is > 0 {
			q = classifyQuadrant(rs, is)
		}
		entries = append(entries, MatrixEntry{
			TaskID:      t.ID,
			TaskTitle:   t.Title,
			RiskScore:   rs,
			ImpactScore: is,
			Quadrant:    q,
		})
	}
	return entries
}

// RenderASCII renders a 2D ASCII quadrant chart. The chart is 40 columns wide
// and 20 rows tall. Each task is plotted as "#<id>" at the (impact, risk)
// coordinate, with quadrant labels in the background.
func RenderASCII(entries []MatrixEntry) string {
	const (
		gridW = 40 // columns for the plotting area
		gridH = 20 // rows for the plotting area
	)

	// grid uses rune slices to support box-drawing characters.
	grid := make([][]rune, gridH)
	for r := range grid {
		grid[r] = make([]rune, gridW)
		for c := range grid[r] {
			grid[r][c] = ' '
		}
	}

	// Place subtle quadrant labels.
	placeStr(grid, 1, 1, "MITIGATE")
	placeStr(grid, 1, gridW/2+1, "CRITICAL")
	placeStr(grid, gridH/2+1, 1, "DEFER")
	placeStr(grid, gridH/2+1, gridW/2+1, "LEVERAGE")

	// Collision tracker: cells that are already used by a task label.
	type point struct{ r, c int }
	used := make(map[point]bool)

	// Plot tasks. Impact score 1-10 maps to col 0-39, risk 1-10 maps to row
	// 19 (bottom) to 0 (top).
	for _, e := range entries {
		if e.RiskScore == 0 || e.ImpactScore == 0 {
			continue // not yet scored
		}
		col := int(float64(e.ImpactScore-1) / 9.0 * float64(gridW-1))
		row := gridH - 1 - int(float64(e.RiskScore-1)/9.0*float64(gridH-1))

		label := []rune(fmt.Sprintf("#%d", e.TaskID))
		// Avoid overflow on the right.
		if col+len(label) > gridW {
			col = gridW - len(label)
		}
		// Shift down if collision.
		for {
			p := point{row, col}
			if !used[p] {
				break
			}
			row++
			if row >= gridH {
				row = gridH - 1
				break
			}
		}
		used[point{row, col}] = true
		placeRuneStr(grid, row, col, label)
	}

	// Separator col/row at the quadrant threshold boundary.
	// threshold=6 → index 5 → col = 5/9*39 = 21.67 → 21
	thresh := float64(quadrantThreshold - 1)
	gw := float64(gridW - 1)
	gh := float64(gridH - 1)
	sepCol := int(thresh / 9.0 * gw)
	sepRow := gridH - 1 - int(thresh/9.0*gh)

	// Draw separator lines.
	for r := 0; r < gridH; r++ {
		if grid[r][sepCol] == ' ' {
			grid[r][sepCol] = '│'
		}
	}
	for c := 0; c < gridW; c++ {
		if grid[sepRow][c] == ' ' || grid[sepRow][c] == '│' {
			if c == sepCol {
				grid[sepRow][c] = '┼'
			} else {
				grid[sepRow][c] = '─'
			}
		}
	}

	var sb strings.Builder

	// Top border.
	sb.WriteString("Risk\n")
	sb.WriteString("10 ┌")
	sb.WriteString(strings.Repeat("─", gridW))
	sb.WriteString("┐\n")

	// Grid rows.
	for r := 0; r < gridH; r++ {
		// Y axis label at r=0 (risk=10), r=sepRow (risk≈6), r=gridH-1 (risk=1).
		riskVal := 10 - int(float64(r)/float64(gridH-1)*9.0)
		if r == 0 || r == sepRow || r == gridH-1 {
			sb.WriteString(fmt.Sprintf("%2d │", riskVal))
		} else {
			sb.WriteString("   │")
		}
		sb.WriteString(string(grid[r]))
		sb.WriteString("│\n")
	}

	// Bottom border.
	sb.WriteString(" 1 └")
	sb.WriteString(strings.Repeat("─", gridW))
	sb.WriteString("┘\n")

	// X axis.
	sb.WriteString("     1")
	padLeft := sepCol - 1
	sb.WriteString(strings.Repeat(" ", padLeft))
	sb.WriteString(fmt.Sprintf("%-2d", quadrantThreshold))
	padRight := gridW - sepCol - 3
	if padRight < 0 {
		padRight = 0
	}
	sb.WriteString(strings.Repeat(" ", padRight))
	sb.WriteString("10\n")
	sb.WriteString("     Impact →\n\n")

	// Legend.
	sb.WriteString("Quadrants:\n")
	sb.WriteString(fmt.Sprintf("  %-10s risk≥%d + impact≥%d — address immediately\n",
		QuadrantCritical, quadrantThreshold, quadrantThreshold))
	sb.WriteString(fmt.Sprintf("  %-10s risk≥%d + impact<%d — high risk, low payoff; mitigate or descope\n",
		QuadrantMitigate, quadrantThreshold, quadrantThreshold))
	sb.WriteString(fmt.Sprintf("  %-10s risk<%d + impact≥%d — low risk, high value; pursue aggressively\n",
		QuadrantLeverage, quadrantThreshold, quadrantThreshold))
	sb.WriteString(fmt.Sprintf("  %-10s risk<%d + impact<%d — low priority; defer or skip\n",
		QuadrantDefer, quadrantThreshold, quadrantThreshold))

	// Task list.
	if len(entries) > 0 {
		sb.WriteString("\nTasks:\n")
		for _, e := range entries {
			if e.RiskScore == 0 {
				sb.WriteString(fmt.Sprintf("  #%-3d  %-10s  [no score — run without --cached]\n",
					e.TaskID, e.Quadrant))
				continue
			}
			title := e.TaskTitle
			if len([]rune(title)) > 50 {
				title = string([]rune(title)[:47]) + "..."
			}
			sb.WriteString(fmt.Sprintf("  #%-3d  risk=%2d  impact=%2d  %-10s  %s\n",
				e.TaskID, e.RiskScore, e.ImpactScore, e.Quadrant, title))
		}
	}

	return sb.String()
}

// placeStr writes s into the rune grid starting at (row, col), clamping at the
// right edge.
func placeStr(grid [][]rune, row, col int, s string) {
	placeRuneStr(grid, row, col, []rune(s))
}

// placeRuneStr writes a rune slice into the grid starting at (row, col).
func placeRuneStr(grid [][]rune, row, col int, rs []rune) {
	if row < 0 || row >= len(grid) {
		return
	}
	for i, r := range rs {
		c := col + i
		if c >= len(grid[row]) {
			break
		}
		grid[row][c] = r
	}
}

// htmlTemplate is the standalone HTML canvas chart template.
const htmlTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Risk Matrix — {{.Goal}}</title>
<style>
  body { font-family: system-ui, sans-serif; background: #0f1117; color: #e2e8f0; margin: 0; padding: 20px; }
  h1 { font-size: 18px; margin-bottom: 4px; color: #f1f5f9; }
  p  { font-size: 12px; color: #94a3b8; margin-bottom: 16px; }
  canvas { border-radius: 8px; display: block; }
  .legend { display: flex; gap: 16px; margin-top: 14px; flex-wrap: wrap; }
  .litem  { display: flex; align-items: center; gap: 6px; font-size: 12px; color: #94a3b8; }
  .lbox   { width: 14px; height: 14px; border-radius: 3px; }
  table   { border-collapse: collapse; margin-top: 18px; font-size: 12px; width: 100%; max-width: 700px; }
  th      { text-align: left; padding: 6px 10px; background: #1e293b; color: #94a3b8; font-weight: 500; }
  td      { padding: 5px 10px; border-bottom: 1px solid #1e293b; }
  .q-critical { color: #ef4444; }
  .q-mitigate { color: #f97316; }
  .q-leverage { color: #22c55e; }
  .q-defer    { color: #6b7280; }
</style>
</head>
<body>
<h1>Risk Matrix</h1>
<p>Goal: {{.Goal}}</p>
<canvas id="c" width="640" height="480"></canvas>
<div class="legend">
  <div class="litem"><div class="lbox" style="background:#ef444455;border:1px solid #ef4444"></div>Critical (high risk + high impact)</div>
  <div class="litem"><div class="lbox" style="background:#f9731655;border:1px solid #f97316"></div>Mitigate (high risk + low impact)</div>
  <div class="litem"><div class="lbox" style="background:#22c55e55;border:1px solid #22c55e"></div>Leverage (low risk + high impact)</div>
  <div class="litem"><div class="lbox" style="background:#6b728055;border:1px solid #6b7280"></div>Defer (low risk + low impact)</div>
</div>
<table>
  <thead><tr><th>#</th><th>Task</th><th>Risk</th><th>Impact</th><th>Quadrant</th></tr></thead>
  <tbody>
  {{range .Entries}}
  <tr>
    <td>#{{.TaskID}}</td>
    <td>{{.TaskTitle}}</td>
    <td>{{.RiskScore}}/10</td>
    <td>{{.ImpactScore}}/10</td>
    <td class="q-{{lower .Quadrant}}">{{.Quadrant}}</td>
  </tr>
  {{end}}
  </tbody>
</table>
<script>
const entries = {{.EntriesJSON}};
const canvas  = document.getElementById('c');
const ctx     = canvas.getContext('2d');
const W = canvas.width, H = canvas.height;
const PAD = { top: 30, right: 20, bottom: 50, left: 50 };
const pw = W - PAD.left - PAD.right;
const ph = H - PAD.top  - PAD.bottom;

// Quadrant backgrounds
const MID_X = PAD.left + pw * 5 / 10;
const MID_Y = PAD.top  + ph * 5 / 10;

function drawQuadrants() {
  const regions = [
    { x: PAD.left,  y: PAD.top,  w: MID_X - PAD.left, h: MID_Y - PAD.top,  color: 'rgba(249,115,22,0.12)', label: 'MITIGATE', lx: PAD.left + 6,  ly: PAD.top  + 16 },
    { x: MID_X,     y: PAD.top,  w: PAD.left+pw-MID_X, h: MID_Y-PAD.top,   color: 'rgba(239,68,68,0.15)',  label: 'CRITICAL', lx: MID_X + 6,     ly: PAD.top  + 16 },
    { x: PAD.left,  y: MID_Y,    w: MID_X - PAD.left, h: PAD.top+ph-MID_Y, color: 'rgba(107,114,128,0.1)', label: 'DEFER',    lx: PAD.left + 6,  ly: MID_Y + 16 },
    { x: MID_X,     y: MID_Y,    w: PAD.left+pw-MID_X, h: PAD.top+ph-MID_Y,color: 'rgba(34,197,94,0.12)',  label: 'LEVERAGE', lx: MID_X + 6,     ly: MID_Y + 16 },
  ];
  for (const r of regions) {
    ctx.fillStyle = r.color;
    ctx.fillRect(r.x, r.y, r.w, r.h);
    ctx.fillStyle = 'rgba(255,255,255,0.18)';
    ctx.font = 'bold 11px system-ui';
    ctx.fillText(r.label, r.lx, r.ly);
  }
}

function drawAxes() {
  ctx.strokeStyle = '#334155';
  ctx.lineWidth = 1;
  // Border
  ctx.strokeRect(PAD.left, PAD.top, pw, ph);
  // Separator lines
  ctx.setLineDash([4,4]);
  ctx.beginPath(); ctx.moveTo(MID_X, PAD.top); ctx.lineTo(MID_X, PAD.top + ph); ctx.stroke();
  ctx.beginPath(); ctx.moveTo(PAD.left, MID_Y); ctx.lineTo(PAD.left + pw, MID_Y); ctx.stroke();
  ctx.setLineDash([]);
  // Labels
  ctx.fillStyle = '#64748b';
  ctx.font = '11px system-ui';
  // X axis ticks
  for (let v = 1; v <= 10; v++) {
    const x = PAD.left + (v-1)/9 * pw;
    ctx.fillText(v, x - 3, PAD.top + ph + 16);
  }
  // Y axis ticks
  for (let v = 1; v <= 10; v++) {
    const y = PAD.top + ph - (v-1)/9 * ph;
    ctx.fillText(v, PAD.left - 20, y + 4);
  }
  // Axis titles
  ctx.fillStyle = '#94a3b8';
  ctx.font = '12px system-ui';
  ctx.fillText('Impact →', PAD.left + pw/2 - 25, H - 8);
  ctx.save();
  ctx.translate(14, PAD.top + ph/2 + 30);
  ctx.rotate(-Math.PI/2);
  ctx.fillText('Risk →', 0, 0);
  ctx.restore();
}

function drawPoints() {
  const colors = { Critical:'#ef4444', Mitigate:'#f97316', Leverage:'#22c55e', Defer:'#9ca3af' };
  const placed = [];
  for (const e of entries) {
    if (!e.risk_score || !e.impact_score) continue;
    let x = PAD.left + (e.impact_score - 1)/9 * pw;
    let y = PAD.top  + ph - (e.risk_score  - 1)/9 * ph;
    // Slight jitter to avoid perfect overlaps
    for (const p of placed) {
      if (Math.abs(p.x - x) < 18 && Math.abs(p.y - y) < 14) { x += 14; y += 6; }
    }
    placed.push({x, y});
    const col = colors[e.quadrant] || '#94a3b8';
    // Dot
    ctx.fillStyle = col;
    ctx.beginPath();
    ctx.arc(x, y, 5, 0, 2 * Math.PI);
    ctx.fill();
    // Label
    ctx.fillStyle = col;
    ctx.font = 'bold 10px system-ui';
    ctx.fillText('#' + e.task_id, x + 7, y + 4);
  }
}

drawQuadrants();
drawAxes();
drawPoints();
</script>
</body>
</html>`

// htmlData is the data passed to the HTML template.
type htmlData struct {
	Goal        string
	Entries     []MatrixEntry
	EntriesJSON template.JS
}

// RenderHTML returns a standalone HTML page with a canvas-based scatter plot.
func RenderHTML(entries []MatrixEntry, goal string) (string, error) {
	// Build JSON array for the JavaScript.
	var jsEntries strings.Builder
	jsEntries.WriteString("[")
	for i, e := range entries {
		if i > 0 {
			jsEntries.WriteString(",")
		}
		title := strings.ReplaceAll(e.TaskTitle, `"`, `\"`)
		jsEntries.WriteString(fmt.Sprintf(
			`{"task_id":%d,"task_title":"%s","risk_score":%d,"impact_score":%d,"quadrant":"%s"}`,
			e.TaskID, title, e.RiskScore, e.ImpactScore, e.Quadrant,
		))
	}
	jsEntries.WriteString("]")

	// Template functions.
	funcMap := template.FuncMap{
		"lower": strings.ToLower,
	}
	tmpl, err := template.New("rm").Funcs(funcMap).Parse(htmlTemplate)
	if err != nil {
		return "", fmt.Errorf("template parse: %w", err)
	}

	data := htmlData{
		Goal:        goal,
		Entries:     entries,
		EntriesJSON: template.JS(jsEntries.String()),
	}

	var buf strings.Builder
	if err := tmpl.Execute(&buf, data); err != nil {
		return "", fmt.Errorf("template execute: %w", err)
	}
	return buf.String(), nil
}

// DefaultTimeout is the timeout used when building a risk matrix.
const DefaultTimeout = 5 * time.Minute
