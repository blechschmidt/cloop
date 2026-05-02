// Package forecast provides AI-powered project completion forecasting for cloop.
// It computes velocity-based completion dates with confidence intervals,
// renders an ASCII burn-down chart, and streams an AI narrative forecast.
package forecast

import (
	"context"
	"fmt"
	"math"
	"sort"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/provider"
	"github.com/blechschmidt/cloop/pkg/state"
)

// Scenario represents one completion estimate (optimistic / expected / pessimistic).
type Scenario struct {
	Label          string
	VelocityFactor float64  // multiplier applied to baseline velocity
	DaysRemaining  float64  // -1 = cannot compute
	CompletionDate time.Time
	Confidence     string // "high" | "medium" | "low"
}

// BurnPoint is one data point for the burn-down chart.
type BurnPoint struct {
	Date      time.Time
	Remaining int
}

// TaskWindow holds per-task schedule projection for the Gantt table.
type TaskWindow struct {
	TaskID           int       `json:"task_id"`
	Title            string    `json:"title"`
	Status           string    `json:"status"`
	Priority         int       `json:"priority"`
	EstimatedMinutes int       `json:"estimated_minutes"`
	AdjustedMinutes  int       `json:"adjusted_minutes"` // estimated * VelocityRatio
	ProjectedStart   time.Time `json:"projected_start"`
	ProjectedEnd     time.Time `json:"projected_end"`
}

// Forecast holds the full forecasting output.
type Forecast struct {
	Goal        string
	GeneratedAt time.Time

	// Task counts
	TotalTasks      int
	DoneTasks       int
	SkippedTasks    int
	FailedTasks     int
	PendingTasks    int
	BlockedTasks    int
	InProgressTasks int

	// Velocity metrics (time-based: tasks/day)
	BaseVelocityPerDay float64 // tasks/day (baseline)
	AvgTaskDuration    time.Duration
	ProjectStartDate   time.Time

	// Velocity metrics (minute-based: actual vs estimated)
	VelocityRatio        float64 // sum(actual_minutes)/sum(estimated_minutes); 1.0 if no data
	AvgEstimatedMinutes  float64 // average EstimatedMinutes across all tasks with estimates
	MinuteDataPoints     int     // number of tasks with both estimated and actual minutes

	// Scenarios
	Optimistic  Scenario
	Expected    Scenario
	Pessimistic Scenario

	// Historical burn-down data (one point per completed task, chronological)
	BurnPoints []BurnPoint

	// Per-task schedule projections for remaining work
	TaskWindows []TaskWindow

	// AI-generated narrative
	AIText string
}

// Build computes a Forecast from the current project state. No AI call is made here.
func Build(s *state.ProjectState) *Forecast {
	f := &Forecast{
		Goal:             s.Goal,
		GeneratedAt:      time.Now(),
		ProjectStartDate: s.CreatedAt,
		VelocityRatio:    1.0,
	}

	if s.Plan == nil {
		return f
	}

	// Count statuses and collect completion timestamps.
	var completedTimes []time.Time
	var durations []time.Duration
	var sumEstimated, sumActual float64
	var estValues []float64

	for _, t := range s.Plan.Tasks {
		f.TotalTasks++
		if t.EstimatedMinutes > 0 {
			estValues = append(estValues, float64(t.EstimatedMinutes))
		}
		switch t.Status {
		case pm.TaskDone:
			f.DoneTasks++
			if t.CompletedAt != nil {
				completedTimes = append(completedTimes, *t.CompletedAt)
			}
			if t.StartedAt != nil && t.CompletedAt != nil {
				durations = append(durations, t.CompletedAt.Sub(*t.StartedAt))
			}
			// Accumulate minute-based velocity data.
			if t.EstimatedMinutes > 0 && t.ActualMinutes > 0 {
				sumEstimated += float64(t.EstimatedMinutes)
				sumActual += float64(t.ActualMinutes)
				f.MinuteDataPoints++
			}
		case pm.TaskFailed:
			f.FailedTasks++
		case pm.TaskSkipped:
			f.SkippedTasks++
		case pm.TaskInProgress:
			f.InProgressTasks++
		case pm.TaskPending:
			f.PendingTasks++
			if s.Plan.PermanentlyBlocked(t) {
				f.BlockedTasks++
			}
		}
	}

	// Compute VelocityRatio (actual/estimated). 1.0 means estimates were perfect.
	// > 1.0 means tasks took longer than estimated (pessimistic signal).
	// < 1.0 means tasks were faster than estimated (optimistic signal).
	if f.MinuteDataPoints > 0 && sumEstimated > 0 {
		f.VelocityRatio = sumActual / sumEstimated
	}

	// Average estimated minutes across all tasks that have estimates.
	if len(estValues) > 0 {
		var total float64
		for _, v := range estValues {
			total += v
		}
		f.AvgEstimatedMinutes = total / float64(len(estValues))
	}

	// Average task duration from StartedAt/CompletedAt.
	if len(durations) > 0 {
		var total time.Duration
		for _, d := range durations {
			total += d
		}
		f.AvgTaskDuration = total / time.Duration(len(durations))
	}

	// Base velocity: tasks/day over the span of completed tasks.
	sort.Slice(completedTimes, func(i, j int) bool { return completedTimes[i].Before(completedTimes[j]) })
	if len(completedTimes) >= 2 {
		span := completedTimes[len(completedTimes)-1].Sub(completedTimes[0])
		days := span.Hours() / 24
		if days > 0 {
			f.BaseVelocityPerDay = float64(len(completedTimes)) / days
		}
	} else if len(completedTimes) == 1 {
		elapsed := time.Since(s.CreatedAt).Hours() / 24
		if elapsed > 0 {
			f.BaseVelocityPerDay = 1.0 / elapsed
		} else {
			f.BaseVelocityPerDay = 1.0
		}
	}

	// Build burn-down history.
	if len(completedTimes) > 0 {
		remaining := f.TotalTasks
		for _, t := range completedTimes {
			remaining--
			f.BurnPoints = append(f.BurnPoints, BurnPoint{Date: t, Remaining: remaining})
		}
	}

	// Build scenarios.
	executableRemaining := f.PendingTasks - f.BlockedTasks + f.InProgressTasks
	if executableRemaining < 0 {
		executableRemaining = 0
	}

	buildScenario := func(label string, factor float64, confidence string) Scenario {
		sc := Scenario{
			Label:          label,
			VelocityFactor: factor,
			Confidence:     confidence,
			DaysRemaining:  -1,
		}
		vel := f.BaseVelocityPerDay * factor
		if vel > 0 && executableRemaining > 0 {
			sc.DaysRemaining = float64(executableRemaining) / vel
			sc.CompletionDate = time.Now().Add(time.Duration(sc.DaysRemaining*24) * time.Hour)
		} else if executableRemaining == 0 {
			sc.DaysRemaining = 0
			sc.CompletionDate = time.Now()
		}
		return sc
	}

	var optConf, expConf, pessConf string
	switch {
	case len(completedTimes) >= 5:
		optConf, expConf, pessConf = "medium", "high", "medium"
	case len(completedTimes) >= 2:
		optConf, expConf, pessConf = "low", "medium", "low"
	default:
		optConf, expConf, pessConf = "low", "low", "low"
	}

	f.Optimistic = buildScenario("Optimistic", 2.0, optConf)
	f.Expected = buildScenario("Expected", 1.0, expConf)
	f.Pessimistic = buildScenario("Pessimistic", 0.5, pessConf)

	// Build per-task windows (sequential schedule for pending/in_progress tasks).
	f.TaskWindows = buildTaskWindows(s.Plan, f)

	return f
}

// buildTaskWindows computes projected start/end times for remaining tasks.
// Tasks are ordered by priority. The velocity ratio adjusts estimated durations.
func buildTaskWindows(plan *pm.Plan, f *Forecast) []TaskWindow {
	if plan == nil {
		return nil
	}

	// Collect pending and in_progress tasks, sort by priority ascending (lower = higher priority).
	var tasks []*pm.Task
	for _, t := range plan.Tasks {
		if t.Status == pm.TaskPending || t.Status == pm.TaskInProgress {
			tasks = append(tasks, t)
		}
	}
	sort.Slice(tasks, func(i, j int) bool {
		return tasks[i].Priority < tasks[j].Priority
	})

	now := time.Now()
	cursor := now
	var windows []TaskWindow

	// Fallback duration when no estimate is available: use AvgEstimatedMinutes, else 60m.
	fallbackMins := f.AvgEstimatedMinutes
	if fallbackMins <= 0 {
		fallbackMins = 60
	}

	for _, t := range tasks {
		est := float64(t.EstimatedMinutes)
		if est <= 0 {
			est = fallbackMins
		}
		// Adjust by velocity ratio (>1 = tasks take longer than estimated).
		adjusted := est * f.VelocityRatio
		if adjusted < 1 {
			adjusted = 1
		}

		// For in_progress tasks with a StartedAt, start from now and reduce remaining.
		start := cursor
		if t.Status == pm.TaskInProgress && t.StartedAt != nil {
			// Already started; project end based on remaining adjusted time.
			elapsed := time.Since(*t.StartedAt).Minutes()
			remaining := adjusted - elapsed
			if remaining < 1 {
				remaining = 1
			}
			start = now
			adjusted = remaining
		}

		end := start.Add(time.Duration(adjusted) * time.Minute)

		windows = append(windows, TaskWindow{
			TaskID:           t.ID,
			Title:            t.Title,
			Status:           string(t.Status),
			Priority:         t.Priority,
			EstimatedMinutes: t.EstimatedMinutes,
			AdjustedMinutes:  int(math.Round(adjusted)),
			ProjectedStart:   start,
			ProjectedEnd:     end,
		})

		cursor = end
	}

	return windows
}

// CompletionPct returns percent of tasks finished (done + skipped).
func (f *Forecast) CompletionPct() int {
	if f.TotalTasks == 0 {
		return 0
	}
	return (f.DoneTasks + f.SkippedTasks) * 100 / f.TotalTasks
}

// GanttTable renders the per-task schedule projection as an ASCII table.
func (f *Forecast) GanttTable() string {
	if len(f.TaskWindows) == 0 {
		return ""
	}

	const (
		colID    = 4
		colTitle = 32
		colEst   = 7
		colAdj   = 7
		colStart = 16
		colEnd   = 16
		colBar   = 20
	)

	// Find the total span for the bar chart.
	minStart := f.TaskWindows[0].ProjectedStart
	maxEnd := f.TaskWindows[len(f.TaskWindows)-1].ProjectedEnd
	totalSpan := maxEnd.Sub(minStart)
	if totalSpan <= 0 {
		totalSpan = time.Minute
	}

	header := fmt.Sprintf("%-*s  %-*s  %-*s  %-*s  %-*s  %-*s  %s",
		colID, "#",
		colTitle, "Title",
		colEst, "Est",
		colAdj, "Adj",
		colStart, "Projected Start",
		colEnd, "Projected End",
		"Timeline",
	)
	sep := strings.Repeat("─", len(header)+2)

	var sb strings.Builder
	sb.WriteString(header)
	sb.WriteByte('\n')
	sb.WriteString(sep)
	sb.WriteByte('\n')

	for _, w := range f.TaskWindows {
		idStr := fmt.Sprintf("#%-*d", colID-1, w.TaskID)
		title := w.Title
		if len(title) > colTitle {
			title = title[:colTitle-1] + "…"
		}

		estStr := formatMins(w.EstimatedMinutes)
		adjStr := formatMins(w.AdjustedMinutes)

		startStr := w.ProjectedStart.Format("Jan 02 15:04")
		endStr := w.ProjectedEnd.Format("Jan 02 15:04")

		// Bar: position within timeline.
		barStart := int(w.ProjectedStart.Sub(minStart).Seconds() * float64(colBar) / totalSpan.Seconds())
		barLen := int(w.ProjectedEnd.Sub(w.ProjectedStart).Seconds() * float64(colBar) / totalSpan.Seconds())
		if barLen < 1 {
			barLen = 1
		}
		if barStart < 0 {
			barStart = 0
		}
		if barStart+barLen > colBar {
			barLen = colBar - barStart
		}
		bar := strings.Repeat(" ", barStart) + strings.Repeat("█", barLen) + strings.Repeat(" ", colBar-barStart-barLen)

		statusMark := " "
		if w.Status == string(pm.TaskInProgress) {
			statusMark = "▶"
		}

		sb.WriteString(fmt.Sprintf("%-*s  %-*s  %-*s  %-*s  %-*s  %-*s  %s%s\n",
			colID, idStr,
			colTitle, title,
			colEst, estStr,
			colAdj, adjStr,
			colStart, startStr,
			colEnd, endStr,
			statusMark,
			bar,
		))
	}

	// Footer: projected finish.
	last := f.TaskWindows[len(f.TaskWindows)-1]
	sb.WriteString(sep)
	sb.WriteByte('\n')
	sb.WriteString(fmt.Sprintf("  Projected finish: %s  (%d tasks remaining)\n",
		last.ProjectedEnd.Format("Mon Jan 2, 2006 15:04"),
		len(f.TaskWindows),
	))

	return sb.String()
}

// formatMins formats a minute count as "Xh Ym" or "Xm" or "—".
func formatMins(mins int) string {
	if mins <= 0 {
		return "—"
	}
	if mins >= 60 {
		h := mins / 60
		m := mins % 60
		if m == 0 {
			return fmt.Sprintf("%dh", h)
		}
		return fmt.Sprintf("%dh%dm", h, m)
	}
	return fmt.Sprintf("%dm", mins)
}

// BurndownChart renders an ASCII burn-down chart (width × height characters).
func (f *Forecast) BurndownChart(width, height int) string {
	if f.TotalTasks == 0 || len(f.BurnPoints) == 0 {
		return ""
	}

	start := f.ProjectStartDate
	var end time.Time
	if f.Expected.DaysRemaining >= 0 {
		end = f.Expected.CompletionDate
	} else {
		end = time.Now()
	}
	if end.Before(time.Now()) {
		end = time.Now().Add(24 * time.Hour)
	}
	totalSpan := end.Sub(start)
	if totalSpan <= 0 {
		return ""
	}

	grid := make([][]rune, height)
	for i := range grid {
		grid[i] = make([]rune, width)
		for j := range grid[i] {
			grid[i][j] = ' '
		}
	}

	timeToCol := func(t time.Time) int {
		frac := t.Sub(start).Seconds() / totalSpan.Seconds()
		col := int(frac * float64(width-1))
		return clampInt(col, 0, width-1)
	}

	countToRow := func(remaining int) int {
		frac := 1.0 - float64(remaining)/float64(f.TotalTasks)
		row := int(frac * float64(height-1))
		return clampInt(row, 0, height-1)
	}

	for col := 0; col < width; col++ {
		frac := float64(col) / float64(width-1)
		idealRemaining := int(math.Round(float64(f.TotalTasks) * (1.0 - frac)))
		row := countToRow(idealRemaining)
		if grid[row][col] == ' ' {
			grid[row][col] = '·'
		}
	}

	allPoints := append([]BurnPoint{{Date: start, Remaining: f.TotalTasks}}, f.BurnPoints...)
	allPoints = append(allPoints, BurnPoint{Date: time.Now(), Remaining: f.TotalTasks - f.DoneTasks - f.SkippedTasks})

	for i := 1; i < len(allPoints); i++ {
		p0, p1 := allPoints[i-1], allPoints[i]
		c0, c1 := timeToCol(p0.Date), timeToCol(p1.Date)
		r0, r1 := countToRow(p0.Remaining), countToRow(p1.Remaining)

		dx := abs(c1 - c0)
		dy := abs(r1 - r0)
		sx, sy := 1, 1
		if c0 > c1 {
			sx = -1
		}
		if r0 > r1 {
			sy = -1
		}
		err := dx - dy
		cx, cy := c0, r0
		for {
			if cx >= 0 && cx < width && cy >= 0 && cy < height {
				grid[cy][cx] = '█'
			}
			if cx == c1 && cy == r1 {
				break
			}
			e2 := 2 * err
			if e2 > -dy {
				err -= dy
				cx += sx
			}
			if e2 < dx {
				err += dx
				cy += sy
			}
		}
	}

	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("  %d tasks ┐\n", f.TotalTasks))
	for row := 0; row < height; row++ {
		if row == height/2 {
			remaining := int(math.Round(float64(f.TotalTasks) * 0.5))
			sb.WriteString(fmt.Sprintf("  %3d    │", remaining))
		} else if row == height-1 {
			sb.WriteString("    0    │")
		} else {
			sb.WriteString("         │")
		}
		sb.WriteString(string(grid[row]))
		sb.WriteByte('\n')
	}

	sb.WriteString("         └")
	sb.WriteString(strings.Repeat("─", width))
	sb.WriteByte('\n')

	sb.WriteString("          ")
	startLabel := start.Format("Jan 2")
	endLabel := end.Format("Jan 2")
	padding := width - len(startLabel) - len(endLabel)
	sb.WriteString(startLabel)
	if padding > 0 {
		sb.WriteString(strings.Repeat(" ", padding))
	}
	sb.WriteString(endLabel)
	sb.WriteByte('\n')

	sb.WriteString("\n  ─── actual   ··· ideal\n")

	return sb.String()
}

func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}

func clampInt(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

// ForecastPrompt builds the AI prompt for a detailed completion forecast.
func ForecastPrompt(f *Forecast) string {
	var b strings.Builder

	b.WriteString("You are an expert AI project manager specializing in delivery forecasting and risk analysis.\n\n")
	b.WriteString(fmt.Sprintf("## PROJECT GOAL\n%s\n\n", f.Goal))

	b.WriteString("## CURRENT STATUS\n")
	b.WriteString(fmt.Sprintf("- Total tasks: %d\n", f.TotalTasks))
	b.WriteString(fmt.Sprintf("- Completed: %d (%.0f%%)\n", f.DoneTasks, float64(f.DoneTasks)*100/math.Max(1, float64(f.TotalTasks))))
	b.WriteString(fmt.Sprintf("- Skipped: %d\n", f.SkippedTasks))
	b.WriteString(fmt.Sprintf("- Failed: %d\n", f.FailedTasks))
	b.WriteString(fmt.Sprintf("- In progress: %d\n", f.InProgressTasks))
	b.WriteString(fmt.Sprintf("- Pending: %d (%d blocked)\n", f.PendingTasks, f.BlockedTasks))

	b.WriteString("\n## VELOCITY & FORECAST\n")
	if f.BaseVelocityPerDay > 0 {
		b.WriteString(fmt.Sprintf("- Current velocity: %.2f tasks/day\n", f.BaseVelocityPerDay))
	} else {
		b.WriteString("- Velocity: insufficient data (no completed tasks yet)\n")
	}
	if f.AvgTaskDuration > 0 {
		b.WriteString(fmt.Sprintf("- Average task duration: %s\n", f.AvgTaskDuration.Round(time.Minute)))
	}

	if f.MinuteDataPoints > 0 {
		b.WriteString(fmt.Sprintf("- Estimation accuracy: %.0f%% (actual/estimated ratio: %.2f, from %d tasks)\n",
			f.VelocityRatio*100, f.VelocityRatio, f.MinuteDataPoints))
		if f.VelocityRatio > 1.1 {
			b.WriteString("  → Tasks are taking longer than estimated (underestimation pattern)\n")
		} else if f.VelocityRatio < 0.9 {
			b.WriteString("  → Tasks are completing faster than estimated (overestimation pattern)\n")
		} else {
			b.WriteString("  → Estimates are accurate\n")
		}
	}

	writeScenario := func(sc Scenario) {
		if sc.DaysRemaining < 0 {
			b.WriteString(fmt.Sprintf("- %s: unknown (no velocity data)\n", sc.Label))
		} else if sc.DaysRemaining == 0 {
			b.WriteString(fmt.Sprintf("- %s: COMPLETE NOW\n", sc.Label))
		} else {
			b.WriteString(fmt.Sprintf("- %s: %.1f days → %s (confidence: %s, velocity ×%.1f)\n",
				sc.Label, sc.DaysRemaining,
				sc.CompletionDate.Format("Mon Jan 2, 2006"),
				sc.Confidence, sc.VelocityFactor))
		}
	}
	writeScenario(f.Optimistic)
	writeScenario(f.Expected)
	writeScenario(f.Pessimistic)

	b.WriteString(fmt.Sprintf("\n- Data points used: %d completed task(s)\n", f.DoneTasks))
	b.WriteString(fmt.Sprintf("- Project age: %s\n", time.Since(f.ProjectStartDate).Round(time.Hour)))

	b.WriteString("\n## FORECAST REQUEST\n")
	b.WriteString("Provide a focused delivery forecast with these sections:\n\n")
	b.WriteString("**Delivery Outlook** (2-3 sentences: most likely completion window, confidence level, key assumption)\n\n")
	b.WriteString("**Velocity Analysis** (what the pace tells us — is it sustainable? accelerating? decelerating?)\n\n")
	b.WriteString("**Key Risks to Schedule** (top 2-3 factors that could push the date right)\n\n")
	b.WriteString("**Acceleration Opportunities** (1-2 concrete actions to hit the optimistic date)\n\n")
	b.WriteString("**Recommendation** (one clear, actionable statement to the project owner)\n\n")
	b.WriteString("Be specific and honest. Avoid hedging. Use calendar dates. Reference the actual numbers.\n")

	return b.String()
}

// Generate calls the AI provider to stream a forecast narrative.
// The streamed output is written to streamFn as it arrives.
// Returns the full text.
func Generate(ctx context.Context, p provider.Provider, f *Forecast, model string, streamFn func(string)) (string, error) {
	prompt := ForecastPrompt(f)

	opts := provider.Options{
		Model:   model,
		Timeout: 120 * time.Second,
		OnToken: streamFn,
	}

	result, err := p.Complete(ctx, prompt, opts)
	if err != nil {
		return "", fmt.Errorf("forecast: %w", err)
	}
	return result.Output, nil
}
