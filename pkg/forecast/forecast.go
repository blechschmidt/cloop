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

// Forecast holds the full forecasting output.
type Forecast struct {
	Goal        string
	GeneratedAt time.Time

	// Task counts
	TotalTasks     int
	DoneTasks      int
	SkippedTasks   int
	FailedTasks    int
	PendingTasks   int
	BlockedTasks   int
	InProgressTasks int

	// Velocity metrics
	BaseVelocityPerDay float64 // tasks/day (baseline)
	AvgTaskDuration    time.Duration
	ProjectStartDate   time.Time

	// Scenarios
	Optimistic  Scenario
	Expected    Scenario
	Pessimistic Scenario

	// Historical burn-down data (one point per completed task, chronological)
	BurnPoints []BurnPoint

	// AI-generated narrative
	AIText string
}

// Build computes a Forecast from the current project state. No AI call is made here.
func Build(s *state.ProjectState) *Forecast {
	f := &Forecast{
		Goal:         s.Goal,
		GeneratedAt:  time.Now(),
		ProjectStartDate: s.CreatedAt,
	}

	if s.Plan == nil {
		return f
	}

	// Count statuses and collect completion timestamps.
	var completedTimes []time.Time
	var durations []time.Duration
	blockedSet := map[int]bool{}

	for _, t := range s.Plan.Tasks {
		f.TotalTasks++
		switch t.Status {
		case pm.TaskDone:
			f.DoneTasks++
			if t.CompletedAt != nil {
				completedTimes = append(completedTimes, *t.CompletedAt)
			}
			if t.StartedAt != nil && t.CompletedAt != nil {
				durations = append(durations, t.CompletedAt.Sub(*t.StartedAt))
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
				blockedSet[t.ID] = true
				f.BlockedTasks++
			}
		}
	}

	// Average task duration.
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
		// Single task done; use elapsed time as velocity baseline.
		elapsed := time.Since(s.CreatedAt).Hours() / 24
		if elapsed > 0 {
			f.BaseVelocityPerDay = 1.0 / elapsed
		} else {
			f.BaseVelocityPerDay = 1.0
		}
	}

	// Build burn-down history: reconstruct remaining tasks at each completion event.
	if len(completedTimes) > 0 {
		initial := f.TotalTasks
		remaining := initial
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

	// Confidence levels depend on data quantity.
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

	return f
}

// CompletionPct returns percent of tasks finished (done + skipped).
func (f *Forecast) CompletionPct() int {
	if f.TotalTasks == 0 {
		return 0
	}
	return (f.DoneTasks + f.SkippedTasks) * 100 / f.TotalTasks
}

// BurndownChart renders an ASCII burn-down chart (width × height characters).
// It projects the expected completion date as a dotted line.
func (f *Forecast) BurndownChart(width, height int) string {
	if f.TotalTasks == 0 || len(f.BurnPoints) == 0 {
		return ""
	}

	// Time range: project start → expected end (or now if no end estimate).
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

	// Build a 2D grid: rows = task count, cols = time.
	grid := make([][]rune, height)
	for i := range grid {
		grid[i] = make([]rune, width)
		for j := range grid[i] {
			grid[i][j] = ' '
		}
	}

	// Helper: map time → column index.
	timeToCol := func(t time.Time) int {
		frac := t.Sub(start).Seconds() / totalSpan.Seconds()
		col := int(frac * float64(width-1))
		return clampInt(col, 0, width-1)
	}

	// Helper: map remaining count → row index (0 = top = max tasks).
	countToRow := func(remaining int) int {
		frac := 1.0 - float64(remaining)/float64(f.TotalTasks)
		row := int(frac * float64(height-1))
		return clampInt(row, 0, height-1)
	}

	// Draw the ideal burn-down as a dashed line from (start,total) to (end,0).
	for col := 0; col < width; col++ {
		frac := float64(col) / float64(width-1)
		idealRemaining := int(math.Round(float64(f.TotalTasks) * (1.0 - frac)))
		row := countToRow(idealRemaining)
		if grid[row][col] == ' ' {
			grid[row][col] = '·'
		}
	}

	// Plot actual burn-down line through the historical points.
	// Add a synthetic start point.
	allPoints := append([]BurnPoint{{Date: start, Remaining: f.TotalTasks}}, f.BurnPoints...)
	allPoints = append(allPoints, BurnPoint{Date: time.Now(), Remaining: f.TotalTasks - f.DoneTasks - f.SkippedTasks})

	for i := 1; i < len(allPoints); i++ {
		p0, p1 := allPoints[i-1], allPoints[i]
		c0, c1 := timeToCol(p0.Date), timeToCol(p1.Date)
		r0, r1 := countToRow(p0.Remaining), countToRow(p1.Remaining)

		// Bresenham line between (c0,r0) and (c1,r1).
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

	// Render: add Y-axis labels (task count) and X-axis.
	var sb strings.Builder

	// Y axis header
	sb.WriteString(fmt.Sprintf("  %d tasks ┐\n", f.TotalTasks))
	for row := 0; row < height; row++ {
		// Y label every few rows
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

	// X axis
	sb.WriteString("         └")
	sb.WriteString(strings.Repeat("─", width))
	sb.WriteByte('\n')

	// X labels
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

	// Legend
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
