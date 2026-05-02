package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/forecast"
	"github.com/blechschmidt/cloop/pkg/provider"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var (
	forecastProvider string
	forecastModel    string
	forecastQuick    bool
	forecastNoChart  bool
	forecastNoGantt  bool
	forecastFormat   string
)

var forecastCmd = &cobra.Command{
	Use:   "forecast",
	Short: "Velocity-based sprint timeline forecasting with Gantt view",
	Long: `Forecast analyzes your project velocity (from estimated vs actual minutes)
and projects when every pending task will complete — with optimistic, expected,
and pessimistic completion dates.

It renders a per-task Gantt-style ASCII table with projected start/end windows,
an ASCII burn-down chart, then streams an AI narrative explaining the delivery
outlook, velocity trends, schedule risks, and acceleration opportunities.

Examples:
  cloop forecast                        # full forecast (chart + Gantt + AI)
  cloop forecast --quick                # metrics, chart, and Gantt only (no AI)
  cloop forecast --no-chart             # skip burn-down chart
  cloop forecast --no-gantt             # skip per-task Gantt table
  cloop forecast --format json          # machine-readable JSON output
  cloop forecast --provider anthropic   # use a specific provider`,
	RunE: func(cmd *cobra.Command, args []string) error {
		workdir, _ := os.Getwd()

		s, err := state.Load(workdir)
		if err != nil {
			return err
		}

		f := forecast.Build(s)

		// ── JSON output ──────────────────────────────────────────────────────
		if forecastFormat == "json" {
			return outputForecastJSON(f)
		}

		bold := color.New(color.Bold)
		dim := color.New(color.Faint)
		cyan := color.New(color.FgCyan, color.Bold)
		green := color.New(color.FgGreen, color.Bold)
		yellow := color.New(color.FgYellow, color.Bold)
		red := color.New(color.FgRed, color.Bold)
		magenta := color.New(color.FgMagenta, color.Bold)

		// ── Header ──────────────────────────────────────────────────────────
		cyan.Printf("━━━ cloop forecast ━━━\n\n")

		bold.Printf("Goal:    ")
		fmt.Printf("%s\n", truncateForecast(s.Goal, 72))

		bold.Printf("As of:   ")
		dim.Printf("%s\n\n", f.GeneratedAt.Format("Mon Jan 2, 2006 15:04"))

		// ── Completion summary ───────────────────────────────────────────────
		bold.Printf("Progress\n")
		pct := f.CompletionPct()
		bar := progressBar(pct, 40)
		fmt.Printf("  %s %d%%\n", bar, pct)
		fmt.Printf("  %d done  %d skipped  %d failed  %d in-progress  %d pending",
			f.DoneTasks, f.SkippedTasks, f.FailedTasks, f.InProgressTasks, f.PendingTasks)
		if f.BlockedTasks > 0 {
			red.Printf("  (%d blocked)", f.BlockedTasks)
		}
		fmt.Printf("\n\n")

		// ── Velocity ─────────────────────────────────────────────────────────
		bold.Printf("Velocity\n")
		if f.BaseVelocityPerDay > 0 {
			fmt.Printf("  %.2f tasks/day", f.BaseVelocityPerDay)
			if f.AvgTaskDuration > 0 {
				fmt.Printf("  ·  avg task: %s", f.AvgTaskDuration.Round(time.Minute))
			}
			fmt.Println()
		} else {
			dim.Printf("  Not enough data yet (complete at least one task)\n")
		}
		// Estimation accuracy from minute-based data.
		if f.MinuteDataPoints > 0 {
			ratio := f.VelocityRatio
			label := "on track"
			var ratioColor *color.Color
			switch {
			case ratio > 1.2:
				label = "tasks taking longer than estimated"
				ratioColor = red
			case ratio > 1.05:
				label = "slightly over estimate"
				ratioColor = yellow
			case ratio < 0.8:
				label = "tasks faster than estimated"
				ratioColor = green
			case ratio < 0.95:
				label = "slightly under estimate"
				ratioColor = green
			default:
				ratioColor = dim
			}
			fmt.Printf("  Estimation accuracy: ")
			ratioColor.Printf("%.0f%% (actual/estimated = %.2f)  %s\n", ratio*100, ratio, label)
			dim.Printf("  Based on %d completed task(s) with time tracking\n", f.MinuteDataPoints)
		}
		if f.AvgEstimatedMinutes > 0 {
			dim.Printf("  Avg estimate: %.0f min/task\n", f.AvgEstimatedMinutes)
		}
		fmt.Println()

		// ── Scenarios ────────────────────────────────────────────────────────
		bold.Printf("Completion Scenarios\n")
		printScenario := func(sc forecast.Scenario, colorFn func(string, ...interface{}) string) {
			label := fmt.Sprintf("  %-14s", sc.Label)
			fmt.Printf("%s", label)
			if sc.DaysRemaining < 0 {
				dim.Printf("unknown (need more velocity data)\n")
				return
			}
			if sc.DaysRemaining == 0 {
				green.Printf("DONE NOW\n")
				return
			}
			dateStr := sc.CompletionDate.Format("Mon Jan 2, 2006")
			daysStr := fmt.Sprintf("%.1f days", sc.DaysRemaining)
			confStr := fmt.Sprintf("(confidence: %s)", sc.Confidence)
			_ = colorFn
			switch sc.Label {
			case "Optimistic":
				green.Printf("%-12s  %s  %s\n", daysStr, dateStr, confStr)
			case "Expected":
				yellow.Printf("%-12s  %s  %s\n", daysStr, dateStr, confStr)
			case "Pessimistic":
				red.Printf("%-12s  %s  %s\n", daysStr, dateStr, confStr)
			default:
				fmt.Printf("%-12s  %s  %s\n", daysStr, dateStr, confStr)
			}
		}
		printScenario(f.Optimistic, green.Sprintf)
		printScenario(f.Expected, yellow.Sprintf)
		printScenario(f.Pessimistic, red.Sprintf)
		fmt.Println()

		dim.Printf("  Optimistic = 2× velocity  ·  Expected = current velocity  ·  Pessimistic = ½ velocity\n\n")

		// ── Gantt table ───────────────────────────────────────────────────────
		if !forecastNoGantt && len(f.TaskWindows) > 0 {
			bold.Printf("Per-Task Schedule (Gantt)\n")
			if f.VelocityRatio != 1.0 && f.MinuteDataPoints > 0 {
				dim.Printf("  Adj = estimated × velocity ratio (%.2f)  ·  ▶ = in progress\n\n", f.VelocityRatio)
			} else {
				dim.Printf("  Adj = estimated (no actuals yet; ratio = 1.00)  ·  ▶ = in progress\n\n")
			}
			magenta.Printf("%s\n", f.GanttTable())
		}

		// ── Burn-down chart ───────────────────────────────────────────────────
		if !forecastNoChart && f.TotalTasks > 0 {
			chart := f.BurndownChart(60, 10)
			if chart != "" {
				bold.Printf("Burn-down Chart\n")
				magenta.Printf("%s\n", chart)
			}
		}

		// ── Quick mode: stop here ─────────────────────────────────────────────
		if forecastQuick {
			return nil
		}

		// ── AI narrative ──────────────────────────────────────────────────────
		cfg, err := config.Load(workdir)
		if err != nil {
			return fmt.Errorf("loading config: %w", err)
		}

		provName := forecastProvider
		if provName == "" {
			provName = cfg.Provider
		}
		if provName == "" {
			provName = s.Provider
		}

		model := forecastModel
		if model == "" {
			switch provName {
			case "anthropic":
				model = cfg.Anthropic.Model
			case "openai":
				model = cfg.OpenAI.Model
			case "ollama":
				model = cfg.Ollama.Model
			case "claudecode":
				model = cfg.ClaudeCode.Model
			}
		}

		provCfg := provider.ProviderConfig{
			Name:             provName,
			AnthropicAPIKey:  cfg.Anthropic.APIKey,
			AnthropicBaseURL: cfg.Anthropic.BaseURL,
			OpenAIAPIKey:     cfg.OpenAI.APIKey,
			OpenAIBaseURL:    cfg.OpenAI.BaseURL,
			OllamaBaseURL:    cfg.Ollama.BaseURL,
		}
		p, err := provider.Build(provCfg)
		if err != nil {
			return fmt.Errorf("building provider: %w", err)
		}

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		go func() {
			<-sigCh
			cancel()
		}()

		bold.Printf("AI Forecast Narrative\n")
		dim.Printf("  Streaming from %s", provName)
		if model != "" {
			dim.Printf(" (%s)", model)
		}
		dim.Printf("...\n\n")

		var buf strings.Builder
		_, err = forecast.Generate(ctx, p, f, model, func(chunk string) {
			fmt.Print(chunk)
			buf.WriteString(chunk)
		})
		fmt.Println()
		if err != nil {
			if ctx.Err() != nil {
				return nil // user cancelled
			}
			return fmt.Errorf("AI forecast: %w", err)
		}

		_ = buf
		return nil
	},
}

// outputForecastJSON serializes the forecast as machine-readable JSON to stdout.
func outputForecastJSON(f *forecast.Forecast) error {
	type scenarioJSON struct {
		Label          string  `json:"label"`
		VelocityFactor float64 `json:"velocity_factor"`
		DaysRemaining  float64 `json:"days_remaining"`
		CompletionDate string  `json:"completion_date,omitempty"`
		Confidence     string  `json:"confidence"`
	}

	type outputJSON struct {
		Goal        string `json:"goal"`
		GeneratedAt string `json:"generated_at"`

		TotalTasks      int `json:"total_tasks"`
		DoneTasks       int `json:"done_tasks"`
		SkippedTasks    int `json:"skipped_tasks"`
		FailedTasks     int `json:"failed_tasks"`
		PendingTasks    int `json:"pending_tasks"`
		BlockedTasks    int `json:"blocked_tasks"`
		InProgressTasks int `json:"in_progress_tasks"`
		CompletionPct   int `json:"completion_pct"`

		BaseVelocityPerDay  float64 `json:"base_velocity_per_day"`
		VelocityRatio       float64 `json:"velocity_ratio"`
		AvgEstimatedMinutes float64 `json:"avg_estimated_minutes"`
		MinuteDataPoints    int     `json:"minute_data_points"`

		Optimistic  scenarioJSON     `json:"optimistic"`
		Expected    scenarioJSON     `json:"expected"`
		Pessimistic scenarioJSON     `json:"pessimistic"`
		TaskWindows []forecast.TaskWindow `json:"task_windows"`
	}

	toScenario := func(sc forecast.Scenario) scenarioJSON {
		s := scenarioJSON{
			Label:          sc.Label,
			VelocityFactor: sc.VelocityFactor,
			DaysRemaining:  sc.DaysRemaining,
			Confidence:     sc.Confidence,
		}
		if sc.DaysRemaining >= 0 {
			s.CompletionDate = sc.CompletionDate.Format(time.RFC3339)
		}
		return s
	}

	out := outputJSON{
		Goal:                f.Goal,
		GeneratedAt:         f.GeneratedAt.Format(time.RFC3339),
		TotalTasks:          f.TotalTasks,
		DoneTasks:           f.DoneTasks,
		SkippedTasks:        f.SkippedTasks,
		FailedTasks:         f.FailedTasks,
		PendingTasks:        f.PendingTasks,
		BlockedTasks:        f.BlockedTasks,
		InProgressTasks:     f.InProgressTasks,
		CompletionPct:       f.CompletionPct(),
		BaseVelocityPerDay:  f.BaseVelocityPerDay,
		VelocityRatio:       f.VelocityRatio,
		AvgEstimatedMinutes: f.AvgEstimatedMinutes,
		MinuteDataPoints:    f.MinuteDataPoints,
		Optimistic:          toScenario(f.Optimistic),
		Expected:            toScenario(f.Expected),
		Pessimistic:         toScenario(f.Pessimistic),
		TaskWindows:         f.TaskWindows,
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}

// progressBar renders a colored ASCII progress bar of the given width.
func progressBar(pct, width int) string {
	filled := pct * width / 100
	if filled > width {
		filled = width
	}
	bar := strings.Repeat("█", filled) + strings.Repeat("░", width-filled)
	return "[" + bar + "]"
}

func truncateForecast(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

func init() {
	forecastCmd.Flags().StringVar(&forecastProvider, "provider", "", "AI provider (claudecode, anthropic, openai, ollama)")
	forecastCmd.Flags().StringVar(&forecastModel, "model", "", "Model override")
	forecastCmd.Flags().BoolVar(&forecastQuick, "quick", false, "Show metrics, chart, and Gantt only (no AI)")
	forecastCmd.Flags().BoolVar(&forecastNoChart, "no-chart", false, "Skip the burn-down chart")
	forecastCmd.Flags().BoolVar(&forecastNoGantt, "no-gantt", false, "Skip the per-task Gantt table")
	forecastCmd.Flags().StringVar(&forecastFormat, "format", "text", "Output format: text or json")
	rootCmd.AddCommand(forecastCmd)
}
