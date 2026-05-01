package cmd

import (
	"context"
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
)

var forecastCmd = &cobra.Command{
	Use:   "forecast",
	Short: "AI-powered completion forecast with confidence intervals",
	Long: `Forecast analyzes your project velocity and predicts when every task
will be done — with optimistic, expected, and pessimistic completion dates.

It renders an ASCII burn-down chart showing actual vs ideal progress,
then streams an AI narrative that explains the delivery outlook, velocity
trends, schedule risks, and concrete acceleration opportunities.

Examples:
  cloop forecast                       # full forecast (chart + AI)
  cloop forecast --quick               # metrics and chart only, no AI
  cloop forecast --no-chart            # AI narrative without the chart
  cloop forecast --provider anthropic  # use a specific provider`,
	RunE: func(cmd *cobra.Command, args []string) error {
		workdir, _ := os.Getwd()

		s, err := state.Load(workdir)
		if err != nil {
			return err
		}

		bold := color.New(color.Bold)
		dim := color.New(color.Faint)
		cyan := color.New(color.FgCyan, color.Bold)
		green := color.New(color.FgGreen, color.Bold)
		yellow := color.New(color.FgYellow, color.Bold)
		red := color.New(color.FgRed, color.Bold)
		magenta := color.New(color.FgMagenta, color.Bold)

		// Build the forecast data model.
		f := forecast.Build(s)

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

		// Velocity-factor legend
		dim.Printf("  Optimistic = 2× velocity  ·  Expected = current velocity  ·  Pessimistic = ½ velocity\n\n")

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
	forecastCmd.Flags().BoolVar(&forecastQuick, "quick", false, "Show metrics and chart only (no AI)")
	forecastCmd.Flags().BoolVar(&forecastNoChart, "no-chart", false, "Skip the burn-down chart")
	rootCmd.AddCommand(forecastCmd)
}
