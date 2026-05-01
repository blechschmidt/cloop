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
	"github.com/blechschmidt/cloop/pkg/insights"
	"github.com/blechschmidt/cloop/pkg/provider"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var (
	insightsProvider string
	insightsModel    string
	insightsQuick    bool
)

var insightsCmd = &cobra.Command{
	Use:   "insights",
	Short: "AI-powered project health analysis and recommendations",
	Long: `Insights analyzes your project's task plan, velocity, risk factors,
and bottlenecks, then generates AI-powered recommendations.

Examples:
  cloop insights                          # full AI analysis
  cloop insights --quick                  # metrics only, no AI call
  cloop insights --provider anthropic     # use specific provider`,
	RunE: func(cmd *cobra.Command, args []string) error {
		workdir, _ := os.Getwd()

		cfg, err := config.Load(workdir)
		if err != nil {
			return fmt.Errorf("loading config: %w", err)
		}

		s, err := state.Load(workdir)
		if err != nil {
			return fmt.Errorf("loading state: %w", err)
		}

		// Print metrics panel immediately (no AI needed).
		m := insights.Analyze(s)
		printMetrics(s, m)

		if insightsQuick {
			return nil
		}

		// Determine provider for AI analysis.
		provName := insightsProvider
		if provName == "" {
			provName = cfg.Provider
		}
		if provName == "" {
			provName = autoSelectProvider()
		}

		model := insightsModel
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
		prov, err := provider.Build(provCfg)
		if err != nil {
			return fmt.Errorf("provider: %w", err)
		}

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		go func() {
			<-sigCh
			cancel()
		}()

		aiColor := color.New(color.FgCyan, color.Bold)
		dimColor := color.New(color.Faint)

		aiColor.Printf("\nAI Analysis  (provider: %s)\n", provName)
		fmt.Println(strings.Repeat("─", 60))

		// Stream tokens if supported.
		var streaming bool
		report, err := insights.Generate(ctx, prov, s, model, 5*time.Minute)
		if err != nil && !streaming {
			// Fall back to non-streaming display on error.
			return fmt.Errorf("generating insights: %w", err)
		}

		if report != nil {
			fmt.Println(report.AIAnalysis)
			fmt.Println()
			dimColor.Printf("Generated at %s using %s\n\n", report.GeneratedAt.Format("2006-01-02 15:04:05"), provName)
		}

		return nil
	},
}

func printMetrics(s *state.ProjectState, m *insights.Metrics) {
	headerColor := color.New(color.FgCyan, color.Bold)
	goodColor := color.New(color.FgGreen, color.Bold)
	warnColor := color.New(color.FgYellow, color.Bold)
	badColor := color.New(color.FgRed, color.Bold)
	dimColor := color.New(color.Faint)
	labelColor := color.New(color.FgWhite)

	headerColor.Printf("\n  Project Insights\n")
	fmt.Printf("  Goal: %s\n", truncate(s.Goal, 70))
	fmt.Println()

	// Progress bar
	pct := m.CompletionPct()
	barWidth := 30
	filled := barWidth * pct / 100
	if filled > barWidth {
		filled = barWidth
	}
	bar := strings.Repeat("█", filled) + strings.Repeat("░", barWidth-filled)

	progressColor := goodColor
	if pct < 30 {
		progressColor = badColor
	} else if pct < 70 {
		progressColor = warnColor
	}
	labelColor.Printf("  Progress   ")
	progressColor.Printf("[%s] %d%%\n", bar, pct)
	fmt.Println()

	// Task breakdown
	fmt.Printf("  %-20s %d\n", "Total Tasks", m.TotalTasks)
	goodColor.Printf("  %-20s %d\n", "Completed", m.DoneTasks)
	if m.SkippedTasks > 0 {
		dimColor.Printf("  %-20s %d\n", "Skipped", m.SkippedTasks)
	}
	if m.FailedTasks > 0 {
		badColor.Printf("  %-20s %d\n", "Failed", m.FailedTasks)
	}
	if m.BlockedTasks > 0 {
		badColor.Printf("  %-20s %d\n", "Blocked", m.BlockedTasks)
	}
	if m.InProgressTasks > 0 {
		warnColor.Printf("  %-20s %d\n", "In Progress", m.InProgressTasks)
	}
	dimColor.Printf("  %-20s %d\n", "Pending", m.PendingTasks)
	fmt.Println()

	// Velocity & forecast
	if m.VelocityPerDay > 0 {
		labelColor.Printf("  %-20s %.1f tasks/day\n", "Velocity", m.VelocityPerDay)
	}
	if m.AvgTaskDuration > 0 {
		labelColor.Printf("  %-20s %s avg\n", "Task Duration", m.AvgTaskDuration.Round(time.Second))
	}
	if m.EstimatedDaysRemaining >= 0 {
		est := m.EstimatedDaysRemaining
		label := labelColor
		if est > 30 {
			label = badColor
		} else if est > 7 {
			label = warnColor
		}
		label.Printf("  %-20s ~%.1f days\n", "Est. Remaining", est)
	}
	fmt.Println()

	// Token usage
	if m.InputTokens > 0 || m.OutputTokens > 0 {
		dimColor.Printf("  %-20s %d in / %d out\n", "Tokens Used", m.InputTokens, m.OutputTokens)
		fmt.Println()
	}

	// Risk score
	riskLabel := m.RiskLabel()
	riskColor := goodColor
	switch riskLabel {
	case "MEDIUM":
		riskColor = warnColor
	case "HIGH":
		riskColor = badColor
	case "CRITICAL":
		riskColor = color.New(color.FgRed, color.Bold, color.BlinkSlow)
	}
	labelColor.Printf("  %-20s ", "Risk Score")
	riskColor.Printf("%d/100 (%s)\n", m.RiskScore, riskLabel)
	if len(m.RiskFactors) > 0 {
		for _, f := range m.RiskFactors {
			warnColor.Printf("    • %s\n", f)
		}
	}
	fmt.Println()

	// Role breakdown (if multiple roles present)
	if len(m.RoleBreakdown) > 1 {
		labelColor.Printf("  Role Breakdown:\n")
		for role, counts := range m.RoleBreakdown {
			done, total := counts[0], counts[1]
			rolePct := 0
			if total > 0 {
				rolePct = done * 100 / total
			}
			barW := 15
			f := barW * rolePct / 100
			roleBar := strings.Repeat("▪", f) + strings.Repeat("·", barW-f)
			c := dimColor
			if rolePct == 100 {
				c = goodColor
			} else if rolePct > 50 {
				c = warnColor
			}
			c.Printf("    %-12s [%s] %d/%d\n", role, roleBar, done, total)
		}
		fmt.Println()
	}

	fmt.Println(strings.Repeat("─", 60))
}

func init() {
	insightsCmd.Flags().StringVar(&insightsProvider, "provider", "", "AI provider for analysis")
	insightsCmd.Flags().StringVar(&insightsModel, "model", "", "Model to use for AI analysis")
	insightsCmd.Flags().BoolVar(&insightsQuick, "quick", false, "Show metrics only, skip AI analysis")
	rootCmd.AddCommand(insightsCmd)
}
