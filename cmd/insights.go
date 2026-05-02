package cmd

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
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
	insightsProvider  string
	insightsModel     string
	insightsQuick     bool
	insightsWorkspace string
)

var insightsCmd = &cobra.Command{
	Use:   "insights",
	Short: "AI-powered project health analysis and cross-project trend recommendations",
	Long: `Insights analyzes your project's task plan, velocity, risk factors,
and bottlenecks, then generates AI-powered recommendations.

When --workspace is provided (or workspace projects are registered via
'cloop workspace add'), insights performs cross-project analysis: it reads
all projects, aggregates metrics, and produces a multi-section report
covering Velocity Trends, Failure Patterns, Provider Performance, and
cross-cutting Recommendations.

Examples:
  cloop insights                                   # single-project AI analysis
  cloop insights --quick                           # metrics only, no AI call
  cloop insights --workspace .cloop/workspace.json # cross-project analysis
  cloop insights --provider anthropic              # use specific provider`,
	RunE: func(cmd *cobra.Command, args []string) error {
		workdir, _ := os.Getwd()

		cfg, err := config.Load(workdir)
		if err != nil {
			return fmt.Errorf("loading config: %w", err)
		}

		// Determine provider details (shared by both modes).
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

		// Decide mode: cross-project when --workspace is set OR when registered
		// workspaces exist and we are not in a single-project context.
		wsFile := insightsWorkspace
		if wsFile == "" {
			// Auto-detect: if a local .cloop/workspace.json exists, use it.
			localWS := filepath.Join(workdir, ".cloop", "workspace.json")
			if _, statErr := os.Stat(localWS); statErr == nil {
				wsFile = localWS
			}
		}

		// Try cross-project mode if a workspace source is available.
		if wsFile != "" || cmd.Flags().Changed("workspace") {
			return runCrossInsights(cfg, provName, model, wsFile, insightsQuick)
		}

		// Also switch to cross-project if global workspaces are registered.
		if !cmd.Flags().Changed("workspace") {
			snaps, wsErr := insights.CollectFromWorkspaces("")
			if wsErr == nil && len(snaps) > 1 {
				return runCrossInsights(cfg, provName, model, "", insightsQuick)
			}
		}

		// ── Single-project mode ──────────────────────────────────────────────
		s, err := state.Load(workdir)
		if err != nil {
			return fmt.Errorf("loading state: %w", err)
		}

		m := insights.Analyze(s)
		printMetrics(s, m)

		if insightsQuick {
			return nil
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

		report, err := insights.Generate(ctx, prov, s, model, 5*time.Minute)
		if err != nil {
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

// runCrossInsights collects all workspace projects, prints aggregate metrics,
// and (unless --quick) calls the AI provider for cross-project recommendations.
func runCrossInsights(cfg *config.Config, provName, model, wsFile string, quick bool) error {
	headerColor := color.New(color.FgCyan, color.Bold)
	goodColor := color.New(color.FgGreen, color.Bold)
	warnColor := color.New(color.FgYellow, color.Bold)
	badColor := color.New(color.FgRed, color.Bold)
	dimColor := color.New(color.Faint)

	snaps, err := insights.CollectFromWorkspaces(wsFile)
	if err != nil {
		return fmt.Errorf("collecting workspace data: %w", err)
	}
	if len(snaps) == 0 {
		return fmt.Errorf("no workspace projects found — register projects with 'cloop workspace add'")
	}

	m := insights.AggregateProjects(snaps)

	// ── Aggregate metrics panel ──────────────────────────────────────────
	headerColor.Printf("\n  Cross-Project Insights  (%d projects)\n", m.TotalProjects)
	fmt.Println(strings.Repeat("─", 60))
	fmt.Printf("  %-24s %d\n", "Total Tasks", m.TotalTasksAcross)
	goodColor.Printf("  %-24s %d\n", "Completed", m.TotalDoneAcross)
	if m.TotalFailedAcross > 0 {
		badColor.Printf("  %-24s %d\n", "Failed", m.TotalFailedAcross)
	}
	fmt.Printf("  %-24s %.0f%%\n", "Avg Completion Rate", m.AvgCompletionRate)
	if m.VelocityMean > 0 {
		fmt.Printf("  %-24s %.1f tasks/day (min %.1f, max %.1f)\n",
			"Velocity (mean)", m.VelocityMean, m.VelocityMin, m.VelocityMax)
	}
	fmt.Println()

	// Provider usage
	if len(m.ProviderCounts) > 0 {
		dimColor.Printf("  Provider usage:\n")
		for prov, cnt := range m.ProviderCounts {
			dimColor.Printf("    %-16s %d project(s)\n", prov, cnt)
		}
		fmt.Println()
	}

	// Per-project table
	headerColor.Printf("  %-20s %6s %6s %6s %8s\n", "PROJECT", "DONE", "FAIL", "TOTAL", "COMPLETE%")
	dimColor.Printf("  %s\n", strings.Repeat("─", 52))
	for _, p := range m.Projects {
		if p.Error != "" {
			badColor.Printf("  %-20s  (load error)\n", truncate(p.Name, 20))
			continue
		}
		c := goodColor
		if p.CompletionPct < 30 {
			c = badColor
		} else if p.CompletionPct < 70 {
			c = warnColor
		}
		c.Printf("  %-20s %6d %6d %6d %7.0f%%\n",
			truncate(p.Name, 20), p.DoneTasks, p.FailedTasks, p.TotalTasks, p.CompletionPct)
	}
	fmt.Println()

	// Top tags
	if len(m.TopTags) > 0 {
		dimColor.Printf("  Top task categories: ")
		labels := make([]string, 0, len(m.TopTags))
		for _, tc := range m.TopTags {
			labels = append(labels, fmt.Sprintf("%s(%d)", tc.Label, tc.Count))
		}
		dimColor.Printf("%s\n", strings.Join(labels, ", "))
	}
	if len(m.TopRoles) > 0 {
		dimColor.Printf("  Top roles:           ")
		labels := make([]string, 0, len(m.TopRoles))
		for _, tc := range m.TopRoles {
			labels = append(labels, fmt.Sprintf("%s(%d)", tc.Label, tc.Count))
		}
		dimColor.Printf("%s\n", strings.Join(labels, ", "))
	}
	fmt.Println(strings.Repeat("─", 60))

	if quick {
		return nil
	}

	// ── AI cross-project analysis ────────────────────────────────────────
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

	headerColor.Printf("\nAI Analysis  (provider: %s)\n", provName)
	fmt.Println(strings.Repeat("─", 60))

	report, err := insights.GenerateCross(ctx, prov, model, 5*time.Minute, snaps)
	if err != nil {
		return fmt.Errorf("generating cross-project insights: %w", err)
	}

	printCrossSection(headerColor, "Velocity Trends", report.VelocityTrends)
	printCrossSection(headerColor, "Failure Patterns", report.FailurePatterns)
	printCrossSection(headerColor, "Provider Performance", report.ProviderPerf)
	printCrossSection(headerColor, "Recommendations", report.Recommendations)

	fmt.Println()
	dimColor.Printf("Generated at %s using %s\n\n",
		report.GeneratedAt.Format("2006-01-02 15:04:05"), provName)

	return nil
}

func printCrossSection(hdr *color.Color, title, body string) {
	if body == "" {
		return
	}
	hdr.Printf("\n%s\n", title)
	fmt.Println(strings.Repeat("─", 40))
	fmt.Println(body)
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
	insightsCmd.Flags().StringVar(&insightsWorkspace, "workspace", "", "Workspace file for cross-project analysis (defaults to .cloop/workspace.json or global registry)")
	rootCmd.AddCommand(insightsCmd)
}
