package cmd

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/provider"
	"github.com/blechschmidt/cloop/pkg/simulate"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var (
	simulateProvider string
	simulateModel    string
	simulateApply    bool
	simulateQuick    bool
)

var simulateCmd = &cobra.Command{
	Use:   "simulate <scenario>",
	Short: "AI what-if scenario analysis: simulate changes before committing",
	Long: `Simulate analyzes a hypothetical scenario against your current project
state and projects the impact on timeline, risk, and task priorities.

Think of it as a risk-free sandbox for PM decisions: ask any question
before making irreversible changes.

Examples:
  cloop simulate "what if we cut the authentication module?"
  cloop simulate "what if the deadline moves up by 2 weeks?"
  cloop simulate "what if we add a second engineer to the project?"
  cloop simulate "what if we defer all testing tasks to phase 2?"
  cloop simulate "what if we focus only on the critical path?" --apply
  cloop simulate "what if we switch from REST to GraphQL?" --provider anthropic`,
	Args: cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		scenario := strings.Join(args, " ")
		workdir, _ := os.Getwd()

		cfg, err := config.Load(workdir)
		if err != nil {
			return fmt.Errorf("loading config: %w", err)
		}

		s, err := state.Load(workdir)
		if err != nil {
			return fmt.Errorf("loading state: %w", err)
		}

		headerColor := color.New(color.FgMagenta, color.Bold)
		boldColor := color.New(color.Bold)
		dimColor := color.New(color.Faint)
		goodColor := color.New(color.FgGreen, color.Bold)
		warnColor := color.New(color.FgYellow, color.Bold)
		badColor := color.New(color.FgRed, color.Bold)
		cyanColor := color.New(color.FgCyan)
		accentColor := color.New(color.FgMagenta)

		headerColor.Printf("\n  Scenario Simulation\n")
		dimColor.Printf("  Project: %s\n\n", truncate(s.Goal, 70))

		boldColor.Printf("  Scenario: ")
		fmt.Printf("%s\n\n", scenario)

		// Print current project snapshot (--quick mode, no AI)
		if simulateQuick {
			snapshot := simulate.ProjectSnapshot(s)
			dimColor.Printf("  Current State:\n")
			for _, line := range strings.Split(strings.TrimSpace(snapshot), "\n") {
				dimColor.Printf("    %s\n", line)
			}
			fmt.Println()
			return nil
		}

		// Select provider
		provName := simulateProvider
		if provName == "" {
			provName = cfg.Provider
		}
		if provName == "" {
			provName = s.Provider
		}
		if provName == "" {
			provName = autoSelectProvider()
		}

		modelName := simulateModel
		if modelName == "" {
			switch provName {
			case "anthropic":
				modelName = cfg.Anthropic.Model
			case "openai":
				modelName = cfg.OpenAI.Model
			case "ollama":
				modelName = cfg.Ollama.Model
			case "claudecode":
				modelName = cfg.ClaudeCode.Model
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
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		go func() {
			<-sigCh
			cancel()
		}()
		defer signal.Stop(sigCh)

		accentColor.Printf("  Running simulation via %s...\n\n", provName)

		result, _, err := simulate.Run(ctx, s, scenario, prov, modelName, nil)
		if err != nil {
			return fmt.Errorf("simulation failed: %w", err)
		}

		// ── Display results ──────────────────────────────────────────────────────

		headerColor.Printf("  Simulation Results\n")
		fmt.Printf("  %s\n\n", strings.Repeat("─", 60))

		// Summary
		boldColor.Printf("  Summary\n")
		for _, line := range wordWrap(result.Summary, 64) {
			fmt.Printf("    %s\n", line)
		}
		fmt.Println()

		// Timeline impact
		boldColor.Printf("  Timeline Impact\n")
		if result.BaselineDays > 0 {
			dimColor.Printf("    Baseline:   %.1f days remaining\n", result.BaselineDays)
		}
		if result.SimulatedDays > 0 {
			dimColor.Printf("    Simulated:  %.1f days remaining\n", result.SimulatedDays)
		}
		fmt.Printf("    Delta:      ")
		switch {
		case result.TimelineDelta > 0:
			badColor.Printf("+%d days (slower)\n", result.TimelineDelta)
		case result.TimelineDelta < 0:
			goodColor.Printf("%d days (faster)\n", result.TimelineDelta)
		default:
			fmt.Printf("no change\n")
		}
		fmt.Println()

		// Risk change
		boldColor.Printf("  Risk\n")
		fmt.Printf("    Before: ")
		printRisk(result.RiskBefore, goodColor, warnColor, badColor)
		fmt.Printf("    After:  ")
		printRisk(result.RiskAfter, goodColor, warnColor, badColor)
		fmt.Println()

		// Confidence
		fmt.Printf("  ")
		boldColor.Printf("Confidence: ")
		switch result.Confidence {
		case "high":
			goodColor.Printf("High\n")
		case "medium":
			warnColor.Printf("Medium\n")
		default:
			badColor.Printf("Low\n")
		}
		fmt.Println()

		// Recommendations
		if len(result.Recommendations) > 0 {
			boldColor.Printf("  Recommendations\n")
			for i, rec := range result.Recommendations {
				fmt.Printf("    %d. %s\n", i+1, rec)
			}
			fmt.Println()
		}

		// Task changes
		if len(result.TaskChanges) > 0 {
			boldColor.Printf("  Task Changes\n")
			for _, tc := range result.TaskChanges {
				actionStr := strings.ToUpper(tc.Action)
				fmt.Printf("    [#%d] %s  ", tc.TaskID, truncate(tc.TaskTitle, 40))
				switch tc.Action {
				case "cut":
					badColor.Printf("%s", actionStr)
				case "add":
					goodColor.Printf("%s", actionStr)
				case "reprioritize":
					cyanColor.Printf("%s", actionStr)
				default:
					warnColor.Printf("%s", actionStr)
				}
				if tc.NewPrio > 0 {
					dimColor.Printf(" → P%d", tc.NewPrio)
				}
				fmt.Println()
				if tc.Rationale != "" {
					dimColor.Printf("         %s\n", tc.Rationale)
				}
			}
			fmt.Println()
		}

		// Trade-offs
		if len(result.TradeOffs) > 0 {
			boldColor.Printf("  Trade-offs\n")
			for _, to := range result.TradeOffs {
				fmt.Printf("    • %s\n", to)
			}
			fmt.Println()
		}

		// Warnings
		if len(result.Warnings) > 0 {
			warnColor.Printf("  Warnings\n")
			for _, w := range result.Warnings {
				warnColor.Printf("    ! %s\n", w)
			}
			fmt.Println()
		}

		// Apply task changes if requested
		if simulateApply && len(result.TaskChanges) > 0 && s.Plan != nil {
			applied := 0
			byID := make(map[int]int, len(s.Plan.Tasks))
			for i, t := range s.Plan.Tasks {
				byID[t.ID] = i
			}
			for _, tc := range result.TaskChanges {
				idx, ok := byID[tc.TaskID]
				if !ok {
					continue
				}
				switch tc.Action {
				case "cut", "defer":
					s.Plan.Tasks[idx].Status = "skipped"
					applied++
				case "reprioritize":
					if tc.NewPrio > 0 {
						s.Plan.Tasks[idx].Priority = tc.NewPrio
						applied++
					}
				}
			}
			if applied > 0 {
				if err := s.Save(); err != nil {
					warnColor.Printf("  Warning: could not save state: %v\n", err)
				} else {
					goodColor.Printf("  Applied %d task change(s) to state.json\n\n", applied)
				}
			}
		} else if simulateApply && len(result.TaskChanges) == 0 {
			dimColor.Printf("  No task changes to apply.\n\n")
		} else if !simulateApply && len(result.TaskChanges) > 0 {
			dimColor.Printf("  Tip: run with --apply to apply recommended task changes.\n\n")
		}

		return nil
	},
}

func printRisk(level string, good, warn, bad *color.Color) {
	switch level {
	case "low":
		good.Printf("Low\n")
	case "medium":
		warn.Printf("Medium\n")
	case "high":
		bad.Printf("High\n")
	case "critical":
		bad.Printf("Critical\n")
	default:
		fmt.Printf("%s\n", level)
	}
}

// wordWrap breaks text into lines of at most width characters on word boundaries.
func wordWrap(text string, width int) []string {
	words := strings.Fields(text)
	if len(words) == 0 {
		return nil
	}
	var lines []string
	line := words[0]
	for _, w := range words[1:] {
		if len(line)+1+len(w) <= width {
			line += " " + w
		} else {
			lines = append(lines, line)
			line = w
		}
	}
	lines = append(lines, line)
	return lines
}

func init() {
	simulateCmd.Flags().StringVar(&simulateProvider, "provider", "", "AI provider (anthropic, openai, ollama, claudecode)")
	simulateCmd.Flags().StringVar(&simulateModel, "model", "", "Model override")
	simulateCmd.Flags().BoolVar(&simulateApply, "apply", false, "Apply recommended task changes to the project")
	simulateCmd.Flags().BoolVar(&simulateQuick, "quick", false, "Print project snapshot only, no AI call")
	rootCmd.AddCommand(simulateCmd)
}
