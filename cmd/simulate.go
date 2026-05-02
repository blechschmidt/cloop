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

var simulatePlanCmd = &cobra.Command{
	Use:   "plan",
	Short: "Dry-run: AI predicts outcome of each pending task without executing",
	Long: `Simulate a plan dry-run: the AI predicts the likely outcome of every pending
task given the codebase context, without actually executing anything.

Each prediction includes:
  • Success probability  (0-100)
  • Expected output summary
  • Potential risks
  • Suggested pre-conditions to check

An overall confidence score is computed as the average success probability.
The report is saved to .cloop/simulation-<timestamp>.json.

Examples:
  cloop simulate plan
  cloop simulate plan --provider anthropic
  cloop simulate plan --model claude-opus-4-5`,
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
		if !s.PMMode || s.Plan == nil || len(s.Plan.Tasks) == 0 {
			return fmt.Errorf("no task plan found — run 'cloop run --pm --plan-only' to create one")
		}

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

		headerColor := color.New(color.FgMagenta, color.Bold)
		dimColor := color.New(color.Faint)
		boldColor := color.New(color.Bold)

		headerColor.Printf("\n  cloop simulate plan — AI dry-run\n")
		dimColor.Printf("  Provider: %s | Goal: %s\n\n", provName, truncate(s.Goal, 70))

		// Count pending tasks
		pendingCount := 0
		for _, t := range s.Plan.Tasks {
			if t.Status == "pending" || t.Status == "in_progress" {
				pendingCount++
			}
		}
		if pendingCount == 0 {
			color.New(color.FgGreen).Printf("  No pending tasks to simulate.\n\n")
			return nil
		}
		boldColor.Printf("  Simulating %d pending task(s)...\n\n", pendingCount)

		ctx, cancel := context.WithCancel(context.Background())
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		go func() {
			<-sigCh
			cancel()
		}()
		defer signal.Stop(sigCh)

		report, err := simulate.Simulate(ctx, prov, modelName, s.Plan, workdir)
		if err != nil {
			return fmt.Errorf("simulation failed: %w", err)
		}

		renderSimulationReport(report)
		return nil
	},
}

// renderSimulationReport prints a colored table of per-task predictions.
func renderSimulationReport(report *simulate.SimulationReport) {
	headerColor := color.New(color.FgMagenta, color.Bold)
	boldColor := color.New(color.Bold)
	dimColor := color.New(color.Faint)
	goodColor := color.New(color.FgGreen, color.Bold)
	warnColor := color.New(color.FgYellow, color.Bold)
	badColor := color.New(color.FgRed, color.Bold)
	cyanColor := color.New(color.FgCyan)

	sep := strings.Repeat("─", 72)

	headerColor.Printf("  Simulation Results\n")
	fmt.Printf("  %s\n\n", sep)

	for _, pred := range report.Predictions {
		boldColor.Printf("  Task #%d — %s\n", pred.TaskID, pred.TaskTitle)

		// Success probability bar
		fmt.Printf("  %-22s ", "Success probability:")
		probColor := goodColor
		if pred.SuccessProb < 50 {
			probColor = badColor
		} else if pred.SuccessProb < 75 {
			probColor = warnColor
		}
		probColor.Printf("%d%%", pred.SuccessProb)
		// ASCII bar (20 chars wide)
		filled := pred.SuccessProb * 20 / 100
		bar := "[" + strings.Repeat("█", filled) + strings.Repeat("░", 20-filled) + "]"
		probColor.Printf("  %s\n", bar)

		// Expected output
		fmt.Printf("  %-22s ", "Expected output:")
		for i, line := range wordWrap(pred.ExpectedOutput, 50) {
			if i == 0 {
				fmt.Printf("%s\n", line)
			} else {
				fmt.Printf("  %-22s %s\n", "", line)
			}
		}

		// Risks
		if len(pred.Risks) > 0 {
			fmt.Printf("  %-22s", "Risks:")
			for i, r := range pred.Risks {
				if i == 0 {
					warnColor.Printf(" %s\n", r)
				} else {
					fmt.Printf("  %-22s", "")
					warnColor.Printf(" %s\n", r)
				}
			}
		}

		// Pre-conditions
		if len(pred.PreConditions) > 0 {
			fmt.Printf("  %-22s", "Pre-conditions:")
			for i, pc := range pred.PreConditions {
				if i == 0 {
					cyanColor.Printf(" %s\n", pc)
				} else {
					fmt.Printf("  %-22s", "")
					cyanColor.Printf(" %s\n", pc)
				}
			}
		}

		fmt.Printf("  %s\n\n", sep)
	}

	// Overall confidence
	boldColor.Printf("  Overall confidence: ")
	switch {
	case report.OverallConfidence >= 75:
		goodColor.Printf("%d%%\n", report.OverallConfidence)
	case report.OverallConfidence >= 50:
		warnColor.Printf("%d%%\n", report.OverallConfidence)
	default:
		badColor.Printf("%d%%\n", report.OverallConfidence)
	}

	dimColor.Printf("\n  Report saved to .cloop/simulation-<timestamp>.json\n\n")
}

func init() {
	simulateCmd.Flags().StringVar(&simulateProvider, "provider", "", "AI provider (anthropic, openai, ollama, claudecode)")
	simulateCmd.Flags().StringVar(&simulateModel, "model", "", "Model override")
	simulateCmd.Flags().BoolVar(&simulateApply, "apply", false, "Apply recommended task changes to the project")
	simulateCmd.Flags().BoolVar(&simulateQuick, "quick", false, "Print project snapshot only, no AI call")
	simulatePlanCmd.Flags().StringVar(&simulateProvider, "provider", "", "AI provider (anthropic, openai, ollama, claudecode)")
	simulatePlanCmd.Flags().StringVar(&simulateModel, "model", "", "Model override")
	simulateCmd.AddCommand(simulatePlanCmd)
	rootCmd.AddCommand(simulateCmd)
}
