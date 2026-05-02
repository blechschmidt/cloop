package cmd

import (
	"context"
	"fmt"
	"math"
	"os"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/calibrate"
	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/provider"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var (
	calibrateApply    bool
	calibrateProvider string
	calibrateModel    string
	calibrateTimeout  string
	calibrateNoAI     bool
)

var taskCalibrateCmd = &cobra.Command{
	Use:   "effort-calibrate",
	Short: "AI recalibration of estimates from historical actuals",
	Long: `Analyze the gap between AI-predicted EstimatedMinutes and measured
ActualMinutes across all completed tasks. Computes per-role accuracy metrics
(MAE, bias, calibration factor) and asks the AI to suggest revised estimates
for all pending tasks.

With --apply the command:
  - Writes the suggested new EstimatedMinutes to each pending task in state
  - Persists the overall calibration factor to .cloop/config.yaml so that
    future 'cloop run --pm' decompositions automatically scale AI estimates

Without --apply the output is read-only (dry run).

Examples:
  cloop task effort-calibrate
  cloop task effort-calibrate --apply
  cloop task effort-calibrate --no-ai            # statistics only, no AI call
  cloop task effort-calibrate --provider anthropic --model claude-opus-4-6`,
	RunE: func(cmd *cobra.Command, args []string) error {
		workdir, _ := os.Getwd()

		s, err := state.Load(workdir)
		if err != nil {
			return err
		}
		if !s.PMMode || s.Plan == nil || len(s.Plan.Tasks) == 0 {
			return fmt.Errorf("no task plan found — run 'cloop run --pm' to create one")
		}

		// Build provider (optional when --no-ai)
		var prov provider.Provider
		if !calibrateNoAI {
			cfg, err := config.Load(workdir)
			if err != nil {
				return fmt.Errorf("loading config: %w", err)
			}
			applyEnvOverrides(cfg)

			pName := calibrateProvider
			if pName == "" {
				pName = cfg.Provider
			}
			if pName == "" && s.Provider != "" {
				pName = s.Provider
			}
			if pName == "" {
				pName = autoSelectProvider()
			}

			model := calibrateModel
			if model == "" {
				switch pName {
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
			if model == "" {
				model = s.Model
			}

			provCfg := provider.ProviderConfig{
				Name:             pName,
				AnthropicAPIKey:  cfg.Anthropic.APIKey,
				AnthropicBaseURL: cfg.Anthropic.BaseURL,
				OpenAIAPIKey:     cfg.OpenAI.APIKey,
				OpenAIBaseURL:    cfg.OpenAI.BaseURL,
				OllamaBaseURL:    cfg.Ollama.BaseURL,
			}
			prov, err = provider.Build(provCfg)
			if err != nil {
				return fmt.Errorf("provider: %w", err)
			}
		}

		timeout := 5 * time.Minute
		if calibrateTimeout != "" {
			var parseErr error
			timeout, parseErr = time.ParseDuration(calibrateTimeout)
			if parseErr != nil {
				return fmt.Errorf("invalid timeout: %w", parseErr)
			}
		}

		opts := provider.Options{
			Model:   calibrateModel,
			Timeout: timeout,
		}

		ctx, cancel := context.WithTimeout(context.Background(), timeout+30*time.Second)
		defer cancel()

		// ── Run calibration ────────────────────────────────────────────────────
		headerColor := color.New(color.FgCyan, color.Bold)
		dimColor := color.New(color.Faint)
		warnColor := color.New(color.FgYellow)
		successColor := color.New(color.FgGreen)
		errColor := color.New(color.FgRed)

		headerColor.Println("Effort Calibration Report")
		fmt.Println(repeatStr("─", 72))

		if !calibrateNoAI {
			fmt.Printf("Computing statistics and asking AI for re-estimates...\n\n")
		} else {
			fmt.Printf("Computing statistics (--no-ai: skipping AI suggestions)...\n\n")
		}

		report, runErr := calibrate.Run(ctx, prov, opts, s.Plan)
		if runErr != nil {
			// Partial results may still be present.
			warnColor.Printf("Warning: %v\n\n", runErr)
		}

		// ── Section 1: Historical accuracy table ───────────────────────────────
		headerColor.Println("Historical Estimation Accuracy")
		fmt.Println()

		hasDat := len(report.ByRole) > 0 && report.ByRole[0].TaskCount > 0
		if !hasDat {
			dimColor.Println("  No completed tasks with both estimated and actual durations found.")
			dimColor.Println("  Run tasks in PM mode to accumulate calibration data.")
			fmt.Println()
		} else {
			// Header row
			fmt.Printf("  %-12s  %5s  %8s  %8s  %7s  %7s  %7s\n",
				"ROLE", "TASKS", "EST(min)", "ACT(min)", "BIAS", "MAE", "FACTOR")
			fmt.Println("  " + repeatStr("─", 68))

			for _, stat := range report.ByRole {
				factorStr := fmt.Sprintf("%.2fx", stat.Factor)
				factorColor := color.New(color.Reset)
				if stat.Factor > 1.2 {
					factorColor = errColor // significant underestimation
				} else if stat.Factor < 0.85 {
					factorColor = warnColor // overestimation
				} else {
					factorColor = successColor // good calibration
				}
				biasSign := ""
				if stat.Bias > 0 {
					biasSign = "+"
				}
				factorColor.Printf("  %-12s  %5d  %8d  %8d  %6s%.1f  %7.1f  %7s\n",
					stat.Role, stat.TaskCount, stat.EstTotal, stat.ActualTotal,
					biasSign, stat.Bias, stat.MAE, factorStr)
			}
			fmt.Println()

			// Overall calibration factor
			factor := report.OverallFactor
			factorLabel := fmt.Sprintf("%.2fx", factor)
			interpretation := calibrationInterpretation(factor)
			fmt.Printf("  Overall calibration factor: ")
			if math.Abs(factor-1.0) < 0.1 {
				successColor.Printf("%s", factorLabel)
			} else if factor > 1.0 {
				errColor.Printf("%s", factorLabel)
			} else {
				warnColor.Printf("%s", factorLabel)
			}
			dimColor.Printf("  — %s\n\n", interpretation)
		}

		// ── Section 2: AI suggestions for pending tasks ────────────────────────
		if len(report.Suggestions) > 0 {
			headerColor.Println("Calibrated Estimates for Pending Tasks")
			fmt.Println()
			fmt.Printf("  %-4s  %-40s  %10s  %10s  %s\n",
				"ID", "TITLE", "OLD(min)", "NEW(min)", "REASONING")
			fmt.Println("  " + repeatStr("─", 90))
			for _, sg := range report.Suggestions {
				delta := sg.NewMinutes - sg.OldMinutes
				deltaStr := fmt.Sprintf("%+d", delta)
				deltaColor := color.New(color.Reset)
				if delta > 0 {
					deltaColor = errColor
				} else if delta < 0 {
					deltaColor = successColor
				} else {
					deltaColor = dimColor
				}
				fmt.Printf("  %-4d  %-40s  %10d  ",
					sg.TaskID, truncateStr(sg.Title, 40), sg.OldMinutes)
				deltaColor.Printf("%10d", sg.NewMinutes)
				fmt.Printf("  (%s min) ", deltaStr)
				dimColor.Printf("%s\n", truncateStr(sg.Reasoning, 60))
			}
			fmt.Println()
		} else if !calibrateNoAI && runErr == nil {
			dimColor.Println("  No pending tasks found for re-estimation.")
			fmt.Println()
		}

		// ── Section 3: Apply ───────────────────────────────────────────────────
		if !calibrateApply {
			dimColor.Println("Run with --apply to persist updated estimates and calibration factor to config.")
			return nil
		}

		// Apply suggestions to pending tasks in plan.
		if len(report.Suggestions) > 0 {
			updated := 0
			for _, sg := range report.Suggestions {
				for _, t := range s.Plan.Tasks {
					if t.ID == sg.TaskID && t.Status == "pending" {
						t.EstimatedMinutes = sg.NewMinutes
						updated++
						break
					}
				}
			}
			if err := s.Save(); err != nil {
				return fmt.Errorf("saving state: %w", err)
			}
			successColor.Printf("Updated EstimatedMinutes for %d pending task(s).\n", updated)
		}

		// Persist calibration factor to config.
		cfg, err := config.Load(workdir)
		if err != nil {
			return fmt.Errorf("loading config for save: %w", err)
		}
		cfg.CalibrationFactor = report.OverallFactor
		if err := config.Save(workdir, cfg); err != nil {
			return fmt.Errorf("saving config: %w", err)
		}
		successColor.Printf("Calibration factor %.2fx stored in .cloop/config.yaml\n", report.OverallFactor)
		dimColor.Println("  Future 'cloop run --pm' decompositions will automatically scale AI estimates.")

		return nil
	},
}

func init() {
	taskCalibrateCmd.Flags().BoolVar(&calibrateApply, "apply", false, "Persist calibrated estimates to state and factor to config")
	taskCalibrateCmd.Flags().BoolVar(&calibrateNoAI, "no-ai", false, "Skip AI suggestions — output statistics only")
	taskCalibrateCmd.Flags().StringVar(&calibrateProvider, "provider", "", "AI provider (anthropic, openai, ollama, claudecode)")
	taskCalibrateCmd.Flags().StringVar(&calibrateModel, "model", "", "Model override for the AI provider")
	taskCalibrateCmd.Flags().StringVar(&calibrateTimeout, "timeout", "5m", "Timeout for the AI call (e.g. 2m, 300s)")
}

// calibrationInterpretation returns a short human-readable note about the factor.
func calibrationInterpretation(f float64) string {
	switch {
	case f > 2.0:
		return "severely underestimated — actual work took >2x longer than predicted"
	case f > 1.5:
		return "significantly underestimated — tasks took 50%+ longer than predicted"
	case f > 1.2:
		return "underestimated — tasks took ~20-50% longer than predicted"
	case f > 1.05:
		return "slightly underestimated — estimates are close but conservative"
	case f > 0.95:
		return "well-calibrated — estimates match actuals closely"
	case f > 0.8:
		return "slightly overestimated — tasks completed faster than predicted"
	case f > 0.6:
		return "overestimated — tasks completed 20-40% faster than predicted"
	default:
		return "significantly overestimated — tasks completed much faster than predicted"
	}
}

// repeatStr returns s repeated n times.
func repeatStr(s string, n int) string {
	return strings.Repeat(s, n)
}
