package cmd

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/pivot"
	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/provider"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var (
	pivotProvider string
	pivotModel    string
	pivotTimeout  string
	pivotYes      bool
)

var pivotCmd = &cobra.Command{
	Use:   "pivot <new-goal>",
	Short: "AI-powered goal pivot: intelligently transition the plan to a new goal",
	Long: `Pivot the current project plan to a new goal without losing progress.

The AI analyses all existing tasks and decides:
  • KEEP   — completed, in-progress, and still-relevant pending tasks
  • SKIP   — pending tasks that no longer serve the new goal (with a reason)
  • ADD    — brand-new tasks required to achieve the new goal

A plan snapshot is saved before the pivot so you can roll back with:
  cloop rollback

Examples:
  cloop pivot "Ship a GraphQL API instead of REST"
  cloop pivot --provider anthropic "Focus only on mobile support"
  cloop pivot --yes "Add real-time collaboration features"`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		newGoal := strings.TrimSpace(args[0])
		if newGoal == "" {
			return fmt.Errorf("new goal cannot be empty")
		}

		workdir, _ := os.Getwd()
		s, err := state.Load(workdir)
		if err != nil {
			return err
		}
		if !s.PMMode || s.Plan == nil || len(s.Plan.Tasks) == 0 {
			return fmt.Errorf("no task plan found — run 'cloop run --pm --plan-only' to create one first")
		}

		cfg, err := config.Load(workdir)
		if err != nil {
			return fmt.Errorf("loading config: %w", err)
		}
		applyEnvOverrides(cfg)

		pName := pivotProvider
		if pName == "" {
			pName = cfg.Provider
		}
		if pName == "" && s.Provider != "" {
			pName = s.Provider
		}
		if pName == "" {
			pName = autoSelectProvider()
		}

		model := pivotModel
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

		timeout := 5 * time.Minute
		if pivotTimeout != "" {
			timeout, err = time.ParseDuration(pivotTimeout)
			if err != nil {
				return fmt.Errorf("invalid --timeout: %w", err)
			}
		}

		provCfg := provider.ProviderConfig{
			Name:             pName,
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

		headerColor := color.New(color.FgCyan, color.Bold)
		warnColor := color.New(color.FgYellow)
		dimColor := color.New(color.Faint)
		successColor := color.New(color.FgGreen, color.Bold)

		headerColor.Printf("\ncloop pivot — AI-powered goal transition\n")
		fmt.Printf("  Provider : %s\n", prov.Name())
		fmt.Printf("  Old goal : %s\n", truncate(s.Goal, 80))
		fmt.Printf("  New goal : %s\n", truncate(newGoal, 80))
		fmt.Printf("  Tasks    : %d\n", len(s.Plan.Tasks))
		fmt.Println()

		if !pivotYes {
			warnColor.Printf("This will modify the current plan. A snapshot will be saved for rollback.\n")
			fmt.Printf("Proceed? [y/N] ")
			var answer string
			fmt.Scanln(&answer) //nolint:errcheck
			answer = strings.TrimSpace(strings.ToLower(answer))
			if answer != "y" && answer != "yes" {
				dimColor.Printf("Pivot cancelled.\n")
				return nil
			}
			fmt.Println()
		}

		// Save snapshot before mutating the plan (enables rollback).
		if saveErr := pm.SaveSnapshot(workdir, s.Plan); saveErr != nil {
			warnColor.Printf("Warning: could not save plan snapshot: %v\n", saveErr)
		} else {
			dimColor.Printf("Snapshot saved. Use 'cloop rollback' to undo.\n\n")
		}

		dimColor.Printf("Analysing plan and generating pivot...\n\n")

		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()

		oldGoal := s.Goal
		result, err := pivot.Pivot(ctx, prov, model, oldGoal, newGoal, s.Plan)
		if err != nil {
			return fmt.Errorf("pivot: %w", err)
		}

		// Update goal in state.
		s.Goal = newGoal

		if err := s.Save(); err != nil {
			return fmt.Errorf("save state: %w", err)
		}

		// Print summary.
		sep := strings.Repeat("─", 70)
		fmt.Println(sep)

		successColor.Printf("Pivot complete!\n\n")

		if len(result.Keep) > 0 {
			fmt.Printf("  Kept    : %d tasks\n", len(result.Keep))
		}
		if len(result.Skip) > 0 {
			warnColor.Printf("  Skipped : %d tasks\n", len(result.Skip))
			for _, sk := range result.Skip {
				fmt.Printf("    #%-3d  %s\n", sk.ID, sk.Reason)
			}
		}
		if len(result.Add) > 0 {
			successColor.Printf("  Added   : %d new tasks\n", len(result.Add))
			for i, spec := range result.Add {
				// The new tasks were appended; find their IDs.
				startID := len(s.Plan.Tasks) - len(result.Add) + i + 1
				_ = startID
				fmt.Printf("    + [P%d] %s\n", spec.Priority, spec.Title)
			}
		}

		if result.Rationale != "" {
			fmt.Println()
			dimColor.Printf("Rationale: %s\n", result.Rationale)
		}

		fmt.Println(sep)
		fmt.Println()
		dimColor.Printf("Run 'cloop run --pm' to execute the updated plan.\n")
		return nil
	},
}

func init() {
	pivotCmd.Flags().StringVar(&pivotProvider, "provider", "", "AI provider to use (anthropic, openai, ollama, claudecode)")
	pivotCmd.Flags().StringVar(&pivotModel, "model", "", "Model override for the AI provider")
	pivotCmd.Flags().StringVar(&pivotTimeout, "timeout", "5m", "Timeout for the AI call (e.g. 3m, 90s)")
	pivotCmd.Flags().BoolVarP(&pivotYes, "yes", "y", false, "Skip confirmation prompt")
	rootCmd.AddCommand(pivotCmd)
}
