package cmd

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/autodeps"
	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/provider"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var (
	autoDepsProvider string
	autoDepsModel    string
	autoDepsTimeout  string
	autoDepsDryRun   bool
	autoDepsApply    bool
)

var taskAutoDepsCmd = &cobra.Command{
	Use:   "auto-deps",
	Short: "AI-powered automatic dependency inference for all pending/in-progress tasks",
	Long: `Analyse all pending and in-progress task titles and descriptions with the
configured AI provider and infer which tasks naturally depend on which others.

The AI returns a JSON map {task_id: [dependency_ids]} which is then validated
for cycles and non-existent references before being applied.

Modes:
  --dry-run   (default) Print suggested dependencies as a table without saving
  --apply     Update Task.DependsOn in state and save

Examples:
  cloop task auto-deps             # dry-run: show suggested deps
  cloop task auto-deps --dry-run   # explicit dry-run
  cloop task auto-deps --apply     # infer and apply to plan
  cloop task auto-deps --apply --provider anthropic --model claude-opus-4-5`,
	RunE: func(cmd *cobra.Command, args []string) error {
		// Default to dry-run unless --apply is explicitly set.
		if !autoDepsApply {
			autoDepsDryRun = true
		}

		workdir, _ := os.Getwd()
		s, err := state.Load(workdir)
		if err != nil {
			return err
		}
		if !s.PMMode || s.Plan == nil || len(s.Plan.Tasks) == 0 {
			return fmt.Errorf("no task plan found — run 'cloop run --pm' to create one")
		}

		// Build provider.
		cfg, err := config.Load(workdir)
		if err != nil {
			return fmt.Errorf("loading config: %w", err)
		}
		applyEnvOverrides(cfg)

		pName := autoDepsProvider
		if pName == "" {
			pName = cfg.Provider
		}
		if pName == "" && s.Provider != "" {
			pName = s.Provider
		}
		if pName == "" {
			pName = autoSelectProvider()
		}

		model := autoDepsModel
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
		prov, err := provider.Build(provCfg)
		if err != nil {
			return fmt.Errorf("provider: %w", err)
		}

		timeout := 5 * time.Minute
		if autoDepsTimeout != "" {
			timeout, err = time.ParseDuration(autoDepsTimeout)
			if err != nil {
				return fmt.Errorf("invalid timeout: %w", err)
			}
		}

		headerColor := color.New(color.FgCyan, color.Bold)
		dimColor := color.New(color.Faint)
		warnColor := color.New(color.FgYellow)
		successColor := color.New(color.FgGreen)

		// Count active tasks.
		activeCount := 0
		for _, t := range s.Plan.Tasks {
			if t.Status == "pending" || t.Status == "in_progress" {
				activeCount++
			}
		}

		headerColor.Printf("Inferring dependencies across %d active tasks...\n\n", activeCount)
		dimColor.Printf("Provider: %s", pName)
		if model != "" {
			dimColor.Printf("  Model: %s", model)
		}
		fmt.Println()
		fmt.Println()

		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()

		opts := provider.Options{
			Model:   model,
			Timeout: timeout,
		}

		suggested, err := autodeps.Infer(ctx, prov, opts, s.Plan)
		if err != nil {
			return fmt.Errorf("inference failed: %w", err)
		}

		if len(suggested) == 0 {
			successColor.Printf("No new dependencies suggested — the plan looks good as-is.\n")
			return nil
		}

		// Build task title map for display.
		titleByID := make(map[int]string, len(s.Plan.Tasks))
		for _, t := range s.Plan.Tasks {
			titleByID[t.ID] = t.Title
		}

		// Build existing-deps set for filtering display.
		existingDeps := make(map[string]bool)
		for _, t := range s.Plan.Tasks {
			for _, d := range t.DependsOn {
				existingDeps[fmt.Sprintf("%d->%d", t.ID, d)] = true
			}
		}

		// Print suggestions table.
		warnColor.Printf("Suggested dependencies:\n\n")
		fmt.Printf("  %-6s  %-40s  %-6s  %-40s\n", "Task", "Title", "Dep", "Dep Title")
		fmt.Printf("  %s  %s  %s  %s\n",
			strings.Repeat("─", 6), strings.Repeat("─", 40),
			strings.Repeat("─", 6), strings.Repeat("─", 40))

		// Sort by task ID for deterministic output.
		taskIDs := make([]int, 0, len(suggested))
		for id := range suggested {
			taskIDs = append(taskIDs, id)
		}
		sort.Ints(taskIDs)

		totalNew := 0
		for _, taskID := range taskIDs {
			depIDs := suggested[taskID]
			sort.Ints(depIDs)
			for _, depID := range depIDs {
				key := fmt.Sprintf("%d->%d", taskID, depID)
				marker := "  "
				if existingDeps[key] {
					marker = "* "
					dimColor.Printf("%s#%-5d  %-40s  #%-5d  %-40s  (already exists)\n",
						marker, taskID, truncateStr(titleByID[taskID], 40),
						depID, truncateStr(titleByID[depID], 40))
					continue
				}
				totalNew++
				fmt.Printf("%s#%-5d  %-40s  #%-5d  %-40s\n",
					marker, taskID, truncateStr(titleByID[taskID], 40),
					depID, truncateStr(titleByID[depID], 40))
			}
		}
		fmt.Println()

		if totalNew == 0 {
			successColor.Printf("All suggested dependencies already exist in the plan.\n")
			return nil
		}

		if autoDepsDryRun && !autoDepsApply {
			dimColor.Printf("%d new dependencies suggested. Re-run with --apply to update the plan.\n", totalNew)
			return nil
		}

		// --apply mode: apply and save.
		added, skippedMsgs := autodeps.Apply(s.Plan, suggested)

		if len(skippedMsgs) > 0 {
			warnColor.Printf("Skipped %d suggestions:\n", len(skippedMsgs))
			for _, msg := range skippedMsgs {
				dimColor.Printf("  - %s\n", msg)
			}
			fmt.Println()
		}

		if err := s.Save(); err != nil {
			return fmt.Errorf("saving state: %w", err)
		}

		successColor.Printf("Applied %d new dependencies to the plan.\n", added)
		return nil
	},
}

func init() {
	taskAutoDepsCmd.Flags().BoolVar(&autoDepsDryRun, "dry-run", false, "Print suggested dependencies without saving (default when --apply is not set)")
	taskAutoDepsCmd.Flags().BoolVar(&autoDepsApply, "apply", false, "Apply inferred dependencies to the plan and save")
	taskAutoDepsCmd.Flags().StringVar(&autoDepsProvider, "provider", "", "AI provider to use (anthropic, openai, ollama, claudecode)")
	taskAutoDepsCmd.Flags().StringVar(&autoDepsModel, "model", "", "Model override for the AI provider")
	taskAutoDepsCmd.Flags().StringVar(&autoDepsTimeout, "timeout", "5m", "Timeout for the AI call (e.g. 2m, 300s)")

	taskCmd.AddCommand(taskAutoDepsCmd)
}
