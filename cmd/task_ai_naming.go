package cmd

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/naming"
	"github.com/blechschmidt/cloop/pkg/provider"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var (
	aiNamingProvider string
	aiNamingModel    string
	aiNamingTimeout  string
	aiNamingDryRun   bool
	aiNamingApply    bool
)

var taskAINamingCmd = &cobra.Command{
	Use:   "ai-naming",
	Short: "AI batch title normalization to consistent verb-object imperative format",
	Long: `Send all task titles to the AI and ask it to rewrite them to follow
a consistent verb-object imperative format (e.g. 'Implement X', 'Fix Y',
'Add Z', 'Refactor W').

The AI returns a JSON map of task ID -> suggested title.

Modes:
  --dry-run   (default) Print a two-column diff table without saving
  --apply     Write updated titles back to state

Examples:
  cloop task ai-naming              # dry-run: show suggested renames
  cloop task ai-naming --dry-run    # explicit dry-run
  cloop task ai-naming --apply      # normalize and save to plan`,
	RunE: func(cmd *cobra.Command, args []string) error {
		// Default to dry-run unless --apply is set.
		if !aiNamingApply {
			aiNamingDryRun = true
		}

		workdir, _ := os.Getwd()
		s, err := state.Load(workdir)
		if err != nil {
			return err
		}
		if !s.PMMode || s.Plan == nil || len(s.Plan.Tasks) == 0 {
			return fmt.Errorf("no task plan found — run 'cloop run --pm' to create one")
		}

		cfg, err := config.Load(workdir)
		if err != nil {
			return fmt.Errorf("loading config: %w", err)
		}
		applyEnvOverrides(cfg)

		pName := aiNamingProvider
		if pName == "" {
			pName = cfg.Provider
		}
		if pName == "" && s.Provider != "" {
			pName = s.Provider
		}
		if pName == "" {
			pName = autoSelectProvider()
		}

		model := aiNamingModel
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
		if aiNamingTimeout != "" {
			timeout, err = time.ParseDuration(aiNamingTimeout)
			if err != nil {
				return fmt.Errorf("invalid timeout: %w", err)
			}
		}

		headerColor := color.New(color.FgCyan, color.Bold)
		dimColor := color.New(color.Faint)
		changedColor := color.New(color.FgYellow)
		unchangedColor := color.New(color.Faint)
		successColor := color.New(color.FgGreen)

		headerColor.Printf("Normalizing %d task titles...\n\n", len(s.Plan.Tasks))
		dimColor.Printf("Provider: %s", pName)
		if model != "" {
			dimColor.Printf("  Model: %s", model)
		}
		fmt.Println()
		fmt.Println()

		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()

		prompt := naming.NormalizationPrompt(s.Plan.Tasks)
		opts := provider.Options{
			Model:   model,
			Timeout: timeout,
		}

		raw, err := prov.Complete(ctx, prompt, opts)
		if err != nil {
			return fmt.Errorf("AI call failed: %w", err)
		}

		suggestions, err := naming.ParseResponse(raw.Output)
		if err != nil {
			return fmt.Errorf("parsing AI response: %w", err)
		}

		// Build task index.
		taskByID := make(map[int]string, len(s.Plan.Tasks))
		for _, t := range s.Plan.Tasks {
			taskByID[t.ID] = t.Title
		}

		// Collect sorted IDs for deterministic output.
		ids := make([]int, 0, len(suggestions))
		for id := range suggestions {
			ids = append(ids, id)
		}
		sort.Ints(ids)

		// Print diff table.
		colW := 48
		fmt.Printf("  %-6s  %-*s  %-*s\n", "ID", colW, "Current Title", colW, "Suggested Title")
		fmt.Printf("  %s  %s  %s\n",
			strings.Repeat("─", 6),
			strings.Repeat("─", colW),
			strings.Repeat("─", colW))

		changedCount := 0
		for _, id := range ids {
			current, ok := taskByID[id]
			if !ok {
				dimColor.Printf("  %-6d  %-*s  (unknown task ID, skipped)\n", id, colW, "")
				continue
			}
			suggested := suggestions[id]
			if suggested == current {
				unchangedColor.Printf("  #%-5d  %-*s  %-*s  (unchanged)\n",
					id, colW, truncateStr(current, colW), colW, truncateStr(suggested, colW))
			} else {
				changedCount++
				changedColor.Printf("  #%-5d  %-*s  %-*s\n",
					id, colW, truncateStr(current, colW), colW, truncateStr(suggested, colW))
			}
		}
		fmt.Println()

		if changedCount == 0 {
			successColor.Printf("All titles already follow the imperative format — no changes needed.\n")
			return nil
		}

		if aiNamingDryRun && !aiNamingApply {
			dimColor.Printf("%d title(s) would be updated. Re-run with --apply to save changes.\n", changedCount)
			return nil
		}

		// --apply: write back to state.
		applied := 0
		for _, t := range s.Plan.Tasks {
			if sug, ok := suggestions[t.ID]; ok && sug != t.Title {
				t.Title = sug
				applied++
			}
		}

		if err := s.Save(); err != nil {
			return fmt.Errorf("saving state: %w", err)
		}

		successColor.Printf("Applied %d title update(s) to the plan.\n", applied)
		return nil
	},
}

func init() {
	taskAINamingCmd.Flags().BoolVar(&aiNamingDryRun, "dry-run", false, "Print diff table without saving (default when --apply is not set)")
	taskAINamingCmd.Flags().BoolVar(&aiNamingApply, "apply", false, "Write updated titles back to state")
	taskAINamingCmd.Flags().StringVar(&aiNamingProvider, "provider", "", "AI provider to use (anthropic, openai, ollama, claudecode)")
	taskAINamingCmd.Flags().StringVar(&aiNamingModel, "model", "", "Model override for the AI provider")
	taskAINamingCmd.Flags().StringVar(&aiNamingTimeout, "timeout", "5m", "Timeout for the AI call (e.g. 2m, 300s)")

	taskCmd.AddCommand(taskAINamingCmd)
}
