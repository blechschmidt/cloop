package cmd

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/narrative"
	"github.com/blechschmidt/cloop/pkg/provider"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var (
	narrativeProvider string
	narrativeModel    string
	narrativeFormat   string
	narrativeOutput   string
	narrativeTimeout  string
)

var narrativeCmd = &cobra.Command{
	Use:   "narrative",
	Short: "AI-generated stakeholder story report for the current project",
	Long: `Generate a polished prose narrative of the project's progress aimed at
non-technical stakeholders: an introduction with the goal, chapters covering
completed work clusters, current state, and what's next.

Unlike 'cloop retro' (team retrospective) or 'cloop standup' (daily sync),
'cloop narrative' is a flowing executive-level "project story" suitable for
board updates, investor briefings, or status emails.

Output formats:
  markdown  — Markdown document with a metrics summary table and prose story
  html      — Self-contained HTML with clean typography, no external dependencies

Examples:
  cloop task narrative
  cloop task narrative --format html --output story.html
  cloop task narrative --format markdown --output story.md
  cloop task narrative --provider anthropic`,
	RunE: func(cmd *cobra.Command, args []string) error {
		workdir, _ := os.Getwd()

		s, err := state.Load(workdir)
		if err != nil {
			return fmt.Errorf("loading state: %w", err)
		}
		if s.Goal == "" {
			return fmt.Errorf("no project initialized — run 'cloop init' first")
		}
		if s.Plan == nil || len(s.Plan.Tasks) == 0 {
			return fmt.Errorf("no task plan found — run 'cloop run --pm' first")
		}

		cfg, err := config.Load(workdir)
		if err != nil {
			return fmt.Errorf("loading config: %w", err)
		}

		// Resolve provider
		providerName := narrativeProvider
		if providerName == "" {
			providerName = cfg.Provider
		}
		if providerName == "" {
			providerName = s.Provider
		}
		if providerName == "" {
			providerName = autoSelectProvider()
		}

		// Resolve model
		model := narrativeModel
		if model == "" {
			model = s.Model
		}
		if model == "" {
			switch providerName {
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
			Name:             providerName,
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

		timeout := 120 * time.Second
		if narrativeTimeout != "" {
			timeout, err = time.ParseDuration(narrativeTimeout)
			if err != nil {
				return fmt.Errorf("invalid --timeout: %w", err)
			}
		}

		dimColor := color.New(color.Faint)
		dimColor.Fprintf(os.Stderr, "Generating stakeholder narrative with %s...\n\n", prov.Name())

		ctx := context.Background()
		prose, err := narrative.GenerateFromPlan(ctx, prov, model, timeout, s.Goal, s.Plan)
		if err != nil {
			return fmt.Errorf("narrative generation failed: %w", err)
		}

		metrics := narrative.CollectMetrics(s.Plan)

		var output string
		switch narrativeFormat {
		case "html":
			output = narrative.RenderHTML(prose, s.Goal, metrics)
		default: // markdown
			output = narrative.RenderMarkdown(prose, s.Goal, metrics)
		}

		dest := narrativeOutput
		if dest != "" {
			if err := os.WriteFile(dest, []byte(output), 0o644); err != nil {
				return fmt.Errorf("writing output file: %w", err)
			}
			color.New(color.FgGreen).Printf("Narrative saved to %s\n", dest)
		} else {
			fmt.Print(output)
		}

		return nil
	},
}

func init() {
	narrativeCmd.Flags().StringVar(&narrativeProvider, "provider", "", "Provider to use for generation")
	narrativeCmd.Flags().StringVar(&narrativeModel, "model", "", "Model to use for generation")
	narrativeCmd.Flags().StringVarP(&narrativeFormat, "format", "f", "markdown", "Output format: markdown (default) or html")
	narrativeCmd.Flags().StringVarP(&narrativeOutput, "output", "o", "", "Write output to file")
	narrativeCmd.Flags().StringVar(&narrativeTimeout, "timeout", "", "Generation timeout (e.g. 120s, 2m)")
	taskCmd.AddCommand(narrativeCmd)
}
