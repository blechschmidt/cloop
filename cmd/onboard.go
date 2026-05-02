package cmd

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/onboard"
	"github.com/blechschmidt/cloop/pkg/provider"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var (
	onboardOutput   string
	onboardProvider string
	onboardModel    string
	onboardTimeout  string
)

var onboardCmd = &cobra.Command{
	Use:   "onboard",
	Short: "Generate an AI-powered contributor onboarding guide",
	Long: `Generate a comprehensive ONBOARDING.md for new contributors.

Collects project goal, task history, file structure, active integrations,
configured providers, and knowledge base entries, then asks the AI to write
a structured Markdown onboarding guide covering purpose, architecture,
setup, testing, key commands, and contribution workflow.

Examples:
  cloop onboard                        # write ONBOARDING.md in current directory
  cloop onboard --output docs/ONBOARDING.md
  cloop onboard --provider anthropic
  cloop onboard --provider anthropic --model claude-opus-4-5`,
	RunE: func(cmd *cobra.Command, args []string) error {
		workdir, _ := os.Getwd()

		s, err := state.Load(workdir)
		if err != nil {
			return fmt.Errorf("loading state: %w", err)
		}
		if s.Goal == "" {
			return fmt.Errorf("no project initialized — run 'cloop init' first")
		}

		cfg, err := config.Load(workdir)
		if err != nil {
			return fmt.Errorf("loading config: %w", err)
		}

		// Resolve provider
		providerName := onboardProvider
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
		model := onboardModel
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

		timeout := 180 * time.Second
		if onboardTimeout != "" {
			timeout, err = time.ParseDuration(onboardTimeout)
			if err != nil {
				return fmt.Errorf("invalid --timeout: %w", err)
			}
		}

		outputFile := onboardOutput
		if outputFile == "" {
			outputFile = "ONBOARDING.md"
		}

		dimColor := color.New(color.Faint)
		dimColor.Printf("Collecting project context...\n")

		inp, err := onboard.Collect(workdir, s, cfg, providerName, model)
		if err != nil {
			return fmt.Errorf("collecting context: %w", err)
		}

		dimColor.Printf("Generating onboarding guide with %s...\n", prov.Name())

		ctx := context.Background()
		guide, err := onboard.Generate(ctx, prov, model, timeout, inp)
		if err != nil {
			return fmt.Errorf("generating guide: %w", err)
		}

		if err := os.WriteFile(outputFile, []byte(guide), 0o644); err != nil {
			return fmt.Errorf("writing %s: %w", outputFile, err)
		}

		color.New(color.FgGreen, color.Bold).Printf("Onboarding guide written to %s\n", outputFile)
		return nil
	},
}

func init() {
	onboardCmd.Flags().StringVarP(&onboardOutput, "output", "o", "", "Output file path (default: ONBOARDING.md)")
	onboardCmd.Flags().StringVar(&onboardProvider, "provider", "", "Provider to use for generation")
	onboardCmd.Flags().StringVar(&onboardModel, "model", "", "Model to use for generation")
	onboardCmd.Flags().StringVar(&onboardTimeout, "timeout", "", "Generation timeout (e.g. 120s, 3m)")
	rootCmd.AddCommand(onboardCmd)
}
