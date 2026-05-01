package cmd

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/orchestrator"
	"github.com/blechschmidt/cloop/pkg/provider"
	"github.com/spf13/cobra"
)

var (
	runModel        string
	stepTimeout     string
	runMaxTokens    int
	verbose         bool
	dryRun          bool
	continueSteps   int
	autoEvolve      bool
	runProvider     string
	pmMode          bool
)

var runCmd = &cobra.Command{
	Use:   "run",
	Short: "Start or continue the autonomous feedback loop",
	Long: `Run the cloop feedback loop. The AI provider will work through
the project goal step by step until completion or max steps.

Press Ctrl+C to pause gracefully.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		workdir, _ := os.Getwd()

		timeout, err := time.ParseDuration(stepTimeout)
		if err != nil {
			return fmt.Errorf("invalid step-timeout: %w", err)
		}

		// Load config
		cfg, err := config.Load(workdir)
		if err != nil {
			return fmt.Errorf("loading config: %w", err)
		}

		// Determine provider (flag > config > default)
		providerName := runProvider
		if providerName == "" {
			providerName = cfg.Provider
		}
		if providerName == "" {
			providerName = "claudecode"
		}

		// Build provider config
		model := runModel
		provCfg := provider.ProviderConfig{
			Name:             providerName,
			AnthropicAPIKey:  cfg.Anthropic.APIKey,
			AnthropicBaseURL: cfg.Anthropic.BaseURL,
			OpenAIAPIKey:     cfg.OpenAI.APIKey,
			OpenAIBaseURL:    cfg.OpenAI.BaseURL,
			OllamaBaseURL:    cfg.Ollama.BaseURL,
		}

		// Apply per-provider model defaults from config if not overridden by flag
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

		prov, err := provider.Build(provCfg)
		if err != nil {
			return fmt.Errorf("provider: %w", err)
		}

		orchCfg := orchestrator.Config{
			WorkDir:      workdir,
			Model:        model,
			MaxTokens:    runMaxTokens,
			StepTimeout:  timeout,
			Verbose:      verbose,
			DryRun:       dryRun,
			PMMode:       pmMode,
			ProviderName: providerName,
			ProviderCfg:  provCfg,
		}

		orc, err := orchestrator.New(orchCfg, prov)
		if err != nil {
			return err
		}

		if continueSteps > 0 {
			orc.AddSteps(continueSteps)
		}
		if autoEvolve {
			orc.SetAutoEvolve(true)
		}

		// Handle Ctrl+C gracefully
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		go func() {
			<-sigCh
			fmt.Println("\n⏸ Pausing after current step...")
			cancel()
		}()

		return orc.Run(ctx)
	},
}

func init() {
	runCmd.Flags().StringVar(&runModel, "model", "", "Override model for this run")
	runCmd.Flags().StringVar(&stepTimeout, "step-timeout", "10m", "Timeout per step")
	runCmd.Flags().IntVar(&runMaxTokens, "max-tokens", 0, "Max output tokens per step")
	runCmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "Verbose output")
	runCmd.Flags().BoolVar(&dryRun, "dry-run", false, "Show prompts without running the provider")
	runCmd.Flags().IntVar(&continueSteps, "add-steps", 0, "Add more steps to max before running")
	runCmd.Flags().BoolVar(&autoEvolve, "auto-evolve", false, "After goal completion, keep improving the project autonomously")
	runCmd.Flags().StringVar(&runProvider, "provider", "", "AI provider: anthropic, openai, ollama, claudecode")
	runCmd.Flags().BoolVar(&pmMode, "pm", false, "Product manager mode: decompose goal into tasks and execute them")
	rootCmd.AddCommand(runCmd)
}
