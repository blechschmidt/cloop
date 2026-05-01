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
	"github.com/blechschmidt/cloop/pkg/state"
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
	planOnly        bool
	retryFailed     bool
	replan          bool
	maxFailures     int
	contextSteps    int
	stepDelay       string
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

		var delay time.Duration
		if stepDelay != "" {
			delay, err = time.ParseDuration(stepDelay)
			if err != nil {
				return fmt.Errorf("invalid step-delay: %w", err)
			}
		}

		// Load config
		cfg, err := config.Load(workdir)
		if err != nil {
			return fmt.Errorf("loading config: %w", err)
		}

		// Load state to check for persisted provider/mode settings
		projectState, _ := state.Load(workdir)

		// Determine provider (flag > config > state > auto-detect > claudecode)
		providerName := runProvider
		if providerName == "" {
			providerName = cfg.Provider
		}
		if providerName == "" && projectState != nil {
			providerName = projectState.Provider
		}
		if providerName == "" {
			providerName = autoSelectProvider()
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

		// Merge PM mode: flag | plan-only | replan | persisted state
		effectivePMMode := pmMode || planOnly || replan
		if !effectivePMMode && projectState != nil && projectState.PMMode {
			effectivePMMode = true
		}

		orchCfg := orchestrator.Config{
			WorkDir:      workdir,
			Model:        model,
			MaxTokens:    runMaxTokens,
			StepTimeout:  timeout,
			Verbose:      verbose,
			DryRun:       dryRun,
			PMMode:       effectivePMMode,
			PlanOnly:     planOnly,
			RetryFailed:  retryFailed,
			Replan:       replan,
			MaxFailures:  maxFailures,
			ContextSteps: contextSteps,
			StepDelay:    delay,
			ProviderName: providerName,
			ProviderCfg:  provCfg,
		}

		orc, err := orchestrator.New(orchCfg, prov)
		if err != nil {
			return err
		}

		// Persist the resolved provider in state so subsequent runs default to the same provider.
		orc.SetProvider(providerName)

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

// autoSelectProvider picks a provider based on available environment variables.
// Priority: anthropic > openai > claudecode (always available as fallback).
func autoSelectProvider() string {
	if os.Getenv("ANTHROPIC_API_KEY") != "" {
		return "anthropic"
	}
	if os.Getenv("OPENAI_API_KEY") != "" {
		return "openai"
	}
	return "claudecode"
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
	runCmd.Flags().BoolVar(&planOnly, "plan-only", false, "PM mode: decompose goal into tasks but do not execute (implies --pm)")
	runCmd.Flags().BoolVar(&retryFailed, "retry-failed", false, "PM mode: retry tasks that previously failed")
	runCmd.Flags().BoolVar(&replan, "replan", false, "PM mode: discard existing plan and re-decompose the goal (implies --pm)")
	runCmd.Flags().IntVar(&maxFailures, "max-failures", 3, "PM mode: consecutive task failures before stopping")
	runCmd.Flags().IntVar(&contextSteps, "context-steps", 3, "Recent steps to include in prompts (0 = disable context)")
	runCmd.Flags().StringVar(&stepDelay, "step-delay", "", "Delay between steps (e.g. 5s, 1m)")
	rootCmd.AddCommand(runCmd)
}
