package cmd

import (
	"context"
	"fmt"
	"os"
	"os/exec"
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
	runTimeout      string
	runMaxTokens    int
	verbose         bool
	dryRun          bool
	continueSteps   int
	runStepsLimit   int
	autoEvolve      bool
	runProvider     string
	pmMode          bool
	planOnly        bool
	retryFailed     bool
	replan          bool
	maxFailures     int
	contextSteps    int
	stepDelay       string
	onComplete      string
	tokenBudget     int
	innovateMode    bool
	parallelMode    bool
	injectContext    bool
	adaptiveReplan   bool
	reviewMode       bool
	verifyTasks      bool
	maxVerifyRetries int
	useMemory        bool
	learn            bool
	memoryLimit      int
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

		// Apply CLOOP_* environment variable overrides to config (env > config file).
		applyEnvOverrides(cfg)

		// Determine provider (flag > env > config > state > auto-detect > claudecode)
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
		if model == "" {
			model = os.Getenv("CLOOP_MODEL")
		}
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

		// Merge PM mode: flag | plan-only | replan | parallel | persisted state
		effectivePMMode := pmMode || planOnly || replan || parallelMode
		if !effectivePMMode && projectState != nil && projectState.PMMode {
			effectivePMMode = true
		}

		orchCfg := orchestrator.Config{
			WorkDir:          workdir,
			Model:            model,
			MaxTokens:        runMaxTokens,
			StepTimeout:      timeout,
			Verbose:          verbose,
			DryRun:           dryRun,
			PMMode:           effectivePMMode,
			PlanOnly:         planOnly,
			RetryFailed:      retryFailed,
			Replan:           replan,
			MaxFailures:      maxFailures,
			ContextSteps:     contextSteps,
			StepDelay:        delay,
			StepsLimit:       runStepsLimit,
			ProviderName:     providerName,
			ProviderCfg:      provCfg,
			TokenBudget:      tokenBudget,
			InnovateMode:     innovateMode,
			Parallel:         parallelMode,
			InjectContext:    injectContext,
			AdaptiveReplan:   adaptiveReplan,
			ReviewMode:       reviewMode,
			Verify:           verifyTasks,
			MaxVerifyRetries: maxVerifyRetries,
			UseMemory:        useMemory,
			Learn:            learn,
			MemoryLimit:      memoryLimit,
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

		// Build context: support total session timeout via --timeout flag.
		var ctx context.Context
		var cancel context.CancelFunc
		if runTimeout != "" {
			totalTimeout, err := time.ParseDuration(runTimeout)
			if err != nil {
				return fmt.Errorf("invalid --timeout: %w", err)
			}
			ctx, cancel = context.WithTimeout(context.Background(), totalTimeout)
			fmt.Printf("Session timeout: %s\n", totalTimeout)
		} else {
			ctx, cancel = context.WithCancel(context.Background())
		}
		defer cancel()

		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		go func() {
			<-sigCh
			fmt.Println("\n⏸ Pausing after current step...")
			cancel()
		}()

		runErr := orc.Run(ctx)

		// Run the on-complete hook if provided and session ended normally.
		if onComplete != "" {
			finalState, _ := state.Load(workdir)
			if finalState != nil && (finalState.Status == "complete" || finalState.Status == "evolving") {
				fmt.Printf("\nRunning --on-complete hook: %s\n", onComplete)
				hookCmd := exec.Command("sh", "-c", onComplete)
				hookCmd.Stdout = os.Stdout
				hookCmd.Stderr = os.Stderr
				if err := hookCmd.Run(); err != nil {
					fmt.Printf("on-complete hook exited with error: %v\n", err)
				}
			}
		}

		return runErr
	},
}

// autoSelectProvider picks a provider based on available environment variables.
// Priority: anthropic > openai > claudecode (always available as fallback).
func autoSelectProvider() string {
	if os.Getenv("ANTHROPIC_API_KEY") != "" || os.Getenv("CLOOP_ANTHROPIC_API_KEY") != "" {
		return "anthropic"
	}
	if os.Getenv("OPENAI_API_KEY") != "" || os.Getenv("CLOOP_OPENAI_API_KEY") != "" {
		return "openai"
	}
	return "claudecode"
}

// applyEnvOverrides applies CLOOP_* environment variables onto the config.
// Env vars take precedence over config file values but are overridden by CLI flags.
//
//   CLOOP_PROVIDER            → config.Provider
//   CLOOP_ANTHROPIC_API_KEY   → config.Anthropic.APIKey
//   CLOOP_ANTHROPIC_BASE_URL  → config.Anthropic.BaseURL
//   CLOOP_OPENAI_API_KEY      → config.OpenAI.APIKey
//   CLOOP_OPENAI_BASE_URL     → config.OpenAI.BaseURL
//   CLOOP_OLLAMA_BASE_URL     → config.Ollama.BaseURL
func applyEnvOverrides(cfg *config.Config) {
	if v := os.Getenv("CLOOP_PROVIDER"); v != "" {
		cfg.Provider = v
	}
	if v := os.Getenv("CLOOP_ANTHROPIC_API_KEY"); v != "" {
		cfg.Anthropic.APIKey = v
	}
	if v := os.Getenv("CLOOP_ANTHROPIC_BASE_URL"); v != "" {
		cfg.Anthropic.BaseURL = v
	}
	if v := os.Getenv("CLOOP_OPENAI_API_KEY"); v != "" {
		cfg.OpenAI.APIKey = v
	}
	if v := os.Getenv("CLOOP_OPENAI_BASE_URL"); v != "" {
		cfg.OpenAI.BaseURL = v
	}
	if v := os.Getenv("CLOOP_OLLAMA_BASE_URL"); v != "" {
		cfg.Ollama.BaseURL = v
	}
}

func init() {
	runCmd.Flags().StringVar(&runModel, "model", "", "Override model for this run")
	runCmd.Flags().StringVar(&stepTimeout, "step-timeout", "10m", "Timeout per step")
	runCmd.Flags().StringVar(&runTimeout, "timeout", "", "Total session timeout (e.g. 30m, 2h); 0 = no limit")
	runCmd.Flags().IntVar(&runMaxTokens, "max-tokens", 0, "Max output tokens per step")
	runCmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "Verbose output")
	runCmd.Flags().BoolVar(&dryRun, "dry-run", false, "Show prompts without running the provider")
	runCmd.Flags().IntVar(&continueSteps, "add-steps", 0, "Add more steps to max before running")
	runCmd.Flags().IntVar(&runStepsLimit, "steps", 0, "Run at most N steps this session (not persisted; 0 = no session limit)")
	runCmd.Flags().BoolVar(&autoEvolve, "auto-evolve", false, "After goal completion, keep improving the project autonomously")
	runCmd.Flags().StringVar(&runProvider, "provider", "", "AI provider: anthropic, openai, ollama, claudecode")
	runCmd.Flags().BoolVar(&pmMode, "pm", false, "Product manager mode: decompose goal into tasks and execute them")
	runCmd.Flags().BoolVar(&planOnly, "plan-only", false, "PM mode: decompose goal into tasks but do not execute (implies --pm)")
	runCmd.Flags().BoolVar(&retryFailed, "retry-failed", false, "PM mode: retry tasks that previously failed")
	runCmd.Flags().BoolVar(&replan, "replan", false, "PM mode: discard existing plan and re-decompose the goal (implies --pm)")
	runCmd.Flags().IntVar(&maxFailures, "max-failures", 3, "PM mode: consecutive task failures before stopping")
	runCmd.Flags().IntVar(&contextSteps, "context-steps", 3, "Recent steps to include in prompts (0 = disable context)")
	runCmd.Flags().StringVar(&stepDelay, "step-delay", "", "Delay between steps (e.g. 5s, 1m)")
	runCmd.Flags().StringVar(&onComplete, "on-complete", "", "Shell command to run when the goal is complete (e.g. 'notify-send done')")
	runCmd.Flags().IntVar(&tokenBudget, "token-budget", 0, "Stop when cumulative tokens (in+out) reach this limit (0 = unlimited)")
	runCmd.Flags().BoolVar(&innovateMode, "innovate", false, "Innovation mode: encourage creative, unconventional features in evolve iterations")
	runCmd.Flags().BoolVar(&parallelMode, "parallel", false, "PM mode: run all dependency-ready tasks concurrently (implies --pm)")
	runCmd.Flags().BoolVar(&injectContext, "inject-context", false, "PM mode: inject project context (git status, file tree) into task prompts")
	runCmd.Flags().BoolVar(&adaptiveReplan, "adaptive-replan", false, "PM mode: re-plan remaining tasks with AI after a failure")
	runCmd.Flags().BoolVar(&reviewMode, "review", false, "PM mode: pause before each task for human approval (y/n/skip/quit)")
	runCmd.Flags().BoolVar(&verifyTasks, "verify", false, "PM mode: run a second AI verification pass after each TASK_DONE to confirm genuine completion")
	runCmd.Flags().IntVar(&maxVerifyRetries, "max-verify-retries", 2, "PM mode: max times a task can be re-queued by verification failure before marking it failed")
	runCmd.Flags().BoolVar(&useMemory, "use-memory", false, "Inject past session learnings into prompts")
	runCmd.Flags().BoolVar(&learn, "learn", false, "Extract key learnings at end of session and store in project memory")
	runCmd.Flags().IntVar(&memoryLimit, "memory-limit", 20, "Max number of memory entries to inject into prompts (0 = all)")
	rootCmd.AddCommand(runCmd)
}
