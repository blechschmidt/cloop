package cmd

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/blechschmidt/cloop/pkg/cache"
	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/hooks"
	"github.com/blechschmidt/cloop/pkg/metrics"
	"github.com/blechschmidt/cloop/pkg/orchestrator"
	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/profile"
	"github.com/blechschmidt/cloop/pkg/provider"
	"github.com/blechschmidt/cloop/pkg/provider/cached"
	"github.com/blechschmidt/cloop/pkg/provider/fallback"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/spf13/cobra"
)

var (
	runModel        string
	stepTimeout     string
	runTimeout      string
	runMaxTokens    int
	runTemperature  float64
	runTopP         float64
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
	maxParallel     int
	injectContext    bool
	adaptiveReplan   bool
	reviewMode       bool
	verifyTasks      bool
	maxVerifyRetries int
	useMemory        bool
	learn            bool
	memoryLimit      int
	webhookURL        string
	webhookEvents     []string
	webhookSecret     string
	fallbackProviders []string
	streamOutput      bool
	notifyEnabled     bool
	costLimit         float64
	gitMode              bool
	diagnoseFailures     bool
	contextTokenLimit    int
	optimizePlan         bool
	optimizeInteractive  bool
	metricsAddr          string
	noDedup              bool
	runTags              []string
	scriptVerify         bool
	runProfile           string
	autoSplit            bool
	skipHealthCheck      bool
	multiAgentMode       bool
	postReview           bool
	healRetries          int
	noHeal               bool
	riskCheck            bool
	riskForce            bool
	consensusN           int
	noContextInject      bool
	requireApproval      bool
	skipClarify          bool
	autoEvalRun          bool
	docsUpdateOnComplete bool
	docsUpdateFile       string
	noCache              bool
	cacheTTL             string
	cacheMaxSize         int
	mockMode             bool
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

		// Apply named profile: --profile flag > active profile from ~/.cloop/active_profile.
		// Profiles overlay provider/model/key settings onto the config before CLI flags take effect.
		activeProfileName := runProfile
		if activeProfileName == "" {
			activeProfileName = profile.GetActive()
		}
		if activeProfileName != "" {
			if prof, err := profile.Get(activeProfileName); err == nil {
				profile.Apply(*prof, cfg)
			} else {
				fmt.Fprintf(os.Stderr, "warning: profile %q not found: %v\n", activeProfileName, err)
			}
		}

		// --mock is a shorthand for --provider mock
		if mockMode {
			runProvider = "mock"
		}

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
			Name:              providerName,
			AnthropicAPIKey:   cfg.Anthropic.APIKey,
			AnthropicBaseURL:  cfg.Anthropic.BaseURL,
			OpenAIAPIKey:      cfg.OpenAI.APIKey,
			OpenAIBaseURL:     cfg.OpenAI.BaseURL,
			OllamaBaseURL:     cfg.Ollama.BaseURL,
			MockResponsesFile: cfg.Mock.ResponsesFile,
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

		// Resolve inference parameters: flag > per-provider config > nil (provider default).
		// A flag value of -1 means "not set"; use config if present.
		effectiveTemperature := resolveFloatParam(runTemperature, providerName, cfg, "temperature")
		effectiveTopP := resolveFloatParam(runTopP, providerName, cfg, "top_p")
		effectiveFreqPenalty := resolveFloatParam(-1, providerName, cfg, "frequency_penalty")

		// MaxTokens: flag > per-provider config > 0 (orchestrator default)
		effectiveMaxTokens := runMaxTokens
		if effectiveMaxTokens == 0 {
			switch providerName {
			case "anthropic":
				effectiveMaxTokens = cfg.Anthropic.MaxTokens
			case "openai":
				effectiveMaxTokens = cfg.OpenAI.MaxTokens
			case "ollama":
				effectiveMaxTokens = cfg.Ollama.MaxTokens
			}
		}

		prov, err := buildProviderWithFallback(providerName, provCfg, fallbackProviders, cfg)
		if err != nil {
			return fmt.Errorf("provider: %w", err)
		}

		// Wrap with response cache unless --no-cache is set.
		if !noCache {
			ttl := cache.DefaultTTL
			if cacheTTL != "" {
				ttl, err = time.ParseDuration(cacheTTL)
				if err != nil {
					return fmt.Errorf("invalid --cache-ttl: %w", err)
				}
			}
			maxSz := cacheMaxSize
			if maxSz <= 0 {
				maxSz = cache.DefaultMaxSize
			}
			if c, cacheErr := cache.New(workdir, ttl, maxSz); cacheErr == nil {
				prov = cached.New(prov, c)
			}
		}

		// --max-parallel / -j implies parallel mode.
		if maxParallel > 0 {
			parallelMode = true
		}
		// Apply config-level MaxParallel as default when flag not set.
		effectiveMaxParallel := maxParallel
		if effectiveMaxParallel == 0 {
			effectiveMaxParallel = cfg.MaxParallel
		}

		// Merge PM mode: flag | plan-only | replan | parallel | persisted state
		effectivePMMode := pmMode || planOnly || replan || parallelMode
		if !effectivePMMode && projectState != nil && projectState.PMMode {
			effectivePMMode = true
		}

		// Merge skip-clarify: CLI flag | persisted state (set by 'cloop init --skip-clarify')
		effectiveSkipClarify := skipClarify
		if !effectiveSkipClarify && projectState != nil && projectState.SkipClarify {
			effectiveSkipClarify = true
		}

		// Webhook: flag overrides config file
		effectiveWebhookURL := webhookURL
		if effectiveWebhookURL == "" {
			effectiveWebhookURL = cfg.Webhook.URL
		}
		effectiveWebhookEvents := webhookEvents
		if len(effectiveWebhookEvents) == 0 {
			effectiveWebhookEvents = cfg.Webhook.Events
		}
		effectiveWebhookSecret := webhookSecret
		if effectiveWebhookSecret == "" {
			effectiveWebhookSecret = cfg.Webhook.Secret
		}

		// Set up metrics collection when --metrics-addr is provided.
		var runMetrics *metrics.Metrics
		if metricsAddr != "" {
			runMetrics = metrics.New(providerName, model)
			mux := http.NewServeMux()
			mux.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
				fmt.Fprint(w, runMetrics.Prometheus())
			})
			srv := &http.Server{Addr: metricsAddr, Handler: mux}
			go func() {
				if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
					fmt.Fprintf(os.Stderr, "metrics server: %v\n", err)
				}
			}()
			fmt.Printf("Prometheus metrics: http://%s/metrics\n", metricsAddr)
		}

		// Merge --log-json flag with config file setting.
		effectiveLogJSON := globalLogJSON || cfg.LogJSON

		orchCfg := orchestrator.Config{
			LogJSON:             effectiveLogJSON,
			SkipHealthCheck:     skipHealthCheck,
			MultiAgent:          multiAgentMode,
			PostReview:          postReview,
			ConsensusN:          consensusN,
			NoCodeContextInject: noContextInject,
			RequireApproval:     requireApproval,
			SkipClarify:         effectiveSkipClarify,
			AutoEval:            autoEvalRun,
			SlackWebhookURL:   cfg.Notify.SlackWebhook,
			DiscordWebhookURL: cfg.Notify.DiscordWebhook,
			Hooks: hooks.Config{
				PreTask:        cfg.Hooks.PreTask,
				PostTask:       cfg.Hooks.PostTask,
				PrePlan:        cfg.Hooks.PrePlan,
				PostPlan:       cfg.Hooks.PostPlan,
				PostTaskReview: cfg.Hooks.PostTaskReview,
			},
			WorkDir:          workdir,
			Model:            model,
			MaxTokens:        effectiveMaxTokens,
			Temperature:      effectiveTemperature,
			TopP:             effectiveTopP,
			FrequencyPenalty: effectiveFreqPenalty,
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
			CostLimit:        costLimit,
			InnovateMode:     innovateMode,
			Parallel:         parallelMode,
			MaxParallel:      effectiveMaxParallel,
			InjectContext:    injectContext,
			AdaptiveReplan:   adaptiveReplan,
			ReviewMode:       reviewMode,
			Verify:           verifyTasks,
			MaxVerifyRetries: maxVerifyRetries,
			UseMemory:        useMemory,
			Learn:            learn,
			MemoryLimit:      memoryLimit,
			WebhookURL:       effectiveWebhookURL,
			WebhookEvents:    effectiveWebhookEvents,
			WebhookSecret:    effectiveWebhookSecret,
			Streaming:        streamOutput,
			Notify:           notifyEnabled,
			GitMode:             gitMode,
			DiagnoseFailures:    diagnoseFailures,
			ContextTokenLimit:   contextTokenLimit,
			Optimize:            optimizePlan,
			OptimizeInteractive: optimizeInteractive,
			Metrics:             runMetrics,
			NoDedup:             noDedup,
			TagFilter:           runTags,
			ScriptVerify:        scriptVerify,
			AutoSplit:           autoSplit,
			HealRetries:         healRetries,
			NoHeal:              noHeal,
			RiskCheck:           riskCheck,
			RiskForce:           riskForce,
			Budget:               cfg.Budget,
			NotifyCfg:            cfg.Notify,
			DocsUpdateOnComplete: docsUpdateOnComplete,
			DocsUpdateFile:       docsUpdateFile,
		}

		orc, err := orchestrator.New(orchCfg, prov)
		if err != nil {
			return err
		}

		// Wire up role-based provider routing from config.
		if len(cfg.Router.Routes) > 0 {
			for role, routeProvName := range cfg.Router.Routes {
				routeProvCfg := provider.ProviderConfig{
					Name:             routeProvName,
					AnthropicAPIKey:  cfg.Anthropic.APIKey,
					AnthropicBaseURL: cfg.Anthropic.BaseURL,
					OpenAIAPIKey:     cfg.OpenAI.APIKey,
					OpenAIBaseURL:    cfg.OpenAI.BaseURL,
					OllamaBaseURL:    cfg.Ollama.BaseURL,
				}
				routeProv, err := provider.Build(routeProvCfg)
				if err != nil {
					return fmt.Errorf("router: role %q provider %q: %w", role, routeProvName, err)
				}
				orc.RegisterRoute(pm.AgentRole(role), routeProv)
			}
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

// resolveFloatParam resolves an inference parameter: if flagVal >= 0 it is used;
// otherwise the per-provider config value is returned (nil when not configured).
func resolveFloatParam(flagVal float64, providerName string, cfg *config.Config, param string) *float64 {
	if flagVal >= 0 {
		v := flagVal
		return &v
	}
	// Fall back to per-provider config
	switch param {
	case "temperature":
		switch providerName {
		case "anthropic":
			return cfg.Anthropic.Temperature
		case "openai":
			return cfg.OpenAI.Temperature
		case "ollama":
			return cfg.Ollama.Temperature
		}
	case "top_p":
		switch providerName {
		case "anthropic":
			return cfg.Anthropic.TopP
		case "openai":
			return cfg.OpenAI.TopP
		case "ollama":
			return cfg.Ollama.TopP
		}
	case "frequency_penalty":
		if providerName == "openai" {
			return cfg.OpenAI.FrequencyPenalty
		}
	}
	return nil
}

// buildProviderWithFallback builds the primary provider and optionally wraps it
// in a fallback chain if --fallback names are provided.
func buildProviderWithFallback(primaryName string, primaryCfg provider.ProviderConfig, fallbackNames []string, cfg *config.Config) (provider.Provider, error) {
	primary, err := provider.Build(primaryCfg)
	if err != nil {
		return nil, fmt.Errorf("primary provider %q: %w", primaryName, err)
	}

	if len(fallbackNames) == 0 {
		return primary, nil
	}

	providers := []provider.Provider{primary}
	for _, name := range fallbackNames {
		name = strings.TrimSpace(name)
		if name == "" || name == primaryName {
			continue
		}
		fbCfg := provider.ProviderConfig{
			Name:             name,
			AnthropicAPIKey:  cfg.Anthropic.APIKey,
			AnthropicBaseURL: cfg.Anthropic.BaseURL,
			OpenAIAPIKey:     cfg.OpenAI.APIKey,
			OpenAIBaseURL:    cfg.OpenAI.BaseURL,
			OllamaBaseURL:    cfg.Ollama.BaseURL,
		}
		fb, err := provider.Build(fbCfg)
		if err != nil {
			return nil, fmt.Errorf("fallback provider %q: %w", name, err)
		}
		providers = append(providers, fb)
	}

	if len(providers) == 1 {
		return primary, nil
	}

	return fallback.New(providers)
}

func init() {
	runCmd.Flags().StringVar(&runModel, "model", "", "Override model for this run")
	runCmd.Flags().StringVar(&stepTimeout, "step-timeout", "10m", "Timeout per step")
	runCmd.Flags().StringVar(&runTimeout, "timeout", "", "Total session timeout (e.g. 30m, 2h); 0 = no limit")
	runCmd.Flags().IntVar(&runMaxTokens, "max-tokens", 0, "Max output tokens per step (overrides config provider.max_tokens)")
	runCmd.Flags().Float64Var(&runTemperature, "temperature", -1, "Sampling temperature override (0–1 for Anthropic/Ollama, 0–2 for OpenAI; -1 = use config/provider default)")
	runCmd.Flags().Float64Var(&runTopP, "top-p", -1, "Top-p nucleus sampling override (0–1; -1 = use config/provider default)")
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
	runCmd.Flags().IntVarP(&maxParallel, "max-parallel", "j", 0, "PM mode: max tasks to run concurrently (implies --parallel; 0 = unlimited)")
	runCmd.Flags().BoolVar(&injectContext, "inject-context", false, "PM mode: inject project context (git status, file tree) into task prompts")
	runCmd.Flags().BoolVar(&adaptiveReplan, "adaptive-replan", false, "PM mode: re-plan remaining tasks with AI after a failure")
	runCmd.Flags().BoolVar(&reviewMode, "review", false, "PM mode: pause before each task for human approval (y/n/skip/quit)")
	runCmd.Flags().BoolVar(&verifyTasks, "verify", false, "PM mode: run a second AI verification pass after each TASK_DONE to confirm genuine completion")
	runCmd.Flags().IntVar(&maxVerifyRetries, "max-verify-retries", 2, "PM mode: max times a task can be re-queued by verification failure before marking it failed")
	runCmd.Flags().BoolVar(&useMemory, "use-memory", false, "Inject past session learnings into prompts")
	runCmd.Flags().BoolVar(&learn, "learn", false, "Extract key learnings at end of session and store in project memory")
	runCmd.Flags().IntVar(&memoryLimit, "memory-limit", 20, "Max number of memory entries to inject into prompts (0 = all)")
	runCmd.Flags().StringVar(&webhookURL, "webhook-url", "", "HTTP(S) URL to POST lifecycle events to (overrides config webhook.url)")
	runCmd.Flags().StringSliceVar(&webhookEvents, "webhook-events", nil, "Comma-separated events to fire: task_done,task_failed,session_complete,... (default: all)")
	runCmd.Flags().StringVar(&webhookSecret, "webhook-secret", "", "HMAC-SHA256 signing secret; sets X-Hub-Signature-256 on every request (overrides config webhook.secret)")
	runCmd.Flags().StringSliceVar(&fallbackProviders, "fallback", nil, "Fallback provider chain (e.g. --fallback anthropic,openai). Tried in order after primary fails.")
	runCmd.Flags().BoolVar(&streamOutput, "stream", false, "Stream tokens to the terminal as they are generated (anthropic, openai, ollama; ignored by claudecode)")
	runCmd.Flags().BoolVar(&notifyEnabled, "notify", false, "Send OS desktop notifications on task done, task failed, and session complete (notify-send on Linux, osascript on macOS)")
	runCmd.Flags().Float64Var(&costLimit, "cost-limit", 0, "Stop when estimated session cost reaches this USD amount (0 = unlimited); warns at 80%")
	runCmd.Flags().BoolVar(&gitMode, "git", false, "PM mode: create a git branch per task, commit on done, leave branch on failure (sequential only)")
	runCmd.Flags().BoolVar(&diagnoseFailures, "diagnose", false, "PM mode: run AI failure diagnosis on TASK_FAILED to analyze root cause and guide retries")
	runCmd.Flags().IntVar(&contextTokenLimit, "context-tokens", 0, "Maximum estimated tokens for step/task-result history in prompts (0 = default 100000); prunes oldest entries when exceeded")
	runCmd.Flags().BoolVar(&optimizePlan, "optimize", false, "PM mode: run AI plan optimizer before execution to suggest reordering, splits, merges, and flag issues")
	runCmd.Flags().BoolVar(&optimizeInteractive, "optimize-interactive", false, "PM mode: prompt before applying optimizer reordering (default: apply automatically)")
	runCmd.Flags().StringVar(&metricsAddr, "metrics-addr", "", "Start a Prometheus /metrics HTTP server on this address (e.g. :9090); writes metrics.json to .cloop/ at plan completion")
	runCmd.Flags().BoolVar(&noDedup, "no-dedup", false, "auto-evolve: disable semantic task deduplication (inject all discovered tasks without filtering duplicates)")
	runCmd.Flags().StringSliceVar(&runTags, "tags", nil, "PM mode: restrict execution to tasks matching any of the given tags (comma-separated or repeated --tags flag)")
	runCmd.Flags().BoolVar(&scriptVerify, "script-verify", false, "PM mode: after each TASK_DONE, generate and run an AI shell script that confirms the task was accomplished; marks task failed if the script exits non-zero")
	runCmd.Flags().StringVar(&runProfile, "profile", "", "Named configuration profile to apply (overrides the active profile set by 'cloop profile use')")
	runCmd.Flags().BoolVar(&autoSplit, "auto-split", false, "PM mode: automatically decompose a task into subtasks when it has failed 2+ times (sequential only)")
	runCmd.Flags().BoolVar(&skipHealthCheck, "skip-health-check", false, "PM mode: skip the AI plan health evaluation that runs after decomposition")
	runCmd.Flags().BoolVar(&multiAgentMode, "multi-agent", false, "PM mode: run each task through a three-pass specialist pipeline: architect→coder→reviewer (sequential only). Each pass uses a distinct system prompt; the reviewer's verdict overrides the coder's signal. Sub-agent outputs are stored as .cloop/tasks/<id>-<slug>-multiagent/{architect,coder,reviewer}.txt")
	runCmd.Flags().BoolVar(&postReview, "post-review", false, "PM mode: after each TASK_DONE run an AI code review on `git diff HEAD~1` and store the verdict as a task annotation (sequential only). Can also be enabled via hooks.post_task_review in config.")
	runCmd.Flags().IntVar(&healRetries, "heal-retries", 0, "PM mode: max auto-heal re-attempts after TASK_FAILED before permanently marking the task failed (0 = default 2); each attempt diagnoses the failure and retries with a modified prompt")
	runCmd.Flags().BoolVar(&noHeal, "no-heal", false, "PM mode: disable the auto-heal loop — TASK_FAILED immediately marks the task failed without any re-attempt")
	runCmd.Flags().BoolVar(&riskCheck, "risk-check", false, "PM mode: run AI risk assessment before each task; abort tasks with CRITICAL findings (use --force to override)")
	runCmd.Flags().BoolVar(&riskForce, "force", false, "PM mode: with --risk-check, execute tasks even when CRITICAL risk findings are present (prints a warning)")
	runCmd.Flags().IntVar(&consensusN, "consensus", 0, "PM mode: for critical tasks (P0/P1 or tagged 'critical'), fan out to up to N providers in parallel and use an AI judge to select the best response (0 = disabled)")
	runCmd.Flags().BoolVar(&noContextInject, "no-context-inject", false, "PM mode: disable automatic codebase context snippet injection in task prompts (keyword-matched source files are injected by default)")
	runCmd.Flags().BoolVar(&requireApproval, "require-approval", false, "PM mode: require interactive approval (y/n/skip/edit) before executing P0/P1 tasks or tasks with requires_approval:true; pre-approved tasks (via 'cloop task approve') are not re-prompted")
	runCmd.Flags().BoolVar(&skipClarify, "skip-clarify", false, "PM mode: skip the interactive goal clarification Q&A dialog before plan decomposition (useful for automation and CI)")
	runCmd.Flags().BoolVar(&autoEvalRun, "auto-eval", false, "PM mode: automatically score each successful task with the default quality rubric and save to .cloop/evals/<task-id>.json (sequential only)")
	runCmd.Flags().BoolVar(&noCache, "no-cache", false, "Disable the disk-based AI response cache for this run")
	runCmd.Flags().StringVar(&cacheTTL, "cache-ttl", "", "Response cache TTL (e.g. 1h, 48h); default 24h")
	runCmd.Flags().IntVar(&cacheMaxSize, "cache-max-size", 0, "Maximum number of cached entries before LRU eviction (default 100)")
	runCmd.Flags().BoolVar(&mockMode, "mock", false, "Use the deterministic offline mock provider (shorthand for --provider mock); responses loaded from .cloop/mock_responses.yaml")
	runCmd.Flags().BoolVar(&docsUpdateOnComplete, "docs-update", false, "PM mode: AI-refresh all tracked documentation files (README.md, CONTRIBUTING.md, etc.) automatically when the plan finishes")
	runCmd.Flags().StringVar(&docsUpdateFile, "docs-update-file", "", "Limit --docs-update to a single file (e.g. README.md)")
	rootCmd.AddCommand(runCmd)
}
