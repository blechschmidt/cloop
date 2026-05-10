package cmd

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/provider"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
	"github.com/blechschmidt/cloop/pkg/taskreplay"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var (
	replayProvider string
	replayModel    string
	replayJudge    string // "<provider>:<model>" or "" to disable
	replayTimeout  string
	replayMaxTok   int

	replaySuiteAgainst       string // "<provider>:<model>"
	replaySuiteJudge         string
	replaySuiteTags          []string
	replaySuiteIncludeFailed bool
	replaySuiteMax           int
	replaySuiteTimeout       string
)

var taskReplayCmd = &cobra.Command{
	Use:   "replay <task-id>",
	Short: "Re-execute a completed task against a different provider/model and diff the output",
	Long: `Re-execute a previously-completed task's reconstructed prompt against a
different provider/model combination, then compare the new output against
the original. Both a Jaccard similarity score (cheap, deterministic) and an
optional AI-judged equivalence verdict (1-10) are computed and persisted to
the replay_runs table.

Use this to validate model upgrades, compare provider quality, or A/B test
prompt-effectiveness changes against historical task outputs.

Examples:
  cloop task replay 42 --provider anthropic --model claude-opus-4-5
  cloop task replay 7 --provider openai --model gpt-5 --judge anthropic:claude-opus-4-5
  cloop task replay 11 --provider ollama --model llama3.2 --timeout 10m`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		workdir, _ := os.Getwd()
		taskID, err := strconv.Atoi(args[0])
		if err != nil {
			return fmt.Errorf("invalid task ID %q: must be a number", args[0])
		}

		if replayProvider == "" {
			return fmt.Errorf("--provider is required (anthropic, openai, ollama, claudecode, mock)")
		}

		cfg, err := config.Load(workdir)
		if err != nil {
			return fmt.Errorf("loading config: %w", err)
		}
		applyEnvOverrides(cfg)

		target, err := buildProviderForReplay(cfg, replayProvider)
		if err != nil {
			return fmt.Errorf("build target provider: %w", err)
		}

		var judge provider.Provider
		var judgeModel string
		if replayJudge != "" {
			jName, jModel, ok := splitProviderModel(replayJudge)
			if !ok {
				return fmt.Errorf("--judge must be '<provider>:<model>', got %q", replayJudge)
			}
			judge, err = buildProviderForReplay(cfg, jName)
			if err != nil {
				return fmt.Errorf("build judge provider: %w", err)
			}
			judgeModel = jModel
		}

		timeout := 5 * time.Minute
		if replayTimeout != "" {
			timeout, err = time.ParseDuration(replayTimeout)
			if err != nil {
				return fmt.Errorf("invalid --timeout: %w", err)
			}
		}

		model := replayModel
		if model == "" {
			model = defaultModelFor(cfg, replayProvider)
		}

		headerColor := color.New(color.FgCyan, color.Bold)
		dimColor := color.New(color.Faint)
		headerColor.Printf("Replaying task %d against %s", taskID, replayProvider)
		if model != "" {
			headerColor.Printf(":%s", model)
		}
		fmt.Println()
		dimColor.Printf("Reconstructing prompt and dispatching target completion...\n\n")

		ctx, cancel := context.WithTimeout(cmd.Context(), timeout+30*time.Second)
		defer cancel()

		res, err := taskreplay.ReplayTask(ctx, workdir, taskID, taskreplay.Options{
			Target:      target,
			TargetName:  replayProvider,
			TargetModel: model,
			MaxTokens:   replayMaxTok,
			Timeout:     timeout,
			Judge:       judge,
			JudgeModel:  judgeModel,
		})
		if err != nil {
			return err
		}
		printReplayResult(res)
		return nil
	},
}

var taskReplaySuiteCmd = &cobra.Command{
	Use:   "replay-suite",
	Short: "Replay a batch of completed tasks against a target provider:model",
	Long: `Run replay against every replayable task in the project (or a tag-filtered
subset) and persist a row per task. Use --against to specify the target
provider/model. Optional --judge enables AI equivalence verdicts.

Examples:
  cloop task replay-suite --against anthropic:claude-opus-4-5
  cloop task replay-suite --against openai:gpt-5 --judge anthropic:claude-opus-4-5
  cloop task replay-suite --against ollama:llama3.2 --tags backend --max 10
  cloop task replay-suite --against anthropic:claude-opus-4-5 --include-failed`,
	RunE: func(cmd *cobra.Command, args []string) error {
		workdir, _ := os.Getwd()
		if replaySuiteAgainst == "" {
			return fmt.Errorf("--against is required (e.g. 'anthropic:claude-opus-4-5')")
		}
		pName, model, ok := splitProviderModel(replaySuiteAgainst)
		if !ok {
			return fmt.Errorf("--against must be '<provider>:<model>', got %q", replaySuiteAgainst)
		}

		cfg, err := config.Load(workdir)
		if err != nil {
			return fmt.Errorf("loading config: %w", err)
		}
		applyEnvOverrides(cfg)

		target, err := buildProviderForReplay(cfg, pName)
		if err != nil {
			return fmt.Errorf("build target provider: %w", err)
		}

		var judge provider.Provider
		var judgeModel string
		if replaySuiteJudge != "" {
			jName, jModel, ok := splitProviderModel(replaySuiteJudge)
			if !ok {
				return fmt.Errorf("--judge must be '<provider>:<model>', got %q", replaySuiteJudge)
			}
			judge, err = buildProviderForReplay(cfg, jName)
			if err != nil {
				return fmt.Errorf("build judge provider: %w", err)
			}
			judgeModel = jModel
		}

		timeout := 10 * time.Minute
		if replaySuiteTimeout != "" {
			timeout, err = time.ParseDuration(replaySuiteTimeout)
			if err != nil {
				return fmt.Errorf("invalid --timeout: %w", err)
			}
		}

		// Sanity check: project has a plan.
		s, err := state.Load(workdir)
		if err != nil {
			return err
		}
		if s.Plan == nil || len(s.Plan.Tasks) == 0 {
			return fmt.Errorf("no task plan found: %w", statedb.ErrTaskNotFound)
		}

		headerColor := color.New(color.FgCyan, color.Bold)
		dimColor := color.New(color.Faint)
		headerColor.Printf("Replaying suite against %s:%s\n", pName, model)
		if judge != nil {
			dimColor.Printf("  judge: %s:%s\n", strings.Split(replaySuiteJudge, ":")[0], judgeModel)
		}
		dimColor.Printf("  workdir: %s\n\n", workdir)

		ctx := cmd.Context()
		summary, err := taskreplay.RunSuite(ctx, workdir, taskreplay.SuiteOptions{
			Options: taskreplay.Options{
				Target:      target,
				TargetName:  pName,
				TargetModel: model,
				Timeout:     timeout,
				Judge:       judge,
				JudgeModel:  judgeModel,
			},
			Tags:          replaySuiteTags,
			IncludeFailed: replaySuiteIncludeFailed,
			MaxTasks:      replaySuiteMax,
		})
		if err != nil {
			return err
		}
		printSuiteSummary(summary)
		return nil
	},
}

// printReplayResult writes a colourised CLI summary of one replay.
func printReplayResult(r *taskreplay.Result) {
	if r == nil {
		return
	}
	dimColor := color.New(color.Faint)
	okColor := color.New(color.FgGreen, color.Bold)
	warnColor := color.New(color.FgYellow)
	errColor := color.New(color.FgRed)

	fmt.Printf("Task #%d — %s\n", r.TaskID, r.TaskTitle)
	fmt.Printf("  Original:  %s/%s\n", r.OriginalProvider, r.OriginalModel)
	fmt.Printf("  Replayed:  %s/%s\n", r.TargetProvider, r.TargetModel)
	dimColor.Printf("  duration: %s   tokens: in=%d out=%d\n",
		r.Duration.Round(time.Millisecond), r.InputTokens, r.OutputTokens)

	switch {
	case r.SimilarityScore >= 0.6:
		okColor.Printf("  Jaccard similarity: %.3f\n", r.SimilarityScore)
	case r.SimilarityScore >= 0.3:
		warnColor.Printf("  Jaccard similarity: %.3f\n", r.SimilarityScore)
	default:
		errColor.Printf("  Jaccard similarity: %.3f\n", r.SimilarityScore)
	}

	if r.EquivalenceScore > 0 {
		switch {
		case r.EquivalenceScore >= 8:
			okColor.Printf("  AI equivalence:     %d/10\n", r.EquivalenceScore)
		case r.EquivalenceScore >= 5:
			warnColor.Printf("  AI equivalence:     %d/10\n", r.EquivalenceScore)
		default:
			errColor.Printf("  AI equivalence:     %d/10\n", r.EquivalenceScore)
		}
		if r.EquivalenceRationale != "" {
			dimColor.Printf("    %s\n", r.EquivalenceRationale)
		}
	}

	if r.Err != "" {
		errColor.Printf("  Error: %s\n", r.Err)
	}
	fmt.Println()
	dimColor.Println("  Replay row persisted in .cloop/state.db (replay_runs).")
}

// printSuiteSummary writes the final batch-replay summary.
func printSuiteSummary(s *taskreplay.SuiteSummary) {
	if s == nil {
		return
	}
	header := color.New(color.FgCyan, color.Bold)
	dim := color.New(color.Faint)
	ok := color.New(color.FgGreen)
	bad := color.New(color.FgRed)

	header.Printf("\nSuite results (%d tasks discovered, %d replayed, %d failed, %d skipped):\n",
		s.TotalTasks, s.Replayed, s.Failed, s.Skipped)

	if s.Replayed == 0 {
		dim.Println("  No tasks were replayed.")
		return
	}

	fmt.Printf("  Average Jaccard similarity: %.3f\n", s.AverageJaccard)
	if s.AverageEquiv > 0 {
		fmt.Printf("  Average AI equivalence:     %.2f/10  ", s.AverageEquiv)
		ok.Printf("[%d high]  ", s.HighEquivCount)
		bad.Printf("[%d low]\n", s.LowEquivCount)
	}
	fmt.Println()

	for _, r := range s.Results {
		marker := "✓"
		clr := color.New(color.FgGreen)
		if r.Err != "" {
			marker = "✗"
			clr = color.New(color.FgRed)
		} else if r.SimilarityScore < 0.3 {
			marker = "·"
			clr = color.New(color.FgYellow)
		}
		clr.Printf("  %s ", marker)
		fmt.Printf("#%d %-50s  jaccard=%.3f", r.TaskID, truncateStr(r.TaskTitle, 50), r.SimilarityScore)
		if r.EquivalenceScore > 0 {
			fmt.Printf("  equiv=%d/10", r.EquivalenceScore)
		}
		if r.Err != "" {
			dim.Printf("  err=%s", truncateStr(r.Err, 60))
		}
		fmt.Println()
	}
	fmt.Println()
	dim.Println("Detailed comparisons stored in .cloop/state.db (replay_runs); browse via the UI Replay panel.")
}

// splitProviderModel parses "<provider>:<model>" into (provider, model, ok).
func splitProviderModel(s string) (string, string, bool) {
	i := strings.Index(s, ":")
	if i <= 0 || i == len(s)-1 {
		return "", "", false
	}
	return s[:i], s[i+1:], true
}

// buildProviderForReplay constructs a provider from the loaded config.
func buildProviderForReplay(cfg *config.Config, name string) (provider.Provider, error) {
	if name == "" {
		return nil, fmt.Errorf("provider name required")
	}
	provCfg := provider.ProviderConfig{
		Name:             name,
		AnthropicAPIKey:  cfg.Anthropic.APIKey,
		AnthropicBaseURL: cfg.Anthropic.BaseURL,
		OpenAIAPIKey:     cfg.OpenAI.APIKey,
		OpenAIBaseURL:    cfg.OpenAI.BaseURL,
		OllamaBaseURL:    cfg.Ollama.BaseURL,
	}
	return provider.Build(provCfg)
}

// defaultModelFor returns the per-provider default model from config.
func defaultModelFor(cfg *config.Config, providerName string) string {
	switch providerName {
	case "anthropic":
		return cfg.Anthropic.Model
	case "openai":
		return cfg.OpenAI.Model
	case "ollama":
		return cfg.Ollama.Model
	case "claudecode":
		return cfg.ClaudeCode.Model
	}
	return ""
}

func init() {
	taskReplayCmd.Flags().StringVar(&replayProvider, "provider", "", "Target provider (anthropic, openai, ollama, claudecode, mock) — required")
	taskReplayCmd.Flags().StringVar(&replayModel, "model", "", "Target model (defaults to per-provider config default)")
	taskReplayCmd.Flags().StringVar(&replayJudge, "judge", "", "Optional judge as 'provider:model' for AI-graded equivalence (1-10)")
	taskReplayCmd.Flags().StringVar(&replayTimeout, "timeout", "5m", "Per-call timeout (e.g. 2m, 10m)")
	taskReplayCmd.Flags().IntVar(&replayMaxTok, "max-tokens", 0, "Max tokens for the target completion (0 = provider default)")

	taskReplaySuiteCmd.Flags().StringVar(&replaySuiteAgainst, "against", "", "'provider:model' to replay against — required")
	taskReplaySuiteCmd.Flags().StringVar(&replaySuiteJudge, "judge", "", "Optional 'provider:model' judge for AI equivalence")
	taskReplaySuiteCmd.Flags().StringSliceVar(&replaySuiteTags, "tags", nil, "Restrict to tasks with any of these tags")
	taskReplaySuiteCmd.Flags().BoolVar(&replaySuiteIncludeFailed, "include-failed", false, "Include failed/skipped/timed_out tasks (default: only done)")
	taskReplaySuiteCmd.Flags().IntVar(&replaySuiteMax, "max", 0, "Maximum number of tasks to replay (0 = no limit)")
	taskReplaySuiteCmd.Flags().StringVar(&replaySuiteTimeout, "timeout", "10m", "Per-call timeout for each task replay")

	taskCmd.AddCommand(taskReplayCmd)
	taskCmd.AddCommand(taskReplaySuiteCmd)
}
