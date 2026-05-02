package cmd

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/provider"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/tdd"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var (
	tddGenerate bool
	tddVerify   bool
	tddProvider string
	tddModel    string
	tddTimeout  string
)

var taskTDDCmd = &cobra.Command{
	Use:   "tdd <task-id>",
	Short: "AI-generated acceptance criteria and post-execution test verification",
	Long: `Two-phase TDD workflow for PM tasks:

  --generate  (before task execution)
    Ask the AI to write concrete acceptance criteria and a runnable bash test
    script. Both are stored in .cloop/tdd/<task-id>/ as:
      criteria.md  — human-readable acceptance criteria
      test.sh      — executable bash verification script

  --verify    (after task execution)
    Run the stored test.sh, capture exit code and output, update the task's
    TDDStatus field (pass/fail), and append the results to the task artifact.

When hooks.post_task is set to "tdd" in the config, the orchestrator
automatically runs --verify after each task completes in PM sequential mode.

Examples:
  cloop task tdd 3 --generate
  cloop task tdd 3 --verify
  cloop task tdd 3 --generate --provider anthropic --model claude-opus-4-6
  cloop task tdd 3 --verify --timeout 2m`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		workdir, _ := os.Getwd()

		if !tddGenerate && !tddVerify {
			return fmt.Errorf("specify --generate (before execution) or --verify (after execution)")
		}

		s, err := state.Load(workdir)
		if err != nil {
			return err
		}
		if !s.PMMode || s.Plan == nil || len(s.Plan.Tasks) == 0 {
			return fmt.Errorf("no task plan found — run 'cloop run --pm' to create one")
		}

		taskID, err := strconv.Atoi(args[0])
		if err != nil {
			return fmt.Errorf("invalid task ID %q: must be a number", args[0])
		}

		var task *pm.Task
		for _, t := range s.Plan.Tasks {
			if t.ID == taskID {
				task = t
				break
			}
		}
		if task == nil {
			return fmt.Errorf("task %d not found", taskID)
		}

		headerColor := color.New(color.FgCyan, color.Bold)
		successColor := color.New(color.FgGreen)
		failColor := color.New(color.FgRed)
		dimColor := color.New(color.Faint)

		// ----------------------------------------------------------------
		// --generate: produce criteria.md + test.sh via AI
		// ----------------------------------------------------------------
		if tddGenerate {
			cfg, cfgErr := config.Load(workdir)
			if cfgErr != nil {
				return fmt.Errorf("loading config: %w", cfgErr)
			}
			applyEnvOverrides(cfg)

			pName := tddProvider
			if pName == "" {
				pName = cfg.Provider
			}
			if pName == "" && s.Provider != "" {
				pName = s.Provider
			}
			if pName == "" {
				pName = autoSelectProvider()
			}

			model := tddModel
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
			prov, buildErr := provider.Build(provCfg)
			if buildErr != nil {
				return fmt.Errorf("provider: %w", buildErr)
			}

			timeout := 5 * time.Minute
			if tddTimeout != "" {
				timeout, err = time.ParseDuration(tddTimeout)
				if err != nil {
					return fmt.Errorf("invalid timeout: %w", err)
				}
			}

			headerColor.Printf("Generating TDD criteria for task %d: %s\n", task.ID, task.Title)
			fmt.Printf("Asking %s to produce acceptance criteria and test script...\n\n", pName)

			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			defer cancel()

			opts := provider.Options{
				Model:   model,
				Timeout: timeout,
			}

			criteria, script, genErr := tdd.GenerateCriteria(ctx, prov, opts, task)
			if genErr != nil {
				return fmt.Errorf("generate criteria: %w", genErr)
			}

			if saveErr := tdd.SaveCriteria(workdir, task.ID, criteria, script); saveErr != nil {
				return fmt.Errorf("save criteria: %w", saveErr)
			}

			successColor.Printf("Acceptance criteria saved to: %s\n", tdd.CriteriaPath(workdir, task.ID))
			successColor.Printf("Test script saved to:         %s\n\n", tdd.TestScriptPath(workdir, task.ID))

			// Print a brief preview of the criteria lines
			for _, line := range strings.Split(criteria, "\n") {
				if strings.HasPrefix(line, "- ") {
					dimColor.Printf("  %s\n", line)
				}
			}
			fmt.Println()
			dimColor.Printf("Run 'cloop task tdd %d --verify' after the task completes.\n", task.ID)
		}

		// ----------------------------------------------------------------
		// --verify: run test.sh and update task TDDStatus
		// ----------------------------------------------------------------
		if tddVerify {
			headerColor.Printf("Verifying task %d: %s\n", task.ID, task.Title)
			fmt.Printf("Running test script: %s\n\n", tdd.TestScriptPath(workdir, task.ID))

			result, runErr := tdd.RunTests(workdir, task.ID)
			if runErr != nil {
				return runErr
			}

			// Print script output
			if result.Output != "" {
				fmt.Println(strings.TrimRight(result.Output, "\n"))
				fmt.Println()
			}

			// Score: 100 on pass, 0 on fail (simple binary; AI scoring optional)
			score := 0
			if result.Passed {
				score = 100
			}

			task.TDDStatus = "fail"
			if result.Passed {
				task.TDDStatus = "pass"
			}
			task.TDDScore = score

			// Best-effort: append result block to task artifact
			if appendErr := tdd.AppendResultToArtifact(workdir, task, result); appendErr != nil {
				dimColor.Printf("  (warning: could not append to artifact: %v)\n", appendErr)
			}

			if saveErr := s.Save(); saveErr != nil {
				return fmt.Errorf("saving state: %w", saveErr)
			}

			if result.Passed {
				successColor.Printf("TDD PASS — exit code 0 (elapsed: %s)\n",
					result.Elapsed.Round(time.Millisecond))
			} else {
				failColor.Printf("TDD FAIL — exit code %d (elapsed: %s)\n",
					result.ExitCode, result.Elapsed.Round(time.Millisecond))
			}
			dimColor.Printf("  TDDStatus=%s  TDDScore=%d%%\n", task.TDDStatus, task.TDDScore)
		}

		return nil
	},
}

func init() {
	taskTDDCmd.Flags().BoolVar(&tddGenerate, "generate", false, "Generate acceptance criteria and test script via AI")
	taskTDDCmd.Flags().BoolVar(&tddVerify, "verify", false, "Run the stored test script and update TDDStatus")
	taskTDDCmd.Flags().StringVar(&tddProvider, "provider", "", "AI provider (anthropic, openai, ollama, claudecode)")
	taskTDDCmd.Flags().StringVar(&tddModel, "model", "", "Model override for the AI provider")
	taskTDDCmd.Flags().StringVar(&tddTimeout, "timeout", "5m", "Timeout for AI calls (e.g. 2m, 300s)")
	taskCmd.AddCommand(taskTDDCmd)
}
