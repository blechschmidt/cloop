package cmd

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/provider"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/taskadd"
	"github.com/blechschmidt/cloop/pkg/testrun"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var (
	testCmdProvider string
	testCmdModel    string
	testCmdTimeout  string
	testCmdSave     bool
	testCmdFix      bool
	testCmdNoAI     bool
	testCmdDir      string
)

var testCmd = &cobra.Command{
	Use:          "test [task-id]",
	Short:        "Run project tests with AI-powered failure analysis",
	SilenceUsage: true,
	Long: `Detect the project test framework, run the tests, capture output, and
pipe failures to the AI provider for root-cause diagnosis.

Output includes:
  - Pass/fail/skip counts
  - AI root-cause summary for each failing test
  - AI-suggested diff or fix strategy

If a task-id is provided the test report is attached to that task's artifact
store when used with --save.

The --fix flag feeds the AI analysis back into 'cloop task add' to create a
remediation task automatically.

Supported frameworks (auto-detected):
  go test   — go.mod present
  cargo     — Cargo.toml present
  pytest    — pyproject.toml / setup.py / requirements.txt / test_*.py
  vitest    — package.json with vitest dependency
  jest      — package.json with jest dependency
  npm test  — package.json with test script (fallback)

Examples:
  cloop test
  cloop test 5
  cloop test --save
  cloop test 3 --fix
  cloop test --no-ai
  cloop test --provider anthropic --model claude-sonnet-4-6
  cloop test --dir ./backend`,
	Args: cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		workdir, _ := os.Getwd()
		if testCmdDir != "" {
			workdir = testCmdDir
			if !filepath.IsAbs(workdir) {
				cwd, _ := os.Getwd()
				workdir = filepath.Join(cwd, workdir)
			}
		}

		// Optional task-id
		taskID := 0
		if len(args) > 0 {
			if _, err := fmt.Sscanf(args[0], "%d", &taskID); err != nil {
				return fmt.Errorf("invalid task ID %q: must be a number", args[0])
			}
		}

		// Detect framework
		headerColor := color.New(color.FgCyan, color.Bold)
		dimColor := color.New(color.Faint)
		successColor := color.New(color.FgGreen)
		failColor := color.New(color.FgRed)
		warnColor := color.New(color.FgYellow)

		fw, err := testrun.Detect(workdir)
		if err != nil {
			return err
		}
		headerColor.Printf("Detected framework: %s\n", fw.Name)
		dimColor.Printf("Command: %s\n\n", strings.Join(fw.Command, " "))

		// Build AI provider (needed for diagnosis and --fix)
		var prov provider.Provider
		var opts provider.Options
		var timeout time.Duration

		timeout = 5 * time.Minute
		if testCmdTimeout != "" {
			timeout, err = time.ParseDuration(testCmdTimeout)
			if err != nil {
				return fmt.Errorf("invalid timeout: %w", err)
			}
		}

		if !testCmdNoAI {
			cfg, cfgErr := config.Load(workdir)
			if cfgErr != nil {
				return fmt.Errorf("loading config: %w", cfgErr)
			}
			applyEnvOverrides(cfg)

			var s *state.ProjectState
			s, err = state.Load(workdir)
			if err != nil {
				// Non-fatal: test can run without PM state
				s = nil
			}

			pName := testCmdProvider
			if pName == "" {
				pName = cfg.Provider
			}
			if pName == "" && s != nil && s.Provider != "" {
				pName = s.Provider
			}
			if pName == "" {
				pName = autoSelectProvider()
			}

			model := testCmdModel
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
			if model == "" && s != nil {
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
			prov, err = provider.Build(provCfg)
			if err != nil {
				return fmt.Errorf("provider: %w", err)
			}

			opts = provider.Options{
				Model:   model,
				Timeout: timeout,
			}
		}

		// Run tests
		fmt.Printf("Running tests...\n\n")

		runCtx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()

		result, err := testrun.Run(runCtx, workdir, fw)
		if err != nil {
			return fmt.Errorf("test run error: %w", err)
		}

		// Print raw output
		if result.RawOutput != "" {
			fmt.Print(result.RawOutput)
			if !strings.HasSuffix(result.RawOutput, "\n") {
				fmt.Println()
			}
		}

		// Summary line
		sep := strings.Repeat("─", 60)
		fmt.Println(sep)

		total := result.Passed + result.Failed + result.Skipped
		if result.Failed == 0 {
			successColor.Printf("PASS  %d passed", result.Passed)
			if result.Skipped > 0 {
				dimColor.Printf(", %d skipped", result.Skipped)
			}
			fmt.Printf("  (total: %d)\n", total)
			fmt.Println(sep)

			// Save report even on all-pass if --save
			if testCmdSave {
				report := &testrun.Report{
					Framework: fw.Name,
					Passed:    result.Passed,
					Failed:    result.Failed,
					Skipped:   result.Skipped,
					RawOutput: result.RawOutput,
				}
				relPath, saveErr := testrun.WriteReportArtifact(workdir, taskID, report)
				if saveErr != nil {
					warnColor.Printf("Could not save report: %v\n", saveErr)
				} else {
					dimColor.Printf("Report saved: %s\n", relPath)
				}
			}
			return nil
		}

		// Failures present
		failColor.Printf("FAIL  %d failed", result.Failed)
		if result.Passed > 0 {
			successColor.Printf(", %d passed", result.Passed)
		}
		if result.Skipped > 0 {
			dimColor.Printf(", %d skipped", result.Skipped)
		}
		fmt.Printf("  (total: %d)\n", total)
		fmt.Println(sep)

		if testCmdNoAI {
			return fmt.Errorf("%d test(s) failed", result.Failed)
		}

		// AI diagnosis
		fmt.Printf("\nAnalyzing failures with AI...\n\n")

		// Optionally include task context
		taskContext := ""
		if taskID > 0 {
			s2, sErr := state.Load(workdir)
			if sErr == nil && s2.PMMode && s2.Plan != nil {
				task := s2.Plan.TaskByID(taskID)
				if task != nil {
					taskContext = fmt.Sprintf("Task #%d: %s\n%s", task.ID, task.Title, task.Description)
				}
			}
		}

		diagReport, diagErr := testrun.Diagnose(runCtx, prov, opts, result, taskContext)
		if diagErr != nil {
			warnColor.Printf("AI diagnosis failed: %v\n", diagErr)
			// Still return the failure
			return fmt.Errorf("%d test(s) failed", result.Failed)
		}

		// Print AI report
		if len(diagReport.Diagnoses) > 0 {
			headerColor.Printf("AI Root-Cause Analysis\n\n")
			for i, d := range diagReport.Diagnoses {
				warnColor.Printf("%d. %s\n", i+1, d.TestName)
				fmt.Printf("   Root cause:   %s\n", d.RootCause)
				fmt.Printf("   Fix strategy: %s\n\n", d.FixStrategy)
			}
		}

		if diagReport.AISummary != "" {
			headerColor.Printf("Summary\n\n")
			fmt.Printf("%s\n\n", diagReport.AISummary)
		}

		// Save report
		if testCmdSave {
			relPath, saveErr := testrun.WriteReportArtifact(workdir, taskID, diagReport)
			if saveErr != nil {
				warnColor.Printf("Could not save report: %v\n", saveErr)
			} else {
				dimColor.Printf("Report saved: %s\n\n", relPath)
			}
		}

		// --fix: create a remediation task
		if testCmdFix && len(diagReport.Diagnoses) > 0 {
			s3, sErr := state.Load(workdir)
			if sErr != nil {
				warnColor.Printf("Could not load state for --fix: %v\n", sErr)
			} else if !s3.PMMode {
				warnColor.Printf("--fix requires PM mode (run 'cloop init --pm' or 'cloop run --pm' first)\n")
			} else {
				fixDesc := testrun.FixPrompt(fw, diagReport.Diagnoses, diagReport.AISummary)
				headerColor.Printf("Creating remediation task...\n")
				dimColor.Printf("Description: %s\n\n", fixDesc)

				fixCtx, fixCancel := context.WithTimeout(context.Background(), timeout)
				defer fixCancel()

				fixOpts := provider.Options{
					Model:   opts.Model,
					Timeout: timeout,
				}

				spec, specErr := taskadd.Enrich(fixCtx, prov, fixOpts, fixDesc, s3.Plan)
				if specErr != nil {
					warnColor.Printf("AI task structuring failed: %v\nAdding task with raw description.\n", specErr)
					// Fall back to direct add
					maxID := 0
					for _, t := range s3.Plan.Tasks {
						if t.ID > maxID {
							maxID = t.ID
						}
					}
					maxPriority := 0
					for _, t := range s3.Plan.Tasks {
						if t.Priority > maxPriority {
							maxPriority = t.Priority
						}
					}
					newTask := &pm.Task{
						ID:          maxID + 1,
						Title:       truncateStr(fixDesc, 80),
						Description: fixDesc,
						Priority:    maxPriority + 1,
						Status:      pm.TaskPending,
						Role:        "testing",
					}
					s3.Plan.Tasks = append(s3.Plan.Tasks, newTask)
					if saveErr := s3.Save(); saveErr != nil {
						warnColor.Printf("Could not save state: %v\n", saveErr)
					} else {
						successColor.Printf("Added remediation task %d: %s\n", newTask.ID, newTask.Title)
					}
				} else {
					// Apply the AI-structured spec
					maxID := 0
					for _, t := range s3.Plan.Tasks {
						if t.ID > maxID {
							maxID = t.ID
						}
					}
					newTask := &pm.Task{
						ID:               maxID + 1,
						Title:            spec.Title,
						Description:      spec.Description,
						Priority:         spec.Priority,
						Role:             pm.AgentRole(spec.Role),
						Tags:             spec.Tags,
						EstimatedMinutes: spec.EstimatedMinutes,
						Status:           pm.TaskPending,
					}
					s3.Plan.Tasks = append(s3.Plan.Tasks, newTask)
					if saveErr := s3.Save(); saveErr != nil {
						warnColor.Printf("Could not save state: %v\n", saveErr)
					} else {
						successColor.Printf("Added remediation task %d: %s (priority %d)\n",
							newTask.ID, newTask.Title, newTask.Priority)
						if spec.Rationale != "" {
							dimColor.Printf("  %s\n", spec.Rationale)
						}
					}
				}
			}
		}

		return fmt.Errorf("%d test(s) failed", result.Failed)
	},
}

func init() {
	testCmd.Flags().StringVar(&testCmdProvider, "provider", "", "AI provider for diagnosis (anthropic, openai, ollama, claudecode)")
	testCmd.Flags().StringVar(&testCmdModel, "model", "", "Model override for the AI provider")
	testCmd.Flags().StringVar(&testCmdTimeout, "timeout", "5m", "Timeout for test run + AI call combined (e.g. 5m, 300s)")
	testCmd.Flags().BoolVar(&testCmdSave, "save", false, "Save test report to .cloop/tasks/<task-id>-test-report.md")
	testCmd.Flags().BoolVar(&testCmdFix, "fix", false, "Create a remediation task via 'cloop task add' for each failing test group")
	testCmd.Flags().BoolVar(&testCmdNoAI, "no-ai", false, "Skip AI diagnosis; only run tests and print raw output")
	testCmd.Flags().StringVar(&testCmdDir, "dir", "", "Working directory (defaults to current directory)")

	rootCmd.AddCommand(testCmd)
}
