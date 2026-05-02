package cmd

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/decompose"
	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/provider"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var (
	decomposeDepth    int
	decomposeDryRun   bool
	decomposeProvider string
	decomposeModel    string
	decomposeTimeout  string
)

var taskDecomposeCmd = &cobra.Command{
	Use:   "decompose <id>",
	Short: "Recursively expand a complex task into 3-7 AI-generated sub-tasks",
	Long: `Ask the AI to break a single complex task into 3-7 concrete sub-tasks.

Sub-tasks:
  - Inherit the parent task's tags and assignee
  - Are assigned sequential IDs (maxID+1, maxID+2, …) and displayed as
    <parent-id>.1, <parent-id>.2, … in the preview
  - Are wired sequentially: sub-task N+1 depends on sub-task N
  - The first sub-task depends on the (now skipped) parent
  - The parent task is marked 'skipped' with annotation 'Decomposed into sub-tasks'
  - Duplicates are filtered via AI semantic deduplication before injection

Use --depth 2 to recursively decompose each generated sub-task one more level.
Use --dry-run to preview the proposed sub-tasks without modifying state.

Examples:
  cloop task decompose 5
  cloop task decompose 5 --depth 2
  cloop task decompose 5 --dry-run
  cloop task decompose 5 --provider anthropic --model claude-opus-4-5`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		workdir, _ := os.Getwd()

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

		// Validate task exists.
		var rootTask *pm.Task
		for _, t := range s.Plan.Tasks {
			if t.ID == taskID {
				rootTask = t
				break
			}
		}
		if rootTask == nil {
			return fmt.Errorf("task %d not found", taskID)
		}

		if decomposeDepth < 1 {
			decomposeDepth = 1
		}
		if decomposeDepth > 5 {
			return fmt.Errorf("--depth must be between 1 and 5")
		}

		// Build provider.
		cfg, err := config.Load(workdir)
		if err != nil {
			return fmt.Errorf("loading config: %w", err)
		}
		applyEnvOverrides(cfg)

		pName := decomposeProvider
		if pName == "" {
			pName = cfg.Provider
		}
		if pName == "" && s.Provider != "" {
			pName = s.Provider
		}
		if pName == "" {
			pName = autoSelectProvider()
		}

		model := decomposeModel
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
		if decomposeTimeout != "" {
			timeout, err = time.ParseDuration(decomposeTimeout)
			if err != nil {
				return fmt.Errorf("invalid timeout: %w", err)
			}
		}

		opts := provider.Options{
			Model:   model,
			Timeout: timeout,
		}

		// Deep-copy plan so we can preview before committing.
		planCopy := deepCopyPlan(s.Plan)

		ctx, cancel := context.WithTimeout(context.Background(), timeout*time.Duration(decomposeDepth))
		defer cancel()

		headerColor := color.New(color.FgCyan, color.Bold)
		warnColor := color.New(color.FgYellow)
		dimColor := color.New(color.Faint)
		successColor := color.New(color.FgGreen)

		headerColor.Printf("Decomposing task %d: %s\n\n", rootTask.ID, rootTask.Title)

		// Recursively decompose with a queue of (taskID, currentDepth, parentLabel).
		type queueItem struct {
			taskID      int
			depth       int
			parentLabel string
		}

		queue := []queueItem{{taskID: taskID, depth: decomposeDepth, parentLabel: fmt.Sprintf("%d", taskID)}}
		totalInjected := 0

		for len(queue) > 0 {
			item := queue[0]
			queue = queue[1:]

			// Find task in the copy.
			var task *pm.Task
			for _, t := range planCopy.Tasks {
				if t.ID == item.taskID {
					task = t
					break
				}
			}
			if task == nil {
				continue
			}

			fmt.Printf("Asking AI to decompose task %d: %s...\n", task.ID, task.Title)

			res, decompErr := decompose.Decompose(ctx, prov, opts, planCopy, item.taskID)
			if decompErr != nil {
				return fmt.Errorf("decompose task %d: %w", item.taskID, decompErr)
			}

			if len(res.SubTasks) == 0 {
				warnColor.Printf("  No novel sub-tasks produced for task %d (all filtered as duplicates).\n\n", item.taskID)
				continue
			}

			// Print preview with dot-notation IDs.
			fmt.Printf("\n  Sub-tasks for task %s:\n", item.parentLabel)
			for i, st := range res.SubTasks {
				label := fmt.Sprintf("%s.%d", item.parentLabel, i+1)
				rolePart := ""
				if st.Role != "" {
					rolePart = fmt.Sprintf(" [%s]", st.Role)
				}
				warnColor.Printf("    %s%s %s\n", label, rolePart, st.Title)
				if st.Description != "" {
					dimColor.Printf("         %s\n", truncateStr(st.Description, 110))
				}
				if len(st.Tags) > 0 {
					dimColor.Printf("         tags: %s\n", strings.Join(st.Tags, ", "))
				}
				if st.EstimatedMinutes > 0 {
					dimColor.Printf("         est: %d min\n", st.EstimatedMinutes)
				}
			}
			fmt.Println()

			if !decomposeDryRun {
				// Inject into the plan copy.
				injected := decompose.InjectSubTasks(planCopy, res)
				totalInjected += len(injected)

				// If more depth, queue each sub-task for further decomposition.
				if item.depth > 1 {
					for i, st := range injected {
						label := fmt.Sprintf("%s.%d", item.parentLabel, i+1)
						queue = append(queue, queueItem{
							taskID:      st.ID,
							depth:       item.depth - 1,
							parentLabel: label,
						})
					}
				}
			}
		}

		if decomposeDryRun {
			warnColor.Printf("Dry run — no changes saved.\n")
			return nil
		}

		if totalInjected == 0 {
			warnColor.Printf("No sub-tasks were injected.\n")
			return nil
		}

		// Commit the modified plan.
		s.Plan = planCopy
		if err := s.Save(); err != nil {
			return fmt.Errorf("saving state: %w", err)
		}

		successColor.Printf("Decomposition complete: %d sub-task(s) injected.\n", totalInjected)
		dimColor.Printf("Parent task %d marked skipped with annotation.\n", taskID)
		dimColor.Printf("Run 'cloop task list' to view the updated plan.\n")
		return nil
	},
}

func init() {
	taskDecomposeCmd.Flags().IntVar(&decomposeDepth, "depth", 1, "Number of decomposition levels (1 = single level, 2 = recursive)")
	taskDecomposeCmd.Flags().BoolVar(&decomposeDryRun, "dry-run", false, "Print proposed sub-tasks without saving changes")
	taskDecomposeCmd.Flags().StringVar(&decomposeProvider, "provider", "", "AI provider to use (anthropic, openai, ollama, claudecode)")
	taskDecomposeCmd.Flags().StringVar(&decomposeModel, "model", "", "Model override for the AI provider")
	taskDecomposeCmd.Flags().StringVar(&decomposeTimeout, "timeout", "5m", "Timeout per AI call (e.g. 2m, 300s)")
	taskCmd.AddCommand(taskDecomposeCmd)
}
