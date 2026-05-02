package cmd

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/provider"
	"github.com/blechschmidt/cloop/pkg/reorder"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var (
	reorderProvider string
	reorderModel    string
	reorderTimeout  string
	reorderAuto     bool
	reorderDryRun   bool
)

var taskReorderCmd = &cobra.Command{
	Use:   "reorder",
	Short: "AI-powered re-ranking of pending tasks",
	Long: `Ask the AI to re-analyze and re-rank all pending tasks given:
  - Completed task summaries and their outcomes
  - Current project state from recent git history
  - Task dependency graph
  - Task descriptions and roles

The AI returns an optimal execution order with a brief rationale per task.
The new order is applied to the plan by reassigning task priorities.
A before/after diff of the task ordering is shown in the terminal.

Examples:
  cloop task reorder
  cloop task reorder --auto
  cloop task reorder --dry-run
  cloop task reorder --provider anthropic --model claude-opus-4-6
  cloop task reorder --timeout 3m`,
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		workdir, _ := os.Getwd()

		s, err := state.Load(workdir)
		if err != nil {
			return err
		}
		if !s.PMMode || s.Plan == nil || len(s.Plan.Tasks) == 0 {
			return fmt.Errorf("no task plan found — run 'cloop run --pm' to create one")
		}

		// Count pending tasks
		pendingCount := 0
		for _, t := range s.Plan.Tasks {
			if t.Status == pm.TaskPending || t.Status == pm.TaskInProgress {
				pendingCount++
			}
		}
		if pendingCount == 0 {
			color.New(color.FgGreen).Println("No pending tasks to reorder — all tasks are complete.")
			return nil
		}

		// Build provider
		cfg, err := config.Load(workdir)
		if err != nil {
			return fmt.Errorf("loading config: %w", err)
		}
		applyEnvOverrides(cfg)

		pName := reorderProvider
		if pName == "" {
			pName = cfg.Provider
		}
		if pName == "" && s.Provider != "" {
			pName = s.Provider
		}
		if pName == "" {
			pName = autoSelectProvider()
		}

		model := reorderModel
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

		timeout := 3 * time.Minute
		if reorderTimeout != "" {
			timeout, err = time.ParseDuration(reorderTimeout)
			if err != nil {
				return fmt.Errorf("invalid timeout: %w", err)
			}
		}

		// Fetch git log for project context (last 20 commits)
		gitLog := fetchGitLog(workdir, 20)

		headerColor := color.New(color.FgCyan, color.Bold)
		dimColor := color.New(color.Faint)

		headerColor.Printf("Reordering %d pending tasks using AI...\n\n", pendingCount)

		// Capture before-order
		beforeIDs := reorder.OrderedPendingIDs(s.Plan)
		beforeByID := buildTaskByID(s.Plan)

		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()

		opts := provider.Options{
			Model:   model,
			Timeout: timeout,
		}

		ranked, err := reorder.Reorder(ctx, prov, opts, s.Plan, gitLog)
		if err != nil {
			return fmt.Errorf("reorder failed: %w", err)
		}

		// Show proposed order with rationale
		headerColor.Println("Proposed new order:")
		fmt.Println()
		for i, rt := range ranked {
			t, ok := beforeByID[rt.ID]
			if !ok {
				continue
			}
			rolePart := ""
			if t.Role != "" {
				rolePart = fmt.Sprintf(" [%s]", t.Role)
			}
			color.New(color.FgWhite, color.Bold).Printf("  %2d. #%d%s %s\n", i+1, t.ID, rolePart, t.Title)
			if rt.Rationale != "" {
				dimColor.Printf("       %s\n", rt.Rationale)
			}
		}
		fmt.Println()

		// Show diff
		afterIDs := make([]int, len(ranked))
		for i, rt := range ranked {
			afterIDs[i] = rt.ID
		}
		printReorderDiff(beforeIDs, afterIDs, beforeByID)

		if reorderDryRun {
			dimColor.Println("(dry-run: no changes saved)")
			return nil
		}

		// Confirm unless --auto
		if !reorderAuto {
			fmt.Printf("Apply this reordering? (y/N): ")
			scanner := bufio.NewScanner(os.Stdin)
			if !scanner.Scan() {
				return fmt.Errorf("no input received")
			}
			answer := strings.TrimSpace(strings.ToLower(scanner.Text()))
			if answer != "y" && answer != "yes" {
				fmt.Println("Reorder cancelled.")
				return nil
			}
		}

		if err := reorder.ApplyOrder(s.Plan, ranked); err != nil {
			return fmt.Errorf("applying order: %w", err)
		}

		if err := s.Save(); err != nil {
			return fmt.Errorf("saving state: %w", err)
		}

		color.New(color.FgGreen).Printf("Reorder applied: %d pending tasks re-ranked.\n", pendingCount)
		return nil
	},
}

// printReorderDiff shows a colored before/after diff of task ordering.
// Tasks that moved up are green, tasks that moved down are red, unchanged are dim.
func printReorderDiff(before, after []int, byID map[int]*pm.Task) {
	// Build position maps
	beforePos := make(map[int]int, len(before))
	for i, id := range before {
		beforePos[id] = i + 1
	}
	afterPos := make(map[int]int, len(after))
	for i, id := range after {
		afterPos[id] = i + 1
	}

	// All IDs union
	allIDs := make(map[int]bool)
	for _, id := range before {
		allIDs[id] = true
	}
	for _, id := range after {
		allIDs[id] = true
	}

	movedUp := color.New(color.FgGreen)
	movedDown := color.New(color.FgRed)
	unchanged := color.New(color.Faint)
	headerColor := color.New(color.FgCyan, color.Bold)

	headerColor.Println("Before/After diff (position change):")
	fmt.Println()

	// Sort by after position
	sortedAfter := make([]int, 0, len(allIDs))
	for id := range allIDs {
		sortedAfter = append(sortedAfter, id)
	}
	sort.SliceStable(sortedAfter, func(i, j int) bool {
		ai, aj := afterPos[sortedAfter[i]], afterPos[sortedAfter[j]]
		if ai == 0 {
			return false
		}
		if aj == 0 {
			return true
		}
		return ai < aj
	})

	for _, id := range sortedAfter {
		t, ok := byID[id]
		if !ok {
			continue
		}
		bp := beforePos[id]
		ap := afterPos[id]

		var arrow string
		var diff int
		if bp > 0 && ap > 0 {
			diff = bp - ap // positive = moved up
		}

		title := truncateStr(t.Title, 50)
		if diff > 0 {
			arrow = fmt.Sprintf("↑+%d", diff)
			movedUp.Printf("  %2d → %2d  %s  #%d %s\n", bp, ap, arrow, id, title)
		} else if diff < 0 {
			arrow = fmt.Sprintf("↓%d", diff)
			movedDown.Printf("  %2d → %2d  %s  #%d %s\n", bp, ap, arrow, id, title)
		} else {
			unchanged.Printf("  %2d → %2d  =    #%d %s\n", bp, ap, id, title)
		}
	}
	fmt.Println()
}

// buildTaskByID returns a map of task ID to *Task for all tasks in the plan.
func buildTaskByID(plan *pm.Plan) map[int]*pm.Task {
	m := make(map[int]*pm.Task, len(plan.Tasks))
	for _, t := range plan.Tasks {
		m[t.ID] = t
	}
	return m
}

// fetchGitLog returns the last n commit messages from the git log in the workdir.
// Returns empty string on any error (git not available, not a repo, etc).
func fetchGitLog(workdir string, n int) string {
	cmd := exec.Command("git", "-C", workdir, "log", fmt.Sprintf("--max-count=%d", n),
		"--pretty=format:%h %s (%ad)", "--date=short")
	out, err := cmd.Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

func init() {
	taskReorderCmd.Flags().StringVar(&reorderProvider, "provider", "", "AI provider to use (anthropic, openai, ollama, claudecode)")
	taskReorderCmd.Flags().StringVar(&reorderModel, "model", "", "Model override for the AI provider")
	taskReorderCmd.Flags().StringVar(&reorderTimeout, "timeout", "3m", "Timeout for the AI call (e.g. 2m, 300s)")
	taskReorderCmd.Flags().BoolVar(&reorderAuto, "auto", false, "Skip confirmation prompt and apply the reordering immediately")
	taskReorderCmd.Flags().BoolVar(&reorderDryRun, "dry-run", false, "Show proposed reordering without saving changes")

	taskCmd.AddCommand(taskReorderCmd)
}
