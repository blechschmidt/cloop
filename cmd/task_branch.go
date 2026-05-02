package cmd

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var (
	branchOnSuccess string
	branchOnFailure string
	branchClear     bool
)

var taskBranchCmd = &cobra.Command{
	Use:   "branch <task-id>",
	Short: "Set conditional branch targets for a task",
	Long: `Declare what happens after a task completes:

  --on-success <ids>  comma-separated task IDs to activate when the task succeeds
  --on-failure <ids>  comma-separated task IDs to activate when the task fails

When a task finishes:
  - success path: on_success tasks remain pending, on_failure tasks are skipped
  - failure path: on_failure tasks remain pending, on_success tasks are skipped

Tasks in neither branch list are unaffected.

Use --clear to remove all branch declarations from a task.

Examples:
  cloop task branch 3 --on-success 4,5 --on-failure 6
  cloop task branch 3 --on-success 4
  cloop task branch 3 --on-failure 7,8
  cloop task branch 3 --clear`,
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

		if branchClear {
			task.OnSuccess = nil
			task.OnFailure = nil
			if err := s.Save(); err != nil {
				return err
			}
			color.New(color.FgYellow).Printf("Task %d: branch declarations cleared\n", taskID)
			return nil
		}

		if !cmd.Flags().Changed("on-success") && !cmd.Flags().Changed("on-failure") {
			// Display current branches.
			showBranches(task, s.Plan)
			return nil
		}

		// Validate and parse --on-success
		if cmd.Flags().Changed("on-success") {
			ids, parseErr := parseBranchIDs(branchOnSuccess, s.Plan, taskID)
			if parseErr != nil {
				return fmt.Errorf("--on-success: %w", parseErr)
			}
			task.OnSuccess = ids
		}

		// Validate and parse --on-failure
		if cmd.Flags().Changed("on-failure") {
			ids, parseErr := parseBranchIDs(branchOnFailure, s.Plan, taskID)
			if parseErr != nil {
				return fmt.Errorf("--on-failure: %w", parseErr)
			}
			task.OnFailure = ids
		}

		if err := s.Save(); err != nil {
			return err
		}

		color.New(color.FgGreen).Printf("Task %d branches updated: %s\n", taskID, task.Title)
		showBranches(task, s.Plan)
		return nil
	},
}

// parseBranchIDs parses a comma-separated string of task IDs, validates them
// against the plan, and ensures they are not self-referential.
func parseBranchIDs(raw string, plan *pm.Plan, selfID int) ([]string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}
	byID := make(map[int]*pm.Task, len(plan.Tasks))
	for _, t := range plan.Tasks {
		byID[t.ID] = t
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		id, err := strconv.Atoi(p)
		if err != nil {
			return nil, fmt.Errorf("invalid task ID %q: must be a number", p)
		}
		if id == selfID {
			return nil, fmt.Errorf("task cannot branch to itself (ID %d)", id)
		}
		if _, ok := byID[id]; !ok {
			return nil, fmt.Errorf("task %d not found in plan", id)
		}
		out = append(out, p)
	}
	return out, nil
}

// showBranches prints the current branch declarations for a task.
func showBranches(task *pm.Task, plan *pm.Plan) {
	byID := make(map[int]*pm.Task, len(plan.Tasks))
	for _, t := range plan.Tasks {
		byID[t.ID] = t
	}

	titleColor := color.New(color.FgWhite, color.Bold)
	successColor := color.New(color.FgGreen)
	failColor := color.New(color.FgRed)
	dimColor := color.New(color.Faint)

	titleColor.Printf("Task %d: %s\n", task.ID, task.Title)

	if len(task.OnSuccess) == 0 && len(task.OnFailure) == 0 {
		dimColor.Printf("  No branch declarations set.\n")
		return
	}

	if len(task.OnSuccess) > 0 {
		successColor.Printf("  on_success:\n")
		for _, idStr := range task.OnSuccess {
			id, _ := strconv.Atoi(idStr)
			if t, ok := byID[id]; ok {
				successColor.Printf("    -> task %d: %s\n", id, t.Title)
			} else {
				successColor.Printf("    -> task %d (not found)\n", id)
			}
		}
	}

	if len(task.OnFailure) > 0 {
		failColor.Printf("  on_failure:\n")
		for _, idStr := range task.OnFailure {
			id, _ := strconv.Atoi(idStr)
			if t, ok := byID[id]; ok {
				failColor.Printf("    -> task %d: %s\n", id, t.Title)
			} else {
				failColor.Printf("    -> task %d (not found)\n", id)
			}
		}
	}
}

func init() {
	taskBranchCmd.Flags().StringVar(&branchOnSuccess, "on-success", "", "Comma-separated task IDs to activate on success")
	taskBranchCmd.Flags().StringVar(&branchOnFailure, "on-failure", "", "Comma-separated task IDs to activate on failure")
	taskBranchCmd.Flags().BoolVar(&branchClear, "clear", false, "Remove all branch declarations from the task")
	taskCmd.AddCommand(taskBranchCmd)
}
