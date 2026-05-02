package cmd

import (
	"fmt"
	"os"
	"strconv"

	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/fatih/color"
	"github.com/google/uuid"
	"github.com/spf13/cobra"
)

var taskChainCmd = &cobra.Command{
	Use:   "chain <id1> <id2> [id3...]",
	Short: "Create a pipeline chain between tasks",
	Long: `Link two or more tasks into an execution pipeline.

When tasks are chained:
  - Each task automatically depends on the previous one (serial execution).
  - After each task completes, its AI output is injected as context into the
    next task's prompt under a "Previous step output:" section.
  - All tasks in the chain are tagged with a shared "chain:<uuid>" label so
    the orchestrator can identify and wire the pipeline at runtime.

The command modifies task dependencies and tags in-place — it does not change
task titles, descriptions, or priorities.

Examples:
  cloop task chain 1 2 3       # 1 → 2 → 3 pipeline
  cloop task chain 5 7         # 5 feeds output into 7`,
	Args: cobra.MinimumNArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		workdir, _ := os.Getwd()
		s, err := state.Load(workdir)
		if err != nil {
			return err
		}
		if !s.PMMode || s.Plan == nil {
			return fmt.Errorf("no task plan found — run 'cloop run --pm' to create one")
		}

		// Parse and validate all IDs.
		ids := make([]int, 0, len(args))
		for _, arg := range args {
			id, parseErr := strconv.Atoi(arg)
			if parseErr != nil {
				return fmt.Errorf("invalid task ID %q: must be a number", arg)
			}
			if s.Plan.TaskByID(id) == nil {
				return fmt.Errorf("task %d not found", id)
			}
			ids = append(ids, id)
		}

		// Deduplicate while preserving order.
		seen := make(map[int]bool, len(ids))
		unique := make([]int, 0, len(ids))
		for _, id := range ids {
			if !seen[id] {
				seen[id] = true
				unique = append(unique, id)
			}
		}
		if len(unique) < 2 {
			return fmt.Errorf("chain requires at least 2 distinct task IDs")
		}

		// Generate a stable identifier for this chain.
		chainTag := "chain:" + uuid.New().String()

		// Wire the pipeline: tag all tasks and add sequential dependencies.
		for i, id := range unique {
			task := s.Plan.TaskByID(id)

			// Add chain tag if not already present.
			alreadyTagged := false
			for _, t := range task.Tags {
				if t == chainTag {
					alreadyTagged = true
					break
				}
			}
			if !alreadyTagged {
				task.Tags = append(task.Tags, chainTag)
			}

			// Link to predecessor: task[i] depends on task[i-1].
			if i > 0 {
				prevID := unique[i-1]
				alreadyDep := false
				for _, dep := range task.DependsOn {
					if dep == prevID {
						alreadyDep = true
						break
					}
				}
				if !alreadyDep {
					task.DependsOn = append(task.DependsOn, prevID)
				}
			}
		}

		if err := s.Save(); err != nil {
			return err
		}

		// Print a summary of the wired pipeline.
		successColor := color.New(color.FgGreen, color.Bold)
		dimColor := color.New(color.Faint)

		successColor.Printf("Pipeline chain created (%s)\n\n", chainTag)
		for i, id := range unique {
			task := s.Plan.TaskByID(id)
			if i == 0 {
				fmt.Printf("  [%d] %s  (source)\n", task.ID, task.Title)
			} else {
				fmt.Printf("  [%d] %s  (depends on #%d)\n", task.ID, task.Title, unique[i-1])
			}
		}
		fmt.Println()
		dimColor.Printf("The orchestrator will pipe each task's output into the next task's prompt.\n")
		dimColor.Printf("Run 'cloop run --pm' to execute the pipeline.\n")

		return nil
	},
}

func init() {
	taskCmd.AddCommand(taskChainCmd)
}
