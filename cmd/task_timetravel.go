package cmd

import (
	"fmt"
	"os"
	"strconv"

	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/timetravel"
	"github.com/spf13/cobra"
)

var taskTimeTravelCmd = &cobra.Command{
	Use:   "time-travel <task-id>",
	Short: "Interactive TUI: step through a task's checkpoint history",
	Long: `Launch a split-pane terminal UI to replay a completed task's
checkpoint history interactively.

Left pane  — git-style diff of state fields (status, output length,
             token count, step number) between adjacent checkpoints.
Right pane — accumulated step log up to the selected checkpoint.

Navigation:
  ← / h        previous checkpoint
  → / l        next checkpoint
  0 / g        jump to first checkpoint
  G / $        jump to last checkpoint
  q / Esc      quit

Checkpoints are written automatically during 'cloop run --pm' execution.
Use 'cloop task checkpoint-diff <id>' for a non-interactive summary.

Examples:
  cloop task time-travel 3
  cloop task time-travel 7`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		workdir, _ := os.Getwd()

		taskID, err := strconv.Atoi(args[0])
		if err != nil {
			return fmt.Errorf("invalid task ID %q: must be a number", args[0])
		}

		// Resolve a human-friendly task title from state (best-effort).
		taskTitle := fmt.Sprintf("Task %d", taskID)
		if s, sErr := state.Load(workdir); sErr == nil && s.Plan != nil {
			for _, t := range s.Plan.Tasks {
				if t.ID == taskID {
					taskTitle = fmt.Sprintf("Task %d: %s", t.ID, t.Title)
					break
				}
			}
		}

		m, err := timetravel.New(workdir, taskID, taskTitle)
		if err != nil {
			return err
		}

		return timetravel.Run(m)
	},
}
