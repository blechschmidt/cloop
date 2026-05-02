package cmd

import (
	"fmt"
	"os"
	"strconv"

	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var taskPinCmd = &cobra.Command{
	Use:   "pin <id>",
	Short: "Pin a task so it always appears at the top of task lists",
	Long: `Mark a task as pinned. Pinned tasks are sorted to the top of all
output: 'cloop status', 'cloop task list', TUI dashboard, kanban board,
and JSON API responses.

Pinned tasks are shown with a [PIN] indicator in terminal output
and a CSS badge in the Web UI.

Note: pinning more than 5 tasks triggers a 'pin-inflation' warning in
'cloop lint'. Use pinning sparingly to highlight truly critical tasks.

Examples:
  cloop task pin 3
  cloop task pin 7`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		return setPinned(args[0], true)
	},
}

var taskUnpinCmd = &cobra.Command{
	Use:   "unpin <id>",
	Short: "Remove the pin from a task",
	Long: `Remove the pin from a previously pinned task. The task will return to
its normal position in priority-sorted lists.

Examples:
  cloop task unpin 3`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		return setPinned(args[0], false)
	},
}

func setPinned(idStr string, pin bool) error {
	workdir, _ := os.Getwd()
	s, err := state.Load(workdir)
	if err != nil {
		return err
	}
	if !s.PMMode || s.Plan == nil {
		return fmt.Errorf("no task plan found — run 'cloop run --pm' to create one")
	}

	id, err := strconv.Atoi(idStr)
	if err != nil {
		return fmt.Errorf("invalid task ID %q: must be a number", idStr)
	}

	var task *pm.Task
	for _, t := range s.Plan.Tasks {
		if t.ID == id {
			task = t
			break
		}
	}
	if task == nil {
		return fmt.Errorf("task %d not found", id)
	}

	if pin && task.Pinned {
		fmt.Printf("Task %d is already pinned: %s\n", id, task.Title)
		return nil
	}
	if !pin && !task.Pinned {
		fmt.Printf("Task %d is not pinned: %s\n", id, task.Title)
		return nil
	}

	task.Pinned = pin
	if err := s.Save(); err != nil {
		return err
	}

	pinCount := pm.PinnedCount(s.Plan.Tasks)
	if pin {
		color.New(color.FgCyan).Printf("[PIN] Task %d pinned: %s\n", task.ID, task.Title)
		if pinCount > 5 {
			color.New(color.FgYellow).Printf(
				"  Warning: %d tasks are now pinned. Consider unpinning some to avoid pin inflation.\n",
				pinCount)
		}
	} else {
		color.New(color.FgYellow).Printf("Task %d unpinned: %s\n", task.ID, task.Title)
	}
	return nil
}

func init() {
	taskCmd.AddCommand(taskPinCmd)
	taskCmd.AddCommand(taskUnpinCmd)
}
