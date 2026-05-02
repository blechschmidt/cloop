package cmd

import (
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/blechschmidt/cloop/pkg/taskwatch"
	"github.com/spf13/cobra"
)

var (
	taskWatchTimeout  string
	taskWatchNoNotify bool
)

var taskWatchCmd = &cobra.Command{
	Use:   "watch <task-id>",
	Short: "Tail live output for a running task",
	Long: `Stream live output for a currently-executing task, similar to 'tail -f'.

The watcher polls the task's live artifact file every 100ms and prints new
bytes to stdout as the AI provider produces them.

If the task is not yet in_progress, it waits up to --timeout (default 5m)
for the task to start.  When the task reaches a terminal state the watcher
prints a final status banner and exits:

  exit 0  task done
  exit 1  task failed or timed out
  exit 2  task skipped

A desktop notification is sent on completion unless --no-notify is set.

Examples:
  cloop task watch 3
  cloop task watch 5 --timeout 10m
  cloop task watch 2 --no-notify`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		taskID, err := strconv.Atoi(args[0])
		if err != nil {
			return fmt.Errorf("invalid task ID %q: must be a number", args[0])
		}

		timeout := 5 * time.Minute
		if taskWatchTimeout != "" {
			d, parseErr := time.ParseDuration(taskWatchTimeout)
			if parseErr != nil {
				return fmt.Errorf("invalid --timeout %q: %w", taskWatchTimeout, parseErr)
			}
			timeout = d
		}

		workDir, _ := os.Getwd()
		ctx := cmd.Context()

		exitCode, watchErr := taskwatch.Watch(ctx, taskwatch.Config{
			WorkDir:  workDir,
			TaskID:   taskID,
			Timeout:  timeout,
			NoNotify: taskWatchNoNotify,
			Output:   os.Stdout,
		})
		if watchErr != nil {
			return watchErr
		}

		// Propagate exit code via os.Exit so the shell sees it.
		if exitCode != 0 {
			os.Exit(exitCode)
		}
		return nil
	},
}

func init() {
	taskWatchCmd.Flags().StringVar(&taskWatchTimeout, "timeout", "5m", "Max time to wait for the task to start")
	taskWatchCmd.Flags().BoolVar(&taskWatchNoNotify, "no-notify", false, "Suppress desktop notification on completion")
	taskCmd.AddCommand(taskWatchCmd)
}
