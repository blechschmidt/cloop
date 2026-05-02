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

var (
	recurringCron  string
	recurringClear bool
)

var taskRecurringCmd = &cobra.Command{
	Use:   "recurring <id>",
	Short: "Set or clear a cron-based recurrence schedule on a task",
	Long: `Attach a 5-field cron expression to a task so it automatically resets
to pending when the schedule fires (after becoming done, skipped, or failed).

The cron format is: "min hour dom mon dow"
  min  — minute       (0-59)
  hour — hour         (0-23)
  dom  — day-of-month (1-31)
  mon  — month        (1-12)
  dow  — day-of-week  (0-7, 0 and 7 = Sunday)

Supported: *, ranges (1-5), lists (1,2,3), step values (*/5).

Examples:
  cloop task recurring 3 --cron "0 9 * * 1"      # every Monday at 09:00
  cloop task recurring 3 --cron "0 9 * * 1-5"    # weekdays at 09:00
  cloop task recurring 3 --cron "0 */6 * * *"    # every 6 hours
  cloop task recurring 3 --cron "0 0 1 * *"      # first day of every month
  cloop task recurring 3 --clear                  # remove recurrence`,
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

		id, err := strconv.Atoi(args[0])
		if err != nil {
			return fmt.Errorf("invalid task ID %q: must be a number", args[0])
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

		if !recurringClear && recurringCron == "" {
			// Display current recurrence setting.
			titleColor := color.New(color.FgWhite, color.Bold)
			titleColor.Printf("Task %d: %s\n", task.ID, task.Title)
			if task.Recurrence == "" {
				color.New(color.Faint).Printf("  No recurrence set.\n")
				fmt.Printf("  Use --cron <expr> to set one, e.g.: --cron \"0 9 * * 1\"\n")
			} else {
				color.New(color.FgCyan).Printf("  Recurrence: %s\n", task.Recurrence)
				if task.NextRunAt != nil {
					color.New(color.FgGreen).Printf("  Next run:   %s\n", task.NextRunAt.Format("2006-01-02 15:04 MST"))
				}
			}
			return nil
		}

		if recurringClear {
			task.Recurrence = ""
			task.NextRunAt = nil
			if err := s.Save(); err != nil {
				return err
			}
			color.New(color.FgYellow).Printf("Task %d: recurrence cleared.\n", id)
			return nil
		}

		// Validate and set the new cron expression.
		if err := pm.ParseCron(recurringCron); err != nil {
			return fmt.Errorf("invalid cron expression: %w", err)
		}

		task.Recurrence = recurringCron
		task.NextRunAt = nil // will be computed on next orchestrator tick

		if err := s.Save(); err != nil {
			return err
		}

		color.New(color.FgGreen).Printf("Task %d recurrence set: %s\n", id, recurringCron)
		fmt.Printf("  The task will automatically reset to pending when the schedule fires.\n")
		return nil
	},
}

func init() {
	taskRecurringCmd.Flags().StringVar(&recurringCron, "cron", "", `5-field cron expression (e.g. "0 9 * * 1" = every Monday at 09:00)`)
	taskRecurringCmd.Flags().BoolVar(&recurringClear, "clear", false, "Remove the recurrence schedule from the task")
	taskCmd.AddCommand(taskRecurringCmd)
}
