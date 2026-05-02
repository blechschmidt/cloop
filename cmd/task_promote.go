package cmd

import (
	"fmt"
	"os"

	"github.com/blechschmidt/cloop/pkg/promote"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var (
	promoteThreshold int
	promoteDryRun    bool
)

var taskPromoteCmd = &cobra.Command{
	Use:   "promote",
	Short: "Deadline-aware automatic priority escalation",
	Long: `Examine all pending and in-progress tasks that have a deadline set.
For each task whose deadline is within --threshold days (default 3), escalate
its priority by 1 (lower number = higher priority).

Tasks that are a direct prerequisite of an overdue task are also escalated,
because unblocking them is urgent.

A table of promoted tasks (ID, title, old priority → new priority, reason) is
always printed.  Without --dry-run the changes are written back to state.

Examples:
  cloop task promote
  cloop task promote --threshold 5
  cloop task promote --dry-run`,
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

		promotions := promote.Run(s.Plan, promoteThreshold, promoteDryRun)

		if len(promotions) == 0 {
			color.New(color.Faint).Println("No tasks require promotion.")
			return nil
		}

		// Print table header.
		hdr := color.New(color.FgCyan, color.Bold)
		hdr.Printf("%-5s  %-8s  %-8s  %-40s  %s\n", "ID", "OLD PRI", "NEW PRI", "TITLE", "REASON")
		fmt.Printf("%-5s  %-8s  %-8s  %-40s  %s\n",
			"-----", "-------", "-------", "----------------------------------------", "------")

		promotedColor := color.New(color.FgYellow, color.Bold)
		for _, p := range promotions {
			title := p.Title
			if len(title) > 40 {
				title = title[:37] + "..."
			}
			promotedColor.Printf("%-5d  %-8s  %-8s  %-40s  %s\n",
				p.TaskID,
				fmt.Sprintf("P%d", p.OldPriority),
				fmt.Sprintf("P%d", p.NewPriority),
				title,
				p.Reason,
			)
		}

		if promoteDryRun {
			color.New(color.Faint).Printf("\n(dry-run) %d task(s) would be promoted. Re-run without --dry-run to apply.\n", len(promotions))
			return nil
		}

		if err := s.Save(); err != nil {
			return fmt.Errorf("saving state: %w", err)
		}
		color.New(color.FgGreen).Printf("\n%d task(s) promoted and saved.\n", len(promotions))
		return nil
	},
}

func init() {
	taskPromoteCmd.Flags().IntVar(&promoteThreshold, "threshold", 3, "Days remaining at which a task is eligible for promotion (default 3)")
	taskPromoteCmd.Flags().BoolVar(&promoteDryRun, "dry-run", false, "Show promotions without writing to state")
	taskCmd.AddCommand(taskPromoteCmd)
}
