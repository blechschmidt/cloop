package cmd

import (
	"fmt"
	"os"
	"sort"
	"time"

	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var taskDeadlinesCmd = &cobra.Command{
	Use:   "deadlines",
	Short: "List all tasks with deadlines sorted by urgency",
	Long: `Display all tasks that have a deadline assigned, sorted from most urgent
(soonest / most overdue) to least urgent.

Overdue tasks are highlighted in red and their priority is shown. Tasks due
within the next 24 hours are highlighted in yellow.

Examples:
  cloop task deadlines
  cloop task deadlines --all    # include done/skipped tasks too`,
	RunE: func(cmd *cobra.Command, args []string) error {
		workdir, _ := os.Getwd()
		s, err := state.Load(workdir)
		if err != nil {
			return err
		}
		if !s.PMMode || s.Plan == nil || len(s.Plan.Tasks) == 0 {
			return fmt.Errorf("no task plan found — run 'cloop run --pm' to create one")
		}

		showAll, _ := cmd.Flags().GetBool("all")

		// Collect tasks with deadlines.
		type entry struct {
			task     *pm.Task
			timeLeft time.Duration
		}
		var entries []entry
		for _, t := range s.Plan.Tasks {
			if t.Deadline == nil {
				continue
			}
			if !showAll && (t.Status == pm.TaskDone || t.Status == pm.TaskSkipped) {
				continue
			}
			entries = append(entries, entry{t, pm.TimeUntilDeadlineD(t)})
		}

		if len(entries) == 0 {
			color.New(color.Faint).Println("No tasks with deadlines found.")
			if !showAll {
				color.New(color.Faint).Println("Use --all to include completed tasks.")
			}
			return nil
		}

		// Sort: most urgent first (smallest timeLeft → most overdue first, then soonest).
		sort.Slice(entries, func(i, j int) bool {
			return entries[i].timeLeft < entries[j].timeLeft
		})

		// Print SLA stats header.
		sla := pm.ComputeSLAStats(s.Plan)
		if sla.Total > 0 {
			pct := int(sla.ComplianceRatio * 100)
			slaColor := color.New(color.FgGreen)
			if pct < 80 {
				slaColor = color.New(color.FgYellow)
			}
			if pct < 50 {
				slaColor = color.New(color.FgRed)
			}
			fmt.Printf("SLA compliance: ")
			slaColor.Printf("%d%% (%d/%d met)\n\n", pct, sla.Met, sla.Total)
		}

		titleColor := color.New(color.FgCyan, color.Bold)
		titleColor.Printf("%-5s  %-12s  %-10s  %-20s  %s\n", "ID", "STATUS", "PRIORITY", "DEADLINE", "TITLE")
		fmt.Println(fmt.Sprintf("%-5s  %-12s  %-10s  %-20s  %s", "-----", "------------", "----------", "--------------------", "-----"))

		for _, e := range entries {
			t := e.task
			countdown := pm.FormatCountdown(e.timeLeft)
			deadlineStr := t.Deadline.Format("2006-01-02 15:04")

			statusStr := string(t.Status)
			priorityStr := fmt.Sprintf("P%d", t.Priority)

			line := fmt.Sprintf("%-5d  %-12s  %-10s  %-20s  %s",
				t.ID, statusStr, priorityStr, deadlineStr, truncateStr(t.Title, 50))

			switch {
			case pm.IsOverdue(t):
				color.New(color.FgRed).Printf("%s", line)
				color.New(color.FgRed, color.Bold).Printf("  ← %s\n", countdown)
			case e.timeLeft < 24*time.Hour:
				color.New(color.FgYellow).Printf("%s", line)
				color.New(color.FgYellow, color.Bold).Printf("  ← %s\n", countdown)
			case t.Status == pm.TaskDone || t.Status == pm.TaskSkipped:
				color.New(color.Faint).Printf("%s", line)
				color.New(color.Faint).Printf("  ← completed\n")
			default:
				fmt.Printf("%s", line)
				color.New(color.FgGreen).Printf("  ← %s\n", countdown)
			}
		}

		return nil
	},
}

func init() {
	taskDeadlinesCmd.Flags().Bool("all", false, "Include completed (done/skipped) tasks")
	taskCmd.AddCommand(taskDeadlinesCmd)
}
