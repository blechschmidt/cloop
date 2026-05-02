package cmd

import (
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/blechschmidt/cloop/pkg/archive"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var archiveAll bool

// taskArchiveCmd is the top-level `cloop task archive` command.
// It doubles as the archive action when no subcommand is given.
var taskArchiveCmd = &cobra.Command{
	Use:   "archive [--all] [id...]",
	Short: "Move completed tasks to .cloop/archive.json",
	Long: `Archive moves done/skipped/failed tasks out of the active plan into
.cloop/archive.json. This keeps the plan lean for long-running projects.

Archived tasks are excluded from the kanban board and timeline but remain
searchable via 'cloop search'.

Examples:
  cloop task archive --all           # archive every terminal task
  cloop task archive 3 7 12         # archive specific tasks by ID
  cloop task archive list            # list all archived tasks
  cloop task unarchive 3             # restore task 3 back to pending`,
	RunE: func(cmd *cobra.Command, args []string) error {
		workdir, _ := os.Getwd()
		s, err := state.Load(workdir)
		if err != nil {
			return err
		}
		if !s.PMMode || s.Plan == nil {
			return fmt.Errorf("no task plan found — run 'cloop run --pm' to create one")
		}

		if !archiveAll && len(args) == 0 {
			return fmt.Errorf("specify task IDs or use --all\n\nUsage: cloop task archive [--all] [id...]\n       cloop task archive list")
		}

		// Parse IDs from args.
		var ids []int
		for _, a := range args {
			id, err := strconv.Atoi(a)
			if err != nil {
				return fmt.Errorf("invalid task ID %q: must be a number", a)
			}
			ids = append(ids, id)
		}

		existing, err := archive.Load(workdir)
		if err != nil {
			return fmt.Errorf("loading archive: %w", err)
		}

		merged, err := archive.ArchiveTasks(s.Plan, existing, ids, archiveAll)
		if err != nil {
			return err
		}

		archived := merged[len(existing):]

		if err := s.Save(); err != nil {
			return fmt.Errorf("saving plan: %w", err)
		}
		if err := archive.Save(workdir, merged); err != nil {
			return fmt.Errorf("saving archive: %w", err)
		}

		successColor := color.New(color.FgGreen)
		dimColor := color.New(color.Faint)

		successColor.Printf("Archived %d task(s):\n", len(archived))
		for _, a := range archived {
			dimColor.Printf("  #%d %s [%s]\n", a.Task.ID, a.Task.Title, a.Task.Status)
		}
		fmt.Printf("\nActive plan now has %d task(s). Use 'cloop task archive list' to view the archive.\n", len(s.Plan.Tasks))
		return nil
	},
}

// taskArchiveListCmd lists all archived tasks.
var taskArchiveListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all archived tasks",
	RunE: func(cmd *cobra.Command, args []string) error {
		workdir, _ := os.Getwd()

		tasks, err := archive.Load(workdir)
		if err != nil {
			return fmt.Errorf("loading archive: %w", err)
		}

		if len(tasks) == 0 {
			color.New(color.Faint).Println("No archived tasks.")
			return nil
		}

		// Sort by archived_at descending (most recent first).
		sort.Slice(tasks, func(i, j int) bool {
			return tasks[i].ArchivedAt.After(tasks[j].ArchivedAt)
		})

		headerColor := color.New(color.FgCyan, color.Bold)
		dimColor := color.New(color.Faint)
		successColor := color.New(color.FgGreen)
		failColor := color.New(color.FgRed)
		warnColor := color.New(color.FgYellow)

		headerColor.Printf("Archived tasks (%d):\n\n", len(tasks))
		for _, a := range tasks {
			t := a.Task
			marker := taskMarker(t.Status)
			line := fmt.Sprintf("  %s #%d [P%d] %s\n", marker, t.ID, t.Priority, t.Title)
			switch t.Status {
			case "done":
				successColor.Print(line)
			case "skipped":
				dimColor.Print(line)
			case "failed", "timed_out":
				failColor.Print(line)
			default:
				warnColor.Print(line)
			}
			dimColor.Printf("       archived: %s\n", a.ArchivedAt.Format("2006-01-02 15:04"))
			if t.Description != "" {
				dimColor.Printf("       %s\n", truncateStr(t.Description, 100))
			}
			if len(t.Tags) > 0 {
				dimColor.Printf("       tags: %s\n", strings.Join(t.Tags, ", "))
			}
		}
		fmt.Printf("\nUse 'cloop task unarchive <id>' to restore a task to the active plan.\n")
		return nil
	},
}

// taskUnarchiveCmd restores a task from the archive back to the active plan.
var taskUnarchiveCmd = &cobra.Command{
	Use:   "unarchive <id>",
	Short: "Restore an archived task back to the active plan (status reset to pending)",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		workdir, _ := os.Getwd()

		id, err := strconv.Atoi(args[0])
		if err != nil {
			return fmt.Errorf("invalid task ID %q: must be a number", args[0])
		}

		s, err := state.Load(workdir)
		if err != nil {
			return err
		}
		if !s.PMMode || s.Plan == nil {
			return fmt.Errorf("no task plan found — run 'cloop run --pm' to create one")
		}

		tasks, err := archive.Load(workdir)
		if err != nil {
			return fmt.Errorf("loading archive: %w", err)
		}

		restored, updated, err := archive.UnarchiveTask(s.Plan, tasks, id)
		if err != nil {
			return err
		}

		if err := s.Save(); err != nil {
			return fmt.Errorf("saving plan: %w", err)
		}
		if err := archive.Save(workdir, updated); err != nil {
			return fmt.Errorf("saving archive: %w", err)
		}

		color.New(color.FgGreen).Printf("Task %d restored to active plan: %s\n", restored.ID, restored.Title)
		color.New(color.Faint).Printf("  Status reset to pending. Archive has %d task(s) remaining.\n", len(updated))
		return nil
	},
}

func init() {
	taskArchiveCmd.Flags().BoolVar(&archiveAll, "all", false, "Archive all done/skipped/failed tasks")
	taskArchiveCmd.AddCommand(taskArchiveListCmd)
}
