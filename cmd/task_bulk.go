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
	bulkTags     []string
	bulkPriority int
	bulkAll      bool
	bulkStatus   string
)

// parseIDList parses a comma-separated or space-separated list of task IDs
// from the given args. Returns deduplicated IDs in order of first appearance.
func parseIDList(args []string) ([]int, error) {
	seen := make(map[int]bool)
	var ids []int
	for _, arg := range args {
		// Each arg may itself be comma-separated (e.g. "1,2,3")
		for _, part := range strings.Split(arg, ",") {
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}
			id, err := strconv.Atoi(part)
			if err != nil {
				return nil, fmt.Errorf("invalid task ID %q: must be a number", part)
			}
			if !seen[id] {
				seen[id] = true
				ids = append(ids, id)
			}
		}
	}
	return ids, nil
}

// resolveTargetTasks returns the tasks matching the given IDs, or — when
// --all is set — all tasks matching the optional --status filter.
func resolveTargetTasks(plan *pm.Plan, ids []int, all bool, statusFilter string) ([]*pm.Task, error) {
	if all {
		var targets []*pm.Task
		for _, t := range plan.Tasks {
			if statusFilter == "" || string(t.Status) == statusFilter {
				targets = append(targets, t)
			}
		}
		if len(targets) == 0 {
			if statusFilter != "" {
				return nil, fmt.Errorf("no tasks with status %q found", statusFilter)
			}
			return nil, fmt.Errorf("no tasks found")
		}
		return targets, nil
	}

	if len(ids) == 0 {
		return nil, fmt.Errorf("provide task IDs as arguments (comma-separated) or use --all")
	}

	byID := make(map[int]*pm.Task, len(plan.Tasks))
	for _, t := range plan.Tasks {
		byID[t.ID] = t
	}

	targets := make([]*pm.Task, 0, len(ids))
	for _, id := range ids {
		t, ok := byID[id]
		if !ok {
			return nil, fmt.Errorf("task %d not found", id)
		}
		targets = append(targets, t)
	}
	return targets, nil
}

var taskBulkCmd = &cobra.Command{
	Use:   "bulk <operation> [ids...]",
	Short: "Batch operations on multiple tasks at once",
	Long: `Perform operations on multiple tasks in a single command, avoiding
the tedium of running 'cloop task' commands one at a time for large plans.

Operations:
  done         <ids>   Mark tasks as done
  skip         <ids>   Mark tasks as skipped
  fail         <ids>   Mark tasks as failed
  reset        <ids>   Reset tasks to pending
  tag          <ids>   Add tags to tasks (requires --tags)
  set-priority <ids>   Set priority on tasks (requires --priority)
  delete       <ids>   Remove tasks from the plan

IDs may be given as space-separated args, comma-separated, or mixed:
  cloop task bulk done 1 2 3
  cloop task bulk done 1,2,3
  cloop task bulk done 1,2 3

Use --all to target all tasks, optionally filtered by --status:
  cloop task bulk reset --all --status failed
  cloop task bulk tag --all --status pending --tags sprint-1

Examples:
  cloop task bulk done 1,2,3
  cloop task bulk skip 4 5 6
  cloop task bulk tag 1,2,3 --tags backend,api
  cloop task bulk set-priority 4,5 --priority 2
  cloop task bulk delete 7,8
  cloop task bulk reset --all --status failed`,
}

var taskBulkDoneCmd = &cobra.Command{
	Use:   "done [ids...]",
	Short: "Mark multiple tasks as done",
	RunE:  bulkStatusFn(pm.TaskDone, "done"),
}

var taskBulkSkipCmd = &cobra.Command{
	Use:   "skip [ids...]",
	Short: "Mark multiple tasks as skipped",
	RunE:  bulkStatusFn(pm.TaskSkipped, "skipped"),
}

var taskBulkFailCmd = &cobra.Command{
	Use:   "fail [ids...]",
	Short: "Mark multiple tasks as failed",
	RunE:  bulkStatusFn(pm.TaskFailed, "failed"),
}

var taskBulkResetCmd = &cobra.Command{
	Use:   "reset [ids...]",
	Short: "Reset multiple tasks to pending",
	RunE:  bulkStatusFn(pm.TaskPending, "reset to pending"),
}

// bulkStatusFn returns a RunE function that sets all target tasks to the given status.
func bulkStatusFn(newStatus pm.TaskStatus, verb string) func(*cobra.Command, []string) error {
	return func(cmd *cobra.Command, args []string) error {
		workdir, _ := os.Getwd()
		s, err := state.Load(workdir)
		if err != nil {
			return err
		}
		if !s.PMMode || s.Plan == nil {
			return fmt.Errorf("no task plan found — run 'cloop run --pm' to create one")
		}

		ids, err := parseIDList(args)
		if err != nil {
			return err
		}

		targets, err := resolveTargetTasks(s.Plan, ids, bulkAll, bulkStatus)
		if err != nil {
			return err
		}

		for _, t := range targets {
			t.Status = newStatus
		}

		if err := s.Save(); err != nil {
			return err
		}

		green := color.New(color.FgGreen)
		green.Printf("Bulk %s: %d task(s)\n", verb, len(targets))
		dim := color.New(color.Faint)
		for _, t := range targets {
			dim.Printf("  #%d %s\n", t.ID, t.Title)
		}
		return nil
	}
}

var taskBulkTagCmd = &cobra.Command{
	Use:   "tag [ids...]",
	Short: "Add tags to multiple tasks",
	Long: `Add one or more tags to multiple tasks at once.

Example:
  cloop task bulk tag 1,2,3 --tags backend,api
  cloop task bulk tag --all --status pending --tags sprint-2`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if len(bulkTags) == 0 {
			return fmt.Errorf("--tags is required for the tag operation")
		}

		workdir, _ := os.Getwd()
		s, err := state.Load(workdir)
		if err != nil {
			return err
		}
		if !s.PMMode || s.Plan == nil {
			return fmt.Errorf("no task plan found — run 'cloop run --pm' to create one")
		}

		ids, err := parseIDList(args)
		if err != nil {
			return err
		}

		targets, err := resolveTargetTasks(s.Plan, ids, bulkAll, bulkStatus)
		if err != nil {
			return err
		}

		for _, t := range targets {
			for _, tag := range bulkTags {
				tag = strings.TrimSpace(tag)
				if tag == "" {
					continue
				}
				found := false
				for _, existing := range t.Tags {
					if existing == tag {
						found = true
						break
					}
				}
				if !found {
					t.Tags = append(t.Tags, tag)
				}
			}
		}

		if err := s.Save(); err != nil {
			return err
		}

		green := color.New(color.FgGreen)
		green.Printf("Tagged %d task(s) with: %s\n", len(targets), strings.Join(bulkTags, ", "))
		dim := color.New(color.Faint)
		for _, t := range targets {
			dim.Printf("  #%d %s  [%s]\n", t.ID, t.Title, strings.Join(t.Tags, ", "))
		}
		return nil
	},
}

var taskBulkSetPriorityCmd = &cobra.Command{
	Use:   "set-priority [ids...]",
	Short: "Set the priority on multiple tasks",
	Long: `Assign a priority value to multiple tasks at once.

Example:
  cloop task bulk set-priority 4,5,6 --priority 2
  cloop task bulk set-priority --all --status pending --priority 10`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if !cmd.Flags().Changed("priority") {
			return fmt.Errorf("--priority is required for the set-priority operation")
		}

		workdir, _ := os.Getwd()
		s, err := state.Load(workdir)
		if err != nil {
			return err
		}
		if !s.PMMode || s.Plan == nil {
			return fmt.Errorf("no task plan found — run 'cloop run --pm' to create one")
		}

		ids, err := parseIDList(args)
		if err != nil {
			return err
		}

		targets, err := resolveTargetTasks(s.Plan, ids, bulkAll, bulkStatus)
		if err != nil {
			return err
		}

		for _, t := range targets {
			t.Priority = bulkPriority
		}

		if err := s.Save(); err != nil {
			return err
		}

		green := color.New(color.FgGreen)
		green.Printf("Set priority %d on %d task(s)\n", bulkPriority, len(targets))
		dim := color.New(color.Faint)
		for _, t := range targets {
			dim.Printf("  #%d %s\n", t.ID, t.Title)
		}
		return nil
	},
}

var taskBulkDeleteCmd = &cobra.Command{
	Use:     "delete [ids...]",
	Aliases: []string{"remove", "rm"},
	Short:   "Remove multiple tasks from the plan",
	Long: `Delete multiple tasks from the plan in one command.

Example:
  cloop task bulk delete 7,8,9
  cloop task bulk delete --all --status skipped`,
	RunE: func(cmd *cobra.Command, args []string) error {
		workdir, _ := os.Getwd()
		s, err := state.Load(workdir)
		if err != nil {
			return err
		}
		if !s.PMMode || s.Plan == nil {
			return fmt.Errorf("no task plan found — run 'cloop run --pm' to create one")
		}

		ids, err := parseIDList(args)
		if err != nil {
			return err
		}

		targets, err := resolveTargetTasks(s.Plan, ids, bulkAll, bulkStatus)
		if err != nil {
			return err
		}

		// Build set of IDs to remove
		removeSet := make(map[int]bool, len(targets))
		for _, t := range targets {
			removeSet[t.ID] = true
		}

		remaining := make([]*pm.Task, 0, len(s.Plan.Tasks)-len(targets))
		for _, t := range s.Plan.Tasks {
			if !removeSet[t.ID] {
				remaining = append(remaining, t)
			}
		}
		s.Plan.Tasks = remaining

		if err := s.Save(); err != nil {
			return err
		}

		yellow := color.New(color.FgYellow)
		yellow.Printf("Deleted %d task(s)\n", len(targets))
		dim := color.New(color.Faint)
		for _, t := range targets {
			dim.Printf("  #%d %s\n", t.ID, t.Title)
		}
		return nil
	},
}

func init() {
	// Shared flags on the parent bulk command so all sub-commands inherit them.
	taskBulkCmd.PersistentFlags().BoolVar(&bulkAll, "all", false, "Target all tasks (optionally filtered by --status)")
	taskBulkCmd.PersistentFlags().StringVar(&bulkStatus, "status", "", "Filter tasks by status when using --all (pending, in_progress, done, skipped, failed)")

	taskBulkTagCmd.Flags().StringSliceVar(&bulkTags, "tags", nil, "Comma-separated tags to apply (required)")
	taskBulkSetPriorityCmd.Flags().IntVar(&bulkPriority, "priority", 0, "Priority value to assign (required)")

	taskBulkCmd.AddCommand(taskBulkDoneCmd)
	taskBulkCmd.AddCommand(taskBulkSkipCmd)
	taskBulkCmd.AddCommand(taskBulkFailCmd)
	taskBulkCmd.AddCommand(taskBulkResetCmd)
	taskBulkCmd.AddCommand(taskBulkTagCmd)
	taskBulkCmd.AddCommand(taskBulkSetPriorityCmd)
	taskBulkCmd.AddCommand(taskBulkDeleteCmd)

	taskCmd.AddCommand(taskBulkCmd)
}
