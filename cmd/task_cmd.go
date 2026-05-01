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
	taskDesc     string
	taskPriority int

	// edit flags
	editTitle    string
	editDesc     string
	editPriority int
)

var taskCmd = &cobra.Command{
	Use:   "task",
	Short: "Manage PM mode tasks",
	Long: `Manage tasks in product manager mode.

Subcommands:
  list          Show all tasks
  skip <id>     Mark a task as skipped
  reset <id>    Reset a task to pending
  done <id>     Mark a task as done
  add <title>   Add a new task to the plan`,
}

var taskListCmd = &cobra.Command{
	Use:     "list",
	Aliases: []string{"ls"},
	Short:   "List all tasks",
	RunE: func(cmd *cobra.Command, args []string) error {
		workdir, _ := os.Getwd()
		s, err := state.Load(workdir)
		if err != nil {
			return err
		}
		if !s.PMMode || s.Plan == nil || len(s.Plan.Tasks) == 0 {
			return fmt.Errorf("no task plan found — run 'cloop run --pm' to create one")
		}
		printTaskList(s.Plan)
		return nil
	},
}

var taskSkipCmd = &cobra.Command{
	Use:   "skip <id>",
	Short: "Mark a task as skipped",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		return setTaskStatus(args[0], pm.TaskSkipped)
	},
}

var taskResetCmd = &cobra.Command{
	Use:   "reset <id>",
	Short: "Reset a task to pending",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		return setTaskStatus(args[0], pm.TaskPending)
	},
}

var taskDoneCmd = &cobra.Command{
	Use:   "done <id>",
	Short: "Mark a task as done",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		return setTaskStatus(args[0], pm.TaskDone)
	},
}

var taskRemoveCmd = &cobra.Command{
	Use:     "remove <id>",
	Aliases: []string{"rm", "delete"},
	Short:   "Remove a task from the plan",
	Args:    cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		workdir, _ := os.Getwd()
		s, err := state.Load(workdir)
		if err != nil {
			return err
		}
		if !s.PMMode || s.Plan == nil {
			return fmt.Errorf("no task plan found — run 'cloop run --pm' to create one")
		}

		id, err := strconv.Atoi(args[0])
		if err != nil {
			return fmt.Errorf("invalid task ID %q: must be a number", args[0])
		}

		idx := -1
		for i, t := range s.Plan.Tasks {
			if t.ID == id {
				idx = i
				break
			}
		}
		if idx == -1 {
			return fmt.Errorf("task %d not found", id)
		}

		removed := s.Plan.Tasks[idx]
		s.Plan.Tasks = append(s.Plan.Tasks[:idx], s.Plan.Tasks[idx+1:]...)
		if err := s.Save(); err != nil {
			return err
		}

		color.New(color.FgYellow).Printf("Removed task %d: %s\n", removed.ID, removed.Title)
		return nil
	},
}

var taskShowCmd = &cobra.Command{
	Use:     "show <id>",
	Aliases: []string{"view", "detail"},
	Short:   "Show full details of a task",
	Args:    cobra.ExactArgs(1),
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

		dimColor := color.New(color.Faint)
		titleColor := color.New(color.FgWhite, color.Bold)

		titleColor.Printf("Task %d: %s\n", task.ID, task.Title)
		fmt.Printf("Status:   %s\n", task.Status)
		fmt.Printf("Priority: %d\n", task.Priority)
		if task.Description != "" {
			fmt.Printf("\nDescription:\n")
			fmt.Printf("  %s\n", strings.ReplaceAll(task.Description, "\n", "\n  "))
		}
		if task.StartedAt != nil {
			fmt.Printf("\nStarted:  %s\n", task.StartedAt.Format("2006-01-02 15:04:05"))
		}
		if task.CompletedAt != nil {
			fmt.Printf("Finished: %s\n", task.CompletedAt.Format("2006-01-02 15:04:05"))
		}
		if task.Result != "" {
			fmt.Printf("\nResult summary:\n")
			dimColor.Printf("  %s\n", strings.ReplaceAll(task.Result, "\n", "\n  "))
		}
		return nil
	},
}

var taskEditCmd = &cobra.Command{
	Use:     "edit <id>",
	Aliases: []string{"update"},
	Short:   "Edit a task's title, description, or priority",
	Args:    cobra.ExactArgs(1),
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

		if !cmd.Flags().Changed("title") && !cmd.Flags().Changed("desc") && !cmd.Flags().Changed("priority") {
			return fmt.Errorf("no changes specified — use --title, --desc, or --priority")
		}

		changed := []string{}
		if cmd.Flags().Changed("title") {
			task.Title = editTitle
			changed = append(changed, "title")
		}
		if cmd.Flags().Changed("desc") {
			task.Description = editDesc
			changed = append(changed, "description")
		}
		if cmd.Flags().Changed("priority") {
			task.Priority = editPriority
			changed = append(changed, "priority")
		}

		if err := s.Save(); err != nil {
			return err
		}

		color.New(color.FgGreen).Printf("Task %d updated (%s)\n", task.ID, strings.Join(changed, ", "))
		fmt.Printf("  Title:    %s\n", task.Title)
		fmt.Printf("  Priority: %d\n", task.Priority)
		if task.Description != "" {
			dimColor := color.New(color.Faint)
			dimColor.Printf("  Desc:     %s\n", truncateStr(task.Description, 100))
		}
		return nil
	},
}

var taskAddCmd = &cobra.Command{
	Use:   "add <title>",
	Short: "Add a new task to the plan",
	Args:  cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		workdir, _ := os.Getwd()
		s, err := state.Load(workdir)
		if err != nil {
			return err
		}
		if !s.PMMode {
			return fmt.Errorf("not in PM mode — run 'cloop init --pm' or 'cloop run --pm' first")
		}
		if s.Plan == nil {
			s.Plan = pm.NewPlan(s.Goal)
		}

		title := strings.Join(args, " ")

		// Auto-assign ID: max existing ID + 1
		maxID := 0
		for _, t := range s.Plan.Tasks {
			if t.ID > maxID {
				maxID = t.ID
			}
		}

		priority := taskPriority
		if priority == 0 {
			// Default: lowest priority (append at end)
			maxPriority := 0
			for _, t := range s.Plan.Tasks {
				if t.Priority > maxPriority {
					maxPriority = t.Priority
				}
			}
			priority = maxPriority + 1
		}

		task := &pm.Task{
			ID:          maxID + 1,
			Title:       title,
			Description: taskDesc,
			Priority:    priority,
			Status:      pm.TaskPending,
		}
		s.Plan.Tasks = append(s.Plan.Tasks, task)

		if err := s.Save(); err != nil {
			return err
		}

		color.New(color.FgGreen).Printf("Added task %d: %s (priority %d)\n", task.ID, task.Title, task.Priority)
		return nil
	},
}

func setTaskStatus(idStr string, status pm.TaskStatus) error {
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

	old := task.Status
	task.Status = status
	if err := s.Save(); err != nil {
		return err
	}

	verb := map[pm.TaskStatus]string{
		pm.TaskPending: "reset to pending",
		pm.TaskDone:    "marked done",
		pm.TaskSkipped: "skipped",
		pm.TaskFailed:  "marked failed",
	}[status]

	dimColor := color.New(color.Faint)
	fmt.Printf("Task %d: %s — %s", id, task.Title, verb)
	dimColor.Printf(" (was: %s)\n", old)
	return nil
}

func printTaskList(plan *pm.Plan) {
	dimColor := color.New(color.Faint)
	successColor := color.New(color.FgGreen)
	failColor := color.New(color.FgRed)
	warnColor := color.New(color.FgYellow)

	fmt.Printf("Tasks: %s\n\n", plan.Summary())
	for _, t := range plan.Tasks {
		line := fmt.Sprintf("  %s #%d [P%d] %s\n", taskMarker(t.Status), t.ID, t.Priority, t.Title)
		switch t.Status {
		case pm.TaskDone:
			successColor.Print(line)
		case pm.TaskSkipped:
			dimColor.Print(line)
		case pm.TaskFailed:
			failColor.Print(line)
		case pm.TaskInProgress:
			warnColor.Print(line)
		default:
			fmt.Print(line)
		}
		if t.Description != "" {
			dimColor.Printf("       %s\n", truncateStr(t.Description, 100))
		}
	}
}

func taskMarker(status pm.TaskStatus) string {
	switch status {
	case pm.TaskDone:
		return "[x]"
	case pm.TaskSkipped:
		return "[-]"
	case pm.TaskFailed:
		return "[!]"
	case pm.TaskInProgress:
		return "[~]"
	default:
		return "[ ]"
	}
}

// truncateStr truncates a string to at most n runes.
func truncateStr(s string, n int) string {
	runes := []rune(s)
	if len(runes) <= n {
		return s
	}
	return string(runes[:n]) + "..."
}

func init() {
	taskAddCmd.Flags().StringVar(&taskDesc, "desc", "", "Task description")
	taskAddCmd.Flags().IntVar(&taskPriority, "priority", 0, "Task priority (1=highest; default: lowest)")

	taskEditCmd.Flags().StringVar(&editTitle, "title", "", "New title for the task")
	taskEditCmd.Flags().StringVar(&editDesc, "desc", "", "New description for the task")
	taskEditCmd.Flags().IntVar(&editPriority, "priority", 0, "New priority for the task (1=highest)")

	taskCmd.AddCommand(taskListCmd)
	taskCmd.AddCommand(taskShowCmd)
	taskCmd.AddCommand(taskSkipCmd)
	taskCmd.AddCommand(taskResetCmd)
	taskCmd.AddCommand(taskDoneCmd)
	taskCmd.AddCommand(taskAddCmd)
	taskCmd.AddCommand(taskEditCmd)
	taskCmd.AddCommand(taskRemoveCmd)
	rootCmd.AddCommand(taskCmd)
}
