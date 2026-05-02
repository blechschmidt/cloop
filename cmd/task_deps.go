package cmd

import (
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"github.com/blechschmidt/cloop/pkg/depseditor"
	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/state"
)

var (
	depsAddID    int
	depsRemoveID int
	depsCheck    bool
)

var taskDepsCmd = &cobra.Command{
	Use:   "deps <task-id>",
	Short: "View and edit task dependencies interactively",
	Long: `Launch an interactive TUI to view and edit the dependencies of a task.

The editor shows the full dependency graph and a checklist of all other tasks.
Use arrow keys to navigate, SPACE to toggle a dependency, and ENTER to confirm.
Cycles are detected in real-time and highlighted in red; the editor blocks
confirmation until the cycle is resolved.

Non-interactive flags:
  --add <id>     Add a dependency without launching the TUI
  --remove <id>  Remove a dependency without launching the TUI
  --check        Exit 0 if the plan has no circular dependencies (CI-friendly)

Examples:
  cloop task deps 5               # open interactive TUI for task 5
  cloop task deps 5 --add 3      # make task 5 depend on task 3
  cloop task deps 5 --remove 3   # remove dependency on task 3
  cloop task deps --check         # check for cycles across entire plan`,
	Args: func(cmd *cobra.Command, args []string) error {
		checkFlag, _ := cmd.Flags().GetBool("check")
		if checkFlag {
			return nil // --check does not require a task ID
		}
		if len(args) != 1 {
			return fmt.Errorf("requires exactly 1 argument: <task-id>")
		}
		return nil
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		workdir, _ := os.Getwd()
		s, err := state.Load(workdir)
		if err != nil {
			return err
		}
		if !s.PMMode || s.Plan == nil || len(s.Plan.Tasks) == 0 {
			return fmt.Errorf("no task plan found — run 'cloop run --pm' to create one")
		}

		// ── --check: exit 0 if no cycles ────────────────────────────────────
		if depsCheck {
			if depseditor.PlanHasCycle(s.Plan) {
				color.New(color.FgRed).Fprintf(os.Stderr, "FAIL: circular dependency detected in plan\n")
				os.Exit(1)
			}
			color.New(color.FgGreen).Printf("OK: no circular dependencies\n")
			return nil
		}

		taskID, err := strconv.Atoi(args[0])
		if err != nil {
			return fmt.Errorf("invalid task ID %q: must be a number", args[0])
		}

		// Find the task.
		var task *pm.Task
		for _, t := range s.Plan.Tasks {
			if t.ID == taskID {
				task = t
				break
			}
		}
		if task == nil {
			return fmt.Errorf("task %d not found", taskID)
		}

		// ── --add / --remove: non-interactive scripting ──────────────────────
		if cmd.Flags().Changed("add") {
			return depsAddDep(s, task, depsAddID)
		}
		if cmd.Flags().Changed("remove") {
			return depsRemoveDep(s, task, depsRemoveID)
		}

		// ── Interactive TUI ──────────────────────────────────────────────────
		editorPtr, err := depseditor.New(s.Plan, taskID)
		if err != nil {
			return err
		}

		p := tea.NewProgram(*editorPtr, tea.WithAltScreen())
		finalModel, runErr := p.Run()
		if runErr != nil {
			return fmt.Errorf("TUI error: %w", runErr)
		}

		result, ok := finalModel.(depseditor.Model)
		if !ok {
			return fmt.Errorf("unexpected model type")
		}
		if result.Cancelled() {
			fmt.Println("Cancelled — no changes saved.")
			return nil
		}
		if !result.Confirmed() {
			return nil
		}

		// Apply updated deps.
		task.DependsOn = result.Result()
		sort.Ints(task.DependsOn)

		if err := s.Save(); err != nil {
			return fmt.Errorf("saving state: %w", err)
		}

		if len(task.DependsOn) == 0 {
			color.New(color.FgGreen).Printf("Task %d: no dependencies\n", taskID)
		} else {
			parts := make([]string, len(task.DependsOn))
			for i, id := range task.DependsOn {
				parts[i] = fmt.Sprintf("#%d", id)
			}
			color.New(color.FgGreen).Printf("Task %d depends on: %s\n", taskID, strings.Join(parts, ", "))
		}
		return nil
	},
}

func depsAddDep(s *state.ProjectState, task *pm.Task, depID int) error {
	// Check dep task exists.
	var depTask *pm.Task
	for _, t := range s.Plan.Tasks {
		if t.ID == depID {
			depTask = t
			break
		}
	}
	if depTask == nil {
		return fmt.Errorf("dependency task %d not found", depID)
	}

	// Already present?
	for _, existing := range task.DependsOn {
		if existing == depID {
			fmt.Printf("Task %d already depends on #%d\n", task.ID, depID)
			return nil
		}
	}

	// Cycle check before committing.
	if depseditor.WouldCreateCycle(s.Plan, task.ID, depID) {
		return fmt.Errorf("adding dependency #%d to task %d would create a circular dependency", depID, task.ID)
	}

	task.DependsOn = append(task.DependsOn, depID)
	sort.Ints(task.DependsOn)

	if err := s.Save(); err != nil {
		return fmt.Errorf("saving state: %w", err)
	}

	color.New(color.FgGreen).Printf("Task %d now depends on #%d (%s)\n", task.ID, depID, depTask.Title)
	return nil
}

func depsRemoveDep(s *state.ProjectState, task *pm.Task, depID int) error {
	idx := -1
	for i, id := range task.DependsOn {
		if id == depID {
			idx = i
			break
		}
	}
	if idx == -1 {
		return fmt.Errorf("task %d does not depend on #%d", task.ID, depID)
	}

	task.DependsOn = append(task.DependsOn[:idx], task.DependsOn[idx+1:]...)

	if err := s.Save(); err != nil {
		return fmt.Errorf("saving state: %w", err)
	}

	color.New(color.FgGreen).Printf("Removed dependency #%d from task %d\n", depID, task.ID)
	return nil
}

func init() {
	taskDepsCmd.Flags().IntVar(&depsAddID, "add", 0, "Add a dependency by task ID (non-interactive)")
	taskDepsCmd.Flags().IntVar(&depsRemoveID, "remove", 0, "Remove a dependency by task ID (non-interactive)")
	taskDepsCmd.Flags().BoolVar(&depsCheck, "check", false, "Exit 0 if no circular dependencies exist (CI mode)")

	taskCmd.AddCommand(taskDepsCmd)
}
