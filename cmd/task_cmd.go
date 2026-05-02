package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

// taskShowArtifact controls whether task show prints the full artifact file.
var taskShowArtifact bool

// parseDeps parses a comma-separated string of task IDs (e.g. "1,2,3") into []int.
// Returns nil and no error for empty input.
func parseDeps(s string) ([]int, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, nil
	}
	parts := strings.Split(s, ",")
	deps := make([]int, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		id, err := strconv.Atoi(p)
		if err != nil {
			return nil, fmt.Errorf("invalid dependency ID %q: must be a number", p)
		}
		deps = append(deps, id)
	}
	return deps, nil
}

var (
	taskDesc      string
	taskPriority  int
	taskListJSON  bool
	taskListGraph bool
	taskShowJSON  bool
	taskDeps      string // comma-separated dep IDs for task add/edit
	taskRole      string // agent role for task add

	// edit flags
	editTitle    string
	editDesc     string
	editPriority int
	editDeps     string
	editRole     string // agent role for task edit
)

var taskCmd = &cobra.Command{
	Use:   "task",
	Short: "Manage PM mode tasks",
	Long: `Manage tasks in product manager mode.

Subcommands:
  list          Show all tasks
  show <id>     Show full task details
  next          Show the next pending task
  skip <id>     Mark a task as skipped
  done <id>     Mark a task as done
  fail <id>     Mark a task as failed
  reset <id>    Reset a task to pending
  add <title>   Add a new task to the plan
  edit <id>     Edit task title, description, priority, or deps
  remove <id>   Remove a task from the plan
  move <id> up|down  Reorder a task by swapping with adjacent priority

Task dependencies:
  Use --deps when adding or editing tasks to specify prerequisites.
  A task with unresolved dependencies will be skipped by the scheduler
  until all dependencies are done or skipped.`,
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
		if taskListJSON {
			fmt.Println(marshalTasksJSON(s.Plan.Tasks))
			return nil
		}
		if taskListGraph {
			printTaskGraph(s.Plan)
			return nil
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

var taskFailCmd = &cobra.Command{
	Use:   "fail <id>",
	Short: "Mark a task as failed",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		return setTaskStatus(args[0], pm.TaskFailed)
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

		if taskShowJSON {
			data, err := json.MarshalIndent(task, "", "  ")
			if err != nil {
				return fmt.Errorf("marshaling task: %w", err)
			}
			fmt.Println(string(data))
			return nil
		}

		dimColor := color.New(color.Faint)
		titleColor := color.New(color.FgWhite, color.Bold)

		titleColor.Printf("Task %d: %s\n", task.ID, task.Title)
		fmt.Printf("Status:   %s\n", task.Status)
		fmt.Printf("Priority: %d\n", task.Priority)
		if task.Role != "" {
			fmt.Printf("Role:     %s\n", task.Role)
		}
		if len(task.DependsOn) > 0 {
			depParts := make([]string, 0, len(task.DependsOn))
			for _, depID := range task.DependsOn {
				depParts = append(depParts, fmt.Sprintf("#%d", depID))
			}
			fmt.Printf("Depends:  %s\n", strings.Join(depParts, ", "))
		}
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
		if task.ArtifactPath != "" {
			fmt.Printf("\nArtifact: %s\n", task.ArtifactPath)
			if taskShowArtifact {
				data, readErr := os.ReadFile(filepath.Join(workdir, task.ArtifactPath))
				if readErr != nil {
					fmt.Printf("  (could not read artifact: %v)\n", readErr)
				} else {
					fmt.Printf("\n%s\n", string(data))
				}
			}
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

		if !cmd.Flags().Changed("title") && !cmd.Flags().Changed("desc") && !cmd.Flags().Changed("priority") && !cmd.Flags().Changed("depends-on") && !cmd.Flags().Changed("role") {
			return fmt.Errorf("no changes specified — use --title, --desc, --priority, --depends-on, or --role")
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
		if cmd.Flags().Changed("depends-on") {
			deps, err := parseDeps(editDeps)
			if err != nil {
				return err
			}
			task.DependsOn = deps
			changed = append(changed, "deps")
		}
		if cmd.Flags().Changed("role") {
			task.Role = pm.AgentRole(editRole)
			changed = append(changed, "role")
		}

		if err := s.Save(); err != nil {
			return err
		}

		color.New(color.FgGreen).Printf("Task %d updated (%s)\n", task.ID, strings.Join(changed, ", "))
		fmt.Printf("  Title:    %s\n", task.Title)
		fmt.Printf("  Priority: %d\n", task.Priority)
		if task.Role != "" {
			fmt.Printf("  Role:     %s\n", task.Role)
		}
		if task.Description != "" {
			dimColor := color.New(color.Faint)
			dimColor.Printf("  Desc:     %s\n", truncateStr(task.Description, 100))
		}
		return nil
	},
}

var taskNextCmd = &cobra.Command{
	Use:   "next",
	Short: "Show the next pending task",
	RunE: func(cmd *cobra.Command, args []string) error {
		workdir, _ := os.Getwd()
		s, err := state.Load(workdir)
		if err != nil {
			return err
		}
		if !s.PMMode || s.Plan == nil || len(s.Plan.Tasks) == 0 {
			return fmt.Errorf("no task plan found — run 'cloop run --pm' to create one")
		}
		task := s.Plan.NextTask()
		if task == nil {
			color.New(color.FgGreen).Printf("All tasks complete — no pending tasks remaining.\n")
			return nil
		}
		titleColor := color.New(color.FgWhite, color.Bold)
		dimColor := color.New(color.Faint)
		titleColor.Printf("Next task: #%d [P%d] %s\n", task.ID, task.Priority, task.Title)
		if task.Description != "" {
			dimColor.Printf("  %s\n", task.Description)
		}
		return nil
	},
}

var taskMoveCmd = &cobra.Command{
	Use:   "move <id> <up|down>",
	Short: "Move a task up or down in priority order",
	Long: `Move a task up (higher priority) or down (lower priority) by swapping
priorities with the adjacent task in the sorted order.

Examples:
  cloop task move 3 up    # increase priority of task 3
  cloop task move 5 down  # decrease priority of task 5`,
	Args: cobra.ExactArgs(2),
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

		direction := strings.ToLower(args[1])
		if direction != "up" && direction != "down" {
			return fmt.Errorf("direction must be 'up' or 'down', got %q", args[1])
		}

		// Build a sorted copy (by priority, stable) to find adjacents.
		sorted := make([]*pm.Task, len(s.Plan.Tasks))
		copy(sorted, s.Plan.Tasks)
		sort.SliceStable(sorted, func(i, j int) bool {
			return sorted[i].Priority < sorted[j].Priority
		})

		// Find our task's position in the sorted slice.
		idx := -1
		for i, t := range sorted {
			if t.ID == id {
				idx = i
				break
			}
		}
		if idx == -1 {
			return fmt.Errorf("task %d not found", id)
		}

		var other *pm.Task
		if direction == "up" {
			if idx == 0 {
				return fmt.Errorf("task %d is already at the highest priority", id)
			}
			other = sorted[idx-1]
		} else {
			if idx == len(sorted)-1 {
				return fmt.Errorf("task %d is already at the lowest priority", id)
			}
			other = sorted[idx+1]
		}

		// Swap priorities.
		sorted[idx].Priority, other.Priority = other.Priority, sorted[idx].Priority

		if err := s.Save(); err != nil {
			return err
		}

		arrow := "↑"
		if direction == "down" {
			arrow = "↓"
		}
		color.New(color.FgGreen).Printf("Moved task %d %s %s (priority now %d)\n",
			id, arrow, direction, sorted[idx].Priority)
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

		deps, err := parseDeps(taskDeps)
		if err != nil {
			return err
		}

		task := &pm.Task{
			ID:          maxID + 1,
			Title:       title,
			Description: taskDesc,
			Priority:    priority,
			Role:        pm.AgentRole(taskRole),
			DependsOn:   deps,
			Status:      pm.TaskPending,
		}
		s.Plan.Tasks = append(s.Plan.Tasks, task)

		if err := s.Save(); err != nil {
			return err
		}

		msg := fmt.Sprintf("Added task %d: %s (priority %d)", task.ID, task.Title, task.Priority)
		if task.Role != "" {
			msg += fmt.Sprintf(", role: %s", task.Role)
		}
		if len(deps) > 0 {
			msg += fmt.Sprintf(", depends on: %s", taskDeps)
		}
		color.New(color.FgGreen).Println(msg)
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

	// Sort by priority (lowest number = highest priority), stable to preserve insertion order for ties.
	sorted := make([]*pm.Task, len(plan.Tasks))
	copy(sorted, plan.Tasks)
	sort.SliceStable(sorted, func(i, j int) bool {
		return sorted[i].Priority < sorted[j].Priority
	})

	fmt.Printf("Tasks: %s\n\n", plan.Summary())
	for _, t := range sorted {
		rolePart := ""
		if t.Role != "" {
			rolePart = fmt.Sprintf(" [%s]", t.Role)
		}
		line := fmt.Sprintf("  %s #%d [P%d]%s %s\n", taskMarker(t.Status), t.ID, t.Priority, rolePart, t.Title)
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
			// Check if blocked by unresolved dependencies
			if t.Status == pm.TaskPending && !plan.DepsReady(t) {
				dimColor.Print(line)
			} else {
				fmt.Print(line)
			}
		}
		if t.Description != "" {
			dimColor.Printf("       %s\n", truncateStr(t.Description, 100))
		}
		if len(t.DependsOn) > 0 {
			depParts := make([]string, 0, len(t.DependsOn))
			for _, depID := range t.DependsOn {
				depParts = append(depParts, fmt.Sprintf("#%d", depID))
			}
			dimColor.Printf("       depends on: %s\n", strings.Join(depParts, ", "))
		}
	}
}

// printTaskGraph renders the task plan as a layered dependency graph.
// Tasks are grouped into topological layers: layer 0 has no deps,
// layer N has all deps in layers < N. Within each layer tasks are sorted
// by priority. Dependency edges are shown as "needs #x, #y" annotations.
func printTaskGraph(plan *pm.Plan) {
	headerColor := color.New(color.FgCyan, color.Bold)
	dimColor := color.New(color.Faint)
	successColor := color.New(color.FgGreen)
	failColor := color.New(color.FgRed)
	warnColor := color.New(color.FgYellow)

	// Build ID → task index map for fast lookup
	byID := make(map[int]*pm.Task, len(plan.Tasks))
	for _, t := range plan.Tasks {
		byID[t.ID] = t
	}

	// Compute depth of each task (longest dep chain).
	depth := make(map[int]int, len(plan.Tasks))
	var computeDepth func(id int, visited map[int]bool) int
	computeDepth = func(id int, visited map[int]bool) int {
		if visited[id] {
			return 0 // cycle guard
		}
		if d, ok := depth[id]; ok {
			return d
		}
		t, ok := byID[id]
		if !ok {
			return 0
		}
		visited[id] = true
		max := 0
		for _, depID := range t.DependsOn {
			if d := computeDepth(depID, visited) + 1; d > max {
				max = d
			}
		}
		visited[id] = false
		depth[id] = max
		return max
	}
	for _, t := range plan.Tasks {
		computeDepth(t.ID, make(map[int]bool))
	}

	// Group by depth layer
	maxDepth := 0
	for _, d := range depth {
		if d > maxDepth {
			maxDepth = d
		}
	}
	layers := make([][]*pm.Task, maxDepth+1)
	for _, t := range plan.Tasks {
		d := depth[t.ID]
		layers[d] = append(layers[d], t)
	}
	for _, layer := range layers {
		sort.SliceStable(layer, func(i, j int) bool {
			return layer[i].Priority < layer[j].Priority
		})
	}

	sep := strings.Repeat("─", 72)
	fmt.Println(sep)
	headerColor.Printf("  Task Graph  —  %s\n", plan.Summary())
	fmt.Println(sep)
	fmt.Println()

	layerNames := []string{
		"ROOT  (no dependencies)",
		"LAYER 2",
		"LAYER 3",
		"LAYER 4",
		"LAYER 5",
		"LAYER 6",
		"LAYER 7",
		"LAYER 8",
	}

	for layerIdx, layer := range layers {
		if len(layer) == 0 {
			continue
		}
		label := fmt.Sprintf("LAYER %d", layerIdx+1)
		if layerIdx == 0 {
			label = "ROOT  (no dependencies)"
		}
		dimColor.Printf("  %s\n", label)

		for _, t := range layer {
			marker := taskMarker(t.Status)

			// Role badge
			rolePart := ""
			if t.Role != "" {
				rolePart = fmt.Sprintf(" [%s]", t.Role)
			}

			// Dependency annotation
			depPart := ""
			if len(t.DependsOn) > 0 {
				parts := make([]string, 0, len(t.DependsOn))
				for _, depID := range t.DependsOn {
					parts = append(parts, fmt.Sprintf("#%d", depID))
				}
				depPart = fmt.Sprintf("  ──needs── %s", strings.Join(parts, ", "))
			}

			line := fmt.Sprintf("  %s #%-3d P%-2d  %-40s%s%s\n",
				marker, t.ID, t.Priority, truncateStr(t.Title, 40), rolePart, depPart)

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
				if !plan.DepsReady(t) {
					dimColor.Print(line)
				} else {
					fmt.Print(line)
				}
			}
		}
		fmt.Println()
		// Draw a connector line between layers
		if layerIdx < len(layers)-1 {
			dimColor.Printf("  %s\n", strings.Repeat("╌", 68))
			fmt.Println()
		}
	}

	// Suppress unused variable warning for layerNames (used only for documentation)
	_ = layerNames

	fmt.Println(sep)
	fmt.Printf("  Legend: [x] done  [-] skipped  [!] failed  [~] in-progress  [ ] pending\n")
	fmt.Println(sep)
	fmt.Println()
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

// marshalTasksJSON returns tasks sorted by priority as a formatted JSON string.
// Returns an empty JSON array on marshal error (should never happen for valid tasks).
func marshalTasksJSON(tasks []*pm.Task) string {
	sorted := make([]*pm.Task, len(tasks))
	copy(sorted, tasks)
	sort.SliceStable(sorted, func(i, j int) bool {
		return sorted[i].Priority < sorted[j].Priority
	})
	data, err := json.MarshalIndent(sorted, "", "  ")
	if err != nil {
		return "[]"
	}
	return string(data)
}

func init() {
	taskListCmd.Flags().BoolVar(&taskListJSON, "json", false, "Output tasks as JSON array")
	taskListCmd.Flags().BoolVar(&taskListGraph, "graph", false, "Render tasks as a layered dependency graph")
	taskShowCmd.Flags().BoolVar(&taskShowJSON, "json", false, "Output task as JSON")
	taskShowCmd.Flags().BoolVar(&taskShowArtifact, "artifact", false, "Print full artifact file contents")

	taskAddCmd.Flags().StringVar(&taskDesc, "desc", "", "Task description")
	taskAddCmd.Flags().IntVar(&taskPriority, "priority", 0, "Task priority (1=highest; default: lowest)")
	taskAddCmd.Flags().StringVar(&taskDeps, "depends-on", "", "Comma-separated IDs of tasks this task depends on (e.g. '1,2')")
	taskAddCmd.Flags().StringVar(&taskRole, "role", "", "Agent role: backend, frontend, testing, security, devops, data, docs, review")

	taskEditCmd.Flags().StringVar(&editTitle, "title", "", "New title for the task")
	taskEditCmd.Flags().StringVar(&editDesc, "desc", "", "New description for the task")
	taskEditCmd.Flags().IntVar(&editPriority, "priority", 0, "New priority for the task (1=highest)")
	taskEditCmd.Flags().StringVar(&editDeps, "depends-on", "", "Comma-separated IDs of tasks this task depends on (e.g. '1,2'); use '' to clear")
	taskEditCmd.Flags().StringVar(&editRole, "role", "", "Agent role: backend, frontend, testing, security, devops, data, docs, review")

	taskCmd.AddCommand(taskListCmd)
	taskCmd.AddCommand(taskShowCmd)
	taskCmd.AddCommand(taskNextCmd)
	taskCmd.AddCommand(taskSkipCmd)
	taskCmd.AddCommand(taskResetCmd)
	taskCmd.AddCommand(taskDoneCmd)
	taskCmd.AddCommand(taskFailCmd)
	taskCmd.AddCommand(taskAddCmd)
	taskCmd.AddCommand(taskEditCmd)
	taskCmd.AddCommand(taskRemoveCmd)
	taskCmd.AddCommand(taskMoveCmd)
	rootCmd.AddCommand(taskCmd)
}
