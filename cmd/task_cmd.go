package cmd

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/provider"
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
	taskListJSON  bool
	taskListGraph bool
	taskShowJSON  bool

	// edit flags
	editTitle    string
	editDesc     string
	editPriority int
	editDeps     string
	editRole     string // agent role for task edit
	editDeadline string // deadline override

	// filter flags
	taskListTags []string // --tags filter for task list
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
  tag <id> <tag...>      Add one or more tags to a task
  untag <id> <tag...>    Remove one or more tags from a task
  annotate <id> <text>   Append a user note to a task
  notes <id>             List all annotations for a task
  query <question>       Answer a natural language question about the plan
  merge <id1> <id2>...   Merge multiple tasks into one AI-synthesised task
  clone <id>             Duplicate a task, optionally AI-adapting it for a new context
  approve <id>           Pre-approve a task to bypass the --require-approval gate

Task dependencies:
  Use --deps when adding or editing tasks to specify prerequisites.
  A task with unresolved dependencies will be skipped by the scheduler
  until all dependencies are done or skipped.

Task tags:
  Use 'cloop task tag <id> <tag...>' to label tasks for filtering.
  Use 'cloop run --tags <tag,...>' to restrict execution to matching tasks.`,
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
			tasks := s.Plan.Tasks
			if len(taskListTags) > 0 {
				filtered := tasks[:0:0]
				for _, t := range tasks {
					if pm.TaskMatchesTags(t, taskListTags) {
						filtered = append(filtered, t)
					}
				}
				tasks = filtered
			}
			fmt.Println(marshalTasksJSON(tasks))
			return nil
		}
		if taskListGraph {
			printTaskGraph(s.Plan)
			return nil
		}
		printTaskListFiltered(s.Plan, taskListTags)
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
		if len(task.Tags) > 0 {
			fmt.Printf("Tags:     %s\n", strings.Join(task.Tags, ", "))
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
		if len(task.Links) > 0 {
			fmt.Printf("\nLinks:\n")
			for i, lnk := range task.Links {
				label := lnk.Label
				if label == "" {
					label = lnk.URL
				}
				dimColor.Printf("  %d. [%s] %s\n", i+1, lnk.Kind, label)
				if lnk.Label != "" {
					dimColor.Printf("       %s\n", lnk.URL)
				}
			}
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

		if !cmd.Flags().Changed("title") && !cmd.Flags().Changed("desc") && !cmd.Flags().Changed("priority") && !cmd.Flags().Changed("depends-on") && !cmd.Flags().Changed("role") && !cmd.Flags().Changed("deadline") {
			return fmt.Errorf("no changes specified — use --title, --desc, --priority, --depends-on, --role, or --deadline")
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
		if cmd.Flags().Changed("deadline") {
			if editDeadline == "" || editDeadline == "none" || editDeadline == "clear" {
				task.Deadline = nil
				changed = append(changed, "deadline cleared")
			} else {
				dl, err := pm.ParseDeadline(editDeadline)
				if err != nil {
					return fmt.Errorf("invalid deadline: %w", err)
				}
				task.Deadline = &dl
				changed = append(changed, "deadline")
			}
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

var taskTagCmd = &cobra.Command{
	Use:   "tag <id> <tag...>",
	Short: "Add tags to a task",
	Long: `Add one or more tags to a task. Tags are persisted in state.json and
can be used with 'cloop run --tags' to restrict execution to matching tasks.

Example:
  cloop task tag 3 backend api
  cloop task tag 5 release-1.0`,
	Args: cobra.MinimumNArgs(2),
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

		added := []string{}
		for _, tag := range args[1:] {
			tag = strings.TrimSpace(tag)
			if tag == "" {
				continue
			}
			// Deduplicate
			found := false
			for _, existing := range task.Tags {
				if existing == tag {
					found = true
					break
				}
			}
			if !found {
				task.Tags = append(task.Tags, tag)
				added = append(added, tag)
			}
		}

		if err := s.Save(); err != nil {
			return err
		}

		if len(added) == 0 {
			fmt.Printf("Task %d: no new tags added (already present)\n", id)
		} else {
			color.New(color.FgGreen).Printf("Task %d tagged: %s\n", id, strings.Join(task.Tags, ", "))
		}
		return nil
	},
}

var taskUntagCmd = &cobra.Command{
	Use:   "untag <id> <tag...>",
	Short: "Remove tags from a task",
	Long: `Remove one or more tags from a task.

Example:
  cloop task untag 3 backend
  cloop task untag 5 release-1.0`,
	Args: cobra.MinimumNArgs(2),
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

		removeSet := make(map[string]bool, len(args)-1)
		for _, tag := range args[1:] {
			removeSet[strings.TrimSpace(tag)] = true
		}

		kept := task.Tags[:0]
		for _, tag := range task.Tags {
			if !removeSet[tag] {
				kept = append(kept, tag)
			}
		}
		task.Tags = kept

		if err := s.Save(); err != nil {
			return err
		}

		if len(task.Tags) == 0 {
			color.New(color.FgYellow).Printf("Task %d: all tags removed\n", id)
		} else {
			color.New(color.FgGreen).Printf("Task %d tags: %s\n", id, strings.Join(task.Tags, ", "))
		}
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

func printTaskListFiltered(plan *pm.Plan, tagFilter []string) {
	if len(tagFilter) == 0 {
		printTaskList(plan)
		return
	}
	// Build a filtered copy of the plan
	filtered := &pm.Plan{Goal: plan.Goal, Tasks: make([]*pm.Task, 0), Version: plan.Version}
	for _, t := range plan.Tasks {
		if pm.TaskMatchesTags(t, tagFilter) {
			filtered.Tasks = append(filtered.Tasks, t)
		}
	}
	color.New(color.FgCyan).Printf("Filtered by tags: %s\n\n", strings.Join(tagFilter, ", "))
	printTaskList(filtered)
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
		if len(t.Tags) > 0 {
			dimColor.Printf("       tags: %s\n", strings.Join(t.Tags, ", "))
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

var (
	splitReason   string
	splitAuto     bool
	splitProvider string
	splitModel    string
	splitTimeout  string
)

var (
	mergeYes      bool
	mergeProvider string
	mergeModel    string
	mergeTimeout  string
)

var (
	cloneAdapt    string
	cloneYes      bool
	cloneProvider string
	cloneModel    string
	cloneTimeout  string
)

var taskSplitCmd = &cobra.Command{
	Use:   "split <id>",
	Short: "AI-powered task decomposition: split a task into smaller subtasks",
	Long: `Ask the AI to intelligently decompose a task into 2-5 smaller,
concrete subtasks. The subtasks replace the original task in the plan.

By default, the proposed subtasks are shown and you are prompted for
confirmation before any changes are made. Use --auto to skip confirmation.

Examples:
  cloop task split 5
  cloop task split 5 --reason "too complex, keeps failing"
  cloop task split 5 --auto
  cloop task split 5 --provider anthropic --model claude-opus-4-5`,
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

		taskID, err := strconv.Atoi(args[0])
		if err != nil {
			return fmt.Errorf("invalid task ID %q: must be a number", args[0])
		}

		// Find the task
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

		// Build provider
		cfg, err := config.Load(workdir)
		if err != nil {
			return fmt.Errorf("loading config: %w", err)
		}
		applyEnvOverrides(cfg)

		pName := splitProvider
		if pName == "" {
			pName = cfg.Provider
		}
		if pName == "" && s.Provider != "" {
			pName = s.Provider
		}
		if pName == "" {
			pName = autoSelectProvider()
		}

		model := splitModel
		if model == "" {
			switch pName {
			case "anthropic":
				model = cfg.Anthropic.Model
			case "openai":
				model = cfg.OpenAI.Model
			case "ollama":
				model = cfg.Ollama.Model
			case "claudecode":
				model = cfg.ClaudeCode.Model
			}
		}
		if model == "" {
			model = s.Model
		}

		provCfg := provider.ProviderConfig{
			Name:             pName,
			AnthropicAPIKey:  cfg.Anthropic.APIKey,
			AnthropicBaseURL: cfg.Anthropic.BaseURL,
			OpenAIAPIKey:     cfg.OpenAI.APIKey,
			OpenAIBaseURL:    cfg.OpenAI.BaseURL,
			OllamaBaseURL:    cfg.Ollama.BaseURL,
		}
		prov, err := provider.Build(provCfg)
		if err != nil {
			return fmt.Errorf("provider: %w", err)
		}

		timeout := 5 * time.Minute
		if splitTimeout != "" {
			timeout, err = time.ParseDuration(splitTimeout)
			if err != nil {
				return fmt.Errorf("invalid timeout: %w", err)
			}
		}

		dimColor := color.New(color.Faint)
		headerColor := color.New(color.FgCyan, color.Bold)
		warnColor := color.New(color.FgYellow)

		headerColor.Printf("Splitting task %d: %s\n", task.ID, task.Title)
		fmt.Printf("Asking AI to decompose this task into smaller subtasks...\n\n")

		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()

		opts := provider.Options{
			Model:   model,
			Timeout: timeout,
		}

		// Call AI to split — pass a copy of the plan so we can preview before applying
		planCopy := &pm.Plan{
			Goal:    s.Plan.Goal,
			Tasks:   make([]*pm.Task, len(s.Plan.Tasks)),
			Version: s.Plan.Version,
		}
		copy(planCopy.Tasks, s.Plan.Tasks)
		// Deep-copy tasks to avoid mutating original before confirmation
		for i, t := range s.Plan.Tasks {
			tc := *t
			planCopy.Tasks[i] = &tc
		}

		subtasks, err := pm.SplitTask(ctx, prov, opts, planCopy, taskID, splitReason)
		if err != nil {
			return fmt.Errorf("split failed: %w", err)
		}

		// Preview the subtasks
		fmt.Printf("Proposed subtasks to replace task %d:\n\n", taskID)
		for _, st := range subtasks {
			rolePart := ""
			if st.Role != "" {
				rolePart = fmt.Sprintf(" [%s]", st.Role)
			}
			warnColor.Printf("  #%d%s %s\n", st.ID, rolePart, st.Title)
			if st.Description != "" {
				dimColor.Printf("       %s\n", truncateStr(st.Description, 120))
			}
			if len(st.DependsOn) > 0 {
				deps := make([]string, 0, len(st.DependsOn))
				for _, depID := range st.DependsOn {
					deps = append(deps, fmt.Sprintf("#%d", depID))
				}
				dimColor.Printf("       depends on: %s\n", strings.Join(deps, ", "))
			}
		}
		fmt.Println()

		// Confirm unless --auto
		if !splitAuto {
			fmt.Printf("Apply this split? (y/N): ")
			scanner := bufio.NewScanner(os.Stdin)
			if !scanner.Scan() {
				return fmt.Errorf("no input received")
			}
			answer := strings.TrimSpace(strings.ToLower(scanner.Text()))
			if answer != "y" && answer != "yes" {
				fmt.Println("Split cancelled.")
				return nil
			}
		}

		// planCopy already has the split applied — make it the active plan.
		s.Plan = planCopy

		if err := s.Save(); err != nil {
			return fmt.Errorf("saving state: %w", err)
		}

		color.New(color.FgGreen).Printf("Split applied: task %d replaced with %d subtasks.\n",
			taskID, len(subtasks))
		return nil
	},
}

var taskMergeCmd = &cobra.Command{
	Use:   "merge <id1> <id2> [id3...]",
	Short: "AI-powered task merging: combine multiple tasks into one",
	Long: `Ask the AI to synthesise a merged task from the selected tasks' titles,
descriptions, and annotations. The merged task inherits:
  - Union of all dependencies (excluding internal ones) and tags
  - Highest priority (lowest number) among input tasks
  - Earliest deadline among input tasks

After optional confirmation the input tasks are marked skipped and the new
merged task is appended to the plan.

Examples:
  cloop task merge 3 5
  cloop task merge 1 2 4 --yes
  cloop task merge 7 8 --provider anthropic --model claude-opus-4-5`,
	Args: cobra.MinimumNArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		workdir, _ := os.Getwd()

		s, err := state.Load(workdir)
		if err != nil {
			return err
		}
		if !s.PMMode || s.Plan == nil || len(s.Plan.Tasks) == 0 {
			return fmt.Errorf("no task plan found — run 'cloop run --pm' to create one")
		}

		// Build provider
		cfg, err := config.Load(workdir)
		if err != nil {
			return fmt.Errorf("loading config: %w", err)
		}
		applyEnvOverrides(cfg)

		pName := mergeProvider
		if pName == "" {
			pName = cfg.Provider
		}
		if pName == "" && s.Provider != "" {
			pName = s.Provider
		}
		if pName == "" {
			pName = autoSelectProvider()
		}

		model := mergeModel
		if model == "" {
			switch pName {
			case "anthropic":
				model = cfg.Anthropic.Model
			case "openai":
				model = cfg.OpenAI.Model
			case "ollama":
				model = cfg.Ollama.Model
			case "claudecode":
				model = cfg.ClaudeCode.Model
			}
		}
		if model == "" {
			model = s.Model
		}

		provCfg := provider.ProviderConfig{
			Name:             pName,
			AnthropicAPIKey:  cfg.Anthropic.APIKey,
			AnthropicBaseURL: cfg.Anthropic.BaseURL,
			OpenAIAPIKey:     cfg.OpenAI.APIKey,
			OpenAIBaseURL:    cfg.OpenAI.BaseURL,
			OllamaBaseURL:    cfg.Ollama.BaseURL,
		}
		prov, err := provider.Build(provCfg)
		if err != nil {
			return fmt.Errorf("provider: %w", err)
		}

		timeout := 5 * time.Minute
		if mergeTimeout != "" {
			timeout, err = time.ParseDuration(mergeTimeout)
			if err != nil {
				return fmt.Errorf("invalid timeout: %w", err)
			}
		}

		dimColor := color.New(color.Faint)
		headerColor := color.New(color.FgCyan, color.Bold)
		warnColor := color.New(color.FgYellow)

		// Show input tasks
		headerColor.Printf("Merging %d tasks into one...\n\n", len(args))
		for _, idStr := range args {
			var id int
			if _, scanErr := fmt.Sscanf(idStr, "%d", &id); scanErr != nil {
				return fmt.Errorf("invalid task ID %q: must be a number", idStr)
			}
			var t *pm.Task
			for _, task := range s.Plan.Tasks {
				if task.ID == id {
					t = task
					break
				}
			}
			if t == nil {
				return fmt.Errorf("task %d not found", id)
			}
			rolePart := ""
			if t.Role != "" {
				rolePart = fmt.Sprintf(" [%s]", t.Role)
			}
			dimColor.Printf("  #%d%s %s\n", t.ID, rolePart, t.Title)
		}
		fmt.Println()

		// Deep-copy plan so we can preview before committing
		planCopy := &pm.Plan{
			Goal:    s.Plan.Goal,
			Tasks:   make([]*pm.Task, len(s.Plan.Tasks)),
			Version: s.Plan.Version,
		}
		for i, t := range s.Plan.Tasks {
			tc := *t
			// deep-copy slices
			if tc.DependsOn != nil {
				tc.DependsOn = append([]int{}, tc.DependsOn...)
			}
			if tc.Tags != nil {
				tc.Tags = append([]string{}, tc.Tags...)
			}
			planCopy.Tasks[i] = &tc
		}

		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()

		opts := pm.MergeOptions{
			Provider: provider.Options{
				Model:   model,
				Timeout: timeout,
			},
		}

		newTask, err := pm.Merge(ctx, prov, opts, planCopy, args)
		if err != nil {
			return fmt.Errorf("merge failed: %w", err)
		}

		// Preview merged task
		fmt.Printf("Proposed merged task:\n\n")
		rolePart := ""
		if newTask.Role != "" {
			rolePart = fmt.Sprintf(" [%s]", newTask.Role)
		}
		warnColor.Printf("  #%d%s %s\n", newTask.ID, rolePart, newTask.Title)
		if newTask.Description != "" {
			dimColor.Printf("       %s\n", truncateStr(newTask.Description, 140))
		}
		if len(newTask.DependsOn) > 0 {
			deps := make([]string, 0, len(newTask.DependsOn))
			for _, depID := range newTask.DependsOn {
				deps = append(deps, fmt.Sprintf("#%d", depID))
			}
			dimColor.Printf("       depends on: %s\n", strings.Join(deps, ", "))
		}
		if len(newTask.Tags) > 0 {
			dimColor.Printf("       tags: %s\n", strings.Join(newTask.Tags, ", "))
		}
		fmt.Println()

		// Confirm unless --yes
		if !mergeYes {
			fmt.Printf("Apply merge? Input tasks will be marked skipped. (y/N): ")
			scanner := bufio.NewScanner(os.Stdin)
			if !scanner.Scan() {
				return fmt.Errorf("no input received")
			}
			answer := strings.TrimSpace(strings.ToLower(scanner.Text()))
			if answer != "y" && answer != "yes" {
				fmt.Println("Merge cancelled.")
				return nil
			}
		}

		// Apply: replace active plan with the modified copy
		s.Plan = planCopy

		if err := s.Save(); err != nil {
			return fmt.Errorf("saving state: %w", err)
		}

		color.New(color.FgGreen).Printf("Merge applied: %d tasks merged into task #%d — %s\n",
			len(args), newTask.ID, newTask.Title)
		return nil
	},
}

var taskCloneCmd = &cobra.Command{
	Use:   "clone <id>",
	Short: "Duplicate a task, optionally AI-adapting it for a new context",
	Long: `Clone duplicates a task and appends the copy to the plan with the next
available ID. All metadata (priority, role, tags, deps, estimated time) is
inherited from the original; the new task starts as pending.

Without --adapt, the title gets a " (copy)" suffix and the description is
copied verbatim.

With --adapt, the AI rewrites the title and description for the supplied
context. This is useful for cloning a task like "add unit tests for X" and
adapting it to "add unit tests for Y" without manually re-writing it.

Examples:
  cloop task clone 5
  cloop task clone 5 --adapt "for the payment module instead of auth"
  cloop task clone 5 --adapt "for the v2 API" --yes
  cloop task clone 5 --provider anthropic --model claude-opus-4-5`,
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

		taskID, err := strconv.Atoi(args[0])
		if err != nil {
			return fmt.Errorf("invalid task ID %q: must be a number", args[0])
		}

		// Find the original task for display
		var original *pm.Task
		for _, t := range s.Plan.Tasks {
			if t.ID == taskID {
				original = t
				break
			}
		}
		if original == nil {
			return fmt.Errorf("task %d not found", taskID)
		}

		headerColor := color.New(color.FgCyan, color.Bold)
		dimColor := color.New(color.Faint)
		warnColor := color.New(color.FgYellow)

		headerColor.Printf("Cloning task %d: %s\n", original.ID, original.Title)

		// Simple copy path — no AI needed
		if cloneAdapt == "" {
			newID := 0
			for _, t := range s.Plan.Tasks {
				if t.ID > newID {
					newID = t.ID
				}
			}
			newID++

			warnColor.Printf("\nProposed clone:\n")
			fmt.Printf("  #%d %s (copy)\n", newID, original.Title)
			if original.Description != "" {
				dimColor.Printf("       %s\n", truncateStr(original.Description, 120))
			}
			fmt.Println()

			if !cloneYes {
				fmt.Printf("Apply clone? (y/N): ")
				scanner := bufio.NewScanner(os.Stdin)
				if !scanner.Scan() {
					return fmt.Errorf("no input received")
				}
				answer := strings.TrimSpace(strings.ToLower(scanner.Text()))
				if answer != "y" && answer != "yes" {
					fmt.Println("Clone cancelled.")
					return nil
				}
			}

			cloned, err := pm.Clone(cmd.Context(), nil, provider.Options{}, s.Plan, taskID, "")
			if err != nil {
				return fmt.Errorf("clone failed: %w", err)
			}
			if err := s.Save(); err != nil {
				return fmt.Errorf("saving state: %w", err)
			}
			color.New(color.FgGreen).Printf("Cloned task %d → task %d: %s\n", taskID, cloned.ID, cloned.Title)
			return nil
		}

		// AI-adaptation path — build provider
		cfg, err := config.Load(workdir)
		if err != nil {
			return fmt.Errorf("loading config: %w", err)
		}
		applyEnvOverrides(cfg)

		pName := cloneProvider
		if pName == "" {
			pName = cfg.Provider
		}
		if pName == "" && s.Provider != "" {
			pName = s.Provider
		}
		if pName == "" {
			pName = autoSelectProvider()
		}

		model := cloneModel
		if model == "" {
			switch pName {
			case "anthropic":
				model = cfg.Anthropic.Model
			case "openai":
				model = cfg.OpenAI.Model
			case "ollama":
				model = cfg.Ollama.Model
			case "claudecode":
				model = cfg.ClaudeCode.Model
			}
		}
		if model == "" {
			model = s.Model
		}

		provCfg := provider.ProviderConfig{
			Name:             pName,
			AnthropicAPIKey:  cfg.Anthropic.APIKey,
			AnthropicBaseURL: cfg.Anthropic.BaseURL,
			OpenAIAPIKey:     cfg.OpenAI.APIKey,
			OpenAIBaseURL:    cfg.OpenAI.BaseURL,
			OllamaBaseURL:    cfg.Ollama.BaseURL,
		}
		prov, err := provider.Build(provCfg)
		if err != nil {
			return fmt.Errorf("provider: %w", err)
		}

		timeout := 5 * time.Minute
		if cloneTimeout != "" {
			timeout, err = time.ParseDuration(cloneTimeout)
			if err != nil {
				return fmt.Errorf("invalid timeout: %w", err)
			}
		}

		fmt.Printf("Asking AI to adapt task for new context: %q\n\n", cloneAdapt)

		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()

		opts := provider.Options{
			Model:   model,
			Timeout: timeout,
		}

		// Deep-copy plan to allow preview before committing
		planCopy := &pm.Plan{
			Goal:    s.Plan.Goal,
			Tasks:   make([]*pm.Task, len(s.Plan.Tasks)),
			Version: s.Plan.Version,
		}
		for i, t := range s.Plan.Tasks {
			tc := *t
			if tc.DependsOn != nil {
				tc.DependsOn = append([]int{}, tc.DependsOn...)
			}
			if tc.Tags != nil {
				tc.Tags = append([]string{}, tc.Tags...)
			}
			planCopy.Tasks[i] = &tc
		}

		cloned, err := pm.Clone(ctx, prov, opts, planCopy, taskID, cloneAdapt)
		if err != nil {
			return fmt.Errorf("clone failed: %w", err)
		}

		// Preview
		warnColor.Printf("Proposed adapted clone:\n\n")
		rolePart := ""
		if cloned.Role != "" {
			rolePart = fmt.Sprintf(" [%s]", cloned.Role)
		}
		warnColor.Printf("  #%d%s %s\n", cloned.ID, rolePart, cloned.Title)
		if cloned.Description != "" {
			dimColor.Printf("       %s\n", truncateStr(cloned.Description, 140))
		}
		if len(cloned.Tags) > 0 {
			dimColor.Printf("       tags: %s\n", strings.Join(cloned.Tags, ", "))
		}
		fmt.Println()

		if !cloneYes {
			fmt.Printf("Apply adapted clone? (y/N): ")
			scanner := bufio.NewScanner(os.Stdin)
			if !scanner.Scan() {
				return fmt.Errorf("no input received")
			}
			answer := strings.TrimSpace(strings.ToLower(scanner.Text()))
			if answer != "y" && answer != "yes" {
				fmt.Println("Clone cancelled.")
				return nil
			}
		}

		s.Plan = planCopy
		if err := s.Save(); err != nil {
			return fmt.Errorf("saving state: %w", err)
		}
		color.New(color.FgGreen).Printf("Cloned task %d → task %d: %s\n", taskID, cloned.ID, cloned.Title)
		return nil
	},
}

var taskApproveCmd = &cobra.Command{
	Use:   "approve <id>",
	Short: "Pre-approve a task so unattended runs skip the approval gate",
	Long: `Mark a task as pre-approved in state.json. When a run uses --require-approval
or the task has requires_approval:true, the interactive gate prompt is automatically
bypassed for tasks that have been pre-approved via this command.

This is useful for unattended CI runs where a human has already reviewed the task
but the approval flag must still be satisfied.

Example:
  cloop task approve 3
  cloop task approve 5 --revoke`,
	Args: cobra.ExactArgs(1),
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

		revoke, _ := cmd.Flags().GetBool("revoke")
		if revoke {
			task.Approved = false
			if err := s.Save(); err != nil {
				return err
			}
			color.New(color.FgYellow).Printf("Task %d approval revoked: %s\n", task.ID, task.Title)
			return nil
		}

		task.Approved = true
		if err := s.Save(); err != nil {
			return err
		}
		color.New(color.FgGreen).Printf("Task %d pre-approved: %s\n", task.ID, task.Title)
		color.New(color.Faint).Printf("  This task will bypass the interactive approval gate on next run.\n")
		return nil
	},
}

var taskAnnotateCmd = &cobra.Command{
	Use:   "annotate <id> <text>",
	Short: "Append a user note to a task",
	Long: `Attach a timestamped note to a task. The note is persisted in state.json
and is displayed by 'cloop task notes <id>' and 'cloop status'.

Example:
  cloop task annotate 3 "Decided to use PostgreSQL instead of SQLite"
  cloop task annotate 5 "Blocked on deployment access — waiting for DevOps"`,
	Args: cobra.MinimumNArgs(2),
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

		text := strings.Join(args[1:], " ")
		pm.AddAnnotation(task, "user", text)

		if err := s.Save(); err != nil {
			return err
		}

		color.New(color.FgGreen).Printf("Annotation added to task %d [%d note(s) total]\n", id, len(task.Annotations))
		return nil
	},
}

var taskNotesCmd = &cobra.Command{
	Use:   "notes <id>",
	Short: "List all annotations for a task",
	Long: `Show all timestamped notes (user and AI) attached to a task.

Example:
  cloop task notes 3`,
	Args: cobra.ExactArgs(1),
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

		titleColor := color.New(color.FgWhite, color.Bold)
		dimColor := color.New(color.Faint)
		aiColor := color.New(color.FgCyan)
		userColor := color.New(color.FgGreen)

		titleColor.Printf("Task %d: %s — %d note(s)\n\n", task.ID, task.Title, len(task.Annotations))
		if len(task.Annotations) == 0 {
			dimColor.Printf("  No annotations yet. Use 'cloop task annotate %d <text>' to add one.\n", id)
			return nil
		}

		for i, a := range task.Annotations {
			ts := a.Timestamp.Format("2006-01-02 15:04:05")
			authorLabel := fmt.Sprintf("[%s]", a.Author)
			header := fmt.Sprintf("  #%d  %s  %s\n", i+1, ts, authorLabel)
			if a.Author == "ai" {
				aiColor.Print(header)
			} else {
				userColor.Print(header)
			}
			fmt.Printf("       %s\n\n", strings.ReplaceAll(a.Text, "\n", "\n       "))
		}
		return nil
	},
}

func init() {
	taskListCmd.Flags().BoolVar(&taskListJSON, "json", false, "Output tasks as JSON array")
	taskListCmd.Flags().BoolVar(&taskListGraph, "graph", false, "Render tasks as a layered dependency graph")
	taskShowCmd.Flags().BoolVar(&taskShowJSON, "json", false, "Output task as JSON")
	taskShowCmd.Flags().BoolVar(&taskShowArtifact, "artifact", false, "Print full artifact file contents")

	taskEditCmd.Flags().StringVar(&editTitle, "title", "", "New title for the task")
	taskEditCmd.Flags().StringVar(&editDesc, "desc", "", "New description for the task")
	taskEditCmd.Flags().IntVar(&editPriority, "priority", 0, "New priority for the task (1=highest)")
	taskEditCmd.Flags().StringVar(&editDeps, "depends-on", "", "Comma-separated IDs of tasks this task depends on (e.g. '1,2'); use '' to clear")
	taskEditCmd.Flags().StringVar(&editRole, "role", "", "Agent role: backend, frontend, testing, security, devops, data, docs, review")
	taskEditCmd.Flags().StringVar(&editDeadline, "deadline", "", "Task deadline: relative ('2h', '3d', '1w'), RFC3339, date ('2025-12-31'), or 'none'/'clear' to remove")

	taskListCmd.Flags().StringSliceVar(&taskListTags, "tags", nil, "Filter listed tasks by tag (comma-separated or repeated --tags)")

	taskSplitCmd.Flags().StringVar(&splitReason, "reason", "", "Reason for splitting (e.g. 'too complex, keeps failing')")
	taskSplitCmd.Flags().BoolVar(&splitAuto, "auto", false, "Skip confirmation prompt and apply the split immediately")
	taskSplitCmd.Flags().StringVar(&splitProvider, "provider", "", "AI provider to use (anthropic, openai, ollama, claudecode)")
	taskSplitCmd.Flags().StringVar(&splitModel, "model", "", "Model override for the AI provider")
	taskSplitCmd.Flags().StringVar(&splitTimeout, "timeout", "5m", "Timeout for the AI call (e.g. 2m, 300s)")

	taskMergeCmd.Flags().BoolVar(&mergeYes, "yes", false, "Skip confirmation prompt and apply the merge immediately")
	taskMergeCmd.Flags().StringVar(&mergeProvider, "provider", "", "AI provider to use (anthropic, openai, ollama, claudecode)")
	taskMergeCmd.Flags().StringVar(&mergeModel, "model", "", "Model override for the AI provider")
	taskMergeCmd.Flags().StringVar(&mergeTimeout, "timeout", "5m", "Timeout for the AI call (e.g. 2m, 300s)")

	taskCloneCmd.Flags().StringVar(&cloneAdapt, "adapt", "", "New context for AI-driven title/description adaptation")
	taskCloneCmd.Flags().BoolVar(&cloneYes, "yes", false, "Skip confirmation prompt and apply immediately")
	taskCloneCmd.Flags().StringVar(&cloneProvider, "provider", "", "AI provider to use (anthropic, openai, ollama, claudecode)")
	taskCloneCmd.Flags().StringVar(&cloneModel, "model", "", "Model override for the AI provider")
	taskCloneCmd.Flags().StringVar(&cloneTimeout, "timeout", "5m", "Timeout for the AI call (e.g. 2m, 300s)")

	taskCmd.AddCommand(taskListCmd)
	taskCmd.AddCommand(taskShowCmd)
	taskCmd.AddCommand(taskNextCmd)
	taskCmd.AddCommand(taskSkipCmd)
	taskCmd.AddCommand(taskResetCmd)
	taskCmd.AddCommand(taskDoneCmd)
	taskCmd.AddCommand(taskFailCmd)
	taskCmd.AddCommand(taskEditCmd)
	taskCmd.AddCommand(taskRemoveCmd)
	taskCmd.AddCommand(taskMoveCmd)
	taskCmd.AddCommand(taskTagCmd)
	taskCmd.AddCommand(taskUntagCmd)
	taskCmd.AddCommand(taskSplitCmd)
	taskCmd.AddCommand(taskMergeCmd)
	taskCmd.AddCommand(taskCloneCmd)
	taskApproveCmd.Flags().Bool("revoke", false, "Revoke a previously granted pre-approval")
	taskCmd.AddCommand(taskApproveCmd)
	taskCmd.AddCommand(taskAnnotateCmd)
	taskCmd.AddCommand(taskNotesCmd)
	taskCmd.AddCommand(taskLinkCmd)
	taskCmd.AddCommand(taskCheckpointDiffCmd)
	taskCmd.AddCommand(taskTimeTravelCmd)
	taskCmd.AddCommand(taskExecCmd)
	taskCmd.AddCommand(taskSummarizeCmd)
	taskCmd.AddCommand(taskCalibrateCmd)
	taskCmd.AddCommand(taskArchiveCmd)
	taskCmd.AddCommand(taskUnarchiveCmd)
	rootCmd.AddCommand(taskCmd)
}
