package cmd

import (
	"encoding/json"
	"fmt"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"text/tabwriter"
	"time"

	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/workspace"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var workspaceAddDesc string

var workspaceCmd = &cobra.Command{
	Use:   "workspace",
	Short: "Manage multiple cloop projects from a single root",
	Long: `Workspace commands let you register and manage multiple cloop project directories.

Workspaces are stored globally in ~/.config/cloop/workspaces.json.

Examples:
  cloop workspace add myapi                        # register cwd as "myapi"
  cloop workspace add frontend /path/to/frontend   # register a specific path
  cloop workspace list                             # table of all workspaces with task counts
  cloop workspace switch myapi                     # set active workspace + write pointer file
  cloop workspace status                           # aggregate dashboard across all workspaces
  cloop workspace run-all                          # run 'cloop run' in every workspace
  cloop --workspace myapi status                   # run any command in a named workspace`,
}

var workspaceAddCmd = &cobra.Command{
	Use:   "add <name> [path]",
	Short: "Register a directory as a named workspace (default: current directory)",
	Args:  cobra.RangeArgs(1, 2),
	RunE: func(cmd *cobra.Command, args []string) error {
		name := args[0]
		path := "."
		if len(args) > 1 {
			path = args[1]
		}
		if err := workspace.Add(name, path, workspaceAddDesc); err != nil {
			return err
		}
		absPath, _ := filepath.Abs(path)
		color.Green("✓ Workspace %q registered", name)
		fmt.Printf("  Path: %s\n", absPath)
		if workspaceAddDesc != "" {
			fmt.Printf("  Desc: %s\n", workspaceAddDesc)
		}
		return nil
	},
}

var workspaceRemoveCmd = &cobra.Command{
	Use:     "remove <name>",
	Aliases: []string{"rm", "delete"},
	Short:   "Unregister a named workspace",
	Args:    cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		name := args[0]
		if err := workspace.Remove(name); err != nil {
			return err
		}
		color.Green("✓ Workspace %q removed", name)
		return nil
	},
}

var workspaceListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all registered workspaces with task counts",
	RunE: func(cmd *cobra.Command, args []string) error {
		workspaces, err := workspace.List()
		if err != nil {
			return err
		}
		if len(workspaces) == 0 {
			fmt.Println("No workspaces registered. Use 'cloop workspace add <name>' to register one.")
			return nil
		}
		active := workspace.GetActive()

		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "  NAME\tPATH\tTASKS\tLAST UPDATED")
		for _, ws := range workspaces {
			marker := "  "
			displayName := ws.Name
			if ws.Name == active {
				marker = "* "
				displayName = color.New(color.FgGreen, color.Bold).Sprint(ws.Name)
			}

			tasksStr := "-"
			lastUpdated := "-"
			s, loadErr := state.Load(ws.Path)
			if loadErr == nil {
				lastUpdated = s.UpdatedAt.Format("2006-01-02 15:04")
				if s.Plan != nil {
					done := countTasks(s, "done")
					pending := countTasks(s, "pending") + countTasks(s, "in_progress")
					tasksStr = fmt.Sprintf("%d done / %d pending", done, pending)
				}
			}

			fmt.Fprintf(w, "%s%s\t%s\t%s\t%s\n", marker, displayName, ws.Path, tasksStr, lastUpdated)
		}
		w.Flush()
		return nil
	},
}

var workspaceSwitchCmd = &cobra.Command{
	Use:   "switch <name>",
	Short: "Set the active workspace and write a local pointer file",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		name := args[0]
		ws, err := workspace.Get(name)
		if err != nil {
			return err
		}
		if err := workspace.Switch(name); err != nil {
			return err
		}
		color.Green("✓ Switched to workspace %q", name)
		fmt.Printf("  Path: %s\n", ws.Path)
		fmt.Printf("\nTo change your shell directory, run:\n")
		color.New(color.FgCyan).Printf("  cd %s\n", ws.Path)
		return nil
	},
}

// WorkspaceStatusEntry holds the aggregate dashboard data for one workspace.
type WorkspaceStatusEntry struct {
	Name         string  `json:"name"`
	Path         string  `json:"path"`
	Active       bool    `json:"active"`
	Goal         string  `json:"goal"`
	Status       string  `json:"status"`
	TotalTasks   int     `json:"total_tasks"`
	DoneTasks    int     `json:"done_tasks"`
	InProgress   int     `json:"in_progress_tasks"`
	FailedTasks  int     `json:"failed_tasks"`
	PendingTasks int     `json:"pending_tasks"`
	Velocity     float64 `json:"velocity_tasks_per_day"` // tasks completed per day
	LastActivity string  `json:"last_activity"`
	HealthScore  int     `json:"health_score"` // 0 if not available
	Error        string  `json:"error,omitempty"`
}

// computeVelocity returns tasks/day based on elapsed time from first to last completion.
// Falls back to tasks/day from project start if only one completed task exists.
func computeVelocity(s *state.ProjectState) float64 {
	if s.Plan == nil {
		return 0
	}
	var times []time.Time
	for _, t := range s.Plan.Tasks {
		if t.CompletedAt != nil {
			times = append(times, *t.CompletedAt)
		}
	}
	if len(times) == 0 {
		return 0
	}
	if len(times) == 1 {
		elapsed := time.Since(s.CreatedAt).Hours() / 24
		if elapsed < 0.001 {
			elapsed = 0.001
		}
		return 1.0 / elapsed
	}
	// Find earliest and latest completion times.
	earliest, latest := times[0], times[0]
	for _, t := range times[1:] {
		if t.Before(earliest) {
			earliest = t
		}
		if t.After(latest) {
			latest = t
		}
	}
	days := latest.Sub(earliest).Hours() / 24
	if days < 0.001 {
		days = 0.001
	}
	return math.Round(float64(len(times))/days*100) / 100
}

var workspaceStatusJSONFlag bool

var workspaceStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Aggregate dashboard across all registered workspaces",
	Long: `Display a unified status table for every registered workspace.

Columns: NAME, TOTAL, DONE, IN-PROG, FAILED, VELOCITY (tasks/day), LAST ACTIVITY, HEALTH

Use --json for machine-readable output.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		workspaces, err := workspace.List()
		if err != nil {
			return err
		}
		if len(workspaces) == 0 {
			fmt.Println("No workspaces registered. Use 'cloop workspace add <name>' to register one.")
			return nil
		}
		active := workspace.GetActive()

		entries := make([]WorkspaceStatusEntry, 0, len(workspaces))
		for _, ws := range workspaces {
			entry := WorkspaceStatusEntry{
				Name:   ws.Name,
				Path:   ws.Path,
				Active: ws.Name == active,
			}
			s, loadErr := state.Load(ws.Path)
			if loadErr != nil {
				entry.Error = "no state (run 'cloop init')"
			} else {
				entry.Goal = s.Goal
				entry.Status = s.Status
				entry.LastActivity = s.UpdatedAt.Format("2006-01-02 15:04")
				if s.Plan != nil {
					for _, t := range s.Plan.Tasks {
						entry.TotalTasks++
						switch string(t.Status) {
						case "done":
							entry.DoneTasks++
						case "in_progress":
							entry.InProgress++
						case "failed":
							entry.FailedTasks++
						case "pending":
							entry.PendingTasks++
						}
					}
					entry.Velocity = computeVelocity(s)
				}
				if s.HealthReport != nil {
					entry.HealthScore = s.HealthReport.Score
				}
			}
			entries = append(entries, entry)
		}

		if workspaceStatusJSONFlag {
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			return enc.Encode(entries)
		}

		// Human-readable table.
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "  NAME\tTOTAL\tDONE\tIN-PROG\tFAILED\tVELOCITY\tLAST ACTIVITY\tHEALTH")
		for _, e := range entries {
			marker := "  "
			displayName := e.Name
			if e.Active {
				marker = "* "
				displayName = color.New(color.FgGreen, color.Bold).Sprint(e.Name)
			}

			totalStr := "-"
			doneStr := "-"
			inProgStr := "-"
			failedStr := "-"
			velocityStr := "-"
			healthStr := "-"

			if e.Error == "" {
				totalStr = fmt.Sprintf("%d", e.TotalTasks)
				doneStr = colorCount(e.DoneTasks, color.FgGreen)
				inProgStr = colorCount(e.InProgress, color.FgYellow)
				failedStr = colorCount(e.FailedTasks, color.FgRed)
				if e.Velocity > 0 {
					velocityStr = fmt.Sprintf("%.2f/d", e.Velocity)
				} else {
					velocityStr = "n/a"
				}
				if e.HealthScore > 0 {
					healthStr = healthScoreStr(e.HealthScore)
				}
			}

			lastActivity := e.LastActivity
			if lastActivity == "" {
				lastActivity = "-"
			}
			if e.Error != "" {
				lastActivity = color.New(color.FgRed).Sprint(e.Error)
			}

			fmt.Fprintf(w, "%s%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
				marker, displayName,
				totalStr, doneStr, inProgStr, failedStr,
				velocityStr, lastActivity, healthStr)
		}
		w.Flush()
		return nil
	},
}

func colorCount(n int, c color.Attribute) string {
	if n == 0 {
		return "0"
	}
	return color.New(c).Sprintf("%d", n)
}

func healthScoreStr(score int) string {
	switch {
	case score >= 80:
		return color.New(color.FgGreen).Sprintf("%d", score)
	case score >= 50:
		return color.New(color.FgYellow).Sprintf("%d", score)
	default:
		return color.New(color.FgRed).Sprintf("%d", score)
	}
}

// ---------- workspace run-all ----------

var (
	runAllParallel   bool
	runAllExtraFlags []string
)

var workspaceRunAllCmd = &cobra.Command{
	Use:   "run-all",
	Short: "Run 'cloop run' in every registered workspace",
	Long: `Sequentially (or in parallel with --parallel) executes 'cloop run' inside
each registered workspace directory.

Extra flags after -- are forwarded to each 'cloop run' invocation.

Examples:
  cloop workspace run-all
  cloop workspace run-all --parallel
  cloop workspace run-all -- --pm --plan-only`,
	RunE: func(cmd *cobra.Command, args []string) error {
		workspaces, err := workspace.List()
		if err != nil {
			return err
		}
		if len(workspaces) == 0 {
			fmt.Println("No workspaces registered.")
			return nil
		}

		// Determine path to the current binary so sub-invocations use the same build.
		self, err := os.Executable()
		if err != nil {
			self = "cloop"
		}

		// Extra args forwarded to each run invocation.
		extra := args // cobra passes unparsed args after -- here

		type result struct {
			name string
			err  error
		}
		results := make([]result, len(workspaces))

		runOne := func(idx int, ws workspace.Workspace) {
			color.New(color.FgCyan).Printf("==> [%s] running in %s\n", ws.Name, ws.Path)
			runArgs := append([]string{"run"}, extra...)
			c := exec.Command(self, runArgs...)
			c.Dir = ws.Path
			c.Stdout = os.Stdout
			c.Stderr = os.Stderr
			results[idx] = result{name: ws.Name, err: c.Run()}
			if results[idx].err != nil {
				color.New(color.FgRed).Printf("==> [%s] FAILED: %v\n", ws.Name, results[idx].err)
			} else {
				color.New(color.FgGreen).Printf("==> [%s] done\n", ws.Name)
			}
		}

		if runAllParallel {
			var wg sync.WaitGroup
			for i, ws := range workspaces {
				wg.Add(1)
				go func(idx int, w workspace.Workspace) {
					defer wg.Done()
					runOne(idx, w)
				}(i, ws)
			}
			wg.Wait()
		} else {
			for i, ws := range workspaces {
				runOne(i, ws)
			}
		}

		// Summary.
		var failed []string
		for _, r := range results {
			if r.err != nil {
				failed = append(failed, r.name)
			}
		}
		fmt.Printf("\n%d workspaces processed", len(workspaces))
		if len(failed) > 0 {
			color.New(color.FgRed).Printf(", %d failed: %v\n", len(failed), failed)
			return fmt.Errorf("%d workspace(s) failed", len(failed))
		}
		color.New(color.FgGreen).Println(", all succeeded")
		return nil
	},
}

func init() {
	workspaceAddCmd.Flags().StringVar(&workspaceAddDesc, "desc", "", "Optional description for the workspace")

	workspaceStatusCmd.Flags().BoolVar(&workspaceStatusJSONFlag, "json", false, "Output as JSON array")

	workspaceRunAllCmd.Flags().BoolVar(&runAllParallel, "parallel", false, "Run all workspaces in parallel")

	workspaceCmd.AddCommand(workspaceAddCmd)
	workspaceCmd.AddCommand(workspaceRemoveCmd)
	workspaceCmd.AddCommand(workspaceListCmd)
	workspaceCmd.AddCommand(workspaceSwitchCmd)
	workspaceCmd.AddCommand(workspaceStatusCmd)
	workspaceCmd.AddCommand(workspaceRunAllCmd)

	rootCmd.AddCommand(workspaceCmd)
}
