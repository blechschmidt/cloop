package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"text/tabwriter"

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
  cloop workspace status                           # combined status across all workspaces
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

var workspaceStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Combined status summary across all registered workspaces",
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
		fmt.Fprintln(w, "  NAME\tGOAL\tSTATUS\tTASKS\tLAST ACTIVITY")
		for _, ws := range workspaces {
			marker := "  "
			displayName := ws.Name
			if ws.Name == active {
				marker = "* "
				displayName = color.New(color.FgGreen, color.Bold).Sprint(ws.Name)
			}

			goal := "-"
			statusStr := "-"
			tasksStr := "-"
			lastActivity := "-"

			s, loadErr := state.Load(ws.Path)
			if loadErr == nil {
				if s.Goal != "" {
					goal = s.Goal
					if len(goal) > 40 {
						goal = goal[:37] + "..."
					}
				}
				statusStr = s.Status
				lastActivity = s.UpdatedAt.Format("2006-01-02 15:04")
				if s.Plan != nil {
					done := countTasks(s, "done")
					pending := countTasks(s, "pending") + countTasks(s, "in_progress")
					tasksStr = fmt.Sprintf("%dd/%dp", done, pending)
				}
			}

			fmt.Fprintf(w, "%s%s\t%s\t%s\t%s\t%s\n",
				marker, displayName, goal, statusStr, tasksStr, lastActivity)
		}
		w.Flush()
		return nil
	},
}

func init() {
	workspaceAddCmd.Flags().StringVar(&workspaceAddDesc, "desc", "", "Optional description for the workspace")

	workspaceCmd.AddCommand(workspaceAddCmd)
	workspaceCmd.AddCommand(workspaceRemoveCmd)
	workspaceCmd.AddCommand(workspaceListCmd)
	workspaceCmd.AddCommand(workspaceSwitchCmd)
	workspaceCmd.AddCommand(workspaceStatusCmd)

	rootCmd.AddCommand(workspaceCmd)
}
