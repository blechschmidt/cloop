package cmd

import (
	"fmt"
	"os"
	"text/tabwriter"
	"time"

	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/session"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var sessionCmd = &cobra.Command{
	Use:   "session",
	Short: "Manage named execution sessions with isolated state",
	Long: `Sessions let you run multiple independent plan variants in the same project.
Each session has its own state.db so plans don't overwrite each other.

Examples:
  cloop session new experiment-a            # new blank session
  cloop session new hotfix --from-current   # branch from current state
  cloop session list                        # show all sessions
  cloop session switch experiment-a         # activate session
  cloop session switch --default            # back to the default (no session)
  cloop session rm old-experiment           # delete a session`,
}

var sessionNewFromCurrent bool

var sessionNewCmd = &cobra.Command{
	Use:   "new <name>",
	Short: "Create a new named session",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		name := args[0]
		workdir, _ := os.Getwd()

		var copyFrom string
		if sessionNewFromCurrent {
			// Copy the currently active session's state.db.
			activeDir := state.ActiveDir(workdir)
			if activeDir == workdir {
				copyFrom = state.StateDBPath(workdir)
			} else {
				copyFrom = activeDir + "/state.db"
			}
			if _, err := os.Stat(copyFrom); os.IsNotExist(err) {
				return fmt.Errorf("no current state to copy (run 'cloop init' first)")
			}
		}

		sess, err := session.New(workdir, name, copyFrom)
		if err != nil {
			return err
		}

		if sessionNewFromCurrent {
			color.Green("Created session %q (copied from current state)", sess.Name)
		} else {
			color.Green("Created session %q", sess.Name)
		}
		fmt.Printf("  Directory : %s\n", session.Dir(workdir, name))
		fmt.Printf("  State     : %s\n", sess.StateFile)
		fmt.Println()
		fmt.Printf("Activate with: cloop session switch %s\n", name)
		return nil
	},
}

var sessionSwitchDefault bool

var sessionSwitchCmd = &cobra.Command{
	Use:   "switch <name>",
	Short: "Switch to a named session (or back to default with --default)",
	Args:  cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		workdir, _ := os.Getwd()

		if sessionSwitchDefault {
			if err := session.Switch(workdir, ""); err != nil && !os.IsNotExist(err) {
				return err
			}
			color.Yellow("Switched to default session")
			return nil
		}

		if len(args) == 0 {
			return fmt.Errorf("provide a session name or use --default")
		}

		name := args[0]
		if err := session.Switch(workdir, name); err != nil {
			return err
		}
		color.Green("Switched to session %q", name)
		return nil
	},
}

var sessionListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all sessions with task counts and status",
	RunE: func(cmd *cobra.Command, args []string) error {
		workdir, _ := os.Getwd()

		sessions, err := session.List(workdir)
		if err != nil {
			return err
		}

		active := session.ActiveName(workdir)

		if len(sessions) == 0 {
			fmt.Println("No sessions found. Create one with: cloop session new <name>")
			return nil
		}

		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "NAME\tCREATED\tTASKS\tDONE\tSTATUS\t")
		for _, s := range sessions {
			marker := ""
			if s.Name == active {
				marker = color.GreenString(" *")
			}
			created := s.CreatedAt.Format(time.DateOnly)
			tasks, done, status := sessionTaskSummary(workdir, s.Name)
			fmt.Fprintf(w, "%s%s\t%s\t%d\t%d\t%s\t\n",
				s.Name, marker, created, tasks, done, status)
		}
		_ = w.Flush()

		if active == "" {
			fmt.Println("\n(default session is active)")
		} else {
			fmt.Printf("\n(active: %s)\n", color.GreenString(active))
		}
		return nil
	},
}

var sessionRmCmd = &cobra.Command{
	Use:   "rm <name>",
	Short: "Delete a session",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		name := args[0]
		workdir, _ := os.Getwd()

		if err := session.Remove(workdir, name); err != nil {
			return err
		}
		color.Yellow("Deleted session %q", name)
		return nil
	},
}

// sessionTaskSummary loads the session's state and returns (totalTasks, doneTasks, status).
func sessionTaskSummary(workdir, name string) (int, int, string) {
	dbPath := session.DBPath(workdir, name)
	if _, err := os.Stat(dbPath); os.IsNotExist(err) {
		return 0, 0, "no state"
	}

	sessDir := session.Dir(workdir, name)
	s, err := state.LoadFromDir(sessDir)
	if err != nil || s == nil {
		return 0, 0, "unreadable"
	}

	if s.Plan == nil {
		return 0, 0, s.Status
	}

	total := len(s.Plan.Tasks)
	done := 0
	for _, t := range s.Plan.Tasks {
		if t.Status == pm.TaskDone {
			done++
		}
	}
	return total, done, s.Status
}

func init() {
	sessionNewCmd.Flags().BoolVar(&sessionNewFromCurrent, "from-current", false, "Copy the current session's state into the new session")
	sessionSwitchCmd.Flags().BoolVar(&sessionSwitchDefault, "default", false, "Switch back to the default (no named session)")

	sessionCmd.AddCommand(sessionNewCmd)
	sessionCmd.AddCommand(sessionListCmd)
	sessionCmd.AddCommand(sessionSwitchCmd)
	sessionCmd.AddCommand(sessionRmCmd)

	rootCmd.AddCommand(sessionCmd)
}
