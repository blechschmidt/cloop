package cmd

import (
	"fmt"
	"os"

	"github.com/blechschmidt/cloop/pkg/clijson"
	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var requireCommittedJSON bool

// requireCommittedCmd shows or sets "done means committed" (Task 20370)
// without starting a run — `cloop run --require-committed` sets it too, and
// then runs.
var requireCommittedCmd = &cobra.Command{
	Use:   "require-committed [committed|pushed|off]",
	Short: "Show or set whether a task is done only once its changes are committed (and pushed)",
	Long: `With "done means committed" on, a task whose agent says it is done is accepted
only once the changes it made are committed — and, with "pushed", on the
upstream of the branch they are on.

When the agent's turn ends, cloop compares the repository with what it held
when the attempt started. Paths the attempt changed and left uncommitted (and,
with "pushed", commits HEAD's upstream lacks) hand the turn back to the agent,
in the same conversation, naming them — at most twice. A task that still ends
that way goes back to pending with its work left in the tree, untouched, and
the next attempt is held to it. Changes that were already in the tree when the
task started, and cloop's own .cloop/ directory, are never the task's.

The setting belongs to the project, travels with it to isolating executors,
and reaches a run that is already going at its next task.

  cloop require-committed            # show the setting
  cloop require-committed committed  # done means committed
  cloop require-committed pushed     # ... and pushed
  cloop require-committed off`,
	Args: cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		workdir, _ := os.Getwd()
		s, err := state.Load(workdir)
		if err != nil {
			return err
		}
		p := s.CommitPolicy.Clone()
		if len(args) == 1 {
			next, err := pm.ParseCommitRequirement(args[0])
			if err != nil {
				return err
			}
			// Switching off keeps "pushed" for the next time it is switched on.
			if !next.Enabled && p != nil {
				next.Pushed = p.Pushed
			}
			if err := state.SetCommitPolicy(workdir, next); err != nil {
				return err
			}
			p = next
		}
		if p == nil {
			p = &pm.CommitPolicy{}
		}
		if requireCommittedJSON {
			return clijson.Emit(cmd.OutOrStdout(), p)
		}
		if len(args) == 1 {
			color.New(color.FgGreen).Println("Done means committed updated.")
		}
		printCommitPolicy(p)
		return nil
	},
}

// printCommitPolicy renders the setting for people.
func printCommitPolicy(p *pm.CommitPolicy) {
	bold := color.New(color.Bold)
	bold.Print("Done means committed: ")
	switch {
	case p.RequiresPush():
		color.New(color.FgGreen).Println("on, and pushed")
		fmt.Println("  A task is done only once its changes are committed and on their branch's upstream.")
	case p.Active():
		color.New(color.FgGreen).Println("on")
		fmt.Println("  A task is done only once its changes are committed.")
	default:
		fmt.Println("off")
		color.New(color.Faint).Println("  Turn it on with: cloop require-committed [committed|pushed]")
	}
}

func init() {
	requireCommittedCmd.Flags().BoolVar(&requireCommittedJSON, "json", false, "Print the setting as JSON")
	rootCmd.AddCommand(requireCommittedCmd)
}
