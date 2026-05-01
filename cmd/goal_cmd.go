package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var goalCmd = &cobra.Command{
	Use:   "goal [new-goal]",
	Short: "Show or update the project goal",
	Long: `Show the current project goal, or update it without reinitializing.

Examples:
  cloop goal                           # show current goal
  cloop goal "Refactor to use GRPC"    # update the goal`,
	Args: cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		workdir, _ := os.Getwd()
		s, err := state.Load(workdir)
		if err != nil {
			return err
		}

		if len(args) == 0 {
			// Show mode
			fmt.Printf("Goal: %s\n", s.Goal)
			return nil
		}

		// Update mode
		newGoal := strings.TrimSpace(args[0])
		if newGoal == "" {
			return fmt.Errorf("goal cannot be empty")
		}

		old := s.Goal
		s.Goal = newGoal
		if err := s.Save(); err != nil {
			return err
		}

		color.New(color.FgGreen).Printf("Goal updated.\n")
		color.New(color.Faint).Printf("  Old: %s\n", old)
		fmt.Printf("  New: %s\n", newGoal)
		return nil
	},
}

func init() {
	rootCmd.AddCommand(goalCmd)
}
