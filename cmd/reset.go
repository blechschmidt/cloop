package cmd

import (
	"fmt"
	"os"

	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var resetCmd = &cobra.Command{
	Use:   "reset",
	Short: "Reset progress (keep goal, clear steps)",
	RunE: func(cmd *cobra.Command, args []string) error {
		workdir, _ := os.Getwd()
		s, err := state.Load(workdir)
		if err != nil {
			return err
		}

		s.Steps = []state.StepResult{}
		s.CurrentStep = 0
		s.Status = "initialized"
		if err := s.Save(); err != nil {
			return err
		}

		color.Green("✓ Progress reset. Goal preserved: %s", s.Goal)
		return nil
	},
}

var cleanCmd = &cobra.Command{
	Use:   "clean",
	Short: "Remove .cloop directory entirely",
	RunE: func(cmd *cobra.Command, args []string) error {
		workdir, _ := os.Getwd()
		if err := os.RemoveAll(fmt.Sprintf("%s/.cloop", workdir)); err != nil {
			return err
		}
		color.Green("✓ Removed .cloop/")
		return nil
	},
}

func init() {
	rootCmd.AddCommand(resetCmd)
	rootCmd.AddCommand(cleanCmd)
}
