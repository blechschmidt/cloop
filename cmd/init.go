package cmd

import (
	"fmt"
	"os"

	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var (
	maxSteps     int
	instructions string
	model        string
)

var initCmd = &cobra.Command{
	Use:   "init [goal]",
	Short: "Initialize a new cloop project with a goal",
	Long: `Set the project goal that cloop will work towards autonomously.

Examples:
  cloop init "Build a Go REST API with SQLite, JWT auth, and user CRUD"
  cloop init --max-steps 20 "Refactor the codebase to use clean architecture"
  cloop init --model sonnet --instructions "Use Go 1.24, no external deps" "Build a CLI tool"`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		goal := args[0]
		workdir, _ := os.Getwd()

		// Check for existing state
		if _, err := state.Load(workdir); err == nil {
			color.Yellow("⚠ Existing cloop project found. Overwriting.")
		}

		s, err := state.Init(workdir, goal, maxSteps)
		if err != nil {
			return fmt.Errorf("failed to initialize: %w", err)
		}

		if instructions != "" {
			s.Instructions = instructions
		}
		if model != "" {
			s.Model = model
		}
		if err := s.Save(); err != nil {
			return err
		}

		color.Green("✓ cloop initialized")
		fmt.Printf("  Goal: %s\n", goal)
		fmt.Printf("  Max steps: %d\n", maxSteps)
		fmt.Printf("  State: %s\n", state.StatePath(workdir))
		if model != "" {
			fmt.Printf("  Model: %s\n", model)
		}
		if instructions != "" {
			fmt.Printf("  Instructions: %s\n", instructions)
		}
		fmt.Printf("\nRun 'cloop run' to start the autonomous loop.\n")
		return nil
	},
}

func init() {
	initCmd.Flags().IntVar(&maxSteps, "max-steps", 0, "Maximum number of autonomous steps (0 = unlimited)")
	initCmd.Flags().StringVar(&instructions, "instructions", "", "Additional instructions/constraints for Claude")
	initCmd.Flags().StringVar(&model, "model", "", "Claude model to use (default: claude's default)")
	rootCmd.AddCommand(initCmd)
}
