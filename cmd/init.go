package cmd

import (
	"fmt"
	"os"

	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var (
	maxSteps     int
	instructions string
	model        string
	initProvider string
)

var initCmd = &cobra.Command{
	Use:   "init [goal]",
	Short: "Initialize a new cloop project with a goal",
	Long: `Set the project goal that cloop will work towards autonomously.

Examples:
  cloop init "Build a Go REST API with SQLite, JWT auth, and user CRUD"
  cloop init --max-steps 20 "Refactor the codebase to use clean architecture"
  cloop init --provider anthropic --model claude-opus-4-6 "Build a CLI tool"
  cloop init --provider ollama --model llama3.2 "Write unit tests for this package"`,
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
		if initProvider != "" {
			s.Provider = initProvider
		}
		if err := s.Save(); err != nil {
			return err
		}

		// Write config.yaml if provider was specified and config doesn't exist
		if initProvider != "" {
			cfg, _ := config.Load(workdir)
			if cfg == nil {
				cfg = config.Default()
			}
			cfg.Provider = initProvider
			if err := config.Save(workdir, cfg); err != nil {
				color.Yellow("⚠ Could not write config.yaml: %v", err)
			}
		} else {
			// Write default config if none exists
			config.WriteDefault(workdir)
		}

		color.Green("✓ cloop initialized")
		fmt.Printf("  Goal: %s\n", goal)
		fmt.Printf("  Max steps: %d\n", maxSteps)
		fmt.Printf("  State: %s\n", state.StatePath(workdir))
		fmt.Printf("  Config: %s\n", config.ConfigPath(workdir))

		prov := initProvider
		if prov == "" {
			prov = "claudecode (default)"
		}
		fmt.Printf("  Provider: %s\n", prov)

		if model != "" {
			fmt.Printf("  Model: %s\n", model)
		}
		if instructions != "" {
			fmt.Printf("  Instructions: %s\n", instructions)
		}
		fmt.Printf("\nRun 'cloop run' to start.\n")
		fmt.Printf("Use 'cloop run --pm' for product manager mode (task decomposition).\n")
		return nil
	},
}

func init() {
	initCmd.Flags().IntVar(&maxSteps, "max-steps", 0, "Maximum number of autonomous steps (0 = unlimited)")
	initCmd.Flags().StringVar(&instructions, "instructions", "", "Additional instructions/constraints for the AI")
	initCmd.Flags().StringVar(&model, "model", "", "Model to use (provider-specific)")
	initCmd.Flags().StringVar(&initProvider, "provider", "", "AI provider: anthropic, openai, ollama, claudecode (default)")
	rootCmd.AddCommand(initCmd)
}
