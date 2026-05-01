package cmd

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/blechschmidt/cloop/pkg/orchestrator"
	"github.com/spf13/cobra"
)

var (
	runModel          string
	stepTimeout       string
	runMaxTokens      int
	verbose           bool
	dryRun            bool
	continueSteps     int
	skipPermissions   bool
	autoEvolve        bool
)

var runCmd = &cobra.Command{
	Use:   "run",
	Short: "Start or continue the autonomous feedback loop",
	Long: `Run the cloop feedback loop. Claude Code will work through
the project goal step by step until completion or max steps.

Press Ctrl+C to pause gracefully.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		workdir, _ := os.Getwd()

		timeout, err := time.ParseDuration(stepTimeout)
		if err != nil {
			return fmt.Errorf("invalid step-timeout: %w", err)
		}

		cfg := orchestrator.Config{
			WorkDir:         workdir,
			Model:           runModel,
			MaxTokens:       runMaxTokens,
			StepTimeout:     timeout,
			Verbose:         verbose,
			DryRun:          dryRun,
			SkipPermissions: skipPermissions,
		}

		orc, err := orchestrator.New(cfg)
		if err != nil {
			return err
		}

		if continueSteps > 0 {
			orc.AddSteps(continueSteps)
		}
		if autoEvolve {
			orc.SetAutoEvolve(true)
		}

		// Handle Ctrl+C gracefully
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		go func() {
			<-sigCh
			fmt.Println("\n⏸ Pausing after current step...")
			cancel()
		}()

		return orc.Run(ctx)
	},
}

func init() {
	runCmd.Flags().StringVar(&runModel, "model", "", "Override model for this run")
	runCmd.Flags().StringVar(&stepTimeout, "step-timeout", "10m", "Timeout per step")
	runCmd.Flags().IntVar(&runMaxTokens, "max-tokens", 0, "Max output tokens per step")
	runCmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "Verbose output")
	runCmd.Flags().BoolVar(&dryRun, "dry-run", false, "Show prompts without running Claude")
	runCmd.Flags().IntVar(&continueSteps, "add-steps", 0, "Add more steps to max before running")
	runCmd.Flags().BoolVar(&skipPermissions, "dangerously-skip-permissions", false, "Pass --dangerously-skip-permissions to Claude Code")
	runCmd.Flags().BoolVar(&autoEvolve, "auto-evolve", false, "After goal completion, keep improving the project autonomously")
	rootCmd.AddCommand(runCmd)
}
