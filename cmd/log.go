package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var (
	logStep  int
	logLines int
)

var logCmd = &cobra.Command{
	Use:   "log",
	Short: "Show step history",
	RunE: func(cmd *cobra.Command, args []string) error {
		workdir, _ := os.Getwd()
		s, err := state.Load(workdir)
		if err != nil {
			return err
		}

		if len(s.Steps) == 0 {
			fmt.Println("No steps recorded yet.")
			return nil
		}

		stepColor := color.New(color.FgYellow, color.Bold)
		dimColor := color.New(color.Faint)

		steps := s.Steps
		if logStep > 0 {
			// Show specific step
			for _, step := range s.Steps {
				if step.Step+1 == logStep {
					steps = []state.StepResult{step}
					break
				}
			}
		}

		for _, step := range steps {
			stepColor.Printf("━━━ Step %d ━━━", step.Step+1)
			dimColor.Printf(" [%s, exit %d, %s]\n", step.Time.Format("15:04:05"), step.ExitCode, step.Duration)

			output := step.Output
			lines := strings.Split(output, "\n")
			if logLines > 0 && len(lines) > logLines {
				for _, line := range lines[:logLines/2] {
					fmt.Printf("  %s\n", line)
				}
				dimColor.Printf("  ... (%d lines omitted) ...\n", len(lines)-logLines)
				for _, line := range lines[len(lines)-logLines/2:] {
					fmt.Printf("  %s\n", line)
				}
			} else {
				for _, line := range lines {
					fmt.Printf("  %s\n", line)
				}
			}
			fmt.Println()
		}

		return nil
	},
}

func init() {
	logCmd.Flags().IntVar(&logStep, "step", 0, "Show specific step (1-indexed)")
	logCmd.Flags().IntVar(&logLines, "lines", 50, "Max output lines per step (0=all)")
	rootCmd.AddCommand(logCmd)
}
