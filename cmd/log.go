package cmd

import (
	"encoding/json"
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
	logJSON  bool
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
			if logJSON {
				fmt.Println("[]")
			} else {
				fmt.Println("No steps recorded yet.")
			}
			return nil
		}

		steps := s.Steps
		if logStep > 0 {
			// Show specific step
			found := false
			for _, step := range s.Steps {
				if step.Step+1 == logStep {
					steps = []state.StepResult{step}
					found = true
					break
				}
			}
			if !found {
				return fmt.Errorf("step %d not found (total steps: %d)", logStep, len(s.Steps))
			}
		}

		if logJSON {
			data, err := json.MarshalIndent(steps, "", "  ")
			if err != nil {
				return fmt.Errorf("marshaling log: %w", err)
			}
			fmt.Println(string(data))
			return nil
		}

		stepColor := color.New(color.FgYellow, color.Bold)
		dimColor := color.New(color.Faint)

		for _, step := range steps {
			stepColor.Printf("━━━ Step %d ━━━", step.Step+1)
			dimColor.Printf(" [%s, exit %d, %s", step.Time.Format("15:04:05"), step.ExitCode, step.Duration)
			if step.InputTokens > 0 || step.OutputTokens > 0 {
				dimColor.Printf(", %d/%d tokens", step.InputTokens, step.OutputTokens)
			}
			dimColor.Printf("]\n")

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
	logCmd.Flags().BoolVar(&logJSON, "json", false, "Output steps as JSON array")
	rootCmd.AddCommand(logCmd)
}
