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
	logLast  int
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

		steps, err := filterSteps(s.Steps, logStep, logLast)
		if err != nil {
			return err
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

// filterSteps applies --step and --last filters to a step slice.
// stepNum is 1-indexed (0 means no filter). lastN is a suffix limit (0 means all).
func filterSteps(steps []state.StepResult, stepNum, lastN int) ([]state.StepResult, error) {
	if stepNum > 0 {
		for _, step := range steps {
			if step.Step+1 == stepNum {
				return []state.StepResult{step}, nil
			}
		}
		return nil, fmt.Errorf("step %d not found (total steps: %d)", stepNum, len(steps))
	}
	if lastN > 0 && len(steps) > lastN {
		return steps[len(steps)-lastN:], nil
	}
	return steps, nil
}

func init() {
	logCmd.Flags().IntVar(&logStep, "step", 0, "Show specific step (1-indexed)")
	logCmd.Flags().IntVar(&logLines, "lines", 50, "Max output lines per step (0=all)")
	logCmd.Flags().IntVar(&logLast, "last", 0, "Show only the last N steps (0=all)")
	logCmd.Flags().BoolVar(&logJSON, "json", false, "Output steps as JSON array")
	rootCmd.AddCommand(logCmd)
}
