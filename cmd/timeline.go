package cmd

import (
	"fmt"
	"os"
	"time"

	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/timeline"
	"github.com/spf13/cobra"
)

var timelineFormat string
var timelineOutput string
var timelineFrom string

var timelineCmd = &cobra.Command{
	Use:   "timeline",
	Short: "Render a Gantt chart of the task plan",
	Long: `Render a Gantt chart of the current task plan in ASCII or HTML format.

Task bars are positioned by dependency order: a task starts after all its
dependencies complete. Bar width is derived from ActualMinutes (when done) or
EstimatedMinutes, falling back to 30 minutes per task.

Formats (--format):
  ascii   Fixed-width color-coded chart for the terminal (default)
  html    Self-contained HTML file with SVG Gantt and hover tooltips

Examples:
  cloop timeline                          # ASCII in terminal
  cloop timeline --format html -o g.html  # export HTML file
  cloop timeline --from 2024-01-15        # override plan start date`,
	RunE: func(cmd *cobra.Command, args []string) error {
		workdir, _ := os.Getwd()
		s, err := state.Load(workdir)
		if err != nil {
			return err
		}
		if !s.PMMode || s.Plan == nil {
			return fmt.Errorf("no active plan — run 'cloop run --pm' first")
		}

		// Determine plan start time.
		planStart := time.Now()
		if timelineFrom != "" {
			// Try RFC3339 first, then date-only.
			if t, err2 := time.Parse(time.RFC3339, timelineFrom); err2 == nil {
				planStart = t
			} else if t, err2 := time.Parse("2006-01-02", timelineFrom); err2 == nil {
				planStart = t
			} else {
				return fmt.Errorf("invalid --from value %q: use RFC3339 or YYYY-MM-DD", timelineFrom)
			}
		} else {
			// Use earliest StartedAt from tasks, or creation time from state.
			for _, t := range s.Plan.Tasks {
				if t.StartedAt != nil && !t.StartedAt.IsZero() {
					if t.StartedAt.Before(planStart) {
						planStart = *t.StartedAt
					}
				}
			}
		}

		bars := timeline.Build(s.Plan, planStart)

		var output string
		switch timelineFormat {
		case "html":
			goal := s.Plan.Goal
			if goal == "" {
				goal = "Task Timeline"
			}
			output = timeline.RenderHTML(bars, goal)
		case "ascii", "":
			useColor := timelineOutput == ""
			output = timeline.RenderASCII(bars, useColor)
		default:
			return fmt.Errorf("unknown format %q — use ascii or html", timelineFormat)
		}

		if timelineOutput != "" {
			if err := os.WriteFile(timelineOutput, []byte(output), 0644); err != nil {
				return fmt.Errorf("write %s: %w", timelineOutput, err)
			}
			fmt.Fprintf(os.Stderr, "wrote %s\n", timelineOutput)
			return nil
		}

		fmt.Print(output)
		return nil
	},
}

func init() {
	timelineCmd.Flags().StringVarP(&timelineFormat, "format", "f", "ascii", "Output format: ascii or html")
	timelineCmd.Flags().StringVarP(&timelineOutput, "output", "o", "", "Write output to file instead of stdout")
	timelineCmd.Flags().StringVar(&timelineFrom, "from", "", "Plan start date/time (RFC3339 or YYYY-MM-DD); defaults to earliest task start or now")
	rootCmd.AddCommand(timelineCmd)
}
