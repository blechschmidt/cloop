package cmd

import (
	"fmt"
	"os"

	"github.com/blechschmidt/cloop/pkg/metrics"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var metricsCmd = &cobra.Command{
	Use:   "metrics",
	Short: "Show the latest run metrics summary from .cloop/metrics.json",
	Long: `Print the metrics recorded during the last cloop run that had --metrics-addr set.

Metrics are written to .cloop/metrics.json at plan completion and can be
inspected here or scraped in Prometheus format via the --metrics-addr server.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		workdir, _ := os.Getwd()

		s, err := metrics.LoadJSON(workdir)
		if err != nil {
			return fmt.Errorf("no metrics found (run 'cloop run --metrics-addr :9090' to collect): %w", err)
		}

		bold := color.New(color.Bold)
		dim := color.New(color.Faint)
		green := color.New(color.FgGreen)
		red := color.New(color.FgRed)
		yellow := color.New(color.FgYellow)

		bold.Printf("\ncloop metrics — %s\n\n", s.Timestamp.Format("2006-01-02 15:04:05 UTC"))

		fmt.Printf("  Provider:    %s\n", s.Provider)
		fmt.Printf("  Model:       %s\n", s.Model)
		fmt.Printf("  Run time:    %.1fs\n\n", s.DurationSecs)

		bold.Printf("Tasks\n")
		fmt.Printf("  Total:     %d\n", s.TasksTotal)
		green.Printf("  Completed: %d\n", s.TasksCompleted)
		red.Printf("  Failed:    %d\n", s.TasksFailed)
		yellow.Printf("  Skipped:   %d\n\n", s.TasksSkipped)

		bold.Printf("Steps\n")
		fmt.Printf("  Total:     %d\n\n", s.StepsTotal)

		if s.TaskDuration.Count > 0 {
			bold.Printf("Task duration (seconds)\n")
			fmt.Printf("  Count: %d\n", s.TaskDuration.Count)
			fmt.Printf("  Sum:   %.2fs\n", s.TaskDuration.Sum)
			if s.TaskDuration.Count > 0 {
				fmt.Printf("  Avg:   %.2fs\n\n", s.TaskDuration.Sum/float64(s.TaskDuration.Count))
			}
		}

		if len(s.TokensUsed) > 0 {
			bold.Printf("Tokens used\n")
			totalIn, totalOut := int64(0), int64(0)
			for key, val := range s.TokensUsed {
				dim.Printf("  %s: %d\n", key, val)
				if len(key) > 5 && key[len(key)-5:] == "input" {
					totalIn += val
				} else {
					totalOut += val
				}
			}
			fmt.Printf("  Total input:  %d\n", totalIn)
			fmt.Printf("  Total output: %d\n\n", totalOut)
		}

		if len(s.CostUSD) > 0 {
			bold.Printf("Estimated cost (USD)\n")
			total := 0.0
			for key, val := range s.CostUSD {
				dim.Printf("  %s: $%.6f\n", key, val)
				total += val
			}
			fmt.Printf("  Total: $%.6f\n\n", total)
		}

		return nil
	},
}

func init() {
	rootCmd.AddCommand(metricsCmd)
}
