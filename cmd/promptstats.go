package cmd

import (
	"fmt"
	"os"
	"sort"

	"github.com/blechschmidt/cloop/pkg/promptstats"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var promptStatsCmd = &cobra.Command{
	Use:   "prompt-stats",
	Short: "Show prompt effectiveness statistics from task history",
	Long: `Reads .cloop/prompt-stats.jsonl and prints a summary of prompt
effectiveness: overall outcome rates, top-performing prompt patterns, and
failure rates broken down by prompt hash.

Each record captures the task title, a prompt fingerprint (hash), the outcome
(done/failed/skipped), and the execution duration. Over time this data reveals
which prompt structures correlate with successful task completion.

Examples:
  cloop prompt-stats
  cloop prompt-stats --top 5`,
	RunE: func(cmd *cobra.Command, args []string) error {
		workDir, _ := os.Getwd()

		top, _ := cmd.Flags().GetInt("top")

		records, err := promptstats.Load(workDir)
		if err != nil {
			return fmt.Errorf("loading prompt stats: %w", err)
		}
		if len(records) == 0 {
			fmt.Println("No prompt stats recorded yet. Run 'cloop run --pm' to generate data.")
			return nil
		}

		summary := promptstats.Summarize(records)

		headerColor := color.New(color.FgCyan, color.Bold)
		successColor := color.New(color.FgGreen)
		failColor := color.New(color.FgRed)
		dimColor := color.New(color.Faint)
		boldColor := color.New(color.Bold)

		// Overall summary
		headerColor.Println("=== Prompt Effectiveness Summary ===")
		fmt.Println()
		boldColor.Printf("Total executions: %d\n", summary.Total)
		successColor.Printf("  Done:    %d (%.0f%%)\n", summary.Done, pct(summary.Done, summary.Total))
		failColor.Printf("  Failed:  %d (%.0f%%)\n", summary.Failed, pct(summary.Failed, summary.Total))
		dimColor.Printf("  Skipped: %d (%.0f%%)\n", summary.Skipped, pct(summary.Skipped, summary.Total))
		fmt.Println()

		// Recent task history (last 15 records)
		headerColor.Println("=== Recent Task Outcomes ===")
		recent := records
		if len(recent) > 15 {
			recent = recent[len(recent)-15:]
		}
		for _, r := range recent {
			icon := "✓"
			c := successColor
			switch r.Outcome {
			case "failed":
				icon = "✗"
				c = failColor
			case "skipped":
				icon = "→"
				c = dimColor
			}
			c.Printf("  %s  %-40s  hash:%-12s  %dms\n",
				icon, truncateStr(r.TaskTitle, 40), r.PromptHash, r.DurationMs)
		}
		fmt.Println()

		// Top-performing prompt hashes
		topHashes := promptstats.TopPerforming(summary, 1)
		if len(topHashes) > top {
			topHashes = topHashes[:top]
		}
		if len(topHashes) > 0 {
			headerColor.Println("=== Top-Performing Prompt Patterns ===")
			for i, hs := range topHashes {
				successRate := hs.SuccessRate() * 100
				failRate := hs.FailureRate() * 100
				fmt.Printf("  %d. hash:%s  %d runs  success:%.0f%%  fail:%.0f%%  avg:%dms\n",
					i+1, hs.Hash, hs.Total, successRate, failRate, hs.AvgDurMs())
			}
			fmt.Println()
		}

		// Failure-prone prompt hashes (those with ≥1 failure and ≥2 total runs)
		var failProne []*promptstats.HashStats
		for _, hs := range summary.ByHash {
			if hs.Failed > 0 && hs.Total >= 2 {
				failProne = append(failProne, hs)
			}
		}
		sort.Slice(failProne, func(i, j int) bool {
			return failProne[i].FailureRate() > failProne[j].FailureRate()
		})
		if len(failProne) > 0 {
			headerColor.Println("=== High Failure-Rate Prompt Patterns ===")
			limit := 5
			if len(failProne) < limit {
				limit = len(failProne)
			}
			for i, hs := range failProne[:limit] {
				failColor.Printf("  %d. hash:%s  %d runs  fail:%.0f%%  (%d failed, %d done)\n",
					i+1, hs.Hash, hs.Total, hs.FailureRate()*100, hs.Failed, hs.Done)
			}
			fmt.Println()
		}

		dimColor.Printf("Stats file: .cloop/prompt-stats.jsonl (%d records)\n", len(records))
		return nil
	},
}

func pct(n, total int) float64 {
	if total == 0 {
		return 0
	}
	return float64(n) / float64(total) * 100
}

func init() {
	promptStatsCmd.Flags().Int("top", 10, "Number of top-performing patterns to display")
	rootCmd.AddCommand(promptStatsCmd)
}
