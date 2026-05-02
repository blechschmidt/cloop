package cmd

import (
	"fmt"
	"os"

	"github.com/blechschmidt/cloop/pkg/perfprofile"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var perfProfileCmd = &cobra.Command{
	Use:   "profile",
	Short: "Analyze task execution bottlenecks across a plan run",
	Long: `Analyzes timing data from .cloop/task-checkpoints/ and the cost ledger
(.cloop/costs.jsonl) to identify execution bottlenecks.

Outputs:
  • Ranked bottleneck table  — slowest tasks with queue delay, provider, cost
  • Provider latency table   — mean / p95 / max step latency per provider
  • Plan efficiency summary  — wall span, parallel efficiency ratio, queue waste
  • ASCII histogram          — task duration distribution

Examples:
  cloop perf profile
  cloop perf profile --top 10`,
	RunE: func(cmd *cobra.Command, args []string) error {
		workDir, _ := os.Getwd()

		top, _ := cmd.Flags().GetInt("top")

		s, err := state.Load(workDir)
		if err != nil {
			return fmt.Errorf("loading state: %w", err)
		}

		headerColor := color.New(color.FgCyan, color.Bold)
		dimColor := color.New(color.Faint)

		if !s.PMMode || s.Plan == nil || len(s.Plan.Tasks) == 0 {
			dimColor.Println("No task plan found. Run 'cloop run --pm' to create one.")
			return nil
		}

		headerColor.Println("=== cloop perf profile: Execution Bottleneck Analysis ===")
		fmt.Println()

		prof := perfprofile.Build(workDir, s)

		if len(prof.Tasks) == 0 {
			dimColor.Println("No task timing data found.")
			return nil
		}

		// Bottleneck table + provider summary + plan summary.
		headerColor.Println("--- Ranked Bottlenecks ---")
		perfprofile.RenderBottleneckTable(prof, top, os.Stdout)

		// ASCII histogram.
		fmt.Println()
		headerColor.Println("--- Task Duration Histogram ---")
		perfprofile.RenderHistogram(prof, os.Stdout)

		return nil
	},
}

func init() {
	perfProfileCmd.Flags().Int("top", 0, "Limit bottleneck table to top N tasks (0 = all)")
	perfCmd.AddCommand(perfProfileCmd)
}
