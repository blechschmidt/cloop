package cmd

import (
	"fmt"
	"os"

	"github.com/blechschmidt/cloop/pkg/compact"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var compactCmd = &cobra.Command{
	Use:   "compact",
	Short: "Prune old artifacts, snapshots, and checkpoints to free disk space",
	Long: `Compact reclaims disk space consumed by long-running projects.

Operations performed:
  1. Delete plan snapshots older than the N most recent (default: keep 10)
  2. Delete task checkpoints for tasks no longer in the plan
  3. Delete task artifacts older than D days for completed tasks (default: 30)
  4. Truncate step log (replay.jsonl) to last 1000 entries

Use --dry-run to preview what would be deleted without making any changes.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		workdir, _ := os.Getwd()

		dryRun, _ := cmd.Flags().GetBool("dry-run")
		keepSnapshots, _ := cmd.Flags().GetInt("keep-snapshots")
		keepArtifactsDays, _ := cmd.Flags().GetInt("keep-artifacts-days")
		truncateLog, _ := cmd.Flags().GetInt("truncate-log")

		opts := compact.Options{
			DryRun:            dryRun,
			KeepSnapshots:     keepSnapshots,
			KeepArtifactsDays: keepArtifactsDays,
			TruncateStepLog:   truncateLog,
		}

		if dryRun {
			color.New(color.FgYellow, color.Bold).Println("DRY RUN — no files will be deleted")
			fmt.Println()
		}

		sum, err := compact.Run(workdir, opts)
		if err != nil {
			return fmt.Errorf("compact: %w", err)
		}

		headerColor := color.New(color.FgCyan, color.Bold)
		dimColor := color.New(color.Faint)
		boldColor := color.New(color.Bold)

		headerColor.Println("Compaction summary")
		fmt.Println()

		printRow := func(label string, count int, bytes int64) {
			if count == 0 && bytes == 0 {
				dimColor.Printf("  %-34s  %4d items   %s\n", label, count, formatBytes(bytes))
			} else {
				fmt.Printf("  %-34s  %4d items   %s\n", label, count, formatBytes(bytes))
			}
		}

		printRow("Plan snapshots pruned", sum.SnapshotsDeleted, sum.SnapshotsBytesFreed)
		printRow("Task checkpoints removed", sum.CheckpointsDeleted, sum.CheckpointsBytesFreed)
		printRow("Task artifacts deleted", sum.ArtifactsDeleted, sum.ArtifactsBytesFreed)

		stepLogLine := "Step log unchanged"
		if sum.StepLogTruncated {
			stepLogLine = "Step log truncated"
		}
		printRow(stepLogLine, 0, sum.StepLogBytesFreed)

		fmt.Println()
		total := sum.TotalBytesFreed()
		if dryRun {
			boldColor.Printf("  Would free: %s\n", formatBytes(total))
		} else {
			boldColor.Printf("  Total freed: %s\n", formatBytes(total))
		}

		return nil
	},
}


func init() {
	defaults := compact.DefaultOptions()
	compactCmd.Flags().Bool("dry-run", false, "Show what would be deleted without deleting anything")
	compactCmd.Flags().Int("keep-snapshots", defaults.KeepSnapshots, "Number of most-recent plan snapshots to keep")
	compactCmd.Flags().Int("keep-artifacts-days", defaults.KeepArtifactsDays, "Delete completed-task artifacts older than this many days")
	compactCmd.Flags().Int("truncate-log", defaults.TruncateStepLog, "Truncate step log to last N entries (0 = skip)")
	rootCmd.AddCommand(compactCmd)
}
