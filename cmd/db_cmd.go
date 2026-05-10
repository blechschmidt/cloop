package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/blechschmidt/cloop/pkg/dbmaintain"
	"github.com/blechschmidt/cloop/pkg/dbverify"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var dbCmd = &cobra.Command{
	Use:   "db",
	Short: "Inspect and maintain the .cloop SQLite state database",
	Long: `Subcommands for inspecting and maintaining the project's SQLite state
database (.cloop/state.db). Use these to detect on-disk corruption after
crashes or disk errors before it cascades into confusing runtime failures.`,
}

var dbVerifyCmd = &cobra.Command{
	Use:   "verify",
	Short: "Run SQLite integrity and foreign-key checks against .cloop/state.db",
	Long: `Run PRAGMA integrity_check and PRAGMA foreign_key_check against
.cloop/state.db. Reports any corruption found and exits non-zero if
issues are detected.

By default the thorough integrity_check is used. Pass --quick to use
PRAGMA quick_check instead, which is several times faster but skips the
exhaustive UNIQUE/PK index verification.

Exit codes:
  0  database passed all checks
  1  one or more issues were detected
  2  the verification itself could not run (file missing, permission denied, etc.)`,
	RunE: func(cmd *cobra.Command, args []string) error {
		quick, _ := cmd.Flags().GetBool("quick")

		workdir, _ := os.Getwd()
		dbPath := filepath.Join(workdir, ".cloop", "state.db")

		header := color.New(color.FgCyan, color.Bold)
		pass := color.New(color.FgGreen, color.Bold)
		fail := color.New(color.FgRed, color.Bold)
		dim := color.New(color.Faint)

		mode := "integrity_check"
		if quick {
			mode = "quick_check"
		}

		header.Printf("cloop db verify — %s\n", mode)
		dim.Printf("  database: %s\n\n", dbPath)

		rep, err := dbverify.Verify(dbPath, quick)
		if err != nil {
			fail.Printf("Verification could not run: %v\n", err)
			// Distinguish "could not run" from "found issues" with a separate exit code.
			os.Exit(2)
		}

		if rep.OK() {
			pass.Println("PASS — no integrity or foreign-key issues found.")
			return nil
		}

		if len(rep.IntegrityIssues) > 0 {
			fail.Printf("FAIL — %s reported %d issue(s):\n", mode, len(rep.IntegrityIssues))
			for _, msg := range rep.IntegrityIssues {
				fmt.Printf("  • %s\n", msg)
			}
			fmt.Println()
		}

		if len(rep.ForeignKeyViolations) > 0 {
			fail.Printf("FAIL — foreign_key_check reported %d violation(s):\n", len(rep.ForeignKeyViolations))
			for _, v := range rep.ForeignKeyViolations {
				rowid := "<null>"
				if v.RowID.Valid {
					rowid = fmt.Sprintf("%d", v.RowID.Int64)
				}
				fmt.Printf("  • table=%s rowid=%s parent=%s fkid=%d\n",
					v.Table, rowid, v.Parent, v.FKID)
			}
			fmt.Println()
		}

		dim.Println("Hint: corruption is rarely repairable in place. Restore from a recent")
		dim.Println("      'cloop snapshot' or 'cloop migrate' the project after backing it up.")

		os.Exit(1)
		return nil
	},
}

var dbMaintainCmd = &cobra.Command{
	Use:   "maintain",
	Short: "Run VACUUM + ANALYZE to reclaim space and refresh query planner stats",
	Long: `Run VACUUM and ANALYZE on .cloop/state.db.

VACUUM rewrites the database file with no free space, returning reclaimed
pages from deleted rows back to the filesystem. ANALYZE refreshes the SQLite
query planner's per-index statistics.

Each successful run is recorded in the maintenance_log table along with the
page count before and after. Use --auto in cron-style invocations to skip
maintenance unless the database has grown more than 20% since the previous
vacuum.

Flags:
  --dry-run   Report the database size and an estimate of reclaimable bytes
              (freelist_count × page_size) without actually running VACUUM.
              Nothing is written to the database.
  --auto      Run only if page_count has grown >20% since the last recorded
              vacuum. First run on a fresh project always proceeds.

Exit codes:
  0  maintenance ran (or was skipped by --auto)
  1  maintenance failed
  2  the maintain command itself could not run (file missing, permission denied)`,
	RunE: func(cmd *cobra.Command, args []string) error {
		dryRun, _ := cmd.Flags().GetBool("dry-run")
		auto, _ := cmd.Flags().GetBool("auto")

		workdir, _ := os.Getwd()
		dbPath := filepath.Join(workdir, ".cloop", "state.db")

		header := color.New(color.FgCyan, color.Bold)
		pass := color.New(color.FgGreen, color.Bold)
		warn := color.New(color.FgYellow, color.Bold)
		fail := color.New(color.FgRed, color.Bold)
		dim := color.New(color.Faint)

		mode := "VACUUM + ANALYZE"
		if dryRun {
			mode = "dry-run (size report only)"
		}
		header.Printf("cloop db maintain — %s\n", mode)
		dim.Printf("  database: %s\n\n", dbPath)

		rep, err := dbmaintain.Run(dbPath, dbmaintain.Options{
			DryRun: dryRun,
			Auto:   auto,
		})
		if err != nil {
			fail.Printf("Maintenance failed: %v\n", err)
			// Distinguish "could not run at all" (missing file) from "started
			// but failed midway through" so cron jobs can react appropriately.
			if rep == nil {
				os.Exit(2)
			}
			os.Exit(1)
		}

		fmt.Printf("  size before:    %s (%d pages, %d bytes/page, %d freelist)\n",
			humanBytes(rep.Before.Bytes), rep.Before.PageCount, rep.Before.PageSize, rep.Before.FreelistPages)

		if rep.LastEntry != nil {
			elapsed := time.Since(rep.LastEntry.CompletedAt).Round(time.Second)
			dim.Printf("  last maintenance: %s ago (%s, freed %s)\n",
				elapsed,
				rep.LastEntry.Operation,
				humanBytes(rep.LastEntry.BytesFreed()),
			)
		} else {
			dim.Println("  last maintenance: never")
		}
		fmt.Println()

		if rep.AutoSkipped {
			warn.Println("SKIPPED — auto-mode threshold not met.")
			dim.Printf("  %s\n", rep.Reason)
			return nil
		}

		if rep.DryRun {
			dim.Println("Dry run — no changes written.")
			fmt.Printf("  estimated reclaim: %s (freelist_count × page_size)\n", humanBytes(rep.EstimatedReclaim))
			return nil
		}

		fmt.Printf("  size after:     %s (%d pages)\n", humanBytes(rep.After.Bytes), rep.After.PageCount)
		fmt.Printf("  operations:     %v\n", rep.Operations)
		fmt.Println()

		if rep.BytesFreed > 0 {
			pass.Printf("Reclaimed %s.\n", humanBytes(rep.BytesFreed))
		} else {
			pass.Println("Maintenance complete (no space to reclaim).")
		}
		if rep.Reason != "" {
			dim.Printf("  %s\n", rep.Reason)
		}
		return nil
	},
}

// humanBytes formats a byte count using SI-style units. Sub-KB values are
// shown as bare numbers ("512 B"); larger values get a single-decimal value
// with the appropriate unit.
func humanBytes(n int64) string {
	const (
		KB = 1 << 10
		MB = 1 << 20
		GB = 1 << 30
	)
	switch {
	case n < 0:
		return fmt.Sprintf("%d B", n)
	case n < KB:
		return fmt.Sprintf("%d B", n)
	case n < MB:
		return fmt.Sprintf("%.1f KB", float64(n)/KB)
	case n < GB:
		return fmt.Sprintf("%.1f MB", float64(n)/MB)
	default:
		return fmt.Sprintf("%.2f GB", float64(n)/GB)
	}
}

func init() {
	dbVerifyCmd.Flags().Bool("quick", false, "Use PRAGMA quick_check instead of integrity_check (faster, less thorough)")
	dbMaintainCmd.Flags().Bool("dry-run", false, "Report DB size and reclaimable estimate without running VACUUM/ANALYZE")
	dbMaintainCmd.Flags().Bool("auto", false, "Run only if DB has grown >20% since the last recorded vacuum")
	dbCmd.AddCommand(dbVerifyCmd)
	dbCmd.AddCommand(dbMaintainCmd)
	rootCmd.AddCommand(dbCmd)
}
