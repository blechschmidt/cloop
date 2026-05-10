package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/blechschmidt/cloop/pkg/dbbackup"
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

var dbBackupCmd = &cobra.Command{
	Use:   "backup",
	Short: "Create a hot backup of .cloop/state.db (safe while cloop is running)",
	Long: `Create a self-contained, transactionally-consistent copy of
.cloop/state.db without stopping the running cloop daemon.

How it works:
  1. PRAGMA wal_checkpoint(TRUNCATE) flushes pending WAL frames into the
     main database file so the snapshot is as current as possible.
  2. VACUUM INTO '<output>' produces a single defragmented .db file at the
     supplied path. SQLite guarantees the copy is consistent at the read
     transaction's snapshot point — concurrent writes do not corrupt it.
  3. A sidecar '<output>.meta.json' is written with SHA-256 checksum,
     source path, size, schema version, and duration.

The default output path is
.cloop/backups/state-<UTC-timestamp>.db. Use --output to override it.

Exit codes:
  0  backup completed
  1  backup failed
  2  the backup command itself could not run (file missing, permission)`,
	RunE: func(cmd *cobra.Command, args []string) error {
		out, _ := cmd.Flags().GetString("output")

		workdir, _ := os.Getwd()
		dbPath := filepath.Join(workdir, ".cloop", "state.db")

		header := color.New(color.FgCyan, color.Bold)
		pass := color.New(color.FgGreen, color.Bold)
		fail := color.New(color.FgRed, color.Bold)
		dim := color.New(color.Faint)

		if out == "" {
			ts := time.Now().UTC().Format("20060102T150405Z")
			out = filepath.Join(workdir, ".cloop", "backups", fmt.Sprintf("state-%s.db", ts))
		}

		header.Println("cloop db backup")
		dim.Printf("  source: %s\n", dbPath)
		dim.Printf("  output: %s\n\n", out)

		if _, err := os.Stat(dbPath); err != nil {
			fail.Printf("Backup could not run: %v\n", err)
			os.Exit(2)
		}

		report, err := dbbackup.Backup(dbPath, out)
		if err != nil {
			fail.Printf("Backup failed: %v\n", err)
			os.Exit(1)
		}

		fmt.Printf("  WAL checkpoint:  %s\n", report.WALCheckpoint)
		fmt.Printf("  size:            %s\n", humanBytes(report.SizeBytes))
		fmt.Printf("  duration:        %s\n", report.Duration.Round(time.Millisecond))
		fmt.Printf("  sha256:          %s\n", report.SHA256)
		fmt.Printf("  schema version:  %d\n", report.SchemaVersion)
		fmt.Printf("  metadata:        %s\n\n", report.MetadataPath)
		pass.Println("Backup complete.")
		return nil
	},
}

var dbRestoreCmd = &cobra.Command{
	Use:   "restore <backup-path>",
	Short: "Restore .cloop/state.db from a backup created by 'cloop db backup'",
	Long: `Validate a backup and atomically swap it into .cloop/state.db.

Validation steps:
  1. PRAGMA integrity_check on the backup file (read-only handle).
  2. SHA-256 verification against the sidecar metadata, if present.

Refuses to overwrite an active database (when state.db, state.db-wal,
or state.db-shm exist alongside it) without --force. With --force, the
existing destination is moved to a sibling .pre-restore.<timestamp>
file before the swap so a botched restore is recoverable.

Exit codes:
  0  restore completed
  1  restore failed (backup invalid, refused without --force, etc.)
  2  the restore command itself could not run (file missing, etc.)`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		backupPath := args[0]
		force, _ := cmd.Flags().GetBool("force")
		skipChecksum, _ := cmd.Flags().GetBool("skip-checksum")

		workdir, _ := os.Getwd()
		dstPath := filepath.Join(workdir, ".cloop", "state.db")

		header := color.New(color.FgCyan, color.Bold)
		pass := color.New(color.FgGreen, color.Bold)
		warn := color.New(color.FgYellow, color.Bold)
		fail := color.New(color.FgRed, color.Bold)
		dim := color.New(color.Faint)

		header.Println("cloop db restore")
		dim.Printf("  backup:      %s\n", backupPath)
		dim.Printf("  destination: %s\n\n", dstPath)

		if _, err := os.Stat(backupPath); err != nil {
			fail.Printf("Restore could not run: %v\n", err)
			os.Exit(2)
		}

		// Surface metadata up front so the operator sees what they are
		// restoring before any disk mutation happens.
		if meta, err := dbbackup.LoadMetadata(backupPath); err == nil && meta != nil {
			dim.Printf("  metadata: created %s, size %s, schema v%d, sha256=%s…\n\n",
				meta.CreatedAt.Format(time.RFC3339),
				humanBytes(meta.SizeBytes),
				meta.SchemaVersion,
				safePrefix(meta.SHA256, 12),
			)
		} else {
			dim.Println("  metadata: (no sidecar found)")
			fmt.Println()
		}

		report, err := dbbackup.Restore(backupPath, dstPath, dbbackup.RestoreOptions{
			Force:        force,
			SkipChecksum: skipChecksum,
		})
		if err != nil {
			fail.Printf("Restore failed: %v\n", err)
			os.Exit(1)
		}

		fmt.Printf("  size:        %s\n", humanBytes(report.SizeBytes))
		fmt.Printf("  duration:    %s\n", report.Duration.Round(time.Millisecond))
		if report.BackedUpPath != "" {
			warn.Printf("  rolled-back snapshot saved to %s\n", report.BackedUpPath)
			dim.Println("  (delete it once you have verified the restored DB.)")
		}
		fmt.Println()
		pass.Println("Restore complete.")
		return nil
	},
}

// safePrefix returns s[:n] if len(s) >= n, otherwise s. Used for trimming
// hash digests in human-readable output without panicking on short inputs.
func safePrefix(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

func init() {
	dbVerifyCmd.Flags().Bool("quick", false, "Use PRAGMA quick_check instead of integrity_check (faster, less thorough)")
	dbMaintainCmd.Flags().Bool("dry-run", false, "Report DB size and reclaimable estimate without running VACUUM/ANALYZE")
	dbMaintainCmd.Flags().Bool("auto", false, "Run only if DB has grown >20% since the last recorded vacuum")
	dbBackupCmd.Flags().String("output", "", "Output path for the backup file (default: .cloop/backups/state-<UTC>.db)")
	dbRestoreCmd.Flags().Bool("force", false, "Overwrite an active destination database; the previous file is preserved as .pre-restore.<timestamp>")
	dbRestoreCmd.Flags().Bool("skip-checksum", false, "Skip SHA-256 verification against the sidecar metadata")
	dbCmd.AddCommand(dbVerifyCmd)
	dbCmd.AddCommand(dbMaintainCmd)
	dbCmd.AddCommand(dbBackupCmd)
	dbCmd.AddCommand(dbRestoreCmd)
	rootCmd.AddCommand(dbCmd)
}
