package cmd

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/auditretention"
	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/dbbackup"
	"github.com/blechschmidt/cloop/pkg/dbmaintain"
	"github.com/blechschmidt/cloop/pkg/dbverify"
	"github.com/blechschmidt/cloop/pkg/rootkey"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
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
			exitProcess(2)
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

		exitProcess(1)
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
  --prune-audit
              Also apply the audit-trail retention window from
              audit.retention_days before vacuuming, so the rows it seals and
              removes actually give their pages back. Implied by
              audit.prune_on_maintain. See 'cloop hub audit prune'.

VACUUM writes every page of the database through the write-ahead log
(.cloop/state.db-wal), and SQLite never shrinks that file on its own, so a run
ends with a TRUNCATE checkpoint and reports the log's size before and after.
The checkpoint waits at most a quarter of a second for another connection: one
that is still reading from the log leaves it as it was, and the run says so.

VACUUM rewrites the whole database file, which is unsafe underneath a running
hub — and this control plane can have two, since several hubs may be started
from one directory. The command refuses while another instance holds the
control-plane lease (Task 20214); stop it, or wait for the lease to lapse.

Exit codes:
  0  maintenance ran (or was skipped by --auto)
  1  maintenance failed
  2  the maintain command itself could not run (file missing, permission denied)`,
	RunE: func(cmd *cobra.Command, args []string) error {
		dryRun, _ := cmd.Flags().GetBool("dry-run")
		auto, _ := cmd.Flags().GetBool("auto")
		pruneAudit, _ := cmd.Flags().GetBool("prune-audit")
		auditHub, _ := cmd.Flags().GetString("audit-hub")
		forceAudit, _ := cmd.Flags().GetBool("force-audit-prune")

		workdir, _ := os.Getwd()
		dbPath := filepath.Join(workdir, ".cloop", "state.db")

		// Retention is opt-in twice over: a window must be configured, and
		// either the flag or audit.prune_on_maintain must ask for it here.
		// Deleting from the compliance record is not something a routine
		// "reclaim disk space" command should start doing on its own.
		cfg, _ := config.Load(workdir)
		var retention *dbmaintain.RetentionOptions
		if cfg != nil && cfg.Audit.RetentionDays > 0 && (pruneAudit || cfg.Audit.PruneOnMaintain) {
			exportDir := cfg.Audit.ExportDir
			if exportDir == "" {
				exportDir = filepath.Join(workdir, ".cloop", auditretention.DefaultExportDirName)
			}
			retention = &dbmaintain.RetentionOptions{
				Days:      cfg.Audit.RetentionDays,
				ExportDir: exportDir,
				Actor:     "cli",
				Force:     forceAudit,
			}
			if auditHub != "" {
				retention.ControlPlane = state.DBPath(auditHub)
			}
		} else if pruneAudit {
			return fmt.Errorf("--prune-audit needs a retention window: set audit.retention_days in .cloop/config.yaml")
		}

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
			DryRun:    dryRun,
			Auto:      auto,
			Retention: retention,
		})
		if err != nil {
			// A live peer is an ordinary, actionable outcome, not a crash:
			// say what to do about it rather than printing it as a failure
			// and exiting 1 into a cron log.
			if errors.Is(err, dbmaintain.ErrPeerHubLive) {
				warn.Printf("Skipped — %v\n", err)
				return nil
			}
			fail.Printf("Maintenance failed: %v\n", err)
			// Distinguish "could not run at all" (missing file) from "started
			// but failed midway through" so cron jobs can react appropriately.
			if rep == nil {
				exitProcess(2)
			}
			exitProcess(1)
		}

		fmt.Printf("  size before:    %s (%d pages, %d bytes/page, %d freelist)\n",
			humanBytes(rep.Before.Bytes), rep.Before.PageCount, rep.Before.PageSize, rep.Before.FreelistPages)
		fmt.Printf("  wal before:     %s\n", humanBytes(rep.WALBefore))

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

		if r := rep.Retention; r != nil {
			if r.Clamped {
				warn.Printf("  audit retention: kept %d row(s) older than the cutoff that audit sink %q has not "+
					"acknowledged (it has id %d); --force-audit-prune removes them anyway\n",
					r.Requested.Count-r.Candidate.Count, r.HeldBy, r.HeldThroughID)
			}
			if len(r.ForcedPast) > 0 && !r.DryRun {
				warn.Printf("  audit retention: forced past what audit sink(s) %s acknowledged; those rows are "+
					"only in the archive now\n", strings.Join(r.ForcedPast, ", "))
			}
			switch {
			case r.Candidate.Count == 0:
				dim.Printf("  audit retention: nothing older than %s\n", r.Cutoff.Format(time.RFC3339))
			case r.DryRun:
				dim.Printf("  audit retention: would seal %d rows (id %d…%d)\n",
					r.Candidate.Count, r.Candidate.FirstID, r.Candidate.ThroughID)
			default:
				dim.Printf("  audit retention: sealed %d rows to %s\n", r.Anchor.PrunedCount, r.ExportPath)
			}
		}

		if rep.DryRun {
			dim.Println("Dry run — no changes written.")
			fmt.Printf("  estimated reclaim: %s (freelist_count × page_size)\n", humanBytes(rep.EstimatedReclaim))
			if rep.WALBefore > 0 {
				fmt.Printf("  write-ahead log:   %s (a real run truncates it)\n", humanBytes(rep.WALBefore))
			}
			return nil
		}

		fmt.Printf("  size after:     %s (%d pages)\n", humanBytes(rep.After.Bytes), rep.After.PageCount)
		fmt.Printf("  wal after:      %s%s\n", humanBytes(rep.WALAfter), walCheckpointNote(rep.WALCheckpoint))
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

// walCheckpointNote says how the run's closing checkpoint went, for the "wal
// after" line: a busy one left the log as it was, and the operator should
// know why it did not shrink.
func walCheckpointNote(cp *statedb.WALCheckpoint) string {
	switch {
	case cp == nil:
		return ""
	case cp.Busy:
		return fmt.Sprintf(" (not truncated: another connection was still using the log after %s; "+
			"a hub's janitor retries every minute while it is over %s)",
			statedb.WALCheckpointBusyTimeout, humanBytes(statedb.JournalSizeLimitBytes))
	case cp.Truncated():
		return " (truncated)"
	}
	return ""
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
     source path, size, schema version, and duration — and the manifest a
     restore checks first: the sealing keys the backup's secrets depend on
     and where its audit chain ends. The whole sidecar is sealed under a key
     derived from CLOOP_SECRET_KEY, so a backup edited and its digest
     recomputed is refused at restore.

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
			exitProcess(2)
		}

		report, err := dbbackup.Backup(dbPath, out)
		if err != nil {
			fail.Printf("Backup failed: %v\n", err)
			exitProcess(1)
		}

		fmt.Printf("  WAL checkpoint:  %s\n", report.WALCheckpoint)
		fmt.Printf("  size:            %s\n", humanBytes(report.SizeBytes))
		fmt.Printf("  duration:        %s\n", report.Duration.Round(time.Millisecond))
		fmt.Printf("  sha256:          %s\n", report.SHA256)
		fmt.Printf("  schema version:  %d\n", report.SchemaVersion)
		if c := report.Chain; c != nil && c.LastID > 0 {
			fmt.Printf("  audit head:      id %d (%s)\n", c.LastID, shortHex(c.LastRowHash))
		}
		var sealedRows int
		for _, k := range report.Keys {
			sealedRows += k.Total()
		}
		fmt.Printf("  sealing keys:    %d, sealing %d row(s)\n", len(report.Keys), sealedRows)
		fmt.Printf("  metadata:        %s\n", report.MetadataPath)
		if report.Sealed() {
			fmt.Printf("  sidecar seal:    under CLOOP_SECRET_KEY %s\n\n", report.KeyFingerprint)
		} else {
			color.New(color.FgYellow, color.Bold).Println("  sidecar seal:    NONE — there is no CLOOP_SECRET_KEY, so nothing will prove this backup")
			color.New(color.FgYellow, color.Bold).Println("                   was not edited; restoring it needs --allow-unsealed")
			fmt.Println()
		}
		pass.Println("Backup complete.")
		return nil
	},
}

var dbRestoreCmd = &cobra.Command{
	Use:   "restore <backup-path>",
	Short: "Restore .cloop/state.db from a backup, after checking it opens under this hub's key",
	Long: `Check a backup, swap it into .cloop/state.db, and record the restore.

Before anything is touched, a read-only preflight asks every question a
restore depends on, and refuses — changing nothing — on any "no":

  1. PRAGMA integrity_check, and a schema this binary can open.
  2. The sidecar: its SHA-256 matches the file, and its seal — an HMAC under a
     key derived from CLOOP_SECRET_KEY — verifies, so a backup edited and its
     digest recomputed is refused.
  3. The sealing keys: the CLOOP_SECRET_KEY this hub will run with derives
     every key the backup's secrets, sessions and hub CA keys are sealed
     under. A refusal names each key it cannot open and what it seals.

Each refusal names the flag that overrides it. --accept-secret-loss restores
a backup whose keys this CLOOP_SECRET_KEY cannot derive: those keys are
retired in the restored database so the hub can start, and what they sealed
is lost there (the backup file keeps it). It is deliberately not --force,
which only allows overwriting a live database. Import the right key from
escrow instead whenever you can: cloop hub key escrow import.

Then the restore is recorded, because to the audit checkpoints a restore
looks exactly like a tail deleted while the hub kept writing: an audit.restored
row is appended to the restored chain, and a restore record sealed under the
checkpoint key goes to audit.checkpoints.file (or --checkpoints) and stderr,
naming the backup, the head restored to, the newest checkpoint superseded and
the history lost, who, and --reason. 'cloop hub audit verify --checkpoints'
then reports the restore as acknowledged instead of failing on it.

--force is required when a live database is present; the existing file is
moved to a sibling .pre-restore.<timestamp> first. Stop the hub first: a
restore is refused while a hub holds the control-plane lease or a cluster
member is live. --check runs the preflight alone and writes nothing:
rehearse a restore with it.

Exit codes:
  0  restored and recorded (with --check: the backup would restore)
  1  refused or failed; nothing was changed
  2  the restore could not run (backup missing, unreadable)
  3  restored, but the record of it is incomplete — the output says what`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		roots, err := rootkey.Resolve()
		if err != nil {
			return err
		}
		o := dbRestoreOptions{Backup: args[0], Key: roots.Current.Value, Previous: roots.Previous.Value,
			Stderr: os.Stderr}
		o.Workdir, _ = os.Getwd()
		o.Force, _ = cmd.Flags().GetBool("force")
		o.SkipChecksum, _ = cmd.Flags().GetBool("skip-checksum")
		o.AllowUnsealed, _ = cmd.Flags().GetBool("allow-unsealed")
		o.AcceptSecretLoss, _ = cmd.Flags().GetBool("accept-secret-loss")
		o.Check, _ = cmd.Flags().GetBool("check")
		o.Reason, _ = cmd.Flags().GetString("reason")
		o.CheckpointFile, _ = cmd.Flags().GetString("checkpoints")
		if code := runDBRestore(os.Stdout, o); code != restoreExitOK {
			exitProcess(code)
		}
		return nil
	},
}

func init() {
	dbVerifyCmd.Flags().Bool("quick", false, "Use PRAGMA quick_check instead of integrity_check (faster, less thorough)")
	dbMaintainCmd.Flags().Bool("dry-run", false, "Report DB size and reclaimable estimate without running VACUUM/ANALYZE")
	dbMaintainCmd.Flags().Bool("auto", false, "Run only if DB has grown >20% since the last recorded vacuum")
	dbMaintainCmd.Flags().Bool("prune-audit", false, "Apply audit.retention_days before vacuuming (see 'cloop hub audit prune')")
	dbMaintainCmd.Flags().String("audit-hub", "", "Hub directory whose audit forwarding cursors bound the prune (default: this database, and the hub it names)")
	dbMaintainCmd.Flags().Bool("force-audit-prune", false, "Prune audit rows an audit sink has not acknowledged yet")
	dbBackupCmd.Flags().String("output", "", "Output path for the backup file (default: .cloop/backups/state-<UTC>.db)")
	dbRestoreCmd.Flags().Bool("force", false, "Overwrite an active destination database; the previous file is preserved as .pre-restore.<timestamp>")
	dbRestoreCmd.Flags().String("reason", "", "Why the database is being restored (required; recorded with the restore)")
	dbRestoreCmd.Flags().Bool("check", false, "Run the preflight only and write nothing: would this backup restore under this key?")
	dbRestoreCmd.Flags().Bool("skip-checksum", false, "Do not check the sidecar at all — no digest, no seal (for a backup whose sidecar was lost)")
	dbRestoreCmd.Flags().Bool("allow-unsealed", false, "Accept a sidecar whose seal cannot be checked here (unsealed, or sealed under another key); the digest is still checked")
	dbRestoreCmd.Flags().Bool("accept-secret-loss", false, "Restore although CLOOP_SECRET_KEY cannot open the backup's sealing keys; retires them, losing what they seal (recorded)")
	dbRestoreCmd.Flags().String("checkpoints", "", "Audit checkpoint file to read superseded checkpoints from and append the restore record to (default: audit.checkpoints.file)")
	dbCmd.AddCommand(dbVerifyCmd)
	dbCmd.AddCommand(dbMaintainCmd)
	dbCmd.AddCommand(dbBackupCmd)
	dbCmd.AddCommand(dbRestoreCmd)
	rootCmd.AddCommand(dbCmd)
}
