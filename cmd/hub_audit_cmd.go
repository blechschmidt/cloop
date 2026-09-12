package cmd

// hub_audit_cmd.go is the operator's retention control for the audit trail
// (Task 20218).
//
// Before this, audit_events only grew. On this project's own hub it reached
// 1,096,198 rows and 2.44 GB, and there was no command anywhere that could
// make it smaller — pkg/compact did not touch it, and `cloop db maintain`
// dutifully copied the whole thing.
//
// The reason it could not simply be given a DELETE is that the table is
// hash-chained and `cloop audit-log verify` checks the chain. Removing rows
// leaves the first survivor pointing at a predecessor that no longer exists,
// which the verifier reports as tampering — correctly, because from inside the
// database a legitimate truncation and a cover-up look identical.
//
// So `prune` never just deletes. It seals the prefix to a JSONL file, digests
// it, and records an anchor holding the boundary hash, the surviving id, and
// that digest. The verifier reads the anchor and walks across the gap; the
// digest is what makes the anchor's claim checkable against something outside
// the database, which is what `verify-seals` does.

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"github.com/blechschmidt/cloop/pkg/auditretention"
	"github.com/blechschmidt/cloop/pkg/config"
)

var hubAuditCmd = &cobra.Command{
	Use:   "audit",
	Short: "Manage retention for the hash-chained audit trail",
	Long: `Manage the audit trail's size without breaking its chain.

The audit trail is append-only and hash-linked, so it can only be shortened
from the front and only if the removal is recorded. A prune seals the removed
rows to a file, records that file's digest in an anchor, and then deletes —
after which chain verification succeeds across the gap instead of reporting a
break.

  cloop hub audit prune --before 90d    seal and remove rows older than 90 days
  cloop hub audit anchors               list previous truncations
  cloop hub audit verify-seals          re-hash each archive against its anchor

Pruning frees pages inside the database but does not shrink the file. Run
'cloop db maintain' afterwards to return them to the filesystem.`,
}

var (
	hubAuditPruneBefore    string
	hubAuditPruneExportDir string
	hubAuditPruneDryRun    bool
	hubAuditPruneActor     string
	hubAuditPruneYes       bool
)

var hubAuditPruneCmd = &cobra.Command{
	Use:   "prune",
	Short: "Seal and remove audit rows older than a cutoff",
	Long: `Seal the audit prefix older than --before to a file, then remove it.

Nothing is deleted until the archive is written, fsynced, and digested, and the
rows are chain-verified on the way out — a trail that is already broken is
reported rather than archived and then destroyed.

The cutoff accepts a duration ("90d", "720h"), an RFC3339 instant, or a date
("2026-01-01"). With no --before, the window comes from audit.retention_days in
.cloop/config.yaml; without that too, the command refuses rather than guess.

Safe to run against a live hub: the seal reads in bounded batches and the
truncation is one transaction. It does not VACUUM, so the file does not shrink
until 'cloop db maintain' runs — that one does need the hub stopped.

Examples:
  cloop hub audit prune --before 90d --dry-run
  cloop hub audit prune --before 2026-01-01
  cloop hub audit prune --export-dir /srv/audit-archive --before 30d`,
	RunE: func(cmd *cobra.Command, args []string) error {
		log, err := openAuditLog()
		if err != nil {
			return err
		}
		defer log.Close()

		workdir, err := os.Getwd()
		if err != nil {
			return fmt.Errorf("resolve working directory: %w", err)
		}
		cfg, _ := config.Load(workdir)

		cutoff, err := resolveAuditCutoff(hubAuditPruneBefore, cfg)
		if err != nil {
			return err
		}
		exportDir := resolveAuditExportDir(hubAuditPruneExportDir, cfg, workdir)

		actor := hubAuditPruneActor
		if actor == "" {
			actor = "cli"
		}

		rep, err := auditretention.Prune(log.DB(), auditretention.Options{
			Before:    cutoff,
			ExportDir: exportDir,
			Actor:     actor,
			DryRun:    hubAuditPruneDryRun,
		})
		if err != nil {
			return err
		}

		bold := color.New(color.Bold)
		dim := color.New(color.Faint)

		if rep.Candidate.Count == 0 {
			fmt.Printf("Nothing to prune: no audit rows older than %s.\n",
				cutoff.Format(time.RFC3339))
			return nil
		}

		if rep.DryRun {
			bold.Printf("Would seal and remove %d audit rows\n", rep.Candidate.Count)
			fmt.Printf("  range       id %d … %d\n", rep.Candidate.FirstID, rep.Candidate.ThroughID)
			fmt.Printf("  cutoff      %s\n", cutoff.Format(time.RFC3339))
			fmt.Printf("  surviving   %d rows\n", rep.Candidate.Remaining)
			fmt.Printf("  archive to  %s\n", exportDir)
			dim.Println("\nRe-run without --dry-run to apply. Then 'cloop db maintain' to reclaim the space.")
			return nil
		}

		bold.Printf("Sealed and removed %d audit rows\n", rep.Anchor.PrunedCount)
		fmt.Printf("  range       id %d … %d\n", rep.Anchor.PrunedFirstID, rep.Anchor.PrunedThroughID)
		fmt.Printf("  archive     %s (%s)\n", rep.ExportPath, humanBytesAudit(rep.ExportBytes))
		fmt.Printf("  sha256      %s\n", rep.ExportSHA256)
		fmt.Printf("  anchor      #%d, boundary %s\n", rep.Anchor.ID, shortHex(rep.Anchor.BoundaryHash))
		if rep.Anchor.RetainedFromID > 0 {
			fmt.Printf("  chain now   resumes at id %d\n", rep.Anchor.RetainedFromID)
		} else {
			fmt.Printf("  chain now   empty; next row will be id %d\n", rep.Anchor.PrunedThroughID+1)
		}

		// Prove the claim immediately rather than leaving the operator to
		// wonder. A prune that broke verification would be the single worst
		// outcome of this command, so it checks its own work.
		verdict, verr := log.Verify()
		if verr != nil {
			return fmt.Errorf("prune succeeded but verification could not run: %w", verr)
		}
		if !verdict.OK {
			return fmt.Errorf("prune left the chain unverifiable at id %d: %s", verdict.BreakAtID, verdict.Reason)
		}
		color.New(color.FgGreen).Printf("\n✓ chain verifies across the truncation (%d rows checked)\n", verdict.Total)
		dim.Println("Run 'cloop db maintain' to return the freed pages to the filesystem.")
		return nil
	},
}

var hubAuditAnchorsCmd = &cobra.Command{
	Use:   "anchors",
	Short: "List previous audit-trail truncations",
	Long: `List every recorded truncation of the audit chain, oldest first.

Each anchor names the id range it removed, where those rows were archived, and
the digest of that archive. Together they are the complete retention history:
any row that ever existed is either still in the table or inside exactly one of
these files.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		log, err := openAuditLog()
		if err != nil {
			return err
		}
		defer log.Close()

		anchors, err := log.DB().ListAuditAnchors()
		if err != nil {
			return err
		}
		if len(anchors) == 0 {
			fmt.Println("No anchors: the audit trail has never been pruned.")
			return nil
		}
		for _, a := range anchors {
			color.New(color.Bold).Printf("anchor #%d  %s  by %s\n",
				a.ID, a.CreatedAt.Format(time.RFC3339), a.Actor)
			fmt.Printf("  removed    %d rows, id %d … %d (cutoff %s)\n",
				a.PrunedCount, a.PrunedFirstID, a.PrunedThroughID, a.Cutoff.Format(time.RFC3339))
			fmt.Printf("  boundary   %s\n", shortHex(a.BoundaryHash))
			fmt.Printf("  archive    %s (%s)\n", a.ExportPath, humanBytesAudit(a.ExportBytes))
			fmt.Printf("  sha256     %s\n", a.ExportSHA256)
		}
		return nil
	},
}

var hubAuditVerifySealsCmd = &cobra.Command{
	Use:   "verify-seals",
	Short: "Re-hash each archived prefix and compare it to its anchor",
	Long: `Check every sealed archive against the digest recorded when it was written.

This is the part of verification that reaches outside the database. Chain
verification can only prove the surviving rows agree with what the anchors
claim, and an attacker who can rewrite audit_events can rewrite audit_anchors
too. The archives are the copy that can live somewhere the hub cannot write —
this compares the two.

A missing archive is reported but is not necessarily wrong: moving old seals to
cold storage is a reasonable thing to do. A digest mismatch always is.

Exits non-zero if any archive that is present fails its digest.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		log, err := openAuditLog()
		if err != nil {
			return err
		}
		defer log.Close()

		statuses, err := auditretention.VerifySeals(log.DB())
		if err != nil {
			return err
		}
		if len(statuses) == 0 {
			fmt.Println("No anchors: the audit trail has never been pruned.")
			return nil
		}
		var bad int
		for _, st := range statuses {
			switch {
			case st.OK:
				color.New(color.FgGreen).Printf("✓ anchor #%d  %s\n", st.Anchor.ID, st.Anchor.ExportPath)
			case !st.Present:
				color.New(color.FgYellow).Printf("? anchor #%d  %s — not readable: %v\n",
					st.Anchor.ID, st.Anchor.ExportPath, st.Err)
			default:
				bad++
				color.New(color.FgRed).Printf("✗ anchor #%d  %s — %v\n",
					st.Anchor.ID, st.Anchor.ExportPath, st.Err)
			}
		}
		if bad > 0 {
			return fmt.Errorf("%d archive(s) do not match their anchor", bad)
		}
		return nil
	},
}

// resolveAuditCutoff turns the --before flag, or the configured retention
// window, into an instant.
//
// There is deliberately no fallback beyond those two. A default cutoff on a
// command that deletes from the compliance record would be the kind of
// convenience that gets someone fired.
func resolveAuditCutoff(flag string, cfg *config.Config) (time.Time, error) {
	if flag != "" {
		ts, err := parseTimeFlag(flag)
		if err != nil {
			return time.Time{}, fmt.Errorf("--before: %w", err)
		}
		return ts.UTC(), nil
	}
	if cfg != nil && cfg.Audit.RetentionDays > 0 {
		return auditretention.ResolveCutoff(cfg.Audit.RetentionDays, time.Now().UTC()), nil
	}
	return time.Time{}, errors.New(
		"no cutoff: pass --before (e.g. --before 90d) or set audit.retention_days in .cloop/config.yaml")
}

// resolveAuditExportDir picks where seals are written: the flag, then the
// config, then a directory beside the database.
func resolveAuditExportDir(flag string, cfg *config.Config, workdir string) string {
	if flag != "" {
		return flag
	}
	if cfg != nil && cfg.Audit.ExportDir != "" {
		return cfg.Audit.ExportDir
	}
	return filepath.Join(workdir, ".cloop", auditretention.DefaultExportDirName)
}

func shortHex(h string) string {
	if len(h) <= 12 {
		return h
	}
	return h[:12] + "…"
}

func humanBytesAudit(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for v := n / unit; v >= unit; v /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}

func init() {
	hubAuditPruneCmd.Flags().StringVar(&hubAuditPruneBefore, "before", "",
		"cutoff: rows older than this are sealed and removed (90d, 720h, 2026-01-01, RFC3339)")
	hubAuditPruneCmd.Flags().StringVar(&hubAuditPruneExportDir, "export-dir", "",
		"directory to seal the removed prefix into (default: audit.export_dir, else .cloop/audit-archive)")
	hubAuditPruneCmd.Flags().BoolVar(&hubAuditPruneDryRun, "dry-run", false,
		"report what would be sealed and removed without touching anything")
	hubAuditPruneCmd.Flags().StringVar(&hubAuditPruneActor, "actor", "",
		"identity to record on the anchor (default: cli)")
	hubAuditPruneCmd.Flags().BoolVar(&hubAuditPruneYes, "yes", false,
		"deprecated no-op, retained so existing scripts keep working")
	_ = hubAuditPruneCmd.Flags().MarkHidden("yes")

	hubAuditCmd.AddCommand(hubAuditPruneCmd)
	hubAuditCmd.AddCommand(hubAuditAnchorsCmd)
	hubAuditCmd.AddCommand(hubAuditVerifySealsCmd)
	hubCmd.AddCommand(hubAuditCmd)
}
