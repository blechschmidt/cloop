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
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"github.com/blechschmidt/cloop/pkg/auditexport"
	"github.com/blechschmidt/cloop/pkg/auditmerge"
	"github.com/blechschmidt/cloop/pkg/auditretention"
	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

var hubAuditCmd = &cobra.Command{
	Use:   "audit",
	Short: "Read, verify, and prune the hash-chained audit trail across both databases",
	Long: `Read the whole audit trail, and manage its size without breaking its chain.

audit_events is not one table: it exists in the hub's control-plane state.db
and in every project's .cloop/state.db, with an independent hash chain in each.
'list' and 'verify' read both and say which rows came from where; everything
else operates on one database, because a chain is truncated where it lives.

  cloop hub audit list --since 24h      merged, timestamp-ordered, labelled
  cloop hub audit verify                check both chains, not just one
  cloop hub audit prune --before 90d    seal and remove rows older than 90 days
  cloop hub audit anchors               list previous truncations
  cloop hub audit verify-seals          re-hash each archive against its anchor

The trail is append-only and hash-linked, so it can only be shortened from the
front and only if the removal is recorded. A prune seals the removed rows to a
file, records that file's digest in an anchor, and then deletes — after which
chain verification succeeds across the gap instead of reporting a break.

Pruning frees pages inside the database but does not shrink the file. Run
'cloop db maintain' afterwards to return them to the filesystem.`,
}

var (
	hubAuditPruneBefore    string
	hubAuditPruneExportDir string
	hubAuditPruneDryRun    bool
	hubAuditPruneActor     string
	hubAuditPruneNoGzip    bool
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
			Before:       cutoff,
			ExportDir:    exportDir,
			Actor:        actor,
			DryRun:       hubAuditPruneDryRun,
			Uncompressed: hubAuditPruneNoGzip,
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

// ── the merged read: list and verify (Task 20292) ───────────────────────────
//
// prune, anchors and verify-seals above each work on one database, which is the
// right shape for retention. Reading is not that shape. Every reader before
// these two — `cloop audit-log list`, `verify`, `export`, the dashboard's Audit
// panel — opens whichever database the working directory resolved to and
// reports it as "the" trail, so an operator asking what happened to a project
// gets a confident answer that silently omits the half of the story the hub
// recorded about it: which executor ran it, which image policy admitted it,
// which credentials it held.
//
// These two read both chains through pkg/auditmerge and label every row with
// the one it came from. verify additionally reports rows sitting in the chain
// their action does not belong in, which no amount of chain verification can
// surface: a misrouted row is hashed correctly into the chain it was written
// to, so both chains verify and the row is still in the wrong place.

var (
	hubAuditListActor    string
	hubAuditListEntity   string
	hubAuditListEntityID string
	hubAuditListType     string
	hubAuditListSearch   string
	hubAuditListSince    string
	hubAuditListUntil    string
	hubAuditListLimit    int
	hubAuditListOffset   int
	hubAuditListOrder    string
	hubAuditListJSON     bool
	hubAuditListNoColor  bool
	hubAuditListProject  string
	hubAuditListHub      string
	hubAuditListSource   string
)

var hubAuditListCmd = &cobra.Command{
	Use:   "list",
	Short: "List audit events from both chains, merged and labelled by source",
	Long: `Read the control-plane and project audit chains as one trail.

Rows are ordered by timestamp, which is the only field comparable across the
two: the chains have independent id sequences, so "id 41" names a different
event in each and is never used to order or identify a row here. Each line is
prefixed with the chain it was read from.

--hub and --project both default to the current directory. On the hub's own
project that is the same database, and it is read once rather than twice — the
summary line says so, so a single chain in the list is distinguishable from a
missing one.

Filters match 'cloop audit-log list', including what --since accepts.

Examples:
  cloop hub audit list --since 24h
  cloop hub audit list --project /srv/projects/api --entity task --entity-id 63
  cloop hub audit list --source control-plane --type executor.enroll
  cloop hub audit list --json --limit 5000 | jq -r 'select(.source=="project")'`,
	RunE: func(cmd *cobra.Command, args []string) error {
		requested, err := hubAuditChains(hubAuditListHub, hubAuditListProject, hubAuditListSource)
		if err != nil {
			return err
		}
		reader, err := auditmerge.Open(requested)
		if err != nil {
			return err
		}
		defer reader.Close()

		f, err := auditLogFilter(auditLogFilterFlags{
			actor:    hubAuditListActor,
			entity:   hubAuditListEntity,
			entityID: hubAuditListEntityID,
			evType:   hubAuditListType,
			search:   hubAuditListSearch,
			since:    hubAuditListSince,
			until:    hubAuditListUntil,
			limit:    hubAuditListLimit,
			offset:   hubAuditListOffset,
			order:    hubAuditListOrder,
		})
		if err != nil {
			return err
		}

		rows, total, err := reader.List(f)
		if err != nil {
			return err
		}

		if hubAuditListJSON {
			if err := hubAuditWriteJSONL(os.Stdout, rows); err != nil {
				return err
			}
		} else {
			// The row itself is rendered by the printer `cloop audit-log list`
			// uses, with the source as a leading column. Sharing the renderer
			// is what keeps the two commands from drifting into showing the
			// same event differently.
			printer := newEventPrinter(false, hubAuditListNoColor)
			for _, r := range rows {
				hubAuditSourceColor(r.Source).Printf("%-13s ", r.Source)
				printer.print(r.AuditEvent)
			}
		}

		// stderr, so `cloop hub audit list --json | jq` stays a clean stream.
		dim := color.New(color.Faint)
		dim.Fprintf(os.Stderr, "\n%d shown / %d total\n", len(rows), total)
		for _, line := range hubAuditChainLines(requested, reader.Chains()) {
			dim.Fprintf(os.Stderr, "  %s\n", line)
		}
		return nil
	},
}

var (
	hubAuditVerifyProject string
	hubAuditVerifyHub     string
)

var hubAuditVerifyCmd = &cobra.Command{
	Use:   "verify",
	Short: "Validate the hash chain in both the control-plane and project databases",
	Long: `Recompute both audit chains and report each one separately.

Each database carries its own chain, so one says nothing about the other. They
are reported as two verdicts rather than one boolean: a single "OK" would let
an intact control-plane chain vouch for a project chain nobody checked. There
is deliberately no --source filter here for the same reason.

Also reports misrouted rows — events found in the chain their action does not
belong in — over a bounded window of recent events. That is advisory, not a
chain break: such a row is correctly hashed into the chain it was written to,
so both chains verify and the row is still in the wrong database. It usually
means an older build, or an emission site holding an unclassified handle.

Exit codes:
  0  both chains intact
  2  a chain is broken, unverifiable, or no audit database was found`,
	RunE: func(cmd *cobra.Command, args []string) error {
		requested, err := hubAuditChains(hubAuditVerifyHub, hubAuditVerifyProject, "all")
		if err != nil {
			return err
		}
		reader, err := auditmerge.Open(requested)
		if err != nil {
			return err
		}
		defer reader.Close()

		red := color.New(color.FgRed, color.Bold)
		dim := color.New(color.Faint)

		if len(reader.Chains()) == 0 {
			// Not exit 0. "Opened nothing" and "verified everything" must not
			// produce the same exit status, or a scheduled integrity check
			// keeps passing after the databases move.
			red.Println("NOTHING VERIFIED — no audit database found")
			for _, line := range hubAuditChainLines(requested, nil) {
				fmt.Printf("  %s\n", line)
			}
			fmt.Println("  pass --hub/--project, or run 'cloop init' here")
			os.Exit(2)
		}

		var bad int
		for _, v := range reader.Verify() {
			switch {
			case v.Err != nil:
				bad++
				red.Printf("UNVERIFIABLE  %-13s %s\n", v.Source, v.Path)
				fmt.Printf("  reason:   %v\n", v.Err)
			case v.Report.OK:
				color.New(color.FgGreen, color.Bold).Printf("OK            %-13s %s — %d events verified\n",
					v.Source, v.Path, v.Report.Total)
				if v.Report.Anchored {
					// Explains a row count that looks short: the prefix is not
					// missing, it is sealed in a file the anchor names.
					dim.Printf("  verified from id %d; %d earlier rows sealed in %s (sha256 %s)\n",
						v.Report.VerifiedFromID, v.Report.PrunedCount, v.Report.ExportPath, shortHex(v.Report.ExportSHA256))
				}
			default:
				bad++
				red.Printf("CHAIN BROKEN  %-13s %s\n", v.Source, v.Path)
				fmt.Printf("  break at  id=%d after %d verified events\n", v.Report.BreakAtID, v.Report.Total-1)
				fmt.Printf("  reason:   %s\n", v.Report.Reason)
				if v.Report.ExpectedHash != "" || v.Report.ActualHash != "" {
					fmt.Printf("  expected: %s\n", v.Report.ExpectedHash)
					fmt.Printf("  actual:   %s\n", v.Report.ActualHash)
				}
			}
		}

		hubAuditReportMisrouted(reader, requested)

		if bad > 0 {
			// Exit 2 rather than returning an error, matching
			// `cloop audit-log verify`: a broken chain is a successful
			// detection, and cobra would print usage text over the finding.
			os.Exit(2)
		}
		return nil
	},
}

// hubAuditMisroutedScan bounds the misrouted sweep to the most recent events.
//
// The check is a full comparison of every row against the action registry, and
// this project's own hub holds over a million rows — an unbounded sweep would
// turn a verification that takes seconds into one nobody runs. Recent rows are
// also the ones worth knowing about: they are what a just-shipped emission site
// would be writing to the wrong database right now.
const hubAuditMisroutedScan = 2000

// hubAuditMisroutedExamples caps how many offenders are printed. The count is
// the finding; the examples are there to make it actionable.
const hubAuditMisroutedExamples = 10

// hubAuditReportMisrouted prints the advisory half of verify.
//
// Failure to run the sweep is reported but does not fail the command: it is a
// secondary check, and letting it mask the chain verdicts that did complete
// would trade a real answer for a partial one.
func hubAuditReportMisrouted(reader *auditmerge.Reader, requested []auditmerge.Chain) {
	dim := color.New(color.Faint)

	// The check compares a row's declared home against the role of the chain it
	// was found in, which only means something when the two roles are two
	// files. On the hub's own project — the default invocation — they are one,
	// both homes are satisfied by it, and running the comparison anyway would
	// report every project-homed row in it as misplaced. That is a false
	// positive on the most common command anyone runs here, which is how a
	// warning gets trained out of an operator.
	if hubAuditOneDatabase(requested) {
		dim.Println("\nMisrouted-row check skipped: --hub and --project are one database, " +
			"so no row in it can be in the wrong chain.")
		dim.Println("  Point them at different directories to compare two chains.")
		return
	}

	rows, _, err := reader.List(statedb.AuditFilter{Order: "desc", Limit: hubAuditMisroutedScan})
	if err != nil {
		// stdout with the verdicts: a redirect that captures the report must
		// capture the fact that part of it did not run.
		dim.Printf("\nMisrouted-row check skipped: %v\n", err)
		return
	}
	bad := auditmerge.Misrouted(rows)
	if len(bad) == 0 {
		dim.Printf("\nNo misrouted rows among the %d most recent events.\n", len(rows))
		return
	}

	noun := "events are"
	if len(bad) == 1 {
		noun = "event is"
	}
	color.New(color.FgYellow, color.Bold).Printf(
		"\n! %d of the %d most recent %s in the wrong chain (advisory, not a chain break)\n",
		len(bad), len(rows), noun)
	shown := bad
	if len(shown) > hubAuditMisroutedExamples {
		shown = shown[:hubAuditMisroutedExamples]
	}
	for _, r := range shown {
		// Only two homes exist, so naming where it was found names where it
		// belongs; printing the registry's answer as well would say the same
		// thing twice.
		fmt.Printf("  %-22s %s  found in %s, belongs in %s\n",
			r.Ref(), r.EventType, r.Source, hubAuditOtherSource(r.Source))
	}
	if len(bad) > len(shown) {
		dim.Printf("  … and %d more\n", len(bad)-len(shown))
	}
	dim.Println("  These rows hash correctly where they are, so verification cannot see them.")
	// Only the unambiguous direction is reported — a fleet fact in a project's
	// chain. The reverse is not listed at all, because a hub runs from a
	// directory that is itself a project and its control-plane database
	// legitimately holds that project's own rows; see auditmerge.Misrouted.
	dim.Println("  A fleet event in a project's journal was written through the wrong database handle.")
}

// hubAuditOneDatabase reports whether two roles were requested but resolve to a
// single file — the hub's own project, where the control-plane and project
// chains are the same database.
func hubAuditOneDatabase(requested []auditmerge.Chain) bool {
	seen := make(map[string]auditmerge.Source, len(requested))
	for _, c := range requested {
		path := hubAuditDBPath(c.Dir)
		if prev, ok := seen[path]; ok && prev != c.Source {
			return true
		}
		seen[path] = c.Source
	}
	return false
}

// hubAuditOtherSource names the chain a misrouted row belongs in.
func hubAuditOtherSource(s auditmerge.Source) auditmerge.Source {
	if s == auditmerge.SourceControlPlane {
		return auditmerge.SourceProject
	}
	return auditmerge.SourceControlPlane
}

// hubAuditChains resolves the two directory flags and the --source filter into
// the chains to open.
//
// Control-plane first is load-bearing rather than alphabetical: on the hub's
// own project both flags name one database, auditmerge collapses the pair and
// keeps the first, and the fleet-wide rows in that file were written under the
// control plane's role. Ordering it second would label them as one project's.
func hubAuditChains(hubFlag, projectFlag, source string) ([]auditmerge.Chain, error) {
	wantHub, wantProject, err := hubAuditParseSource(source)
	if err != nil {
		return nil, err
	}
	var chains []auditmerge.Chain
	if wantHub {
		dir, err := hubAuditDir(hubFlag, "--hub")
		if err != nil {
			return nil, err
		}
		chains = append(chains, auditmerge.Chain{Source: auditmerge.SourceControlPlane, Dir: dir})
	}
	if wantProject {
		dir, err := hubAuditDir(projectFlag, "--project")
		if err != nil {
			return nil, err
		}
		chains = append(chains, auditmerge.Chain{Source: auditmerge.SourceProject, Dir: dir})
	}
	return chains, nil
}

// hubAuditParseSource maps --source onto the two chains.
func hubAuditParseSource(s string) (hub, project bool, err error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "all":
		return true, true, nil
	case "control-plane":
		return true, false, nil
	case "project":
		return false, true, nil
	}
	return false, false, fmt.Errorf("--source: unknown value %q (valid: control-plane, project, all)", s)
}

// hubAuditDir absolutises a directory flag, defaulting to the working
// directory. Absolute because the resolved path is printed back in the summary,
// where "." would tell an operator nothing about which database was read.
func hubAuditDir(flag, name string) (string, error) {
	dir := strings.TrimSpace(flag)
	if dir == "" {
		wd, err := os.Getwd()
		if err != nil {
			return "", fmt.Errorf("resolve working directory: %w", err)
		}
		dir = wd
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		return "", fmt.Errorf("%s: resolve %s: %w", name, dir, err)
	}
	return abs, nil
}

// hubAuditChainLines reports what each requested chain actually contributed.
//
// An empty result has three very different causes — nothing matched, the
// database is not there, or both flags named one file — and they are
// indistinguishable from the rows alone. Saying which happened is the whole
// reason Reader.Chains exists.
func hubAuditChainLines(requested, opened []auditmerge.Chain) []string {
	openedAt := make(map[string]auditmerge.Source, len(opened))
	for _, c := range opened {
		openedAt[hubAuditDBPath(c.Dir)] = c.Source
	}
	lines := make([]string, 0, len(requested))
	for _, c := range requested {
		path := hubAuditDBPath(c.Dir)
		switch src, ok := openedAt[path]; {
		case !ok:
			lines = append(lines, fmt.Sprintf("%-13s not present: %s", c.Source, path))
		case src != c.Source:
			lines = append(lines, fmt.Sprintf("%-13s same database as %s, read once: %s", c.Source, src, path))
		default:
			lines = append(lines, fmt.Sprintf("%-13s read: %s", c.Source, path))
		}
	}
	return lines
}

// hubAuditDBPath is how a chain's directory maps to the file auditmerge opens,
// so the summary names the database rather than the flag value.
func hubAuditDBPath(dir string) string {
	path := state.DBPath(dir)
	if abs, err := filepath.Abs(path); err == nil {
		return abs
	}
	return path
}

// hubAuditWriteJSONL writes the merged rows as JSONL, one object per line.
//
// The event is serialised by auditexport — the same writer
// `cloop audit-log export --format jsonl` uses — so a merged stream and a
// single-chain one parse identically, and a consumer's jq does not have to know
// which command produced the file. That package serialises audit rows and has
// nowhere to put provenance, so source and dir are appended to the object it
// produced. Declaring a parallel record type instead would duplicate a wire
// contract that already exists, leaving two copies to keep in step by hand.
func hubAuditWriteJSONL(w io.Writer, rows []auditmerge.Row) error {
	var buf bytes.Buffer
	for _, r := range rows {
		buf.Reset()
		if err := auditexport.Write(&buf, []auditexport.Event{r.AuditEvent}, auditexport.Options{
			Format: auditexport.FormatJSONL,
		}); err != nil {
			return fmt.Errorf("encode %s: %w", r.Ref(), err)
		}
		obj := bytes.TrimRight(buf.Bytes(), "\n")
		if len(obj) == 0 || obj[len(obj)-1] != '}' {
			return fmt.Errorf("encode %s: expected one JSON object from auditexport, got %q", r.Ref(), obj)
		}
		// Marshalled rather than quoted by hand: a directory path may contain a
		// quote or a backslash, and one such row would otherwise emit a line
		// that breaks the whole stream for whatever is parsing it. Marshalling
		// a string cannot fail.
		source, _ := json.Marshal(r.Source.String())
		dir, _ := json.Marshal(r.Dir)
		if _, err := fmt.Fprintf(w, "%s,\"source\":%s,\"dir\":%s}\n", obj[:len(obj)-1], source, dir); err != nil {
			return err
		}
	}
	return nil
}

// hubAuditSourceColor gives each chain a stable colour, so a merged read is
// scannable by source without reading the label on every line.
func hubAuditSourceColor(s auditmerge.Source) *color.Color {
	if s == auditmerge.SourceControlPlane {
		return color.New(color.FgBlue, color.Bold)
	}
	return color.New(color.FgGreen, color.Bold)
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
	hubAuditPruneCmd.Flags().BoolVar(&hubAuditPruneNoGzip, "no-compress", false,
		"write the archive as plain JSONL instead of gzip (roughly 10x larger)")
	hubAuditPruneCmd.Flags().StringVar(&hubAuditPruneActor, "actor", "",
		"identity to record on the anchor (default: cli)")
	hubAuditListCmd.Flags().StringVar(&hubAuditListActor, "actor", "", "Filter by actor (exact match)")
	hubAuditListCmd.Flags().StringVar(&hubAuditListEntity, "entity", "", "Filter by entity_type (task, plan, config, secret, executor, permission)")
	hubAuditListCmd.Flags().StringVar(&hubAuditListEntityID, "entity-id", "", "Filter by entity_id within --entity")
	hubAuditListCmd.Flags().StringVar(&hubAuditListType, "type", "", "Filter by event_type (exact match)")
	hubAuditListCmd.Flags().StringVar(&hubAuditListSearch, "search", "", "Case-insensitive substring match on the payload")
	hubAuditListCmd.Flags().StringVar(&hubAuditListSince, "since", "", "Events at/after RFC3339, YYYY-MM-DD, or 30m/2h/7d")
	hubAuditListCmd.Flags().StringVar(&hubAuditListUntil, "until", "", "Events at/before RFC3339, YYYY-MM-DD, or 30m/2h/7d")
	hubAuditListCmd.Flags().IntVar(&hubAuditListLimit, "limit", 100, "Page size, applied to the merged sequence")
	hubAuditListCmd.Flags().IntVar(&hubAuditListOffset, "offset", 0, "Skip the first N merged rows")
	hubAuditListCmd.Flags().StringVar(&hubAuditListOrder, "order", "desc", "Sort by timestamp: asc or desc")
	hubAuditListCmd.Flags().BoolVar(&hubAuditListJSON, "json", false, "Emit JSONL (each row carries source and dir) instead of the coloured table")
	hubAuditListCmd.Flags().BoolVar(&hubAuditListNoColor, "no-color", false, "Disable coloured output")
	hubAuditListCmd.Flags().StringVar(&hubAuditListProject, "project", "", "Project directory holding .cloop/state.db (default: current directory)")
	hubAuditListCmd.Flags().StringVar(&hubAuditListHub, "hub", "", "Control-plane directory holding .cloop/state.db (default: current directory)")
	hubAuditListCmd.Flags().StringVar(&hubAuditListSource, "source", "all", "Which chains to read: control-plane, project, or all")

	hubAuditVerifyCmd.Flags().StringVar(&hubAuditVerifyProject, "project", "", "Project directory holding .cloop/state.db (default: current directory)")
	hubAuditVerifyCmd.Flags().StringVar(&hubAuditVerifyHub, "hub", "", "Control-plane directory holding .cloop/state.db (default: current directory)")

	hubAuditCmd.AddCommand(hubAuditListCmd)
	hubAuditCmd.AddCommand(hubAuditVerifyCmd)
	hubAuditCmd.AddCommand(hubAuditPruneCmd)
	hubAuditCmd.AddCommand(hubAuditAnchorsCmd)
	hubAuditCmd.AddCommand(hubAuditVerifySealsCmd)
	hubCmd.AddCommand(hubAuditCmd)
}
