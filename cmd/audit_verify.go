package cmd

// The verdicts the audit verify commands share (Task 20404).
//
// A chain verification used to have two answers: intact, exit 0, or broken,
// exit 2. It now has a third, because a chain can be intact — every row present
// hashes correctly — and still be missing events: an append that failed leaves
// no hole in a hash chain, only an audit.gap row recording it, written once the
// database took writes again. Reporting that as "intact" is the lie by omission
// this task removed, so it exits 3 unless --allow-gaps says the operator has
// already accounted for the gaps.
//
// `cloop hub audit verify --checkpoints <file>` adds the check that reaches off
// the database: the heads the hub recorded under its seal, asked whether the
// chains still hold them. A head the chain lost is a finding exactly as a hash
// mismatch is, and exits 2.

import (
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"github.com/fatih/color"

	"github.com/blechschmidt/cloop/pkg/auditcheckpoint"
	"github.com/blechschmidt/cloop/pkg/auditmerge"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// Exit codes of the audit verify commands.
const (
	auditExitIntact = 0
	auditExitBroken = 2
	auditExitGaps   = 3
)

// auditVerifyExit folds chain statuses into one exit code: broken beats gaps,
// and gaps exit 0 only when allowGaps says they are expected.
func auditVerifyExit(statuses []string, allowGaps bool) int {
	code := auditExitIntact
	for _, st := range statuses {
		switch st {
		case statedb.AuditChainBroken:
			return auditExitBroken
		case statedb.AuditChainGaps:
			if !allowGaps {
				code = auditExitGaps
			}
		}
	}
	return code
}

// auditGapLine describes a chain's recorded gaps in one line.
func auditGapLine(rep statedb.AuditVerifyReport) string {
	noun := "gap"
	if rep.Gaps != 1 {
		noun = "gaps"
	}
	ids := make([]string, 0, len(rep.GapIDs))
	for _, id := range rep.GapIDs {
		ids = append(ids, fmt.Sprintf("#%d", id))
	}
	more := ""
	if rep.Gaps > len(rep.GapIDs) {
		more = fmt.Sprintf(" and %d more", rep.Gaps-len(rep.GapIDs))
	}
	return fmt.Sprintf("%d recorded %s covering %d lost event(s): audit.gap rows %s%s",
		rep.Gaps, noun, rep.GapEvents, strings.Join(ids, ", "), more)
}

// printSingleChainVerdict renders one chain's report for `cloop audit-log
// verify` and `cloop events verify`, and returns the exit code.
func printSingleChainVerdict(w io.Writer, report statedb.AuditVerifyReport, allowGaps bool) int {
	switch report.Status() {
	case statedb.AuditChainBroken:
		color.New(color.FgRed, color.Bold).Fprintf(w,
			"CHAIN BROKEN at id=%d after %d verified events\n", report.BreakAtID, report.Total-1)
		fmt.Fprintf(w, "  reason: %s\n", report.Reason)
	case statedb.AuditChainGaps:
		color.New(color.FgYellow, color.Bold).Fprintf(w,
			"INTACT WITH GAPS — %d events verified\n", report.Total)
		fmt.Fprintf(w, "  %s\n", auditGapLine(report))
		fmt.Fprintln(w, "  Each gap row records audit events that could not be appended (the database was")
		fmt.Fprintln(w, "  locked, read-only or full): the chain holds what was written, and says what was not.")
		if allowGaps {
			fmt.Fprintln(w, "  --allow-gaps: not failing on them.")
		}
	default:
		color.New(color.FgGreen, color.Bold).Fprintf(w, "OK — %d events verified\n", report.Total)
	}
	return auditVerifyExit([]string{report.Status()}, allowGaps)
}

// hubAuditVerifyOptions are `cloop hub audit verify`'s inputs.
type hubAuditVerifyOptions struct {
	Hub, Project    string
	AllowGaps       bool
	CheckpointsFile string
}

// runHubAuditVerify is `cloop hub audit verify`. It writes the report to w and
// returns the exit code; an error means it could not run at all.
func runHubAuditVerify(w io.Writer, opts hubAuditVerifyOptions) (int, error) {
	requested, err := hubAuditChains(opts.Hub, opts.Project, "all")
	if err != nil {
		return 0, err
	}
	reader, err := auditmerge.Open(requested)
	if err != nil {
		return 0, err
	}
	defer reader.Close()

	red := color.New(color.FgRed, color.Bold)
	yellow := color.New(color.FgYellow, color.Bold)
	dim := color.New(color.Faint)

	if len(reader.Chains()) == 0 {
		// Not exit 0. "Opened nothing" and "verified everything" must not
		// produce the same exit status, or a scheduled integrity check
		// keeps passing after the databases move.
		red.Fprintln(w, "NOTHING VERIFIED — no audit database found")
		for _, line := range hubAuditChainLines(requested, nil) {
			fmt.Fprintf(w, "  %s\n", line)
		}
		fmt.Fprintln(w, "  pass --hub/--project, or run 'cloop init' here")
		return auditExitBroken, nil
	}

	var statuses []string
	for _, v := range reader.Verify() {
		switch {
		case v.Err != nil:
			statuses = append(statuses, statedb.AuditChainBroken)
			red.Fprintf(w, "UNVERIFIABLE  %-13s %s\n", v.Source, v.Path)
			fmt.Fprintf(w, "  reason:   %v\n", v.Err)
			continue
		case !v.Report.OK:
			red.Fprintf(w, "CHAIN BROKEN  %-13s %s\n", v.Source, v.Path)
			fmt.Fprintf(w, "  break at  id=%d after %d verified events\n", v.Report.BreakAtID, v.Report.Total-1)
			fmt.Fprintf(w, "  reason:   %s\n", v.Report.Reason)
			if v.Report.ExpectedHash != "" || v.Report.ActualHash != "" {
				fmt.Fprintf(w, "  expected: %s\n", v.Report.ExpectedHash)
				fmt.Fprintf(w, "  actual:   %s\n", v.Report.ActualHash)
			}
		case v.Report.Gaps > 0:
			yellow.Fprintf(w, "GAPS          %-13s %s — %d events verified\n", v.Source, v.Path, v.Report.Total)
			fmt.Fprintf(w, "  %s\n", auditGapLine(v.Report))
		default:
			color.New(color.FgGreen, color.Bold).Fprintf(w, "OK            %-13s %s — %d events verified\n",
				v.Source, v.Path, v.Report.Total)
		}
		statuses = append(statuses, v.Report.Status())
		if v.Report.OK && v.Report.Anchored {
			// Explains a row count that looks short: the prefix is not
			// missing, it is sealed in a file the anchor names.
			dim.Fprintf(w, "  verified from id %d; %d earlier rows sealed in %s (sha256 %s)\n",
				v.Report.VerifiedFromID, v.Report.PrunedCount, v.Report.ExportPath, shortHex(v.Report.ExportSHA256))
		}
	}

	hubAuditReportMisrouted(w, reader, requested)

	code := auditVerifyExit(statuses, opts.AllowGaps)
	if code == auditExitGaps {
		dim.Fprintln(w, "\nEach gap row records audit events that could not be appended — the database was")
		dim.Fprintln(w, "locked, read-only or full. The chain is intact and says what it is missing; exit 3")
		dim.Fprintln(w, "says the same. Pass --allow-gaps once they are accounted for.")
	}

	if opts.CheckpointsFile != "" {
		failed, err := hubAuditCheckCheckpoints(w, reader, opts.CheckpointsFile)
		if err != nil {
			return 0, err
		}
		if failed {
			code = auditExitBroken
		}
	}
	return code, nil
}

// hubAuditCheckCheckpoints checks each opened chain against the records in
// file, and reports whether anything failed.
func hubAuditCheckCheckpoints(w io.Writer, reader *auditmerge.Reader, file string) (bool, error) {
	red := color.New(color.FgRed, color.Bold)
	yellow := color.New(color.FgYellow, color.Bold)
	dim := color.New(color.Faint)

	parsed, err := auditcheckpoint.ReadFile(file)
	if err != nil {
		// A verdict on the chains was asked for against this file and cannot
		// be given: that fails, after the chain verdicts already printed,
		// rather than replacing them with an error.
		red.Fprintf(w, "\nCHECKPOINTS UNREADABLE  %s\n  %v\n", file, err)
		return true, nil
	}
	key, kerr := auditcheckpoint.KeyFromEnv()
	if kerr != nil {
		key = nil
	}

	fmt.Fprintf(w, "\nCheckpoints   %s — %d record(s)\n", file, len(parsed.Records))
	if key == nil {
		yellow.Fprintf(w, "  no %s here: seals are not checked, only what the records say\n", auditcheckpoint.EnvKey)
	} else {
		dim.Fprintf(w, "  checking seals under key %s (from %s)\n", key.Fingerprint(), auditcheckpoint.EnvKey)
	}
	if len(parsed.Malformed) > 0 {
		yellow.Fprintf(w, "  %d line(s) name a checkpoint and do not decode (first: line %d) — a torn write or an edit\n",
			len(parsed.Malformed), parsed.Malformed[0])
	}
	if len(parsed.Oversized) > 0 {
		yellow.Fprintf(w, "  %d line(s) longer than any checkpoint were skipped (first: line %d)\n",
			len(parsed.Oversized), parsed.Oversized[0])
	}

	groups := auditcheckpoint.ByPath(parsed.Records)
	failed := false
	checkedAny := false
	for _, o := range reader.Opened() {
		recs, matchedAs := hubAuditCheckpointRecords(groups, o)
		if len(recs) == 0 {
			yellow.Fprintf(w, "NO CHECKPOINT %-13s %s\n", o.Source, o.Path)
			paths := auditcheckpoint.Paths(parsed.Records)
			if len(paths) > 5 {
				paths = append(paths[:5], "…")
			}
			fmt.Fprintf(w, "  none of the records names this database; they name: %s\n", strings.Join(paths, ", "))
			continue
		}
		checkedAny = true
		chain := auditcheckpoint.ChainProject
		if o.Source == auditmerge.SourceControlPlane {
			chain = auditcheckpoint.ChainControlPlane
		}
		rep, err := auditcheckpoint.VerifyChain(o.DB, o.Path, chain, recs, key)
		if err != nil {
			// Reported with the other verdicts, not instead of them: the
			// chains already printed above are still what was found.
			red.Fprintf(w, "UNCHECKED     %-13s %s\n  could not check it against its checkpoints: %v\n", o.Source, o.Path, err)
			failed = true
			continue
		}
		if matchedAs != "" {
			dim.Fprintf(w, "  (records for %s matched by role: they name %s)\n", o.Source, matchedAs)
		}
		hubAuditPrintCheckpointReport(w, o, rep, red, yellow, dim)
		if !rep.OK() {
			failed = true
		}
	}
	if !checkedAny {
		red.Fprintln(w, "NOTHING CHECKED — no checkpoint names a database that was opened")
		fmt.Fprintln(w, "  the file may belong to another hub, or the databases were moved since it was written")
		return true, nil
	}
	return failed, nil
}

// hubAuditCheckpointRecords finds the records naming o's database: by path,
// resolved, and for the control plane by role when the file names exactly one
// control-plane database — the case of a trail copied to another machine for
// review, where every path differs. matchedAs names the recorded path when the
// match was by role.
func hubAuditCheckpointRecords(groups map[string][]auditcheckpoint.Located, o auditmerge.Opened) ([]auditcheckpoint.Located, string) {
	candidates := []string{auditcheckpoint.ValidPath(o.Path)}
	if real, err := filepath.EvalSymlinks(o.Path); err == nil {
		candidates = append(candidates, auditcheckpoint.ValidPath(real))
	}
	for _, p := range candidates {
		if recs := groups[p]; len(recs) > 0 {
			return recs, ""
		}
	}
	if o.Source != auditmerge.SourceControlPlane {
		return nil, ""
	}
	var cp []string
	for p, recs := range groups {
		if len(recs) > 0 && recs[0].Chain == auditcheckpoint.ChainControlPlane {
			cp = append(cp, p)
		}
	}
	if len(cp) == 1 {
		return groups[cp[0]], cp[0]
	}
	return nil, ""
}

// hubAuditPrintCheckpointReport renders one chain's checkpoint verdict.
func hubAuditPrintCheckpointReport(w io.Writer, o auditmerge.Opened, rep auditcheckpoint.ChainReport, red, yellow, dim *color.Color) {
	if rep.OK() {
		color.New(color.FgGreen, color.Bold).Fprintf(w, "OK            %-13s %s\n", o.Source, o.Path)
		agree := rep.Consistent + rep.Pruned + rep.PrunedUnverified
		line := fmt.Sprintf("  %d checkpoint(s) agree with the chain", agree)
		if rep.Newest != nil {
			line += fmt.Sprintf("; the newest, at %s, saw id %d", rep.Newest.Time, rep.Newest.LastID)
		}
		fmt.Fprintln(w, line)
	} else {
		first := rep.Failures[0]
		red.Fprintf(w, "%-13s %-13s %s\n", strings.ToUpper(strings.ReplaceAll(string(first.Result), "-", " ")), o.Source, o.Path)
		fmt.Fprintf(w, "  finding:  %s\n", rep.Finding)
		if rep.Hint != "" {
			fmt.Fprintf(w, "  or:       %s\n", rep.Hint)
		}
		fmt.Fprintf(w, "  %d of %d checkpoint(s) disagree; the first is on line %d\n",
			len(rep.Failures), rep.Records, first.Line)
		for i, f := range rep.Failures {
			if i == 5 {
				fmt.Fprintf(w, "    … and %d more\n", len(rep.Failures)-i)
				break
			}
			fmt.Fprintf(w, "    line %-6d %-16s %s\n", f.Line, f.Result, f.Detail)
		}
	}
	if rep.PrunedUnverified > 0 {
		yellow.Fprintf(w, "  %d checkpoint(s) fall in a pruned prefix whose archive cannot be read here; "+
			"run this where the archives are to confirm them\n", rep.PrunedUnverified)
	}
	if rep.Unsigned > 0 {
		yellow.Fprintf(w, "  %d unsigned checkpoint(s): written by a hub with no %s, so anyone able to write "+
			"the file could have written them\n", rep.Unsigned, auditcheckpoint.EnvKey)
	}
	if rep.ForeignKey > 0 {
		yellow.Fprintf(w, "  %d checkpoint(s) sealed under another key — a rotated %s, or another hub's records\n",
			rep.ForeignKey, auditcheckpoint.EnvKey)
	}
	if rep.Unchecked > 0 {
		dim.Fprintf(w, "  %d sealed checkpoint(s) not checked: no key here\n", rep.Unchecked)
	}
}

// exitAuditVerify ends a verify command with code. Exiting rather than
// returning an error, because a finding is a successful verification and cobra
// would print usage text over it.
func exitAuditVerify(code int) {
	if code != auditExitIntact {
		exitProcess(code)
	}
}
