package cmd

// `cloop db restore` (Task 20410): a preflight before anything is swapped,
// a refusal that names the flag overriding it, and a restore that records
// itself where the audit checkpoints can account for it.

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/fatih/color"

	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/dbbackup"
	"github.com/blechschmidt/cloop/pkg/secretbroker"
)

// Exit codes of `cloop db restore`.
const (
	restoreExitOK         = 0
	restoreExitRefused    = 1
	restoreExitCannotRun  = 2
	restoreExitUnrecorded = 3
)

// dbRestoreOptions are `cloop db restore`'s inputs.
type dbRestoreOptions struct {
	Backup, Workdir  string
	Reason           string
	Force            bool
	SkipChecksum     bool
	AllowUnsealed    bool
	AcceptSecretLoss bool
	Check            bool
	// CheckpointFile overrides audit.checkpoints.file.
	CheckpointFile string
	// Key is CLOOP_SECRET_KEY and Previous CLOOP_SECRET_KEY_PREVIOUS, from
	// wherever pkg/rootkey resolved them; Stderr where the restore record's
	// stderr copy goes when the configuration asks for one.
	Key      string
	Previous string
	// KMS are the key-management services of the hub's secrets section
	// (Task 20433), through which a backup's KMS-held keys open.
	KMS    []secretbroker.KMS
	Stderr io.Writer
	Now    func() time.Time
}

// runDBRestore is `cloop db restore`. It writes its report to w and returns
// the exit code.
func runDBRestore(w io.Writer, o dbRestoreOptions) int {
	header := color.New(color.FgCyan, color.Bold)
	pass := color.New(color.FgGreen, color.Bold)
	warn := color.New(color.FgYellow, color.Bold)
	fail := color.New(color.FgRed, color.Bold)
	dim := color.New(color.Faint)

	dstPath := filepath.Join(o.Workdir, ".cloop", "state.db")
	mode := "cloop db restore"
	if o.Check {
		mode += " --check (nothing is written)"
	}
	header.Fprintln(w, mode)
	dim.Fprintf(w, "  backup:      %s\n", o.Backup)
	dim.Fprintf(w, "  destination: %s\n\n", dstPath)

	if !o.Check && strings.TrimSpace(o.Reason) == "" {
		fail.Fprintln(w, "Restore refused: --reason is required. It is recorded with the restore, in the restored")
		fmt.Fprintln(w, "audit chain and in the restore record the audit checkpoints accept it by.")
		return restoreExitRefused
	}
	if _, err := os.Stat(o.Backup); err != nil {
		fail.Fprintf(w, "Restore could not run: %v\n", err)
		return restoreExitCannotRun
	}

	pre, err := dbbackup.Inspect(o.Backup, dbbackup.PreflightOptions{
		Key:              o.Key,
		Previous:         o.Previous,
		KMS:              o.KMS,
		SkipChecksum:     o.SkipChecksum,
		AllowUnsealed:    o.AllowUnsealed,
		AcceptSecretLoss: o.AcceptSecretLoss,
	})
	if err != nil {
		fail.Fprintf(w, "Restore could not run: %v\n", err)
		return restoreExitCannotRun
	}
	printRestorePreflight(w, pre, dim, warn)

	if len(pre.Refusals) > 0 {
		fail.Fprintln(w, "Refused — nothing was changed:")
		for _, r := range pre.Refusals {
			fmt.Fprintf(w, "  • %s\n", r.Message)
			if r.Override != "" {
				dim.Fprintf(w, "    %s proceeds anyway\n", r.Override)
			}
		}
		return restoreExitRefused
	}
	if o.Check {
		pass.Fprintln(w, "PASS — this backup restores under this key.")
		return restoreExitOK
	}

	file, stderrOn, note := restoreCheckpointSinks(o.Workdir, o.CheckpointFile)
	if note != "" {
		warn.Fprintf(w, "  %s\n", note)
	}
	var stderr io.Writer
	if stderrOn {
		stderr = o.Stderr
	}
	report, err := dbbackup.Restore(o.Backup, dstPath, dbbackup.RestoreOptions{
		Force:            o.Force,
		Key:              o.Key,
		Previous:         o.Previous,
		KMS:              o.KMS,
		SkipChecksum:     o.SkipChecksum,
		AllowUnsealed:    o.AllowUnsealed,
		AcceptSecretLoss: o.AcceptSecretLoss,
		Reason:           o.Reason,
		Actor:            "cli:" + currentUser(),
		CheckpointFile:   file,
		CheckpointStderr: stderr,
		Now:              o.Now,
	})
	var unrecorded *dbbackup.UnrecordedError
	if err != nil && !errors.As(err, &unrecorded) {
		fail.Fprintf(w, "Restore failed: %v\n", err)
		return restoreExitRefused
	}

	fmt.Fprintf(w, "  size:        %s\n", humanBytes(report.SizeBytes))
	fmt.Fprintf(w, "  duration:    %s\n", report.Duration.Round(time.Millisecond))
	if report.BackedUpPath != "" {
		warn.Fprintf(w, "  rolled-back snapshot saved to %s\n", report.BackedUpPath)
		dim.Fprintln(w, "  (delete it once you have verified the restored DB.)")
	}
	printRecording(w, report.Recorded, file, dim, warn)

	if unrecorded != nil {
		fmt.Fprintln(w)
		warn.Fprintln(w, "Restored — but not fully recorded:")
		for _, p := range unrecorded.Problems {
			fmt.Fprintf(w, "  • %s\n", p)
		}
		return restoreExitUnrecorded
	}
	fmt.Fprintln(w)
	pass.Fprintln(w, "Restore complete.")
	dim.Fprintln(w, "Next: start the hub, then `cloop hub audit verify --checkpoints <file>` reports this restore as acknowledged.")
	return restoreExitOK
}

// printRestorePreflight renders what the backup was found to be.
func printRestorePreflight(w io.Writer, p *dbbackup.Preflight, dim, warn *color.Color) {
	if p.SHA256 != "" {
		fmt.Fprintf(w, "  sha256:      %s\n", p.SHA256)
	}
	if m := p.Meta; m != nil {
		dim.Fprintf(w, "  taken:       %s, schema v%d\n", m.CreatedAt.UTC().Format(time.RFC3339), m.SchemaVersion)
	}
	sidecar := string(p.Sidecar)
	switch {
	case p.Sidecar == dbbackup.SidecarSealed:
		sidecar = "sealed under key " + p.Meta.KeyFingerprint + ", and the seal verifies"
	case p.Sidecar == dbbackup.SidecarUnchecked && p.Seal == dbbackup.SealUnsigned:
		sidecar = "unchecked: it carries no seal"
	case p.Sidecar == dbbackup.SidecarUnchecked && p.Seal == dbbackup.SealForeignKey:
		sidecar = "unchecked: sealed under another key, " + p.Meta.KeyFingerprint
	case p.Sidecar == dbbackup.SidecarUnchecked:
		sidecar = "unchecked: no CLOOP_SECRET_KEY here to check its seal"
	case p.Sidecar == dbbackup.SidecarBroken && p.Seal == dbbackup.SealBad:
		sidecar = "BROKEN: its seal does not verify"
	case p.Sidecar == dbbackup.SidecarBroken:
		sidecar = "BROKEN: it does not describe this file"
	}
	fmt.Fprintf(w, "  sidecar:     %s\n", sidecar)
	if p.Chain.LastID > 0 {
		fmt.Fprintf(w, "  audit head:  id %d (%s), written %s\n", p.Chain.LastID, shortHex(p.Chain.LastRowHash),
			p.Chain.LastTimestamp.UTC().Format(time.RFC3339))
	} else {
		fmt.Fprintln(w, "  audit head:  the backup's chain is empty")
	}
	if p.KeyFingerprint != "" {
		fmt.Fprintf(w, "  checked against CLOOP_SECRET_KEY %s\n", p.KeyFingerprint)
		if p.PreviousKeyFingerprint != "" {
			fmt.Fprintf(w, "  and CLOOP_SECRET_KEY_PREVIOUS %s (a change of root is in progress)\n",
				p.PreviousKeyFingerprint)
		}
	} else {
		warn.Fprintln(w, "  no CLOOP_SECRET_KEY: no sealing key can be checked, and no seal")
	}
	if len(p.Keys) > 0 {
		fmt.Fprintln(w)
		tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "  SEALING KEY\tSTATE\tSEALED ROWS\tOPENS")
		for _, k := range p.Keys {
			opens := "yes"
			switch {
			case k.Lost:
				opens = "NO — " + k.Why
			case !k.Opens:
				opens = "no — " + k.Why
			}
			fmt.Fprintf(tw, "  %s\t%s\t%s\t%s\n", k.ID, k.State, rowsBySet(k.Rows), opens)
		}
		_ = tw.Flush()
	}
	fmt.Fprintln(w)
	for _, n := range p.Notes {
		warn.Fprintf(w, "  ! %s\n", n)
	}
	if len(p.Notes) > 0 {
		fmt.Fprintln(w)
	}
}

// printRecording says how the restore was recorded.
func printRecording(w io.Writer, rec dbbackup.Recording, file string, dim, warn *color.Color) {
	fmt.Fprintf(w, "  restored to: audit id %d\n", rec.RestoredHead.LastID)
	if s := rec.Superseded; s != nil {
		x := rec.Record.Restore
		fmt.Fprintf(w, "  supersedes:  the checkpoint at %s, which saw id %d — %d event(s) lost\n",
			s.Time, s.LastID, x.LostEvents())
	} else {
		dim.Fprintln(w, "  supersedes:  no checkpoint saw history past the restored head")
	}
	if rec.Row.ID > 0 {
		fmt.Fprintf(w, "  recorded:    audit.restored row %d in the restored chain\n", rec.Row.ID)
	}
	if len(rec.Sinks) > 0 {
		where := strings.Join(rec.Sinks, " and ")
		if file != "" {
			where = strings.Replace(where, "file", file, 1)
		}
		sealed := "sealed under key " + rec.Record.KeyFingerprint
		if !rec.Sealed {
			sealed = "UNSIGNED"
		}
		fmt.Fprintf(w, "  record:      restore record %s, written to %s\n", sealed, where)
	}
	if len(rec.RetiredKeys) > 0 {
		warn.Fprintf(w, "  retired:     %s — what they sealed is lost here; the backup file keeps them\n",
			strings.Join(rec.RetiredKeys, ", "))
	}
	for _, n := range rec.Notes {
		warn.Fprintf(w, "  ! %s\n", n)
	}
}

// restoreCheckpointSinks decides where the restore record goes: the
// --checkpoints file, else the audit.checkpoints.file the hubs here write —
// each per-instance overlay merged over config.yaml, which is what each hub
// reads, or config.yaml alone when no hub has an overlay — and stderr unless
// config.yaml turns it off. Hubs here writing different files is a question
// only the operator can answer, so the record then goes to stderr alone.
func restoreCheckpointSinks(workdir, flagFile string) (file string, stderr bool, note string) {
	cfg, err := config.Load(workdir)
	stderr = true
	if err == nil && cfg != nil {
		stderr = cfg.Audit.Checkpoints.StderrEnabled()
	}
	if flagFile != "" {
		return flagFile, stderr, ""
	}
	seen := map[string]bool{}
	ports, _ := config.UIInstancePorts(workdir)
	for _, port := range ports {
		if c, _, err := config.LoadUIInstance(workdir, port); err == nil && c != nil && c.Audit.Checkpoints.File != "" {
			seen[c.Audit.Checkpoints.File] = true
		}
	}
	if len(ports) == 0 && cfg != nil && cfg.Audit.Checkpoints.File != "" {
		seen[cfg.Audit.Checkpoints.File] = true
	}
	files := make([]string, 0, len(seen))
	for f := range seen {
		files = append(files, f)
	}
	sort.Strings(files)
	switch len(files) {
	case 0:
		return "", stderr, ""
	case 1:
		return files[0], stderr, ""
	}
	return "", stderr, fmt.Sprintf("the hubs here write checkpoints to %s; pass --checkpoints to say which "+
		"this restore record belongs in — it goes to stderr only", strings.Join(files, " and "))
}

// rowsBySet renders a key's sealed rows.
func rowsBySet(rows map[string]int) string {
	if len(rows) == 0 {
		return "-"
	}
	sets := make([]string, 0, len(rows))
	for s := range rows {
		sets = append(sets, s)
	}
	sort.Strings(sets)
	parts := make([]string, 0, len(sets))
	for _, s := range sets {
		parts = append(parts, fmt.Sprintf("%s=%d", s, rows[s]))
	}
	return strings.Join(parts, " ")
}
