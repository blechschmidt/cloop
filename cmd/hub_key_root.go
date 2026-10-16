package cmd

// `cloop hub key rotate --retire-previous`: the last step of changing
// CLOOP_SECRET_KEY itself, online (Task 20425).
//
// The steps before it are a rolling restart: every hub member is restarted with
// the new key as CLOOP_SECRET_KEY and the old one as CLOOP_SECRET_KEY_PREVIOUS,
// and the new key is escrowed. This step then makes a key of the new root the
// primary, rewraps every secret, session refresh token and hub CA key onto it
// with the compare-and-swap rotation `rotate` has always used, and retires every
// key of the old root — after which the old key opens nothing and can be
// removed from every member.
//
// Both preconditions are checked here, against the deployment, before anything
// is minted or rewrapped:
//
//   - Every live hub member advertises the new root as its current one (in its
//     hub_members row's meta). A member still on the old root would be left
//     unable to read anything the moment the old keys are retired — and one
//     that advertises nothing predates the advertisement, so nothing is known
//     about the key it holds.
//   - An escrow of the new root is on record. Once the old keys are retired,
//     the new root is the only thing that opens this hub; until it is escrowed,
//     losing it loses everything.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/fatih/color"

	"github.com/blechschmidt/cloop/pkg/auditaction"
	"github.com/blechschmidt/cloop/pkg/hubcluster"
	"github.com/blechschmidt/cloop/pkg/hublease"
	"github.com/blechschmidt/cloop/pkg/keyescrow"
	"github.com/blechschmidt/cloop/pkg/rootkey"
	"github.com/blechschmidt/cloop/pkg/secretbroker"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// errRootChangeNotReady is a refusal of --retire-previous: a precondition about
// the deployment is not met, and nothing was changed.
var errRootChangeNotReady = errors.New("the change of root cannot be finished yet")

// rootMember is one live hub member as the change of root sees it.
type rootMember struct {
	ID       string `json:"id"`
	Hostname string `json:"hostname"`
	PID      int    `json:"pid"`
	// Current and Previous are the root fingerprints the member advertises;
	// "" when it advertises none.
	Current  string `json:"current_root,omitempty"`
	Previous string `json:"previous_root,omitempty"`
	// Ready: it advertises the new root as its current one.
	Ready bool `json:"ready"`
}

// rootChangeReadiness is what --retire-previous checked before acting.
type rootChangeReadiness struct {
	Current  string       `json:"current_root"`
	Previous string       `json:"previous_root"`
	Members  []rootMember `json:"members"`
	// Exclusive names a hub serving this control plane under
	// ui.cluster.exclusive: it holds the lease, has no member row, and so
	// advertises no root.
	Exclusive string `json:"exclusive_hub,omitempty"`
	// Escrow is the escrow on record; EscrowReady says it holds the new root.
	Escrow      *keyescrow.Record `json:"escrow,omitempty"`
	EscrowReady bool              `json:"escrow_ready"`
	// CurrentKMS: the new root is a KMS (Task 20433), so no escrow is
	// required; KMSKey is the key it reported when checked.
	CurrentKMS bool   `json:"current_kms,omitempty"`
	KMSKey     string `json:"kms_key,omitempty"`
	// Problems say what is not ready, one line each; none when it is.
	Problems []string `json:"problems,omitempty"`
}

// checkRootChangeReady reads the members and the escrow record of the control
// plane db holds and judges them against the new root, current, at now.
// currentKMS says the new root is a KMS (Task 20433): an escrow of
// CLOOP_SECRET_KEY recovers nothing it holds, so none is required — the KMS
// key's own durability is what a restore depends on, and it must answer.
func checkRootChangeReady(db *statedb.DB, current, previous string, currentKMS bool, now time.Time) (rootChangeReadiness, error) {
	r := rootChangeReadiness{Current: current, Previous: previous, CurrentKMS: currentKMS}
	rows, err := db.ListHubMembers()
	if err != nil {
		return r, fmt.Errorf("read the hub members: %w", err)
	}
	live := map[string]bool{}
	for _, row := range rows {
		if !hubcluster.RowAlive(row, now) {
			continue
		}
		live[row.InstanceID] = true
		m := rootMember{ID: row.InstanceID, Hostname: row.Hostname, PID: row.PID}
		meta := map[string]string{}
		if s := strings.TrimSpace(row.Meta); s != "" {
			_ = json.Unmarshal([]byte(s), &meta)
		}
		m.Current, m.Previous = meta[rootkey.EndpointCurrent], meta[rootkey.EndpointPrevious]
		m.Ready = m.Current == current
		restartNew := fmt.Sprintf("restart it on this build with the new key as %s", rootkey.EnvKey)
		restart := fmt.Sprintf("restart it with the new key as %s and the old one as %s", rootkey.EnvKey, rootkey.EnvPrevious)
		if currentKMS || strings.Contains(previous, ":") {
			// A KMS root (Task 20433): what a member needs is the secrets
			// section, not a key.
			restart = "restart it with the secrets section this shell has — secrets.kms, and the root being " +
				"replaced as secrets.previous_root or secrets.kms_previous"
			restartNew = restart + ", on this build"
		}
		switch {
		case m.Current == "":
			r.Problems = append(r.Problems, fmt.Sprintf("hub member %s (pid %d on %s) advertises no root key: it "+
				"predates this release or runs without a key — %s", m.ID, m.PID, m.Hostname, restartNew))
		case !m.Ready:
			r.Problems = append(r.Problems, fmt.Sprintf("hub member %s (pid %d on %s) runs on root key %s, not the "+
				"new %s: %s", m.ID, m.PID, m.Hostname, m.Current, current, restart))
		}
		r.Members = append(r.Members, m)
	}

	// A hub under ui.cluster.exclusive holds the lease and no member row, so
	// it advertises nothing: whatever key it holds is unknown.
	if lease, err := hublease.Inspect(hublease.Options{Store: db}); err == nil && lease.Live &&
		!live[lease.Row.InstanceID] {
		r.Exclusive = fmt.Sprintf("pid %d on %s", lease.Row.PID, lease.Row.Hostname)
		r.Problems = append(r.Problems, fmt.Sprintf("a hub serves this control plane exclusively (%s, "+
			"ui.cluster.exclusive) and advertises no root key: stop it, finish the change, and start it with the "+
			"new key", r.Exclusive))
	}

	if currentKMS {
		// Recorded for the report; not a condition. The keys move onto the
		// KMS, and no escrow of a passphrase opens them.
		if rec, ok, err := keyescrow.LoadRecord(db); err == nil && ok {
			r.Escrow = &rec
		}
		return r, nil
	}
	rec, ok, err := keyescrow.LoadRecord(db)
	switch {
	case err != nil:
		r.Problems = append(r.Problems, "the escrow record cannot be read: "+err.Error())
	case !ok:
		r.Problems = append(r.Problems, "no escrow is on record: once the old keys are retired the new key is "+
			"the only thing that opens this hub — escrow it first: `cloop hub key escrow export --output <file "+
			"off this host>`")
	default:
		r.Escrow = &rec
		r.EscrowReady = rec.KeyFingerprint == current
		if !r.EscrowReady {
			r.Problems = append(r.Problems, fmt.Sprintf("the escrow on record (%s) holds key %s, not the new %s: "+
				"escrow the new key first — `cloop hub key escrow export --output <file off this host>`",
				rec.ID, rec.KeyFingerprint, current))
		}
	}
	return r, nil
}

// runRetirePrevious is `cloop hub key rotate --retire-previous`.
func runRetirePrevious(w io.Writer, workdir string, h *hubKeyring, dryRun, asJSON bool) error {
	if !h.keyring.HasPrevious() {
		return fmt.Errorf("%w: --retire-previous finishes a change of root, and this shell holds only one root — "+
			"give it the one being replaced beside the new: the old key as %s (or %s), secrets.previous_root: "+
			"passphrase when moving onto a KMS, or secrets.kms_previous when moving off one",
			secretbroker.ErrNoPreviousRoot, rootkey.EnvPrevious, rootkey.EnvPreviousFile)
	}
	current, previous, err := h.keyring.RootFingerprints()
	if err != nil {
		return err
	}
	currentKMS := h.keyring.CurrentKMS() != nil
	ready, err := checkRootChangeReady(h.db, current, previous, currentKMS, time.Now())
	if err != nil {
		return err
	}
	if currentKMS {
		// The keys are about to move onto the KMS: it has to answer now, not
		// half way through the rewrap.
		if rep, ok := h.keyring.CurrentKMS().(secretbroker.KMSKeyReporter); ok {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			key, kerr := rep.CurrentKeyID(ctx)
			cancel()
			if kerr != nil {
				ready.Problems = append(ready.Problems, "the KMS "+current+" does not answer: "+kerr.Error())
			}
			ready.KMSKey = key
		}
	}

	bold := color.New(color.Bold)
	dim := color.New(color.Faint)
	if !asJSON {
		bold.Fprintf(w, "Change of root %s → %s\n", previous, current)
		printRootReadiness(w, ready)
	}
	if len(ready.Problems) > 0 {
		if asJSON {
			_ = printJSON(map[string]any{"readiness": ready})
		} else {
			color.New(color.FgRed).Fprintln(w, "\nRefused — nothing was minted, rewrapped or retired:")
			for _, p := range ready.Problems {
				fmt.Fprintf(w, "  • %s\n", p)
			}
		}
		return fmt.Errorf("%w: %d problem(s)", errRootChangeNotReady, len(ready.Problems))
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if !asJSON && !dryRun {
		dim.Fprintln(w, "\nRewrapping. Interrupting is safe — re-run to continue; nothing is retired until every row has moved.")
	}
	before := h.keyring.PrimaryID()
	report, rerr := h.rotator.RetirePrevious(ctx, secretbroker.RetirePreviousOptions{
		Actor:  "cli:" + currentUser(),
		DryRun: dryRun,
	})

	if !dryRun {
		if report.Rotation.TargetKeyID != "" {
			appendKeyAuditEvent(workdir, auditaction.ActionSealingKeyRotated, report.Rotation.TargetKeyID, map[string]any{
				"from_primary": before,
				"to_key":       report.Rotation.TargetKeyID,
				"rewrapped":    report.Rotation.Rewrapped,
				"skipped":      report.Rotation.Skipped,
				"failed":       report.Rotation.Failed,
				"complete":     report.Rotation.Complete,
				"via":          "cli",
			})
		}
		for _, id := range report.Keys {
			appendKeyAuditEvent(workdir, auditaction.ActionSealingKeyRetired, id, map[string]any{
				"key_id": id,
				"via":    "cli",
			})
		}
		escrowID := ""
		if ready.Escrow != nil {
			escrowID = ready.Escrow.ID
		}
		appendKeyAuditEvent(workdir, auditaction.ActionSealingKeyRootChanged, current, map[string]any{
			"root":          current,
			"previous_root": previous,
			"minted":        report.Minted,
			"to_key":        report.Rotation.TargetKeyID,
			"rewrapped":     report.Rotation.Rewrapped,
			"skipped":       report.Rotation.Skipped,
			"failed":        report.Rotation.Failed,
			"retired":       report.Keys,
			"remaining":     report.Remaining,
			"members":       len(ready.Members),
			"escrow_id":     escrowID,
			"complete":      report.Complete,
			"via":           "cli",
		})
	}

	if asJSON {
		if perr := printJSON(map[string]any{"readiness": ready, "report": report}); perr != nil {
			return perr
		}
		return rerr
	}

	if dryRun {
		onto := report.Rotation.TargetKeyID
		if !h.keyring.PrimaryFromCurrent() {
			onto = "a key minted from the new root"
		}
		fmt.Fprintf(w, "\nDry run: %d row(s) would be rewrapped onto %s, and %d key(s) of the previous root "+
			"retired: %s.\n", report.Rotation.Rewrapped, onto, len(report.Keys), orDash(strings.Join(report.Keys, ", ")))
		return rerr
	}

	fmt.Fprintln(w)
	if report.Minted != "" {
		fmt.Fprintf(w, "  minted %s from the new root and made it primary\n", report.Minted)
	}
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "  SET\tREWRAPPED\tSKIPPED\tFAILED")
	for _, s := range report.Rotation.Sets {
		fmt.Fprintf(tw, "  %s\t%d\t%d\t%d\n", s.Name, s.Rewrapped, s.Skipped, s.Failed)
	}
	_ = tw.Flush()
	for _, s := range report.Rotation.Sets {
		for _, e := range s.Errors {
			color.Red("  %s", e)
		}
	}
	for _, e := range report.Errors {
		color.Red("  %s", e)
	}
	if rerr != nil {
		color.New(color.FgYellow).Fprintf(w, "\nThe change of root did not finish: %v\n", rerr)
		dim.Fprintln(w, "Re-run 'cloop hub key rotate --retire-previous' to continue.")
		return rerr
	}
	color.New(color.FgGreen).Fprintf(w, "\nEvery row is sealed under %s, and the previous root's %d key(s) are retired: %s.\n",
		report.Rotation.TargetKeyID, len(report.Keys), orDash(strings.Join(report.Keys, ", ")))
	switch {
	case h.keyring.PreviousIsKMS():
		dim.Fprintf(w, "The KMS %s holds nothing of this hub's any more. Remove secrets.kms_previous from every\n"+
			"member and restart them; until then `cloop hub doctor` warns that it is set.\n", previous)
	case currentKMS:
		dim.Fprintf(w, "%s derives nothing in the secret store any more. Remove secrets.previous_root from every\n"+
			"member and restart them; until then `cloop hub doctor` warns that it is set. A backup taken before\n"+
			"this step still opens with %s — retire or destroy those, or keep them as safe as the key.\n",
			rootkey.EnvKey, rootkey.EnvKey)
	default:
		dim.Fprintf(w, "%s opens nothing any more. Remove it from every member and restart them; until then\n"+
			"`cloop hub doctor` warns that it is set.\n", rootkey.EnvPrevious)
	}
	return nil
}

// printRootReadiness renders the members and the escrow as --retire-previous
// found them.
func printRootReadiness(w io.Writer, r rootChangeReadiness) {
	dim := color.New(color.Faint)
	if len(r.Members) == 0 && r.Exclusive == "" {
		dim.Fprintln(w, "  no hub member is serving: the change runs offline, and a member started later must "+
			"hold the new root")
	}
	for _, m := range r.Members {
		mark := "ready  "
		if !m.Ready {
			mark = "NOT    "
		}
		fmt.Fprintf(w, "  %s member %s (pid %d on %s): root %s", mark, m.ID, m.PID, m.Hostname, orDash(m.Current))
		if m.Previous != "" {
			fmt.Fprintf(w, ", previous %s", m.Previous)
		}
		fmt.Fprintln(w)
	}
	switch {
	case r.CurrentKMS && r.KMSKey != "":
		fmt.Fprintf(w, "  ready   the KMS %s answers, encrypting under %s; no escrow is needed for it — a restore\n"+
			"          of this hub needs access to that KMS key instead\n", r.Current, r.KMSKey)
	case r.CurrentKMS:
		fmt.Fprintf(w, "  NOT     the KMS %s does not answer\n", r.Current)
	case r.Escrow == nil:
		fmt.Fprintln(w, "  NOT     no escrow on record")
	case r.EscrowReady:
		fmt.Fprintf(w, "  ready   escrow %s holds the new key\n", r.Escrow.ID)
	default:
		fmt.Fprintf(w, "  NOT     escrow %s holds key %s\n", r.Escrow.ID, r.Escrow.KeyFingerprint)
	}
}
