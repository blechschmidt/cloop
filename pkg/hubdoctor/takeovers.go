package hubdoctor

// The credentials adopted runs have not taken over yet (Task 20451).
//
// A hub process adopting a run — a hub restarted in its own directory, a
// cluster member whose peer died, the nightly deploy of a hub while a device
// runs a task — takes over what the run's owner row names: its secret leases,
// its workspace lease and its egress sessions. An attempt the secret store
// cannot answer — unreadable for a moment, the database locked, a KMS down —
// decides nothing, and the member keeps trying until it does or the
// credential's recorded expiry passes. Until then what the credential feeds is
// not served: the run's git pushes and kubectl calls through the hub are
// refused, and they stay refused if the lease lapses first.
//
// The member names each such takeover in the run's owner row, beside the
// credential lists a later adopter reads, so this check finds them with a
// read-only look at the rows — from `cloop hub doctor` with no member running,
// and from Settings → Hub health, which runs the same step — and an operator
// learns of it before a developer's push fails.

import (
	"fmt"
	"os"
	"time"

	"github.com/blechschmidt/cloop/pkg/hubcluster"
	"github.com/blechschmidt/cloop/pkg/state"
)

const (
	runTakeoversCheck = "runs.lease_takeovers"
	runTakeoversTitle = "Credentials of adopted runs"
)

func checkRunTakeovers(dir string, opts Options, add addFn) {
	dbPath := state.DBPath(dir)
	if _, err := os.Stat(dbPath); err != nil {
		return // no control plane yet: nothing has been adopted
	}
	now := opts.now()
	claims, err := hubcluster.PeekRunClaims(dbPath, now)
	if err != nil {
		add(Finding{
			Check: runTakeoversCheck, Title: runTakeoversTitle, Severity: SeverityWarn,
			Message: fmt.Sprintf("the run claims could not be read to see whether an adopted run waits on a "+
				"credential: %v", err),
			Remediation: "Check the storage findings above; the run claims live in .cloop/state.db (hub_owners)",
		})
		return
	}
	found := 0
	for _, o := range claims {
		var meta hubcluster.RunTakeoverMeta
		if err := o.Meta(&meta); err != nil {
			continue
		}
		for _, tk := range meta.Takeovers {
			found++
			add(runTakeoverFinding(o, tk, now))
		}
	}
	if found == 0 {
		add(Finding{
			Check: runTakeoversCheck, Title: runTakeoversTitle, Severity: SeverityPass,
			Message: "no adopted run waits on a credential its hub process could not take over",
		})
	}
}

// runTakeoverFinding reports one undecided takeover of the run o claims.
func runTakeoverFinding(o hubcluster.Owner, tk hubcluster.RunTakeover, now time.Time) Finding {
	owner := fmt.Sprintf("hub process %s, which serves", o.InstanceID)
	next := "It retries on its own, the wait growing from two seconds to a minute; the first attempt that can " +
		"read the secret store takes the credential over and restores what it feeds, with nothing to restart. "
	if !o.Alive {
		owner = fmt.Sprintf("hub process %s, which has stopped", o.InstanceID)
		next = "The member that adopts the run next tries it again from the run's owner row. "
	}
	msg := fmt.Sprintf("the run of %s, adopted by %s, has not taken over %s %s since %s (%d attempt(s)): %s",
		o.Key, owner, takeoverWhat(tk.Kind), tk.ID, tk.Since.UTC().Format(time.RFC3339), tk.Attempts, tk.Reason)
	if !tk.Until.IsZero() {
		if left := tk.Until.Sub(now); left > 0 {
			msg += fmt.Sprintf(". It is tried until it lapses at %s, in %s", tk.Until.UTC().Format(time.RFC3339),
				left.Round(time.Second))
		} else {
			msg += fmt.Sprintf(". It lapsed at %s", tk.Until.UTC().Format(time.RFC3339))
		}
	}
	msg += "; until then " + takeoverStakeOf(tk.Kind)
	return Finding{
		Check: runTakeoversCheck, Title: runTakeoversTitle, Severity: SeverityWarn,
		Message: msg,
		Remediation: next + "Find why it cannot: the storage findings above (the database locked or its disk at " +
			"the floor) and secrets.kms.reachable (a KMS that does not answer). One that lapses first is recorded " +
			"on the run's event history as a failed lease_takeover, and the run carries on without it; restart " +
			"the run to have a new lease issued",
		Details: map[string]any{
			"project": o.Key, "member": o.InstanceID, "member_serving": o.Alive, "kind": tk.Kind, "id": tk.ID,
			"since": tk.Since.UTC().Format(time.RFC3339), "attempts": tk.Attempts,
			"until": tk.Until.UTC().Format(time.RFC3339),
		},
	}
}

// takeoverWhat names a takeover's kind.
func takeoverWhat(kind string) string {
	switch kind {
	case "workspace":
		return "its workspace lease"
	case "egress":
		return "its egress proxy session"
	default:
		return "its secret lease"
	}
}

// takeoverStakeOf says what a run goes without while kind is not taken over.
func takeoverStakeOf(kind string) string {
	switch kind {
	case "workspace":
		return "the pinned git session it stands on is not served, and the run's push write-back is refused"
	case "egress":
		return "the run's requests through the hub's egress proxy are refused"
	default:
		return "what it feeds — the run's git proxy and Kubernetes monitor sessions, its GitHub App tokens — " +
			"is not served, and the run's git pushes and kubectl calls through the hub are refused"
	}
}
