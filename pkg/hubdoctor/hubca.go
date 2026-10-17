package hubdoctor

// The hub's own CA and its rotation (Task 20438).
//
// A rotation is three steps an operator takes, and each can stall: a stage
// waits for the runs dispatched before it, an activation for the cluster
// leader to reissue the monitors' certificates, a retirement for the operator.
// None of that stalls loudly — the hub keeps serving, every sandbox keeps
// verifying — so this says when one has gone on longer than it should:
//
//   - hubca.rotation: a stage older than the longest session a monitor grants
//     (session_minutes) — the runs it waits for should have ended by then —
//     and a previous CA still trusted that long after its activation;
//   - hubca.members: a live hub member whose build predates rotation, which
//     an activation refuses to run beside, or one that has not adopted the
//     step;
//   - hubca.names: a monitor reached at a name the active CA's X.509 name
//     constraints do not permit, which every sandbox's check refuses.
//
// hubca.expiry, in monitortls.go, names the rotation as the way to replace a
// CA nearing its end.

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/hubca"
	"github.com/blechschmidt/cloop/pkg/hubcluster"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// hubCADocs is where the rotation is explained.
const hubCADocs = "docs/operations/runbook.md#rotating-the-hub-ca"

// LongestMonitorSession is the longest session a credential monitor that
// issues from the hub CA grants: the git proxy's or the Kubernetes monitor's
// session_minutes, for whichever runs under tls: auto. Zero when neither does.
func LongestMonitorSession(cfg *config.Config) time.Duration {
	if cfg == nil {
		return 0
	}
	var longest time.Duration
	if g := cfg.Executors.GitProxy; g.Enabled && g.AutoTLS() {
		longest = time.Duration(g.SessionTTLMinutes()) * time.Minute
	}
	if k := cfg.Executors.KubeGuard; k.Enabled && k.AutoTLS() {
		if d := time.Duration(k.SessionTTLMinutes()) * time.Minute; d > longest {
			longest = d
		}
	}
	return longest
}

// HubCAConfigNames are the names the configuration says sandboxes reach the
// monitors under tls: auto at: each one's advertise URL's host and the host
// its listen address names. A monitor advertised at no URL is reached at the
// address it binds, which only the running hub knows; the leaf it was issued
// names it, and a stage reads that too.
func HubCAConfigNames(cfg *config.Config) []string {
	if cfg == nil {
		return nil
	}
	var names []string
	if g := cfg.Executors.GitProxy; g.Enabled && g.AutoTLS() {
		if n, err := hubca.SANsFor(g.AdvertiseURL, g.ListenAddr); err == nil {
			names = append(names, n...)
		}
	}
	if k := cfg.Executors.KubeGuard; k.Enabled && k.AutoTLS() {
		if n, err := hubca.SANsFor(k.AdvertiseURL, k.ListenAddr); err == nil {
			names = append(names, n...)
		}
	}
	out, err := hubca.NormalizeSANs(names)
	if err != nil {
		return names
	}
	return out
}

// checkHubCA reports on a rotation under way, the members taking part in it,
// and the active CA's name constraints.
func checkHubCA(dir string, cfg *config.Config, opts Options, add addFn) {
	store, closeStore, err := openHubTLSStore(dir)
	if errors.Is(err, hubca.ErrNotMinted) {
		return
	}
	if err != nil {
		add(Finding{Check: "hubca.rotation", Title: "Hub CA rotation", Severity: SeverityWarn,
			Message:     "the hub CA could not be read: " + err.Error(),
			Remediation: "See the storage findings; the CA lives in the control-plane database"})
		return
	}
	defer closeStore()
	now := opts.now()
	st, err := hubca.ReadStatus(hubca.Env{Store: store, Options: hubca.Options{Now: func() time.Time { return now }},
		Alive: func(r statedb.HubMemberRow) bool { return hubcluster.RowAlive(r, now) }})
	if err != nil {
		add(Finding{Check: "hubca.rotation", Title: "Hub CA rotation", Severity: SeverityWarn,
			Message:     "where the hub CA's rotation stands could not be read: " + err.Error(),
			Remediation: "Run `cloop hub ca rotate --status` on the hub host"})
		return
	}
	if st.Phase == hubca.PhaseNone {
		return
	}
	checkRotationAge(st, LongestMonitorSession(cfg), now, add)
	checkRotationMembers(st, add)
	checkCANames(st, HubCAConfigNames(cfg), add)
}

func checkRotationAge(st hubca.Status, longest time.Duration, now time.Time, add addFn) {
	const check, title = "hubca.rotation", "Hub CA rotation"
	if longest <= 0 {
		// No monitor issues from the CA now; a session period cannot be the
		// yardstick, and an hour is the default one.
		longest = time.Hour
	}
	details := map[string]any{"phase": string(st.Phase), "running_runs": st.Running,
		"blocking_runs": len(st.Blocking), "longest_session": longest.String()}
	if st.Rotation != nil {
		details["rotation"] = st.Rotation.ID
	}
	switch st.Phase {
	case hubca.PhaseSteady:
		add(Finding{Check: check, Title: title, Severity: SeverityPass,
			Message: fmt.Sprintf("no rotation under way; the hub CA %s is valid until %s", short(st.Active.Serial),
				st.Active.NotAfter.UTC().Format(time.RFC3339)),
			Details: details})
	case hubca.PhaseStaged:
		staged := st.Next.IssuedAt
		if st.Rotation != nil {
			staged = st.Rotation.StagedAt
		}
		age := now.Sub(staged)
		details["staged_at"] = staged.UTC().Format(time.RFC3339)
		if age <= longest {
			add(Finding{Check: check, Title: title, Severity: SeverityPass,
				Message: fmt.Sprintf("hub CA %s staged %s ago: every sandbox dispatched since trusts it; %d run(s) "+
					"dispatched before the stage are still running", short(st.Next.Serial), age.Round(time.Minute),
					len(st.Blocking)),
				Remediation: "When none is left: `cloop hub ca rotate --activate`", Details: details})
			return
		}
		add(Finding{Check: check, Title: title, Severity: SeverityWarn,
			Message: fmt.Sprintf("hub CA %s was staged %s ago, longer than the longest session a monitor grants "+
				"(%s), so the runs the stage waits for should have ended: %s", short(st.Next.Serial),
				age.Round(time.Minute), longest, blockingSummary(st)),
			Remediation: "Activate it (`cloop hub ca rotate --activate`; --force names the runs it breaks), or " +
				"abort it with `--abort`. See " + hubCADocs,
			Details: details})
	case hubca.PhaseActivated:
		activated := time.Time{}
		if st.Rotation != nil {
			activated = st.Rotation.ActivatedAt
		}
		age := now.Sub(activated)
		details["activated_at"] = activated.UTC().Format(time.RFC3339)
		leavesBehind := 0
		for _, l := range st.Leaves {
			if l.Issuer != st.Active.Serial {
				leavesBehind++
			}
		}
		switch {
		case leavesBehind > 0 && age > 2*hubca.ActivationGrace:
			add(Finding{Check: check, Title: title, Severity: SeverityFail,
				Message: fmt.Sprintf("hub CA %s was activated %s ago, and %d monitor certificate(s) still come from "+
					"the previous CA: the cluster leader has not reissued them", short(st.Active.Serial),
					age.Round(time.Minute), leavesBehind),
				Remediation: "Check the hub's log for \"could not be renewed\"; restarting the leader reissues them",
				Details:     details})
		case age > longest:
			add(Finding{Check: check, Title: title, Severity: SeverityWarn,
				Message: fmt.Sprintf("the previous hub CA %s is still trusted %s after hub CA %s was activated: its "+
					"key is still in the database, and every new sandbox is still told to trust it",
					short(st.Previous.Serial), age.Round(time.Minute), short(st.Active.Serial)),
				Remediation: "Retire it: `cloop hub ca rotate --retire-previous`. See " + hubCADocs,
				Details:     details})
		default:
			add(Finding{Check: check, Title: title, Severity: SeverityPass,
				Message: fmt.Sprintf("hub CA %s activated %s ago; the previous one, %s, is trusted until it is retired",
					short(st.Active.Serial), age.Round(time.Minute), short(st.Previous.Serial)),
				Remediation: "Once every member serves the new certificates: `cloop hub ca rotate --retire-previous`",
				Details:     details})
		}
	}
}

func blockingSummary(st hubca.Status) string {
	if len(st.Blocking) == 0 {
		return "none is left, so it can be activated now"
	}
	names := make([]string, 0, len(st.Blocking))
	for i, r := range st.Blocking {
		if i == 5 {
			names = append(names, fmt.Sprintf("and %d more", len(st.Blocking)-5))
			break
		}
		names = append(names, r.Describe())
	}
	return fmt.Sprintf("%d still running — %s", len(st.Blocking), strings.Join(names, "; "))
}

func checkRotationMembers(st hubca.Status, add addFn) {
	var old, behind []string
	for _, m := range st.Members {
		switch {
		case !m.Rotates:
			old = append(old, m.Name()+" ("+orUnknownVersion(m.Version)+")")
		case !m.CaughtUp:
			behind = append(behind, m.Name()+": "+m.Behind)
		}
	}
	const check, title = "hubca.members", "Hub members and the hub CA"
	switch {
	case len(old) > 0:
		sev := SeverityWarn
		if st.Phase != hubca.PhaseSteady {
			sev = SeverityFail
		}
		add(Finding{Check: check, Title: title, Severity: sev,
			Message: fmt.Sprintf("%d live hub member(s) run a build that predates rotating the hub CA: %s — they keep "+
				"signing with the CA they opened at start, so an activation is refused while they run",
				len(old), strings.Join(old, ", ")),
			Remediation: "Upgrade or stop them before activating a rotation"})
	case len(behind) > 0:
		add(Finding{Check: check, Title: title, Severity: SeverityWarn,
			Message: fmt.Sprintf("%d hub member(s) have not caught up with the rotation: %s", len(behind),
				strings.Join(behind, "; ")),
			Remediation: "Members re-read the hub CA every minute; one that stays behind is not refreshing — " +
				"check its log for \"the hub CA could not be refreshed\""})
	case len(st.Members) > 0:
		add(Finding{Check: check, Title: title, Severity: SeverityPass,
			Message: fmt.Sprintf("every live hub member (%d) takes part in rotating the hub CA and has caught up",
				len(st.Members))})
	}
}

func checkCANames(st hubca.Status, want []string, add addFn) {
	if st.Active == nil || len(want) == 0 {
		return
	}
	const check, title = "hubca.names", "Hub CA name constraints"
	if !hubca.Constrained(st.Active.Cert) {
		add(Finding{Check: check, Title: title, Severity: SeverityPass,
			Message: "the hub CA carries no name constraints, so it may vouch for any name — git trusts it for the " +
				"monitors' URLs only, but a harness's Node.js trusts it for every host; the next rotation " +
				"constrains it to the names the monitors are reached at",
			Details: map[string]any{"names": want}})
		return
	}
	_, refused := hubca.Permitted(st.Active.Cert, want)
	if len(refused) == 0 {
		add(Finding{Check: check, Title: title, Severity: SeverityPass,
			Message: "the hub CA's name constraints permit every name the monitors are configured at: " +
				strings.Join(want, ", "),
			Details: map[string]any{"permitted": st.Active.Names}})
		return
	}
	add(Finding{Check: check, Title: title, Severity: SeverityFail,
		Message: fmt.Sprintf("the monitors are configured at %s, which the hub CA's name constraints (%s) do not "+
			"permit: their certificates leave those names out, and a sandbox reaching a monitor there refuses it",
			strings.Join(refused, ", "), strings.Join(st.Active.Names, ", ")),
		Remediation: "An advertise URL that moved to a new host needs a CA that permits it: `cloop hub ca rotate " +
			"--stage --name " + refused[0] + "`, then --activate and --retire-previous. See " + hubCADocs,
		Details: map[string]any{"permitted": st.Active.Names, "refused": refused}})
}

func short(serial string) string {
	if len(serial) > 12 {
		return serial[:12]
	}
	return serial
}

func orUnknownVersion(v string) string {
	if strings.TrimSpace(v) == "" {
		return "unknown build"
	}
	return v
}
