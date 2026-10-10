package hubdoctor

// Audit trail checks: whether the trail is complete, and whether anything
// outside the database would notice it being shortened (Task 20404).
//
// A hash chain proves what it holds and nothing about what it lacks. Two kinds
// of lack matter. Events whose append failed are recorded in the chain as
// audit.gap rows once the database takes writes again — until then they are
// only in the failing process's memory and in the status file it keeps, which
// is what these checks read. And rows deleted from the newest end leave a
// shorter chain that verifies; only a checkpoint written off the database can
// tell, so these checks also ask whether checkpoints are written, where,
// whether they are signed, whether they are fresh, and whether the newest still
// agree with the chain.

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/auditcheckpoint"
	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// auditCheckpointsVerified bounds how many of the newest control-plane
// checkpoints the doctor checks against the chain; `cloop hub audit verify
// --checkpoints` checks them all.
const auditCheckpointsVerified = 50

func checkAuditTrail(dir string, cfg *config.Config, opts Options, add addFn) {
	checkAuditUnrecorded(dir, add)
	db := openAuditDB(dir, add)
	if db != nil {
		defer db.Close()
		checkAuditGaps(db, add)
	}
	checkAuditCheckpoints(dir, cfg, db, opts, add)
}

// openAuditDB opens the control plane's database, or reports why it did not.
func openAuditDB(dir string, add addFn) *statedb.DB {
	path := state.DBPath(dir)
	if _, err := os.Stat(path); err != nil {
		return nil // checkStorage reports a missing database
	}
	db, err := statedb.Open(path)
	if err != nil {
		add(Finding{
			Check: "audit.gaps", Title: "Audit trail completeness", Severity: SeverityWarn,
			Message:     "could not open the control-plane database to read the audit trail: " + err.Error(),
			Remediation: "Run `cloop db verify` and fix what it reports",
		})
		return nil
	}
	return db
}

// checkAuditGaps reports the gaps the control-plane chain records.
func checkAuditGaps(db *statedb.DB, add addFn) {
	sum, err := db.AuditGapSummary()
	if err != nil {
		add(Finding{
			Check: "audit.gaps", Title: "Audit trail completeness", Severity: SeverityWarn,
			Message:     "could not read the audit trail's gap rows: " + err.Error(),
			Remediation: "Run `cloop hub audit verify` and fix what it reports",
		})
		return
	}
	if sum.Gaps == 0 {
		add(Finding{
			Check: "audit.gaps", Title: "Audit trail completeness", Severity: SeverityPass,
			Message: "the control-plane chain records no lost audit events",
		})
		return
	}
	lower := ""
	if sum.Truncated {
		lower = " at least"
	}
	add(Finding{
		Check: "audit.gaps", Title: "Audit trail completeness", Severity: SeverityWarn,
		Message: fmt.Sprintf("the control-plane chain holds %d audit.gap row(s) recording%s %d event(s) that could "+
			"not be appended — the newest written %s", sum.Gaps, lower, sum.Events, sum.LastAt.UTC().Format(time.RFC3339)),
		Remediation: "Read them with `cloop hub audit list --type audit.gap` (each names the actions lost and why), " +
			"fix the cause — a full disk, a read-only file, a lock — then `cloop hub audit verify --allow-gaps`",
		Details: map[string]any{"gaps": sum.Gaps, "events": sum.Events, "last_gap_id": sum.LastID},
	})
}

// checkAuditUnrecorded reports losses a hub process holds in memory and has
// not yet written into their chain, from the status files under .cloop.
func checkAuditUnrecorded(dir string, add addFn) {
	statuses, err := statedb.ReadAuditFailureStatus(statedb.AuditFailureStatusDir(dir))
	if err != nil {
		add(Finding{
			Check: "audit.unrecorded", Title: "Unrecorded audit losses", Severity: SeverityWarn,
			Message:     "could not read " + statedb.AuditFailureStatusDir(dir) + ": " + err.Error(),
			Remediation: "Check the directory's permissions",
		})
		return
	}
	found := false
	for _, st := range statuses {
		running := st.ProcessRunning()
		unadoptable := strings.HasPrefix(filepath.Base(st.File), "unadoptable-")
		for _, c := range st.Chains {
			u := c.Unrecorded
			if u.Empty() {
				continue
			}
			found = true
			if unadoptable {
				add(Finding{
					Check: "audit.unrecorded", Title: "Unrecorded audit losses", Severity: SeverityWarn,
					Message: fmt.Sprintf("process %d lost %d audit event(s) for %s that no hub could record: the "+
						"database is gone, or could not be confirmed as cloop's (kept in %s)",
						st.PID, u.Events, c.Path, st.File),
					Remediation: "Restore the database if it moved; once the loss is accounted for, delete the file",
					Details:     map[string]any{"pid": st.PID, "path": c.Path, "events": u.Events, "file": st.File},
				})
				continue
			}
			if running {
				add(Finding{
					Check: "audit.unrecorded", Title: "Unrecorded audit losses", Severity: SeverityWarn,
					Message: fmt.Sprintf("hub process %d on %s could not append %d audit event(s) to %s since %s "+
						"and has not recorded them in the chain yet (last error: %s)",
						st.PID, st.Host, u.Events, c.Path, u.FirstAt.UTC().Format(time.RFC3339), u.LastError),
					Remediation: "Fix what stops the database taking writes (free its disk, fix its permissions); " +
						"the hub writes an audit.gap row recording them as soon as an append succeeds",
					Details: map[string]any{"pid": st.PID, "path": c.Path, "events": u.Events, "actions": u.Actions},
				})
				continue
			}
			add(Finding{
				Check: "audit.unrecorded", Title: "Unrecorded audit losses", Severity: SeverityWarn,
				Message: fmt.Sprintf("process %d on %s exited with %d audit event(s) for %s it never recorded "+
					"(lost between %s and %s)", st.PID, st.Host, u.Events, c.Path,
					u.FirstAt.UTC().Format(time.RFC3339), u.LastAt.UTC().Format(time.RFC3339)),
				Remediation: "Start the hub here: it adopts the losses and records them in the chain as an audit.gap row",
				Details:     map[string]any{"pid": st.PID, "path": c.Path, "events": u.Events, "file": st.File},
			})
		}
	}
	if !found {
		add(Finding{
			Check: "audit.unrecorded", Title: "Unrecorded audit losses", Severity: SeverityPass,
			Message: "no hub process reports audit events it failed to append and has not recorded",
		})
	}
}

// checkAuditCheckpoints reports where the audit head checkpoints go, whether
// they are signed, and whether the newest still agree with the chain.
func checkAuditCheckpoints(dir string, cfg *config.Config, db *statedb.DB, opts Options, add addFn) {
	cp := cfg.Audit.Checkpoints
	if !cp.Enabled() {
		add(Finding{
			Check: "audit.checkpoints", Title: "Audit head checkpoints", Severity: SeverityWarn,
			Message: "off: deleting the newest audit rows leaves a shorter chain that verifies, " +
				"and nothing outside the database records how long it was",
			Remediation: "Set audit.checkpoints.file to a path outside .cloop/ on storage the database does not " +
				"share, or remove `audit.checkpoints.stderr: false`",
		})
		return
	}

	key, kerr := auditcheckpoint.KeyFromEnv()
	if kerr != nil {
		key = nil
		add(Finding{
			Check: "audit.checkpoints.signed", Title: "Audit checkpoint seals", Severity: SeverityWarn,
			Message: "checkpoints are written unsigned: there is no " + auditcheckpoint.EnvKey + ", so anyone " +
				"who can write where they are kept can write a record agreeing with a truncated chain",
			Remediation: "Export " + auditcheckpoint.EnvKey + " from .cloop/hub.env (`cloop hub bootstrap` writes it) " +
				"and restart the hub",
		})
	} else {
		add(Finding{
			Check: "audit.checkpoints.signed", Title: "Audit checkpoint seals", Severity: SeverityPass,
			Message: "checkpoints are sealed under the key " + auditcheckpoint.EnvKey + " derives (fingerprint " +
				key.Fingerprint() + ")",
		})
	}

	interval := cp.EffectiveInterval()
	if cp.File == "" {
		add(Finding{
			Check: "audit.checkpoints", Title: "Audit head checkpoints", Severity: SeverityWarn,
			Message: fmt.Sprintf("every %s, to stderr only: they pin the trail only if a log pipeline ships this "+
				"hub's stderr off the machine", interval),
			Remediation: "Also set audit.checkpoints.file to a path on storage the database does not share, " +
				"unless this hub's stderr already leaves the machine",
		})
		return
	}
	if err := auditcheckpoint.CheckFile(cp.File); err != nil {
		add(Finding{
			Check: "audit.checkpoints", Title: "Audit head checkpoints", Severity: SeverityFail,
			Message:     "audit.checkpoints.file cannot hold checkpoints: " + err.Error(),
			Remediation: "Point audit.checkpoints.file at an existing directory outside every .cloop/ directory",
		})
		return
	}

	parsed, err := auditcheckpoint.ReadFile(cp.File)
	if os.IsNotExist(err) {
		add(Finding{
			Check: "audit.checkpoints", Title: "Audit head checkpoints", Severity: SeverityWarn,
			Message:     fmt.Sprintf("every %s to %s, which has no checkpoint yet", interval, cp.File),
			Remediation: "Start the hub; the cluster leader writes the first checkpoint within one interval",
		})
		return
	}
	if err != nil {
		add(Finding{
			Check: "audit.checkpoints", Title: "Audit head checkpoints", Severity: SeverityFail,
			Message:     "could not read " + cp.File + ": " + err.Error(),
			Remediation: "Check the file's permissions; the hub appends to it as the user it runs as",
		})
		return
	}

	cpPath := state.DBPath(dir)
	all := auditcheckpoint.ByPath(parsed.Records)[auditcheckpoint.ValidPath(cleanAbs(cpPath))]
	// Only records that may vouch decide freshness and which are checked: a
	// record anybody appended, or one dated in the future, could otherwise
	// keep this green over a truncated chain.
	recs := auditcheckpoint.Usable(all, key, opts.now())
	age, ok := auditcheckpoint.Age(recs, opts.now())
	switch {
	case !ok:
		msg := fmt.Sprintf("%s holds %d checkpoint(s), none of them for this hub's control plane (%s)",
			cp.File, len(parsed.Records), cpPath)
		if len(all) > 0 {
			msg = fmt.Sprintf("%s holds %d checkpoint(s) for this hub's control plane and none that vouches: "+
				"none sealed under the key %s derives, or every one dated in the future",
				cp.File, len(all), auditcheckpoint.EnvKey)
		}
		add(Finding{
			Check: "audit.checkpoints", Title: "Audit head checkpoints", Severity: SeverityWarn,
			Message:     msg,
			Remediation: "Start the hub here with this CLOOP_SECRET_KEY; or point audit.checkpoints.file at this hub's own file",
		})
		return
	case age > 3*interval:
		add(Finding{
			Check: "audit.checkpoints", Title: "Audit head checkpoints", Severity: SeverityWarn,
			Message: fmt.Sprintf("the newest control-plane checkpoint in %s is %s old, and one is due every %s: "+
				"the hub is not running, is not the cluster leader's, or cannot write the file — "+
				"or newer records were deleted from it", cp.File, age.Round(time.Second), interval),
			Remediation: "Check the hub is running and its stderr for `could not write audit checkpoints`",
			Details:     map[string]any{"age_seconds": int(age.Seconds())},
		})
	default:
		add(Finding{
			Check: "audit.checkpoints", Title: "Audit head checkpoints", Severity: SeverityPass,
			Message: fmt.Sprintf("every %s to %s; the newest control-plane checkpoint is %s old",
				interval, cp.File, age.Round(time.Second)),
			Details: auditWindowDetails(db),
		})
	}
	if len(parsed.Malformed) > 0 {
		add(Finding{
			Check: "audit.checkpoints.file", Title: "Audit checkpoint file", Severity: SeverityWarn,
			Message: fmt.Sprintf("%d line(s) of %s name a checkpoint and do not decode (first: line %d)",
				len(parsed.Malformed), cp.File, parsed.Malformed[0]),
			Remediation: "A torn write after a crash is harmless; anything else is an edit — run " +
				"`cloop hub audit verify --checkpoints " + cp.File + "`",
		})
	}
	if db == nil || len(recs) == 0 {
		return
	}
	if len(recs) > auditCheckpointsVerified {
		recs = recs[len(recs)-auditCheckpointsVerified:]
	}
	rep, err := auditcheckpoint.VerifyChain(db, cpPath, auditcheckpoint.ChainControlPlane, recs, key)
	if err != nil {
		add(Finding{
			Check: "audit.checkpoints.chain", Title: "Audit chain against its checkpoints", Severity: SeverityWarn,
			Message:     "could not check the chain against its checkpoints: " + err.Error(),
			Remediation: "Run `cloop hub audit verify --checkpoints " + cp.File + "`",
		})
		return
	}
	if !rep.OK() {
		msg := rep.Finding
		if rep.Hint != "" {
			msg += " — or " + rep.Hint
		}
		add(Finding{
			Check: "audit.checkpoints.chain", Title: "Audit chain against its checkpoints", Severity: SeverityFail,
			Message:     msg,
			Remediation: "Treat it as an incident: run `cloop hub audit verify --checkpoints " + cp.File + "` for every finding",
			Details:     map[string]any{"failures": len(rep.Failures), "checked": rep.Records},
		})
		return
	}
	var notes []string
	if rep.ForeignKey > 0 {
		notes = append(notes, fmt.Sprintf("%d sealed under another key", rep.ForeignKey))
	}
	if rep.Unsigned > 0 {
		notes = append(notes, fmt.Sprintf("%d unsigned", rep.Unsigned))
	}
	msg := fmt.Sprintf("the newest %d control-plane checkpoint(s) agree with the chain", rep.Records)
	if len(notes) > 0 {
		msg += " (" + strings.Join(notes, ", ") + ")"
	}
	add(Finding{
		Check: "audit.checkpoints.chain", Title: "Audit chain against its checkpoints", Severity: SeverityPass,
		Message: msg,
	})
}

// cleanAbs is path made absolute and clean, the form checkpoint records name
// databases by.
func cleanAbs(path string) string {
	if abs, err := filepath.Abs(path); err == nil {
		return abs
	}
	return filepath.Clean(path)
}

// auditWindowDetails reports the shared window marker: which window was last
// claimed, by which member, and whether it was written.
func auditWindowDetails(db *statedb.DB) map[string]any {
	if db == nil {
		return nil
	}
	m, ok, err := db.AuditCheckpointWindowMarker()
	if err != nil || !ok {
		return nil
	}
	return map[string]any{"window": m.Window, "member": m.Member, "claimed_at": m.ClaimedAt, "written": m.Done}
}
