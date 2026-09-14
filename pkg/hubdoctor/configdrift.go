package hubdoctor

// Config drift: does .cloop/config.yaml still say what .cloop/state.db's
// mirror says?
//
// cloop keeps the config twice. The YAML is canonical and human-edited; the
// SQLite copy is what `cloop config set`, the Settings tab and the hub's own
// queries read. They are written together, so they agree — until something
// writes only one of them. An operator editing the file on a running hub, a
// restore that replaced state.db from a backup, a deploy that shipped a new
// config.yaml onto an existing database: each leaves the two disagreeing,
// with no error anywhere, and the hub behaving according to whichever copy the
// code path in question happened to read.
//
// pkg/configdiff has been able to detect this since Task 20109 and `cloop
// config diff` exposes it, but an operator only runs that command once they
// already suspect the config. The command they run when something is wrong and
// they do not know what is `cloop hub doctor` — which is why this belongs
// here, and why its absence meant a whole class of "I changed that setting and
// nothing happened" was invisible to the one tool meant to find it.
//
// Severity is Warn, never Fail. Drift is a discrepancy rather than a breakage:
// the hub runs, and which copy wins is path-dependent rather than uniformly
// wrong. Failing a deployment gate on it would also make `cloop hub doctor`
// red on a hub whose mirror has simply never been written — a fresh install.

import (
	"fmt"
	"strings"

	"github.com/blechschmidt/cloop/pkg/configdiff"
)

// maxDriftPathsListed bounds how many keys a finding names.
//
// A report that names forty keys is a wall an operator scrolls past; the
// count in the message carries the magnitude, and `cloop config diff` prints
// the full list with both values. Six is enough to recognise the change that
// caused the drift.
const maxDriftPathsListed = 6

// checkConfigDrift compares the YAML on disk with the mirror in state.db.
func checkConfigDrift(dir string, add addFn) {
	rep, err := configdiff.Compute(dir)
	if err != nil {
		// Absence is not a pass: a comparison that could not run is reported,
		// because "we did not look" and "we looked and they agree" are
		// different answers to the question being asked.
		add(Finding{
			Check:    "config.drift",
			Title:    "Config drift (yaml vs state.db)",
			Severity: SeverityWarn,
			Message:  fmt.Sprintf("config.yaml and the state.db mirror could not be compared: %v", err),
			Remediation: "Run `cloop config diff` in this directory for the full error; if state.db " +
				"is unreadable, `cloop db verify` diagnoses it",
		})
		return
	}

	if !rep.HasDrift() {
		add(Finding{
			Check:    "config.drift",
			Title:    "Config drift (yaml vs state.db)",
			Severity: SeverityPass,
			Message:  "config.yaml and the state.db mirror agree",
		})
		return
	}

	paths := make([]string, 0, len(rep.Entries))
	for _, e := range rep.Entries {
		// Values are deliberately not rendered. configdiff masks secrets for
		// its own output, but a doctor report is pasted into issue trackers
		// and piped to log collectors far more often than `config diff` is,
		// and a key name is enough to act on.
		paths = append(paths, e.Path)
	}
	listed := paths
	suffix := ""
	if len(listed) > maxDriftPathsListed {
		listed = listed[:maxDriftPathsListed]
		suffix = fmt.Sprintf(" (and %d more)", len(paths)-maxDriftPathsListed)
	}

	msg := rep.Summary()
	if len(listed) > 0 {
		msg += ": " + strings.Join(listed, ", ") + suffix
	}
	add(Finding{
		Check:    "config.drift",
		Title:    "Config drift (yaml vs state.db)",
		Severity: SeverityWarn,
		Message: msg + " — the hub reads one copy in some paths and the other in others, so a " +
			"setting may be in force that the file does not show",
		Remediation: "Run `cloop config diff` to see both values, then `cloop config sync` to make " +
			"the mirror match the file (or `cloop config sync --from-db` when the file is the wrong one)",
		Details: map[string]any{
			"paths":        paths,
			"yaml_present": rep.YAMLPresent,
			"db_present":   rep.DBPresent,
		},
	})
}
