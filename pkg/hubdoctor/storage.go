package hubdoctor

// Storage checks: the one durable thing a hub owns.
//
// Everything else in a cloop deployment is reconstructible — executors
// re-enroll, sessions re-authenticate, config is a file in a repo. state.db is
// not: it holds the sealed credentials, the enrolled fleet, the audit chain and
// every project's plan. So the two questions here are whether it is intact, and
// whether this binary's schema and the database's agree.
//
// The version comparison is the check that only exists in a hosted world. On a
// developer's laptop the binary and the database always advance together. In a
// deployment they are separate artifacts, and a rolled-back image meets a schema
// a newer one wrote.
//
// pkg/statedb now refuses that combination outright (Task 20226), so this check
// has become a pre-flight rather than the only line of defence: it answers "will
// the hub start" before the operator finds out by starting it, and names the
// build that moved the schema so the answer points at an image tag. That is also
// why it opens the database with the guard explicitly off — a diagnostic that
// cannot read the broken thing has nothing to report about it.

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/blechschmidt/cloop/pkg/dbverify"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

func checkStorage(dir string, add addFn) {
	dbPath := filepath.Join(dir, ".cloop", "state.db")
	if _, err := os.Stat(dbPath); os.IsNotExist(err) {
		add(Finding{
			Check: "storage.database", Title: "State database", Severity: SeverityWarn,
			Message: "no .cloop/state.db yet; it is created on first start, so nothing could be verified",
			Remediation: "Start the hub once (`cloop ui`) or run `cloop hub bootstrap` in this directory, " +
				"then re-run",
		})
		return
	}

	// quick_check rather than the full integrity_check: this is a
	// pre-flight, and the thorough variant on a large database takes long
	// enough that operators skip running it at all. `cloop db verify` is the
	// escalation.
	rep, err := dbverify.Verify(dbPath, true)
	switch {
	case err != nil:
		add(Finding{
			Check: "storage.integrity", Title: "Database integrity", Severity: SeverityFail,
			Message:     fmt.Sprintf("quick_check could not run: %v", err),
			Remediation: "Check file permissions on .cloop/state.db, then run `cloop db verify`",
		})
	case !rep.OK():
		var detail string
		if n := len(rep.IntegrityIssues); n > 0 {
			detail = fmt.Sprintf("%d integrity issue(s): %s", n, rep.IntegrityIssues[0])
		}
		if n := len(rep.ForeignKeyViolations); n > 0 {
			if detail != "" {
				detail += "; "
			}
			detail += fmt.Sprintf("%d foreign-key violation(s)", n)
		}
		add(Finding{
			Check: "storage.integrity", Title: "Database integrity", Severity: SeverityFail,
			Message:     detail,
			Remediation: "Run `cloop db verify` for the full report, then restore from `cloop snapshot`",
		})
	default:
		add(Finding{
			Check: "storage.integrity", Title: "Database integrity", Severity: SeverityPass,
			Message: "quick_check and foreign_key_check both passed",
		})
	}

	checkSchemaVersion(dbPath, add)
}

// checkSchemaVersion compares what is applied against what this binary carries.
func checkSchemaVersion(dbPath string, add addFn) {
	latest, err := statedb.LatestSchemaVersion()
	if err != nil {
		// A packaging bug, not a deployment one — the embedded migrations
		// did not load. Worth reporting because everything downstream of it
		// is unreliable.
		add(Finding{
			Check: "storage.schema", Title: "Schema version", Severity: SeverityFail,
			Message:     "this binary's embedded migrations could not be read: " + err.Error(),
			Remediation: "Reinstall cloop; the build is missing its migrations",
		})
		return
	}

	// Deliberately opted out of the version-skew guard. A hub refuses to open
	// a database newer than itself, which is the whole point of the guard —
	// but a diagnostic that cannot open the broken thing cannot diagnose it,
	// and "could not open .cloop/state.db" is exactly the uninformative answer
	// this check exists to replace. Reading it is safe: nothing here writes,
	// and the two version numbers live in schema_migrations, whose shape has
	// not changed since 0001.
	db, err := statedb.OpenWithOptions(dbPath, statedb.OpenOptions{AllowSchemaDowngrade: true})
	if err != nil {
		add(Finding{
			Check: "storage.schema", Title: "Schema version", Severity: SeverityFail,
			Message:     fmt.Sprintf("could not open %s: %v", dbPath, err),
			Remediation: "Check permissions and that no other process holds an exclusive lock",
		})
		return
	}
	defer func() { _ = db.Close() }()

	current, err := db.CurrentSchemaVersion()
	if err != nil {
		add(Finding{
			Check: "storage.schema", Title: "Schema version", Severity: SeverityFail,
			Message:     "could not read the applied schema version: " + err.Error(),
			Remediation: "Run `cloop db verify`; the schema_migrations table may be damaged",
		})
		return
	}

	switch {
	case current == latest:
		add(Finding{
			Check: "storage.schema", Title: "Schema version", Severity: SeverityPass,
			Message: fmt.Sprintf("at version %d, matching this binary", current),
		})
	case current < latest:
		// Opening the database ran Migrate, so reaching here means a
		// migration did not apply rather than that one is merely pending.
		add(Finding{
			Check: "storage.schema", Title: "Schema version", Severity: SeverityFail,
			Message: fmt.Sprintf("database is at version %d but this binary carries %d, and opening it "+
				"did not close the gap", current, latest),
			Remediation: "Run `cloop migrate` and read the error it reports",
		})
	default:
		// What happens next depends on whether the guard is suppressed, and
		// saying "this build will not open it" to an operator who has already
		// set the opt-out would be simply wrong.
		consequence := "and this build will refuse to open it"
		remediation := "Roll forward to that cloop version, or restore a backup taken before the " +
			"upgrade (`cloop db restore`). If the schemas are known-compatible, set " +
			statedb.EnvAllowSchemaDowngrade + "=1 to start anyway"
		if statedb.AllowSchemaDowngradeFromEnv() {
			consequence = "and this build opens it only because " +
				statedb.EnvAllowSchemaDowngrade + " is set"
			remediation = "Roll forward to that cloop version, or restore a backup taken before the " +
				"upgrade (`cloop db restore`), then unset " + statedb.EnvAllowSchemaDowngrade
		}
		add(Finding{
			Check: "storage.schema", Title: "Schema version", Severity: SeverityFail,
			Message: fmt.Sprintf("database is at version %d, ahead of this binary's %d: it was written "+
				"by a newer cloop%s, %s", current, latest, appliedByClause(db), consequence),
			Remediation: remediation,
			Details:     map[string]any{"db_version": current, "binary_version": latest},
		})
	}

	checkSchemaGuard(current, latest, add)
}

// appliedByClause names the build that applied the database's current schema
// version, so the finding points at an image tag rather than only a number.
// Returns "" when the database records nothing useful — provenance is a
// convenience, and its absence must not cost the rest of the message.
func appliedByClause(db *statedb.DB) string {
	stamp, err := db.SchemaStamp()
	if err != nil || stamp.AppliedBy == "" {
		return ""
	}
	out := " (cloop " + stamp.AppliedBy
	if !stamp.AppliedAt.IsZero() {
		out += ", " + stamp.AppliedAt.UTC().Format(time.RFC3339)
	}
	return out + ")"
}

// checkSchemaGuard reports the version-skew guard being switched off.
//
// The opt-out exists because not every schema bump touches a table an older
// binary reads, and an operator who has checked should not have to restore a
// backup to get back to a known-good build. But an exemption nobody can see is
// an exemption that outlives its reason: it ends up in a Deployment manifest,
// survives three upgrades, and is still there the day it stops being true. So
// the off state is itself a finding — a warning when the schemas do agree, a
// failure when the thing it is suppressing is actually present.
func checkSchemaGuard(current, latest int, add addFn) {
	if !statedb.AllowSchemaDowngradeFromEnv() {
		return
	}
	f := Finding{
		Check: "storage.schema_guard", Title: "Schema version guard", Severity: SeverityWarn,
		Message: statedb.EnvAllowSchemaDowngrade + " is set: this hub will open a database " +
			"migrated by a newer cloop instead of refusing it",
		Remediation: "Unset " + statedb.EnvAllowSchemaDowngrade + " once the rollback that needed it is over",
	}
	if current > latest {
		f.Severity = SeverityFail
		f.Message = fmt.Sprintf("%s is set and the database is at version %d against this binary's %d: "+
			"the hub is running on a schema it does not fully know",
			statedb.EnvAllowSchemaDowngrade, current, latest)
		f.Remediation = "Roll forward to the cloop that wrote this schema, or restore a backup taken " +
			"before the upgrade (`cloop db restore`), then unset " + statedb.EnvAllowSchemaDowngrade
	}
	add(f)
}
