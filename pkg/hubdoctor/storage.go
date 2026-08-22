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
// deployment they are separate artifacts: a rolled-back image runs against a
// schema written by a newer one and fails on whichever column it does not know
// about, at whatever moment first touches it — which is exactly the kind of
// failure a rollback is supposed to prevent.

import (
	"fmt"
	"os"
	"path/filepath"

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

	db, err := statedb.Open(dbPath)
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
		add(Finding{
			Check: "storage.schema", Title: "Schema version", Severity: SeverityFail,
			Message: fmt.Sprintf("database is at version %d, ahead of this binary's %d: it was written "+
				"by a newer cloop and this one will fail on columns it does not know about",
				current, latest),
			Remediation: "Roll forward to the newer cloop version, or restore a snapshot taken before the upgrade",
		})
	}
}
