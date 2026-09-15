package hubdoctor

// Retention checks: whether this hub will still have a disk tomorrow
// (Task 20229).
//
// cloop shipped three retention mechanisms and ran none of them unprompted —
// `cloop compact`, `cloop db maintain` and `cloop hub audit prune` are all
// operator-invoked. That is survivable on a laptop and is an outage on a
// hosted hub, because nothing in the product could see the growth coming: the
// dominant consumer, SQLite's freelist, is invisible to `du`, and the second,
// plan history, is thousands of small files nobody thinks to look at.
//
// So these findings answer two questions an operator has no other way to ask:
// is the janitor actually going to run here, and what is the disk doing right
// now. They are deliberately reported even when everything is fine — a hub
// doctor that stays silent about disk until it is too late is the defect this
// package is meant to catch.

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/diskusage"
	"github.com/blechschmidt/cloop/pkg/janitor"
)

// vacuumAdvisoryRatio is the free-page fraction at which the *report* starts
// arguing for a vacuum. It sits below the janitor's own acting threshold so an
// operator whose janitor is disabled still learns the file is mostly holes
// before it becomes urgent.
const vacuumAdvisoryRatio = 0.25

// archiveAdvisoryBytes is the audit-archive size above which the report points
// at the retention settings. Archive retention is opt-in — a seal is the only
// copy of the rows it holds — so the useful thing to do is name the cost and
// let the operator choose, rather than delete on their behalf.
const archiveAdvisoryBytes int64 = 1 << 30 // 1 GiB

func checkRetention(dir string, cfg *config.Config, add addFn) {
	pol := janitor.PolicyFromConfig(cfg)

	if !pol.Enabled {
		add(Finding{
			Check: "retention.janitor", Title: "Retention janitor", Severity: SeverityWarn,
			Message: "disabled: nothing reclaims .cloop on this hub, so it grows until the disk fills",
			Remediation: "Remove `retention.enabled: false` from .cloop/config.yaml, " +
				"or schedule `cloop compact` and `cloop db maintain` externally",
			Details: map[string]any{"enabled": false},
		})
	} else {
		add(Finding{
			Check: "retention.janitor", Title: "Retention janitor", Severity: SeverityPass,
			Message: fmt.Sprintf("every %s: keeping %d plan snapshots, vacuuming above %.0f%% free pages",
				pol.Interval, pol.KeepSnapshots, pol.VacuumFreeRatio*100),
			Details: map[string]any{
				"interval":          pol.Interval.String(),
				"keep_snapshots":    pol.KeepSnapshots,
				"vacuum_free_ratio": pol.VacuumFreeRatio,
			},
		})
	}

	checkRetentionDisk(dir, pol, add)
	checkRetentionTables(dir, pol, add)
}

// checkRetentionTables reports the row tables and names any that the active
// policy does not bound (Task 20291).
//
// The question this answers has no other source. `du` sees one state.db file;
// the freelist finding above sees how much of it is dead; neither can say that
// 14% of the live data is 265 provider-call rows carrying whole LLM prompts,
// which is what a measurement of this hub actually found. And a limit set to
// RetentionKeepEverything is invisible until the table it exempted is the
// reason a disk filled — so an exemption is reported as a warning, with the
// table's current size attached, rather than silently honoured.
func checkRetentionTables(dir string, pol janitor.Policy, add addFn) {
	stats, err := janitor.RowTableStats(dir)
	if err != nil {
		// A project that has never run has no database, which is not a finding.
		if errors.Is(err, os.ErrNotExist) {
			return
		}
		add(Finding{
			Check: "retention.tables", Title: "Row tables", Severity: SeverityWarn,
			Message:     "could not measure the row tables: " + err.Error(),
			Remediation: "Run `cloop db verify` to inspect the database",
		})
		return
	}

	details := map[string]any{}
	var (
		unbounded []string
		rows      int64
		bytes     int64
	)
	for _, s := range stats {
		rows += s.Rows
		bytes += s.Bytes
		details[s.Name] = fmt.Sprintf("%d rows, %s", s.Rows, diskusage.HumanBytes(s.Bytes))
		if !janitor.TableBounded(pol, s.Name) {
			unbounded = append(unbounded, s.Name)
		}
	}

	if len(unbounded) == 0 {
		add(Finding{
			Check: "retention.tables", Title: "Row tables", Severity: SeverityPass,
			Message: fmt.Sprintf("%d rows across %d tables (%s), all bounded by the active policy",
				rows, len(stats), diskusage.HumanBytes(bytes)),
			Details: details,
		})
		return
	}

	details["unbounded"] = unbounded
	sev := SeverityWarn
	remedy := "Set a limit for " + strings.Join(unbounded, ", ") + " under `retention:` in .cloop/config.yaml"
	if !pol.Enabled {
		// The janitor being off is already reported above as its own warning;
		// repeating it per table would bury that finding under this one.
		remedy = "Re-enable the retention janitor, or bound these tables externally"
	}
	add(Finding{
		Check: "retention.tables", Title: "Row tables", Severity: sev,
		Message: fmt.Sprintf("%d rows across %d tables (%s); %s not bounded by the active policy",
			rows, len(stats), diskusage.HumanBytes(bytes), strings.Join(unbounded, ", ")),
		Remediation: remedy,
		Details:     details,
	})
}

// checkRetentionDisk reports the measured .cloop breakdown and the reclaimable
// page estimate.
func checkRetentionDisk(dir string, pol janitor.Policy, add addFn) {
	usage, err := diskusage.Measure(dir)
	if err != nil {
		add(Finding{
			Check: "retention.disk", Title: "Disk usage", Severity: SeverityWarn,
			Message:     "could not measure .cloop: " + err.Error(),
			Remediation: "Check that " + filepath.Join(dir, ".cloop") + " is readable by the hub's user",
		})
		return
	}

	details := map[string]any{"total": diskusage.HumanBytes(usage.TotalBytes)}
	for _, e := range usage.Entries {
		// Only the entries big enough to matter; the total covers the rest.
		if e.Bytes < 10<<20 {
			break // Entries is sorted largest-first
		}
		details[e.Name] = diskusage.HumanBytes(e.Bytes)
	}
	add(Finding{
		Check: "retention.disk", Title: "Disk usage", Severity: SeverityPass,
		Message: fmt.Sprintf(".cloop uses %s across %d entries", diskusage.HumanBytes(usage.TotalBytes), len(usage.Entries)),
		Details: details,
	})

	// The freelist: the part no filesystem tool reports. On the hub that
	// motivated this package, 87% of a 2.3 GB state.db was free pages.
	switch {
	case usage.DBError != "":
		add(Finding{
			Check: "retention.freelist", Title: "Reclaimable pages", Severity: SeverityWarn,
			Message:     "could not read database page statistics: " + usage.DBError,
			Remediation: "Run `cloop db verify` to inspect the database",
		})
	case usage.DBBytes == 0:
		add(Finding{
			Check: "retention.freelist", Title: "Reclaimable pages", Severity: SeverityPass,
			Message: "no state.db yet",
		})
	case usage.FreeRatio >= vacuumAdvisoryRatio:
		sev := SeverityWarn
		remedy := "Run `cloop db maintain` to reclaim it now"
		// A janitor that will act on its own turns this from a problem into
		// a scheduled one. Say which, rather than telling an operator to run
		// a command that is about to run itself.
		if pol.Enabled && usage.FreeRatio >= pol.VacuumFreeRatio && usage.ReclaimableBytes >= pol.VacuumMinFreeBytes {
			sev = SeverityPass
			remedy = ""
		}
		add(Finding{
			Check: "retention.freelist", Title: "Reclaimable pages", Severity: sev,
			Message: fmt.Sprintf("%s of state.db's %s is free pages (%.0f%%), reclaimable by VACUUM",
				diskusage.HumanBytes(usage.ReclaimableBytes), diskusage.HumanBytes(usage.DBBytes), usage.FreeRatio*100),
			Remediation: remedy,
			Details: map[string]any{
				"reclaimable": diskusage.HumanBytes(usage.ReclaimableBytes),
				"free_ratio":  fmt.Sprintf("%.2f", usage.FreeRatio),
			},
		})
	default:
		add(Finding{
			Check: "retention.freelist", Title: "Reclaimable pages", Severity: SeverityPass,
			Message: fmt.Sprintf("%s free pages in a %s database (%.0f%%)",
				diskusage.HumanBytes(usage.ReclaimableBytes), diskusage.HumanBytes(usage.DBBytes), usage.FreeRatio*100),
		})
	}

	checkRetentionArchive(usage, pol, add)
	checkRetentionHistory(dir, usage, pol, add)
}

// checkRetentionArchive reports the sealed audit exports, whose retention is
// off by default and therefore the one directory that can still grow without
// bound on a fully-configured hub.
func checkRetentionArchive(usage *diskusage.Usage, pol janitor.Policy, add addFn) {
	e, ok := usage.Entry("audit-archive")
	if !ok || e.Bytes == 0 {
		return
	}
	bounded := pol.ArchiveMaxBytes > 0 || pol.ArchiveMaxAgeDays > 0
	if bounded || e.Bytes < archiveAdvisoryBytes {
		add(Finding{
			Check: "retention.archive", Title: "Audit archive", Severity: SeverityPass,
			Message: fmt.Sprintf("%s in %d seal(s)%s", diskusage.HumanBytes(e.Bytes), e.Files, archiveBoundNote(pol)),
		})
		return
	}
	add(Finding{
		Check: "retention.archive", Title: "Audit archive", Severity: SeverityWarn,
		Message: fmt.Sprintf("%s in %d seal(s) with no retention limit set", diskusage.HumanBytes(e.Bytes), e.Files),
		Remediation: "Copy the seals to durable storage, then set retention.archive_max_mb " +
			"or retention.archive_max_age_days — each seal is the only remaining copy of the audit rows it holds",
		Details: map[string]any{"bytes": e.Bytes, "seals": e.Files},
	})
}

func archiveBoundNote(pol janitor.Policy) string {
	switch {
	case pol.ArchiveMaxBytes > 0 && pol.ArchiveMaxAgeDays > 0:
		return fmt.Sprintf(", capped at %s and %d days", diskusage.HumanBytes(pol.ArchiveMaxBytes), pol.ArchiveMaxAgeDays)
	case pol.ArchiveMaxBytes > 0:
		return fmt.Sprintf(", capped at %s", diskusage.HumanBytes(pol.ArchiveMaxBytes))
	case pol.ArchiveMaxAgeDays > 0:
		return fmt.Sprintf(", capped at %d days", pol.ArchiveMaxAgeDays)
	default:
		return ""
	}
}

// checkRetentionHistory reports plan-history against its keep-count, and when
// the last janitor pass ran.
func checkRetentionHistory(dir string, usage *diskusage.Usage, pol janitor.Policy, add addFn) {
	e, ok := usage.Entry("plan-history")
	if !ok {
		return
	}
	msg := fmt.Sprintf("%s in %d snapshot(s)", diskusage.HumanBytes(e.Bytes), e.Files)
	// A file count far past the keep-count means the write-time bound is not
	// being applied by whatever is writing here — an older binary, or a
	// backlog no pass has caught up with yet.
	if pol.KeepSnapshots > 0 && e.Files > pol.KeepSnapshots*2 {
		add(Finding{
			Check: "retention.history", Title: "Plan history", Severity: SeverityWarn,
			Message: msg + fmt.Sprintf(", well past the keep-count of %d", pol.KeepSnapshots),
			Remediation: "The next janitor pass reclaims this; to do it now run " +
				"`cloop compact --keep-snapshots " + fmt.Sprint(pol.KeepSnapshots) + "`",
			Details: map[string]any{"snapshots": e.Files, "keep": pol.KeepSnapshots},
		})
	} else {
		add(Finding{
			Check: "retention.history", Title: "Plan history", Severity: SeverityPass,
			Message: msg,
		})
	}

	// Absent simply means no pass has completed yet, which is not itself a
	// finding — the janitor's own status above already says whether one is
	// coming.
	if ts, ok := janitor.LastRun(dir); ok {
		add(Finding{
			Check: "retention.last_run", Title: "Last retention pass", Severity: SeverityPass,
			Message: fmt.Sprintf("%s ago", time.Since(ts).Round(time.Minute)),
		})
	}
}
