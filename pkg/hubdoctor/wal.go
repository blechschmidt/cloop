package hubdoctor

// The write-ahead log check (Task 20392): statedb.wal.
//
// state.db-wal is the working space every write to the database passes
// through on its way in. A hub in steady state keeps it to a few megabytes,
// but SQLite never shrinks the file on its own: a burst — a bulk delete by row
// retention or an audit prune, a VACUUM, which writes the whole database
// through it — leaves the log at that size for as long as the database stays
// open, which for a hub is forever. On 2026-10-06 the hub this code runs on
// had a 340 MB log beside a 409 MB database, on a disk 98% full. Nothing `du`
// or the freelist findings report says whether that space is coming back;
// this does.
//
// Read-write connections now trim the log to statedb.JournalSizeLimitBytes
// when they start it over, and the hub's leader truncates it while it is
// larger — so a log well past that size is one something is holding: a reader
// that never finishes, or writers that all predate the limit.

import (
	"fmt"
	"os"

	"github.com/blechschmidt/cloop/pkg/diskusage"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// walSample is the log as Run found it.
//
// It is measured before any check opens the database, because the last
// connection to close a WAL database deletes the log: against a hub that is
// not running, the doctor's own checks would remove the very file this one
// is about, and it would report a log nobody else would ever see.
type walSample struct {
	present  bool // a state.db exists
	dbBytes  int64
	walBytes int64
	err      error
}

func sampleWAL(dir string) walSample {
	dbPath := state.DBPath(dir)
	fi, err := os.Stat(dbPath)
	if err != nil {
		return walSample{} // no database: checkStorage says so
	}
	n, err := statedb.WALSize(dbPath)
	return walSample{present: true, dbBytes: fi.Size(), walBytes: n, err: err}
}

// walWarnAbove is the size past which a log is reported: the larger of the
// size connections trim it to and a quarter of the database. The quarter is
// for a large database, whose ordinary bursts are larger too; the floor is so
// a small one is not warned about a log every write keeps.
func walWarnAbove(dbBytes int64) int64 {
	if q := dbBytes / 4; q > statedb.JournalSizeLimitBytes {
		return q
	}
	return statedb.JournalSizeLimitBytes
}

func checkWAL(s walSample, add addFn) {
	if !s.present {
		return
	}
	if s.err != nil {
		add(Finding{
			Check: "statedb.wal", Title: "Write-ahead log", Severity: SeverityWarn,
			Message:     "could not measure state.db-wal: " + s.err.Error(),
			Remediation: "Check that .cloop/state.db-wal is readable by the hub's user",
		})
		return
	}
	above := walWarnAbove(s.dbBytes)
	details := map[string]any{
		"wal_bytes":        s.walBytes,
		"db_bytes":         s.dbBytes,
		"warn_above_bytes": above,
	}
	rule := fmt.Sprintf("the larger of %s and a quarter of the %s database",
		diskusage.HumanBytes(statedb.JournalSizeLimitBytes), diskusage.HumanBytes(s.dbBytes))
	if s.walBytes <= above {
		add(Finding{
			Check: "statedb.wal", Title: "Write-ahead log", Severity: SeverityPass,
			Message: fmt.Sprintf("state.db-wal is %s; warned about above %s (%s)",
				diskusage.HumanBytes(s.walBytes), diskusage.HumanBytes(above), rule),
			Details: details,
		})
		return
	}
	add(Finding{
		Check: "statedb.wal", Title: "Write-ahead log", Severity: SeverityWarn,
		Message: fmt.Sprintf("state.db-wal is %s, over the %s it should stay under (%s); "+
			"SQLite keeps a log at its largest burst until something truncates it",
			diskusage.HumanBytes(s.walBytes), diskusage.HumanBytes(above), rule),
		Remediation: fmt.Sprintf("A running hub's leader truncates it within a minute of finding it over %s "+
			"unless a connection is still reading from it, and logs \"write-ahead log is … over the limit\" while "+
			"one is; `fuser -v .cloop/state.db-wal` lists the processes holding it, and builds that predate the "+
			"limit never trim it. `cloop hub retention --apply` truncates it now, beside a running hub or not",
			diskusage.HumanBytes(statedb.JournalSizeLimitBytes)),
		Details: details,
	})
}
