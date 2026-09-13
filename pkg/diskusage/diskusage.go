// Package diskusage measures what a project's .cloop directory actually costs
// on disk, broken down by the thing that produced it (Task 20229).
//
// It exists because "the hub filled its disk" is an availability defect that
// nothing in cloop could previously see coming. `cloop doctor` reported one
// aggregate number for .cloop and a separate one for state.db, which is not
// enough to act on: an operator looking at "4.9 GB" cannot tell whether to
// vacuum the database, prune plan history, or ship audit archives to cold
// storage, and those have very different costs. The per-entry breakdown names
// the culprit.
//
// The database gets a second number the filesystem cannot provide. A SQLite
// file does not shrink when rows are deleted; the pages move to a freelist and
// are reused for future writes. On this repository's own hub, state.db was
// 2.3 GB on disk of which 87% was freelist — reclaimable by a VACUUM, and
// invisible to du. ReclaimableBytes reports that, so the difference between
// "this database holds 2.3 GB of data" and "this database holds 300 MB of data
// in a 2.3 GB file" is legible before the disk fills rather than after.
package diskusage

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"syscall"

	"github.com/blechschmidt/cloop/pkg/statedb"
)

// Entry is one top-level member of .cloop — a subdirectory such as
// plan-history, or a file such as state.db.
//
// Top-level files are reported alongside directories rather than lumped into
// an "other" bucket because the two largest single files in a busy project,
// state.db and its write-ahead log, are exactly the ones an operator needs to
// see. On the hub this was measured at, state.db-wal alone was 63 MB.
type Entry struct {
	Name  string `json:"name"`
	Bytes int64  `json:"bytes"`
	// Files counts regular files beneath this entry (1 for a plain file).
	// It is what distinguishes "one enormous archive" from "four thousand
	// small snapshots", which have different remedies.
	Files int  `json:"files"`
	IsDir bool `json:"is_dir"`
}

// Usage is the full picture for one .cloop directory.
type Usage struct {
	Dir        string `json:"dir"`
	TotalBytes int64  `json:"total_bytes"`
	// Entries is sorted largest-first so the caller can render the top N
	// without re-sorting and an operator reads the culprit on line one.
	Entries []Entry `json:"entries"`

	// DBBytes is state.db's own size, repeated out of Entries so callers
	// that only care about the database need not search the slice.
	DBBytes int64 `json:"db_bytes"`
	// ReclaimableBytes is what a VACUUM would return to the filesystem:
	// freelist_count × page_size. Zero when the database could not be read.
	ReclaimableBytes int64 `json:"reclaimable_bytes"`
	// FreeRatio is ReclaimableBytes / DBBytes, in [0,1]. This is the number
	// the janitor's VACUUM threshold is compared against — a ratio rather
	// than an absolute size, because a 2 GB freelist is urgent in a 2.3 GB
	// file and unremarkable in a 200 GB one.
	FreeRatio float64 `json:"free_ratio"`
	// DBError explains why the database numbers are absent, if they are.
	// A project with no state.db yet is not an error; it leaves this empty
	// and the DB fields zero.
	DBError string `json:"db_error,omitempty"`
}

// Entry returns the named entry and whether it was present.
func (u *Usage) Entry(name string) (Entry, bool) {
	if u == nil {
		return Entry{}, false
	}
	for _, e := range u.Entries {
		if e.Name == name {
			return e, true
		}
	}
	return Entry{}, false
}

// Bytes returns the size of the named entry, or zero if absent.
func (u *Usage) Bytes(name string) int64 {
	e, _ := u.Entry(name)
	return e.Bytes
}

// Measure walks workDir/.cloop and reads the database's page statistics.
//
// The database read is best-effort: a state.db that is missing, locked by a
// peer, or newer than this binary (statedb.Open refuses those, by design)
// leaves the DB fields zero and DBError set. Disk usage is still reported,
// because the reason an operator is running this is usually that something is
// wrong with the database.
func Measure(workDir string) (*Usage, error) {
	u, err := MeasureFiles(workDir)
	if err != nil {
		return nil, err
	}
	dbPath := filepath.Join(workDir, ".cloop", "state.db")
	if _, statErr := os.Stat(dbPath); statErr != nil {
		// No database is a legitimate state (a project that has never run).
		// Only a stat failure that is not "absent" is worth reporting.
		if !os.IsNotExist(statErr) {
			u.DBError = statErr.Error()
		}
		return u, nil
	}
	db, err := statedb.Open(dbPath)
	if err != nil {
		u.DBError = err.Error()
		return u, nil
	}
	defer db.Close() //nolint:errcheck // read-only probe

	stats, err := db.SizeStats()
	if err != nil {
		u.DBError = err.Error()
		return u, nil
	}
	u.ApplySizeStats(stats)
	return u, nil
}

// ApplySizeStats fills the database fields from an already-open connection.
// Callers inside the hub, which holds the control-plane database open, use
// this to avoid a second connection to a multi-gigabyte file.
func (u *Usage) ApplySizeStats(stats statedb.SizeStats) {
	if u == nil {
		return
	}
	u.DBError = ""
	u.ReclaimableBytes = stats.FreelistBytes()
	// Prefer the page arithmetic over the on-disk size for the ratio's
	// denominator: they agree, and using one source for both halves means the
	// ratio cannot exceed 1 because the two were sampled a moment apart while
	// a writer extended the file.
	if stats.Bytes > 0 {
		u.FreeRatio = float64(u.ReclaimableBytes) / float64(stats.Bytes)
	}
	if u.DBBytes == 0 {
		u.DBBytes = stats.Bytes
	}
}

// MeasureFiles reports the on-disk breakdown without touching the database.
// Measure is the usual entry point; this exists for callers that already have
// the page statistics, and for tests that have no database at all.
func MeasureFiles(workDir string) (*Usage, error) {
	dir := filepath.Join(workDir, ".cloop")
	u := &Usage{Dir: dir}

	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return u, nil
		}
		return nil, fmt.Errorf("diskusage: read %s: %w", dir, err)
	}

	for _, e := range entries {
		path := filepath.Join(dir, e.Name())
		ent := Entry{Name: e.Name(), IsDir: e.IsDir()}
		if e.IsDir() {
			ent.Bytes, ent.Files = dirSize(path)
		} else {
			fi, err := e.Info()
			if err != nil {
				// A file that vanished between ReadDir and Info (an atomic
				// rename's temporary, a concurrent prune) contributes nothing
				// rather than aborting the whole measurement.
				continue
			}
			if !fi.Mode().IsRegular() {
				continue
			}
			ent.Bytes, ent.Files = fi.Size(), 1
		}
		u.TotalBytes += ent.Bytes
		u.Entries = append(u.Entries, ent)
		if e.Name() == "state.db" {
			u.DBBytes = ent.Bytes
		}
	}

	sort.Slice(u.Entries, func(i, j int) bool {
		if u.Entries[i].Bytes != u.Entries[j].Bytes {
			return u.Entries[i].Bytes > u.Entries[j].Bytes
		}
		return u.Entries[i].Name < u.Entries[j].Name
	})
	return u, nil
}

// dirSize sums regular files beneath root. Walk errors are skipped rather than
// propagated: an unreadable subdirectory should under-report, not fail the
// measurement an operator is using to diagnose a full disk.
func dirSize(root string) (bytes int64, files int) {
	_ = filepath.WalkDir(root, func(_ string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil //nolint:nilerr // deliberate: under-report rather than fail
		}
		fi, err := d.Info()
		if err != nil || !fi.Mode().IsRegular() {
			return nil //nolint:nilerr // deliberate: see above
		}
		bytes += fi.Size()
		files++
		return nil
	})
	return bytes, files
}

// FreeBytes reports the space this process could actually write on the
// filesystem holding path, or an error if it cannot be determined.
//
// This exists because VACUUM is not a pure reclaim: SQLite rebuilds the
// database into a temporary copy and then writes it back through the journal,
// so it needs free space *before* it returns any. Running it on a nearly-full
// disk is therefore the one case where the operation meant to save you is the
// one that finishes the job — and "nearly full" is exactly when a janitor
// decides to run. The machine this was written on was at 100% with zero bytes
// available, which is how the check came to exist.
//
// Bavail or Bfree depending on who we are, and the distinction matters here
// more than it usually does. Bavail excludes the blocks reserved for root —
// typically 5%, which on a 150 GB volume is 7.5 GB. A hub running as root
// reads Bavail as zero on exactly the full disk it was deployed to rescue,
// and would then decline to vacuum forever. Asking for the number that
// describes *this* process is the only reading that does not either overstate
// the space for an unprivileged hub or understate it for a privileged one.
func FreeBytes(path string) (int64, error) {
	var fs syscall.Statfs_t
	if err := syscall.Statfs(path, &fs); err != nil {
		return 0, fmt.Errorf("diskusage: statfs %s: %w", path, err)
	}
	blocks := fs.Bavail
	if os.Geteuid() == 0 {
		blocks = fs.Bfree
	}
	// Bsize is int64 on Linux and uint32 on Darwin; the conversion is valid
	// for both and cloop publishes no other platforms.
	return int64(blocks) * int64(uint64(fs.Bsize)), nil //nolint:gosec,unconvert // see comment
}

// VacuumHeadroom estimates the free space a VACUUM of this database needs.
//
// SQLite copies the live pages into a temporary database and then writes that
// back into the original through the journal, so the peak requirement is about
// twice the *compacted* size — not twice the file size, which is the number
// that would stop a mostly-empty database from ever being reclaimed. The fixed
// addend covers the schema, the WAL's own overhead, and the fact that the
// freelist figure is a snapshot of a file a writer may still be extending.
func (u *Usage) VacuumHeadroom() int64 {
	if u == nil {
		return 0
	}
	live := u.DBBytes - u.ReclaimableBytes
	if live < 0 {
		live = u.DBBytes
	}
	return live*2 + (64 << 20)
}

// HumanBytes formats a byte count for operator-facing output.
func HumanBytes(n int64) string {
	const (
		KB = 1 << 10
		MB = 1 << 20
		GB = 1 << 30
	)
	switch {
	case n < KB:
		return fmt.Sprintf("%d B", n)
	case n < MB:
		return fmt.Sprintf("%.1f KB", float64(n)/KB)
	case n < GB:
		return fmt.Sprintf("%.1f MB", float64(n)/MB)
	default:
		return fmt.Sprintf("%.2f GB", float64(n)/GB)
	}
}
