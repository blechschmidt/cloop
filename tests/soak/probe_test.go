package soak

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/securewipe"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// sample is one measurement of everything that must stay bounded, taken at a
// known task count.
type sample struct {
	tasks int

	// hubDBBytes is the control-plane database including its write-ahead log.
	// The -wal file is not optional bookkeeping here: SQLite in WAL mode can
	// leave state.db itself untouched across a commit while a reader is open,
	// so a stat of the main file alone reads a growing database as a static
	// one.
	hubDBBytes int64
	// projectDBBytes is the same, summed across every tenant project.
	projectDBBytes int64
	// auditRows is the hash-chained trail's length. The sharpest of the three
	// signals: the Task 20218 amplification emitted one row per task in the
	// plan on every save, so its regression is quadratic here and visible
	// long before the byte counts move.
	auditRows int
	// rssBytes is this process's resident set. The hub runs in-process, so
	// this is the hub's memory plus the harness's own, which is why it is
	// asserted with the loosest bound of the three.
	rssBytes int64
	// goroutines is the live goroutine count.
	goroutines int
}

func (s sample) String() string {
	return fmt.Sprintf("tasks=%-4d hubDB=%-9s projectDB=%-9s auditRows=%-6d rss=%-9s goroutines=%d",
		s.tasks, humanBytes(s.hubDBBytes), humanBytes(s.projectDBBytes),
		s.auditRows, humanBytes(s.rssBytes), s.goroutines)
}

func humanBytes(n int64) string {
	switch {
	case n >= 1<<30:
		return fmt.Sprintf("%.1fGiB", float64(n)/(1<<30))
	case n >= 1<<20:
		return fmt.Sprintf("%.1fMiB", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.1fKiB", float64(n)/(1<<10))
	}
	return fmt.Sprintf("%dB", n)
}

// measure takes one sample.
//
// It returns an error rather than calling t.Fatalf because the driver samples
// from its per-project goroutines, and FailNow from a goroutine that is not
// the test's own does not fail the test — it exits that one goroutine and
// leaves the run to carry on with a missing sample.
func (w *world) measure(tasks int) (sample, error) {
	rows, err := w.auditRows()
	if err != nil {
		return sample{}, err
	}
	s := sample{
		tasks:      tasks,
		hubDBBytes: dbBytes(w.hubDir),
		auditRows:  rows,
		rssBytes:   processRSS(),
		goroutines: settleGoroutines(),
	}
	for _, p := range w.projects {
		s.projectDBBytes += dbBytes(p.dir)
	}
	return s, nil
}

// mustMeasure is measure for the test's own goroutine, where failing fast is
// correct.
func (w *world) mustMeasure(t *testing.T, tasks int) sample {
	t.Helper()
	s, err := w.measure(tasks)
	if err != nil {
		t.Fatalf("sample at %d tasks: %v", tasks, err)
	}
	return s
}

// dbBytes sums a project's state database and its WAL sidecars.
func dbBytes(workDir string) int64 {
	base := state.DBPath(workDir)
	var total int64
	for _, suffix := range []string{"", "-wal", "-shm"} {
		if fi, err := os.Stat(base + suffix); err == nil {
			total += fi.Size()
		}
	}
	return total
}

// auditRows counts the hub's audit trail.
func (w *world) auditRows() (int, error) {
	db, err := statedb.Open(state.DBPath(w.hubDir))
	if err != nil {
		return 0, fmt.Errorf("open control plane for audit count: %w", err)
	}
	defer db.Close()
	_, total, err := db.ListAuditEvents(statedb.AuditFilter{Limit: 1})
	if err != nil {
		return 0, fmt.Errorf("count audit events: %w", err)
	}
	return total, nil
}

// processRSS reads this process's resident set size, or 0 where /proc is not
// available. Returning 0 rather than guessing keeps the growth assertion from
// pretending to have measured something it did not; the caller skips the RSS
// check when it sees a zero.
func processRSS() int64 {
	f, err := os.Open("/proc/self/status")
	if err != nil {
		return 0
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if !strings.HasPrefix(line, "VmRSS:") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			return 0
		}
		kb, err := strconv.ParseInt(fields[1], 10, 64)
		if err != nil {
			return 0
		}
		return kb * 1024
	}
	return 0
}

// settleGoroutines returns the goroutine count after giving teardown a chance
// to finish.
//
// The sleep is not superstition. A dispatch's teardown runs through the SQLite
// connection pool's deferred close and modernc.org/sqlite's finalizers, both
// of which outlive the call that triggered them; sampling immediately counts
// goroutines that are already on their way out and reports a leak that is not
// one. This mirrors settleStatedbGoroutineCount in pkg/statedb, which exists
// for the same reason.
func settleGoroutines() int {
	runtime.GC()
	runtime.Gosched()
	time.Sleep(250 * time.Millisecond)
	runtime.GC()
	return runtime.NumGoroutine()
}

// containerInventory lists containers this soak's executor owns.
//
// Filtered by this run's unique executor ID rather than by cloop.managed:
// a developer box routinely has another hub's containers on it, and a soak
// that reported those as its own leak would be untrustworthy exactly where
// trust matters.
func (w *world) containerInventory(t *testing.T) []string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, w.runtime, "ps", "--all", "--no-trunc",
		"--filter", "label=cloop.executor="+w.executorID,
		"--format", "{{.Names}}\t{{.Status}}\t{{.Image}}").CombinedOutput()
	if err != nil {
		t.Fatalf("%s ps: %v\n%s", w.runtime, err, out)
	}
	var names []string
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if strings.TrimSpace(line) != "" {
			names = append(names, line)
		}
	}
	sort.Strings(names)
	return names
}

// leaseDirRoots are the directories a credential lease can be staged in.
//
// /dev/shm first because that is what the broker prefers — it is tmpfs, so
// plaintext never reaches a disk block — with the temp directory as the
// fallback the broker itself falls back to.
func leaseDirRoots() []string {
	roots := []string{"/dev/shm"}
	if tmp := os.TempDir(); tmp != "" && tmp != "/dev/shm" {
		roots = append(roots, tmp)
	}
	return roots
}

// leaseDirs lists credential staging directories, restricted to those created
// no earlier than since.
//
// The time bound is what makes this safe to run on a shared machine: another
// hub's live lease directory is not this suite's leak, and a set difference
// taken before and after would still be fooled by a sibling that happened to
// mint a lease during the window. Pairing both — a set difference *and* a
// creation time inside this run — is as close to attribution as the filesystem
// allows, and the failure message says so rather than claiming certainty.
func leaseDirs(since time.Time) []string {
	var found []string
	for _, root := range leaseDirRoots() {
		entries, err := os.ReadDir(root)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if !e.IsDir() || !strings.HasPrefix(e.Name(), securewipe.LeaseDirPrefix) {
				continue
			}
			full := filepath.Join(root, e.Name())
			info, err := e.Info()
			if err != nil {
				continue
			}
			if info.ModTime().Before(since) {
				continue
			}
			found = append(found, full)
		}
	}
	sort.Strings(found)
	return found
}

// scanForSentinels walks a directory tree looking for any of the given byte
// strings, returning the first few hits with their location.
//
// Used to prove no credential survived: the sentinel is embedded in the
// granted kubeconfig and appears nowhere else, so a hit is the credential
// itself and not a coincidence.
//
// since prunes by modification time before reading anything. That is what
// makes it affordable to point this at /tmp on a shared machine: the scan has
// to consider the whole tree, because a credential that escaped its staging
// directory could be anywhere in it, but it only has to *read* files this run
// could have written. Without the prune the assertion costs a full read of
// every small file on the host.
func scanForSentinels(root string, sentinels map[string]string, since time.Time, limit int) []string {
	var hits []string
	deadline := time.Now().Add(scanBudget)
	checked := 0
	_ = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil || len(hits) >= limit {
			return nil
		}
		// A budget rather than an unbounded walk: this runs inside an
		// assertion, and a scan that never returns reads as a hung soak.
		if checked%512 == 0 && time.Now().After(deadline) {
			return filepath.SkipAll
		}
		if d.IsDir() {
			return nil
		}
		checked++
		info, ierr := d.Info()
		if ierr != nil {
			return nil
		}
		// Anything over a few MiB is not a credential file; skipping them
		// keeps a soak from reading a multi-gigabyte state database byte by
		// byte on every assertion.
		if info.Size() > 4<<20 || info.ModTime().Before(since) {
			return nil
		}
		data, rerr := os.ReadFile(path)
		if rerr != nil {
			return nil
		}
		for sentinel, owner := range sentinels {
			if strings.Contains(string(data), sentinel) {
				hits = append(hits, fmt.Sprintf("%s's credential found in %s", owner, path))
				if len(hits) >= limit {
					return filepath.SkipAll
				}
			}
		}
		return nil
	})
	return hits
}

// scanBudget bounds one sentinel sweep.
const scanBudget = 45 * time.Second

// sentinelIndex maps each project's credential sentinel to a describable owner.
func (w *world) sentinelIndex() map[string]string {
	idx := make(map[string]string, len(w.projects))
	for _, p := range w.projects {
		idx[p.secretSentinel] = p.tenant.name + "/" + p.name
	}
	return idx
}

// runtimeStack fills buf with the stacks of all live goroutines.
func runtimeStack(buf []byte) int { return runtime.Stack(buf, true) }

// joinPath is filepath.Join, named separately so the driver can read as prose.
func joinPath(elem ...string) string { return filepath.Join(elem...) }

// dispatchCount renders a project's task count, or "n/a" for a global-scope
// stream that belongs to no project.
func dispatchCount(n int) string {
	if n < 0 {
		return "n/a"
	}
	return strconv.Itoa(n)
}
