// Package resources samples system-level resource usage of the running cloop
// process and the .cloop project directory. It exposes a JSON-friendly
// snapshot used by the Web UI's per-project Resources card.
//
// All metrics are best-effort:
//   - Linux paths (/proc/self/stat, /proc/self/fd) return zero values on
//     other operating systems rather than failing the whole snapshot, so a
//     macOS or Windows operator still sees memory/goroutine/disk numbers.
//   - DiskUsage walks the .cloop directory and bins every regular file under
//     a known category (state.db, artifacts, snapshots, checkpoints, logs,
//     other). Symlinks and unreadable entries are skipped silently to match
//     `du`-style robustness.
//
// The package is intentionally free of UI/HTTP concerns so it can be reused
// from CLI commands (e.g. `cloop doctor`) without import cycles.
package resources

import (
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Snapshot is a single point-in-time reading of resource usage.
//
// All time-related fields use UnixMilli so they round-trip cleanly through
// JSON and remain monotonic across timezone changes on the rendering client.
type Snapshot struct {
	Timestamp time.Time `json:"timestamp"`

	// CPU process CPU usage as a fraction of one core (0..N where N = NumCPU).
	// Computed from /proc/self/stat utime+stime ticks divided by elapsed
	// wall-clock ticks since the previous snapshot. The first sample after
	// process start (or after a long idle period) reports 0 because there
	// is no prior sample to diff against.
	CPUPercent float64 `json:"cpu_percent"`

	// MemoryRSS resident set size in bytes (runtime.MemStats.Sys).
	// Sys is the total bytes of memory obtained from the OS — a more
	// reliable proxy for the operator's "how much RAM is cloop using"
	// question than HeapAlloc, which excludes runtime overhead.
	MemoryRSS uint64 `json:"memory_rss"`

	// MemoryHeapAlloc bytes currently allocated to the Go heap. Cheap to
	// read and useful for spotting leaks even when Sys plateaus.
	MemoryHeapAlloc uint64 `json:"memory_heap_alloc"`

	// MemoryHeapSys bytes obtained for the heap from the OS.
	MemoryHeapSys uint64 `json:"memory_heap_sys"`

	// NumGC the number of completed GC cycles since process start.
	NumGC uint32 `json:"num_gc"`

	// Goroutines the result of runtime.NumGoroutine() — the leak signal.
	Goroutines int `json:"goroutines"`

	// FileDescriptors count of entries under /proc/self/fd. Returns 0 on
	// non-Linux platforms or when the directory cannot be read.
	FileDescriptors int `json:"file_descriptors"`

	// Disk per-category breakdown of .cloop disk usage.
	Disk DiskUsage `json:"disk"`
}

// DiskUsage breaks .cloop directory size down by category. Categories are
// matched in declaration order; the first match wins so a file under
// .cloop/snapshots/state.db is bucketed as a snapshot, not as the StateDB.
type DiskUsage struct {
	Total       int64 `json:"total"`
	StateDB     int64 `json:"state_db"`
	Artifacts   int64 `json:"artifacts"`
	Tasks       int64 `json:"tasks"`
	Snapshots   int64 `json:"snapshots"`
	Checkpoints int64 `json:"checkpoints"`
	Logs        int64 `json:"logs"`
	Backups     int64 `json:"backups"`
	Other       int64 `json:"other"`
}

// Sampler keeps the small amount of state needed to derive CPUPercent
// from successive /proc/self/stat reads. Safe for concurrent use.
type Sampler struct {
	mu          sync.Mutex
	prevCPUTick uint64    // utime+stime from previous /proc/self/stat read
	prevWall    time.Time // wall-clock at previous read
	clkTck      float64   // SC_CLK_TCK; 100 on virtually every Linux system
}

// NewSampler returns a sampler with default settings. The clock tick value
// (used to translate /proc/self/stat ticks into seconds) defaults to 100
// — the value glibc returns for sysconf(_SC_CLK_TCK) on every mainstream
// Linux distribution. Callers needing non-default tick rates can construct
// Sampler{clkTck: ...} directly.
func NewSampler() *Sampler {
	return &Sampler{clkTck: 100}
}

// Sample returns a fresh Snapshot for the given .cloop directory.
//
// workDir should be the project root (the directory CONTAINING .cloop,
// not .cloop itself). When workDir is empty or .cloop does not exist,
// DiskUsage returns zero values.
func (s *Sampler) Sample(workDir string) Snapshot {
	now := time.Now()

	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)

	snap := Snapshot{
		Timestamp:       now,
		MemoryRSS:       ms.Sys,
		MemoryHeapAlloc: ms.HeapAlloc,
		MemoryHeapSys:   ms.HeapSys,
		NumGC:           ms.NumGC,
		Goroutines:      runtime.NumGoroutine(),
		FileDescriptors: countFDs(),
		CPUPercent:      s.cpuPercent(now),
	}

	if workDir != "" {
		snap.Disk = DiskUsage{} // zeroed; ComputeDiskUsage fills it
		if du, err := ComputeDiskUsage(filepath.Join(workDir, ".cloop")); err == nil {
			snap.Disk = du
		}
	}

	return snap
}

// cpuPercent reads /proc/self/stat, diffs against the previous reading,
// and returns the percentage of one core consumed since the last call.
// Returns 0 on the first call, on non-Linux platforms, or if the stat
// file cannot be parsed.
func (s *Sampler) cpuPercent(now time.Time) float64 {
	if runtime.GOOS != "linux" {
		return 0
	}
	tick, ok := readProcStatTicks()
	if !ok {
		return 0
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.prevWall.IsZero() {
		s.prevCPUTick = tick
		s.prevWall = now
		return 0
	}

	wallDelta := now.Sub(s.prevWall).Seconds()
	if wallDelta <= 0 {
		return 0
	}

	tickDelta := float64(tick - s.prevCPUTick)
	s.prevCPUTick = tick
	s.prevWall = now

	if s.clkTck <= 0 {
		s.clkTck = 100
	}
	cpuSeconds := tickDelta / s.clkTck
	// Percent of one core: 1.0 == 100% of one core. With N cores, the value
	// can exceed 1.0 (multiplied by 100 in the UI) up to NumCPU.
	return (cpuSeconds / wallDelta) * 100
}

// readProcStatTicks parses utime+stime out of /proc/self/stat.
//
// Field layout (ticks-since-process-start in jiffies):
//
//	field 14 = utime
//	field 15 = stime
//
// Fields are space-separated, but field 2 (comm) is enclosed in
// parentheses and may itself contain spaces. We slice the string at the
// last ')' so subsequent fields are unambiguous.
func readProcStatTicks() (uint64, bool) {
	data, err := os.ReadFile("/proc/self/stat")
	if err != nil {
		return 0, false
	}
	s := string(data)
	// strip up to and including the last ')'
	idx := strings.LastIndex(s, ")")
	if idx < 0 || idx+2 >= len(s) {
		return 0, false
	}
	rest := s[idx+2:]
	fields := strings.Fields(rest)
	// rest starts at field 3 (state). utime is field 14, so index 11
	// in the post-comm slice (14 - 3 = 11). stime is index 12.
	if len(fields) < 13 {
		return 0, false
	}
	utime, err := strconv.ParseUint(fields[11], 10, 64)
	if err != nil {
		return 0, false
	}
	stime, err := strconv.ParseUint(fields[12], 10, 64)
	if err != nil {
		return 0, false
	}
	return utime + stime, true
}

// countFDs returns the number of open file descriptors held by this
// process. Implementation reads /proc/self/fd; returns 0 on non-Linux
// platforms or when the directory cannot be enumerated.
func countFDs() int {
	if runtime.GOOS != "linux" {
		return 0
	}
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		return 0
	}
	return len(entries)
}

// ComputeDiskUsage walks dir (typically the .cloop directory) and bins
// each regular file into a category based on its top-level subdirectory.
// Symlinks, unreadable entries, and non-regular files (sockets, devices)
// are skipped. The function never returns a partial error: any failure
// short-circuits to (DiskUsage{}, err). Callers that need best-effort
// behavior should check err and fall back to the zero value.
func ComputeDiskUsage(dir string) (DiskUsage, error) {
	var du DiskUsage
	st, err := os.Stat(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return du, nil
		}
		return du, err
	}
	if !st.IsDir() {
		return du, nil
	}

	walkErr := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			// Skip unreadable entries (permission denied on a single
			// file shouldn't fail the whole scan) but propagate the
			// "directory disappeared mid-walk" condition so callers
			// can retry.
			if d == nil {
				return nil
			}
			return nil
		}
		if d.IsDir() {
			return nil
		}
		if !d.Type().IsRegular() {
			return nil
		}
		info, ierr := d.Info()
		if ierr != nil {
			return nil
		}
		size := info.Size()
		du.Total += size

		rel, rerr := filepath.Rel(dir, path)
		if rerr != nil {
			du.Other += size
			return nil
		}
		// Normalize separators so Windows paths bucket the same way as
		// Linux ones in tests.
		rel = filepath.ToSlash(rel)
		switch categorize(rel) {
		case catStateDB:
			du.StateDB += size
		case catArtifacts:
			du.Artifacts += size
		case catTasks:
			du.Tasks += size
		case catSnapshots:
			du.Snapshots += size
		case catCheckpoints:
			du.Checkpoints += size
		case catLogs:
			du.Logs += size
		case catBackups:
			du.Backups += size
		default:
			du.Other += size
		}
		return nil
	})
	if walkErr != nil {
		return DiskUsage{}, walkErr
	}
	return du, nil
}

type category int

const (
	catOther category = iota
	catStateDB
	catArtifacts
	catTasks
	catSnapshots
	catCheckpoints
	catLogs
	catBackups
)

// categorize maps a path relative to .cloop to its bucket. Order matters:
// directory-prefix matches are checked before single-file matches so a
// snapshot of state.db inside .cloop/snapshots is counted as a snapshot.
func categorize(rel string) category {
	switch {
	case strings.HasPrefix(rel, "snapshots/"):
		return catSnapshots
	case strings.HasPrefix(rel, "checkpoints/"):
		return catCheckpoints
	case strings.HasPrefix(rel, "artifacts/"):
		return catArtifacts
	case strings.HasPrefix(rel, "tasks/"):
		return catTasks
	case strings.HasPrefix(rel, "logs/"):
		return catLogs
	case strings.HasPrefix(rel, "plan-history/"):
		return catSnapshots
	case strings.HasPrefix(rel, "backups/"):
		return catBackups
	case rel == "state.db" || rel == "state.db-wal" || rel == "state.db-shm" || rel == "state.json":
		return catStateDB
	}
	return catOther
}

// History keeps the last N snapshots in a fixed-size ring so the UI can
// draw sparklines without persisting anything to disk. Safe for concurrent
// use; the canonical reader is the Web UI handler, but tests exercise
// Append directly.
type History struct {
	mu       sync.Mutex
	capacity int
	items    []Snapshot
}

// NewHistory returns a History that retains up to capacity samples. When
// the buffer is full, Append drops the oldest entry. capacity ≤ 0 falls
// back to 1 to avoid divide-by-zero in the ring math.
func NewHistory(capacity int) *History {
	if capacity <= 0 {
		capacity = 1
	}
	return &History{capacity: capacity}
}

// Append records snap, evicting the oldest entry if the ring is full.
func (h *History) Append(snap Snapshot) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.items) < h.capacity {
		h.items = append(h.items, snap)
		return
	}
	// Shift left: O(N) but N is small (60 by default) so allocation-free
	// shifting beats the complexity of a true ring with wrap indices.
	copy(h.items, h.items[1:])
	h.items[len(h.items)-1] = snap
}

// Snapshots returns a defensive copy of the retained samples in
// chronological order.
func (h *History) Snapshots() []Snapshot {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := make([]Snapshot, len(h.items))
	copy(out, h.items)
	return out
}

// Latest returns the most recently appended snapshot and a boolean
// indicating whether the history is non-empty.
func (h *History) Latest() (Snapshot, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.items) == 0 {
		return Snapshot{}, false
	}
	return h.items[len(h.items)-1], true
}
