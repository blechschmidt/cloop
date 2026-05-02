// Package compact prunes old artifacts, snapshots, and checkpoints from a
// cloop project directory to reclaim disk space.
package compact

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/state"
)

// Options controls compaction behaviour.
type Options struct {
	DryRun            bool
	KeepSnapshots     int // number of most-recent plan snapshots to keep
	KeepCheckpoints   int // task IDs no longer in plan have their checkpoints removed; this is not a count limit
	KeepArtifactsDays int // delete artifacts older than this many days for completed tasks
	TruncateStepLog   int // keep last N entries in replay.jsonl (0 = skip)
}

// DefaultOptions returns the spec-mandated defaults.
func DefaultOptions() Options {
	return Options{
		KeepSnapshots:     10,
		KeepArtifactsDays: 30,
		TruncateStepLog:   1000,
	}
}

// Summary reports bytes freed per category.
type Summary struct {
	SnapshotsBytesFreed    int64
	CheckpointsBytesFreed  int64
	ArtifactsBytesFreed    int64
	StepLogBytesFreed      int64
	SnapshotsDeleted       int
	CheckpointsDeleted     int
	ArtifactsDeleted       int
	StepLogTruncated       bool
}

// TotalBytesFreed returns total bytes freed across all categories.
func (s Summary) TotalBytesFreed() int64 {
	return s.SnapshotsBytesFreed + s.CheckpointsBytesFreed + s.ArtifactsBytesFreed + s.StepLogBytesFreed
}

// Run executes compaction with the given options and returns a summary.
func Run(workDir string, opts Options) (Summary, error) {
	var sum Summary

	// Load current plan to know which task IDs are active.
	activeTasks := map[int]bool{}
	completedTasks := map[int]bool{}
	st, err := state.Load(workDir)
	if err == nil && st.Plan != nil {
		for _, t := range st.Plan.Tasks {
			activeTasks[t.ID] = true
			if t.Status == pm.TaskDone || t.Status == pm.TaskSkipped {
				completedTasks[t.ID] = true
			}
		}
	}

	if err := compactSnapshots(workDir, opts, &sum); err != nil {
		return sum, fmt.Errorf("snapshots: %w", err)
	}
	if err := compactCheckpoints(workDir, opts, activeTasks, &sum); err != nil {
		return sum, fmt.Errorf("checkpoints: %w", err)
	}
	if err := compactArtifacts(workDir, opts, completedTasks, &sum); err != nil {
		return sum, fmt.Errorf("artifacts: %w", err)
	}
	if opts.TruncateStepLog > 0 {
		if err := truncateStepLog(workDir, opts, &sum); err != nil {
			return sum, fmt.Errorf("step log: %w", err)
		}
	}

	return sum, nil
}

// DirSize returns the total size of a directory tree in bytes.
func DirSize(path string) (int64, error) {
	var size int64
	err := filepath.Walk(path, func(_ string, fi os.FileInfo, err error) error {
		if err != nil {
			return nil // skip unreadable entries
		}
		if !fi.IsDir() {
			size += fi.Size()
		}
		return nil
	})
	return size, err
}

// ─── plan snapshots ──────────────────────────────────────────────────────────

func compactSnapshots(workDir string, opts Options, sum *Summary) error {
	dir := filepath.Join(workDir, ".cloop", "plan-history")
	entries, err := os.ReadDir(dir)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}

	// Collect snapshot files sorted by name (timestamp prefix ensures order).
	var files []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".json") {
			files = append(files, filepath.Join(dir, e.Name()))
		}
	}
	sort.Strings(files) // oldest first

	keep := opts.KeepSnapshots
	if keep < 1 {
		keep = 1
	}
	if len(files) <= keep {
		return nil
	}

	toDelete := files[:len(files)-keep]
	for _, f := range toDelete {
		fi, err := os.Stat(f)
		if err != nil {
			continue
		}
		sum.SnapshotsBytesFreed += fi.Size()
		sum.SnapshotsDeleted++
		if !opts.DryRun {
			_ = os.Remove(f)
		}
	}
	return nil
}

// ─── task checkpoints ────────────────────────────────────────────────────────

func compactCheckpoints(workDir string, opts Options, activeTasks map[int]bool, sum *Summary) error {
	base := filepath.Join(workDir, ".cloop", "task-checkpoints")
	entries, err := os.ReadDir(base)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}

	for _, e := range entries {
		if !e.IsDir() || !strings.HasPrefix(e.Name(), "task-") {
			continue
		}
		// Parse task ID from directory name "task-<id>".
		var taskID int
		if _, err := fmt.Sscanf(e.Name(), "task-%d", &taskID); err != nil {
			continue
		}
		if activeTasks[taskID] {
			continue // task is still in the plan, keep checkpoints
		}

		dirPath := filepath.Join(base, e.Name())
		sz, _ := DirSize(dirPath)
		sum.CheckpointsBytesFreed += sz
		// Count files inside as individual checkpoint entries.
		files, _ := os.ReadDir(dirPath)
		sum.CheckpointsDeleted += len(files)

		if !opts.DryRun {
			_ = os.RemoveAll(dirPath)
		}
	}

	// Also remove the single active checkpoint.json if it references a gone task.
	cpPath := filepath.Join(workDir, ".cloop", "checkpoint.json")
	data, err := os.ReadFile(cpPath)
	if err == nil {
		var cp struct {
			TaskID int `json:"task_id"`
		}
		if json.Unmarshal(data, &cp) == nil && !activeTasks[cp.TaskID] {
			fi, _ := os.Stat(cpPath)
			if fi != nil {
				sum.CheckpointsBytesFreed += fi.Size()
				sum.CheckpointsDeleted++
			}
			if !opts.DryRun {
				_ = os.Remove(cpPath)
			}
		}
	}
	return nil
}

// ─── task artifacts ──────────────────────────────────────────────────────────

func compactArtifacts(workDir string, opts Options, completedTasks map[int]bool, sum *Summary) error {
	dir := filepath.Join(workDir, ".cloop", "tasks")
	entries, err := os.ReadDir(dir)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}

	cutoff := time.Now().AddDate(0, 0, -opts.KeepArtifactsDays)

	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".md") {
			continue
		}

		// Parse task ID from filename "<id>-<slug>*.md".
		var taskID int
		if _, err := fmt.Sscanf(e.Name(), "%d-", &taskID); err != nil {
			continue
		}

		// Only prune artifacts for completed/skipped tasks.
		if !completedTasks[taskID] {
			continue
		}

		fi, err := e.Info()
		if err != nil {
			continue
		}
		if fi.ModTime().After(cutoff) {
			continue // not old enough
		}

		sum.ArtifactsBytesFreed += fi.Size()
		sum.ArtifactsDeleted++
		if !opts.DryRun {
			_ = os.Remove(filepath.Join(dir, e.Name()))
		}
	}
	return nil
}

// ─── step log (replay.jsonl) truncation ──────────────────────────────────────

func truncateStepLog(workDir string, opts Options, sum *Summary) error {
	path := filepath.Join(workDir, ".cloop", "replay.jsonl")
	fi, err := os.Stat(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	originalSize := fi.Size()

	// Read all lines.
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	var lines []string
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 4*1024*1024), 4*1024*1024)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.TrimSpace(line) != "" {
			lines = append(lines, line)
		}
	}
	f.Close()
	if err := scanner.Err(); err != nil {
		return err
	}

	if len(lines) <= opts.TruncateStepLog {
		return nil // nothing to truncate
	}

	// Keep last N lines.
	keep := lines[len(lines)-opts.TruncateStepLog:]

	if opts.DryRun {
		// Estimate bytes that would be freed.
		dropped := lines[:len(lines)-opts.TruncateStepLog]
		var droppedBytes int64
		for _, l := range dropped {
			droppedBytes += int64(len(l)) + 1
		}
		sum.StepLogBytesFreed = droppedBytes
		sum.StepLogTruncated = true
		return nil
	}

	// Write truncated file.
	tmp := path + ".tmp"
	out, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	w := bufio.NewWriter(out)
	for _, l := range keep {
		w.WriteString(l)
		w.WriteByte('\n')
	}
	if err := w.Flush(); err != nil {
		out.Close()
		os.Remove(tmp)
		return err
	}
	out.Close()

	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return err
	}

	fi2, _ := os.Stat(path)
	var newSize int64
	if fi2 != nil {
		newSize = fi2.Size()
	}
	freed := originalSize - newSize
	if freed > 0 {
		sum.StepLogBytesFreed = freed
	}
	sum.StepLogTruncated = true
	return nil
}
