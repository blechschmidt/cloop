// Package archive manages the task archive store (.cloop/archive.json).
// Archived tasks are removed from the active plan and stored here with a
// timestamp so the plan stays lean for long-running projects.
package archive

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/blechschmidt/cloop/pkg/atomicfile"
	"github.com/blechschmidt/cloop/pkg/pm"
)

const archiveFile = ".cloop/archive.json"

// ArchivedTask wraps a pm.Task with the timestamp it was archived.
type ArchivedTask struct {
	Task       pm.Task   `json:"task"`
	ArchivedAt time.Time `json:"archived_at"`
}

// Load reads the archive from disk. Returns an empty slice when the file does
// not exist (normal for a new project).
//
// On parse failure (zero-byte file from a pre-atomicfile torn write, manual
// edit gone wrong, schema drift) the corrupt file is quarantined aside as
// archive.json.corrupt-<unix> and a nil slice is returned. The next archive
// operation will reseed the file from scratch — losing the historical archive
// is preferable to hard-failing `cloop task archive`, `cloop task unarchive`,
// and any search/report path that calls Load (e.g. pkg/search/search.go).
func Load(workDir string) ([]ArchivedTask, error) {
	path := filepath.Join(workDir, archiveFile)
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("reading archive: %w", err)
	}
	var tasks []ArchivedTask
	if err := json.Unmarshal(data, &tasks); err != nil {
		qpath := atomicfile.QuarantineCorrupt(path)
		if qpath != "" {
			fmt.Fprintf(os.Stderr, "warning: archive at %s was corrupt (%v); quarantined to %s, starting fresh\n", path, err, qpath)
		} else {
			fmt.Fprintf(os.Stderr, "warning: archive at %s was corrupt (%v) and could not be quarantined; ignoring\n", path, err)
		}
		return nil, nil
	}
	return tasks, nil
}

// Save persists the archive to disk atomically.
//
// The previous tmp+rename hand-roll skipped fsync of both the data file and
// the parent directory; on power loss the rename could be lost (leaving the
// previous file) or — worse — the new file could exist on disk but the dirent
// could be missing, leaving neither the old nor the new archive visible.
// atomicfile.Write fsyncs both the data file and the parent directory's
// inode, so the rename survives a power loss.
func Save(workDir string, tasks []ArchivedTask) error {
	path := filepath.Join(workDir, archiveFile)
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return fmt.Errorf("creating .cloop dir: %w", err)
	}
	data, err := json.MarshalIndent(tasks, "", "  ")
	if err != nil {
		return fmt.Errorf("encoding archive: %w", err)
	}
	return atomicfile.Write(path, data, 0o600)
}

// isTerminal returns true for statuses that are considered "completed" and
// thus eligible for archival.
func isTerminal(s pm.TaskStatus) bool {
	return s == pm.TaskDone || s == pm.TaskSkipped || s == pm.TaskFailed || s == pm.TaskTimedOut
}

// ArchiveTasks moves tasks matching ids (or all terminal tasks when all=true)
// from plan into the archive. The plan is mutated in place; the caller must
// persist the plan and the returned archive slice.
//
// Returns the newly archived entries and an error if any requested ID is
// missing or not in a terminal state.
func ArchiveTasks(plan *pm.Plan, existing []ArchivedTask, ids []int, all bool) ([]ArchivedTask, error) {
	if plan == nil {
		return nil, fmt.Errorf("no plan loaded")
	}

	// Build set of IDs to archive.
	toArchive := map[int]bool{}
	if all {
		for _, t := range plan.Tasks {
			if isTerminal(t.Status) {
				toArchive[t.ID] = true
			}
		}
		if len(toArchive) == 0 {
			return nil, fmt.Errorf("no done/skipped/failed tasks to archive")
		}
	} else {
		for _, id := range ids {
			toArchive[id] = true
		}
	}

	// Validate requested IDs.
	if !all {
		for id := range toArchive {
			found := false
			for _, t := range plan.Tasks {
				if t.ID == id {
					found = true
					if !isTerminal(t.Status) {
						return nil, fmt.Errorf("task %d has status %q — only done/skipped/failed/timed_out tasks can be archived", id, t.Status)
					}
					break
				}
			}
			if !found {
				return nil, fmt.Errorf("task %d not found in plan", id)
			}
		}
	}

	now := time.Now()
	var newEntries []ArchivedTask
	remaining := plan.Tasks[:0:0]
	for _, t := range plan.Tasks {
		if toArchive[t.ID] {
			cp := *t
			newEntries = append(newEntries, ArchivedTask{Task: cp, ArchivedAt: now})
		} else {
			remaining = append(remaining, t)
		}
	}

	plan.Tasks = remaining
	merged := append(existing, newEntries...)
	return merged, nil
}

// UnarchiveTask moves the task with the given ID from the archive back into
// the plan with status reset to pending. Returns the restored task.
func UnarchiveTask(plan *pm.Plan, existing []ArchivedTask, id int) (*pm.Task, []ArchivedTask, error) {
	if plan == nil {
		return nil, nil, fmt.Errorf("no plan loaded")
	}

	idx := -1
	for i, a := range existing {
		if a.Task.ID == id {
			idx = i
			break
		}
	}
	if idx == -1 {
		return nil, nil, fmt.Errorf("task %d not found in archive", id)
	}

	restored := existing[idx].Task
	restored.Status = pm.TaskPending

	// Remove from archive.
	updated := append(existing[:idx:idx], existing[idx+1:]...)

	// Append to plan (avoid ID collision — check and reassign if needed).
	maxID := 0
	for _, t := range plan.Tasks {
		if t.ID > maxID {
			maxID = t.ID
		}
	}
	if restored.ID <= maxID {
		// Give it a new ID to avoid collision.
		restored.ID = maxID + 1
	}

	plan.Tasks = append(plan.Tasks, &restored)
	return &restored, updated, nil
}
