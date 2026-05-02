package pm

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const historyDir = ".cloop/plan-history"

// Snapshot is a versioned, timestamped copy of a Plan.
type Snapshot struct {
	Version   int       `json:"version"`
	Timestamp time.Time `json:"timestamp"`
	Plan      *Plan     `json:"plan"`
}

// SnapshotMeta contains lightweight metadata about a snapshot (no full plan).
type SnapshotMeta struct {
	Version   int       `json:"version"`
	Timestamp time.Time `json:"timestamp"`
	Filename  string    `json:"filename"`
	TaskCount int       `json:"task_count"`
	Summary   string    `json:"summary"`
}

// FieldChange records one field that changed between two task versions.
type FieldChange struct {
	Field    string
	OldValue string
	NewValue string
}

// TaskDiff describes what changed in a specific task between two plan versions.
type TaskDiff struct {
	ID      int
	Title   string
	Changes []FieldChange
}

// PlanDiff is the result of comparing two Plan snapshots.
type PlanDiff struct {
	Added   []*Task
	Removed []*Task
	Changed []TaskDiff
}

// IsEmpty returns true if there are no differences.
func (d *PlanDiff) IsEmpty() bool {
	return len(d.Added) == 0 && len(d.Removed) == 0 && len(d.Changed) == 0
}

// snapshotFilename returns the filename for a snapshot with the given version and timestamp.
func snapshotFilename(ts time.Time, version int) string {
	return fmt.Sprintf("%s-v%d.json", ts.UTC().Format("20060102-150405"), version)
}

// historyPath returns the path to the plan-history directory.
func historyPath(workDir string) string {
	return filepath.Join(workDir, historyDir)
}

// SaveSnapshot serialises the current plan and appends a new snapshot to the
// history directory. It deduplicates: if the plan's tasks are identical to the
// most-recent snapshot it returns nil without writing.
// The plan's Version field is incremented before saving.
func SaveSnapshot(workDir string, plan *Plan) error {
	if plan == nil {
		return nil
	}

	dir := historyPath(workDir)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create plan-history dir: %w", err)
	}

	// Compute a fingerprint of the current tasks for deduplication.
	fingerprint, err := planFingerprint(plan)
	if err != nil {
		return fmt.Errorf("fingerprint plan: %w", err)
	}

	// Read the latest snapshot (if any) and skip if identical.
	metas, _ := ListSnapshots(workDir)
	if len(metas) > 0 {
		latest := metas[len(metas)-1]
		last, loadErr := LoadSnapshot(workDir, latest.Version)
		if loadErr == nil {
			lastFP, fpErr := planFingerprint(last.Plan)
			if fpErr == nil && lastFP == fingerprint {
				return nil // no change
			}
		}
	}

	// Increment version.
	plan.Version++

	snap := Snapshot{
		Version:   plan.Version,
		Timestamp: time.Now(),
		Plan:      plan,
	}

	data, err := json.MarshalIndent(snap, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal snapshot: %w", err)
	}

	fname := snapshotFilename(snap.Timestamp, snap.Version)
	path := filepath.Join(dir, fname)
	return os.WriteFile(path, data, 0o644)
}

// LoadSnapshot loads the snapshot with the given version number.
// Returns an error if no snapshot with that version exists.
func LoadSnapshot(workDir string, version int) (*Snapshot, error) {
	dir := historyPath(workDir)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("read plan-history: %w", err)
	}

	suffix := fmt.Sprintf("-v%d.json", version)
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if strings.HasSuffix(e.Name(), suffix) {
			data, err := os.ReadFile(filepath.Join(dir, e.Name()))
			if err != nil {
				return nil, fmt.Errorf("read snapshot %s: %w", e.Name(), err)
			}
			var snap Snapshot
			if err := json.Unmarshal(data, &snap); err != nil {
				return nil, fmt.Errorf("parse snapshot %s: %w", e.Name(), err)
			}
			return &snap, nil
		}
	}
	return nil, fmt.Errorf("snapshot v%d not found", version)
}

// ListSnapshots returns metadata for all saved snapshots, sorted by version ascending.
func ListSnapshots(workDir string) ([]*SnapshotMeta, error) {
	dir := historyPath(workDir)
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read plan-history: %w", err)
	}

	var metas []*SnapshotMeta
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			continue
		}
		var snap Snapshot
		if err := json.Unmarshal(data, &snap); err != nil {
			continue
		}
		metas = append(metas, &SnapshotMeta{
			Version:   snap.Version,
			Timestamp: snap.Timestamp,
			Filename:  e.Name(),
			TaskCount: len(snap.Plan.Tasks),
			Summary:   snap.Plan.Summary(),
		})
	}

	sort.Slice(metas, func(i, j int) bool {
		return metas[i].Version < metas[j].Version
	})
	return metas, nil
}

// DiffPlans computes the diff between plan a (old) and plan b (new).
func DiffPlans(a, b *Plan) PlanDiff {
	var diff PlanDiff

	// Index tasks by ID.
	aByID := make(map[int]*Task, len(a.Tasks))
	for _, t := range a.Tasks {
		aByID[t.ID] = t
	}
	bByID := make(map[int]*Task, len(b.Tasks))
	for _, t := range b.Tasks {
		bByID[t.ID] = t
	}

	// Find added tasks (in b but not in a).
	for _, t := range b.Tasks {
		if _, exists := aByID[t.ID]; !exists {
			diff.Added = append(diff.Added, t)
		}
	}

	// Find removed tasks (in a but not in b).
	for _, t := range a.Tasks {
		if _, exists := bByID[t.ID]; !exists {
			diff.Removed = append(diff.Removed, t)
		}
	}

	// Find changed tasks (in both, but fields differ).
	for _, bt := range b.Tasks {
		at, exists := aByID[bt.ID]
		if !exists {
			continue
		}
		var changes []FieldChange
		if at.Status != bt.Status {
			changes = append(changes, FieldChange{
				Field:    "status",
				OldValue: string(at.Status),
				NewValue: string(bt.Status),
			})
		}
		if at.Priority != bt.Priority {
			changes = append(changes, FieldChange{
				Field:    "priority",
				OldValue: fmt.Sprintf("%d", at.Priority),
				NewValue: fmt.Sprintf("%d", bt.Priority),
			})
		}
		if at.Title != bt.Title {
			changes = append(changes, FieldChange{
				Field:    "title",
				OldValue: at.Title,
				NewValue: bt.Title,
			})
		}
		if at.Description != bt.Description {
			changes = append(changes, FieldChange{
				Field:    "description",
				OldValue: truncateHistStr(at.Description, 80),
				NewValue: truncateHistStr(bt.Description, 80),
			})
		}
		if len(changes) > 0 {
			diff.Changed = append(diff.Changed, TaskDiff{
				ID:      bt.ID,
				Title:   bt.Title,
				Changes: changes,
			})
		}
	}

	// Sort slices for stable output.
	sort.Slice(diff.Added, func(i, j int) bool { return diff.Added[i].ID < diff.Added[j].ID })
	sort.Slice(diff.Removed, func(i, j int) bool { return diff.Removed[i].ID < diff.Removed[j].ID })
	sort.Slice(diff.Changed, func(i, j int) bool { return diff.Changed[i].ID < diff.Changed[j].ID })

	return diff
}

// planFingerprint returns a JSON hash of tasks for deduplication.
// We only compare task fields that represent meaningful plan state.
func planFingerprint(plan *Plan) (string, error) {
	type taskKey struct {
		ID       int        `json:"id"`
		Title    string     `json:"title"`
		Desc     string     `json:"desc"`
		Priority int        `json:"priority"`
		Status   TaskStatus `json:"status"`
		DepsOn   []int      `json:"deps_on"`
	}
	keys := make([]taskKey, 0, len(plan.Tasks))
	for _, t := range plan.Tasks {
		keys = append(keys, taskKey{
			ID:       t.ID,
			Title:    t.Title,
			Desc:     t.Description,
			Priority: t.Priority,
			Status:   t.Status,
			DepsOn:   t.DependsOn,
		})
	}
	// Sort by ID for a stable fingerprint regardless of slice order.
	sort.Slice(keys, func(i, j int) bool { return keys[i].ID < keys[j].ID })
	data, err := json.Marshal(keys)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// truncateHistStr truncates a string to n runes, appending "..." if truncated.
func truncateHistStr(s string, n int) string {
	runes := []rune(s)
	if len(runes) <= n {
		return s
	}
	return string(runes[:n]) + "..."
}
