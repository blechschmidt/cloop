package pm

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/blechschmidt/cloop/pkg/atomicfile"
)

const historyDir = ".cloop/plan-history"

// historyMu serialises SaveSnapshot. Two concurrent callers (e.g. a CLI
// snapshot save racing with the orchestrator's auto-save on task transition)
// would otherwise both read the same "latest" version, both increment to
// version N+1, and write two files at the same version — one clobbering the
// other or producing duplicate-versioned snapshots.
var historyMu sync.Mutex

// DefaultSnapshotRetention is how many plan snapshots SaveSnapshot keeps on
// disk (Task 20229).
//
// Every mutation of the plan writes a full copy of it, so an unbounded history
// grows without limit in proportion to how much work a project does — not to
// how much state it holds. This repository's own history reached 3,983 files
// and 2.0 GB, which is 40% of its .cloop directory and larger than the state
// database it describes.
//
// The bound is enforced here, at write time, rather than only by the periodic
// janitor, because a busy project can write thousands of snapshots between two
// janitor passes. A write-time bound makes the directory's size a function of
// the policy alone; the janitor then only has to catch up existing installs
// and re-apply a lowered keep-count.
//
// 50 is deliberately more generous than `cloop compact`'s KeepSnapshots of 10
// — this runs unattended, so it should destroy less than the tool an operator
// invokes on purpose — while still bounding the directory at roughly 25 MB at
// this repository's average snapshot size. Commands that reach far back into
// history (`cloop diff`, `cloop scope creep`, `cloop rollback`) address
// snapshots by version, and a pruned version reports "not found" rather than
// returning wrong data.
const DefaultSnapshotRetention = 50

// snapshotRetention is the live keep-count, settable at runtime so the hub can
// apply an operator's configured policy (config `retention.keep_snapshots`)
// to the in-process writers — the orchestrator and every UI mutation — without
// threading it through the twelve call sites of SaveSnapshot.
//
// Zero or negative means "keep everything", which is the pre-Task-20229
// behaviour and what an operator gets by explicitly opting out.
var snapshotRetention atomic.Int64

func init() { snapshotRetention.Store(DefaultSnapshotRetention) }

// SetSnapshotRetention sets how many snapshots SaveSnapshot keeps. A value of
// zero or less disables write-time pruning entirely.
func SetSnapshotRetention(keep int) {
	if keep < 0 {
		keep = 0
	}
	snapshotRetention.Store(int64(keep))
}

// SnapshotRetention reports the process-wide write-time keep-count. Zero means
// pruning is disabled.
func SnapshotRetention() int { return int(snapshotRetention.Load()) }

// retentionResolver, when set, answers the keep-count for a specific project,
// overriding the process-wide value.
//
// The hub needs this because it is the one writer that serves many projects
// from one process: pkg/state's Save calls SaveSnapshot for whichever project
// a request touched, so a single process-wide number would apply the control
// plane's policy to every tenant — silently pruning the history of a project
// whose own config said to keep it. A resolver keeps the value a property of
// the project rather than of the process.
//
// Guarded by its own mutex rather than an atomic: it is written once at
// startup and read on every save, and a func value cannot be stored atomically
// without an interface box.
var (
	retentionMu       sync.RWMutex
	retentionResolver func(workDir string) int
)

// SetSnapshotRetentionResolver installs a per-project keep-count lookup. Pass
// nil to fall back to the process-wide value set by SetSnapshotRetention.
//
// The resolver is called on every snapshot write, so it must be cheap and must
// not call back into this package.
func SetSnapshotRetentionResolver(fn func(workDir string) int) {
	retentionMu.Lock()
	defer retentionMu.Unlock()
	retentionResolver = fn
}

// snapshotRetentionFor returns the keep-count that governs workDir.
func snapshotRetentionFor(workDir string) int {
	retentionMu.RLock()
	fn := retentionResolver
	retentionMu.RUnlock()
	if fn == nil {
		return SnapshotRetention()
	}
	return fn(workDir)
}

// PruneStats reports what a snapshot prune removed.
type PruneStats struct {
	// Deleted counts snapshot files removed (or, for a dry run, that would
	// have been removed).
	Deleted int
	// BytesFreed sums their sizes.
	BytesFreed int64
	// Remaining counts the snapshots left behind.
	Remaining int
}

// PruneSnapshots deletes all but the `keep` newest snapshots in workDir's
// plan-history directory, newest by version number.
//
// keep <= 0 is a no-op: it means "retention disabled", not "delete
// everything". Callers that want an empty history should remove the directory
// themselves, so that a mis-parsed or zero-valued config can never be the
// instruction that destroys a project's history.
//
// Files that do not parse as snapshots are left strictly alone — including the
// `.corrupt-<unix>` siblings LoadSnapshot quarantines, which are forensic
// evidence that something wrote a bad snapshot and are not ours to reclaim.
func PruneSnapshots(workDir string, keep int, dryRun bool) (PruneStats, error) {
	historyMu.Lock()
	defer historyMu.Unlock()
	return pruneSnapshotsLocked(historyPath(workDir), keep, dryRun)
}

// pruneSnapshotsLocked is the body of PruneSnapshots, split out so SaveSnapshot
// can prune while it already holds historyMu.
func pruneSnapshotsLocked(dir string, keep int, dryRun bool) (PruneStats, error) {
	var st PruneStats
	if keep <= 0 {
		return st, nil
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return st, nil
		}
		return st, fmt.Errorf("read plan-history: %w", err)
	}

	// Order by version, not by filename. The two agree in practice because
	// filenames lead with a timestamp, but version is the authoritative
	// sequence — SaveSnapshot anchors it to max(caller's version, on-disk
	// max)+1 precisely so concurrent writers cannot reuse one — and a clock
	// that stepped backwards would otherwise make the oldest-first ordering
	// delete the wrong files.
	type snapFile struct {
		name    string
		version int
	}
	var files []snapFile
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		v, ok := snapshotVersionFromName(e.Name())
		if !ok {
			continue
		}
		files = append(files, snapFile{name: e.Name(), version: v})
	}

	st.Remaining = len(files)
	if len(files) <= keep {
		return st, nil
	}
	sort.Slice(files, func(i, j int) bool {
		if files[i].version != files[j].version {
			return files[i].version < files[j].version
		}
		return files[i].name < files[j].name
	})

	var firstErr error
	for _, f := range files[:len(files)-keep] {
		path := filepath.Join(dir, f.name)
		fi, err := os.Stat(path)
		if err != nil {
			continue
		}
		if !dryRun {
			if err := os.Remove(path); err != nil {
				// Keep going: one undeletable file (permissions, a concurrent
				// reader on Windows) must not leave the rest of the backlog in
				// place. Report the first failure so the caller can surface it.
				if firstErr == nil {
					firstErr = fmt.Errorf("remove snapshot %s: %w", f.name, err)
				}
				continue
			}
		}
		st.Deleted++
		st.BytesFreed += fi.Size()
		st.Remaining--
	}
	return st, firstErr
}

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

// snapshotVersionFromName extracts N from a snapshot filename of the form
// <timestamp>-v<N>.json, the shape snapshotFilename writes. Quarantined
// siblings (<name>.corrupt-<unix>) and unrelated files yield ok=false.
func snapshotVersionFromName(name string) (int, bool) {
	if !strings.HasSuffix(name, ".json") || strings.Contains(name, ".corrupt-") {
		return 0, false
	}
	base := strings.TrimSuffix(name, ".json")
	i := strings.LastIndex(base, "-v")
	if i < 0 {
		return 0, false
	}
	v, err := strconv.Atoi(base[i+len("-v"):])
	if err != nil || v < 0 {
		return 0, false
	}
	return v, true
}

// latestSnapshotVersion returns the highest version present in the history
// directory, derived from filenames alone — it opens no snapshot files.
// Returns 0 when the directory is absent or holds no parseable snapshot.
func latestSnapshotVersion(dir string) int {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0
	}
	max := 0
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if v, ok := snapshotVersionFromName(e.Name()); ok && v > max {
			max = v
		}
	}
	return max
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

	historyMu.Lock()
	defer historyMu.Unlock()

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
	//
	// The version and the newest file are both derivable from filenames, so
	// resolve them with a dirent scan plus one targeted read. Calling
	// ListSnapshots here instead — as this did — reads and unmarshals *every*
	// snapshot, and each snapshot is a full copy of the plan. On a long-lived
	// project that is the dominant cost of saving state: 3.8k snapshots
	// averaging ~525 KiB meant ~1.9 GiB of JSON parsed per save, which put a
	// ~16s stall behind every task add, status change and edit in the UI.
	latestOnDisk := latestSnapshotVersion(dir)
	if latestOnDisk > 0 {
		// A corrupt newest snapshot fails to load (and is quarantined by
		// LoadSnapshot); fall through and write a fresh one rather than
		// deduplicating against nothing. That self-heals on the next save.
		if last, loadErr := LoadSnapshot(workDir, latestOnDisk); loadErr == nil && last.Plan != nil {
			lastFP, fpErr := planFingerprint(last.Plan)
			if fpErr == nil && lastFP == fingerprint {
				return nil // no change
			}
		}
	}

	// Pick the next version. Bumping plan.Version alone is insufficient when
	// distinct Plan instances share a history dir (e.g. cross-process callers,
	// or two writers each starting from a freshly-loaded Plan): both could land
	// on the same version and produce duplicate filenames where the rename
	// silently clobbers the loser. Anchor the next version to whichever is
	// greater — the caller's plan.Version+1 or the on-disk max+1 — so the
	// version sequence is strictly monotonic across all writers.
	next := plan.Version + 1
	if latestOnDisk+1 > next {
		next = latestOnDisk + 1
	}
	plan.Version = next

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
	if err := atomicfile.Write(path, data, 0o644); err != nil {
		return err
	}

	// Bound the directory in the same call that grew it (Task 20229). The
	// snapshot just written has the highest version, so it always survives.
	//
	// A prune failure is reported but does not fail the save: the snapshot is
	// on disk and the caller's state is durable, and returning an error here
	// would make a read-only plan-history directory look like a failure to
	// persist the plan. The janitor retries on its next pass.
	if keep := snapshotRetentionFor(workDir); keep > 0 {
		if _, err := pruneSnapshotsLocked(dir, keep, false); err != nil {
			fmt.Fprintf(os.Stderr, "warning: plan-history retention (keep %d): %v\n", keep, err)
		}
	}
	return nil
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
			path := filepath.Join(dir, e.Name())
			data, err := os.ReadFile(path)
			if err != nil {
				return nil, fmt.Errorf("read snapshot %s: %w", e.Name(), err)
			}
			var snap Snapshot
			if err := json.Unmarshal(data, &snap); err != nil {
				// Quarantine the bad snapshot so subsequent snapshot/diff/restore
				// commands stop tripping over it. The bytes are preserved as a
				// .corrupt-<unix> sibling for forensic inspection. We surface the
				// error so the user sees that *this specific version* is gone,
				// but other versions remain loadable.
				qpath := atomicfile.QuarantineCorrupt(path)
				if qpath != "" {
					fmt.Fprintf(os.Stderr, "warning: plan-history snapshot %s was corrupt (%v); quarantined to %s\n", path, err, qpath)
				} else {
					fmt.Fprintf(os.Stderr, "warning: plan-history snapshot %s was corrupt (%v) and could not be quarantined\n", path, err)
				}
				return nil, fmt.Errorf("snapshot v%d corrupt and quarantined: %w", version, err)
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
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".json") {
			continue
		}
		// Skip already-quarantined siblings (atomicfile.QuarantineCorrupt
		// renames bad files to <name>.corrupt-<unix>) — they're forensic
		// artefacts, not snapshots.
		if strings.Contains(name, ".corrupt-") {
			continue
		}
		path := filepath.Join(dir, name)
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		var snap Snapshot
		if err := json.Unmarshal(data, &snap); err != nil {
			// Quarantine instead of silently re-skipping forever. Without this,
			// a bad snapshot lingers and gets re-read on every `cloop snapshot
			// list`, wasting I/O and masking real corruption from the user.
			qpath := atomicfile.QuarantineCorrupt(path)
			if qpath != "" {
				fmt.Fprintf(os.Stderr, "warning: plan-history snapshot %s was corrupt (%v); quarantined to %s\n", path, err, qpath)
			}
			continue
		}
		// LoadSnapshot fingerprinting in SaveSnapshot dereferences snap.Plan; a
		// nil plan in a partially-written file would panic this loop. Defensive
		// nil-check costs nothing.
		if snap.Plan == nil {
			continue
		}
		metas = append(metas, &SnapshotMeta{
			Version:   snap.Version,
			Timestamp: snap.Timestamp,
			Filename:  name,
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

// RestoreSnapshot loads the snapshot identified by snapshotID (a version number
// as a string, e.g. "3") and returns its Plan. The caller is responsible for
// persisting the returned plan back to state.
func RestoreSnapshot(workDir, snapshotID string) (*Plan, error) {
	var version int
	if _, err := fmt.Sscanf(snapshotID, "%d", &version); err != nil {
		return nil, fmt.Errorf("invalid snapshot ID %q: must be a version number", snapshotID)
	}
	snap, err := LoadSnapshot(workDir, version)
	if err != nil {
		return nil, err
	}
	return snap.Plan, nil
}

// truncateHistStr truncates a string to n runes, appending "..." if truncated.
func truncateHistStr(s string, n int) string {
	runes := []rune(s)
	if len(runes) <= n {
		return s
	}
	return string(runes[:n]) + "..."
}
