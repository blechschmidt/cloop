// Package multiui manages a registry of cloop projects for the multi-project
// web UI dashboard. The registry is persisted at ~/.cloop/projects.json.
package multiui

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/blechschmidt/cloop/pkg/atomicfile"
	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/state"
)

// registryMu serializes the read-modify-write performed by AddPaths so that
// concurrent UI-server handlers (or any other in-process callers) cannot lose
// each other's writes when both load → mutate → save the same file.
//
// This is in-process only — multiple cloop CLI processes that race to write
// the registry at the same moment can still drop updates, but Save's atomic
// rename guarantees the file on disk is never observed truncated/corrupt
// (last-writer-wins instead of partial-data-wins).
var registryMu sync.Mutex

// IsCloopRunningInDir returns true if a "cloop run" process has its working
// directory set to dir. It reads /proc/*/cwd symlinks (Linux only).
func IsCloopRunningInDir(dir string) bool {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return false
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		pid := e.Name()
		// Only numeric entries are PIDs.
		allDigits := true
		for _, c := range pid {
			if c < '0' || c > '9' {
				allDigits = false
				break
			}
		}
		if !allDigits {
			continue
		}
		// Check executable name.
		exePath, err := os.Readlink("/proc/" + pid + "/exe")
		if err != nil {
			continue
		}
		if !strings.HasSuffix(exePath, "/cloop") && !strings.HasSuffix(exePath, "cloop") {
			continue
		}
		// Check cmdline to ensure it's "cloop run", not "cloop ui" etc.
		cmdline, err := os.ReadFile("/proc/" + pid + "/cmdline")
		if err != nil {
			continue
		}
		cmdParts := strings.Split(string(cmdline), "\x00")
		isCloopRun := false
		for _, part := range cmdParts {
			if part == "run" {
				isCloopRun = true
				break
			}
		}
		if !isCloopRun {
			continue
		}
		// Check working directory.
		cwd, err := os.Readlink("/proc/" + pid + "/cwd")
		if err != nil {
			continue
		}
		if cwd == dir {
			return true
		}
	}
	return false
}

// ProjectEntry is a registered project in the multi-project registry.
type ProjectEntry struct {
	Name string `json:"name"`
	Path string `json:"path"`
}

type registry struct {
	Projects []ProjectEntry `json:"projects"`
}

// registryPath returns ~/.cloop/projects.json.
func registryPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".cloop", "projects.json"), nil
}

// Load reads the registry from disk; returns an empty registry if file is absent.
//
// On parse failure (zero-byte file from a torn pre-atomicfile write, schema
// drift, manual edit gone wrong) the corrupt projects.json is quarantined
// aside as projects.json.corrupt-<unix> and (nil, nil) is returned. The
// multi-project Web UI dashboard is the worst pre-fix case here: a bad save
// in this global registry bricked every "cloop ui" multi-project listing
// across all projects on the host. Returning empty is a recoverable state —
// the user re-adds projects via `cloop ui add` — whereas a hard error
// disabled the entire dashboard.
func Load() ([]ProjectEntry, error) {
	path, err := registryPath()
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var reg registry
	if err := json.Unmarshal(data, &reg); err != nil {
		qpath := atomicfile.QuarantineCorrupt(path)
		if qpath != "" {
			fmt.Fprintf(os.Stderr, "warning: multi-project registry at %s was corrupt (%v); quarantined to %s, starting fresh\n", path, err, qpath)
		} else {
			fmt.Fprintf(os.Stderr, "warning: multi-project registry at %s was corrupt (%v) and could not be quarantined; ignoring\n", path, err)
		}
		return nil, nil
	}
	return reg.Projects, nil
}

// Save writes projects to the registry file atomically: it serialises the JSON,
// writes it to a sibling tmp file, fsyncs, and renames into place. A crash or
// disk-full mid-write therefore leaves the previous registry intact instead of
// a half-written / zero-byte projects.json that future loads would refuse.
func Save(projects []ProjectEntry) error {
	registryMu.Lock()
	defer registryMu.Unlock()
	return saveLocked(projects)
}

// saveLocked is the same as Save without acquiring registryMu. Callers that
// already hold the lock (e.g. AddPaths' read-modify-write block) use this so
// they don't deadlock against themselves.
func saveLocked(projects []ProjectEntry) error {
	path, err := registryPath()
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(registry{Projects: projects}, "", "  ")
	if err != nil {
		return err
	}

	tmp, err := os.CreateTemp(dir, ".projects.json.*.tmp")
	if err != nil {
		return fmt.Errorf("multiui: create tmp: %w", err)
	}
	tmpPath := tmp.Name()
	// Best-effort cleanup if anything below fails before the rename completes.
	defer func() {
		if _, statErr := os.Stat(tmpPath); statErr == nil {
			_ = os.Remove(tmpPath)
		}
	}()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("multiui: write tmp: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("multiui: sync tmp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("multiui: close tmp: %w", err)
	}
	// Match the 0o600 the legacy WriteFile used; CreateTemp defaults to 0o600
	// already on Unix, but be explicit so this survives platform changes.
	if err := os.Chmod(tmpPath, 0o600); err != nil {
		return fmt.Errorf("multiui: chmod tmp: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("multiui: rename tmp: %w", err)
	}
	return nil
}

// AddPaths appends new paths to the registry, avoiding duplicates, and saves.
// The load-mutate-save sequence runs under registryMu so two concurrent
// in-process callers cannot each load the same baseline and then race to
// overwrite each other's additions.
func AddPaths(paths []string) error {
	registryMu.Lock()
	defer registryMu.Unlock()

	// Load does not take registryMu, so calling it while we hold the lock
	// does not deadlock. Reads are safe even mid-Save because Save publishes
	// the new file via atomic rename.
	existing, err := Load()
	if err != nil {
		return err
	}
	seen := make(map[string]bool)
	for _, e := range existing {
		seen[e.Path] = true
	}
	for _, p := range paths {
		abs, err := filepath.Abs(p)
		if err != nil {
			continue
		}
		if seen[abs] {
			continue
		}
		seen[abs] = true
		name := filepath.Base(abs)
		existing = append(existing, ProjectEntry{Name: name, Path: abs})
	}
	return saveLocked(existing)
}

// Scan walks a parent directory one level deep and returns all subdirectories
// (including the directory itself) that contain a .cloop/ folder.
func Scan(dir string) ([]string, error) {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return nil, err
	}
	var found []string
	// Check the directory itself.
	if hasCloop(abs) {
		found = append(found, abs)
	}
	entries, err := os.ReadDir(abs)
	if err != nil {
		return found, nil //nolint:nilerr
	}
	for _, e := range entries {
		if !e.IsDir() || strings.HasPrefix(e.Name(), ".") {
			continue
		}
		sub := filepath.Join(abs, e.Name())
		if hasCloop(sub) {
			found = append(found, sub)
		}
	}
	return found, nil
}

// hasCloop returns true if dir/.cloop exists.
func hasCloop(dir string) bool {
	_, err := os.Stat(filepath.Join(dir, ".cloop"))
	return err == nil
}

// ────────────────────────────────────────────────────────────────────────────
// ProjectStatus — live snapshot of a project's health for the dashboard.
// ────────────────────────────────────────────────────────────────────────────

// Health is a high-level project health indicator.
type Health string

const (
	HealthRunning  Health = "running"
	HealthStalled  Health = "stalled"
	HealthFailed   Health = "failed"
	HealthComplete Health = "complete"
	HealthIdle     Health = "idle"
	HealthUnknown  Health = "unknown"
)

// ProjectStatus is the live status of a project, returned by the /api/projects endpoint.
type ProjectStatus struct {
	Name         string    `json:"name"`
	Path         string    `json:"path"`
	Status       string    `json:"status"`        // state.Status field value
	Health       Health    `json:"health"`        // computed indicator
	Goal         string    `json:"goal"`
	TotalTasks   int       `json:"total_tasks"`
	DoneTasks    int       `json:"done_tasks"`
	FailedTasks  int       `json:"failed_tasks"`
	ActiveTasks  int       `json:"active_tasks"`
	TotalSteps   int       `json:"total_steps"`
	LastActivity time.Time `json:"last_activity"`
	Provider     string    `json:"provider,omitempty"`
	Model        string    `json:"model,omitempty"`
	PMMode       bool      `json:"pm_mode"`
	HasProject   bool      `json:"has_project"` // false if no state file found
	Running      bool      `json:"running"`     // true if cloop run is actually executing
}

// GetStatus loads the state for the project at path and returns a ProjectStatus.
func GetStatus(entry ProjectEntry) ProjectStatus {
	ps := ProjectStatus{
		Name:   entry.Name,
		Path:   entry.Path,
		Health: HealthUnknown,
	}
	st, err := state.Load(entry.Path)
	if err != nil {
		ps.HasProject = false
		ps.Health = HealthUnknown
		return ps
	}
	ps.HasProject = true
	ps.Goal = st.Goal
	ps.Status = st.Status
	ps.TotalSteps = len(st.Steps)
	ps.Provider = st.Provider
	ps.Model = st.Model
	// Fall back to config model when state doesn't have one
	if ps.Model == "" {
		if cfg, cfgErr := config.Load(entry.Path); cfgErr == nil {
			switch ps.Provider {
			case "anthropic":
				ps.Model = cfg.Anthropic.Model
			case "openai":
				ps.Model = cfg.OpenAI.Model
			case "ollama":
				ps.Model = cfg.Ollama.Model
			case "claudecode":
				ps.Model = cfg.ClaudeCode.Model
				if ps.Model == "" {
					ps.Model = "claude-sonnet-4-6" // Claude Code default
				}
			}
		}
	}
	ps.PMMode = st.PMMode
	ps.LastActivity = st.UpdatedAt

	if st.Plan != nil {
		for _, t := range st.Plan.Tasks {
			ps.TotalTasks++
			switch t.Status {
			case pm.TaskDone:
				ps.DoneTasks++
			case pm.TaskFailed, pm.TaskTimedOut:
				ps.FailedTasks++
			case pm.TaskInProgress:
				ps.ActiveTasks++
			}
		}
	}

	ps.Health = computeHealth(st)
	ps.Running = IsCloopRunningInDir(entry.Path)
	return ps
}

// computeHealth derives a Health indicator from the project state.
func computeHealth(st *state.ProjectState) Health {
	switch st.Status {
	case "running", "evolving":
		// If state was updated recently the run is still active — never stalled.
		if !st.UpdatedAt.IsZero() && time.Since(st.UpdatedAt) <= 15*time.Minute {
			return HealthRunning
		}
		// Check for stall: last step older than 15 minutes while status is running.
		if len(st.Steps) > 0 {
			last := st.Steps[len(st.Steps)-1].Time
			if !last.IsZero() && time.Since(last) > 15*time.Minute {
				return HealthStalled
			}
		}
		// If we have no steps but UpdatedAt is older than 15 min, consider stalled.
		if !st.UpdatedAt.IsZero() && time.Since(st.UpdatedAt) > 15*time.Minute {
			return HealthStalled
		}
		return HealthRunning
	case "complete":
		return HealthComplete
	case "failed":
		return HealthFailed
	case "paused", "initialized":
		return HealthIdle
	default:
		if st.Goal != "" {
			return HealthIdle
		}
		return HealthUnknown
	}
}

// AggregateStats holds aggregated metrics across all projects.
type AggregateStats struct {
	TotalProjects int `json:"total_projects"`
	ActiveRuns    int `json:"active_runs"`
	TotalTasks    int `json:"total_tasks"`
	DoneTasks     int `json:"done_tasks"`
	FailedTasks   int `json:"failed_tasks"`
	TotalSteps    int `json:"total_steps"`
}

// Aggregate computes aggregate stats from a slice of project statuses.
func Aggregate(statuses []ProjectStatus) AggregateStats {
	var a AggregateStats
	for _, s := range statuses {
		a.TotalProjects++
		if s.Health == HealthRunning {
			a.ActiveRuns++
		}
		a.TotalTasks += s.TotalTasks
		a.DoneTasks += s.DoneTasks
		a.FailedTasks += s.FailedTasks
		a.TotalSteps += s.TotalSteps
	}
	return a
}
