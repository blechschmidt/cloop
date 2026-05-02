// Package multiui manages a registry of cloop projects for the multi-project
// web UI dashboard. The registry is persisted at ~/.cloop/projects.json.
package multiui

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/state"
)

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
		return nil, err
	}
	return reg.Projects, nil
}

// Save writes projects to the registry file.
func Save(projects []ProjectEntry) error {
	path, err := registryPath()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(registry{Projects: projects}, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o600)
}

// AddPaths appends new paths to the registry, avoiding duplicates, and saves.
func AddPaths(paths []string) error {
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
	return Save(existing)
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
	PMMode       bool      `json:"pm_mode"`
	HasProject   bool      `json:"has_project"` // false if no state file found
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
