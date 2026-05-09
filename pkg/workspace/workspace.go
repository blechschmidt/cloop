// Package workspace manages multiple cloop projects registered in a global registry.
// The registry is stored in ~/.config/cloop/workspaces.json (respecting XDG_CONFIG_HOME).
package workspace

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/blechschmidt/cloop/pkg/atomicfile"
)

// regMu serializes load → mutate → save sequences against the global registry.
// Without this, two concurrent Add/Remove/Switch calls each read the same
// baseline, mutate independently, and the second saver silently overwrites the
// first saver's changes (last-writer-wins). Same shape of bug as the one fixed
// in pkg/multiui/registry.go's AddPaths.
var regMu sync.Mutex

// Workspace represents a registered cloop project.
type Workspace struct {
	Name        string `json:"name"`
	Path        string `json:"path"`
	Description string `json:"description,omitempty"`
}

type registry struct {
	Workspaces []Workspace `json:"workspaces"`
}

// configDir returns the cloop global config directory.
// Respects XDG_CONFIG_HOME; falls back to ~/.config/cloop.
func configDir() (string, error) {
	if xdg := os.Getenv("XDG_CONFIG_HOME"); xdg != "" {
		return filepath.Join(xdg, "cloop"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".config", "cloop"), nil
}

// registryPath returns the path to ~/.config/cloop/workspaces.json.
func registryPath() (string, error) {
	dir, err := configDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "workspaces.json"), nil
}

// activeWorkspacePath returns the path to the active workspace file.
func activeWorkspacePath() (string, error) {
	dir, err := configDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "active_workspace"), nil
}

// load reads the registry from disk; returns empty registry if file does not exist.
func load() (*registry, error) {
	path, err := registryPath()
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return &registry{}, nil
	}
	if err != nil {
		return nil, err
	}
	var reg registry
	if err := json.Unmarshal(data, &reg); err != nil {
		return nil, fmt.Errorf("parsing workspace registry: %w", err)
	}
	return &reg, nil
}

// saveRegistry writes the registry to disk via an atomic tmp+fsync+rename so a
// crash, ENOSPC, or concurrent reader during the write can't observe a
// half-written or empty workspaces.json (which would silently unregister every
// project across the user's machine).
func saveRegistry(reg *registry) error {
	dir, err := configDir()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("creating config dir: %w", err)
	}
	path := filepath.Join(dir, "workspaces.json")
	data, err := json.MarshalIndent(reg, "", "  ")
	if err != nil {
		return err
	}
	return atomicfile.Write(path, append(data, '\n'), 0o644)
}

// List returns all registered workspaces.
func List() ([]Workspace, error) {
	reg, err := load()
	if err != nil {
		return nil, err
	}
	return reg.Workspaces, nil
}

// Add registers a workspace with the given name and path.
// If a workspace with the same name already exists it is updated.
// The path is resolved to an absolute path before storing.
func Add(name, path, description string) error {
	if name == "" {
		return fmt.Errorf("workspace name must not be empty")
	}
	absPath, err := filepath.Abs(path)
	if err != nil {
		return fmt.Errorf("resolving path: %w", err)
	}
	regMu.Lock()
	defer regMu.Unlock()
	reg, err := load()
	if err != nil {
		return err
	}
	for i, w := range reg.Workspaces {
		if w.Name == name {
			reg.Workspaces[i].Path = absPath
			reg.Workspaces[i].Description = description
			return saveRegistry(reg)
		}
	}
	reg.Workspaces = append(reg.Workspaces, Workspace{
		Name:        name,
		Path:        absPath,
		Description: description,
	})
	return saveRegistry(reg)
}

// Remove unregisters the workspace with the given name.
// Returns nil if the workspace does not exist (idempotent).
func Remove(name string) error {
	regMu.Lock()
	defer regMu.Unlock()
	reg, err := load()
	if err != nil {
		return err
	}
	filtered := reg.Workspaces[:0]
	for _, w := range reg.Workspaces {
		if w.Name != name {
			filtered = append(filtered, w)
		}
	}
	reg.Workspaces = filtered
	// Clear active marker if it pointed to this workspace. Read+write the
	// active marker directly here — calling SetActive() would re-acquire
	// regMu and deadlock.
	if getActiveLocked() == name {
		_ = setActiveLocked("")
	}
	return saveRegistry(reg)
}

// Get returns the workspace with the given name, or an error if not found.
func Get(name string) (*Workspace, error) {
	reg, err := load()
	if err != nil {
		return nil, err
	}
	for i := range reg.Workspaces {
		if reg.Workspaces[i].Name == name {
			return &reg.Workspaces[i], nil
		}
	}
	return nil, fmt.Errorf("workspace %q not found", name)
}

// Switch sets the given workspace as the active one and writes a .cloop_workspace
// pointer file inside the workspace directory as a local breadcrumb.
func Switch(name string) error {
	w, err := Get(name)
	if err != nil {
		return err
	}
	// Write breadcrumb pointer file atomically — a half-written pointer
	// (especially an empty one) silently re-routes future commands to the
	// default workspace and the user's edits land in the wrong project.
	pointerFile := filepath.Join(w.Path, ".cloop_workspace")
	if err := atomicfile.Write(pointerFile, []byte(name+"\n"), 0o644); err != nil {
		return fmt.Errorf("writing workspace pointer: %w", err)
	}
	return SetActive(name)
}

// GetActive returns the currently active workspace name, or "" if none is set.
func GetActive() string {
	regMu.Lock()
	defer regMu.Unlock()
	return getActiveLocked()
}

// getActiveLocked reads the active marker assuming regMu is already held.
func getActiveLocked() string {
	path, err := activeWorkspacePath()
	if err != nil {
		return ""
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

// SetActive persists the active workspace name. Pass "" to clear.
func SetActive(name string) error {
	regMu.Lock()
	defer regMu.Unlock()
	return setActiveLocked(name)
}

// setActiveLocked writes the active marker assuming regMu is already held.
// The marker is written atomically — a truncated or empty marker would
// silently fall back to the default workspace and route subsequent commands
// (and any edits/state writes they make) to the wrong project.
func setActiveLocked(name string) error {
	dir, err := configDir()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("creating config dir: %w", err)
	}
	path := filepath.Join(dir, "active_workspace")
	if name == "" {
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		return nil
	}
	return atomicfile.Write(path, []byte(name+"\n"), 0o644)
}

// ResolveWorkDir returns the working directory for the given workspace name.
// If name is empty, the current working directory is returned.
func ResolveWorkDir(name string) (string, error) {
	if name == "" {
		return os.Getwd()
	}
	w, err := Get(name)
	if err != nil {
		return "", err
	}
	return w.Path, nil
}
