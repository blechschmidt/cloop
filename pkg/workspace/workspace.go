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
)

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

// saveRegistry writes the registry to disk.
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
	return os.WriteFile(path, append(data, '\n'), 0o644)
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
	// Clear active marker if it pointed to this workspace.
	if GetActive() == name {
		_ = SetActive("")
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
	// Write breadcrumb pointer file in the workspace directory.
	pointerFile := filepath.Join(w.Path, ".cloop_workspace")
	if err := os.WriteFile(pointerFile, []byte(name+"\n"), 0o644); err != nil {
		return fmt.Errorf("writing workspace pointer: %w", err)
	}
	return SetActive(name)
}

// GetActive returns the currently active workspace name, or "" if none is set.
func GetActive() string {
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
	return os.WriteFile(path, []byte(name+"\n"), 0o644)
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
