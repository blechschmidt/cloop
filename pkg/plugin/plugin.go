// Package plugin implements discovery and execution of shell-script plugins
// for cloop. Plugins are executable files placed in .cloop/plugins/ (project-local)
// or ~/.cloop/plugins/ (global). Each plugin must implement a "describe" subcommand
// that prints a one-line description to stdout.
package plugin

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
)

// Plugin describes a discovered plugin.
type Plugin struct {
	Name        string // base filename without extension
	Path        string // absolute path to the executable
	Description string // output of `<plugin> describe`
	Scope       string // "local" (.cloop/plugins/) or "global" (~/.cloop/plugins/)
}

// Discover finds all executable plugin scripts in .cloop/plugins/ (workDir-relative)
// and ~/.cloop/plugins/ (global). Local plugins shadow global ones with the same name.
// Non-executable files and directories are silently skipped.
func Discover(workDir string) ([]*Plugin, error) {
	seen := make(map[string]bool)
	var plugins []*Plugin

	// Local first so they shadow global ones.
	localDir := filepath.Join(workDir, ".cloop", "plugins")
	local, err := discoverDir(localDir, "local", seen)
	if err != nil {
		return nil, err
	}
	plugins = append(plugins, local...)

	// Global plugins.
	home, err := os.UserHomeDir()
	if err == nil {
		globalDir := filepath.Join(home, ".cloop", "plugins")
		global, err := discoverDir(globalDir, "global", seen)
		if err != nil {
			return nil, err
		}
		plugins = append(plugins, global...)
	}

	sort.Slice(plugins, func(i, j int) bool {
		return plugins[i].Name < plugins[j].Name
	})
	return plugins, nil
}

// discoverDir scans dir for executable files. Names already in seen are skipped
// (allows local plugins to shadow global ones). seen is updated in place.
func discoverDir(dir, scope string, seen map[string]bool) ([]*Plugin, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("reading plugin dir %s: %w", dir, err)
	}

	var plugins []*Plugin
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := pluginName(e.Name())
		if seen[name] {
			continue
		}
		fullPath := filepath.Join(dir, e.Name())
		info, err := e.Info()
		if err != nil {
			continue
		}
		if !isExecutable(info) {
			continue
		}
		desc, _ := describe(fullPath)
		seen[name] = true
		plugins = append(plugins, &Plugin{
			Name:        name,
			Path:        fullPath,
			Description: desc,
			Scope:       scope,
		})
	}
	return plugins, nil
}

// pluginName strips the file extension from a plugin filename to derive its name.
// E.g. "lint.sh" → "lint", "deploy" → "deploy".
func pluginName(filename string) string {
	name := strings.TrimSuffix(filename, filepath.Ext(filename))
	return name
}

// Describe returns the one-line description of a plugin by running `<plugin> describe`.
// Returns an error if the describe subcommand fails or the output is empty.
func Describe(pluginPath string) (string, error) {
	desc, err := describe(pluginPath)
	if err != nil {
		return "", err
	}
	if desc == "" {
		return "", fmt.Errorf("plugin %s returned empty description", pluginPath)
	}
	return desc, nil
}

func describe(pluginPath string) (string, error) {
	cmd := exec.Command(pluginPath, "describe")
	var buf bytes.Buffer
	cmd.Stdout = &buf
	cmd.Stderr = nil
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("plugin describe failed: %w", err)
	}
	return strings.TrimSpace(buf.String()), nil
}

// Run executes a plugin by name with the given arguments and optional extra
// environment variables (KEY=value strings). The plugin process inherits the
// current process's stdio. extraEnv values are appended to os.Environ().
// workDir is used for discovery if the plugin is referenced by name (not path).
func Run(workDir, name string, args []string, extraEnv []string) error {
	path, err := Resolve(workDir, name)
	if err != nil {
		return err
	}
	cmd := exec.Command(path, args...)
	cmd.Env = append(os.Environ(), extraEnv...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("plugin %s: %w", name, err)
	}
	return nil
}

// Resolve finds the absolute path for a plugin name. It checks .cloop/plugins/
// before ~/.cloop/plugins/ and supports scripts with or without file extensions.
func Resolve(workDir, name string) (string, error) {
	home, _ := os.UserHomeDir()
	dirs := []string{
		filepath.Join(workDir, ".cloop", "plugins"),
	}
	if home != "" {
		dirs = append(dirs, filepath.Join(home, ".cloop", "plugins"))
	}

	for _, dir := range dirs {
		// Try exact match first, then with common script extensions.
		candidates := []string{
			filepath.Join(dir, name),
			filepath.Join(dir, name+".sh"),
			filepath.Join(dir, name+".py"),
			filepath.Join(dir, name+".rb"),
			filepath.Join(dir, name+".js"),
		}
		for _, p := range candidates {
			info, err := os.Stat(p)
			if err != nil {
				continue
			}
			if !info.IsDir() && isExecutable(info) {
				return p, nil
			}
		}
	}
	return "", fmt.Errorf("plugin %q not found in .cloop/plugins/ or ~/.cloop/plugins/", name)
}

func isExecutable(info os.FileInfo) bool {
	return info.Mode()&0o111 != 0
}
