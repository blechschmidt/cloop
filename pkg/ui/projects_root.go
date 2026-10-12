package ui

// Where a project created by name goes (Task 20417).
//
// POST /api/projects/new takes the project's directory on the hub, which the
// dashboard's dialog asks a person for. `cloop remote init` runs in a checkout
// on a developer's machine and cannot know where this hub keeps projects — on
// the packaged image it is /var/lib/cloop/projects, on a host install it is
// wherever the operator likes — so it sends a name, and the hub places it under
// its projects root: ui.projects_root, or projects/ in the hub's home.

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/blechschmidt/cloop/pkg/state"
)

// maxProjectNameLen bounds a project name: a directory name a person types,
// which is also the project's name on every card and in every link.
const maxProjectNameLen = 100

// validProjectName accepts one path segment of letters, digits, dots,
// hyphens and underscores, starting with a letter or a digit. Nothing that
// could climb out of the projects root, start a flag, or hide.
func validProjectName(name string) error {
	if name == "" {
		return fmt.Errorf("a project name is required")
	}
	if len(name) > maxProjectNameLen {
		return fmt.Errorf("the project name is longer than %d characters", maxProjectNameLen)
	}
	for i, c := range name {
		alnum := c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9'
		if i == 0 && !alnum {
			return fmt.Errorf("project name %q must start with a letter or a digit", name)
		}
		if !alnum && c != '.' && c != '-' && c != '_' {
			return fmt.Errorf("project name %q may contain only letters, digits, dots, hyphens and underscores", name)
		}
	}
	return nil
}

// projectsRoot is the directory a project created by name is placed in.
func (s *Server) projectsRoot() (string, error) {
	cfg, err := s.loadHubConfig()
	if err != nil {
		return "", fmt.Errorf("this hub's configuration could not be read to find ui.projects_root: %v — "+
			"name a directory instead", err)
	}
	root := strings.TrimSpace(cfg.UI.ProjectsRoot)
	if root == "" {
		home, herr := os.UserHomeDir()
		if herr != nil || strings.TrimSpace(home) == "" {
			return "", fmt.Errorf("this hub has no ui.projects_root and no home directory to keep projects in: " +
				"set ui.projects_root, or name a directory")
		}
		root = filepath.Join(home, "projects")
	}
	if !filepath.IsAbs(root) {
		return "", fmt.Errorf("ui.projects_root is %q, which is not an absolute path: fix it in the hub's "+
			"configuration, or name a directory", root)
	}
	return filepath.Clean(root), nil
}

// projectExistsAt reports whether dir already holds a cloop project: its
// database, the database of the session active in it, or a legacy state.json
// that `cloop init` would read — and then overwrite.
func projectExistsAt(dir string) bool {
	for _, path := range []string{state.StateDBPath(dir), state.DBPath(dir), state.StatePath(dir)} {
		if _, err := os.Stat(path); err == nil {
			return true
		}
	}
	return false
}
