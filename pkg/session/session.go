// Package session manages named execution sessions with isolated state.
// Sessions allow teams to run multiple independent plan variants without
// overwriting each other. Each session stores its own state.db in
// .cloop/sessions/<name>/.
package session

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	sessionsDir     = ".cloop/sessions"
	activeFile      = ".cloop/active_session"
	sessionMetaFile = "session.json"
	sessionDBFile   = "state.db"
)

// Session describes a named execution session.
type Session struct {
	Name        string    `json:"name"`
	CreatedAt   time.Time `json:"created_at"`
	StateFile   string    `json:"state_file"`   // relative path from workDir
	ConfigFile  string    `json:"config_file"`  // relative path from workDir
}

// Dir returns the absolute path to the session directory.
func Dir(workDir, name string) string {
	return filepath.Join(workDir, sessionsDir, name)
}

// DBPath returns the absolute path to the session's state.db.
func DBPath(workDir, name string) string {
	return filepath.Join(Dir(workDir, name), sessionDBFile)
}

// ActiveName returns the currently active session name, or "" for the default.
func ActiveName(workDir string) string {
	data, err := os.ReadFile(filepath.Join(workDir, activeFile))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

// ActiveDir returns the effective state directory:
//   - workDir if no session is active
//   - workDir/.cloop/sessions/<name> if a session is active
func ActiveDir(workDir string) string {
	name := ActiveName(workDir)
	if name == "" {
		return workDir
	}
	return Dir(workDir, name)
}

// New creates a new session directory and metadata file.
// If copyFromDBPath is non-empty, that state.db is copied into the new session.
func New(workDir, name string, copyFromDBPath string) (*Session, error) {
	if err := validateName(name); err != nil {
		return nil, err
	}

	dir := Dir(workDir, name)
	if _, err := os.Stat(dir); err == nil {
		return nil, fmt.Errorf("session %q already exists", name)
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("create session dir: %w", err)
	}

	sess := &Session{
		Name:       name,
		CreatedAt:  time.Now(),
		StateFile:  filepath.Join(sessionsDir, name, sessionDBFile),
		ConfigFile: ".cloop/config.yaml",
	}

	if copyFromDBPath != "" {
		if err := copyFile(copyFromDBPath, filepath.Join(dir, sessionDBFile)); err != nil {
			return nil, fmt.Errorf("copy state: %w", err)
		}
	}

	if err := writeMeta(dir, sess); err != nil {
		return nil, err
	}
	return sess, nil
}

// List returns all sessions for the given project.
func List(workDir string) ([]*Session, error) {
	base := filepath.Join(workDir, sessionsDir)
	entries, err := os.ReadDir(base)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	var sessions []*Session
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		sess, err := load(workDir, e.Name())
		if err != nil {
			continue // skip corrupt entries
		}
		sessions = append(sessions, sess)
	}
	return sessions, nil
}

// Switch sets the active session. Pass "" to clear (use default).
func Switch(workDir, name string) error {
	if name != "" {
		if _, err := load(workDir, name); err != nil {
			return fmt.Errorf("session %q not found", name)
		}
	}
	path := filepath.Join(workDir, activeFile)
	if name == "" {
		return os.Remove(path)
	}
	return os.WriteFile(path, []byte(name+"\n"), 0o644)
}

// Remove deletes a session. Returns an error if the session is currently active.
func Remove(workDir, name string) error {
	if ActiveName(workDir) == name {
		return fmt.Errorf("session %q is currently active; switch to another session first", name)
	}
	dir := Dir(workDir, name)
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		return fmt.Errorf("session %q not found", name)
	}
	return os.RemoveAll(dir)
}

// ────────────────────────────────────────────────────────────
// Helpers
// ────────────────────────────────────────────────────────────

func load(workDir, name string) (*Session, error) {
	dir := Dir(workDir, name)
	data, err := os.ReadFile(filepath.Join(dir, sessionMetaFile))
	if err != nil {
		return nil, err
	}
	var sess Session
	if err := json.Unmarshal(data, &sess); err != nil {
		return nil, err
	}
	return &sess, nil
}

func writeMeta(dir string, sess *Session) error {
	data, err := json.MarshalIndent(sess, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, sessionMetaFile), data, 0o644)
}

func copyFile(src, dst string) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, data, 0o644)
}

func validateName(name string) error {
	if name == "" {
		return fmt.Errorf("session name cannot be empty")
	}
	for _, c := range name {
		if !isValidNameChar(c) {
			return fmt.Errorf("session name %q contains invalid character %q (use letters, digits, hyphens, underscores)", name, string(c))
		}
	}
	return nil
}

func isValidNameChar(c rune) bool {
	return (c >= 'a' && c <= 'z') ||
		(c >= 'A' && c <= 'Z') ||
		(c >= '0' && c <= '9') ||
		c == '-' || c == '_'
}
