// Package session manages named execution sessions with isolated state.
// Sessions allow teams to run multiple independent plan variants without
// overwriting each other. Each session stores its own state.db in
// .cloop/sessions/<name>/.
package session

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	sessionsDir     = ".cloop/sessions"
	activeFile      = ".cloop/active_session"
	sessionMetaFile = "session.json"
	sessionDBFile   = "state.db"
)

// sessionMu serialises in-process writes to .cloop/active_session and the
// per-session session.json + state.db copy that New performs. Switch is a
// single small write that the atomic-rename already protects across
// processes; the mutex is what stops two concurrent New("name") calls from
// both passing the existence check before either creates the directory.
var sessionMu sync.Mutex

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
//
// Runs under sessionMu so two concurrent New("foo") calls can't both pass
// the existence check and race on the mkdir.
func New(workDir, name string, copyFromDBPath string) (*Session, error) {
	if err := validateName(name); err != nil {
		return nil, err
	}

	sessionMu.Lock()
	defer sessionMu.Unlock()

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
		if err := atomicCopyFile(copyFromDBPath, filepath.Join(dir, sessionDBFile), 0o644); err != nil {
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
//
// The write to .cloop/active_session is atomic — a torn write (crash mid-
// write, ENOSPC) would leave a 0-byte file, and ActiveName would silently
// route every subsequent command to the default session, hiding the user's
// real working state.
func Switch(workDir, name string) error {
	sessionMu.Lock()
	defer sessionMu.Unlock()

	if name != "" {
		if _, err := load(workDir, name); err != nil {
			return fmt.Errorf("session %q not found", name)
		}
	}
	dir := filepath.Join(workDir, ".cloop")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	path := filepath.Join(workDir, activeFile)
	if name == "" {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return err
		}
		return nil
	}
	return writeAtomic(dir, path, ".active_session.*.tmp", []byte(name+"\n"), 0o644)
}

// Remove deletes a session. Returns an error if the session is currently active.
func Remove(workDir, name string) error {
	sessionMu.Lock()
	defer sessionMu.Unlock()

	// ActiveName re-reads the file rather than calling the public function
	// to avoid lock-ordering surprises if it ever takes sessionMu.
	if currentActive(workDir) == name {
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

func currentActive(workDir string) string {
	data, err := os.ReadFile(filepath.Join(workDir, activeFile))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

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
	return writeAtomic(dir, filepath.Join(dir, sessionMetaFile), ".session.json.*.tmp", data, 0o644)
}

// writeAtomic stages data in a sibling .tmp file under dir, fsyncs it, chmods,
// then renames into path. POSIX rename is atomic for readers, so any concurrent
// reader sees either the previous valid file or the new one — never a torn one.
func writeAtomic(dir, path, tmpPattern string, data []byte, mode os.FileMode) error {
	tmp, err := os.CreateTemp(dir, tmpPattern)
	if err != nil {
		return fmt.Errorf("session: create tmp: %w", err)
	}
	tmpPath := tmp.Name()
	defer func() {
		if _, statErr := os.Stat(tmpPath); statErr == nil {
			_ = os.Remove(tmpPath)
		}
	}()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("session: write tmp: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("session: sync tmp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("session: close tmp: %w", err)
	}
	if err := os.Chmod(tmpPath, mode); err != nil {
		return fmt.Errorf("session: chmod tmp: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("session: rename tmp: %w", err)
	}
	return nil
}

// atomicCopyFile streams src into a sibling .tmp under dst's directory then
// atomically renames it into dst. Used by New() when seeding a session's
// state.db from an existing project — a torn write would leave a half-copied
// SQLite file that opens to garbage.
func atomicCopyFile(src, dst string, mode os.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	dir := filepath.Dir(dst)
	tmp, err := os.CreateTemp(dir, ".state.db.*.tmp")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer func() {
		if _, statErr := os.Stat(tmpPath); statErr == nil {
			_ = os.Remove(tmpPath)
		}
	}()
	if _, err := io.Copy(tmp, in); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmpPath, mode); err != nil {
		return err
	}
	return os.Rename(tmpPath, dst)
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
