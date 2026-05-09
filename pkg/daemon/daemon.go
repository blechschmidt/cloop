// Package daemon manages the cloop background daemon process.
// It stores PID in .cloop/daemon.pid, state in .cloop/daemon.json,
// and log output in .cloop/daemon.log.
package daemon

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"
)

// saveMu serializes concurrent State.Save and WritePID calls per workdir to
// prevent two goroutines from racing on the .cloop/daemon.json or
// .cloop/daemon.pid file. The daemon worker process mutates State from at least
// three goroutines (main tick loop, file-watcher goroutine, file-watcher
// callback), and previously called Save without coordination — torn writes
// surfaced to operators as "corrupt daemon state" parse errors from Load.
var (
	saveMuMapMu sync.Mutex
	saveMuMap   = make(map[string]*sync.Mutex)
)

func lockForPath(path string) *sync.Mutex {
	saveMuMapMu.Lock()
	defer saveMuMapMu.Unlock()
	if m, ok := saveMuMap[path]; ok {
		return m
	}
	m := &sync.Mutex{}
	saveMuMap[path] = m
	return m
}

const (
	pidFile   = ".cloop/daemon.pid"
	stateFile = ".cloop/daemon.json"
	logFile   = ".cloop/daemon.log"
)

// State tracks the daemon's runtime status, persisted to .cloop/daemon.json.
type State struct {
	PID                 int       `json:"pid"`
	StartedAt           time.Time `json:"started_at"`
	LastRunAt           time.Time `json:"last_run_at,omitempty"`
	NextRunAt           time.Time `json:"next_run_at,omitempty"`
	RunCount            int       `json:"run_count"`
	TotalTasksCompleted int       `json:"total_tasks_completed"`
	TotalTasksFailed    int       `json:"total_tasks_failed"`
	Status              string    `json:"status"` // starting, idle, running, stopped, error
	Interval            string    `json:"interval"`
	Provider            string    `json:"provider,omitempty"`
	Model               string    `json:"model,omitempty"`
	LastError           string    `json:"last_error,omitempty"`
	WatchEnabled        bool      `json:"watch_enabled,omitempty"`
	WatchTriggers       int       `json:"watch_triggers,omitempty"`
}

// PIDPath returns the absolute path to the PID file.
func PIDPath(workdir string) string {
	return filepath.Join(workdir, pidFile)
}

// StatePath returns the absolute path to the daemon state file.
func StatePath(workdir string) string {
	return filepath.Join(workdir, stateFile)
}

// LogPath returns the absolute path to the daemon log file.
func LogPath(workdir string) string {
	return filepath.Join(workdir, logFile)
}

// Load reads the daemon state from disk; returns nil if not found.
func Load(workdir string) (*State, error) {
	data, err := os.ReadFile(StatePath(workdir))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var s State
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, fmt.Errorf("corrupt daemon state: %w", err)
	}
	return &s, nil
}

// Save writes the daemon state to disk atomically. The write is serialized
// per-workdir so concurrent Save calls from the daemon worker's goroutines
// never produce a torn or partially-written .cloop/daemon.json file.
func (s *State) Save(workdir string) error {
	dir := filepath.Join(workdir, ".cloop")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	path := StatePath(workdir)
	mu := lockForPath(path)
	mu.Lock()
	defer mu.Unlock()
	return writeAtomic(path, data, 0o644)
}

// WritePID writes the daemon PID to .cloop/daemon.pid atomically.
func WritePID(workdir string, pid int) error {
	dir := filepath.Join(workdir, ".cloop")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	path := PIDPath(workdir)
	mu := lockForPath(path)
	mu.Lock()
	defer mu.Unlock()
	return writeAtomic(path, []byte(fmt.Sprintf("%d", pid)), 0o644)
}

// writeAtomic writes data to path via a sibling tmp file, fsyncs, then renames.
// A crash, ENOSPC, or a concurrent reader during the write can no longer leave
// the destination half-written — Load() previously failed with "corrupt daemon
// state" when daemon.json was found in a torn state, breaking `cloop daemon
// status` for the entire user.
func writeAtomic(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".*.tmp")
	if err != nil {
		return fmt.Errorf("daemon: create tmp: %w", err)
	}
	tmpPath := tmp.Name()
	defer func() {
		if _, statErr := os.Stat(tmpPath); statErr == nil {
			_ = os.Remove(tmpPath)
		}
	}()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("daemon: write tmp: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("daemon: sync tmp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("daemon: close tmp: %w", err)
	}
	if err := os.Chmod(tmpPath, mode); err != nil {
		return fmt.Errorf("daemon: chmod tmp: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("daemon: rename tmp: %w", err)
	}
	return nil
}

// ReadPID reads the daemon PID from .cloop/daemon.pid; returns 0 if not found.
func ReadPID(workdir string) int {
	data, err := os.ReadFile(PIDPath(workdir))
	if err != nil {
		return 0
	}
	var pid int
	fmt.Sscanf(string(data), "%d", &pid)
	return pid
}

// IsRunning returns true if the daemon is alive (PID file exists and process responds).
func IsRunning(workdir string) (bool, int) {
	pid := ReadPID(workdir)
	if pid == 0 {
		return false, 0
	}
	proc, err := os.FindProcess(pid)
	if err != nil {
		return false, 0
	}
	// Signal 0 tests if process exists without affecting it.
	if err := proc.Signal(syscall.Signal(0)); err != nil {
		return false, 0
	}
	return true, pid
}

// Stop sends SIGTERM to the daemon process.
func Stop(workdir string) error {
	running, pid := IsRunning(workdir)
	if !running {
		return fmt.Errorf("daemon is not running")
	}
	proc, err := os.FindProcess(pid)
	if err != nil {
		return err
	}
	if err := proc.Signal(syscall.SIGTERM); err != nil {
		return fmt.Errorf("failed to stop daemon (pid %d): %w", pid, err)
	}
	// Remove PID file after signalling.
	os.Remove(PIDPath(workdir))
	return nil
}

// RemovePID removes the PID file (called by worker on clean exit).
func RemovePID(workdir string) {
	os.Remove(PIDPath(workdir))
}
