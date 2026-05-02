// Package daemon manages the cloop background daemon process.
// It stores PID in .cloop/daemon.pid, state in .cloop/daemon.json,
// and log output in .cloop/daemon.log.
package daemon

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

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

// Save writes the daemon state to disk.
func (s *State) Save(workdir string) error {
	dir := filepath.Join(workdir, ".cloop")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(StatePath(workdir), data, 0o644)
}

// WritePID writes the daemon PID to .cloop/daemon.pid.
func WritePID(workdir string, pid int) error {
	dir := filepath.Join(workdir, ".cloop")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	return os.WriteFile(PIDPath(workdir), []byte(fmt.Sprintf("%d", pid)), 0o644)
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
