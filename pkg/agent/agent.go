package agent

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"
)

const (
	pidFile   = ".cloop/agent.pid"
	stateFile = ".cloop/agent.json"
	logFile   = ".cloop/agent.log"
)

// stateMu serialises in-process writes to .cloop/agent.json and .cloop/agent.pid.
// The daemon writes State frequently (status transitions, run counters, error
// strings) from a worker goroutine and may race with a heartbeat or status
// query in the same process. Pairs with atomic-rename writes that protect
// crash-safety across processes.
var stateMu sync.Mutex

// State tracks the daemon's runtime status, persisted to .cloop/agent.json.
type State struct {
	PID                 int       `json:"pid"`
	StartedAt           time.Time `json:"started_at"`
	LastRunAt           time.Time `json:"last_run_at,omitempty"`
	NextRunAt           time.Time `json:"next_run_at,omitempty"`
	RunCount            int       `json:"run_count"`
	TotalTasksCompleted int       `json:"total_tasks_completed"`
	TotalTasksFailed    int       `json:"total_tasks_failed"`
	Status              string    `json:"status"` // starting, idle, running, stopped
	Interval            string    `json:"interval"`
	Provider            string    `json:"provider,omitempty"`
	Model               string    `json:"model,omitempty"`
	LastError           string    `json:"last_error,omitempty"`
}

// PIDPath returns the absolute path to the PID file.
func PIDPath(workdir string) string {
	return filepath.Join(workdir, pidFile)
}

// StatePath returns the absolute path to the agent state file.
func StatePath(workdir string) string {
	return filepath.Join(workdir, stateFile)
}

// LogPath returns the absolute path to the agent log file.
func LogPath(workdir string) string {
	return filepath.Join(workdir, logFile)
}

// Load reads the agent state from disk; returns nil if not found.
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
		return nil, fmt.Errorf("corrupt agent state: %w", err)
	}
	return &s, nil
}

// Save writes the agent state to disk atomically.
//
// A torn write of agent.json (crash mid-write, ENOSPC) would corrupt the JSON;
// `Load` would then return an error and `cloop agent status` / the daemon
// itself would refuse to read its own counters. The write also runs under
// stateMu so two daemon goroutines saving in parallel can't interleave their
// MarshalIndent buffers.
func (s *State) Save(workdir string) error {
	stateMu.Lock()
	defer stateMu.Unlock()
	dir := filepath.Join(workdir, ".cloop")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return writeAtomic(dir, StatePath(workdir), ".agent.json.*.tmp", data, 0o644)
}

// WritePID writes the daemon PID to .cloop/agent.pid atomically. A partial
// write here would let `IsRunning` see "0" or a half-printed PID and treat
// the daemon as dead even when it is alive.
func WritePID(workdir string, pid int) error {
	stateMu.Lock()
	defer stateMu.Unlock()
	dir := filepath.Join(workdir, ".cloop")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	return writeAtomic(dir, PIDPath(workdir), ".agent.pid.*.tmp", []byte(fmt.Sprintf("%d", pid)), 0o644)
}

// ReadPID reads the daemon PID from .cloop/agent.pid; returns 0 if not found.
func ReadPID(workdir string) int {
	data, err := os.ReadFile(PIDPath(workdir))
	if err != nil {
		return 0
	}
	var pid int
	fmt.Sscanf(string(data), "%d", &pid)
	return pid
}

// IsRunning returns true if the daemon is alive (PID exists and process is reachable).
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
		return fmt.Errorf("agent is not running")
	}
	proc, err := os.FindProcess(pid)
	if err != nil {
		return err
	}
	if err := proc.Signal(syscall.SIGTERM); err != nil {
		return fmt.Errorf("failed to stop agent (pid %d): %w", pid, err)
	}
	// Remove PID file after signalling.
	os.Remove(PIDPath(workdir))
	return nil
}

// RemovePID removes the PID file (called by worker on exit).
func RemovePID(workdir string) {
	os.Remove(PIDPath(workdir))
}

// writeAtomic stages data in a sibling .tmp file in dir, fsyncs, chmods, then
// renames into path. The rename is atomic on POSIX, so concurrent readers see
// either the old file or the new — never a truncated one.
func writeAtomic(dir, path, tmpPattern string, data []byte, mode os.FileMode) error {
	tmp, err := os.CreateTemp(dir, tmpPattern)
	if err != nil {
		return fmt.Errorf("agent: create tmp: %w", err)
	}
	tmpPath := tmp.Name()
	defer func() {
		if _, statErr := os.Stat(tmpPath); statErr == nil {
			_ = os.Remove(tmpPath)
		}
	}()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("agent: write tmp: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("agent: sync tmp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("agent: close tmp: %w", err)
	}
	if err := os.Chmod(tmpPath, mode); err != nil {
		return fmt.Errorf("agent: chmod tmp: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("agent: rename tmp: %w", err)
	}
	return nil
}
