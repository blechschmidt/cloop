// Package daemon manages the cloop background daemon process.
// It stores PID in .cloop/daemon.pid, state in .cloop/daemon.json,
// and log output in .cloop/daemon.log.
package daemon

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/blechschmidt/cloop/pkg/atomicfile"
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
//
// On parse failure (zero-byte file, schema drift, manual edit gone wrong) the
// corrupt file is quarantined aside as daemon.json.corrupt-<unix> and
// (nil, nil) is returned. Losing the daemon counters/last-error is preferable
// to wedging `cloop daemon status` and the orchestrator's heartbeat reads —
// the bytes are preserved next to the original location for forensics.
func Load(workdir string) (*State, error) {
	path := StatePath(workdir)
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var s State
	if err := json.Unmarshal(data, &s); err != nil {
		qpath := atomicfile.QuarantineCorrupt(path)
		if qpath != "" {
			fmt.Fprintf(os.Stderr, "warning: daemon state at %s was corrupt (%v); quarantined to %s, starting fresh\n", path, err, qpath)
		} else {
			fmt.Fprintf(os.Stderr, "warning: daemon state at %s was corrupt (%v) and could not be quarantined; ignoring\n", path, err)
		}
		return nil, nil
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
	return atomicfile.Write(path, data, 0o644)
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
	return atomicfile.Write(path, []byte(fmt.Sprintf("%d", pid)), 0o644)
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

// stopGraceTimeout bounds how long Stop waits for the daemon worker to exit
// after SIGTERM before escalating to SIGKILL. The worker may have HTTP servers
// or running tasks to drain, so this is generous; tune via StopWithTimeout if
// callers need a stricter bound.
const stopGraceTimeout = 15 * time.Second

// stopPollInterval is how often Stop polls Signal(0) to check whether the
// worker has exited. Cheap because Signal(0) is a syscall that doesn't touch
// the process — we just want to notice exit promptly without busy-looping.
const stopPollInterval = 100 * time.Millisecond

// Stop sends SIGTERM to the daemon worker and waits for it to exit, escalating
// to SIGKILL if the worker doesn't terminate within stopGraceTimeout.
//
// Unlike a fire-and-forget signal + os.Remove(pidPath), this:
//  1. Lets the worker run its own cleanup (PID-file removal, final state Save,
//     HTTP-server graceful shutdown) before Stop returns. A subsequent
//     `daemon start` therefore sees a clean slate instead of racing the
//     drain.
//  2. Forcibly cleans up if the worker is wedged, so a stuck daemon can
//     always be replaced.
//
// Returns nil on clean exit; a wrapped error if SIGKILL was needed (the
// daemon is gone, but the caller should know it didn't shut down cleanly).
func Stop(workdir string) error {
	return StopWithTimeout(workdir, stopGraceTimeout)
}

// StopWithTimeout is Stop with a caller-supplied grace period. Used by tests
// to drive the SIGKILL escalation path without waiting the production default.
func StopWithTimeout(workdir string, grace time.Duration) error {
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

	// Poll until the process exits or we hit the grace deadline. Signal(0)
	// returns nil while the process is alive; once it's reaped or no longer
	// exists, the syscall errors and we know the worker is gone.
	deadline := time.Now().Add(grace)
	for time.Now().Before(deadline) {
		if err := proc.Signal(syscall.Signal(0)); err != nil {
			return nil
		}
		time.Sleep(stopPollInterval)
	}

	// Worker didn't exit within grace — escalate. SIGKILL is uncatchable, so
	// we also remove the PID file ourselves since the worker won't get the
	// chance to clean up.
	if killErr := proc.Signal(syscall.SIGKILL); killErr != nil && !errors.Is(killErr, os.ErrProcessDone) {
		os.Remove(PIDPath(workdir))
		return fmt.Errorf("daemon (pid %d) did not exit within %s and SIGKILL failed: %w", pid, grace, killErr)
	}
	os.Remove(PIDPath(workdir))
	return fmt.Errorf("daemon (pid %d) did not exit within %s; force-killed", pid, grace)
}

// RemovePID removes the PID file (called by worker on clean exit).
func RemovePID(workdir string) {
	os.Remove(PIDPath(workdir))
}
