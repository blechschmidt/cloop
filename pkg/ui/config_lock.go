package ui

import (
	"os"
	"path/filepath"
	"sync"
	"syscall"
)

// hubConfigLock is hubConfigMu's type: a process mutex plus an advisory file
// lock on the control plane's config, so load-modify-save is serialised
// across every hub process sharing it (Task 20354). The file lock is
// best-effort — a filesystem that refuses flock degrades to the mutex alone,
// which is what a single hub always had.
type hubConfigLock struct {
	mu sync.Mutex
	f  *os.File
}

// Lock takes the mutex, then the file lock.
func (l *hubConfigLock) Lock() {
	l.mu.Lock()
	dir := controlPlaneDir()
	if dir == "" {
		return
	}
	path := filepath.Join(dir, ".cloop", "config.yaml.lock")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		_ = f.Close()
		return
	}
	l.f = f
}

// Unlock releases both, file lock first.
func (l *hubConfigLock) Unlock() {
	if l.f != nil {
		_ = syscall.Flock(int(l.f.Fd()), syscall.LOCK_UN)
		_ = l.f.Close()
		l.f = nil
	}
	l.mu.Unlock()
}
