package chaos

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

// DiskFullSimulator creates a large ballast file inside .cloop/chaos/ to
// occupy disk space, simulating an ENOSPC environment for code paths that
// write into the project tree. The simulator targets a fixed byte size; if
// the filesystem cannot accommodate it, we surface that directly to the
// caller (which, for chaos purposes, is the desired outcome).
//
// The simulator never deletes files outside .cloop/chaos/ballast, so it is
// safe to run alongside other chaos faults. Stop() removes the ballast file
// regardless of how Start exited.
type DiskFullSimulator struct {
	workDir string
	size    int64
	path    string
}

// NewDiskFullSimulator targets the given .cloop project root. The default
// size (256 MiB) is comfortably above the typical free-space buffer most
// developer machines keep, while still far below the level that would cause
// genuine cascading failures.
func NewDiskFullSimulator(workDir string, sizeBytes int64) *DiskFullSimulator {
	if sizeBytes <= 0 {
		sizeBytes = 256 << 20 // 256 MiB
	}
	return &DiskFullSimulator{
		workDir: workDir,
		size:    sizeBytes,
		path:    filepath.Join(workDir, ".cloop", chaosDirName, defaultBallast),
	}
}

// Start creates the ballast file. Uses os.O_CREATE|os.O_TRUNC|os.O_WRONLY so
// repeated invocations do not pile up multiple ballasts. The body is sparse
// when supported by the filesystem (Truncate) and otherwise written in 1 MiB
// chunks.
func (d *DiskFullSimulator) Start() error {
	dir := filepath.Dir(d.path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("chaos: mkdir %s: %w", dir, err)
	}
	f, err := os.OpenFile(d.path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
	if err != nil {
		return fmt.Errorf("chaos: open %s: %w", d.path, err)
	}
	defer f.Close()

	// Try sparse first — instant on ext4/XFS, NTFS; the next dd-style fallback
	// guarantees behaviour on filesystems without sparse support.
	if err := f.Truncate(d.size); err == nil {
		return nil
	}
	chunk := make([]byte, 1<<20)
	written := int64(0)
	for written < d.size {
		n := int64(len(chunk))
		if d.size-written < n {
			n = d.size - written
		}
		w, werr := f.Write(chunk[:n])
		if werr != nil {
			// Cleanup so a half-written ballast does not linger.
			_ = os.Remove(d.path)
			if errors.Is(werr, io.ErrShortWrite) || isENOSPC(werr) {
				// ENOSPC at chaos time is the chaos: surface the exact error
				// so the report row records a "could not run" outcome.
				return fmt.Errorf("chaos: disk-full write hit real ENOSPC: %w", werr)
			}
			return fmt.Errorf("chaos: write ballast: %w", werr)
		}
		written += int64(w)
	}
	return nil
}

// Stop removes the ballast file. Returns nil if the file was already gone.
func (d *DiskFullSimulator) Stop() error {
	if err := os.Remove(d.path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("chaos: remove %s: %w", d.path, err)
	}
	return nil
}

// SlowDiskDelay returns the artificial delay configured for an active
// slow-disk fault, or zero when no slow-disk fault is active. The delay is
// stored in the fault's Note field as a Go duration string (e.g. "150ms").
// Callers wrapping disk writes can use this to introduce latency.
func SlowDiskDelay(c *Controller) time.Duration {
	if c == nil {
		c = Global()
		if c == nil {
			return 0
		}
	}
	for _, f := range c.FaultsOfType(FaultSlowDisk) {
		if f.Note == "" {
			return 50 * time.Millisecond
		}
		d, err := time.ParseDuration(f.Note)
		if err == nil && d > 0 {
			return d
		}
	}
	return 0
}

// MaybeSleepSlowDisk applies the slow-disk delay if active. Centralising the
// helper means atomicfile and other writers don't have to know how the delay
// is configured. Safe to call frequently — returns immediately when no fault
// is active.
func MaybeSleepSlowDisk(c *Controller) {
	if d := SlowDiskDelay(c); d > 0 {
		time.Sleep(d)
	}
}
