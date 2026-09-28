package hubcluster

import (
	"errors"
	"os"
	"syscall"
)

// processAlive reports whether pid names a live process in this pid
// namespace. EPERM counts as alive: the process exists and belongs to someone
// else, and guessing "dead" there would hand a live member's work away.
func processAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	p, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	err = p.Signal(syscall.Signal(0))
	if err == nil {
		return true
	}
	return errors.Is(err, os.ErrPermission)
}
