//go:build unix

package chaos

import (
	"errors"
	"syscall"
)

// isENOSPC reports whether err is the syscall-level "no space left on device"
// error. Used by DiskFullSimulator.Start to distinguish between a chaos
// ballast that exhausted real disk and an unrelated I/O error.
func isENOSPC(err error) bool {
	var errno syscall.Errno
	if errors.As(err, &errno) {
		return errno == syscall.ENOSPC
	}
	return false
}
