//go:build linux

package diskwatch

import (
	"errors"

	"golang.org/x/sys/unix"
)

// ioprio_set(2) arguments, from linux/ioprio.h.
const (
	ioprioWhoProcess = 1
	ioprioClassIdle  = 3
	ioprioClassShift = 13
)

// lowerThreadPriority moves the calling thread to nice 19 and the idle I/O
// class. Both calls name the thread by its tid, which on Linux scopes them to
// that one thread rather than to the process. Raising a nice value and
// entering the idle class need no privilege.
func lowerThreadPriority() error {
	tid := unix.Gettid()
	errNice := unix.Setpriority(unix.PRIO_PROCESS, tid, 19)
	var errIO error
	if _, _, errno := unix.Syscall(unix.SYS_IOPRIO_SET, ioprioWhoProcess, uintptr(tid),
		ioprioClassIdle<<ioprioClassShift); errno != 0 {
		errIO = errno
	}
	return errors.Join(errNice, errIO)
}
