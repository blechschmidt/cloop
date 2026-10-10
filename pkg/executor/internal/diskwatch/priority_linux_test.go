//go:build linux

package diskwatch

import "golang.org/x/sys/unix"

// threadPriority reads the calling thread's nice value and I/O class.
//
// The raw getpriority(2) syscall returns 20 - nice, so that its result is
// never negative; x/sys/unix does not undo that, so it is undone here.
func threadPriority() (nice, class int) {
	tid := unix.Gettid()
	if prio, err := unix.Getpriority(unix.PRIO_PROCESS, tid); err == nil {
		nice = 20 - prio
	}
	r, _, errno := unix.Syscall(unix.SYS_IOPRIO_GET, ioprioWhoProcess, uintptr(tid), 0)
	if errno == 0 {
		class = int(r) >> ioprioClassShift
	}
	return nice, class
}
