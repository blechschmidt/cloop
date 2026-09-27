//go:build linux && !cgo

package caps

import (
	"errors"
	"fmt"
	"runtime"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// clearInherited clears the ambient and inheritable sets on every thread.
//
// AllThreadsSyscall stops the world and makes the call on each thread the
// runtime has, so no goroutine can fork from a thread that still holds the old
// sets, and every thread the runtime starts later is cloned from one that no
// longer does. This is the release build's path: releases are built with
// CGO_ENABLED=0, where AllThreadsSyscall is available.
func clearInherited() error {
	if _, _, errno := syscall.AllThreadsSyscall(syscall.SYS_PRCTL,
		unix.PR_CAP_AMBIENT, unix.PR_CAP_AMBIENT_CLEAR_ALL, 0); errno != 0 {
		// EINVAL is a kernel older than 4.3, which has no ambient set and so
		// nothing ambient to pass on.
		if !errors.Is(errno, syscall.EINVAL) {
			return fmt.Errorf("caps: clear the ambient capability set: %w", errno)
		}
	}

	// The inheritable set is cleared too. It grants nothing by itself, but a
	// child that execs a file carrying inheritable file capabilities receives
	// their intersection with it — and a child has no business receiving
	// anything. Every thread holds the same sets, so one capget describes all
	// of them and one capset value is right for each.
	hdr := &unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	data := new([2]unix.CapUserData)
	if err := unix.Capget(hdr, &data[0]); err != nil {
		return fmt.Errorf("caps: read this process's capabilities: %w", err)
	}
	if data[0].Inheritable == 0 && data[1].Inheritable == 0 {
		return nil
	}
	data[0].Inheritable, data[1].Inheritable = 0, 0
	// Heap-allocated and kept alive across the call: every thread reads these
	// two structs while the world is stopped.
	_, _, errno := syscall.AllThreadsSyscall(syscall.SYS_CAPSET,
		uintptr(unsafe.Pointer(hdr)), uintptr(unsafe.Pointer(&data[0])), 0)
	runtime.KeepAlive(hdr)
	runtime.KeepAlive(data)
	if errno != 0 {
		return fmt.Errorf("caps: clear the inheritable capability set: %w", errno)
	}
	return nil
}
