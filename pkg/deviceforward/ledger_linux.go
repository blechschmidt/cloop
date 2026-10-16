//go:build linux

package deviceforward

import (
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"syscall"
	"unsafe"
)

// processStartTime reads a process's start time in clock ticks since boot
// (field 22 of /proc/<pid>/stat), which with the pid identifies one process
// across pid reuse. 0 when it cannot be read.
func processStartTime(pid int) uint64 {
	b, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		return 0
	}
	// The command name (field 2) is parenthesised and may contain spaces;
	// count fields from after its closing parenthesis.
	s := string(b)
	i := strings.LastIndexByte(s, ')')
	if i < 0 {
		return 0
	}
	fields := strings.Fields(s[i+1:])
	// fields[0] is field 3 (state); start time is field 22.
	if len(fields) < 20 {
		return 0
	}
	n, err := strconv.ParseUint(fields[19], 10, 64)
	if err != nil {
		return 0
	}
	return n
}

// processAlive reports whether the process that wrote a ledger is still
// running: the pid exists and, when the ledger recorded one, has the same
// start time.
func processAlive(pid int, start uint64) bool {
	if err := syscall.Kill(pid, 0); err != nil && !errors.Is(err, syscall.EPERM) {
		return false
	}
	if start == 0 {
		return true
	}
	return processStartTime(pid) == start
}

// undoLedgerEntry undoes one recorded attachment of a dead process.
func undoLedgerEntry(e LedgerEntry, rep *SweepReport, logf func(string, ...any)) {
	switch e.Kind {
	case LedgerVHCI:
		v := VHCI{Root: e.VHCIRoot}
		detached, err := v.detachIfOurs(e.VHCIPort, e.DevID)
		switch {
		case err != nil:
			rep.Errors = append(rep.Errors, fmt.Sprintf("vhci port %d: %v", e.VHCIPort, err))
		case detached:
			rep.Detached = append(rep.Detached, fmt.Sprintf("port %d", e.VHCIPort))
			if logf != nil {
				logf("deviceforward: swept vhci port %d (device id %08x) a previous process left attached", e.VHCIPort, e.DevID)
			}
		}
	case LedgerTAP:
		removed, err := removeOrphanTAP(e.TAP)
		switch {
		case err != nil:
			rep.Errors = append(rep.Errors, fmt.Sprintf("tap %s: %v", e.TAP, err))
		case removed:
			rep.Removed = append(rep.Removed, e.TAP)
			if logf != nil {
				logf("deviceforward: swept TAP %s a previous process left behind", e.TAP)
			}
		}
	}
}

// removeOrphanTAP removes a TAP that outlived the process that made it. Only
// a TAP no descriptor holds can be re-opened by name; one some process still
// holds answers EBUSY and is left alone, as is a name that is not a TAP.
func removeOrphanTAP(name string) (bool, error) {
	if name == "" {
		return false, nil
	}
	if _, err := net.InterfaceByName(name); err != nil {
		return false, nil // gone already, the usual case
	}
	f, err := os.OpenFile("/dev/net/tun", os.O_RDWR, 0)
	if err != nil {
		return false, err
	}
	defer f.Close()
	const (
		tunsetiff     = 0x400454ca
		tunsetpersist = 0x400454cb
		iffTap        = 0x0002
		iffNoPI       = 0x1000
	)
	var req struct {
		name  [16]byte
		flags uint16
		_     [22]byte
	}
	copy(req.name[:15], name)
	req.flags = iffTap | iffNoPI
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, f.Fd(), tunsetiff, uintptr(unsafe.Pointer(&req))); errno != 0 {
		if errno == syscall.EBUSY || errno == syscall.EINVAL {
			return false, nil // held by a live process, or not a TAP
		}
		return false, errno
	}
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, f.Fd(), tunsetpersist, 0); errno != 0 {
		return false, errno
	}
	return true, nil
}
