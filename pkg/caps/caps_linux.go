//go:build linux

package caps

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

// confine clears what children would inherit, then checks every thread.
//
// The fast path matters: this runs at the start of every cloop invocation, and
// nearly all of them hold no capability at all. One read of /proc answers that.
func confine() error {
	if s, err := readSets("/proc/self/status"); err == nil && s.Ambient == 0 && s.Inheritable == 0 {
		return nil
	}
	if err := clearInherited(); err != nil {
		return err
	}
	return verifyConfined()
}

// verifyConfined checks every thread of this process rather than trusting the
// clearing call, because a single thread left holding an ambient capability is
// enough for a child forked from it to inherit it.
func verifyConfined() error {
	tasks, err := filepath.Glob("/proc/self/task/*/status")
	if err != nil || len(tasks) == 0 {
		// No /proc to look at. The clearing call reported success, and with
		// nothing to check against that is the best available answer.
		return nil
	}
	var leaking []string
	for _, t := range tasks {
		s, err := readSets(t)
		if err != nil {
			// A thread that exited between the glob and the read.
			continue
		}
		if s.Ambient != 0 || s.Inheritable != 0 {
			leaking = append(leaking, fmt.Sprintf("thread %s: ambient %#x, inheritable %#x",
				filepath.Base(filepath.Dir(t)), s.Ambient, s.Inheritable))
		}
	}
	if len(leaking) > 0 {
		return fmt.Errorf("caps: programs this process starts would inherit its capabilities (%s)",
			strings.Join(leaking, "; "))
	}
	return nil
}

func readSets(path string) (Sets, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return Sets{}, err
	}
	return ParseStatus(string(b))
}

// holds asks the kernel directly rather than reading /proc: it is on the path of
// every nft(8) invocation, and capget is one syscall.
func holds(c Cap) bool {
	if c > unix.CAP_LAST_CAP {
		return false
	}
	hdr := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	var data [2]unix.CapUserData
	if err := unix.Capget(&hdr, &data[0]); err != nil {
		return false
	}
	if data[c/32].Permitted&(1<<(c%32)) == 0 {
		return false
	}
	// Go raises a granted capability into the child's inheritable set before
	// the ambient one, and the kernel allows that only for a capability that
	// is also in the bounding set.
	inBounding, err := unix.PrctlRetInt(unix.PR_CAPBSET_READ, uintptr(c), 0, 0, 0)
	return err == nil && inBounding == 1
}

func grant(cmd *exec.Cmd, c Cap) bool {
	if os.Geteuid() == 0 || !holds(c) {
		return false
	}
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	if !slices.Contains(cmd.SysProcAttr.AmbientCaps, uintptr(c)) {
		cmd.SysProcAttr.AmbientCaps = append(cmd.SysProcAttr.AmbientCaps, uintptr(c))
	}
	return true
}
