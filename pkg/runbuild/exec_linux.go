//go:build linux

package runbuild

import (
	"os"
	"strconv"
	"syscall"
	"time"
)

// Supported reports whether a run on this platform can adopt a build.
const Supported = true

// Exec replaces this process's image with the candidate's file. It returns
// only if the exec failed; the process is then unchanged.
//
// The file is executed through /proc/self/fd/<n>, the descriptor Open took and
// Probe asked — see Candidate. The descriptor is close-on-exec, which is fine
// for an ELF binary (Open refuses anything else): the kernel opens the file
// before it closes the descriptor. What the process keeps is everything the
// hub and the local driver know it by: its pid and start time, its parent, and
// its stdout and stderr — the hub's live log of the run.
func Exec(c *Candidate, argv, env []string) error {
	return syscall.Exec("/proc/self/fd/"+strconv.Itoa(int(c.Fd())), argv, env)
}

func ctimeOf(info os.FileInfo) time.Time {
	if st, ok := info.Sys().(*syscall.Stat_t); ok {
		return time.Unix(int64(st.Ctim.Sec), int64(st.Ctim.Nsec))
	}
	return info.ModTime()
}
