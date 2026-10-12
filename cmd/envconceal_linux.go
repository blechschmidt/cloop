//go:build linux

package cmd

import "golang.org/x/sys/unix"

// concealInitialEnvironment makes this process non-dumpable, which is what
// keeps the environment it was started with from being read back through
// /proc/<pid>/environ by another process of the same user (Task 20424).
//
// os.Unsetenv removes a variable from the copy Go keeps; the kernel still
// serves the block the process was exec'd with, and a harness this process
// spawns runs as the same user. A non-dumpable process's /proc entries belong
// to root and its memory cannot be traced, so that block is out of the
// harness's reach unless it holds CAP_SYS_PTRACE, which no sandbox cloop
// builds grants. The flag is not inherited across exec: the harness itself
// stays dumpable.
func concealInitialEnvironment() error {
	return unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0)
}
