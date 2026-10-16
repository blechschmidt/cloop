//go:build unix

package ui

import (
	"os"
	"syscall"
)

// openProjectFileNoBlock opens a file in a project's .cloop for reading
// without following a symbolic link in its last component and without
// blocking: a workload whose sandbox shares the project directory can put a
// FIFO where config.yaml was, and an open that waited for a writer would hold
// the git proxy's request forever (Task 20436).
func openProjectFileNoBlock(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
}
