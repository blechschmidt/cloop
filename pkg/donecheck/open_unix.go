//go:build unix

package donecheck

import (
	"os"
	"syscall"
)

// openPlain opens path for reading without following a symbolic link in its
// last component, and without blocking on a FIFO someone put in its place: the
// directory is in the agent's reach.
func openPlain(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
}
