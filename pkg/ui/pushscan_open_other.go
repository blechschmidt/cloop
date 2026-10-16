//go:build !unix

package ui

import (
	"fmt"
	"os"
)

// openProjectFileNoBlock opens a file in a project's .cloop for reading,
// refusing anything but a regular file before it opens it. Without O_NOFOLLOW
// and O_NONBLOCK the check and the open are two steps; cloop's release
// platforms are all unix, so this only keeps other builds compiling.
func openProjectFileNoBlock(path string) (*os.File, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", path)
	}
	return os.Open(path)
}
