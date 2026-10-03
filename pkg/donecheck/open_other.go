//go:build !unix

package donecheck

import (
	"fmt"
	"os"
)

// openPlain opens path for reading, refusing anything but a regular file.
// Without O_NOFOLLOW the check and the open are two steps; cloop's release
// platforms are all unix, so this only keeps other builds compiling.
func openPlain(path string) (*os.File, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", path)
	}
	return os.Open(path)
}
