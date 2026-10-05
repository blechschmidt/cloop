//go:build !linux

package diskreserve

import "os"

// allocateFile writes the reserve out where fallocate(2) is not available.
func allocateFile(f *os.File, size int64) error {
	return writeOut(f, size)
}
