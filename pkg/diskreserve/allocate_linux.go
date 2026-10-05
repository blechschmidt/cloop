package diskreserve

import (
	"errors"
	"os"
	"syscall"
)

// allocateFile preallocates size bytes with fallocate(2), which reserves the
// blocks without writing them: instant, and no 16 MiB of I/O on a disk that is
// already under pressure. A filesystem that cannot (some FUSE and network
// filesystems, older ZFS) answers EOPNOTSUPP, and gets the data written out
// instead.
func allocateFile(f *os.File, size int64) error {
	err := syscall.Fallocate(int(f.Fd()), 0, 0, size) //nolint:gosec // Fd fits an int on every platform Go supports
	if err == nil {
		return nil
	}
	if errors.Is(err, syscall.EOPNOTSUPP) || errors.Is(err, syscall.ENOSYS) || errors.Is(err, syscall.EINVAL) {
		return writeOut(f, size)
	}
	return err
}
