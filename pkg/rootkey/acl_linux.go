//go:build linux

package rootkey

import (
	"errors"
	"os"

	"golang.org/x/sys/unix"
)

// readACL returns the open file's extended POSIX access ACL, or nil when it
// has none — its mode bits are then the whole of its permissions — or its
// filesystem keeps none. Read through the descriptor that is read, like every
// other check on a key file.
func readACL(f *os.File) ([]aclEntry, error) {
	buf := make([]byte, 256)
	for {
		n, err := unix.Fgetxattr(int(f.Fd()), "system.posix_acl_access", buf)
		switch {
		case err == nil:
			return parseACL(buf[:n])
		case errors.Is(err, unix.ENODATA), errors.Is(err, unix.EOPNOTSUPP):
			return nil, nil
		case errors.Is(err, unix.ERANGE) && len(buf) < 64<<10:
			buf = make([]byte, 2*len(buf))
		default:
			return nil, err
		}
	}
}
