//go:build unix

package taskrecover

import (
	"os"
	"syscall"
)

// openNoFollow opens path for reading, refusing a symbolic link in its last
// component (ELOOP) rather than resolving it.
func openNoFollow(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
}
