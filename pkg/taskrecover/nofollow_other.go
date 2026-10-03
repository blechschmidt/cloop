//go:build !unix

package taskrecover

import (
	"fmt"
	"os"
)

// openNoFollow opens path for reading, refusing a symbolic link in its last
// component. Without O_NOFOLLOW the check and the open are two steps; cloop's
// release platforms are all unix, so this only keeps other builds compiling.
func openNoFollow(path string) (*os.File, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("%s is a symbolic link; not following it", path)
	}
	return os.Open(path)
}
