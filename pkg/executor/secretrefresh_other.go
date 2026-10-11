//go:build !unix

package executor

import (
	"errors"
	"fmt"
	"io/fs"
)

// errReplaceUnsupported is what a platform without directory-relative file
// operations answers. It lives with the only code that returns it, so a linter
// run for a unix target does not report it unused.
var errReplaceUnsupported = errors.New("executor: replacing a credential file in place is not supported on this platform")

// IdentityOf is unsupported off unix.
func IdentityOf(path string) (FileIdentity, error) {
	return FileIdentity{}, fmt.Errorf("%w: %s", errReplaceUnsupported, path)
}

func replaceInDir(dir, _ string, _ []byte, _ fs.FileMode, _ ReplaceOptions) error {
	return fmt.Errorf("%w: %s", errReplaceUnsupported, dir)
}
