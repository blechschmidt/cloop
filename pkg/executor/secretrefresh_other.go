//go:build !unix

package executor

import (
	"fmt"
	"io/fs"
)

// IdentityOf is unsupported off unix.
func IdentityOf(path string) (FileIdentity, error) {
	return FileIdentity{}, fmt.Errorf("%w: %s", errReplaceUnsupported, path)
}

func replaceInDir(dir, _ string, _ []byte, _ fs.FileMode, _ ReplaceOptions) error {
	return fmt.Errorf("%w: %s", errReplaceUnsupported, dir)
}
