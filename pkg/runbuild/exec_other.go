//go:build !linux

package runbuild

import (
	"errors"
	"os"
	"time"
)

// Supported reports whether a run on this platform can adopt a build: only
// Linux, whose procfs the process identity and the exec both rely on.
const Supported = false

// Exec is not available off Linux.
func Exec(c *Candidate, argv, env []string) error {
	return errors.New("adopting a build needs Linux")
}

func ctimeOf(info os.FileInfo) time.Time { return info.ModTime() }
