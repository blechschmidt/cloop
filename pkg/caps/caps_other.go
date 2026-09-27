//go:build !linux

package caps

import "os/exec"

// Capabilities are a Linux mechanism; elsewhere there is nothing to confine,
// hold or grant.

func confine() error { return nil }

func holds(Cap) bool { return false }

func grant(*exec.Cmd, Cap) bool { return false }
