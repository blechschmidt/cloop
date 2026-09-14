//go:build !linux

package ptyshell

import (
	"os"
	"os/exec"
)

const supported = false

// The non-Linux build refuses rather than emulating. Callers treat
// ErrUnsupported as "fall back to pipes", so the outcome on a developer's
// macOS laptop is a working session without line editing — not a broken one,
// and not a silently different one that pretends to have a terminal.

func resize(*os.File, uint16, uint16) error { return ErrUnsupported }

func start(*exec.Cmd, uint16, uint16) (*Session, error) { return nil, ErrUnsupported }
