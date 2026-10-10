//go:build !linux

package diskwatch

// lowerThreadPriority has no per-thread priority to lower off Linux; the walk's
// deadline is what bounds it there.
func lowerThreadPriority() error { return nil }
