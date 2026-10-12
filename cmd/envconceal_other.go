//go:build !linux

package cmd

// concealInitialEnvironment has nothing to do where /proc/<pid>/environ does
// not exist. See envconceal_linux.go.
func concealInitialEnvironment() error { return nil }
