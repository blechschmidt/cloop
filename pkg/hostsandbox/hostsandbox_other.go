//go:build !linux

package hostsandbox

import (
	"fmt"
	"os"
	"os/exec"
)

// Main is helper mode. There is no sandbox off Linux, so it only says so.
func Main() int {
	fmt.Fprintln(os.Stderr, "cloop: host sandbox: unsupported on this operating system")
	return ExitHelperFailed
}

// ABI reports that this platform has no Landlock.
func ABI() (int, error) {
	return 0, fmt.Errorf("%w: the host sandbox needs Linux", ErrUnsupported)
}

// Available reports that this platform cannot sandbox a workload.
func Available() error {
	_, err := ABI()
	return err
}

// Wrap refuses: there is nothing to wrap a workload in here.
func Wrap(*exec.Cmd, string, Policy) error { return Available() }

// UsesNamespaces is false where there are no namespaces.
func UsesNamespaces() bool { return false }
