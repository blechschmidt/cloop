package hostsandbox

import (
	"fmt"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
)

// testHelperInstalled says a test binary's TestMain ran InstallTestHelper,
// so starting this binary with Arg runs the helper rather than the tests.
var testHelperInstalled atomic.Bool

// HelperPath is the binary a driver starts as the helper: this one, with its
// links resolved, so that the policy can grant exactly the file that runs.
//
// A test binary qualifies only once its TestMain has installed the helper.
// Started with Arg, any other test binary would run its tests instead — and
// each of those could start the helper again.
func HelperPath() (string, error) {
	if testing.Testing() && !testHelperInstalled.Load() {
		return "", fmt.Errorf("%w: this test binary has not installed the host sandbox's helper "+
			"(call hostsandbox.InstallTestHelper from its TestMain)", ErrUnsupported)
	}
	exe, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("hostsandbox: find this binary: %w", err)
	}
	if resolved, err := filepath.EvalSymlinks(exe); err == nil {
		exe = resolved
	}
	return exe, nil
}

// InstallTestHelper is for a test binary's TestMain, called before m.Run:
// started as the helper, the binary runs it and exits without reaching the
// tests; otherwise it records that the helper is there to be started.
func InstallTestHelper() {
	if IsInvocation(os.Args) {
		os.Exit(Main())
	}
	testHelperInstalled.Store(true)
}
