package cmd

import (
	"errors"
	"os"
	"testing"

	"github.com/blechschmidt/cloop/internal/hometest"
)

// cliReexecEnv makes this test binary act as the cloop CLI instead of running
// tests. The `cloop remote` tests run a hub in this process
// (internal/ssohubtest), and the hub dispatches its own work — `cloop init`
// for a new project, `cloop feature new` for a feature — to its SelfExe. That
// is pointed at this binary through a wrapper that sets the variable
// (cliSelfExe), so the hub runs the real commands, built from the tree under
// test, without building a cloop binary first.
const cliReexecEnv = "CLOOP_CMD_TEST_AS_CLI"

// TestMain redirects the per-user state directory at a temporary one for the
// whole test binary, so this package's tests cannot write to any of the
// ~/.cloop and ~/.config/cloop files the CLI owns on the machine that runs
// them.
//
// See internal/hometest for why this is done once per package rather than
// per test, and for the leak that motivated it.
func TestMain(m *testing.M) {
	// No test reaches the host's systemd-creds: run as root, its first
	// encryption creates the host's credential secret (Task 20425). A test
	// that wants the encrypted path installs a stand-in of its own.
	systemdCredsEncrypt = func(string, []byte, string) error {
		return errors.New("systemd-creds is not used by tests")
	}
	if os.Getenv(cliReexecEnv) == "1" {
		// A child of a test's hub, whose environment — HOME included — is
		// already the test's.
		Execute()
		exitProcess(0)
	}
	os.Exit(hometest.Isolate(m))
}
