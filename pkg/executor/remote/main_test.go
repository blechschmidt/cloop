package remote_test

import (
	"os"
	"testing"

	"github.com/blechschmidt/cloop/internal/hometest"
	"github.com/blechschmidt/cloop/pkg/hostsandbox"
)

func TestMain(m *testing.M) {
	// Started as the host sandbox's helper — a device's payload kept to its
	// project (Task 20500) — run it; it never reaches the tests.
	hostsandbox.InstallTestHelper()
	// The agent's harness lookup reads the home directory.
	os.Exit(hometest.Isolate(m))
}
