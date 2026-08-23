package agent

import (
	"os"
	"testing"

	"github.com/blechschmidt/cloop/internal/hometest"
)

// TestMain redirects the per-user state directory at a temporary one for the
// whole test binary, so this package's tests cannot write to the real
// ~/.cloop/agent.json executor credential on the machine that runs them.
//
// See internal/hometest for why this is done once per package rather than
// per test, and for the leak that motivated it.
func TestMain(m *testing.M) {
	os.Exit(hometest.Isolate(m))
}
