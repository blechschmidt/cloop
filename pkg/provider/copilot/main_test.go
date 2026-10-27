package copilot

import (
	"os"
	"testing"

	"github.com/blechschmidt/cloop/internal/hometest"
)

// TestMain points HOME at a temporary directory for the whole test binary: the
// CLI keeps its sign-in, sessions and logs under ~/.copilot, and a test that
// reaches a real one must not write to the machine's.
func TestMain(m *testing.M) {
	os.Exit(hometest.Isolate(m))
}
