package copilotauth

import (
	"os"
	"testing"

	"github.com/blechschmidt/cloop/internal/hometest"
)

// TestMain points HOME at a temporary directory for the whole test binary: the
// homes this package makes live under the hub user's config directory.
func TestMain(m *testing.M) {
	os.Exit(hometest.Isolate(m))
}
