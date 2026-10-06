package hubdoctor

import (
	"os"
	"testing"

	"github.com/blechschmidt/cloop/internal/hometest"
)

// TestMain redirects the per-user state directory at a temporary one for the
// whole test binary: the global budget this package reads lives in
// ~/.config/cloop, and a test must neither depend on the caps of the machine
// that runs it nor write to that machine.
//
// See internal/hometest for why this is done once per package rather than
// per test.
func TestMain(m *testing.M) {
	os.Exit(hometest.Isolate(m))
}
