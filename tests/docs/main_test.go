package docs_test

import (
	"os"
	"testing"

	"github.com/blechschmidt/cloop/internal/hometest"
)

// TestMain isolates the home directory for this package.
//
// These tests read source and markdown out of the working tree and have no
// business touching $HOME at all — which is the reason to isolate rather than
// a reason not to. tests/hermetic requires it of every package made only of
// test files, because that shape is how integration suites that drive
// subprocesses are written, and a subprocess inherits $HOME. Carving out an
// exception for the ones that look harmless today is how the rule stops
// meaning anything.
func TestMain(m *testing.M) {
	os.Exit(hometest.Isolate(m))
}
