package demo_test

import (
	"os"
	"testing"

	"github.com/blechschmidt/cloop/internal/hometest"
)

// TestMain isolates the home directory for this package.
//
// These tests read the demo's fixtures and the dashboard's assets out of the
// working tree and have no business touching $HOME at all; tests/hermetic
// requires the isolation of every package made only of test files anyway.
func TestMain(m *testing.M) {
	os.Exit(hometest.Isolate(m))
}
