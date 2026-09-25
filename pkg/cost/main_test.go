package cost

import (
	"os"
	"testing"

	"github.com/blechschmidt/cloop/internal/hometest"
)

// TestMain redirects the per-user state directory at a temporary one for the
// whole test binary. This package imports globalbudget, which owns
// ~/.config/cloop/{budget.yaml,costs.jsonl,global.db}, so without it a test run
// could write to the real files on the machine that runs it.
//
// See internal/hometest for why this is done once per package rather than
// per test.
func TestMain(m *testing.M) {
	os.Exit(hometest.Isolate(m))
}
