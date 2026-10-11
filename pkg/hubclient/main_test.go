package hubclient

import (
	"os"
	"testing"

	"github.com/blechschmidt/cloop/internal/hometest"
)

// TestMain gives the tests a home directory of their own: DefaultPath reads
// it, and a credential file written to the real one would outlive the run.
func TestMain(m *testing.M) { os.Exit(hometest.Isolate(m)) }
