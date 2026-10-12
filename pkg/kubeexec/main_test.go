package kubeexec

import (
	"os"
	"testing"

	"github.com/blechschmidt/cloop/internal/hometest"
)

// TestMain gives the tests a home directory of their own: DefaultPaths reads
// ~/.kube/config, and a test must never find — or run the plugin in — the
// developer's own.
func TestMain(m *testing.M) { os.Exit(hometest.Isolate(m)) }
