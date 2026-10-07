package security

import (
	"os"
	"testing"

	"github.com/blechschmidt/cloop/internal/hometest"
)

// TestMain points the per-user state directory at a temporary one for the
// whole suite. TestAnOpenHubNeverListensBeyondLoopback runs a real hub, and a
// running hub reads the project registry under the user's home and opens every
// project it lists: on a developer's machine, without this, the suite opened
// the live projects' state databases (found while landing Task 20394 — their
// duplicate-migration warnings appeared in its output).
func TestMain(m *testing.M) { os.Exit(hometest.Isolate(m)) }
