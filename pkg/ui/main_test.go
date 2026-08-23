package ui

import (
	"os"
	"testing"

	"github.com/blechschmidt/cloop/internal/hometest"
)

// TestMain redirects the per-user state directory at a temporary one for the
// whole pkg/ui test binary.
//
// This package is where the leak that motivated it lived. POST
// /api/projects/new registers the created project in the global
// ~/.cloop/projects.json, and TestProjectNewDoesNotGrantWhatTheCallerMayNotGrant
// exercises that route without an isolated HOME — so every run appended an
// entry to the developer's real registry and left it there. At 99 entries,
// project index 99 resolved to a deleted /tmp directory and
// TestScopeForNeverSilentlyWidens, TestProjectExecutorBind_RejectsBadIndex and
// TestUnresolvableProjectIdxDoesNotFallBackToGlobalScope all began failing —
// on a developer's machine only, since CI runners start from an empty HOME.
//
// Isolating here rather than in that one test is deliberate: 50 test files in
// this package reach handlers that touch the registry, and the next one to be
// added should not have to know that.
func TestMain(m *testing.M) {
	os.Exit(hometest.Isolate(m))
}
