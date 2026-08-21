package cmd

// executors.go registers the built-in execution backends with the executor
// registry, mirroring how providers.go registers AI providers. Importing the
// cmd package registers them automatically.
//
// Registration lives here rather than inside pkg/executor so that package
// stays free of driver dependencies (and so drivers can import it without a
// cycle) — the same reason provider registration lives in providers.go.

import (
	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/executor/localprocess"
)

func init() {
	// The host-process driver is the zero-config default so a plain
	// single-machine install works out of the box. It provides no
	// isolation; deployments that must not run agents on the control-plane
	// host bind their projects to an isolated executor instead, and
	// executor.Resolve then fails closed rather than falling back here.
	//
	// Ensure (not Register) because pkg/ui performs the same bootstrap when
	// it constructs a Server: whichever runs first wins, and the second is
	// a no-op.
	_ = localprocess.Ensure(executor.DefaultRegistry)
}
