package orchestrator

import (
	"context"
	"fmt"
	"os"
	"runtime/debug"

	"github.com/blechschmidt/cloop/pkg/provider"
)

// safeComplete wraps provider.Complete with panic recovery so that a panic
// inside a provider implementation (e.g. nil-pointer in a third-party SDK,
// malformed JSON deref) becomes an error rather than crashing the entire
// `cloop run` process.
//
// The runPMParallel, consensus, and bench packages already protect their
// fan-out goroutines individually. This helper exists for the main-goroutine
// call sites (runPMSequential heal/clarify retries, evolvePM), where a
// crash would tear down the orchestrator.
//
// On panic, the stack trace is logged to stderr at the point of recovery so
// debugging information is not lost; the returned error matches the shape
// of an ordinary provider error so the existing error-handling branches at
// the call site keep working unchanged.
func safeComplete(ctx context.Context, p provider.Provider, prompt string, opts provider.Options) (result *provider.Result, err error) {
	defer func() {
		if rec := recover(); rec != nil {
			err = fmt.Errorf("provider panic in %s: %v", p.Name(), rec)
			fmt.Fprintf(os.Stderr, "orchestrator: provider panic in %s: %v\n%s\n", p.Name(), rec, debug.Stack())
		}
	}()
	return p.Complete(ctx, prompt, opts)
}
