package multiagent

import (
	"context"
	"fmt"
	"os"
	"runtime/debug"

	"github.com/blechschmidt/cloop/pkg/provider"
)

// safeComplete wraps provider.Complete with panic recovery so a panic inside a
// provider implementation (e.g. nil-pointer in a third-party SDK, malformed
// JSON deref) becomes an error rather than crashing the orchestrator midway
// through the architect → coder → reviewer pipeline. Without this, a single
// crashing pass would tear down the whole `cloop run` process and lose every
// queued task that hadn't started.
//
// The returned error matches the shape of an ordinary provider error so the
// existing `fmt.Errorf("X pass: %w", err)` wrappers at the call sites keep
// working unchanged. The full stack trace is logged to stderr at the point of
// recovery so debugging information is preserved.
func safeComplete(ctx context.Context, p provider.Provider, prompt string, opts provider.Options) (result *provider.Result, err error) {
	defer func() {
		if rec := recover(); rec != nil {
			err = fmt.Errorf("provider panic in %s: %v", p.Name(), rec)
			fmt.Fprintf(os.Stderr, "multiagent: provider panic in %s: %v\n%s\n", p.Name(), rec, debug.Stack())
		}
	}()
	return p.Complete(ctx, prompt, opts)
}
