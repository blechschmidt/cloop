package multiagent

import (
	"context"
	"fmt"
	"os"
	"runtime/debug"
	"strings"

	"github.com/blechschmidt/cloop/pkg/provider"
)

// safeComplete wraps provider.Complete with panic recovery so a panic inside a
// provider implementation (e.g. nil-pointer in a third-party SDK, malformed
// JSON deref) becomes an error rather than crashing the orchestrator midway
// through the architect → coder → reviewer pipeline. Without this, a single
// crashing pass would tear down the whole `cloop run` process and lose every
// queued task that hadn't started.
//
// It also surfaces the (*Result{Output:""}, nil) / (nil, nil) shapes as
// transient errors. The architect → coder → reviewer pipeline feeds each
// pass's output into the next pass's prompt; if the architect returned
// silently empty, the coder would be asked to "implement the task following
// the architect's design above" with an empty design block, then the
// reviewer would default-vote TaskDone (the switch's default arm at
// multiagent.go) with no audit trail of the upstream hiccup. Treating
// empty as an explicit failure here keeps the pipeline consistent with the
// orchestrator/pm/verifier empty-output guards (commits 1d3c8a8, ceaf396,
// 9d94cad, 3f45190, 55f0337) so transient provider hiccups can't mask
// themselves as a successful no-op pass.
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
			result = nil
		}
	}()
	result, err = p.Complete(ctx, prompt, opts)
	if err != nil {
		return result, err
	}
	if result == nil || strings.TrimSpace(result.Output) == "" {
		return nil, fmt.Errorf("provider %s returned empty output", p.Name())
	}
	return result, nil
}
