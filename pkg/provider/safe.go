package provider

import (
	"context"
	"fmt"
	"os"
	"runtime/debug"
)

// WithPanicSafety wraps p so that a panic raised inside p.Complete is
// converted into an ordinary error rather than crashing the host process.
//
// Most cloop commands call p.Complete from a single foreground goroutine
// (e.g. the long-running `cloop run` orchestrator, ad-hoc commands like
// `cloop scope`/`cloop critique`/`cloop ask`). A nil-pointer deref inside
// a third-party SDK or a bad JSON cast inside a provider's response parser
// would otherwise tear the entire process down — losing every queued task,
// every cached state mutation that hadn't been flushed, and the WS server.
//
// The Build factory below applies this wrapper unconditionally, so every
// provider returned to the rest of the codebase is already panic-safe.
// Per-package safeComplete helpers in pkg/orchestrator and pkg/multiagent
// remain in place as defense-in-depth; with this wrapper they should now
// be unreachable on the panic branch but still correct.
//
// On panic, the full stack trace is logged to stderr at the recovery point
// and the returned error matches the existing "provider panic in <name>"
// shape so callers that already match against that string keep working.
func WithPanicSafety(p Provider) Provider {
	if p == nil {
		return nil
	}
	if _, already := p.(*panicSafe); already {
		return p
	}
	return &panicSafe{inner: p}
}

type panicSafe struct {
	inner Provider
}

func (p *panicSafe) Name() string         { return p.inner.Name() }
func (p *panicSafe) DefaultModel() string { return p.inner.DefaultModel() }

func (p *panicSafe) Complete(ctx context.Context, prompt string, opts Options) (result *Result, err error) {
	defer func() {
		if rec := recover(); rec != nil {
			name := p.inner.Name()
			err = fmt.Errorf("provider panic in %s: %v", name, rec)
			fmt.Fprintf(os.Stderr, "provider: panic in %s: %v\n%s\n", name, rec, debug.Stack())
			result = nil
		}
	}()
	return p.inner.Complete(ctx, prompt, opts)
}
