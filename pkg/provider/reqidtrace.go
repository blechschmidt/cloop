package provider

import (
	"context"
	"fmt"

	"github.com/blechschmidt/cloop/pkg/reqid"
)

// WithRequestIDTracing decorates p so that every error returned from
// p.Complete is automatically tagged with the request ID carried by ctx
// (via pkg/reqid). Successful results pass through unchanged.
//
// The wrapper sits OUTSIDE retry/breaker logic — retries internal to the
// provider already use DoWithRetry, which tags its own outermost error.
// What this layer adds: error paths that bypass retry (streaming-only
// providers, claudecode subprocess execution, request-construction
// failures) also receive the tag, so a future log aggregation never sees
// an untagged error from a request that did flow through the middleware.
//
// In addition, when ctx carries no request ID at all the wrapper mints a
// fresh one (via reqid.EnsureContext) and binds it to the context handed
// down to the inner provider. This guarantees every provider call in the
// process is traceable, even when invoked from a CLI command that did
// not go through the HTTP middleware (e.g. `cloop run` from a shell).
//
// The wrapper is idempotent: applying it twice has the same effect as
// applying it once. The factory.go Build pipeline composes it with
// WithPanicSafety so callers get both behaviours by default.
func WithRequestIDTracing(p Provider) Provider {
	if p == nil {
		return nil
	}
	if _, already := p.(*reqIDTrace); already {
		return p
	}
	return &reqIDTrace{inner: p}
}

type reqIDTrace struct {
	inner Provider
}

func (p *reqIDTrace) Name() string         { return p.inner.Name() }
func (p *reqIDTrace) DefaultModel() string { return p.inner.DefaultModel() }

func (p *reqIDTrace) Complete(ctx context.Context, prompt string, opts Options) (*Result, error) {
	ctx, rid := reqid.EnsureContext(ctx)
	res, err := p.inner.Complete(ctx, prompt, opts)
	if err == nil {
		return res, nil
	}
	// Avoid double-tagging: if the inner error message already starts with
	// our [request_id=...] marker (because retry wrapped it), pass through.
	if alreadyTagged(err, rid) {
		return res, err
	}
	return res, fmt.Errorf("[request_id=%s] %w", rid, err)
}

// alreadyTagged reports whether err's message already begins with the
// request-ID marker for rid. We do a prefix check on Error() rather than
// errors.As because the marker is text-only — no sentinel type.
func alreadyTagged(err error, rid string) bool {
	if err == nil || rid == "" {
		return false
	}
	prefix := "[request_id=" + rid + "]"
	msg := err.Error()
	return len(msg) >= len(prefix) && msg[:len(prefix)] == prefix
}
