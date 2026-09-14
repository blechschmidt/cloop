package provider

// redaction.go keeps a leased credential out of everything a run writes down.
//
// # The leak this closes
//
// A task holding a GitHub PAT, a kubeconfig or an egress credential can echo
// it. Not maliciously — a `set -x`, a debug flag, an HTTP library dumping its
// request headers, a stack trace carrying an argv. The value then lands in
// places that outlive the lease by a wide margin:
//
//	provider result ─┬─> .cloop/tasks/<id>-<slug>.md      (task artifact)
//	                 ├─> .cloop/artifacts/<id>_output.txt (live, via OnToken)
//	                 ├─> state.db steps                   (the step log)
//	                 ├─> .cloop/replay                    (the replay log)
//	                 └─> stdout ──> the executor ──> the live-log room
//
// pkg/audit already scans artifacts for leaked credentials after the fact,
// which is the admission that this was expected rather than prevented. Removing
// the value here is what makes that scan find nothing.
//
// # Why here
//
// Build is the single point at which every provider in this binary is
// constructed — the orchestrator's, every role-specific route registered on it,
// the consensus fan-out's, and every one-off `cloop` AI subcommand. Those all
// reach the same artifact and step-log writers, so wrapping any one call site
// would leave the others. This decorator joins the chain Build already applies
// for panic safety and request-ID tracing, for the same reason those are there.
//
// The executor drivers scrub independently, on the hub side of the sandbox
// boundary (see executor.Spec.Redactor). Neither half subsumes the other: this
// one catches output before the orchestrator writes it to disk *inside* the
// sandbox, and that one catches whatever the workload prints to a stream the
// hub captures. A credential echoed by a harness would otherwise be caught in
// the live-log room and missed in the artifact.
//
// # What it does not do
//
// It matches only values a lease actually delivered, never anything that merely
// looks like a secret. An entropy heuristic on this path would be both a cost
// on every token and a way to mangle a legitimate base64 blob in a diff.

import (
	"context"
	"os"
	"sync"

	"github.com/blechschmidt/cloop/pkg/redact"
)

// redactingProvider removes the process's own leased credentials from
// everything the wrapped provider returns or streams.
type redactingProvider struct {
	inner Provider
	set   *redact.Set
}

// WithRedaction returns p with credential scrubbing applied, or p unchanged
// when there is nothing to scrub — which is the ordinary case for a project
// with no grants, and must cost nothing.
func WithRedaction(p Provider, set *redact.Set) Provider {
	if p == nil || set.Len() == 0 {
		return p
	}
	return &redactingProvider{inner: p, set: set}
}

// processRedactor is the scrub set for this process, derived from the
// environment the lease put its material in. Computed once: it reads the lease
// directory off disk, and Build is called many times per run.
//
// A control-plane process has no lease and gets a nil set, so the hub pays
// nothing for a mechanism that only applies to workloads.
var processRedactor = sync.OnceValue(func() *redact.Set {
	return redact.FromEnviron(os.Environ())
})

func (p *redactingProvider) Name() string         { return p.inner.Name() }
func (p *redactingProvider) DefaultModel() string { return p.inner.DefaultModel() }

// Complete scrubs both the streamed tokens and the final output.
//
// Both, not either: OnToken feeds the live artifact that `cloop task watch`
// tails, and Result.Output feeds everything that outlives the run. A harness
// that streams is covered by the first and one that does not by the second.
func (p *redactingProvider) Complete(ctx context.Context, prompt string, opts Options) (*Result, error) {
	var flush func()
	if opts.OnToken != nil {
		opts.OnToken, flush = p.streamFilter(opts.OnToken)
	}
	res, err := p.inner.Complete(ctx, prompt, opts)
	if flush != nil {
		flush()
	}
	if res != nil {
		res.Output = p.set.String(res.Output)
	}
	return res, err
}

// streamFilter wraps an OnToken callback so a credential cannot pass through
// it, including one split across two tokens — which on a token-by-token stream
// is the normal case rather than the edge one, since a tokenizer has no reason
// to keep a secret whole.
//
// The returned flush releases whatever is still withheld. It must run when the
// stream ends, or a response whose final tokens happened to begin a known
// secret would lose them — and the end of the output is where the answer is.
func (p *redactingProvider) streamFilter(next func(string)) (func(string), func()) {
	var (
		mu      sync.Mutex
		pending string
	)
	emit := func(tok string) {
		mu.Lock()
		text := p.set.String(pending + tok)
		// Withhold only a tail that could genuinely begin a known secret, so
		// ordinary tokens reach the live artifact with no added latency.
		if hold := p.set.Holdback(text); hold > 0 {
			pending = text[len(text)-hold:]
			text = text[:len(text)-hold]
		} else {
			pending = ""
		}
		mu.Unlock()
		if text != "" {
			next(text)
		}
	}
	flush := func() {
		mu.Lock()
		tail := pending
		pending = ""
		mu.Unlock()
		if tail != "" {
			next(p.set.String(tail))
		}
	}
	return emit, flush
}
