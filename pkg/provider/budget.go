package provider

import (
	"context"
	"errors"
	"sync/atomic"
)

// ErrRetryBudgetExhausted is returned by DoWithRetry when the per-task
// retry budget bound to ctx has been fully consumed. It is a distinct
// failure mode from a plain provider error: the upstream may be perfectly
// healthy, but the calling task has spent its allotment of provider
// attempts and the orchestrator must surface this as task-level failure
// rather than retrying further.
//
// Callers branch on it with errors.Is(err, ErrRetryBudgetExhausted).
var ErrRetryBudgetExhausted = errors.New("provider: retry budget exhausted")

// IsRetryBudgetExhausted reports whether err is, or wraps,
// ErrRetryBudgetExhausted. Provided as a small convenience so callers do
// not have to import errors and remember to use errors.Is.
func IsRetryBudgetExhausted(err error) bool {
	return errors.Is(err, ErrRetryBudgetExhausted)
}

// DefaultRetryBudget is the per-task ceiling applied when neither the
// task nor the configuration overrides it. With three internal retries
// per provider call (the default DoWithRetry config), ten attempts cover
// at least three back-to-back provider invocations before the task is
// declared failed — enough headroom for normal flake recovery, not
// enough to drain a budget on a single deeply-stuck task.
const DefaultRetryBudget = 10

// RetryBudget caps the total number of provider attempts a single
// logical task is allowed to consume across all DoWithRetry calls made
// from goroutines that share its context. A "task" here is anything the
// orchestrator scopes a budget to — typically one entry in pm.Plan.Tasks,
// but sub-agent fan-out, consensus voting, and heal retries also share
// the same budget so a misbehaving task cannot escape the cap by
// spawning helpers.
//
// All methods are safe for concurrent use. Multiple goroutines may share
// a single *RetryBudget; the counter is updated with sync/atomic so
// parallel sub-calls cannot race past the limit.
//
// The zero value is NOT usable; call NewRetryBudget. A nil *RetryBudget
// is treated as "no budget configured" — Take returns nil so existing
// call sites that do not wire a budget keep working unchanged.
type RetryBudget struct {
	limit    int64
	attempts int64 // atomic
}

// NewRetryBudget returns a budget allowing up to limit total provider
// attempts. limit values <= 0 are clamped to DefaultRetryBudget so a
// hand-constructed Config{Task.RetryBudget: 0} or a forgotten override
// never produces a no-cap budget.
func NewRetryBudget(limit int) *RetryBudget {
	if limit <= 0 {
		limit = DefaultRetryBudget
	}
	return &RetryBudget{limit: int64(limit)}
}

// Limit returns the maximum number of attempts the budget allows.
// A nil receiver returns 0 ("no budget configured").
func (b *RetryBudget) Limit() int {
	if b == nil {
		return 0
	}
	return int(atomic.LoadInt64(&b.limit))
}

// Used returns the number of attempts that have been consumed so far.
// May exceed Limit() if Take has been called past exhaustion (the over-
// budget calls return ErrRetryBudgetExhausted but the counter still
// advances so audit logs show the true demand).
func (b *RetryBudget) Used() int {
	if b == nil {
		return 0
	}
	return int(atomic.LoadInt64(&b.attempts))
}

// Remaining returns the number of attempts still available, never
// negative. A nil receiver returns 0.
func (b *RetryBudget) Remaining() int {
	if b == nil {
		return 0
	}
	used := atomic.LoadInt64(&b.attempts)
	limit := atomic.LoadInt64(&b.limit)
	rem := limit - used
	if rem < 0 {
		return 0
	}
	return int(rem)
}

// Take consumes one attempt from the budget. It returns nil while the
// budget has room and ErrRetryBudgetExhausted (without actually rolling
// back the counter) once the limit has been crossed.
//
// A nil receiver returns nil — call sites that have not wired a budget
// behave exactly as they did before this type existed. Concurrent calls
// are safe: even if N goroutines invoke Take simultaneously, at most
// limit of them will observe a nil return.
func (b *RetryBudget) Take() error {
	if b == nil {
		return nil
	}
	used := atomic.AddInt64(&b.attempts, 1)
	if used > atomic.LoadInt64(&b.limit) {
		atomic.AddInt64(&retryBudgetExhausted, 1)
		return ErrRetryBudgetExhausted
	}
	return nil
}

// retryBudgetExhausted is a process-wide counter incremented every time
// a Take call crosses into the over-budget region. Surfaces in metrics
// as cloop_retry_budget_exhausted_total. Read with
// RetryBudgetExhaustedTotal.
var retryBudgetExhausted int64

// RetryBudgetExhaustedTotal returns the number of Take calls that have
// returned ErrRetryBudgetExhausted since process start. Used by the
// metrics layer to expose retry_budget_exhausted_total without having
// to plumb a callback through every provider implementation.
func RetryBudgetExhaustedTotal() int64 {
	return atomic.LoadInt64(&retryBudgetExhausted)
}

// resetRetryBudgetExhaustedForTest zeroes the counter. Used only by
// tests in this package; not exported.
func resetRetryBudgetExhaustedForTest() {
	atomic.StoreInt64(&retryBudgetExhausted, 0)
}

type retryBudgetCtxKey struct{}

var retryBudgetKey retryBudgetCtxKey

// WithRetryBudget returns a copy of ctx that carries b. When b is nil
// the original ctx is returned unchanged, so installing a missing
// budget at an outer layer does not clobber an inner one.
func WithRetryBudget(ctx context.Context, b *RetryBudget) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	if b == nil {
		return ctx
	}
	return context.WithValue(ctx, retryBudgetKey, b)
}

// RetryBudgetFromContext returns the budget bound to ctx, or nil when
// none is present. Callers MUST treat a nil return as "no budget
// configured" and proceed normally.
func RetryBudgetFromContext(ctx context.Context) *RetryBudget {
	if ctx == nil {
		return nil
	}
	v, _ := ctx.Value(retryBudgetKey).(*RetryBudget)
	return v
}
