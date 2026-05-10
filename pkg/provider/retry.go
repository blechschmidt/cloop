package provider

import (
	"context"
	"fmt"
	"math"
	"math/rand"
	"time"

	"github.com/blechschmidt/cloop/pkg/reqid"
)

// RetryConfig controls retry behavior for provider HTTP requests.
type RetryConfig struct {
	MaxAttempts  int           // total attempts including the first (default: 3)
	InitialDelay time.Duration // base delay before the first retry (default: 1s)
	MaxDelay     time.Duration // cap on delay between retries (default: 30s)

	// BreakerKey, if non-empty, gates the call through a circuit breaker
	// looked up from the global registry (or created with default config).
	// When the breaker is open the call short-circuits with ErrCircuitOpen
	// without consuming an attempt or contacting the upstream.
	BreakerKey string
}

var defaultRetryConfig = RetryConfig{
	MaxAttempts:  3,
	InitialDelay: time.Second,
	MaxDelay:     30 * time.Second,
}

func (c RetryConfig) withDefaults() RetryConfig {
	if c.MaxAttempts <= 0 {
		c.MaxAttempts = defaultRetryConfig.MaxAttempts
	}
	if c.InitialDelay <= 0 {
		c.InitialDelay = defaultRetryConfig.InitialDelay
	}
	if c.MaxDelay <= 0 {
		c.MaxDelay = defaultRetryConfig.MaxDelay
	}
	return c
}

// IsRetryableStatus returns true for HTTP status codes worth retrying.
// 429 = rate limited, 500/502/503/504 = transient server errors.
func IsRetryableStatus(code int) bool {
	switch code {
	case 429, 500, 502, 503, 504:
		return true
	}
	return false
}

// DoWithRetry calls fn up to cfg.MaxAttempts times, sleeping with exponential
// backoff between attempts. fn returns the HTTP status code (0 for non-HTTP
// errors) and an error. Retries stop when fn returns nil, the context is done,
// or the error comes from a non-retryable HTTP status.
//
// When ctx carries a request ID (via pkg/reqid) it is included in the
// returned error wrappers so a single failure can be traced from the
// orchestrator log → provider error → HTTP-level audit trail without
// having to correlate timestamps. Errors that already wrap the request ID
// (the inner fn might do its own wrapping) are not double-tagged: only
// the outermost retry/breaker error gets the prefix.
func DoWithRetry(ctx context.Context, cfg RetryConfig, fn func() (statusCode int, err error)) error {
	cfg = cfg.withDefaults()

	var breaker *CircuitBreaker
	if cfg.BreakerKey != "" {
		breaker = GetBreaker(cfg.BreakerKey)
	}

	rid := reqid.FromContext(ctx)
	budget := RetryBudgetFromContext(ctx)

	var lastErr error
	for attempt := 0; attempt < cfg.MaxAttempts; attempt++ {
		if attempt > 0 {
			delay := retryDelay(cfg.InitialDelay, cfg.MaxDelay, attempt)
			select {
			case <-ctx.Done():
				return wrapWithReqID(ctx.Err(), rid)
			case <-time.After(delay):
			}
		}

		// Per-task retry budget check: consumed BEFORE the breaker so
		// an over-budget call neither hammers the upstream nor burns a
		// half-open probe slot. When the budget is exhausted we surface
		// ErrRetryBudgetExhausted directly; the orchestrator then
		// declares the task failed instead of retrying further.
		if err := budget.Take(); err != nil {
			if lastErr != nil {
				return wrapWithReqID(fmt.Errorf("%w: last error: %v", err, lastErr), rid)
			}
			return wrapWithReqID(err, rid)
		}

		// Check the breaker before each attempt. A retry that arrives
		// after the breaker tripped on the previous attempt should be
		// short-circuited, not allowed to hammer the upstream further.
		if breaker != nil && !breaker.Allow() {
			if lastErr != nil {
				return wrapWithReqID(fmt.Errorf("%w: last error: %v", formatBreakerError(cfg.BreakerKey), lastErr), rid)
			}
			return wrapWithReqID(formatBreakerError(cfg.BreakerKey), rid)
		}

		status, err := fn()
		if err == nil {
			if breaker != nil {
				breaker.RecordSuccess()
			}
			return nil
		}

		// Stop immediately if the parent context is cancelled. Context
		// cancellation is the caller's choice, not an upstream failure,
		// so don't trip the breaker on it.
		if ctx.Err() != nil {
			if breaker != nil {
				// Release the in-flight probe slot in half-open without
				// counting cancellation as a failure.
				breaker.releaseProbe()
			}
			return wrapWithReqID(err, rid)
		}

		// For HTTP errors, only retry on known-transient status codes.
		// A zero status means a network-level error — always retry those.
		// Both kinds count as failures against the breaker; client errors
		// (4xx other than 429) don't, since they signal a caller-side
		// problem rather than upstream unavailability.
		if status != 0 && !IsRetryableStatus(status) {
			if breaker != nil {
				breaker.releaseProbe()
			}
			return wrapWithReqID(err, rid)
		}

		if breaker != nil {
			breaker.RecordFailure(err)
		}
		lastErr = err
	}
	return wrapWithReqID(lastErr, rid)
}

// wrapWithReqID prepends "[request_id=...] " to err's message so the ID
// flows out alongside the underlying cause. Returns err unchanged when
// rid is empty (no propagation in scope) or err is nil. Uses fmt.Errorf
// with %w so errors.Is / errors.As keep working — the wrapper only adds
// a tag, it does not introduce a new sentinel.
func wrapWithReqID(err error, rid string) error {
	if err == nil || rid == "" {
		return err
	}
	return fmt.Errorf("[request_id=%s] %w", rid, err)
}

// WrapErrWithRequestID is the public helper for provider implementations
// (anthropic, openai, ollama, claudecode) to tag a direct error with the
// request ID carried by ctx. Streaming and one-shot paths that don't go
// through DoWithRetry use this so every error returned to the caller is
// traceable end-to-end.
//
// Returns err unchanged when ctx carries no ID or err is nil.
func WrapErrWithRequestID(ctx context.Context, err error) error {
	if err == nil {
		return nil
	}
	return wrapWithReqID(err, reqid.FromContext(ctx))
}

// retryDelay calculates the delay for a given attempt (1-indexed) using
// exponential backoff with ±25% jitter.
func retryDelay(initial, max time.Duration, attempt int) time.Duration {
	exp := math.Pow(2, float64(attempt-1))
	delay := time.Duration(float64(initial) * exp)
	if delay > max {
		delay = max
	}
	// Add ±25% jitter to spread retries from concurrent callers.
	jitter := time.Duration((rand.Float64() - 0.5) * 0.5 * float64(delay))
	delay += jitter
	if delay < 0 {
		delay = 0
	}
	return delay
}
