package provider

import (
	"context"
	"math"
	"math/rand"
	"time"
)

// RetryConfig controls retry behavior for provider HTTP requests.
type RetryConfig struct {
	MaxAttempts  int           // total attempts including the first (default: 3)
	InitialDelay time.Duration // base delay before the first retry (default: 1s)
	MaxDelay     time.Duration // cap on delay between retries (default: 30s)
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
func DoWithRetry(ctx context.Context, cfg RetryConfig, fn func() (statusCode int, err error)) error {
	cfg = cfg.withDefaults()

	var lastErr error
	for attempt := 0; attempt < cfg.MaxAttempts; attempt++ {
		if attempt > 0 {
			delay := retryDelay(cfg.InitialDelay, cfg.MaxDelay, attempt)
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(delay):
			}
		}

		status, err := fn()
		if err == nil {
			return nil
		}

		// Stop immediately if the parent context is cancelled.
		if ctx.Err() != nil {
			return err
		}

		// For HTTP errors, only retry on known-transient status codes.
		// A zero status means a network-level error — always retry those.
		if status != 0 && !IsRetryableStatus(status) {
			return err
		}

		lastErr = err
	}
	return lastErr
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
