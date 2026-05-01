package provider

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestDoWithRetry_SuccessFirstAttempt(t *testing.T) {
	calls := 0
	err := DoWithRetry(context.Background(), RetryConfig{}, func() (int, error) {
		calls++
		return 200, nil
	})
	if err != nil {
		t.Fatalf("expected nil, got %v", err)
	}
	if calls != 1 {
		t.Fatalf("expected 1 call, got %d", calls)
	}
}

func TestDoWithRetry_RetriesOnRateLimit(t *testing.T) {
	calls := 0
	err := DoWithRetry(context.Background(), RetryConfig{
		MaxAttempts:  3,
		InitialDelay: time.Millisecond,
		MaxDelay:     10 * time.Millisecond,
	}, func() (int, error) {
		calls++
		if calls < 3 {
			return 429, errors.New("rate limited")
		}
		return 200, nil
	})
	if err != nil {
		t.Fatalf("expected success after retries, got %v", err)
	}
	if calls != 3 {
		t.Fatalf("expected 3 calls, got %d", calls)
	}
}

func TestDoWithRetry_RetriesOnServerError(t *testing.T) {
	for _, status := range []int{500, 502, 503, 504} {
		calls := 0
		err := DoWithRetry(context.Background(), RetryConfig{
			MaxAttempts:  2,
			InitialDelay: time.Millisecond,
			MaxDelay:     5 * time.Millisecond,
		}, func() (int, error) {
			calls++
			if calls == 1 {
				return status, errors.New("server error")
			}
			return 200, nil
		})
		if err != nil {
			t.Errorf("status %d: expected retry success, got %v", status, err)
		}
		if calls != 2 {
			t.Errorf("status %d: expected 2 calls, got %d", status, calls)
		}
	}
}

func TestDoWithRetry_NoRetryOnClientError(t *testing.T) {
	for _, status := range []int{400, 401, 403, 404} {
		calls := 0
		err := DoWithRetry(context.Background(), RetryConfig{
			MaxAttempts:  3,
			InitialDelay: time.Millisecond,
			MaxDelay:     5 * time.Millisecond,
		}, func() (int, error) {
			calls++
			return status, errors.New("client error")
		})
		if err == nil {
			t.Errorf("status %d: expected error, got nil", status)
		}
		if calls != 1 {
			t.Errorf("status %d: expected 1 call (no retry), got %d", status, calls)
		}
	}
}

func TestDoWithRetry_RetriesNetworkError(t *testing.T) {
	calls := 0
	err := DoWithRetry(context.Background(), RetryConfig{
		MaxAttempts:  3,
		InitialDelay: time.Millisecond,
		MaxDelay:     5 * time.Millisecond,
	}, func() (int, error) {
		calls++
		if calls < 3 {
			return 0, errors.New("connection refused") // status=0: network error
		}
		return 200, nil
	})
	if err != nil {
		t.Fatalf("expected success after retries, got %v", err)
	}
	if calls != 3 {
		t.Fatalf("expected 3 calls, got %d", calls)
	}
}

func TestDoWithRetry_MaxAttemptsExhausted(t *testing.T) {
	calls := 0
	wantErr := errors.New("always fails")
	err := DoWithRetry(context.Background(), RetryConfig{
		MaxAttempts:  3,
		InitialDelay: time.Millisecond,
		MaxDelay:     5 * time.Millisecond,
	}, func() (int, error) {
		calls++
		return 503, wantErr
	})
	if !errors.Is(err, wantErr) {
		t.Fatalf("expected %v, got %v", wantErr, err)
	}
	if calls != 3 {
		t.Fatalf("expected 3 calls, got %d", calls)
	}
}

func TestDoWithRetry_ContextCancelledBeforeSleep(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	calls := 0
	err := DoWithRetry(ctx, RetryConfig{
		MaxAttempts:  3,
		InitialDelay: time.Second, // long delay that won't be hit
		MaxDelay:     5 * time.Second,
	}, func() (int, error) {
		calls++
		return 503, errors.New("server error")
	})
	// First attempt runs, then context is checked before the sleep.
	if err == nil {
		t.Fatal("expected error due to cancelled context")
	}
	if calls != 1 {
		t.Fatalf("expected 1 call (context cancelled before sleep), got %d", calls)
	}
}

func TestDoWithRetry_DefaultConfig(t *testing.T) {
	cfg := RetryConfig{}.withDefaults()
	if cfg.MaxAttempts != 3 {
		t.Errorf("expected MaxAttempts=3, got %d", cfg.MaxAttempts)
	}
	if cfg.InitialDelay != time.Second {
		t.Errorf("expected InitialDelay=1s, got %v", cfg.InitialDelay)
	}
	if cfg.MaxDelay != 30*time.Second {
		t.Errorf("expected MaxDelay=30s, got %v", cfg.MaxDelay)
	}
}

func TestIsRetryableStatus(t *testing.T) {
	retryable := []int{429, 500, 502, 503, 504}
	for _, code := range retryable {
		if !IsRetryableStatus(code) {
			t.Errorf("expected %d to be retryable", code)
		}
	}

	notRetryable := []int{200, 201, 400, 401, 403, 404, 422}
	for _, code := range notRetryable {
		if IsRetryableStatus(code) {
			t.Errorf("expected %d to NOT be retryable", code)
		}
	}
}

func TestRetryDelay_Bounds(t *testing.T) {
	initial := 100 * time.Millisecond
	max := 2 * time.Second

	for attempt := 1; attempt <= 10; attempt++ {
		delay := retryDelay(initial, max, attempt)
		if delay < 0 {
			t.Errorf("attempt %d: delay %v < 0", attempt, delay)
		}
		// Allow a generous upper bound (max + 25% jitter)
		upperBound := time.Duration(float64(max) * 1.3)
		if delay > upperBound {
			t.Errorf("attempt %d: delay %v > %v", attempt, delay, upperBound)
		}
	}
}
