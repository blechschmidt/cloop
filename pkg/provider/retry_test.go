package provider

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
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

// --- Retry budget tests (Task 20114) ----------------------------------------

func TestRetryBudget_NewClampsZeroAndNegative(t *testing.T) {
	for _, in := range []int{0, -1, -100} {
		b := NewRetryBudget(in)
		if got := b.Limit(); got != DefaultRetryBudget {
			t.Errorf("limit %d: expected default %d, got %d", in, DefaultRetryBudget, got)
		}
	}

	b := NewRetryBudget(7)
	if b.Limit() != 7 {
		t.Errorf("limit 7: expected 7, got %d", b.Limit())
	}
}

func TestRetryBudget_TakeDecrementsAndReportsRemaining(t *testing.T) {
	b := NewRetryBudget(3)
	if b.Used() != 0 {
		t.Fatalf("fresh budget: used=%d", b.Used())
	}
	if b.Remaining() != 3 {
		t.Fatalf("fresh budget: remaining=%d", b.Remaining())
	}

	for i := 1; i <= 3; i++ {
		if err := b.Take(); err != nil {
			t.Fatalf("attempt %d: unexpected err: %v", i, err)
		}
		if b.Used() != i {
			t.Errorf("attempt %d: used=%d", i, b.Used())
		}
	}
	if b.Remaining() != 0 {
		t.Errorf("after 3 takes: remaining=%d", b.Remaining())
	}
}

func TestRetryBudget_TakeReturnsSentinelOnExhaustion(t *testing.T) {
	b := NewRetryBudget(2)
	if err := b.Take(); err != nil {
		t.Fatalf("first Take: %v", err)
	}
	if err := b.Take(); err != nil {
		t.Fatalf("second Take: %v", err)
	}
	err := b.Take()
	if err == nil {
		t.Fatal("third Take: expected error, got nil")
	}
	if !errors.Is(err, ErrRetryBudgetExhausted) {
		t.Fatalf("third Take: expected ErrRetryBudgetExhausted, got %v", err)
	}
	if !IsRetryBudgetExhausted(err) {
		t.Fatal("IsRetryBudgetExhausted reported false on sentinel error")
	}

	// Subsequent takes keep returning the sentinel; counter keeps moving so
	// audit logs reflect the true demand.
	if err := b.Take(); !errors.Is(err, ErrRetryBudgetExhausted) {
		t.Fatalf("fourth Take: expected ErrRetryBudgetExhausted, got %v", err)
	}
	if b.Used() < 4 {
		t.Errorf("used did not advance past limit, got %d", b.Used())
	}
	if b.Remaining() != 0 {
		t.Errorf("remaining clamps to 0, got %d", b.Remaining())
	}
}

func TestRetryBudget_NilReceiverIsNoOp(t *testing.T) {
	var b *RetryBudget
	if err := b.Take(); err != nil {
		t.Fatalf("nil Take: %v", err)
	}
	if b.Limit() != 0 || b.Used() != 0 || b.Remaining() != 0 {
		t.Fatalf("nil getters: %d/%d/%d", b.Limit(), b.Used(), b.Remaining())
	}
}

func TestRetryBudget_Context(t *testing.T) {
	b := NewRetryBudget(5)
	ctx := WithRetryBudget(context.Background(), b)
	got := RetryBudgetFromContext(ctx)
	if got != b {
		t.Fatalf("expected same budget pointer, got %p vs %p", got, b)
	}

	// nil budget passes through without overwriting.
	ctx2 := WithRetryBudget(ctx, nil)
	if RetryBudgetFromContext(ctx2) != b {
		t.Fatal("WithRetryBudget(nil) clobbered an existing binding")
	}

	if RetryBudgetFromContext(context.Background()) != nil {
		t.Fatal("FromContext on bare ctx returned non-nil")
	}
	if RetryBudgetFromContext(nil) != nil {
		t.Fatal("FromContext(nil) returned non-nil")
	}
}

func TestDoWithRetry_BudgetDecrementsOnEachAttempt(t *testing.T) {
	resetRetryBudgetExhaustedForTest()

	b := NewRetryBudget(10)
	ctx := WithRetryBudget(context.Background(), b)

	calls := 0
	err := DoWithRetry(ctx, RetryConfig{
		MaxAttempts:  3,
		InitialDelay: time.Millisecond,
		MaxDelay:     5 * time.Millisecond,
	}, func() (int, error) {
		calls++
		if calls < 3 {
			return 503, errors.New("transient")
		}
		return 200, nil
	})
	if err != nil {
		t.Fatalf("expected success, got %v", err)
	}
	if calls != 3 {
		t.Fatalf("expected 3 calls, got %d", calls)
	}
	if b.Used() != 3 {
		t.Fatalf("expected budget used=3, got %d", b.Used())
	}
	if RetryBudgetExhaustedTotal() != 0 {
		t.Fatalf("expected exhausted counter to stay 0, got %d", RetryBudgetExhaustedTotal())
	}
}

func TestDoWithRetry_BudgetExhaustionReturnsSentinel(t *testing.T) {
	resetRetryBudgetExhaustedForTest()

	// Budget = 2 attempts, but RetryConfig allows 5: budget exhausts first.
	b := NewRetryBudget(2)
	ctx := WithRetryBudget(context.Background(), b)

	calls := 0
	err := DoWithRetry(ctx, RetryConfig{
		MaxAttempts:  5,
		InitialDelay: time.Millisecond,
		MaxDelay:     5 * time.Millisecond,
	}, func() (int, error) {
		calls++
		return 503, errors.New("always 503")
	})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !errors.Is(err, ErrRetryBudgetExhausted) {
		t.Fatalf("expected ErrRetryBudgetExhausted, got %v", err)
	}
	if calls != 2 {
		t.Fatalf("expected 2 calls (budget cap), got %d", calls)
	}
	if RetryBudgetExhaustedTotal() == 0 {
		t.Fatal("expected exhausted counter to advance, got 0")
	}
}

func TestDoWithRetry_BudgetSpansMultipleCalls(t *testing.T) {
	// Same budget shared across multiple DoWithRetry invocations on the
	// same task — second invocation finds the budget already half-spent.
	resetRetryBudgetExhaustedForTest()

	b := NewRetryBudget(4)
	ctx := WithRetryBudget(context.Background(), b)

	cfg := RetryConfig{
		MaxAttempts:  5,
		InitialDelay: time.Millisecond,
		MaxDelay:     5 * time.Millisecond,
	}

	// First call: 3 attempts, succeeds on the 3rd.
	calls1 := 0
	err1 := DoWithRetry(ctx, cfg, func() (int, error) {
		calls1++
		if calls1 < 3 {
			return 503, errors.New("transient")
		}
		return 200, nil
	})
	if err1 != nil {
		t.Fatalf("first call: %v", err1)
	}
	if b.Used() != 3 {
		t.Fatalf("after first call: used=%d", b.Used())
	}

	// Second call: budget has 1 attempt left. After that, budget exhausts.
	calls2 := 0
	err2 := DoWithRetry(ctx, cfg, func() (int, error) {
		calls2++
		return 503, errors.New("still 503")
	})
	if err2 == nil {
		t.Fatal("second call: expected error, got nil")
	}
	if !errors.Is(err2, ErrRetryBudgetExhausted) {
		t.Fatalf("second call: expected ErrRetryBudgetExhausted, got %v", err2)
	}
	if calls2 != 1 {
		t.Fatalf("second call: expected 1 attempt, got %d", calls2)
	}
}

func TestDoWithRetry_NoBudgetIsBackwardsCompatible(t *testing.T) {
	resetRetryBudgetExhaustedForTest()

	// No budget bound to ctx → unchanged behaviour from before Task 20114.
	calls := 0
	err := DoWithRetry(context.Background(), RetryConfig{
		MaxAttempts:  3,
		InitialDelay: time.Millisecond,
		MaxDelay:     5 * time.Millisecond,
	}, func() (int, error) {
		calls++
		return 200, nil
	})
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if calls != 1 {
		t.Fatalf("expected 1 call, got %d", calls)
	}
	if RetryBudgetExhaustedTotal() != 0 {
		t.Fatalf("expected exhausted counter to stay 0, got %d", RetryBudgetExhaustedTotal())
	}
}

func TestRetryBudget_ConcurrentTasksAreIndependent(t *testing.T) {
	// Two budgets running in parallel: each gets its own counter, neither
	// can drain the other.
	resetRetryBudgetExhaustedForTest()

	const tasks = 8
	const budgetPerTask = 3
	const attemptsPerTask = 5 // guaranteed to exceed the budget

	var wg sync.WaitGroup
	exhaustionsByTask := make([]int32, tasks)

	for i := 0; i < tasks; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			b := NewRetryBudget(budgetPerTask)
			ctx := WithRetryBudget(context.Background(), b)
			err := DoWithRetry(ctx, RetryConfig{
				MaxAttempts:  attemptsPerTask,
				InitialDelay: time.Microsecond,
				MaxDelay:     time.Microsecond * 5,
			}, func() (int, error) {
				return 503, errors.New("flaky upstream")
			})
			if !errors.Is(err, ErrRetryBudgetExhausted) {
				t.Errorf("task %d: expected ErrRetryBudgetExhausted, got %v", idx, err)
			}
			if b.Used() < budgetPerTask {
				t.Errorf("task %d: used=%d (< %d)", idx, b.Used(), budgetPerTask)
			}
			// Each task's budget should report exactly budgetPerTask in
			// successful Takes plus exactly one over-budget Take that
			// returned the sentinel.
			if b.Used() != budgetPerTask+1 {
				t.Errorf("task %d: expected used=%d (budget+1 sentinel), got %d", idx, budgetPerTask+1, b.Used())
			}
			atomic.AddInt32(&exhaustionsByTask[idx], 1)
		}(i)
	}
	wg.Wait()

	// Each task must have observed exactly one exhaustion path.
	for i, n := range exhaustionsByTask {
		if n != 1 {
			t.Errorf("task %d: exhaustions=%d (want 1)", i, n)
		}
	}

	// Process-wide counter saw exactly `tasks` exhaustion events.
	if got := RetryBudgetExhaustedTotal(); got != int64(tasks) {
		t.Errorf("expected exhausted counter=%d, got %d", tasks, got)
	}
}

func TestRetryBudget_ConcurrentTakesRespectLimit(t *testing.T) {
	// 50 goroutines all calling Take on a budget of 10 — exactly 10 must
	// see nil; the rest get the sentinel.
	const limit = 10
	const goroutines = 50

	b := NewRetryBudget(limit)

	var wg sync.WaitGroup
	var ok, exhausted int64
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := b.Take(); err == nil {
				atomic.AddInt64(&ok, 1)
			} else if errors.Is(err, ErrRetryBudgetExhausted) {
				atomic.AddInt64(&exhausted, 1)
			}
		}()
	}
	wg.Wait()

	if ok != limit {
		t.Errorf("expected exactly %d successful takes, got %d", limit, ok)
	}
	if exhausted != goroutines-limit {
		t.Errorf("expected %d exhaustions, got %d", goroutines-limit, exhausted)
	}
}
