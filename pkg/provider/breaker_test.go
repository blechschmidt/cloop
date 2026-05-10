package provider

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fakeClock is a manually-advanced clock for deterministic breaker tests.
type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func newFakeClock(t time.Time) *fakeClock { return &fakeClock{now: t} }

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

func newTestBreaker(clock *fakeClock) *CircuitBreaker {
	b := NewCircuitBreaker("test", BreakerConfig{
		FailureThreshold: 3,
		FailureWindow:    10 * time.Second,
		Cooldown:         5 * time.Second,
	})
	b.SetClock(clock.Now)
	return b
}

func TestBreaker_DefaultsApplied(t *testing.T) {
	b := NewCircuitBreaker("k", BreakerConfig{})
	cfg := b.Config()
	if cfg.FailureThreshold != 5 {
		t.Errorf("FailureThreshold default: want 5, got %d", cfg.FailureThreshold)
	}
	if cfg.FailureWindow != 60*time.Second {
		t.Errorf("FailureWindow default: want 60s, got %v", cfg.FailureWindow)
	}
	if cfg.Cooldown != 30*time.Second {
		t.Errorf("Cooldown default: want 30s, got %v", cfg.Cooldown)
	}
}

func TestBreaker_ClosedAllowsAllRequests(t *testing.T) {
	clock := newFakeClock(time.Now())
	b := newTestBreaker(clock)

	for i := 0; i < 100; i++ {
		if !b.Allow() {
			t.Fatalf("expected closed breaker to allow request %d", i)
		}
		b.RecordSuccess()
	}
	if got := b.Status().State; got != "closed" {
		t.Errorf("expected state=closed, got %s", got)
	}
}

func TestBreaker_TransitionsClosedToOpen(t *testing.T) {
	clock := newFakeClock(time.Now())
	b := newTestBreaker(clock)
	want := errors.New("upstream down")

	// 2 failures: still closed.
	for i := 0; i < 2; i++ {
		if !b.Allow() {
			t.Fatalf("attempt %d: should be allowed", i)
		}
		b.RecordFailure(want)
	}
	if s := b.Status().State; s != "closed" {
		t.Fatalf("after 2 failures want state=closed, got %s", s)
	}

	// 3rd failure trips the breaker.
	if !b.Allow() {
		t.Fatal("3rd attempt: should be allowed")
	}
	b.RecordFailure(want)

	st := b.Status()
	if st.State != "open" {
		t.Errorf("after threshold failures: want state=open, got %s", st.State)
	}
	if st.LastError != want.Error() {
		t.Errorf("LastError: want %q, got %q", want.Error(), st.LastError)
	}
	if st.RecentFailures != 3 {
		t.Errorf("RecentFailures: want 3, got %d", st.RecentFailures)
	}

	// Subsequent calls are blocked while open.
	if b.Allow() {
		t.Error("open breaker must reject Allow()")
	}
}

func TestBreaker_OpenTransitionsToHalfOpenAfterCooldown(t *testing.T) {
	clock := newFakeClock(time.Now())
	b := newTestBreaker(clock)

	// Trip it.
	for i := 0; i < 3; i++ {
		b.Allow()
		b.RecordFailure(errors.New("boom"))
	}
	if b.Status().State != "open" {
		t.Fatal("setup: breaker should be open")
	}

	// Just before cooldown elapses: still open.
	clock.Advance(4*time.Second + 999*time.Millisecond)
	if b.Allow() {
		t.Error("breaker must remain open until cooldown elapses")
	}

	// At cooldown: probe admitted, state moves to half-open.
	clock.Advance(2 * time.Millisecond) // > 5s total
	if !b.Allow() {
		t.Fatal("breaker should admit a probe after cooldown")
	}
	if got := b.Status().State; got != "half_open" {
		t.Errorf("after cooldown probe admitted: want state=half_open, got %s", got)
	}

	// While the probe is in flight, no second request gets through.
	if b.Allow() {
		t.Error("half-open with in-flight probe must reject concurrent requests")
	}
}

func TestBreaker_HalfOpenSuccessClosesBreaker(t *testing.T) {
	clock := newFakeClock(time.Now())
	b := newTestBreaker(clock)

	// Trip + cool down.
	for i := 0; i < 3; i++ {
		b.Allow()
		b.RecordFailure(errors.New("boom"))
	}
	clock.Advance(6 * time.Second)
	if !b.Allow() {
		t.Fatal("expected probe to be admitted")
	}

	// Probe succeeds.
	b.RecordSuccess()
	st := b.Status()
	if st.State != "closed" {
		t.Errorf("after successful probe: want state=closed, got %s", st.State)
	}
	if st.RecentFailures != 0 {
		t.Errorf("RecentFailures after recovery: want 0, got %d", st.RecentFailures)
	}
	if st.ConsecutiveFails != 0 {
		t.Errorf("ConsecutiveFails after recovery: want 0, got %d", st.ConsecutiveFails)
	}

	// Subsequent traffic flows freely again.
	if !b.Allow() {
		t.Error("closed breaker must admit requests")
	}
}

func TestBreaker_HalfOpenFailureReopensWithFreshCooldown(t *testing.T) {
	clock := newFakeClock(time.Now())
	b := newTestBreaker(clock)

	// Trip + cool down.
	for i := 0; i < 3; i++ {
		b.Allow()
		b.RecordFailure(errors.New("boom"))
	}
	clock.Advance(6 * time.Second)
	if !b.Allow() {
		t.Fatal("probe should be admitted")
	}

	// Probe fails: re-open with full cooldown.
	b.RecordFailure(errors.New("still down"))
	if got := b.Status().State; got != "open" {
		t.Fatalf("after failed probe: want state=open, got %s", got)
	}

	// Just before the new cooldown elapses, still open.
	clock.Advance(4 * time.Second)
	if b.Allow() {
		t.Error("breaker should remain open during fresh cooldown")
	}

	// After full new cooldown, half-open again.
	clock.Advance(2 * time.Second)
	if !b.Allow() {
		t.Error("breaker should re-admit a probe after the second cooldown")
	}
	if got := b.Status().State; got != "half_open" {
		t.Errorf("want state=half_open, got %s", got)
	}
}

func TestBreaker_FailuresOutsideWindowDoNotTrip(t *testing.T) {
	clock := newFakeClock(time.Now())
	b := newTestBreaker(clock) // window=10s, threshold=3

	// 2 failures.
	for i := 0; i < 2; i++ {
		b.Allow()
		b.RecordFailure(errors.New("boom"))
	}
	// Step past the window so the early failures expire.
	clock.Advance(11 * time.Second)
	// Two more failures within a fresh window.
	for i := 0; i < 2; i++ {
		b.Allow()
		b.RecordFailure(errors.New("boom"))
	}

	st := b.Status()
	if st.State != "closed" {
		t.Errorf("want state=closed (failures outside window expired), got %s", st.State)
	}
	if st.RecentFailures != 2 {
		t.Errorf("want 2 recent failures inside window, got %d", st.RecentFailures)
	}
}

func TestBreaker_StatusReportsCooldownRemaining(t *testing.T) {
	clock := newFakeClock(time.Now())
	b := newTestBreaker(clock)
	for i := 0; i < 3; i++ {
		b.Allow()
		b.RecordFailure(errors.New("boom"))
	}
	clock.Advance(2 * time.Second)
	st := b.Status()
	if st.State != "open" {
		t.Fatalf("setup: want state=open, got %s", st.State)
	}
	if st.CooldownRemaining != 3*time.Second {
		t.Errorf("CooldownRemaining: want 3s, got %v", st.CooldownRemaining)
	}
	if st.OpenedAt.IsZero() {
		t.Error("OpenedAt should be set when state=open")
	}
}

func TestBreaker_ResetReturnsToClosed(t *testing.T) {
	clock := newFakeClock(time.Now())
	b := newTestBreaker(clock)
	for i := 0; i < 3; i++ {
		b.Allow()
		b.RecordFailure(errors.New("boom"))
	}
	if b.Status().State != "open" {
		t.Fatal("setup failed")
	}
	b.Reset()
	st := b.Status()
	if st.State != "closed" {
		t.Errorf("after Reset: want state=closed, got %s", st.State)
	}
	if st.RecentFailures != 0 || st.ConsecutiveFails != 0 {
		t.Errorf("Reset did not clear failure counters: %+v", st)
	}
}

func TestBreaker_ConcurrentAccessDoesNotRace(t *testing.T) {
	// Run with -race to catch data races on the breaker's internal state.
	b := NewCircuitBreaker("concurrent", BreakerConfig{
		FailureThreshold: 100,
		FailureWindow:    time.Minute,
		Cooldown:         time.Second,
	})

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				if b.Allow() {
					if j%2 == 0 {
						b.RecordSuccess()
					} else {
						b.RecordFailure(errors.New("e"))
					}
				}
				_ = b.Status()
			}
		}()
	}
	wg.Wait()
}

// TestBreaker_HalfOpenAdmitsExactlyOneConcurrentProbe asserts the
// half-open exclusivity invariant: among N goroutines simultaneously
// calling Allow() while the breaker is half-open, exactly one is
// admitted. The remaining callers must be rejected to protect the
// upstream from a thundering-herd probe storm.
func TestBreaker_HalfOpenAdmitsExactlyOneConcurrentProbe(t *testing.T) {
	clock := newFakeClock(time.Now())
	b := newTestBreaker(clock)

	// Trip and let cooldown elapse so the next Allow() will transition
	// the breaker into half-open.
	for i := 0; i < 3; i++ {
		b.Allow()
		b.RecordFailure(errors.New("boom"))
	}
	clock.Advance(6 * time.Second)
	if b.Status().State != "open" {
		t.Fatalf("setup: want open, got %s", b.Status().State)
	}

	const goroutines = 64
	var (
		admitted atomic.Int32
		start    sync.WaitGroup
		done     sync.WaitGroup
	)
	start.Add(1)
	for i := 0; i < goroutines; i++ {
		done.Add(1)
		go func() {
			defer done.Done()
			start.Wait() // line everyone up at the gate
			if b.Allow() {
				admitted.Add(1)
			}
		}()
	}
	start.Done() // release the herd
	done.Wait()

	if got := admitted.Load(); got != 1 {
		t.Errorf("half-open exclusivity violated: %d goroutines admitted, want exactly 1", got)
	}
	if got := b.Status().State; got != "half_open" {
		t.Errorf("after probe admission: want state=half_open, got %s", got)
	}
}

// TestBreaker_ConcurrentFailuresTripBreakerOnce asserts that under
// concurrent failure recording the breaker reaches the open state and
// only counts a bounded number of in-window failures (sliding window
// trim does not corrupt under contention).
func TestBreaker_ConcurrentFailuresTripBreakerOnce(t *testing.T) {
	b := NewCircuitBreaker("concurrent-trip", BreakerConfig{
		FailureThreshold: 5,
		FailureWindow:    time.Minute,
		Cooldown:         time.Hour,
	})

	const goroutines = 32
	const perGoroutine = 10

	var wg sync.WaitGroup
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < perGoroutine; j++ {
				if b.Allow() {
					b.RecordFailure(errors.New("boom"))
				}
			}
		}()
	}
	wg.Wait()

	st := b.Status()
	if st.State != "open" {
		t.Errorf("after concurrent failures: want state=open, got %s", st.State)
	}
	// Each goroutine sees Allow()=false once the breaker opens, so
	// total failures recorded must be < goroutines * perGoroutine.
	if st.RecentFailures > goroutines*perGoroutine {
		t.Errorf("RecentFailures inflated under contention: got %d", st.RecentFailures)
	}
	if st.RecentFailures < 5 {
		t.Errorf("RecentFailures should be at least the threshold: got %d", st.RecentFailures)
	}
}

// TestBreaker_ReleaseProbeAllowsNextAttempt verifies that releasing an
// in-flight probe (e.g., on context cancellation) leaves the breaker in
// half-open and admits the next caller as a fresh probe rather than
// silently rejecting all subsequent attempts.
func TestBreaker_ReleaseProbeAllowsNextAttempt(t *testing.T) {
	clock := newFakeClock(time.Now())
	b := newTestBreaker(clock)

	for i := 0; i < 3; i++ {
		b.Allow()
		b.RecordFailure(errors.New("boom"))
	}
	clock.Advance(6 * time.Second)
	if !b.Allow() {
		t.Fatal("setup: probe must be admitted after cooldown")
	}
	if got := b.Status().State; got != "half_open" {
		t.Fatalf("setup: want state=half_open, got %s", got)
	}

	// Concurrent caller while probe in flight is rejected.
	if b.Allow() {
		t.Fatal("second caller must be rejected while probe in flight")
	}

	// Release the probe slot without recording outcome (e.g., the probe
	// caller's context was cancelled).
	b.releaseProbe()

	// Breaker stays in half-open and admits the next caller.
	if got := b.Status().State; got != "half_open" {
		t.Errorf("after releaseProbe: want state=half_open, got %s", got)
	}
	if !b.Allow() {
		t.Error("after releaseProbe: next caller should be admitted as fresh probe")
	}
	b.RecordSuccess()
	if got := b.Status().State; got != "closed" {
		t.Errorf("after fresh probe success: want state=closed, got %s", got)
	}
}

// TestBreaker_ReopensAfterEachFailedProbe verifies that each failed
// probe re-opens the breaker with a full fresh cooldown, even across
// multiple recovery attempts.
func TestBreaker_ReopensAfterEachFailedProbe(t *testing.T) {
	clock := newFakeClock(time.Now())
	b := newTestBreaker(clock)

	for i := 0; i < 3; i++ {
		b.Allow()
		b.RecordFailure(errors.New("boom"))
	}

	// Three full open → half-open → open cycles.
	for cycle := 0; cycle < 3; cycle++ {
		clock.Advance(6 * time.Second)
		if !b.Allow() {
			t.Fatalf("cycle %d: probe should be admitted after cooldown", cycle)
		}
		if got := b.Status().State; got != "half_open" {
			t.Fatalf("cycle %d: want state=half_open, got %s", cycle, got)
		}
		b.RecordFailure(errors.New("still down"))
		st := b.Status()
		if st.State != "open" {
			t.Fatalf("cycle %d: want state=open after probe failure, got %s", cycle, st.State)
		}
		if st.CooldownRemaining < 4*time.Second {
			t.Errorf("cycle %d: cooldown should reset to ~5s; got %v", cycle, st.CooldownRemaining)
		}
	}
}

// TestBreaker_RecordOutOfBandSuccess covers the defensive branches
// where RecordSuccess is called in unexpected states. The breaker must
// not panic and counters must move toward a healthy state.
func TestBreaker_RecordOutOfBandSuccess(t *testing.T) {
	clock := newFakeClock(time.Now())
	b := newTestBreaker(clock)

	// Closed-state success: clears failure history.
	b.Allow()
	b.RecordFailure(errors.New("boom"))
	if b.Status().RecentFailures != 1 {
		t.Fatal("setup: failure not recorded")
	}
	b.RecordSuccess()
	if got := b.Status().RecentFailures; got != 0 {
		t.Errorf("RecordSuccess in closed: failures want 0, got %d", got)
	}

	// Open-state success (out-of-order callback): does not panic and
	// resets the consecutive-fails counter defensively.
	for i := 0; i < 3; i++ {
		b.Allow()
		b.RecordFailure(errors.New("boom"))
	}
	if b.Status().State != "open" {
		t.Fatal("setup: breaker should be open")
	}
	b.RecordSuccess()
	if got := b.Status().ConsecutiveFails; got != 0 {
		t.Errorf("RecordSuccess in open: ConsecutiveFails want 0, got %d", got)
	}
}

// --- registry tests ---------------------------------------------------------

func TestRegistry_GetBreakerReturnsSingleton(t *testing.T) {
	ResetAllBreakers()
	defer ResetAllBreakers()

	a := GetBreaker("provider-x")
	b := GetBreaker("provider-x")
	if a != b {
		t.Error("GetBreaker should return the same instance for the same key")
	}
	c := GetBreaker("provider-y")
	if a == c {
		t.Error("GetBreaker should return distinct instances for different keys")
	}
}

func TestRegistry_AllBreakerStatusesSorted(t *testing.T) {
	ResetAllBreakers()
	defer ResetAllBreakers()

	GetBreaker("zeta")
	GetBreaker("alpha")
	GetBreaker("mu")

	statuses := AllBreakerStatuses()
	if len(statuses) != 3 {
		t.Fatalf("want 3 statuses, got %d", len(statuses))
	}
	wantOrder := []string{"alpha", "mu", "zeta"}
	for i, s := range statuses {
		if s.Key != wantOrder[i] {
			t.Errorf("position %d: want key=%q, got %q", i, wantOrder[i], s.Key)
		}
	}
}

// --- DoWithRetry integration tests ------------------------------------------

func TestDoWithRetry_BreakerOpenShortCircuitsImmediately(t *testing.T) {
	ResetAllBreakers()
	defer ResetAllBreakers()

	key := "shortcircuit-test"
	b := NewCircuitBreaker(key, BreakerConfig{
		FailureThreshold: 2,
		FailureWindow:    time.Minute,
		Cooldown:         time.Hour, // never recover within the test
	})
	RegisterBreaker(key, b)

	cfg := RetryConfig{
		MaxAttempts:  1, // single attempt per call so we control failures
		InitialDelay: time.Millisecond,
		MaxDelay:     time.Millisecond,
		BreakerKey:   key,
	}

	// Two calls fail with a retryable status: trips the breaker.
	for i := 0; i < 2; i++ {
		err := DoWithRetry(context.Background(), cfg, func() (int, error) {
			return 503, errors.New("upstream 503")
		})
		if err == nil {
			t.Fatalf("call %d: expected error", i)
		}
	}
	if b.Status().State != "open" {
		t.Fatalf("expected breaker open after threshold, got %s", b.Status().State)
	}

	// Next call must short-circuit without calling fn.
	var called atomic.Int32
	err := DoWithRetry(context.Background(), cfg, func() (int, error) {
		called.Add(1)
		return 200, nil
	})
	if err == nil {
		t.Fatal("expected ErrCircuitOpen, got nil")
	}
	if !errors.Is(err, ErrCircuitOpen) {
		t.Errorf("want ErrCircuitOpen, got %v", err)
	}
	if called.Load() != 0 {
		t.Errorf("upstream fn was called %d times; expected 0 (short-circuited)", called.Load())
	}
	if !strings.Contains(err.Error(), key) {
		t.Errorf("breaker error should include key %q: %v", key, err)
	}
}

func TestDoWithRetry_BreakerSucceedsAfterCooldown(t *testing.T) {
	ResetAllBreakers()
	defer ResetAllBreakers()

	clock := newFakeClock(time.Now())
	key := "cooldown-test"
	b := NewCircuitBreaker(key, BreakerConfig{
		FailureThreshold: 2,
		FailureWindow:    time.Minute,
		Cooldown:         100 * time.Millisecond,
	})
	b.SetClock(clock.Now)
	RegisterBreaker(key, b)

	cfg := RetryConfig{
		MaxAttempts:  1,
		InitialDelay: time.Millisecond,
		MaxDelay:     time.Millisecond,
		BreakerKey:   key,
	}

	// Trip it.
	for i := 0; i < 2; i++ {
		_ = DoWithRetry(context.Background(), cfg, func() (int, error) {
			return 503, errors.New("down")
		})
	}
	if b.Status().State != "open" {
		t.Fatalf("setup: want open, got %s", b.Status().State)
	}

	// Within cooldown: short-circuited.
	clock.Advance(50 * time.Millisecond)
	err := DoWithRetry(context.Background(), cfg, func() (int, error) {
		t.Fatal("upstream should not be called while breaker is open")
		return 200, nil
	})
	if !errors.Is(err, ErrCircuitOpen) {
		t.Errorf("want ErrCircuitOpen during cooldown, got %v", err)
	}

	// After cooldown: probe is admitted; success closes the breaker.
	clock.Advance(60 * time.Millisecond)
	var probeRan bool
	err = DoWithRetry(context.Background(), cfg, func() (int, error) {
		probeRan = true
		return 200, nil
	})
	if err != nil {
		t.Fatalf("probe should succeed, got %v", err)
	}
	if !probeRan {
		t.Error("probe fn was not called")
	}
	if got := b.Status().State; got != "closed" {
		t.Errorf("after successful probe: want state=closed, got %s", got)
	}
}

func TestDoWithRetry_NonRetryableStatusDoesNotTripBreaker(t *testing.T) {
	ResetAllBreakers()
	defer ResetAllBreakers()

	key := "client-err-test"
	b := NewCircuitBreaker(key, BreakerConfig{
		FailureThreshold: 2,
		FailureWindow:    time.Minute,
		Cooldown:         time.Hour,
	})
	RegisterBreaker(key, b)

	cfg := RetryConfig{
		MaxAttempts:  1,
		InitialDelay: time.Millisecond,
		MaxDelay:     time.Millisecond,
		BreakerKey:   key,
	}

	// 4xx errors are caller-side problems, not upstream unavailability;
	// they must not contribute to the breaker's failure count.
	for i := 0; i < 5; i++ {
		_ = DoWithRetry(context.Background(), cfg, func() (int, error) {
			return 401, errors.New("unauthorized")
		})
	}
	st := b.Status()
	if st.State != "closed" {
		t.Errorf("client errors should not trip breaker; got state=%s", st.State)
	}
	if st.RecentFailures != 0 {
		t.Errorf("client errors should not be counted; got %d", st.RecentFailures)
	}
}

func TestDoWithRetry_ContextCancelDoesNotTripBreaker(t *testing.T) {
	ResetAllBreakers()
	defer ResetAllBreakers()

	key := "cancel-test"
	b := NewCircuitBreaker(key, BreakerConfig{
		FailureThreshold: 2,
		FailureWindow:    time.Minute,
		Cooldown:         time.Hour,
	})
	RegisterBreaker(key, b)

	cfg := RetryConfig{
		MaxAttempts:  1,
		InitialDelay: time.Millisecond,
		MaxDelay:     time.Millisecond,
		BreakerKey:   key,
	}

	for i := 0; i < 5; i++ {
		ctx, cancel := context.WithCancel(context.Background())
		cancel() // cancel before calling
		_ = DoWithRetry(ctx, cfg, func() (int, error) {
			return 0, context.Canceled
		})
	}
	if got := b.Status().State; got != "closed" {
		t.Errorf("context cancel should not affect breaker state; got %s", got)
	}
}

func TestDoWithRetry_BreakerWithMultiAttemptRetries(t *testing.T) {
	// When MaxAttempts > 1, each attempt within a single DoWithRetry call
	// goes through the breaker. Failures during the same call should still
	// trip the breaker after enough cumulative failures.
	ResetAllBreakers()
	defer ResetAllBreakers()

	key := "multi-attempt-test"
	b := NewCircuitBreaker(key, BreakerConfig{
		FailureThreshold: 3,
		FailureWindow:    time.Minute,
		Cooldown:         time.Hour,
	})
	RegisterBreaker(key, b)

	cfg := RetryConfig{
		MaxAttempts:  5,
		InitialDelay: time.Microsecond,
		MaxDelay:     time.Microsecond,
		BreakerKey:   key,
	}

	calls := 0
	err := DoWithRetry(context.Background(), cfg, func() (int, error) {
		calls++
		return 503, errors.New("down")
	})
	if err == nil {
		t.Fatal("expected error")
	}
	// First 3 attempts run and fail (tripping the breaker on the 3rd
	// failure). Attempts 4 and 5 should be short-circuited by the
	// breaker check at the top of the loop.
	if calls != 3 {
		t.Errorf("expected 3 attempts (3rd trips breaker, rest short-circuit), got %d", calls)
	}
	if got := b.Status().State; got != "open" {
		t.Errorf("breaker should be open; got %s", got)
	}
}
