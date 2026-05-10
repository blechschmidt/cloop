package provider

import (
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"
)

// CircuitState is the operational state of a circuit breaker.
type CircuitState int

const (
	// CircuitClosed means requests flow through normally.
	CircuitClosed CircuitState = iota
	// CircuitOpen means requests are rejected without being attempted.
	CircuitOpen
	// CircuitHalfOpen means a single probe request is allowed through to test recovery.
	CircuitHalfOpen
)

func (s CircuitState) String() string {
	switch s {
	case CircuitClosed:
		return "closed"
	case CircuitOpen:
		return "open"
	case CircuitHalfOpen:
		return "half_open"
	default:
		return "unknown"
	}
}

// ErrCircuitOpen is returned by DoWithRetry when the breaker rejects a request.
var ErrCircuitOpen = errors.New("provider: circuit breaker is open")

// BreakerConfig configures a CircuitBreaker.
type BreakerConfig struct {
	// FailureThreshold is the number of failures within FailureWindow that
	// trigger a transition from closed to open. Default: 5.
	FailureThreshold int
	// FailureWindow is the rolling window in which failures are counted.
	// Default: 60s.
	FailureWindow time.Duration
	// Cooldown is the duration the breaker stays open before transitioning
	// to half-open and admitting a probe request. Default: 30s.
	Cooldown time.Duration
}

func (c BreakerConfig) withDefaults() BreakerConfig {
	if c.FailureThreshold <= 0 {
		c.FailureThreshold = 5
	}
	if c.FailureWindow <= 0 {
		c.FailureWindow = 60 * time.Second
	}
	if c.Cooldown <= 0 {
		c.Cooldown = 30 * time.Second
	}
	return c
}

// BreakerStatus is a point-in-time snapshot of a breaker for surfacing in
// the UI or metrics layer. Safe to copy across goroutines.
type BreakerStatus struct {
	Key              string        `json:"key"`
	State            string        `json:"state"`
	ConsecutiveFails int           `json:"consecutive_failures"`
	RecentFailures   int           `json:"recent_failures"`
	OpenedAt         time.Time     `json:"opened_at,omitempty"`
	CooldownRemaining time.Duration `json:"cooldown_remaining"`
	LastFailure      time.Time     `json:"last_failure,omitempty"`
	LastError        string        `json:"last_error,omitempty"`
}

// CircuitBreaker tracks failures for one logical endpoint (typically a single
// upstream provider) and short-circuits new requests when the upstream is
// failing repeatedly. The zero value is not usable; call NewCircuitBreaker.
type CircuitBreaker struct {
	key string
	cfg BreakerConfig
	now func() time.Time

	mu               sync.Mutex
	state            CircuitState
	consecutiveFails int
	failures         []time.Time // sliding window of recent failure timestamps
	openedAt         time.Time
	lastFailureAt    time.Time
	lastError        string
	probeInFlight    bool // true while a half-open probe request is outstanding
}

// NewCircuitBreaker creates a breaker for the given key (used in Status).
func NewCircuitBreaker(key string, cfg BreakerConfig) *CircuitBreaker {
	return &CircuitBreaker{
		key: key,
		cfg: cfg.withDefaults(),
		now: time.Now,
	}
}

// SetClock overrides the breaker's time source. Test-only — not concurrency
// safe with in-flight Allow/RecordSuccess/RecordFailure calls.
func (b *CircuitBreaker) SetClock(now func() time.Time) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if now == nil {
		now = time.Now
	}
	b.now = now
}

// Config returns the effective configuration (with defaults applied).
func (b *CircuitBreaker) Config() BreakerConfig { return b.cfg }

// Allow checks whether a request should be admitted. It mutates the breaker's
// state to handle cooldown expiry (open → half-open) and probe gating.
// Callers MUST follow Allow()==true with exactly one of RecordSuccess or
// RecordFailure when the request completes.
func (b *CircuitBreaker) Allow() bool {
	b.mu.Lock()
	defer b.mu.Unlock()

	now := b.now()
	switch b.state {
	case CircuitClosed:
		return true
	case CircuitOpen:
		if now.Sub(b.openedAt) >= b.cfg.Cooldown {
			b.state = CircuitHalfOpen
			b.probeInFlight = true
			return true
		}
		return false
	case CircuitHalfOpen:
		// Only one probe at a time. Reject concurrent requests until the
		// in-flight probe resolves, then close or re-open the breaker.
		if b.probeInFlight {
			return false
		}
		b.probeInFlight = true
		return true
	}
	return false
}

// RecordSuccess marks the most recent admitted request as successful. In
// half-open state this closes the breaker and clears all failure history.
func (b *CircuitBreaker) RecordSuccess() {
	b.mu.Lock()
	defer b.mu.Unlock()

	switch b.state {
	case CircuitHalfOpen:
		b.state = CircuitClosed
		b.consecutiveFails = 0
		b.failures = nil
		b.openedAt = time.Time{}
		b.probeInFlight = false
	case CircuitClosed:
		b.consecutiveFails = 0
		b.failures = nil
	case CircuitOpen:
		// Shouldn't happen — Allow() returns false in this state — but
		// reset state defensively if it does (e.g., out-of-order callbacks).
		b.consecutiveFails = 0
	}
}

// RecordFailure marks the most recent admitted request as failed. May
// transition the breaker from closed → open (after threshold failures
// within the rolling window) or half-open → open (probe failed).
func (b *CircuitBreaker) RecordFailure(err error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	now := b.now()
	b.consecutiveFails++
	b.lastFailureAt = now
	if err != nil {
		b.lastError = err.Error()
	}
	b.failures = append(b.failures, now)
	b.trimFailuresLocked(now)

	switch b.state {
	case CircuitHalfOpen:
		// Probe failed: re-open with a fresh cooldown.
		b.state = CircuitOpen
		b.openedAt = now
		b.probeInFlight = false
	case CircuitClosed:
		if len(b.failures) >= b.cfg.FailureThreshold {
			b.state = CircuitOpen
			b.openedAt = now
		}
	case CircuitOpen:
		// Out-of-order callback: keep the failure recorded but don't
		// alter timing.
	}
}

// trimFailuresLocked drops failure timestamps older than the window.
// Caller must hold b.mu.
func (b *CircuitBreaker) trimFailuresLocked(now time.Time) {
	cutoff := now.Add(-b.cfg.FailureWindow)
	idx := sort.Search(len(b.failures), func(i int) bool {
		return !b.failures[i].Before(cutoff)
	})
	if idx > 0 {
		b.failures = append(b.failures[:0], b.failures[idx:]...)
	}
}

// Status returns a point-in-time snapshot for observation. Side-effect free
// except that it expires an open breaker into half-open if the cooldown has
// passed and there is no in-flight probe (mirrors what Allow would do).
func (b *CircuitBreaker) Status() BreakerStatus {
	b.mu.Lock()
	defer b.mu.Unlock()

	now := b.now()
	b.trimFailuresLocked(now)

	st := BreakerStatus{
		Key:              b.key,
		State:            b.state.String(),
		ConsecutiveFails: b.consecutiveFails,
		RecentFailures:   len(b.failures),
		LastFailure:      b.lastFailureAt,
		LastError:        b.lastError,
	}
	if b.state == CircuitOpen {
		st.OpenedAt = b.openedAt
		remaining := b.cfg.Cooldown - now.Sub(b.openedAt)
		if remaining < 0 {
			remaining = 0
		}
		st.CooldownRemaining = remaining
	}
	return st
}

// releaseProbe clears the probeInFlight flag without recording success
// or failure. Used when a half-open probe was admitted but the request
// outcome doesn't reflect upstream health (e.g., context cancellation
// or a non-retryable client-side error). The breaker stays in the same
// state so the next admitted request becomes the real probe.
func (b *CircuitBreaker) releaseProbe() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.probeInFlight = false
}

// Reset returns the breaker to closed state and clears all history.
// Intended for tests and explicit operator action.
func (b *CircuitBreaker) Reset() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.state = CircuitClosed
	b.consecutiveFails = 0
	b.failures = nil
	b.openedAt = time.Time{}
	b.lastFailureAt = time.Time{}
	b.lastError = ""
	b.probeInFlight = false
}

// --- registry ---------------------------------------------------------------

var (
	breakerRegistryMu sync.Mutex
	breakerRegistry   = make(map[string]*CircuitBreaker)
)

// GetBreaker returns the singleton breaker for the given key, creating one
// with default config if needed. Safe for concurrent use.
func GetBreaker(key string) *CircuitBreaker {
	breakerRegistryMu.Lock()
	defer breakerRegistryMu.Unlock()
	if b, ok := breakerRegistry[key]; ok {
		return b
	}
	b := NewCircuitBreaker(key, BreakerConfig{})
	breakerRegistry[key] = b
	return b
}

// RegisterBreaker installs a custom-configured breaker under the given key.
// Replaces any existing entry. Useful in tests and for tuning per provider.
func RegisterBreaker(key string, b *CircuitBreaker) {
	breakerRegistryMu.Lock()
	defer breakerRegistryMu.Unlock()
	breakerRegistry[key] = b
}

// AllBreakerStatuses returns a snapshot of every registered breaker, sorted
// by key. The UI/metrics layer can render this directly.
func AllBreakerStatuses() []BreakerStatus {
	breakerRegistryMu.Lock()
	keys := make([]string, 0, len(breakerRegistry))
	for k := range breakerRegistry {
		keys = append(keys, k)
	}
	breakers := make([]*CircuitBreaker, 0, len(keys))
	sort.Strings(keys)
	for _, k := range keys {
		breakers = append(breakers, breakerRegistry[k])
	}
	breakerRegistryMu.Unlock()

	out := make([]BreakerStatus, 0, len(breakers))
	for _, b := range breakers {
		out = append(out, b.Status())
	}
	return out
}

// ResetAllBreakers wipes the breaker registry. Test helper.
func ResetAllBreakers() {
	breakerRegistryMu.Lock()
	defer breakerRegistryMu.Unlock()
	breakerRegistry = make(map[string]*CircuitBreaker)
}

// formatBreakerError wraps the underlying error with the breaker key so
// logs and UI clearly indicate which provider tripped.
func formatBreakerError(key string) error {
	return fmt.Errorf("%w (provider=%q)", ErrCircuitOpen, key)
}
