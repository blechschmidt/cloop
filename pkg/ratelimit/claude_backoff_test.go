package ratelimit

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

func resetFetchErrors() {
	fetchErrMu.Lock()
	fetchErrs = map[string]fetchFailure{}
	fetchErrMu.Unlock()
	authFailMu.Lock()
	authFails = map[string]authFailure{}
	authFailMu.Unlock()
}

// writeTestCredentials lays down a .credentials.json that the token resolver
// will accept, so a test can exercise the fetch path without a real login.
func writeTestCredentials(t *testing.T, dir, token string, expires time.Time) {
	t.Helper()
	var creds claudeCredentials
	creds.ClaudeAiOauth.AccessToken = token
	creds.ClaudeAiOauth.ExpiresAt = expires.UnixMilli()
	blob, err := json.Marshal(creds)
	if err != nil {
		t.Fatalf("marshal credentials: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".credentials.json"), blob, 0o600); err != nil {
		t.Fatalf("write credentials: %v", err)
	}
}

// TestRateLimitWaitNeverBelowCacheTTL is the invariant the whole file exists
// for: being rate-limited must never make cloop ask *more* often than it would
// have while healthy. Before Task 20326 the backoff was a flat 30s against a
// 60s success TTL, so a 429 doubled the request rate and kept itself alive.
func TestRateLimitWaitNeverBelowCacheTTL(t *testing.T) {
	for streak := 0; streak <= 20; streak++ {
		for _, ra := range []time.Duration{0, time.Second, 5 * time.Second, time.Hour} {
			got := rateLimitWait(streak, ra)
			if got < MinUsageCacheTTL {
				t.Fatalf("rateLimitWait(%d, %s) = %s, must be >= MinUsageCacheTTL (%s)",
					streak, ra, got, MinUsageCacheTTL)
			}
		}
	}
}

func TestRateLimitWaitEscalatesAndCaps(t *testing.T) {
	first := rateLimitWait(1, 0)
	second := rateLimitWait(2, 0)
	third := rateLimitWait(3, 0)
	if !(first < second && second < third) {
		t.Fatalf("consecutive refusals must escalate: %s, %s, %s", first, second, third)
	}
	if first != rateLimitBackoff {
		t.Fatalf("first refusal should wait rateLimitBackoff (%s), got %s", rateLimitBackoff, first)
	}
	// Far out on the streak the wait must saturate, not overflow into a
	// negative duration (which would read as "retry immediately").
	for _, streak := range []int{20, 64, 1000} {
		if got := rateLimitWait(streak, 0); got != maxRateLimitBackoff {
			t.Fatalf("rateLimitWait(%d, 0) = %s, want cap %s", streak, got, maxRateLimitBackoff)
		}
	}
}

func TestRateLimitWaitHonoursRetryAfterAsFloorOnly(t *testing.T) {
	// A server asking for longer than our own escalation wins.
	if got := rateLimitWait(1, 10*time.Minute); got != 10*time.Minute {
		t.Fatalf("Retry-After longer than our backoff must win, got %s", got)
	}
	// A server asking for *shorter* must not shrink the wall — that is the
	// same self-sustaining loop by another route.
	if got := rateLimitWait(1, time.Second); got < MinUsageCacheTTL {
		t.Fatalf("Retry-After shorter than the floor must be ignored, got %s", got)
	}
	// Above the cap, the server still wins: it knows its own window.
	if got := rateLimitWait(1, 2*maxRateLimitBackoff); got != 2*maxRateLimitBackoff {
		t.Fatalf("Retry-After beyond the cap must be honoured, got %s", got)
	}
}

func TestParseRetryAfter(t *testing.T) {
	now := time.Date(2026, 9, 20, 12, 0, 0, 0, time.UTC)
	cases := []struct {
		name string
		val  string
		want time.Duration
	}{
		{"absent", "", 0},
		{"seconds", "120", 2 * time.Minute},
		{"zero", "0", 0},
		{"negative", "-5", 0},
		{"garbage", "soon", 0},
		{"http date", now.Add(90 * time.Second).Format(http.TimeFormat), 90 * time.Second},
		{"past date", now.Add(-time.Hour).Format(http.TimeFormat), 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := http.Header{}
			if tc.val != "" {
				h.Set("Retry-After", tc.val)
			}
			if got := parseRetryAfter(h, now); got != tc.want {
				t.Fatalf("parseRetryAfter(%q) = %s, want %s", tc.val, got, tc.want)
			}
		})
	}
}

func TestRecordFetchErrorTransientDoesNotEscalate(t *testing.T) {
	resetFetchErrors()
	defer resetFetchErrors()

	const dir = "/transient"
	for i := 0; i < 5; i++ {
		recordFetchError(dir, errors.New("connection reset"))
	}
	fetchErrMu.Lock()
	f := fetchErrs[dir]
	fetchErrMu.Unlock()
	if f.streak != 0 {
		t.Fatalf("a network error must not count toward the rate-limit streak, got %d", f.streak)
	}
	wait := time.Until(f.until)
	if wait > transientBackoff+time.Second {
		t.Fatalf("transient backoff should stay at %s, got %s", transientBackoff, wait)
	}
}

func TestRecordFetchErrorRateLimitEscalatesAndClears(t *testing.T) {
	resetFetchErrors()
	defer resetFetchErrors()

	const dir = "/limited"
	rl := &RateLimitError{Status: http.StatusTooManyRequests, Detail: "Rate limited. Please try again later."}

	recordFetchError(dir, rl)
	fetchErrMu.Lock()
	firstUntil := fetchErrs[dir].until
	fetchErrMu.Unlock()
	if d := time.Until(firstUntil); d < MinUsageCacheTTL-time.Second {
		t.Fatalf("first 429 must hold off at least %s, got %s", MinUsageCacheTTL, d)
	}
	if recentFetchError(dir) == nil {
		t.Fatal("a just-recorded refusal must suppress the next attempt")
	}

	recordFetchError(dir, rl)
	fetchErrMu.Lock()
	secondUntil := fetchErrs[dir].until
	streak := fetchErrs[dir].streak
	fetchErrMu.Unlock()
	if !secondUntil.After(firstUntil) {
		t.Fatalf("a second refusal must extend the wall: %s then %s", firstUntil, secondUntil)
	}
	if streak != 2 {
		t.Fatalf("streak = %d, want 2", streak)
	}

	// A success forgets the escalation, so an operator who fixes the cause
	// does not keep paying for it.
	clearFetchError(dir)
	if recentFetchError(dir) != nil {
		t.Fatal("clearFetchError must lift the wall")
	}
	recordFetchError(dir, rl)
	fetchErrMu.Lock()
	afterClear := fetchErrs[dir].streak
	fetchErrMu.Unlock()
	if afterClear != 1 {
		t.Fatalf("streak must restart after a success, got %d", afterClear)
	}
}

func TestRateLimitErrorUnwrapsToSentinel(t *testing.T) {
	err := error(&RateLimitError{Status: 429, RetryAfter: 30 * time.Second, Detail: "slow down"})
	if !errors.Is(err, ErrUsageRateLimited) {
		t.Fatal("RateLimitError must unwrap to ErrUsageRateLimited so callers never string-match")
	}
	if got := err.Error(); got == "" {
		t.Fatal("RateLimitError must render a message")
	}
	// An auth failure and a rate limit are different problems; conflating them
	// would make the dashboard tell a rate-limited operator to log in again.
	if errors.Is(err, ErrReauthRequired) {
		t.Fatal("a rate limit must not read as a re-authentication")
	}
}

// TestRateLimitedUpstreamIsNotHammered is the end-to-end form: a usage endpoint
// that answers 429 must see one request, not one per caller, however hard the
// dashboard polls.
func TestRateLimitedUpstreamIsNotHammered(t *testing.T) {
	resetUsageCache()
	resetFetchErrors()
	defer func() { resetUsageCache(); resetFetchErrors() }()

	var hits int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&hits, 1)
		w.Header().Set("Retry-After", "120")
		w.WriteHeader(http.StatusTooManyRequests)
		fmt.Fprint(w, "Rate limited. Please try again later.")
	}))
	defer srv.Close()

	prev := usageEndpoint
	usageEndpoint = srv.URL
	defer func() { usageEndpoint = prev }()

	dir := t.TempDir()
	writeTestCredentials(t, dir, "sk-ant-oat01-test", time.Now().Add(time.Hour))

	var lastErr error
	for i := 0; i < 50; i++ {
		_, lastErr = FetchOrCachedUsageIn(dir, "", MinUsageCacheTTL)
	}
	if got := atomic.LoadInt64(&hits); got != 1 {
		t.Fatalf("50 pollers against a rate-limited endpoint made %d upstream requests, want 1", got)
	}
	var rl *RateLimitError
	if !errors.As(lastErr, &rl) {
		t.Fatalf("expected a classified *RateLimitError, got %T: %v", lastErr, lastErr)
	}
	if rl.RetryAfter != 2*time.Minute {
		t.Fatalf("Retry-After not carried through: got %s", rl.RetryAfter)
	}

	// And the wall the server asked for is the one actually in force.
	fetchErrMu.Lock()
	until := fetchErrs[dir].until
	fetchErrMu.Unlock()
	if d := time.Until(until); d < 110*time.Second {
		t.Fatalf("Retry-After: 120 should hold us off ~2m, got %s", d)
	}
}
