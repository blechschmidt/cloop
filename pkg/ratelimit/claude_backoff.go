// Package ratelimit - claude_backoff.go decides how long to stay away from the
// Claude Code subscription usage API after a failed fetch.
//
// Motivation (Task 20326): the dashboard was observed calling
// /api/claudecode-limits about once a second, and the caps panel was reporting
// "Rate limited. Please try again later." The two were connected, but not in
// the obvious way — the handler caches for MinUsageCacheTTL, so the browser's
// polling could not by itself reach the upstream API more than once a minute.
//
// The connection was here. A failed fetch does not refresh the snapshot, so
// the *only* thing standing between a caller and another upstream request is
// this backoff, and it was a flat 30s — half of MinUsageCacheTTL. So a hub
// that was healthy asked once a minute, and a hub that had just been told
// "too many requests" asked twice a minute. Being rate-limited made cloop
// press harder, which is exactly the self-sustaining loop the old comment on
// transientBackoff said it existed to prevent.
//
// The rule this file encodes: a rate-limit response must never be retried
// sooner than a success would have been re-fetched, it must honour Retry-After
// when the server sends one, and repeated refusals must escalate rather than
// settle into a fixed drumbeat.
package ratelimit

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ErrUsageRateLimited marks a usage fetch that the server refused for rate
// reasons. Callers match it with errors.Is rather than string-matching the
// "Rate limited. Please try again later." body.
var ErrUsageRateLimited = errors.New("claude usage API rate limited")

// RateLimitError is a usage fetch refused with 429 (or an overload status),
// carrying the server's own Retry-After when it sent one.
type RateLimitError struct {
	Status int
	// RetryAfter is the server's instruction, or 0 when it gave none. It is a
	// floor on the backoff, never a ceiling: a server asking for ten minutes
	// gets ten minutes even though our own escalation would have asked for
	// less.
	RetryAfter time.Duration
	Detail     string
}

func (e *RateLimitError) Error() string {
	detail := e.Detail
	if detail == "" {
		detail = fmt.Sprintf("usage API returned status %d", e.Status)
	}
	if e.RetryAfter > 0 {
		return fmt.Sprintf("%s (retry after %s)", detail, e.RetryAfter.Round(time.Second))
	}
	return detail
}

func (e *RateLimitError) Unwrap() error { return ErrUsageRateLimited }

// transientBackoff is how long a *non-auth, non-rate-limit* fetch failure (a
// network error, a 5xx) suppresses further attempts.
//
// Without it a failing fetch is retried by every caller that asks, because
// only a successful fetch populates the snapshot cache: before every task in a
// parallel plan and on every dashboard render. These failures genuinely are
// transient and carry no signal that we are the cause, so this stays short.
const transientBackoff = 30 * time.Second

// rateLimitBackoff is the first wall after a rate-limit response, and the base
// of the escalation. It is deliberately >= MinUsageCacheTTL: retrying a
// refusal sooner than we would have refreshed a success is what turned a
// transient 429 into a standing one.
const rateLimitBackoff = MinUsageCacheTTL

// maxRateLimitBackoff caps the escalation. Long enough that a hub left open
// overnight stops contributing to the problem; short enough that an operator
// who fixes the cause does not have to wait out an hour to see the caps move.
const maxRateLimitBackoff = 15 * time.Minute

type fetchFailure struct {
	err   error
	at    time.Time
	until time.Time
	// streak counts consecutive rate-limit refusals, so the wall grows while
	// the server keeps saying no. Reset by any successful fetch.
	streak int
}

var (
	fetchErrMu sync.Mutex
	fetchErrs  = map[string]fetchFailure{}
)

// recentFetchError returns a still-current failure for dir, or nil to let the
// caller make a live attempt.
func recentFetchError(dir string) error {
	fetchErrMu.Lock()
	defer fetchErrMu.Unlock()
	f := fetchErrs[dir]
	if f.err != nil && time.Now().Before(f.until) {
		return f.err
	}
	return nil
}

// recordFetchError stores err against dir and computes how long it suppresses
// further attempts. A rate-limit refusal escalates; anything else does not.
func recordFetchError(dir string, err error) {
	now := time.Now()
	fetchErrMu.Lock()
	defer fetchErrMu.Unlock()

	prev := fetchErrs[dir]
	var rl *RateLimitError
	if !errors.As(err, &rl) {
		// A network blip or 5xx says nothing about our request rate, so it
		// neither escalates nor inherits an escalation.
		fetchErrs[dir] = fetchFailure{err: err, at: now, until: now.Add(transientBackoff)}
		return
	}

	streak := prev.streak + 1
	fetchErrs[dir] = fetchFailure{
		err:    err,
		at:     now,
		until:  now.Add(rateLimitWait(streak, rl.RetryAfter)),
		streak: streak,
	}
}

// rateLimitWait is the backoff for the streak'th consecutive refusal, honouring
// a server-supplied Retry-After as a floor. Exported behaviour, unexported
// name: the invariant that matters to the rest of the system is that the result
// is never below MinUsageCacheTTL, and TestRateLimitWaitNeverBelowCacheTTL
// holds it there.
func rateLimitWait(streak int, retryAfter time.Duration) time.Duration {
	if streak < 1 {
		streak = 1
	}
	// Exponential in the streak, saturating at the cap. The shift is computed
	// in float64 so a long-lived hub cannot overflow it into a negative
	// duration the way `base << streak` eventually would.
	grown := float64(rateLimitBackoff) * math.Pow(2, float64(streak-1))
	wait := maxRateLimitBackoff
	if grown < float64(maxRateLimitBackoff) {
		wait = time.Duration(grown)
	}
	// The server's instruction wins when it asks for longer than we chose. It
	// is not allowed to ask for *shorter*: a 429 answered with Retry-After: 1
	// would otherwise put us straight back into the loop this file exists to
	// break.
	if retryAfter > wait {
		wait = retryAfter
	}
	if wait < rateLimitBackoff {
		wait = rateLimitBackoff
	}
	return wait
}

func clearFetchError(dir string) {
	fetchErrMu.Lock()
	delete(fetchErrs, dir)
	fetchErrMu.Unlock()
}

// parseRetryAfter reads an RFC 7231 Retry-After header, which may be either a
// delay in seconds or an HTTP date. Returns 0 when absent or unparseable —
// callers treat that as "the server gave no instruction", not as "retry now".
func parseRetryAfter(h http.Header, now time.Time) time.Duration {
	v := h.Get("Retry-After")
	if v == "" {
		return 0
	}
	if secs, err := strconv.Atoi(v); err == nil {
		if secs <= 0 {
			return 0
		}
		return time.Duration(secs) * time.Second
	}
	if when, err := http.ParseTime(v); err == nil {
		if d := when.Sub(now); d > 0 {
			return d
		}
	}
	return 0
}

// maxRateLimitDetailBytes bounds how much of a rate-limit body is quoted back
// to the operator. The message is a sentence; a gateway that answers 429 with
// an HTML error page should not put a page into the dashboard.
const maxRateLimitDetailBytes = 200

// rateLimitDetail renders the operator-facing reason for a refusal, preferring
// the API's own structured message and falling back to a bounded snippet of
// whatever the body actually was.
func rateLimitDetail(status int, body []byte) string {
	var raw ClaudeUsageResponse
	if err := json.Unmarshal(body, &raw); err == nil && raw.Error != nil &&
		strings.TrimSpace(raw.Error.Message) != "" {
		return "usage API error: " + strings.TrimSpace(raw.Error.Message)
	}
	if s := strings.TrimSpace(string(body)); s != "" && !strings.Contains(s, "<") {
		if len(s) > maxRateLimitDetailBytes {
			s = s[:maxRateLimitDetailBytes] + "…"
		}
		return fmt.Sprintf("usage API returned status %d: %s", status, s)
	}
	return fmt.Sprintf("usage API returned status %d", status)
}

// isRateLimitStatus reports whether a status means "you are asking too often".
// 529 is Anthropic's overloaded status; it is not formally a rate limit but
// responds to the same treatment, and retrying it hard makes it worse.
func isRateLimitStatus(status int) bool {
	return status == http.StatusTooManyRequests || status == 529
}
