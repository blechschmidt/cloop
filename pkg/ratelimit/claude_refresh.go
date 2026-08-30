// Package ratelimit - claude_refresh.go exposes this package's OAuth
// credential refresh to callers outside it.
//
// Motivation (Task 20204): the `claude` CLI subprocesses spawned by
// pkg/provider/claudecode each manage their own OAuth refresh, entirely
// outside the single-flight locks maintained here. Claude.ai refresh tokens
// are single-use and rotate on every exchange, so when a parallel plan runs
// several tasks at once and the access token lapses mid-round, multiple CLI
// processes POST the same refresh token concurrently: one wins, the losers get
// invalid_grant and their task dies with "API Error: 401". The following task
// succeeds because by then the winner has written a fresh credential to disk
// — which is exactly the reported "sometimes 401, next task is fine" symptom.
//
// A provider that hits a 401 therefore wants to re-read — and, only if the
// credential is genuinely stale, rotate — the token under *this* package's
// locks before retrying, rather than immediately re-sending the credential the
// server just rejected.
package ratelimit

// ForceCredentialRefresh returns a currently-valid Claude Code OAuth access
// token, rotating the stored credential when it is past its recorded expiry.
//
// It is safe to call concurrently and from multiple processes: the underlying
// exchange holds the process-wide oauthRefreshMu plus a cross-process flock,
// and re-checks freshness after taking them. When a peer already rotated the
// token while this caller was blocked, the peer's token is returned rather
// than spending the (now consumed) refresh token a second time — so a whole
// parallel round of 401s coalesces into at most one exchange.
//
// Returns "" when no refresh is possible: no credentials file, no refresh
// token, or a failed exchange. Callers should treat that as "retry with
// whatever the CLI resolves for itself" rather than as a hard failure, since
// the credential may legitimately come from elsewhere — CLAUDE_CODE_OAUTH_TOKEN,
// or a long-lived `claude setup-token` credential that carries no refresh
// token at all.
func ForceCredentialRefresh() string {
	return forceRefreshToken()
}
