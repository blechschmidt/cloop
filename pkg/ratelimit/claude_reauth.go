// Package ratelimit - claude_reauth.go classifies *why* the Claude Code
// subscription usage API cannot be reached, so a stalled caps panel says
// "re-authenticate" instead of going quietly blank.
//
// Motivation (Task 20202): this hub's caps stopped updating for four days.
// The OAuth access token had expired and ~/.claude/.credentials.json carried
// an empty refreshToken (the shape `claude setup-token` writes), so the token
// resolver bailed out with a bare "no OAuth token available". Every consumer
// discarded that string: the UI handler dropped the error on the floor, the
// panel rendered four "not reported" rows, and the orchestrator's cap
// enforcement silently degraded to a no-op. Nothing anywhere said the words
// "log in again".
//
// The fix is to make the failure a typed, classified, cached value that the
// API and the dashboard can both render, with a concrete recovery hint.
package ratelimit

import (
	"errors"
	"fmt"
	"sync"
	"time"
)

// Sentinels for errors.Is, so callers never string-match. A transient failure
// resolves itself on the next refresh; these two do not, and the difference is
// exactly what the dashboard needs in order to say something useful.
var (
	// ErrReauthRequired marks every failure that a human fixes by logging
	// into Claude Code again.
	ErrReauthRequired = errors.New("claude code re-authentication required")

	// ErrNoCredentials means no Claude Code credentials were found at all —
	// neither a usable credentials file nor CLAUDE_CODE_OAUTH_TOKEN.
	ErrNoCredentials = errors.New("no claude code credentials available")
)

// AuthProblem classifies why the OAuth credential is unusable. It is
// serialized to the dashboard, so the values are stable identifiers.
type AuthProblem string

const (
	// AuthNoCredentials: no credentials file, no access token in it, and no
	// CLAUDE_CODE_OAUTH_TOKEN in the environment.
	AuthNoCredentials AuthProblem = "no_credentials"
	// AuthRefreshFailed: a refresh token existed but the exchange failed.
	// Usually means the single-use refresh token was already consumed.
	AuthRefreshFailed AuthProblem = "refresh_failed"
	// AuthRejected: a token was sent and the server answered 401. This is
	// the only classification backed by the server's own opinion.
	AuthRejected AuthProblem = "rejected"
	// AuthScopeInsufficient: the token authenticates but was not granted the
	// scope the usage endpoint requires (HTTP 403 oauth_scope_insufficient).
	// Retrying and refreshing are both useless — the grant itself is too
	// narrow, so only a fresh login with the right scopes fixes it.
	AuthScopeInsufficient AuthProblem = "scope_insufficient"
)

// AuthError is a classified authentication failure carrying an operator-facing
// recovery hint. It unwraps to ErrReauthRequired.
type AuthError struct {
	Problem AuthProblem
	// Detail is the underlying cause, safe to show an operator. It never
	// contains token material — only paths, statuses and server messages.
	Detail string
}

func (e *AuthError) Error() string {
	if e.Detail == "" {
		return fmt.Sprintf("claude code auth (%s): %s", e.Problem, ErrReauthRequired)
	}
	return fmt.Sprintf("claude code auth (%s): %s", e.Problem, e.Detail)
}

// Unwrap maps the classification onto a sentinel. "Nothing is configured" and
// "what is configured no longer works" call for different words in the UI, so
// they unwrap differently; every other case is a re-authentication.
func (e *AuthError) Unwrap() error {
	if e.Problem == AuthNoCredentials {
		return ErrNoCredentials
	}
	return ErrReauthRequired
}

// Hint returns the concrete next step for an operator. The dashboard renders
// this verbatim next to a link to the Claude Code login panel.
func (e *AuthError) Hint() string {
	switch e.Problem {
	case AuthNoCredentials:
		return "No Claude Code credentials found. Sign in from the Claude Code panel below, or run `claude auth login`."
	case AuthRefreshFailed:
		return "The stored refresh token could not be exchanged. Sign in again from the Claude Code panel below, or run `claude auth login`."
	case AuthRejected:
		return "Claude rejected the stored token (expired or revoked). Sign in again from the Claude Code panel below, or run `claude auth login`."
	case AuthScopeInsufficient:
		return "The stored token lacks the scope required to read subscription usage. Sign in again from the Claude Code panel below, or run `claude auth login`, to re-grant it."
	default:
		return "Sign in again from the Claude Code panel below, or run `claude auth login`."
	}
}

// authFailureTTL is how long a classified auth failure is served from cache
// before another live attempt is made.
//
// This exists because the resolver now *attempts* a locally-stale token rather
// than refusing it (see credentialFileToken). Without a negative cache, a hub
// whose credential has died would send a fresh 401 to api.anthropic.com on
// every overview render and before every task in a parallel plan. One attempt
// per minute is enough to notice a re-login promptly — and ClearUsageCache
// drops this immediately when a login actually completes, so the panel
// recovers on the next refresh rather than after a TTL.
const authFailureTTL = time.Minute

var (
	authFailMu  sync.Mutex
	authFailErr *AuthError
	authFailAt  time.Time
)

// cachedAuthFailure returns the last classified auth failure while it is still
// within authFailureTTL, or nil to let the caller make a live attempt.
func cachedAuthFailure() *AuthError {
	authFailMu.Lock()
	defer authFailMu.Unlock()
	if authFailErr != nil && time.Since(authFailAt) < authFailureTTL {
		return authFailErr
	}
	return nil
}

// recordAuthFailure caches e and returns it, so call sites can
// `return nil, recordAuthFailure(...)` in one line.
func recordAuthFailure(e *AuthError) *AuthError {
	authFailMu.Lock()
	authFailErr, authFailAt = e, time.Now()
	authFailMu.Unlock()
	return e
}

// clearAuthFailure forgets any cached failure. Called after a successful fetch
// and from ClearUsageCache on login/logout.
func clearAuthFailure() {
	authFailMu.Lock()
	authFailErr, authFailAt = nil, time.Time{}
	authFailMu.Unlock()
}

// AuthFailure reports the currently cached authentication failure, or nil when
// the last usage fetch authenticated successfully. The dashboard uses this to
// decide whether to show the re-authentication banner without triggering a
// fetch of its own.
func AuthFailure() *AuthError {
	authFailMu.Lock()
	defer authFailMu.Unlock()
	return authFailErr
}

// ReauthRequired reports whether the last attempt failed in a way a human
// fixes by logging in again.
func ReauthRequired() bool { return AuthFailure() != nil }
