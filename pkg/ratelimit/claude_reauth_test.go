package ratelimit

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"sync/atomic"
	"testing"
	"time"
)

// resetAuthState clears both usage and auth-failure caches so each test starts
// from a known state. The caches are package-level, so tests that exercise
// them must not run in parallel with one another.
func resetAuthState(t *testing.T) {
	t.Helper()
	ClearUsageCache()
	t.Cleanup(ClearUsageCache)
}

// usageServer stands in for the OAuth usage API, returning the given status
// and body, and counting requests.
func usageServer(t *testing.T, status int, body string, hits *int32) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if hits != nil {
			atomic.AddInt32(hits, 1)
		}
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	old := usageEndpoint
	usageEndpoint = srv.URL
	t.Cleanup(func() { usageEndpoint = old; srv.Close() })
	return srv
}

// TestExpiredTokenWithoutRefreshIsStillAttempted is the core regression test
// for Task 20202. A credentials file whose access token is past its recorded
// expiry and which carries NO refresh token used to make the resolver give up
// locally and report a bare "no OAuth token available" — so the caps froze
// with no request ever being made and nothing to diagnose.
//
// expiresAt is our own bookkeeping and can be wrong, so the token must be sent
// and the server allowed to decide.
func TestExpiredTokenWithoutRefreshIsStillAttempted(t *testing.T) {
	resetAuthState(t)
	t.Setenv("HOME", t.TempDir())
	t.Setenv("CLAUDE_CODE_OAUTH_TOKEN", "")
	past := time.Now().Add(-72 * time.Hour).UnixMilli()
	writeCreds(t, "stale-but-maybe-valid", "", past)

	var hits int32
	usageServer(t, http.StatusOK, `{"five_hour":{"utilization":42,"resets_at":""}}`, &hits)

	usage, err := FetchClaudeUsage("")
	if err != nil {
		t.Fatalf("expected the stale token to be attempted, got error: %v", err)
	}
	if atomic.LoadInt32(&hits) != 1 {
		t.Fatalf("expected exactly 1 request to the usage API, got %d", hits)
	}
	if usage == nil || usage.FiveHour == nil || usage.FiveHour.Utilization != 42 {
		t.Fatalf("expected utilization 42 from the server, got %+v", usage)
	}
}

// TestUnauthorizedIsClassifiedAsReauth verifies that a server-side 401 becomes
// an actionable, typed error rather than a generic failure string.
func TestUnauthorizedIsClassifiedAsReauth(t *testing.T) {
	resetAuthState(t)
	t.Setenv("HOME", t.TempDir())
	t.Setenv("CLAUDE_CODE_OAUTH_TOKEN", "")
	writeCreds(t, "dead-token", "", time.Now().Add(-time.Hour).UnixMilli())

	usageServer(t, http.StatusUnauthorized,
		`{"error":{"type":"authentication_error","message":"OAuth access token has expired."}}`, nil)

	_, err := FetchClaudeUsage("")
	if err == nil {
		t.Fatal("expected an error for a 401 response")
	}
	if !errors.Is(err, ErrReauthRequired) {
		t.Fatalf("expected errors.Is(err, ErrReauthRequired), got %v", err)
	}
	var authErr *AuthError
	if !errors.As(err, &authErr) {
		t.Fatalf("expected an *AuthError, got %T", err)
	}
	if authErr.Problem != AuthRejected {
		t.Fatalf("expected problem %q, got %q", AuthRejected, authErr.Problem)
	}
	if authErr.Hint() == "" {
		t.Fatal("an auth failure must carry a recovery hint")
	}
}

// TestForbiddenIsClassifiedAsScopeInsufficient covers the token that
// authenticates but was never granted the scope the usage endpoint needs.
// Refreshing cannot widen a scope, so this must not be reported as a
// transient failure.
func TestForbiddenIsClassifiedAsScopeInsufficient(t *testing.T) {
	resetAuthState(t)
	t.Setenv("HOME", t.TempDir())
	t.Setenv("CLAUDE_CODE_OAUTH_TOKEN", "")
	writeCreds(t, "narrow-scope-token", "", time.Now().Add(time.Hour).UnixMilli())

	usageServer(t, http.StatusForbidden,
		`{"error":{"type":"oauth_scope_insufficient","message":"missing scope"}}`, nil)

	_, err := FetchClaudeUsage("")
	var authErr *AuthError
	if !errors.As(err, &authErr) {
		t.Fatalf("expected an *AuthError, got %v", err)
	}
	if authErr.Problem != AuthScopeInsufficient {
		t.Fatalf("expected problem %q, got %q", AuthScopeInsufficient, authErr.Problem)
	}
	if !errors.Is(err, ErrReauthRequired) {
		t.Fatalf("a scope failure still needs a fresh login: %v", err)
	}
}

// TestAuthFailureIsNegativelyCached guards the cost of attempting a stale
// token: a hub whose credential has died must not fire a doomed 401 before
// every task in a parallel plan and on every dashboard render.
func TestAuthFailureIsNegativelyCached(t *testing.T) {
	resetAuthState(t)
	t.Setenv("HOME", t.TempDir())
	t.Setenv("CLAUDE_CODE_OAUTH_TOKEN", "")
	writeCreds(t, "dead-token", "", time.Now().Add(-time.Hour).UnixMilli())

	var hits int32
	usageServer(t, http.StatusUnauthorized, `{"error":{"message":"expired"}}`, &hits)

	for i := 0; i < 5; i++ {
		if _, err := FetchClaudeUsage(""); err == nil {
			t.Fatal("expected a persistent auth error")
		}
	}
	if got := atomic.LoadInt32(&hits); got != 1 {
		t.Fatalf("expected the failure to be cached after 1 request, got %d requests", got)
	}
	if !ReauthRequired() {
		t.Fatal("ReauthRequired() should report the cached failure")
	}
}

// TestClearUsageCacheClearsAuthFailure verifies that completing a login is
// picked up immediately instead of being masked by the negative cache for the
// remainder of its TTL.
func TestClearUsageCacheClearsAuthFailure(t *testing.T) {
	resetAuthState(t)
	t.Setenv("HOME", t.TempDir())
	t.Setenv("CLAUDE_CODE_OAUTH_TOKEN", "")
	writeCreds(t, "dead-token", "", time.Now().Add(-time.Hour).UnixMilli())

	usageServer(t, http.StatusUnauthorized, `{"error":{"message":"expired"}}`, nil)
	if _, err := FetchClaudeUsage(""); err == nil {
		t.Fatal("expected an auth error to prime the cache")
	}
	if AuthFailure() == nil {
		t.Fatal("expected a cached auth failure")
	}

	ClearUsageCache() // what the login handler calls on success
	if AuthFailure() != nil {
		t.Fatal("a completed login must clear the cached auth failure")
	}
}

// TestExplicitTokenDoesNotPoisonSharedCache ensures a caller-supplied token
// (used by connectivity probes) cannot make the whole process believe the
// ambient credential is broken.
func TestExplicitTokenDoesNotPoisonSharedCache(t *testing.T) {
	resetAuthState(t)
	t.Setenv("HOME", t.TempDir())
	t.Setenv("CLAUDE_CODE_OAUTH_TOKEN", "")

	usageServer(t, http.StatusUnauthorized, `{"error":{"message":"nope"}}`, nil)
	if _, err := FetchClaudeUsage("someone-elses-bad-token"); err == nil {
		t.Fatal("expected an error for the explicit token")
	}
	if AuthFailure() != nil {
		t.Fatal("an explicit token's failure must not be cached as the ambient state")
	}
}

// TestUpdateCredentialsFileDropsStaleExpiry covers the wedge that can make a
// brand-new token look permanently expired: when the refresh response carries
// no expires_in, retaining the previous (already-past) expiresAt would make
// tokenIsFresh report the new token as stale forever.
func TestUpdateCredentialsFileDropsStaleExpiry(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	path := writeCreds(t, "old-access", "old-refresh", time.Now().Add(-time.Hour).UnixMilli())

	if err := updateCredentialsFile("new-access", "new-refresh", 0); err != nil {
		t.Fatalf("updateCredentialsFile: %v", err)
	}

	creds, ok := loadCredentials()
	if !ok {
		t.Fatalf("could not reload %s", path)
	}
	if creds.ClaudeAiOauth.AccessToken != "new-access" {
		t.Fatalf("access token not updated: %q", creds.ClaudeAiOauth.AccessToken)
	}
	if creds.ClaudeAiOauth.ExpiresAt != 0 {
		t.Fatalf("stale expiresAt should have been dropped, got %d", creds.ClaudeAiOauth.ExpiresAt)
	}
	if !tokenIsFresh(creds) {
		t.Fatal("a token with no recorded expiry must be treated as usable")
	}
}

// TestMissingCredentialsFallsBackToEnv keeps the documented precedence intact:
// the credentials file wins, but the env var is still honoured when the file
// yields nothing.
func TestMissingCredentialsFallsBackToEnv(t *testing.T) {
	resetAuthState(t)
	t.Setenv("HOME", t.TempDir())
	t.Setenv("CLAUDE_CODE_OAUTH_TOKEN", "env-token")

	tok, authErr := resolveCredentialToken()
	if authErr != nil {
		t.Fatalf("expected the env token to satisfy the resolver, got %v", authErr)
	}
	if tok != "env-token" {
		t.Fatalf("expected the env token, got %q", tok)
	}
}

// TestNoCredentialsAtAllIsClassified verifies the empty-environment case is
// reported as "nothing configured" rather than "log in again".
func TestNoCredentialsAtAllIsClassified(t *testing.T) {
	resetAuthState(t)
	t.Setenv("HOME", t.TempDir())
	t.Setenv("CLAUDE_CODE_OAUTH_TOKEN", "")
	// Ensure no credentials file exists under the isolated HOME.
	home, _ := os.UserHomeDir()
	_ = os.RemoveAll(home + "/.claude")

	_, err := FetchClaudeUsage("")
	if !errors.Is(err, ErrNoCredentials) {
		t.Fatalf("expected errors.Is(err, ErrNoCredentials), got %v", err)
	}
	var authErr *AuthError
	if !errors.As(err, &authErr) || authErr.Problem != AuthNoCredentials {
		t.Fatalf("expected AuthNoCredentials, got %v", err)
	}
}
