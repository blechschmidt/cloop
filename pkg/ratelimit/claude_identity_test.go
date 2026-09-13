package ratelimit

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestCredentialsPathHonorsConfigDir(t *testing.T) {
	// A run dispatched for one user is started with CLAUDE_CONFIG_DIR set.
	// If the refresh path ignored it, that run would rotate the *host's*
	// single-use refresh token: it would break the host credential and hand
	// the user an account that is not theirs.
	dir := t.TempDir()
	t.Setenv("CLAUDE_CONFIG_DIR", dir)
	if got, want := credentialsPath(), filepath.Join(dir, ".credentials.json"); got != want {
		t.Fatalf("credentialsPath() = %s, want %s", got, want)
	}
	if got, want := credentialsLockPath(dir), filepath.Join(dir, ".credentials.json.lock"); got != want {
		t.Fatalf("credentialsLockPath = %s, want %s", got, want)
	}

	t.Setenv("CLAUDE_CONFIG_DIR", "")
	home, _ := os.UserHomeDir()
	if got, want := credentialsPath(), filepath.Join(home, ".claude", ".credentials.json"); got != want {
		t.Fatalf("credentialsPath() without a config dir = %s, want %s", got, want)
	}
}

// One tenant's utilization must never be rendered on another tenant's
// dashboard.
func TestUsageCacheIsPerIdentity(t *testing.T) {
	usageByDir = map[string]*ClaudeUsage{}
	alice := &ClaudeUsage{FetchedAt: time.Now()}
	setCachedUsage("/homes/alice", alice)

	if got := GetCachedUsageIn("/homes/bob"); got != nil {
		t.Fatalf("bob was served alice's usage snapshot: %+v", got)
	}
	if got := GetCachedUsageIn(""); got != nil {
		t.Fatalf("the host default was served a user's usage snapshot: %+v", got)
	}
	if got := GetCachedUsageIn("/homes/alice"); got != alice {
		t.Fatalf("alice's own snapshot = %+v, want it cached", got)
	}
}

// Signing out must invalidate only the person who signed out.
func TestClearUsageCacheOnlyClearsOneIdentity(t *testing.T) {
	usageByDir = map[string]*ClaudeUsage{}
	setCachedUsage("/homes/alice", &ClaudeUsage{FetchedAt: time.Now()})
	setCachedUsage("/homes/bob", &ClaudeUsage{FetchedAt: time.Now()})

	ClearUsageCacheIn("/homes/alice")

	if GetCachedUsageIn("/homes/alice") != nil {
		t.Fatal("alice's snapshot survived her own logout")
	}
	if GetCachedUsageIn("/homes/bob") == nil {
		t.Fatal("alice logging out discarded bob's cached usage")
	}
}

// The ambient-token fallback is what makes a logged-out user look logged in.
// It is legitimate for a single-user host and must never apply to an identity.
func TestAmbientTokenFallbackOnlyAppliesToHostDefault(t *testing.T) {
	t.Setenv("CLAUDE_CODE_OAUTH_TOKEN", "host-token")

	// An identity with no credential of their own is logged out, full stop.
	empty := t.TempDir()
	tok, authErr := resolveCredentialToken(empty)
	if tok != "" {
		t.Fatalf("a user with no credential resolved to %q — the host's token", tok)
	}
	if authErr == nil {
		t.Fatal("expected a classified auth error for an identity with no credential")
	}

	// The host default keeps its existing behaviour.
	if tok, _ := resolveCredentialToken(""); tok != "host-token" {
		t.Fatalf("host default resolved to %q, want the ambient token", tok)
	}
}

// Exporting a refreshed token into the process environment is a cache for the
// process's own credential. Doing it for someone else's directory would hand
// that token to every subprocess the hub starts afterwards, including other
// users' runs.
func TestCacheTokenInEnvRefusesForeignIdentity(t *testing.T) {
	t.Setenv("CLAUDE_CONFIG_DIR", "/homes/alice")
	t.Setenv("CLAUDE_CODE_OAUTH_TOKEN", "")

	cacheTokenInEnv("/homes/bob", "bobs-token")
	if got := os.Getenv("CLAUDE_CODE_OAUTH_TOKEN"); got != "" {
		t.Fatalf("another identity's token leaked into the process environment: %q", got)
	}

	cacheTokenInEnv("/homes/alice", "own-token")
	if got := os.Getenv("CLAUDE_CODE_OAUTH_TOKEN"); got != "own-token" {
		t.Fatalf("the process's own refreshed token was not cached: %q", got)
	}
}

// A hub refreshing on behalf of a user must not publish that token either:
// the hub's own config dir is the host default, so every per-user refresh is
// a "foreign" one by construction.
func TestHubNeverPublishesAUsersToken(t *testing.T) {
	t.Setenv("CLAUDE_CONFIG_DIR", "")
	t.Setenv("CLAUDE_CODE_OAUTH_TOKEN", "")

	cacheTokenInEnv("/homes/alice", "alices-token")
	if got := os.Getenv("CLAUDE_CODE_OAUTH_TOKEN"); got != "" {
		t.Fatalf("a hub published a user's token into its own environment: %q", got)
	}
}

// One user's expired credential must not raise a re-authentication banner on
// everyone else's dashboard.
func TestAuthFailureIsPerIdentity(t *testing.T) {
	authFails = map[string]authFailure{}
	recordAuthFailure("/homes/alice", &AuthError{Problem: AuthRejected, Detail: "alice's token died"})

	if got := AuthFailureIn("/homes/alice"); got == nil {
		t.Fatal("alice's own failure was not recorded")
	}
	if got := AuthFailureIn("/homes/bob"); got != nil {
		t.Fatalf("bob inherited alice's auth failure: %v", got)
	}
	if ReauthRequiredIn("/homes/bob") {
		t.Fatal("bob is told to re-authenticate because alice's token expired")
	}

	clearAuthFailure("/homes/alice")
	if AuthFailureIn("/homes/alice") != nil {
		t.Fatal("alice's failure survived a clear")
	}
}

func TestFetchErrorBackoffIsPerIdentity(t *testing.T) {
	fetchErrs = map[string]fetchFailure{}
	recordFetchError("/homes/alice", os.ErrDeadlineExceeded)

	if recentFetchError("/homes/alice") == nil {
		t.Fatal("alice's transient failure was not recorded")
	}
	if err := recentFetchError("/homes/bob"); err != nil {
		t.Fatalf("bob is backed off by alice's transient failure: %v", err)
	}
}
