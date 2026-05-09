package ratelimit

import (
	"testing"
	"time"
)

// resetUsageCache is a test helper that clears the package-level cache.
// Tests run sequentially so we don't bother locking writers here.
func resetUsageCache() {
	usageMu.Lock()
	lastUsage = nil
	usageMu.Unlock()
}

func TestFetchOrCachedUsage_ServesCacheWithinTTL(t *testing.T) {
	resetUsageCache()
	defer resetUsageCache()

	// Seed the cache as if a previous fetch had succeeded.
	seeded := &ClaudeUsage{FetchedAt: time.Now().UTC()}
	usageMu.Lock()
	lastUsage = seeded
	usageMu.Unlock()

	got, err := FetchOrCachedUsage("ignored-token", MinUsageCacheTTL)
	if err != nil {
		t.Fatalf("expected no error from cache hit, got %v", err)
	}
	if got != seeded {
		t.Fatalf("expected cached pointer to be returned, got %p want %p", got, seeded)
	}
}

func TestFetchOrCachedUsage_TTLFloor(t *testing.T) {
	resetUsageCache()
	defer resetUsageCache()

	// Seed cache 30s ago — fresher than the 1-minute floor but older than a
	// caller-supplied 5s TTL. The floor must win, so the cached value is
	// returned without an HTTP attempt.
	seeded := &ClaudeUsage{FetchedAt: time.Now().UTC().Add(-30 * time.Second)}
	usageMu.Lock()
	lastUsage = seeded
	usageMu.Unlock()

	got, err := FetchOrCachedUsage("ignored-token", 5*time.Second)
	if err != nil {
		t.Fatalf("expected no error from floor-clamped cache hit, got %v", err)
	}
	if got != seeded {
		t.Fatalf("expected cached pointer despite shorter requested ttl, got %p want %p", got, seeded)
	}
}

func TestFetchOrCachedUsage_StaleCacheTriggersRefresh(t *testing.T) {
	resetUsageCache()
	defer resetUsageCache()

	// Seed cache 2 minutes ago — older than the 1-minute floor — and supply
	// no token / credentials path. FetchClaudeUsage should fail (no token),
	// but FetchOrCachedUsage must surface the stale cache as a fallback so
	// the UI/orchestrator never lose historical numbers.
	stale := &ClaudeUsage{FetchedAt: time.Now().UTC().Add(-2 * time.Minute)}
	usageMu.Lock()
	lastUsage = stale
	usageMu.Unlock()

	t.Setenv("CLAUDE_CODE_OAUTH_TOKEN", "")
	t.Setenv("HOME", t.TempDir()) // ensure no ~/.claude/.credentials.json

	got, err := FetchOrCachedUsage("", MinUsageCacheTTL)
	if err == nil {
		t.Fatalf("expected fetch error when no token is available")
	}
	if got != stale {
		t.Fatalf("expected stale cache to be returned as fallback, got %p want %p", got, stale)
	}
}
