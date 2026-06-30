package ratelimit

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// writeCreds writes a ~/.claude/.credentials.json under the test HOME with the
// given access/refresh tokens and expiry (ms since epoch). Returns the path.
func writeCreds(t *testing.T, access, refresh string, expiresAtMs int64) string {
	t.Helper()
	home, _ := os.UserHomeDir()
	dir := home + "/.claude"
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	payload := map[string]any{
		"claudeAiOauth": map[string]any{
			"accessToken":  access,
			"refreshToken": refresh,
			"expiresAt":    expiresAtMs,
			"scopes":       []string{"user:inference"},
		},
	}
	b, _ := json.MarshalIndent(payload, "", "  ")
	path := dir + "/.credentials.json"
	if err := os.WriteFile(path, b, 0600); err != nil {
		t.Fatalf("write creds: %v", err)
	}
	return path
}

// TestReadCredentialsToken_FreshTokenNoRefresh verifies the fast path: a token
// that is not near expiry is returned verbatim without any network refresh.
func TestReadCredentialsToken_FreshTokenNoRefresh(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("CLAUDE_CODE_OAUTH_TOKEN", "")
	future := time.Now().Add(2 * time.Hour).UnixMilli()
	writeCreds(t, "fresh-access", "refresh-1", future)

	if got := readCredentialsToken(); got != "fresh-access" {
		t.Fatalf("expected fresh access token, got %q", got)
	}
}

// TestReadCredentialsToken_SingleFlightRefresh is the core regression test for
// the recurring 401: when many goroutines see an expired token at once, the
// rotating refresh token must be exchanged exactly ONCE. A second concurrent
// exchange would 401 (invalid_grant) and could clobber the credentials file.
func TestReadCredentialsToken_SingleFlightRefresh(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("CLAUDE_CODE_OAUTH_TOKEN", "")

	var exchanges int32
	var mu sync.Mutex
	validRefresh := "refresh-1"

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		sent := r.Form.Get("refresh_token")
		mu.Lock()
		defer mu.Unlock()
		if sent != validRefresh {
			// Simulate Anthropic rejecting an already-consumed refresh token.
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"invalid_grant"}`))
			return
		}
		atomic.AddInt32(&exchanges, 1)
		validRefresh = "refresh-2" // rotate; old token now invalid
		resp := map[string]any{
			"access_token":  "new-access",
			"refresh_token": "refresh-2",
			"expires_in":    3600,
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	// Point the refresh URL at our mock server for the duration of the test.
	origURL := claudeOAuthTokenURL
	claudeOAuthTokenURL = srv.URL
	defer func() { claudeOAuthTokenURL = origURL }()

	past := time.Now().Add(-1 * time.Hour).UnixMilli() // already expired
	writeCreds(t, "old-access", "refresh-1", past)

	const goroutines = 20
	var wg sync.WaitGroup
	results := make([]string, goroutines)
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			results[idx] = readCredentialsToken()
		}(i)
	}
	wg.Wait()

	if n := atomic.LoadInt32(&exchanges); n != 1 {
		t.Fatalf("expected exactly 1 refresh exchange (single-flight), got %d", n)
	}
	for i, r := range results {
		if r != "new-access" {
			t.Fatalf("goroutine %d got token %q, want new-access", i, r)
		}
	}

	// Credentials file must be valid JSON with the rotated tokens persisted.
	home, _ := os.UserHomeDir()
	b, err := os.ReadFile(home + "/.claude/.credentials.json")
	if err != nil {
		t.Fatalf("read creds after refresh: %v", err)
	}
	var parsed claudeCredentials
	if err := json.Unmarshal(b, &parsed); err != nil {
		t.Fatalf("credentials file corrupted after concurrent refresh: %v\n%s", err, b)
	}
	if parsed.ClaudeAiOauth.AccessToken != "new-access" {
		t.Fatalf("persisted access token = %q, want new-access", parsed.ClaudeAiOauth.AccessToken)
	}
	if parsed.ClaudeAiOauth.RefreshToken != "refresh-2" {
		t.Fatalf("persisted refresh token = %q, want refresh-2 (rotated)", parsed.ClaudeAiOauth.RefreshToken)
	}
}

// TestWriteFileAtomic_ValidAfterWrite ensures the atomic writer leaves a
// complete, parseable file and no leftover temp files.
func TestWriteFileAtomic_ValidAfterWrite(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/.credentials.json"
	content := []byte(`{"claudeAiOauth":{"accessToken":"a","refreshToken":"r","expiresAt":1}}`)
	writeFileAtomic(path, content, 0600)

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(got) != string(content) {
		t.Fatalf("content mismatch: got %q", got)
	}
	var v map[string]any
	if err := json.Unmarshal(got, &v); err != nil {
		t.Fatalf("atomic-written file not valid JSON: %v", err)
	}
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if e.Name() != ".credentials.json" {
			t.Fatalf("leftover temp file: %s", e.Name())
		}
	}
}

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

func TestClearUsageCache(t *testing.T) {
	resetUsageCache()
	defer resetUsageCache()

	seeded := &ClaudeUsage{FetchedAt: time.Now().UTC()}
	usageMu.Lock()
	lastUsage = seeded
	usageMu.Unlock()

	if GetCachedUsage() != seeded {
		t.Fatalf("precondition: seeded cache should be readable")
	}
	ClearUsageCache()
	if got := GetCachedUsage(); got != nil {
		t.Fatalf("ClearUsageCache must drop the snapshot, got %p", got)
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
