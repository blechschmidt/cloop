// Package ratelimit - claude_usage.go fetches Claude Code subscription usage
// from the Anthropic OAuth usage API endpoint.
package ratelimit

import (
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/blechschmidt/cloop/pkg/provider"
)

// maxUsageResponseBytes caps the OAuth usage API JSON envelope. The real
// response is a few hundred bytes; 1 MiB leaves generous headroom while
// preventing a misbehaving proxy from OOMing the daemon.
const maxUsageResponseBytes int64 = 1 << 20

// UsageWindow represents a single usage limit window (5-hour or 7-day).
type UsageWindow struct {
	Utilization *float64 `json:"utilization"` // percentage 0-100, nil if not applicable
	ResetsAt    string   `json:"resets_at"`   // ISO 8601 timestamp
}

// ExtraUsage represents extra/overflow usage info.
type ExtraUsage struct {
	IsEnabled    bool     `json:"is_enabled"`
	MonthlyLimit *float64 `json:"monthly_limit"`
	UsedCredits  *float64 `json:"used_credits"`
	Utilization  *float64 `json:"utilization"`
}

// ClaudeUsageResponse is the raw API response from /api/oauth/usage.
type ClaudeUsageResponse struct {
	FiveHour       *UsageWindow `json:"five_hour"`
	SevenDay       *UsageWindow `json:"seven_day"`
	SevenDayOpus   *UsageWindow `json:"seven_day_opus"`
	SevenDaySonnet *UsageWindow `json:"seven_day_sonnet"`
	ExtraUsage     *ExtraUsage  `json:"extra_usage"`
	Error          *struct {
		Message string `json:"message"`
	} `json:"error,omitempty"`
}

// ClaudeUsage is the processed usage data exposed to the UI.
type ClaudeUsage struct {
	FiveHour       *UsageDetail `json:"five_hour,omitempty"`
	SevenDay       *UsageDetail `json:"seven_day,omitempty"`
	SevenDayOpus   *UsageDetail `json:"seven_day_opus,omitempty"`
	SevenDaySonnet *UsageDetail `json:"seven_day_sonnet,omitempty"`
	ExtraUsage     *ExtraUsage  `json:"extra_usage,omitempty"`
	FetchedAt      time.Time    `json:"fetched_at"`
}

// UsageDetail is a single limit window with parsed fields.
type UsageDetail struct {
	Utilization float64   `json:"utilization"` // 0-100
	ResetsAt    time.Time `json:"resets_at"`
}

var (
	usageMu   sync.RWMutex
	lastUsage *ClaudeUsage

	// usageFetchMu serializes concurrent FetchOrCachedUsage refreshes so a
	// burst of callers (orchestrator + UI poller + limit check arriving in
	// the same tick) coalesces into a single HTTP round-trip rather than N.
	usageFetchMu sync.Mutex

	// oauthRefreshMu serializes OAuth token refreshes *within this process*.
	// Claude.ai refresh tokens are single-use and rotate on every exchange:
	// the first refresh consumes the refresh token and the server hands back a
	// new one. If two goroutines refresh concurrently they each POST the same
	// refresh token; the first wins, the second gets HTTP 400/401 invalid_grant
	// and (worse) can clobber ~/.claude/.credentials.json with a failed/partial
	// write — after which even the `claude` CLI subprocess reads broken
	// credentials and every task step returns "401 Invalid authentication
	// credentials". This mutex + the cross-process flock in refreshOAuthToken
	// guarantee exactly one refresh at a time, process-wide and machine-wide.
	oauthRefreshMu sync.Mutex
)

// usageEndpoint is the OAuth subscription-usage API. A var, not a const, so
// tests can point it at a mock server — same reason as claudeOAuthTokenURL.
var usageEndpoint = "https://api.anthropic.com/api/oauth/usage"

// MinUsageCacheTTL is the floor on how long a fetched ClaudeUsage snapshot is
// served without re-fetching. The OAuth usage API returns slowly-changing
// utilization percentages and is itself rate-limited, so callers that ask
// "may I make another claudecode call?" within this window receive the
// cached snapshot without a network round-trip. Callers may pass a longer
// TTL but anything shorter is rounded up to this value.
const MinUsageCacheTTL = time.Minute

// GetCachedUsage returns the last fetched usage, or nil if not available.
// No freshness check — callers that need fresh data should use
// FetchOrCachedUsage instead.
func GetCachedUsage() *ClaudeUsage {
	usageMu.RLock()
	defer usageMu.RUnlock()
	return lastUsage
}

// ClearUsageCache discards the in-memory ClaudeUsage snapshot so the next
// FetchOrCachedUsage call goes back to the OAuth usage API. Call this on
// reauthentication (login completes, logout) — the cached snapshot was tied
// to the previous identity's account and would otherwise be served as stale
// data for up to MinUsageCacheTTL.
func ClearUsageCache() {
	usageMu.Lock()
	lastUsage = nil
	usageMu.Unlock()
	// Also drop any cached authentication failure. A login that just
	// succeeded must not keep being told it needs to re-authenticate for the
	// remainder of authFailureTTL.
	clearAuthFailure()
}

// FetchOrCachedUsage returns the cached usage snapshot when it is fresher
// than max(ttl, MinUsageCacheTTL), otherwise re-fetches from the OAuth usage
// API. Concurrent callers coalesce on usageFetchMu so the API is hit once
// per refresh window even under contention. On fetch error, a previously
// cached snapshot (if any) is returned alongside the error so callers can
// fall back to stale data instead of failing open.
func FetchOrCachedUsage(token string, ttl time.Duration) (*ClaudeUsage, error) {
	if ttl < MinUsageCacheTTL {
		ttl = MinUsageCacheTTL
	}
	if u := GetCachedUsage(); u != nil && time.Since(u.FetchedAt) <= ttl {
		return u, nil
	}
	usageFetchMu.Lock()
	defer usageFetchMu.Unlock()
	// Re-check after acquiring the lock — a sibling caller may have just
	// refreshed the cache while we were waiting.
	if u := GetCachedUsage(); u != nil && time.Since(u.FetchedAt) <= ttl {
		return u, nil
	}
	fresh, err := FetchClaudeUsage(token)
	if err != nil {
		if u := GetCachedUsage(); u != nil {
			return u, err
		}
		return nil, err
	}
	return fresh, nil
}

// FetchClaudeUsage calls the Anthropic OAuth usage API to get subscription
// limits (5-hour window, weekly window, per-model breakdowns).
// The token should be a Claude Code OAuth access token (sk-ant-oat01-*).
func FetchClaudeUsage(token string) (*ClaudeUsage, error) {
	explicit := token != ""
	if !explicit {
		// Serve a recently classified auth failure without another doomed
		// round-trip. Cleared by a successful fetch and by ClearUsageCache
		// on login, so a re-authentication is picked up promptly.
		if cached := cachedAuthFailure(); cached != nil {
			return nil, cached
		}
		var authErr *AuthError
		token, authErr = resolveCredentialToken()
		if authErr != nil {
			return nil, recordAuthFailure(authErr)
		}
	}

	usage, status, err := fetchUsageWithToken(token)
	// On 401 with a non-explicit token, the token went stale between our
	// freshness check and the request (or the env var was used). Force a
	// refresh once and retry, instead of surfacing a spurious auth failure.
	if status == http.StatusUnauthorized && !explicit {
		// Constant-time even though both values are local: this is a
		// "did the token change" check, and comparing credential bytes with
		// == is the habit worth not having. tests/security enforces it.
		if fresh := forceRefreshToken(); fresh != "" &&
			subtle.ConstantTimeCompare([]byte(fresh), []byte(token)) != 1 {
			usage, status, err = fetchUsageWithToken(fresh)
		}
	}

	if explicit {
		// A caller-supplied token must never poison the shared cache that
		// describes the *ambient* credential.
		return usage, err
	}
	// The server is the only authority on whether a credential still works, so
	// these classifications are facts rather than inferences from local expiry
	// bookkeeping. Both are terminal: refreshing cannot widen a scope, and it
	// cannot revive a revoked grant.
	if status == http.StatusUnauthorized || status == http.StatusForbidden {
		problem := AuthRejected
		if status == http.StatusForbidden {
			problem = AuthScopeInsufficient
		}
		detail := "Claude rejected the stored OAuth token"
		if err != nil {
			detail = err.Error()
		}
		return nil, recordAuthFailure(&AuthError{Problem: problem, Detail: detail})
	}
	if err == nil {
		clearAuthFailure()
	}
	return usage, err
}

// resolveCredentialToken picks the OAuth access token to authenticate with,
// preferring the credentials file (which validates expiry and refreshes under
// lock) over CLAUDE_CODE_OAUTH_TOKEN. The env var is only a cache populated by
// a previous refresh and is never re-checked for expiry, so trusting it first
// meant a stale token kept producing 401s with no refresh.
//
// The returned *AuthError is non-nil only when no token could be produced at
// all; it is already classified for display.
func resolveCredentialToken() (string, *AuthError) {
	tok, authErr := credentialFileToken()
	if tok != "" {
		return tok, nil
	}
	if env := strings.TrimSpace(os.Getenv("CLAUDE_CODE_OAUTH_TOKEN")); env != "" {
		return env, nil
	}
	if authErr == nil {
		authErr = &AuthError{
			Problem: AuthNoCredentials,
			Detail:  fmt.Sprintf("no access token in %s and CLAUDE_CODE_OAUTH_TOKEN is unset", credentialsPath()),
		}
	}
	return "", authErr
}

// forceRefreshToken refreshes the OAuth token regardless of the cached
// freshness check, serialized through the same locks as the normal path. Used
// to recover from a 401 caused by a token that expired mid-flight.
func forceRefreshToken() string {
	oauthRefreshMu.Lock()
	defer oauthRefreshMu.Unlock()
	creds, ok := loadCredentials()
	if !ok || creds.ClaudeAiOauth.RefreshToken == "" {
		return ""
	}
	// If another goroutine already refreshed while we waited, use that.
	if tokenIsFresh(creds) {
		return creds.ClaudeAiOauth.AccessToken
	}
	if tok, err := refreshOAuthToken(creds.ClaudeAiOauth.RefreshToken); err == nil {
		return tok
	}
	return ""
}

// fetchUsageWithToken performs a single usage-API request with the given
// bearer token. It returns the parsed usage (on success), the HTTP status
// code (0 if the request never completed), and any error.
func fetchUsageWithToken(token string) (*ClaudeUsage, int, error) {
	client := &http.Client{Timeout: 10 * time.Second}
	req, err := http.NewRequest("GET", usageEndpoint, nil)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("anthropic-beta", "oauth-2025-04-20")
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("usage API request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := provider.ReadResponseBody(resp.Body, maxUsageResponseBytes)
	if err != nil {
		return nil, resp.StatusCode, fmt.Errorf("reading usage response: %w", err)
	}

	var raw ClaudeUsageResponse
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, resp.StatusCode, fmt.Errorf("parsing usage response: %w", err)
	}

	if raw.Error != nil {
		return nil, resp.StatusCode, fmt.Errorf("usage API error: %s", raw.Error.Message)
	}

	// A non-2xx status with no structured error (e.g. a bare 401 from a
	// proxy) must still be reported so the caller can trigger a refresh.
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, resp.StatusCode, fmt.Errorf("usage API returned status %d", resp.StatusCode)
	}

	usage := &ClaudeUsage{
		FetchedAt:  time.Now().UTC(),
		ExtraUsage: raw.ExtraUsage,
	}

	if raw.FiveHour != nil && raw.FiveHour.Utilization != nil {
		usage.FiveHour = parseWindow(raw.FiveHour)
	}
	if raw.SevenDay != nil && raw.SevenDay.Utilization != nil {
		usage.SevenDay = parseWindow(raw.SevenDay)
	}
	if raw.SevenDayOpus != nil && raw.SevenDayOpus.Utilization != nil {
		usage.SevenDayOpus = parseWindow(raw.SevenDayOpus)
	}
	if raw.SevenDaySonnet != nil && raw.SevenDaySonnet.Utilization != nil {
		usage.SevenDaySonnet = parseWindow(raw.SevenDaySonnet)
	}

	usageMu.Lock()
	lastUsage = usage
	usageMu.Unlock()

	return usage, resp.StatusCode, nil
}

func parseWindow(w *UsageWindow) *UsageDetail {
	if w == nil || w.Utilization == nil {
		return nil
	}
	d := &UsageDetail{
		Utilization: *w.Utilization,
	}
	if w.ResetsAt != "" {
		t, err := time.Parse(time.RFC3339Nano, w.ResetsAt)
		if err == nil {
			d.ResetsAt = t
		}
	}
	return d
}

const claudeOAuthClientID = "9d1c250a-e61b-44d9-88ed-5944d1962f5e"

// claudeOAuthTokenURL is the Claude Code OAuth token endpoint (same endpoint
// the claude CLI itself uses). A var, not a const, so tests can point it at a
// mock server.
var claudeOAuthTokenURL = "https://platform.claude.com/v1/oauth/token"

type claudeCredentials struct {
	ClaudeAiOauth struct {
		AccessToken  string   `json:"accessToken"`
		RefreshToken string   `json:"refreshToken"`
		ExpiresAt    int64    `json:"expiresAt"`
		Scopes       []string `json:"scopes"`
	} `json:"claudeAiOauth"`
}

func credentialsPath() string {
	home, _ := os.UserHomeDir()
	return home + "/.claude/.credentials.json"
}

// tokenExpiryBufferMs is how far ahead of the real expiry we treat a token as
// stale. The CLI uses a similar margin; 60s is enough to cover clock skew plus
// the round-trip of an in-flight request that started just before expiry.
const tokenExpiryBufferMs int64 = 60000

// loadCredentials reads and parses ~/.claude/.credentials.json. Returns the
// parsed struct and whether parsing succeeded.
func loadCredentials() (claudeCredentials, bool) {
	data, err := os.ReadFile(credentialsPath())
	if err != nil {
		return claudeCredentials{}, false
	}
	var creds claudeCredentials
	if err := json.Unmarshal(data, &creds); err != nil {
		return claudeCredentials{}, false
	}
	return creds, true
}

// tokenIsFresh reports whether the access token is present and not within the
// expiry buffer of its deadline.
func tokenIsFresh(c claudeCredentials) bool {
	if c.ClaudeAiOauth.AccessToken == "" {
		return false
	}
	if c.ClaudeAiOauth.ExpiresAt <= 0 {
		// No expiry recorded: trust the access token as-is rather than
		// forcing a refresh loop.
		return true
	}
	return time.Now().UnixMilli() < c.ClaudeAiOauth.ExpiresAt-tokenExpiryBufferMs
}

// readCredentialsToken reads the OAuth token from ~/.claude/.credentials.json,
// auto-refreshing it if expired.
//
// Refresh is serialized through oauthRefreshMu (process-wide) plus a
// cross-process flock inside refreshOAuthToken (machine-wide). After taking the
// lock we re-read the credentials file and re-check freshness: if another
// goroutine/process already refreshed while we were blocked, we return the
// freshly written token instead of POSTing the now-consumed refresh token a
// second time (which is what produced the recurring 401 burst). This is the
// classic single-flight pattern for rotating refresh tokens.
func readCredentialsToken() string {
	tok, _ := credentialFileToken()
	return tok
}

// credentialFileToken implements readCredentialsToken and additionally
// classifies the failure when it cannot produce a token.
func credentialFileToken() (string, *AuthError) {
	creds, ok := loadCredentials()
	if !ok {
		return "", &AuthError{
			Problem: AuthNoCredentials,
			Detail:  fmt.Sprintf("%s is missing or unreadable", credentialsPath()),
		}
	}

	// Fast path: token still fresh, no lock needed.
	if tokenIsFresh(creds) {
		return creds.ClaudeAiOauth.AccessToken, nil
	}

	// Slow path: needs refresh. Serialize so only one refresh happens.
	oauthRefreshMu.Lock()
	defer oauthRefreshMu.Unlock()

	// Double-check after acquiring the lock: a concurrent caller may have
	// refreshed the file while we waited.
	if creds2, ok := loadCredentials(); ok && tokenIsFresh(creds2) {
		return creds2.ClaudeAiOauth.AccessToken, nil
	} else if ok {
		creds = creds2 // use the most recent refresh token on disk
	}

	if creds.ClaudeAiOauth.RefreshToken == "" {
		// Past its recorded expiry with no way to rotate. Hand the token
		// back anyway rather than declaring defeat locally: expiresAt is our
		// own bookkeeping and can be wrong (a refresh response without
		// expires_in used to leave the previous, already-past value behind;
		// clocks skew; `claude setup-token` writes long-lived credentials
		// with no refresh token at all). Only the server can say whether a
		// token still works — if it is genuinely dead the request comes
		// back 401 and FetchClaudeUsage classifies it as AuthRejected, which
		// is a fact instead of a guess. Refusing to even try is what turned
		// one expired token into four days of silently frozen caps.
		if creds.ClaudeAiOauth.AccessToken != "" {
			return creds.ClaudeAiOauth.AccessToken, nil
		}
		return "", &AuthError{
			Problem: AuthNoCredentials,
			Detail:  fmt.Sprintf("%s has neither an access token nor a refresh token", credentialsPath()),
		}
	}
	newToken, err := refreshOAuthToken(creds.ClaudeAiOauth.RefreshToken)
	if err != nil {
		// A failed exchange is a sharper diagnosis than the 401 that
		// attempting the stale access token would produce, so report it
		// rather than burning a doomed request to rediscover it.
		return "", &AuthError{Problem: AuthRefreshFailed, Detail: err.Error()}
	}
	return newToken, nil
}

// credentialsLockPath is the advisory lock file guarding refresh+write of the
// credentials file across processes (cloop instances and, defensively, the
// claude CLI run by this host). We lock a sidecar file rather than the
// credentials file itself so an flock failure can never leave the real
// credentials truncated.
func credentialsLockPath() string {
	return credentialsPath() + ".lock"
}

// withCredentialsFileLock runs fn while holding an exclusive cross-process
// flock on the credentials lock file. If the lock can't be acquired it still
// runs fn (best-effort) rather than failing the refresh outright — the
// in-process mutex already prevents the common self-race; the flock is defense
// against multiple cloop processes / the CLI.
func withCredentialsFileLock(fn func()) {
	lockPath := credentialsLockPath()
	if err := os.MkdirAll(filepath.Dir(lockPath), 0700); err != nil {
		fn()
		return
	}
	f, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		fn()
		return
	}
	defer f.Close()
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		fn()
		return
	}
	defer syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
	fn()
}

// refreshOAuthToken uses the refresh token to get a new access token and
// updates the credentials file. Callers MUST hold oauthRefreshMu. The whole
// HTTP-exchange + file-write happens under a cross-process flock so a
// concurrent cloop process (or the claude CLI) can't interleave its own
// refresh and double-consume the rotating refresh token.
func refreshOAuthToken(refreshToken string) (string, error) {
	client := &http.Client{Timeout: 10 * time.Second}

	formData := oauthRefreshForm(refreshToken)

	var (
		accessToken string
		refreshErr  error
	)
	withCredentialsFileLock(func() {
		// Re-check under the cross-process lock: another process may have
		// just refreshed. If so, adopt its fresh token and skip the exchange
		// so we never POST an already-consumed refresh token.
		if creds, ok := loadCredentials(); ok && tokenIsFresh(creds) {
			accessToken = creds.ClaudeAiOauth.AccessToken
			os.Setenv("CLAUDE_CODE_OAUTH_TOKEN", accessToken)
			return
		} else if ok && creds.ClaudeAiOauth.RefreshToken != "" {
			// Use the newest refresh token on disk, not the (possibly stale)
			// one captured by the caller before it blocked on the lock.
			formData = oauthRefreshForm(creds.ClaudeAiOauth.RefreshToken)
		}

		req, err := http.NewRequest("POST", claudeOAuthTokenURL, strings.NewReader(formData))
		if err != nil {
			refreshErr = err
			return
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		resp, err := client.Do(req)
		if err != nil {
			refreshErr = fmt.Errorf("refresh request failed: %w", err)
			return
		}
		defer resp.Body.Close()

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			refreshErr = err
			return
		}

		if resp.StatusCode != 200 {
			refreshErr = fmt.Errorf("refresh failed with status %d: %s", resp.StatusCode, string(body))
			return
		}

		var tokenResp struct {
			AccessToken  string `json:"access_token"`
			RefreshToken string `json:"refresh_token"`
			ExpiresIn    int64  `json:"expires_in"`
		}
		if err := json.Unmarshal(body, &tokenResp); err != nil {
			refreshErr = fmt.Errorf("parsing refresh response: %w", err)
			return
		}

		if tokenResp.AccessToken == "" {
			refreshErr = fmt.Errorf("no access_token in refresh response")
			return
		}

		// Persist atomically while still holding the flock. A persist
		// failure must not fail the refresh (the in-memory token is still
		// usable), but it must be loud: the refresh token is single-use,
		// so if the rotated one isn't on disk, every other consumer of the
		// credentials file is now holding a dead token.
		if err := updateCredentialsFile(tokenResp.AccessToken, tokenResp.RefreshToken, tokenResp.ExpiresIn); err != nil {
			fmt.Fprintf(os.Stderr, "cloop: WARNING: failed to persist refreshed OAuth credentials to %s: %v (the rotated refresh token only exists in this process; other claude/cloop processes may fail to authenticate)\n", credentialsPath(), err)
		}
		os.Setenv("CLAUDE_CODE_OAUTH_TOKEN", tokenResp.AccessToken)
		accessToken = tokenResp.AccessToken
	})

	if refreshErr != nil {
		return "", refreshErr
	}
	return accessToken, nil
}

// oauthRefreshForm builds the x-www-form-urlencoded body for a refresh-token
// exchange. url.Values handles escaping, so a token containing reserved
// characters can never corrupt the form encoding.
func oauthRefreshForm(refreshToken string) string {
	return url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshToken},
		"client_id":     {claudeOAuthClientID},
		"redirect_uri":  {"https://platform.claude.com/oauth/code/callback"},
	}.Encode()
}

// updateCredentialsFile writes the new tokens back to ~/.claude/.credentials.json.
//
// The write is ATOMIC (write temp + fsync + rename): a crash or concurrent
// reader can never observe a half-written credentials file. Previously this
// used a plain os.WriteFile, so an interrupted/concurrent write could leave
// truncated JSON — which the claude CLI then read as broken credentials and
// returned "401 Invalid authentication credentials" on every subsequent step.
//
// Callers should hold the cross-process flock (see withCredentialsFileLock).
func updateCredentialsFile(accessToken, refreshToken string, expiresIn int64) error {
	path := credentialsPath()
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("reading credentials file: %w", err)
	}

	var raw map[string]interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		return fmt.Errorf("parsing credentials file: %w", err)
	}

	oauth, ok := raw["claudeAiOauth"].(map[string]interface{})
	if !ok {
		return fmt.Errorf("credentials file has no claudeAiOauth object")
	}

	oauth["accessToken"] = accessToken
	if refreshToken != "" {
		oauth["refreshToken"] = refreshToken
	}
	if expiresIn > 0 {
		oauth["expiresAt"] = time.Now().UnixMilli() + expiresIn*1000
	} else {
		// The response carried no expires_in, so we have no idea when this
		// brand-new token dies. Keeping the *previous* expiresAt is the worst
		// option: it is already in the past, so tokenIsFresh would report the
		// new token as stale forever and every refresh would be re-attempted
		// on a token that never gets a chance to be used. Dropping the key
		// means "no recorded expiry", which tokenIsFresh trusts as-is.
		delete(oauth, "expiresAt")
	}

	updated, err := json.MarshalIndent(raw, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling credentials: %w", err)
	}
	return writeFileAtomic(path, updated, 0600)
}

// writeFileAtomic writes data to path via a temp file in the same directory
// followed by an atomic rename, so readers never see a partial file.
//
// If ANY temp-file step fails it falls back to a direct (non-atomic)
// os.WriteFile: the data may contain a freshly rotated single-use refresh
// token, so dropping the write entirely is far worse than losing atomicity.
func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	tmpErr := func() error {
		dir := filepath.Dir(path)
		tmp, err := os.CreateTemp(dir, ".credentials-*.tmp")
		if err != nil {
			return err
		}
		tmpName := tmp.Name()
		defer os.Remove(tmpName) // no-op if the rename below succeeded

		if _, err := tmp.Write(data); err != nil {
			tmp.Close()
			return err
		}
		if err := tmp.Sync(); err != nil {
			tmp.Close()
			return err
		}
		if err := tmp.Close(); err != nil {
			return err
		}
		if err := os.Chmod(tmpName, perm); err != nil {
			return err
		}
		return os.Rename(tmpName, path)
	}()
	if tmpErr == nil {
		return nil
	}
	if err := os.WriteFile(path, data, perm); err != nil {
		return fmt.Errorf("atomic write failed (%v) and direct write failed: %w", tmpErr, err)
	}
	return nil
}
