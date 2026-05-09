// Package ratelimit - claude_usage.go fetches Claude Code subscription usage
// from the Anthropic OAuth usage API endpoint.
package ratelimit

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
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
	FiveHour      *UsageWindow `json:"five_hour"`
	SevenDay      *UsageWindow `json:"seven_day"`
	SevenDayOpus  *UsageWindow `json:"seven_day_opus"`
	SevenDaySonnet *UsageWindow `json:"seven_day_sonnet"`
	ExtraUsage    *ExtraUsage  `json:"extra_usage"`
	Error         *struct {
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
)

const usageEndpoint = "https://api.anthropic.com/api/oauth/usage"

// GetCachedUsage returns the last fetched usage, or nil if not available.
func GetCachedUsage() *ClaudeUsage {
	usageMu.RLock()
	defer usageMu.RUnlock()
	return lastUsage
}

// FetchClaudeUsage calls the Anthropic OAuth usage API to get subscription
// limits (5-hour window, weekly window, per-model breakdowns).
// The token should be a Claude Code OAuth access token (sk-ant-oat01-*).
func FetchClaudeUsage(token string) (*ClaudeUsage, error) {
	if token == "" {
		// Try to get from environment
		token = os.Getenv("CLAUDE_CODE_OAUTH_TOKEN")
	}
	if token == "" {
		// Try to read from credentials file
		token = readCredentialsToken()
	}
	if token == "" {
		return nil, fmt.Errorf("no OAuth token available")
	}

	client := &http.Client{Timeout: 10 * time.Second}
	req, err := http.NewRequest("GET", usageEndpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("anthropic-beta", "oauth-2025-04-20")
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("usage API request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := provider.ReadResponseBody(resp.Body, maxUsageResponseBytes)
	if err != nil {
		return nil, fmt.Errorf("reading usage response: %w", err)
	}

	var raw ClaudeUsageResponse
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, fmt.Errorf("parsing usage response: %w", err)
	}

	if raw.Error != nil {
		return nil, fmt.Errorf("usage API error: %s", raw.Error.Message)
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

	return usage, nil
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
const claudeOAuthTokenURL = "https://platform.claude.com/v1/oauth/token"

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

// readCredentialsToken reads the OAuth token from ~/.claude/.credentials.json,
// auto-refreshing it if expired.
func readCredentialsToken() string {
	data, err := os.ReadFile(credentialsPath())
	if err != nil {
		return ""
	}
	var creds claudeCredentials
	if err := json.Unmarshal(data, &creds); err != nil {
		return ""
	}

	// Check if token is expired (with 60s buffer)
	nowMs := time.Now().UnixMilli()
	if creds.ClaudeAiOauth.ExpiresAt > 0 && nowMs >= creds.ClaudeAiOauth.ExpiresAt-60000 {
		// Try to refresh
		if creds.ClaudeAiOauth.RefreshToken != "" {
			if newToken, err := refreshOAuthToken(creds.ClaudeAiOauth.RefreshToken); err == nil {
				return newToken
			}
		}
		return "" // expired and can't refresh
	}

	return creds.ClaudeAiOauth.AccessToken
}

// refreshOAuthToken uses the refresh token to get a new access token and
// updates the credentials file.
func refreshOAuthToken(refreshToken string) (string, error) {
	client := &http.Client{Timeout: 10 * time.Second}

	formData := fmt.Sprintf(
		"grant_type=refresh_token&refresh_token=%s&client_id=%s&redirect_uri=%s",
		refreshToken,
		claudeOAuthClientID,
		"https%3A%2F%2Fplatform.claude.com%2Foauth%2Fcode%2Fcallback",
	)

	req, err := http.NewRequest("POST", claudeOAuthTokenURL, strings.NewReader(formData))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("refresh request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	if resp.StatusCode != 200 {
		return "", fmt.Errorf("refresh failed with status %d: %s", resp.StatusCode, string(body))
	}

	var tokenResp struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		ExpiresIn    int64  `json:"expires_in"`
	}
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return "", fmt.Errorf("parsing refresh response: %w", err)
	}

	if tokenResp.AccessToken == "" {
		return "", fmt.Errorf("no access_token in refresh response")
	}

	// Update credentials file
	updateCredentialsFile(tokenResp.AccessToken, tokenResp.RefreshToken, tokenResp.ExpiresIn)

	// Also update the env var for cloop's claudecode provider
	os.Setenv("CLAUDE_CODE_OAUTH_TOKEN", tokenResp.AccessToken)

	return tokenResp.AccessToken, nil
}

// updateCredentialsFile writes the new tokens back to ~/.claude/.credentials.json
func updateCredentialsFile(accessToken, refreshToken string, expiresIn int64) {
	path := credentialsPath()
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}

	var raw map[string]interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		return
	}

	oauth, ok := raw["claudeAiOauth"].(map[string]interface{})
	if !ok {
		return
	}

	oauth["accessToken"] = accessToken
	if refreshToken != "" {
		oauth["refreshToken"] = refreshToken
	}
	if expiresIn > 0 {
		oauth["expiresAt"] = time.Now().UnixMilli() + expiresIn*1000
	}

	updated, err := json.MarshalIndent(raw, "", "  ")
	if err != nil {
		return
	}
	_ = os.WriteFile(path, updated, 0600)
}


