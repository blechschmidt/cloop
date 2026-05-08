// Package ratelimit - claude_usage.go fetches Claude Code subscription usage
// from the Anthropic OAuth usage API endpoint.
package ratelimit

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

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

	body, err := io.ReadAll(resp.Body)
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

// readCredentialsToken reads the OAuth token from ~/.claude/.credentials.json
func readCredentialsToken() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	data, err := os.ReadFile(home + "/.claude/.credentials.json")
	if err != nil {
		return ""
	}
	var creds struct {
		ClaudeAiOauth struct {
			AccessToken string `json:"accessToken"`
		} `json:"claudeAiOauth"`
	}
	if err := json.Unmarshal(data, &creds); err != nil {
		return ""
	}
	return creds.ClaudeAiOauth.AccessToken
}

// FetchClaudeUsageFallback runs the Claude CLI /usage command via script(1)
// as a fallback when the API doesn't work (e.g. missing user:profile scope).
func FetchClaudeUsageFallback() (*ClaudeUsage, error) {
	claudeBin := findClaudeBin()

	cmd := exec.Command("script", "-qec",
		fmt.Sprintf("echo '/usage\n/exit' | %s", claudeBin),
		"/dev/null")
	cmd.Env = os.Environ()

	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out

	done := make(chan error, 1)
	go func() { done <- cmd.Run() }()

	select {
	case <-done:
	case <-time.After(30 * time.Second):
		if cmd.Process != nil {
			cmd.Process.Kill()
		}
		return nil, fmt.Errorf("claude usage fetch timed out")
	}

	return parseUsageOutput(out.String())
}

var usageLineRegex = regexp.MustCompile(`(\d+)%\s+of\s+your\s+([\w-]+)\s+limit`)

func parseUsageOutput(raw string) (*ClaudeUsage, error) {
	ansiRegex := regexp.MustCompile(`\x1b\[[0-9;]*[a-zA-Z]|\x1b\][^\x1b]*\x1b\\|\x1b\[\[\?]?[0-9;]*[a-zA-Z]`)
	clean := ansiRegex.ReplaceAllString(raw, "")
	clean = strings.ReplaceAll(clean, "\r", "")

	matches := usageLineRegex.FindStringSubmatch(clean)
	if matches == nil {
		return nil, fmt.Errorf("could not parse /usage output")
	}

	pct, _ := strconv.ParseFloat(matches[1], 64)
	period := matches[2]

	usage := &ClaudeUsage{FetchedAt: time.Now().UTC()}
	detail := &UsageDetail{Utilization: pct}

	switch period {
	case "weekly":
		usage.SevenDay = detail
	case "5-hour":
		usage.FiveHour = detail
	default:
		usage.SevenDay = detail
	}

	usageMu.Lock()
	lastUsage = usage
	usageMu.Unlock()

	return usage, nil
}

// findClaudeBin locates the claude binary.
func findClaudeBin() string {
	if p, err := exec.LookPath("claude"); err == nil {
		return p
	}
	home, _ := os.UserHomeDir()
	candidates := []string{
		home + "/.local/bin/claude",
		home + "/.npm-global/bin/claude",
		"/usr/local/bin/claude",
	}
	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			return c
		}
	}
	return "claude"
}
