// Package ratelimit - claude_usage.go scrapes Claude Code CLI /usage output
// to get subscription usage limits (5-hour, weekly caps).
package ratelimit

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ClaudeUsage holds parsed /usage output from Claude Code CLI.
type ClaudeUsage struct {
	Percentage int       `json:"percentage"`      // e.g. 82
	Period     string    `json:"period"`           // e.g. "weekly" or "5-hour"
	ResetTime  string    `json:"reset_time"`       // e.g. "10pm (UTC)"
	RawLine    string    `json:"raw_line"`         // full parsed line
	FetchedAt  time.Time `json:"fetched_at"`
}

var (
	usageMu    sync.RWMutex
	lastUsage  *ClaudeUsage
	usageRegex = regexp.MustCompile(`You've used (\d+)% of your ([\w-]+) limit\s*[·•\-–]\s*resets?\s+(.+)`)
)

// GetCachedUsage returns the last fetched usage, or nil if not available.
func GetCachedUsage() *ClaudeUsage {
	usageMu.RLock()
	defer usageMu.RUnlock()
	return lastUsage
}

// FetchClaudeUsage runs `claude` in a pseudo-terminal, sends /usage, and
// parses the response. This is needed because Claude Code's /usage command
// is only available interactively and subscription limits are not exposed
// via any public API.
func FetchClaudeUsage() (*ClaudeUsage, error) {
	claudeBin := findClaudeBin()

	// Use script(1) to wrap claude in a PTY — avoids needing a Go PTY library.
	// script -qc 'echo "/usage" | claude' /dev/null
	cmd := exec.Command("script", "-qec",
		fmt.Sprintf("echo '/usage\n/exit' | %s", claudeBin),
		"/dev/null")

	// Inherit environment for CLAUDE_CODE_OAUTH_TOKEN etc.
	cmd.Env = os.Environ()

	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out

	// Set a timeout via context
	done := make(chan error, 1)
	go func() {
		done <- cmd.Run()
	}()

	select {
	case err := <-done:
		if err != nil {
			// Claude may exit non-zero on /exit, that's fine
			_ = err
		}
	case <-time.After(30 * time.Second):
		if cmd.Process != nil {
			cmd.Process.Kill()
		}
		return nil, fmt.Errorf("claude usage fetch timed out after 30s")
	}

	return parseUsageOutput(out.String())
}

// parseUsageOutput extracts usage info from raw terminal output.
func parseUsageOutput(raw string) (*ClaudeUsage, error) {
	// Strip ANSI escape codes
	ansiRegex := regexp.MustCompile(`\x1b\[[0-9;]*[a-zA-Z]|\x1b\][^\x1b]*\x1b\\|\x1b\[[\?]?[0-9;]*[a-zA-Z]`)
	clean := ansiRegex.ReplaceAllString(raw, "")

	// Also handle some common terminal artifacts
	clean = strings.ReplaceAll(clean, "\r", "")

	matches := usageRegex.FindStringSubmatch(clean)
	if matches == nil {
		// Try a more lenient match
		pctRegex := regexp.MustCompile(`(\d+)%\s+of\s+your\s+([\w-]+)\s+limit`)
		pctMatches := pctRegex.FindStringSubmatch(clean)
		if pctMatches != nil {
			pct, _ := strconv.Atoi(pctMatches[1])
			usage := &ClaudeUsage{
				Percentage: pct,
				Period:     pctMatches[2],
				RawLine:    strings.TrimSpace(pctMatches[0]),
				FetchedAt:  time.Now().UTC(),
			}
			usageMu.Lock()
			lastUsage = usage
			usageMu.Unlock()
			return usage, nil
		}
		return nil, fmt.Errorf("could not parse /usage output")
	}

	pct, _ := strconv.Atoi(matches[1])
	usage := &ClaudeUsage{
		Percentage: pct,
		Period:     matches[2],
		ResetTime:  strings.TrimSpace(matches[3]),
		RawLine:    strings.TrimSpace(matches[0]),
		FetchedAt:  time.Now().UTC(),
	}

	usageMu.Lock()
	lastUsage = usage
	usageMu.Unlock()

	return usage, nil
}

// findClaudeBin locates the claude binary (same logic as provider).
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
