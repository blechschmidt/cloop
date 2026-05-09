// Package claudecode wraps the claude CLI binary as a provider.
package claudecode

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/blechschmidt/cloop/pkg/provider"
)

const ProviderName = "claudecode"

var envOnce sync.Once

type Provider struct{}

func New() *Provider { return &Provider{} }

func (p *Provider) Name() string         { return ProviderName }
func (p *Provider) DefaultModel() string { return "" }

// findClaude locates the claude binary. It checks PATH first, then common
// install locations that may not be in PATH when launched from a web server.
func findClaude() string {
	if p, err := exec.LookPath("claude"); err == nil {
		return p
	}
	// Common install paths
	home, _ := os.UserHomeDir()
	candidates := []string{
		filepath.Join(home, ".local", "bin", "claude"),
		filepath.Join(home, ".npm-global", "bin", "claude"),
		"/usr/local/bin/claude",
	}
	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			return c
		}
	}
	return "claude" // fall back, will produce a clear error
}

func (p *Provider) Complete(ctx context.Context, prompt string, opts provider.Options) (*provider.Result, error) {
	envOnce.Do(loadEnvFiles)

	args := []string{"--print", "--output-format", "text", "--permission-mode", "bypassPermissions"}
	if opts.Model != "" {
		args = append(args, "--model", opts.Model)
	}
	if opts.MaxTokens > 0 {
		args = append(args, "--max-tokens", fmt.Sprintf("%d", opts.MaxTokens))
	}

	timeout := opts.Timeout
	if timeout == 0 {
		timeout = 10 * time.Minute
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	claudeBin := findClaude()
	cmd := exec.CommandContext(ctx, claudeBin, args...)
	cmd.Env = append(os.Environ(), "IS_SANDBOX=1")
	if opts.WorkDir != "" {
		cmd.Dir = opts.WorkDir
	}
	cmd.Stdin = strings.NewReader(prompt)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	start := time.Now()
	err := cmd.Run()
	duration := time.Since(start)

	output := stdout.String()
	if output == "" && stderr.String() != "" {
		output = stderr.String()
	}
	output = strings.TrimSpace(output)

	if err != nil {
		exitErr, ok := err.(*exec.ExitError)
		if !ok {
			return nil, fmt.Errorf("claude CLI error: %w", err)
		}
		// Distinguish fatal auth/API errors from benign non-zero exits.
		// Without this, the orchestrator records the auth-failure message as a
		// normal step output and re-runs forever (observed: 1500+ consecutive
		// 401s in a single session).
		if isFatalCLIError(output) {
			return nil, fmt.Errorf("claude CLI auth/API failure (exit %d): %s", exitErr.ExitCode(), truncateForError(output))
		}
	}

	return &provider.Result{
		Output:   output,
		Duration: duration,
		Provider: ProviderName,
		Model:    opts.Model,
	}, nil
}

// isFatalCLIError returns true when the claude CLI's combined stdout/stderr
// output indicates an authentication failure or a clear API-side error that
// will not resolve by retrying with the same credentials. Conservative: only
// matches phrases the CLI emits for these exact failure modes, plus the
// distinct shape of an HTML error page (a misconfigured upstream/proxy
// returning a 4xx page instead of JSON — observed alongside the 401 burst
// that motivated the original fix).
//
// Why no 5xx markers: 5xx responses are transient and worth retrying. They are
// surfaced through the per-provider retry helper at the request layer, not
// here.
func isFatalCLIError(output string) bool {
	lower := strings.ToLower(output)
	switch {
	case strings.Contains(lower, "failed to authenticate"):
		return true
	case strings.Contains(lower, "invalid authentication credentials"):
		return true
	case strings.Contains(lower, "authentication_error"):
		return true
	case strings.Contains(lower, "api error: 401"):
		return true
	case strings.Contains(lower, "api error: 403"):
		return true
	case isLikelyHTMLErrorPage(lower):
		return true
	}
	return false
}

// isLikelyHTMLErrorPage detects output that is an HTML error page rather than
// a model response. Signals: a doctype, or the combination of an opening and
// closing <html> tag. Without this, an upstream proxy returning an auth/error
// HTML page can leak through as "successful" step output (observed: stray
// "</html>" entries in the autonomous loop alongside 401 bursts).
func isLikelyHTMLErrorPage(lowerOutput string) bool {
	if strings.Contains(lowerOutput, "<!doctype html") {
		return true
	}
	if strings.Contains(lowerOutput, "<html") && strings.Contains(lowerOutput, "</html>") {
		return true
	}
	return false
}

// truncateForError caps an error's embedded output at a length useful for log
// readability without flooding state.json or terminal scrollback.
func truncateForError(s string) string {
	const max = 512
	if len(s) <= max {
		return s
	}
	return s[:max] + "...(truncated)"
}

func loadEnvFiles() {
	home, _ := os.UserHomeDir()
	for _, p := range []string{
		filepath.Join(home, ".openclaw", "workspace", ".env"),
		filepath.Join(home, ".env"),
		".env",
	} {
		loadEnvFile(p)
	}
}

func loadEnvFile(path string) {
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) == 2 {
			key := strings.TrimSpace(parts[0])
			val := strings.TrimSpace(parts[1])
			if os.Getenv(key) == "" {
				os.Setenv(key, val)
			}
		}
	}
}
