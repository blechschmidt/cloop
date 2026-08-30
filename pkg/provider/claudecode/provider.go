// Package claudecode wraps the claude CLI binary as a provider.
package claudecode

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/blechschmidt/cloop/pkg/provider"
)

const ProviderName = "claudecode"

var envOnce sync.Once

// ErrAuthFailure marks a CLI invocation the API rejected for credential
// reasons (HTTP 401 / authentication_error). Callers use errors.Is to tell it
// apart from the other fatal CLI failures — 403, 429, 5xx, HTML error pages —
// which a credential refresh cannot fix and which must therefore not be
// retried here.
var ErrAuthFailure = errors.New("claude CLI authentication failure")

// refreshCredential rotates the stored Claude Code OAuth credential and
// returns a fresh access token, or "" when none could be produced.
//
// It is a hook rather than a direct call to pkg/ratelimit because that package
// transitively pulls in the executor, Kubernetes and secret-broker trees;
// importing it here would turn a leaf provider into a package that cannot
// compile — or be tested — unless all of that builds. cmd/providers.go wires
// the real implementation, alongside the other provider registration.
//
// Leaving it unset degrades gracefully rather than breaking the retry: the CLI
// re-reads ~/.claude/.credentials.json on the second attempt anyway, which is
// what recovers the common case where a peer process won the refresh race and
// has already written the rotated token to disk.
var refreshCredential func() string

// SetCredentialRefresher installs the OAuth refresh used before an
// authentication retry. Called once from cmd/providers.go; also used by tests
// to substitute a stub for the real credentials and network.
func SetCredentialRefresher(fn func() string) { refreshCredential = fn }

// CredentialRefresherWired reports whether a refresher has been installed.
// Exists so a test can assert the cmd/providers.go wiring is still present:
// losing it degrades the retry silently — it would still fire, but could only
// recover races a peer process happened to win, not a credential this process
// must rotate itself.
func CredentialRefresherWired() bool { return refreshCredential != nil }

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

// buildArgs assembles the claude CLI argument list for a completion call.
// Split out from Complete so the flag mapping is unit-testable without
// spawning the real binary.
func buildArgs(opts provider.Options) []string {
	args := []string{"--print", "--output-format", "text", "--permission-mode", "bypassPermissions"}
	if opts.Model != "" {
		args = append(args, "--model", opts.Model)
	}
	if opts.MaxTokens > 0 {
		args = append(args, "--max-tokens", fmt.Sprintf("%d", opts.MaxTokens))
	}
	// Reasoning-effort level (low/medium/high/xhigh/max). Guarded by
	// ValidEffort so a corrupted state value can never inject an unknown
	// flag value that would make every CLI invocation fail.
	if opts.Effort != "" && provider.ValidEffort(opts.Effort) {
		args = append(args, "--effort", opts.Effort)
	}
	return args
}

// Complete runs the CLI once and, if the API rejected our credentials,
// refreshes the OAuth token and retries exactly once.
//
// Why a retry belongs here (Task 20204): a 401 from this provider is usually
// not a dead credential but a *lost race* for one. The CLI subprocesses
// refresh OAuth independently of each other and of cloop, and Claude.ai
// refresh tokens are single-use — so when a parallel round of tasks straddles
// the token's expiry, several CLI processes exchange the same refresh token at
// once. One wins; the losers get invalid_grant and surface "API Error: 401".
// The task after them succeeds because the winner has meanwhile written a
// fresh credential to disk, which is precisely the reported symptom: an
// isolated 401 with a healthy task on either side. A transient 401 from the
// edge (observed: a Cloudflare 502 body delivered under a 401 status) has the
// same shape and the same remedy.
//
// Retrying is therefore scoped strictly to authentication failures. 429 and
// 5xx are deliberately excluded: an immediate retry cannot help a rate limit
// and would feed the loop that keeps it alive, and the orchestrator's
// MaxFailures gate already handles sustained upstream outages.
func (p *Provider) Complete(ctx context.Context, prompt string, opts provider.Options) (*provider.Result, error) {
	envOnce.Do(loadEnvFiles)

	res, err := p.runCLI(ctx, prompt, opts, "")
	if err == nil || !errors.Is(err, ErrAuthFailure) {
		return res, err
	}
	// Don't spend a retry on a context that is already done — the second
	// attempt would fail instantly and replace a clear auth diagnosis with a
	// cancellation one.
	if ctx.Err() != nil {
		return res, err
	}

	// Re-resolve the credential under pkg/ratelimit's process-wide mutex and
	// cross-process flock. When peers lost the same race, they coalesce here
	// and all receive the winner's token, so a whole parallel round recovers
	// on a single exchange rather than N competing ones.
	var fresh string
	if refreshCredential != nil {
		fresh = refreshCredential()
	}

	retryRes, retryErr := p.runCLI(ctx, prompt, opts, fresh)
	if retryErr != nil {
		// Keep the sentinel intact so errors.Is still classifies this, and say
		// that the retry happened so a genuinely dead credential is not
		// mistaken for a race that nobody tried to recover from.
		return retryRes, fmt.Errorf("%w (retried once after refreshing credentials)", retryErr)
	}
	return retryRes, nil
}

// runCLI performs a single claude CLI invocation. tokenOverride, when
// non-empty, pins CLAUDE_CODE_OAUTH_TOKEN for this child process; it carries
// the freshly refreshed credential into a retry so the attempt cannot be
// undone by a stale token already present in the environment (cloop injects
// one from ~/.openclaw/workspace/.env via loadEnvFiles, and that value is a
// snapshot that is never itself refreshed).
func (p *Provider) runCLI(ctx context.Context, prompt string, opts provider.Options, tokenOverride string) (*provider.Result, error) {
	args := buildArgs(opts)

	timeout := opts.Timeout
	if timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}
	// When timeout == 0, no deadline is applied — the parent context
	// controls cancellation. The process-exit watchdog below ensures
	// we never hang on a dead child process.

	claudeBin := findClaude()
	cmd := exec.CommandContext(ctx, claudeBin, args...)
	// Run the CLI in its own process group so cancellation can SIGKILL the
	// whole tree: grandchildren inherit the stdout/stderr pipes and would
	// otherwise keep cmd.Wait blocked after the CLI itself dies. WaitDelay
	// bounds Wait even if some pipe-holder survives the group kill (mirrors
	// pkg/plugin and pkg/hooks).
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.WaitDelay = 5 * time.Second
	cmd.Env = append(os.Environ(), "IS_SANDBOX=1")
	if tokenOverride != "" {
		// exec deduplicates the environment keeping the last occurrence, so
		// this wins over any CLAUDE_CODE_OAUTH_TOKEN inherited or loaded from
		// a .env file.
		cmd.Env = append(cmd.Env, "CLAUDE_CODE_OAUTH_TOKEN="+tokenOverride)
	}
	if opts.WorkDir != "" {
		cmd.Dir = opts.WorkDir
	}
	cmd.Stdin = strings.NewReader(prompt)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	start := time.Now()

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("claude CLI start error: %w", err)
	}

	// Wait for the process in a goroutine so we can detect context
	// cancellation even if cmd.Wait blocks on inherited pipe readers
	// (child processes that inherit stdout/stderr).
	waitCh := make(chan error, 1)
	go func() { waitCh <- cmd.Wait() }()

	var err error
	select {
	case err = <-waitCh:
		// Process exited normally.
	case <-ctx.Done():
		// Context cancelled or timed out. Kill the whole process group
		// (negative pid) so forked children die too; fall back to killing
		// just the CLI process if the group kill fails.
		if err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL); err != nil {
			_ = cmd.Process.Kill()
		}
		<-waitCh // reap
		return nil, fmt.Errorf("claude CLI cancelled: %w", ctx.Err())
	}

	duration := time.Since(start)

	output := stdout.String()
	if output == "" && stderr.String() != "" {
		output = stderr.String()
	}
	output = strings.TrimSpace(output)

	// Surface context cancellation/timeout as a real error rather than silently
	// returning the partial output. Without this, exec.CommandContext kills the
	// subprocess on timeout, cmd.Run returns a benign-looking *exec.ExitError,
	// and the orchestrator records the truncated output as a "successful" step.
	// A recurring timeout would then re-fire indefinitely without ever tripping
	// the MaxFailures gate (same failure shape as the auth-loop incident).
	if ctxErr := ctx.Err(); ctxErr != nil {
		return nil, fmt.Errorf("claude CLI cancelled: %w", ctxErr)
	}

	if err != nil {
		exitErr, ok := err.(*exec.ExitError)
		if !ok {
			return nil, fmt.Errorf("claude CLI error: %w", err)
		}
		// Distinguish fatal auth/API errors from benign non-zero exits.
		// Without this, the orchestrator records the auth-failure message as a
		// normal step output and re-runs forever (observed: 1500+ consecutive
		// 401s in a single session).
		if kind := classifyCLIError(output); kind != cliErrorNone {
			return nil, cliFailureError(kind, exitErr.ExitCode(), output)
		}
	} else if kind := classifyCLIError(output); kind != cliErrorNone {
		// In production the claude CLI sometimes exits 0 while writing an
		// auth/API failure to stdout (observed: 2000+ consecutive 401-bearing
		// steps in one session, all with exit 0). The exit-non-zero branch
		// above never fired, so the failure leaked through as "successful"
		// step output. Surface it as an error here too so the orchestrator's
		// MaxFailures gate can stop the loop.
		return nil, cliFailureError(kind, 0, output)
	}

	return &provider.Result{
		Output:   output,
		Duration: duration,
		Provider: ProviderName,
		Model:    opts.Model,
	}, nil
}

// isFatalCLIError returns true when the claude CLI's combined stdout/stderr
// output is a recognised API-side failure (auth, rate-limit, or server-side
// error) and must therefore be surfaced as a Go error rather than swallowed as
// step output. Conservative: only matches phrases the CLI emits for these
// failure modes, plus the distinct shape of an HTML error page (a
// misconfigured upstream/proxy returning a 4xx page instead of JSON — observed
// alongside the 401 burst that motivated the original fix).
//
// Why 5xx/429 are also surfaced (not just 4xx auth): claudecode runs the CLI
// as a subprocess and has no internal retry layer. If we swallow a 5xx as
// "successful" output, the orchestrator's consecutiveErrors counter never
// increments and a sustained upstream outage (observed: 10+ "API Error: 502
// Bad Gateway" entries across one autonomous session) burns budget
// indefinitely. Returning an error lets the orchestrator's MaxFailures gate
// distinguish transient (1 failure → counter resets on next success) from
// persistent (≥MaxFailures → abort). A single 502 therefore costs one step;
// a 502 storm costs at most MaxFailures steps before the loop stops.
func isFatalCLIError(output string) bool {
	return classifyCLIError(output) != cliErrorNone
}

// cliErrorKind separates the fatal CLI failures that a credential refresh can
// plausibly fix from those it cannot. Only the former are worth an immediate
// retry (Task 20204).
type cliErrorKind int

const (
	// cliErrorNone: not a recognised API-side failure.
	cliErrorNone cliErrorKind = iota
	// cliErrorAuth: the API rejected our credentials (401 /
	// authentication_error). Frequently a lost race for a rotating
	// single-use refresh token, so one retry after refreshing usually wins.
	cliErrorAuth
	// cliErrorOther: fatal, but retrying now would not help — 403 (the grant
	// is too narrow, refreshing cannot widen it), 429 (retrying sustains the
	// rate limit), 5xx and HTML error pages (upstream, not us).
	cliErrorOther
)

// classifyCLIError inspects the combined stdout/stderr for a recognised
// API-side failure and reports which kind it is.
//
// Auth markers are tested first and deliberately win over the others: the CLI
// has been observed emitting "Failed to authenticate. API Error: 401" with an
// upstream HTML 502 body attached, and that is a transient auth failure worth
// retrying, not an HTML error page worth giving up on.
func classifyCLIError(output string) cliErrorKind {
	lower := strings.ToLower(output)
	switch {
	case strings.Contains(lower, "failed to authenticate"),
		strings.Contains(lower, "invalid authentication credentials"),
		strings.Contains(lower, "authentication_error"),
		strings.Contains(lower, "api error: 401"):
		return cliErrorAuth
	case strings.Contains(lower, "api error: 403"),
		strings.Contains(lower, "api error: 429"),
		hasAPIError5xx(lower),
		isLikelyHTMLErrorPage(lower):
		return cliErrorOther
	}
	return cliErrorNone
}

// cliFailureError renders a fatal CLI failure, tagging authentication ones
// with ErrAuthFailure so Complete can decide whether a retry is worthwhile.
// The non-auth wording is unchanged from before the split, since operators and
// log greps already know it.
func cliFailureError(kind cliErrorKind, exitCode int, output string) error {
	if kind == cliErrorAuth {
		return fmt.Errorf("%w (exit %d): %s", ErrAuthFailure, exitCode, truncateForError(output))
	}
	return fmt.Errorf("claude CLI auth/API failure (exit %d): %s", exitCode, truncateForError(output))
}

// hasAPIError5xx reports whether the (already lower-cased) output contains the
// CLI's "API Error: 5xx ..." marker for any 5xx status. We intentionally avoid
// matching bare "5xx" tokens elsewhere in the output to keep false positives
// out of normal model responses that happen to mention a status code.
func hasAPIError5xx(lowerOutput string) bool {
	const prefix = "api error: 5"
	idx := strings.Index(lowerOutput, prefix)
	if idx < 0 {
		return false
	}
	rest := lowerOutput[idx+len(prefix):]
	if len(rest) < 2 {
		return false
	}
	// Require two more digits so "api error: 5 servers tried" can't trip.
	return isASCIIDigit(rest[0]) && isASCIIDigit(rest[1])
}

func isASCIIDigit(b byte) bool { return b >= '0' && b <= '9' }

// isLikelyHTMLErrorPage detects output that is an HTML error page rather than
// a model response. Signals: a doctype, the combination of an opening and
// closing <html> tag, or — defense in depth — output that is *exactly* a bare
// "</html>" after trimming. Without this, an upstream proxy returning an
// auth/error HTML page can leak through as "successful" step output
// (observed: stray "</html>" entries in the autonomous loop alongside 401
// bursts; some appeared in isolation when the surrounding markup was stripped
// by output buffering).
//
// The bare-tag check is intentionally strict (full-output equality, not
// substring): a legitimate model response that happens to mention "</html>"
// in code or examples must NOT trip this, only a response whose *entire*
// content is the closing tag — which is never a real model answer.
func isLikelyHTMLErrorPage(lowerOutput string) bool {
	if strings.Contains(lowerOutput, "<!doctype html") {
		return true
	}
	if strings.Contains(lowerOutput, "<html") && strings.Contains(lowerOutput, "</html>") {
		return true
	}
	if strings.TrimSpace(lowerOutput) == "</html>" {
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
