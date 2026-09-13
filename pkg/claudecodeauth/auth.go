// Package claudecodeauth wraps the `claude auth` subcommand so the Web UI can
// drive Claude Code login/logout/status from the browser. The login flow is
// inherently interactive: `claude auth login` prints a one-shot OAuth URL and
// then blocks on stdin reading a paste-back authorization code. We model that
// as a server-side session: Start spawns the CLI, captures the URL, and keeps
// the process handle; SubmitCode writes the code to stdin and waits for the
// process to exit; Cancel/Stop kills it.
//
// Every operation is scoped to a Claude CLI configuration directory (see
// identity.go), so an OIDC hub can give each signed-in user their own login,
// credential and session history. An empty configDir means "use the host
// default", which is the single-user behaviour this package started with.
//
// Login sessions are keyed the same way, because a hub has as many concurrent
// operators as it has users: one global in-flight session would mean the
// second person to click Login silently kills the first person's OAuth flow.
package claudecodeauth

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// findClaude returns the path to the claude CLI binary. Mirrors the lookup in
// pkg/provider/claudecode so the Web UI uses the same binary that the
// orchestrator would spawn for task execution.
func findClaude() string {
	if p, err := exec.LookPath("claude"); err == nil {
		return p
	}
	home, _ := os.UserHomeDir()
	for _, c := range []string{
		filepath.Join(home, ".local", "bin", "claude"),
		filepath.Join(home, ".npm-global", "bin", "claude"),
		"/usr/local/bin/claude",
	} {
		if _, err := os.Stat(c); err == nil {
			return c
		}
	}
	return "claude"
}

// AmbientTokenVars are the environment variables that hand the Claude CLI a
// credential without it ever consulting its configuration directory.
//
// They must be cleared whenever a per-identity configDir is in force. cloop
// itself populates CLAUDE_CODE_OAUTH_TOKEN from ~/.openclaw/workspace/.env and
// ~/.env (see pkg/provider/claudecode.loadEnvFiles), and an ambient token
// beats an empty config directory: measured against the real CLI, a user who
// has never logged in reports `loggedIn: true, authMethod: oauth_token` and
// their prompts run on the host's account. Per-user isolation would then be
// an illusion — every tenant silently sharing one subscription — which is
// precisely the failure this package exists to prevent.
var AmbientTokenVars = []string{
	"CLAUDE_CODE_OAUTH_TOKEN",
	"ANTHROPIC_API_KEY",
	"ANTHROPIC_AUTH_TOKEN",
}

// ClaudeOnlyTokenVars is the subset of AmbientTokenVars that nothing except
// the Claude Code path consumes.
//
// The distinction matters because the two environments this package scopes are
// not the same. A `claude` subprocess may have every ambient credential
// cleared, since that environment serves one program. A dispatched cloop
// harness may not: ANTHROPIC_API_KEY is also how pkg/provider/anthropic finds
// its key, so blanking it there would break a project using the `anthropic`
// provider on an OIDC hub — a self-inflicted outage in the name of isolating a
// provider that project is not even using.
var ClaudeOnlyTokenVars = []string{"CLAUDE_CODE_OAUTH_TOKEN"}

// ScopeEnv returns env (in "K=V" form) rewritten so the Claude CLI resolves
// its credential from configDir and nowhere else. Use it for a `claude`
// subprocess, where clearing every ambient credential is free of collateral
// damage.
//
// When configDir is empty the environment is returned untouched: a deployment
// with no OIDC keeps using whatever credential the host is configured with,
// ambient tokens included.
//
// Clearing is done by appending an empty assignment rather than by dropping
// the variable, so the result is correct whether the caller hands it to
// exec (last assignment wins) or scans it for a value.
func ScopeEnv(env []string, configDir string) []string {
	return scopeEnv(env, configDir, AmbientTokenVars)
}

// ScopeHarnessEnv pins a dispatched cloop harness to one identity's Claude
// configuration directory, clearing only the variables that belong to the
// Claude Code path. Other providers' credentials pass through untouched — see
// ClaudeOnlyTokenVars.
//
// The harness's own claudecode provider re-scopes with the stricter ScopeEnv
// when it finally spawns the CLI, so the remaining ambient credentials never
// reach the `claude` binary regardless.
func ScopeHarnessEnv(env []string, configDir string) []string {
	return scopeEnv(env, configDir, ClaudeOnlyTokenVars)
}

func scopeEnv(env []string, configDir string, clear []string) []string {
	if strings.TrimSpace(configDir) == "" {
		return env
	}
	out := make([]string, 0, len(env)+len(clear)+1)
	for _, kv := range env {
		if !assignsAny(kv, clear) && !strings.HasPrefix(kv, "CLAUDE_CONFIG_DIR=") {
			out = append(out, kv)
		}
	}
	for _, k := range clear {
		out = append(out, k+"=")
	}
	return append(out, "CLAUDE_CONFIG_DIR="+configDir)
}

func assignsAny(kv string, keys []string) bool {
	for _, k := range keys {
		if strings.HasPrefix(kv, k+"=") {
			return true
		}
	}
	return false
}

// cliEnv builds the environment for a `claude` subprocess scoped to configDir.
func cliEnv(configDir string) []string {
	return ScopeEnv(append(os.Environ(), "IS_SANDBOX=1"), configDir)
}

// Status mirrors the JSON shape that `claude auth status --json` returns.
// Fields not emitted by the CLI are simply left zero-valued.
type Status struct {
	LoggedIn         bool   `json:"loggedIn"`
	AuthMethod       string `json:"authMethod,omitempty"`
	APIProvider      string `json:"apiProvider,omitempty"`
	Email            string `json:"email,omitempty"`
	OrgID            string `json:"orgId,omitempty"`
	OrgName          string `json:"orgName,omitempty"`
	SubscriptionType string `json:"subscriptionType,omitempty"`
}

// FetchStatus runs `claude auth status --json` and parses the result. The CLI
// returns exit code 0 even when logged out (loggedIn=false in the JSON), so
// any non-nil error here is a real environmental failure (binary missing,
// timeout, malformed output) and the UI should surface it as such.
// configDir scopes the lookup to one identity's credential; empty means the
// host default.
func FetchStatus(ctx context.Context, configDir string) (*Status, error) {
	if _, cancel := contextWithTimeoutIfNone(ctx, 10*time.Second); cancel != nil {
		defer cancel()
	}
	cmd := exec.CommandContext(ctx, findClaude(), "auth", "status", "--json")
	cmd.Env = cliEnv(configDir)
	out, err := cmd.Output()
	// The CLI exits 1 when logged out but still returns valid JSON with
	// loggedIn=false. Try to parse the output first; only treat as error
	// if parsing fails (binary missing, garbled output, etc.).
	if len(out) > 0 {
		var s Status
		if jsonErr := json.Unmarshal(out, &s); jsonErr == nil {
			return &s, nil
		}
	}
	if err != nil {
		var stderr string
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			stderr = strings.TrimSpace(string(exitErr.Stderr))
			// Also try stdout from ExitError
			if stderr == "" {
				stderr = strings.TrimSpace(string(out))
			}
		}
		if stderr != "" {
			return nil, fmt.Errorf("claude auth status failed: %s", stderr)
		}
		return nil, fmt.Errorf("claude auth status: %w", err)
	}
	var s Status
	if err := json.Unmarshal(out, &s); err != nil {
		return nil, fmt.Errorf("parse claude auth status: %w (output: %s)", err, strings.TrimSpace(string(out)))
	}
	return &s, nil
}

// Logout invokes `claude auth logout`. The CLI is non-interactive in this path
// so a 10-second timeout is sufficient.
// configDir scopes the logout to one identity, so a user signing out of the
// hub does not sign out every other tenant.
func Logout(ctx context.Context, configDir string) error {
	ctx, cancel := contextWithTimeoutIfNone(ctx, 10*time.Second)
	if cancel != nil {
		defer cancel()
	}
	cmd := exec.CommandContext(ctx, findClaude(), "auth", "logout")
	cmd.Env = cliEnv(configDir)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("claude auth logout: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// LoginOptions controls how `claude auth login` is invoked. The defaults match
// the CLI's default flow (Claude subscription, no email pre-fill).
type LoginOptions struct {
	// Console switches the OAuth target to api.anthropic.com (console billing)
	// instead of claude.ai subscription auth.
	Console bool
	// Email pre-populates the login page's email field.
	Email string
	// SSO forces the SSO login flow.
	SSO bool
}

// Session represents a live `claude auth login` subprocess waiting for the
// pasted authorization code on stdin.
type Session struct {
	StartedAt time.Time
	URL       string

	mu         sync.Mutex
	cmd        *exec.Cmd
	stdin      io.WriteCloser
	stdoutBuf  *bufferedReader
	done       chan struct{}
	exitErr    error
	output     string
	closed     bool
	finishedAt time.Time
}

// State is a snapshot of session progress safe to serialize for the UI.
type State struct {
	Active    bool      `json:"active"`
	StartedAt time.Time `json:"started_at,omitempty"`
	URL       string    `json:"url,omitempty"`
	Done      bool      `json:"done,omitempty"`
	Success   bool      `json:"success,omitempty"`
	Output    string    `json:"output,omitempty"`
	Error     string    `json:"error,omitempty"`
}

// Snapshot returns a serializable view of the session's progress without
// taking ownership of any goroutines or channels. Safe for concurrent reads.
func (s *Session) Snapshot() State {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := State{
		Active:    !s.closed,
		StartedAt: s.StartedAt,
		URL:       s.URL,
		Output:    s.output,
	}
	select {
	case <-s.done:
		st.Done = true
		st.Active = false
		if s.exitErr != nil {
			// Include CLI output so the UI shows what actually went wrong,
			// not just "exit status 1".
			out := strings.TrimSpace(s.output)
			if out != "" {
				st.Error = out
			} else {
				st.Error = s.exitErr.Error()
			}
		} else {
			st.Success = true
		}
	default:
	}
	return st
}

// maxSessions bounds how many login flows can be in flight across the whole
// hub. Each one is a live `claude auth login` subprocess parked on stdin, so
// an unbounded map is a process-exhaustion lever for any authenticated user
// with a script. Well past what a real deployment needs concurrently, since a
// session only lives for as long as a human takes to paste a code.
const maxSessions = 32

// sessionReapAfter is how long a finished session's outcome stays readable
// before it is swept. The UI polls the snapshot right after SubmitCode to
// render success or the CLI's error text, so terminal sessions cannot be
// dropped immediately — but they must not accumulate either.
const sessionReapAfter = 10 * time.Minute

// Manager owns the in-flight login sessions, keyed by identity. Methods are
// safe for concurrent use by multiple HTTP handlers.
//
// The key is the caller's identity (an OwnerKey) so that two users logging in
// at the same time do not evict each other, and so one user's pasted code can
// never be delivered to another user's OAuth flow. An empty key is the
// single-user/host session.
type Manager struct {
	mu       sync.Mutex
	sessions map[string]*Session
}

// NewManager returns a fresh login session manager.
func NewManager() *Manager { return &Manager{sessions: make(map[string]*Session)} }

// Start spawns `claude auth login` scoped to configDir and waits for it to
// emit the OAuth URL, returning a Session that the caller can later complete
// by passing the authorization code to SubmitCode. If the same identity
// already has a session in flight it is killed first so the new flow can take
// over; other identities' sessions are left alone.
func (m *Manager) Start(ctx context.Context, key, configDir string, opts LoginOptions) (*Session, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.sessions == nil {
		m.sessions = make(map[string]*Session)
	}
	m.reapLocked()

	// Replace this identity's existing session — the previous browser tab
	// presumably timed out or the user restarted the flow.
	if prev := m.sessions[key]; prev != nil {
		prev.kill("superseded by new login attempt")
		delete(m.sessions, key)
	}

	// Counted after reaping and after evicting our own predecessor, so a user
	// retrying their own login never trips the bound.
	if len(m.sessions) >= maxSessions {
		return nil, fmt.Errorf("too many Claude logins in flight (%d); retry shortly", len(m.sessions))
	}

	args := []string{"auth", "login"}
	if opts.Console {
		args = append(args, "--console")
	} else {
		args = append(args, "--claudeai")
	}
	if opts.SSO {
		args = append(args, "--sso")
	}
	if opts.Email != "" {
		args = append(args, "--email", opts.Email)
	}

	// We deliberately don't use exec.CommandContext: the manager controls the
	// lifetime explicitly via Cancel/SubmitCode/kill, and we don't want the
	// HTTP handler's request context to abort an in-flight OAuth flow.
	cmd := exec.Command(findClaude(), args...)
	// Scoped to this identity's directory, with ambient tokens cleared — see
	// ScopeEnv. Without this the CLI would happily report the host's account
	// as already logged in and never perform the OAuth exchange at all.
	cmd.Env = cliEnv(configDir)

	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, fmt.Errorf("open stdin: %w", err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		_ = stdin.Close()
		return nil, fmt.Errorf("open stdout: %w", err)
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		_ = stdin.Close()
		_ = stdout.Close()
		return nil, fmt.Errorf("open stderr: %w", err)
	}

	if err := cmd.Start(); err != nil {
		_ = stdin.Close()
		return nil, fmt.Errorf("start claude auth login: %w", err)
	}

	sess := &Session{
		StartedAt: time.Now(),
		cmd:       cmd,
		stdin:     stdin,
		stdoutBuf: newBufferedReader(),
		done:      make(chan struct{}),
	}

	// Pump stdout and stderr into a single bounded buffer so the snapshot
	// can show the URL line, prompts, and any error text.
	go sess.stdoutBuf.consume(stdout)
	go sess.stdoutBuf.consume(stderr)

	// Wait for either the URL to appear or the process to exit. Bound the
	// wait so a wedged or unauthenticated child can't pin the handler.
	urlCh := make(chan string, 1)
	go func() {
		urlCh <- sess.stdoutBuf.waitForURL(15 * time.Second)
	}()

	go func() {
		err := cmd.Wait()
		sess.mu.Lock()
		sess.exitErr = err
		sess.output = sess.stdoutBuf.snapshot()
		sess.closed = true
		sess.finishedAt = time.Now()
		close(sess.done)
		sess.mu.Unlock()
		_ = stdin.Close()
	}()

	select {
	case url := <-urlCh:
		sess.mu.Lock()
		sess.URL = url
		sess.mu.Unlock()
		if url == "" {
			// No URL within the timeout window — either the CLI errored out
			// immediately or it's emitting something we don't recognise.
			sess.kill("no OAuth URL emitted within timeout")
			out := sess.stdoutBuf.snapshot()
			return nil, fmt.Errorf("claude auth login did not emit an OAuth URL: %s", strings.TrimSpace(out))
		}
	case <-sess.done:
		out := sess.stdoutBuf.snapshot()
		if sess.exitErr != nil {
			return nil, fmt.Errorf("claude auth login exited early: %w: %s", sess.exitErr, strings.TrimSpace(out))
		}
		return nil, fmt.Errorf("claude auth login exited before emitting a URL: %s", strings.TrimSpace(out))
	}

	m.sessions[key] = sess
	return sess, nil
}

// reapLocked drops sessions that finished long enough ago that nobody is
// still reading their outcome. Caller must hold m.mu.
func (m *Manager) reapLocked() {
	for k, sess := range m.sessions {
		if sess.finishedBefore(time.Now().Add(-sessionReapAfter)) {
			delete(m.sessions, k)
		}
	}
}

// finishedBefore reports whether the session has exited and did so before t.
func (s *Session) finishedBefore(t time.Time) bool {
	select {
	case <-s.done:
	default:
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.finishedAt.Before(t)
}

// SubmitCode pipes the OAuth authorization code to the running login session
// and waits up to 30 seconds for the CLI to exit. On success the session is
// cleared. The returned State describes the final outcome regardless of
// whether the CLI exited cleanly.
// The key selects the caller's own session, so a code pasted by one user can
// never complete another user's OAuth flow.
func (m *Manager) SubmitCode(key, code string) (State, error) {
	m.mu.Lock()
	sess := m.sessions[key]
	m.mu.Unlock()
	if sess == nil {
		return State{}, errors.New("no active login session")
	}

	code = strings.TrimSpace(code)
	if code == "" {
		return State{}, errors.New("authorization code is required")
	}

	sess.mu.Lock()
	stdin := sess.stdin
	sess.mu.Unlock()
	if stdin == nil {
		return State{}, errors.New("login session is no longer accepting input")
	}

	if _, err := io.WriteString(stdin, code+"\n"); err != nil {
		return State{}, fmt.Errorf("write code to claude CLI: %w", err)
	}
	// Close stdin so the CLI knows no more input is coming and proceeds
	// with the PKCE token exchange immediately. Without EOF the CLI may
	// loop waiting for a retry code instead of exchanging the current one.
	_ = stdin.Close()

	// Don't hold m.mu while waiting — let other handlers read status.
	select {
	case <-sess.done:
	case <-time.After(30 * time.Second):
		sess.kill("timed out waiting for login to complete")
		<-sess.done
	}

	snap := sess.Snapshot()

	m.mu.Lock()
	if m.sessions[key] == sess {
		delete(m.sessions, key)
	}
	m.mu.Unlock()

	return snap, nil
}

// Cancel kills one identity's login session (if any) and clears the manager's
// reference so a fresh Start can begin. Other identities are unaffected.
func (m *Manager) Cancel(key string) {
	m.mu.Lock()
	sess := m.sessions[key]
	delete(m.sessions, key)
	m.mu.Unlock()
	if sess != nil {
		sess.kill("cancelled by user")
		<-sess.done
	}
}

// Snapshot returns one identity's session state, or an inactive zero State if
// that identity has no session in flight.
func (m *Manager) Snapshot(key string) State {
	m.mu.Lock()
	sess := m.sessions[key]
	m.mu.Unlock()
	if sess == nil {
		return State{Active: false}
	}
	return sess.Snapshot()
}

// Shutdown kills every in-flight login session. Called when the hub is
// stopping so parked `claude auth login` children do not outlive it.
func (m *Manager) Shutdown() {
	m.mu.Lock()
	sessions := make([]*Session, 0, len(m.sessions))
	for k, sess := range m.sessions {
		sessions = append(sessions, sess)
		delete(m.sessions, k)
	}
	m.mu.Unlock()
	for _, sess := range sessions {
		sess.kill("hub shutting down")
		<-sess.done
	}
}

func (s *Session) kill(reason string) {
	s.mu.Lock()
	cmd := s.cmd
	stdin := s.stdin
	s.mu.Unlock()
	if stdin != nil {
		_ = stdin.Close()
	}
	if cmd != nil && cmd.Process != nil {
		_ = cmd.Process.Kill()
	}
	_ = reason // retained for callers/grep; not surfaced separately.
}

func contextWithTimeoutIfNone(parent context.Context, d time.Duration) (context.Context, context.CancelFunc) {
	if _, ok := parent.Deadline(); ok {
		return parent, nil
	}
	return context.WithTimeout(parent, d)
}

// bufferedReader accumulates CLI output into a bounded buffer and exposes a
// helper that blocks until the OAuth URL line appears (or a deadline fires).
type bufferedReader struct {
	mu     sync.Mutex
	buf    strings.Builder
	url    string
	urlCh  chan struct{}
	closed bool
}

func newBufferedReader() *bufferedReader {
	return &bufferedReader{urlCh: make(chan struct{})}
}

const maxBufferedBytes = 16 << 10 // 16 KiB is more than enough for the prompt + URL.

func (b *bufferedReader) consume(r io.ReadCloser) {
	defer r.Close()
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 4096), 1<<20)
	for sc.Scan() {
		line := sc.Text()
		b.append(line + "\n")
		if url := extractOAuthURL(line); url != "" {
			b.mu.Lock()
			if b.url == "" {
				b.url = url
				close(b.urlCh)
			}
			b.mu.Unlock()
		}
	}
}

func (b *bufferedReader) append(s string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	remaining := maxBufferedBytes - b.buf.Len()
	if remaining <= 0 {
		return
	}
	if len(s) > remaining {
		s = s[:remaining]
	}
	b.buf.WriteString(s)
}

func (b *bufferedReader) snapshot() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func (b *bufferedReader) waitForURL(d time.Duration) string {
	select {
	case <-b.urlCh:
		b.mu.Lock()
		url := b.url
		b.mu.Unlock()
		return url
	case <-time.After(d):
		b.mu.Lock()
		url := b.url
		b.mu.Unlock()
		return url
	}
}

// extractOAuthURL pulls the first https:// URL on a line that also matches the
// OAuth-flow shape (claude.com/cai/oauth/authorize, console.anthropic.com OAuth,
// or any URL the CLI prints right after "visit:"). Keeping the matcher
// permissive avoids brittleness when the CLI tweaks its hostnames.
func extractOAuthURL(line string) string {
	idx := strings.Index(line, "https://")
	if idx < 0 {
		return ""
	}
	rest := line[idx:]
	// URL ends at the first whitespace.
	if cut := strings.IndexAny(rest, " \t\r\n"); cut >= 0 {
		rest = rest[:cut]
	}
	if !looksLikeOAuthURL(rest) {
		// Still return it: the CLI might evolve, and showing any printed URL
		// is better than failing silently. The only thing we want to filter
		// out is empty strings (handled above).
		return rest
	}
	return rest
}

func looksLikeOAuthURL(u string) bool {
	switch {
	case strings.Contains(u, "claude.com/cai/oauth"):
		return true
	case strings.Contains(u, "console.anthropic.com"):
		return true
	case strings.Contains(u, "oauth"):
		return true
	}
	return false
}
