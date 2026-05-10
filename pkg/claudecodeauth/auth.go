// Package claudecodeauth wraps the `claude auth` subcommand so the Web UI can
// drive Claude Code login/logout/status from the browser. The login flow is
// inherently interactive: `claude auth login` prints a one-shot OAuth URL and
// then blocks on stdin reading a paste-back authorization code. We model that
// as a server-side session: Start spawns the CLI, captures the URL, and keeps
// the process handle; SubmitCode writes the code to stdin and waits for the
// process to exit; Cancel/Stop kills it.
//
// Only one in-flight login session is supported at a time per process. That
// matches the single-user assumption of the local dashboard and avoids leaking
// processes if the operator opens multiple browser tabs.
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
func FetchStatus(ctx context.Context) (*Status, error) {
	if _, cancel := contextWithTimeoutIfNone(ctx, 10*time.Second); cancel != nil {
		defer cancel()
	}
	cmd := exec.CommandContext(ctx, findClaude(), "auth", "status", "--json")
	out, err := cmd.Output()
	if err != nil {
		// Surface stderr so a missing CLI or a version that doesn't know the
		// status subcommand is debuggable from the UI.
		var stderr string
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			stderr = strings.TrimSpace(string(exitErr.Stderr))
		}
		if stderr != "" {
			return nil, fmt.Errorf("claude auth status: %w: %s", err, stderr)
		}
		return nil, fmt.Errorf("claude auth status: %w", err)
	}
	var s Status
	if err := json.Unmarshal(out, &s); err != nil {
		return nil, fmt.Errorf("parse claude auth status output: %w", err)
	}
	return &s, nil
}

// Logout invokes `claude auth logout`. The CLI is non-interactive in this path
// so a 10-second timeout is sufficient.
func Logout(ctx context.Context) error {
	ctx, cancel := contextWithTimeoutIfNone(ctx, 10*time.Second)
	if cancel != nil {
		defer cancel()
	}
	cmd := exec.CommandContext(ctx, findClaude(), "auth", "logout")
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

	mu        sync.Mutex
	cmd       *exec.Cmd
	stdin     io.WriteCloser
	stdoutBuf *bufferedReader
	done      chan struct{}
	exitErr   error
	output    string
	closed    bool
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
			st.Error = s.exitErr.Error()
		} else {
			st.Success = true
		}
	default:
	}
	return st
}

// Manager owns the single in-flight login session per process. Methods are
// safe for concurrent use by multiple HTTP handlers.
type Manager struct {
	mu      sync.Mutex
	session *Session
}

// NewManager returns a fresh login session manager.
func NewManager() *Manager { return &Manager{} }

// Start spawns `claude auth login` and waits for it to emit the OAuth URL,
// returning a Session that the caller can later complete by passing the
// authorization code to SubmitCode. If another session is already active it
// is killed first so the new flow can take over.
func (m *Manager) Start(ctx context.Context, opts LoginOptions) (*Session, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Replace any existing session — the previous browser tab presumably
	// timed out or the user restarted the flow.
	if m.session != nil {
		m.session.kill("superseded by new login attempt")
		m.session = nil
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
	cmd.Env = append(os.Environ(), "IS_SANDBOX=1")

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

	m.session = sess
	return sess, nil
}

// SubmitCode pipes the OAuth authorization code to the running login session
// and waits up to 30 seconds for the CLI to exit. On success the session is
// cleared. The returned State describes the final outcome regardless of
// whether the CLI exited cleanly.
func (m *Manager) SubmitCode(code string) (State, error) {
	m.mu.Lock()
	sess := m.session
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

	// Don't hold m.mu while waiting — let other handlers read status.
	select {
	case <-sess.done:
	case <-time.After(30 * time.Second):
		sess.kill("timed out waiting for login to complete")
		<-sess.done
	}

	snap := sess.Snapshot()

	m.mu.Lock()
	if m.session == sess {
		m.session = nil
	}
	m.mu.Unlock()

	return snap, nil
}

// Cancel kills the current login session (if any) and clears the manager's
// reference so a fresh Start can begin.
func (m *Manager) Cancel() {
	m.mu.Lock()
	sess := m.session
	m.session = nil
	m.mu.Unlock()
	if sess != nil {
		sess.kill("cancelled by user")
		<-sess.done
	}
}

// Snapshot returns the current session's state, or an inactive zero State if
// no session is in flight.
func (m *Manager) Snapshot() State {
	m.mu.Lock()
	sess := m.session
	m.mu.Unlock()
	if sess == nil {
		return State{Active: false}
	}
	return sess.Snapshot()
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
