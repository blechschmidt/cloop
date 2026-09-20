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
	"net/url"
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

	// expectState is the `state` parameter of URL: the value the IdP will hand
	// back alongside the authorization code, and therefore the half of a
	// `code#state` paste that identifies which sign-in attempt the code came
	// from. Empty when the URL carried no state, which makes the check
	// inoperative rather than wrong — see normalizePastedCode.
	expectState string

	mu        sync.Mutex
	cmd       *exec.Cmd
	stdin     io.WriteCloser
	stdoutBuf *bufferedReader
	// pipes are the parent's ends of stdout and stderr. Held only so kill can
	// force the reader goroutines out of a read that will never end on its
	// own — see forcePipeCloseAfter.
	pipes      []io.Closer
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
			// Summarized, not dumped. The full transcript stays in Output for
			// anyone who wants it; Error is what the panel renders on one
			// line, and pasting the URL and the prompt back at the user buries
			// the single sentence that says what went wrong.
			out := strings.TrimSpace(s.output)
			if summary := summarizeLoginFailure(out); summary != "" {
				st.Error = summary
			} else if out != "" {
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
		pipes:     []io.Closer{stdout, stderr},
		done:      make(chan struct{}),
	}

	// Pump stdout and stderr into a single bounded buffer so the snapshot
	// can show the URL line, prompts, and any error text.
	//
	// Tracked, and waited on below before the child is reaped. os/exec closes
	// the parent's ends of these pipes inside Wait as soon as it sees the
	// child exit — "it is thus incorrect to call Wait before all reads from
	// the pipe have completed" — so a Wait racing the readers either steals
	// whatever is still sitting in the kernel buffer or fails their read
	// outright. For this flow the tail is the entire payload: it is the CLI's
	// error text when a login fails, and losing it is why a failed login
	// could report nothing actionable.
	var readers sync.WaitGroup
	readers.Add(2)
	go func() { defer readers.Done(); sess.stdoutBuf.consume(stdout) }()
	go func() { defer readers.Done(); sess.stdoutBuf.consume(stderr) }()

	// Wait for either the URL to appear or the process to exit. Bound the
	// wait so a wedged or unauthenticated child can't pin the handler.
	urlCh := make(chan string, 1)
	go func() {
		urlCh <- sess.stdoutBuf.waitForURL(15 * time.Second)
	}()

	go func() {
		// Both readers at EOF first, then reap, then snapshot. The buffer is
		// only complete once the goroutines filling it have stopped, so
		// snapshotting beside a live reader would truncate the output even if
		// Wait had not already closed the pipe under it.
		readers.Wait()
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
		sess.expectState = oauthStateFromURL(url)
		sess.mu.Unlock()
		if url == "" {
			// No URL within the timeout window — either the CLI errored out
			// immediately or it's emitting something we don't recognise.
			sess.kill("no OAuth URL emitted within timeout")
			// Wait for the readers to finish before reading their buffer:
			// this error message is the only account of why the login failed,
			// and snapshotting beside a live reader reports half of it.
			// Bounded by kill's own pipe-close backstop.
			<-sess.done
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

	// Validated before anything is written, and without disturbing the
	// session: a rejected paste leaves the flow exactly as it was, so the user
	// can correct it against the link still on screen. Consuming the session
	// here would force them to restart — which mints a new challenge and makes
	// the code they are holding genuinely unusable.
	sess.mu.Lock()
	expect := sess.expectState
	stdin := sess.stdin
	sess.mu.Unlock()

	line, err := normalizePastedCode(code, expect)
	if err != nil {
		return State{}, err
	}

	if stdin == nil {
		return State{}, errors.New("login session is no longer accepting input")
	}

	if _, err := io.WriteString(stdin, line+"\n"); err != nil {
		return State{}, fmt.Errorf("write code to claude CLI: %w", err)
	}
	// Close stdin because this session will never be written to again — the
	// manager drops it below, so one Start is one code.
	//
	// Not, as this comment claimed until Task 20321, because the CLI needs EOF
	// to proceed: the exchange is driven by readline's "line" event, which
	// fires on the newline above. Measured against the real CLI (v2.1.181), a
	// login handed EOF and nothing else hangs until it is killed, so EOF
	// triggers nothing. What EOF does do is make the CLI's own "Invalid code"
	// re-prompt unreachable, which is why the paste is normalized above rather
	// than left for the CLI to reject.
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

// summarizeLoginFailure reduces a failed login's captured transcript to the
// lines that say why it failed, and translates the CLI's HTTP-level phrasing
// into something a user can act on.
//
// The transcript is mostly noise for this purpose: three of its four lines are
// the banner, the authorize URL and the paste prompt, all of which the panel is
// already showing. Rendering the lot is how a 400 reached the user as a
// paragraph beginning "Opening browser to sign in…".
//
// Returns "" when nothing recognisable is found, leaving the caller to fall
// back to the full text rather than to silence.
func summarizeLoginFailure(output string) string {
	var keep []string
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		switch {
		case line == "":
		case strings.HasPrefix(line, "Login failed:"):
			keep = append(keep, translateLoginFailure(line))
		case strings.HasPrefix(line, "Invalid code"):
			keep = append(keep, line)
		case strings.HasPrefix(line, "OAuth login failed"):
			keep = append(keep, line)
		}
	}
	return strings.Join(keep, " ")
}

// translateLoginFailure rewrites the CLI's axios-level message for the one
// status that has a specific, actionable cause in this flow.
//
// "Request failed with status code 400" is what the token endpoint returns
// when the code cannot be redeemed against the verifier being offered: it was
// already used, it expired, or it was minted for a different sign-in attempt.
// The first two are recoverable by retrying; the third is what
// normalizePastedCode now catches up front, so reaching here means the state
// matched and the code itself was refused.
func translateLoginFailure(line string) string {
	if !strings.Contains(line, "status code 400") {
		return line
	}
	return line + " — the authorization code was refused. A code can be used once and expires quickly, " +
		"so this usually means it was already submitted or too much time passed. Start the sign-in again and paste a fresh code."
}

// ErrCodeFromAnotherLogin reports a paste whose `state` belongs to a different
// sign-in attempt than the session that would receive it. Exchanging it is
// guaranteed to fail, because the PKCE verifier that would be sent with it
// belongs to this session and the code was minted against another one's
// challenge.
//
// This is the whole reason the check exists: the CLI cannot make it. Its
// readline handler splits the paste into `authorizationCode` and `state` and
// then calls handleManualAuthCodeInput, which uses only the code and discards
// the state — so a stale code is exchanged against the live session's verifier
// and the token endpoint answers 400. The CLI surfaces that verbatim as
// "Login failed: Request failed with status code 400", which names neither the
// cause nor a remedy. The hub is the only layer holding both states at once.
var ErrCodeFromAnotherLogin = errors.New(
	"this authorization code is from a different sign-in attempt: the sign-in was restarted after that link was opened, " +
		"which replaced the one-time code it was issued for. Open the link shown above again, authorize, and paste the new code")

// ErrCodeMalformed reports a paste that is not an authorization code at all.
var ErrCodeMalformed = errors.New("that does not look like an authorization code")

// oauthStateFromURL returns the `state` query parameter of an OAuth authorize
// URL, or "" if the URL is unparseable or carries no state.
func oauthStateFromURL(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(u.Query().Get("state"))
}

// normalizePastedCode turns whatever a human pasted into the exact line the
// Claude CLI's readline handler expects — `code#state` — or explains why it
// cannot.
//
// It accepts three shapes, because all three are things people actually paste:
//
//	code#state   the canonical form the callback page displays
//	code         just the code, with the state half left behind
//	https://platform.claude.com/oauth/code/callback?code=…&state=…
//	             the whole callback URL, straight from the address bar
//
// expectState is the session's own state, from its authorize URL. When it is
// empty the URL carried no state and there is nothing to compare against, so
// the paste is forwarded untouched: an inoperative check must not become a
// wrong one, and a CLI that stops emitting state must not become a CLI nobody
// can log in with.
//
// A bare code is repaired rather than refused. The CLI discards the pasted
// state anyway, so `code#expectState` is byte-for-byte what a correct paste
// would have reduced to — and refusing it would strand the user, because the
// CLI's own "Invalid code" re-prompt is unreachable through this pipe: it
// `return`s to a readline that SubmitCode has already closed.
func normalizePastedCode(paste, expectState string) (string, error) {
	paste = strings.TrimSpace(paste)
	paste = strings.Trim(paste, "\"'")
	paste = strings.TrimSpace(paste)
	if paste == "" {
		return "", errors.New("authorization code is required")
	}

	code, state := paste, ""
	if strings.HasPrefix(paste, "http://") || strings.HasPrefix(paste, "https://") {
		u, err := url.Parse(paste)
		if err != nil {
			return "", ErrCodeMalformed
		}
		q := u.Query()
		code, state = strings.TrimSpace(q.Get("code")), strings.TrimSpace(q.Get("state"))
		// The authorize link is itself ?code=true&state=… — "code" there is
		// the flag selecting manual-paste mode, not an authorization code, and
		// it carries the very state we are about to compare against. Taken at
		// face value it parses into a plausible-looking "true#<state>" that
		// passes every later check and fails only at the token endpoint, as a
		// 400. Recognise the link by its path and say so.
		if strings.Contains(u.Path, "/authorize") || code == "" || code == "true" {
			return "", fmt.Errorf("%w: that is the sign-in link, not the code it leads to. Open it, authorize, then paste the code shown on the page you land on", ErrCodeMalformed)
		}
	} else if before, after, found := strings.Cut(paste, "#"); found {
		code, state = strings.TrimSpace(before), strings.TrimSpace(after)
	}

	// stdin here is line-oriented: the CLI reads one line and splits it on
	// "#". An embedded newline would be read as a second, attacker-chosen
	// line, so it is rejected rather than trimmed.
	if code == "" || strings.ContainsAny(code, "\n\r \t") {
		return "", ErrCodeMalformed
	}
	if strings.ContainsAny(state, "\n\r \t") {
		return "", ErrCodeMalformed
	}

	// No state to compare against: hand over the parsed form rather than the
	// raw paste, so a callback URL is still unpacked into what the CLI reads.
	// A bare code stays bare here — with no state of our own there is nothing
	// to repair it with, and the CLI's own complaint is the better answer.
	if expectState == "" {
		if state == "" {
			return code, nil
		}
		return code + "#" + state, nil
	}
	if state != "" && state != expectState {
		return "", ErrCodeFromAnotherLogin
	}
	return code + "#" + expectState, nil
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
	// Reaping now waits for the readers, so something still holding the write
	// end of stdout would keep them — and therefore every caller blocked on
	// s.done — waiting indefinitely. A grandchild that inherited the
	// descriptors is the way that happens; pkg/executor/gitprovision.BoundChild
	// exists because git does exactly this.
	go s.forcePipeCloseAfter(pipeDrainGrace)
	_ = reason // retained for callers/grep; not surfaced separately.
}

// pipeDrainGrace is how long a killed session's readers get to reach EOF on
// their own before their pipes are closed out from under them.
//
// Deliberately not zero. A killed child normally closes its descriptors on the
// way out and the readers drain within microseconds, so cutting them off
// immediately would throw away the very error text the caller killed the
// session to read. This only ever elapses when the ordinary path has already
// failed.
//
// A var so the test that exercises the backstop need not spend five seconds
// doing it; nothing outside that test assigns to it.
var pipeDrainGrace = 5 * time.Second

// forcePipeCloseAfter closes the parent's ends of stdout and stderr if the
// session has not finished within d, unblocking readers that will never see
// EOF. Closing a *os.File unblocks a read already in flight, which is the
// whole point: the goroutines are parked in read(2), not waiting on a channel.
func (s *Session) forcePipeCloseAfter(d time.Duration) {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-s.done:
	case <-t.C:
		s.mu.Lock()
		pipes := s.pipes
		s.mu.Unlock()
		for _, p := range pipes {
			_ = p.Close()
		}
	}
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
