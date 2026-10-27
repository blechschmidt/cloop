// Package copilot runs the GitHub Copilot CLI (`copilot`) as a provider.
//
// Like claudecode it drives an agent harness rather than calling a model: the
// CLI works in the project directory with tools of its own — a shell, file
// edits, search — and cloop reads its answer off stdout. It runs in prompt mode
// (the prompt arrives on stdin, so no argument-length limit applies and the
// task never appears in a process listing), once per call, under the sign-in
// the CLI already has: `copilot login`, a token in COPILOT_GITHUB_TOKEN,
// GH_TOKEN or GITHUB_TOKEN — in that order — or the GitHub CLI's, and with
// COPILOT_PROVIDER_BASE_URL set, a model provider of the operator's own (BYOK).
//
// The flags were taken from Copilot CLI 1.0.103's own help and each behaviour
// this package depends on was checked against that binary: see
// copilot_cli_test.go, which runs the real CLI against a stub model server when
// one is installed.
package copilot

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/google/uuid"

	"github.com/blechschmidt/cloop/pkg/provider"
	"github.com/blechschmidt/cloop/pkg/provider/agentproc"
)

const (
	// ProviderName is the name config.yaml, --provider and the dashboard use.
	ProviderName = "copilot"
	// Binary is the program this provider execs. The dashboard's placement
	// check and a device's harness inventory name it the same way.
	Binary = "copilot"
)

// The variables the CLI authenticates with. COPILOT_GITHUB_TOKEN outranks
// GH_TOKEN and GITHUB_TOKEN, which is what makes it the one to grant a sandbox:
// a repository grant may put a GitHub token without the Copilot permission in
// those two, and this one is still the one the CLI uses.
const (
	EnvGitHubToken     = "COPILOT_GITHUB_TOKEN"
	EnvProviderBaseURL = "COPILOT_PROVIDER_BASE_URL"
)

// ErrAuthFailure marks a CLI run that found no credential, or whose credential
// was refused — the GitHub account has no Copilot access, or a custom
// provider rejected its key. Nothing cloop can retry fixes it.
var ErrAuthFailure = errors.New("copilot CLI is not signed in or its credential was refused")

// BackgroundPolicy governs the work the CLI leaves running after it exits; see
// agentproc. The zero value detects it, waits for it and terminates whatever
// outlives the wait.
type BackgroundPolicy = agentproc.BackgroundPolicy

// Provider runs the Copilot CLI once per Complete.
type Provider struct {
	// Background governs the handling of work the CLI leaves running after it
	// exits. The CLI's shell tool has an async mode, so an agent can leave a
	// build or a training run behind exactly as a claude agent can.
	Background BackgroundPolicy
}

// New builds a provider with the default background policy.
func New() *Provider { return &Provider{} }

// NewWithBackground builds a provider with an explicit policy for work the CLI
// leaves running. Zero-valued fields resolve to agentproc's defaults.
func NewWithBackground(policy BackgroundPolicy) *Provider {
	return &Provider{Background: policy}
}

func (p *Provider) Name() string { return ProviderName }

// DefaultModel is empty: with no model set cloop passes no --model, and the
// CLI's own choice applies — COPILOT_MODEL, the model saved in its settings, or
// its default.
func (p *Provider) DefaultModel() string { return "" }

// FindBinary locates the copilot binary: PATH first, then where its installers
// put it — GitHub's install script at ~/.local/bin for a user and
// /usr/local/bin for root, `npm install -g` under a redirected prefix, and
// Homebrew on Apple silicon — which may not be on the PATH of a dashboard
// started by a service manager.
func FindBinary() string {
	if p, err := exec.LookPath(Binary); err == nil {
		return p
	}
	home, _ := os.UserHomeDir()
	for _, c := range []string{
		filepath.Join(home, ".local", "bin", Binary),
		filepath.Join(home, ".npm-global", "bin", Binary),
		filepath.Join("/usr/local/bin", Binary),
		filepath.Join("/opt/homebrew/bin", Binary),
	} {
		if fi, err := os.Stat(c); err == nil && !fi.IsDir() {
			return c
		}
	}
	return Binary // exec reports it missing, by name
}

// readOnlyTools are the CLI's tools a read-only call may use: they read files
// and search them, and nothing else. An allow-list, so a tool that writes and
// is added to a later CLI is withheld rather than granted by omission.
const readOnlyTools = "view,grep,glob"

// Flags the CLI may not know. Each is dropped for the life of the process once
// a CLI refuses it, so a release that predates one keeps working without it:
// a call loses its usage counts, its resumable session, or its guard against
// the agent stopping to ask a question nobody will answer — not every task.
const (
	flagSessionID = "--session-id"
	flagUsageFile = "--usage-output-file"
	flagNoAskUser = "--no-ask-user"
)

var optionalFlags = []string{flagSessionID, flagUsageFile, flagNoAskUser}

var unsupportedFlags sync.Map // flag name → struct{}

func flagSupported(name string) bool {
	_, refused := unsupportedFlags.Load(name)
	return !refused
}

// session says which conversation a call runs in.
type session struct {
	resume string // an existing session to continue
	id     string // the id to give a new one
}

// buildArgs assembles the CLI's arguments. Every value is passed as
// --flag=value, so a value that begins with "-" — a model name typed into the
// dashboard, say — is read as the value it is and never as another flag.
func buildArgs(opts provider.Options, sess session, usageFile string) []string {
	// Prompt mode with output reduced to the agent's own words, which is what
	// cloop parses TASK_DONE from, and every tool allowed: nobody is there to
	// approve one, as claudecode's bypassPermissions has it.
	args := []string{"--silent", "--allow-all-tools"}
	if opts.ReadOnly {
		// The review gate's reviewer (Task 20357): reading tools only, no
		// built-in MCP servers — the GitHub one can write to GitHub — and
		// the CLI's own path check left on, so it reads the project and not
		// the machine.
		args = append(args, "--available-tools="+readOnlyTools, "--disable-builtin-mcps")
	} else {
		args = append(args, "--allow-all-paths", "--allow-all-urls")
	}
	if flagSupported(flagNoAskUser) {
		args = append(args, flagNoAskUser)
	}
	if m := strings.TrimSpace(opts.Model); m != "" {
		args = append(args, "--model="+m)
	}
	// cloop's effort levels are a subset of the CLI's, so they pass straight
	// through; ValidEffort keeps a corrupted state value from failing every
	// call with an unknown level.
	if opts.Effort != "" && provider.ValidEffort(opts.Effort) {
		args = append(args, "--reasoning-effort="+opts.Effort)
	}
	switch {
	case sess.resume != "":
		args = append(args, "--resume="+sess.resume)
	case sess.id != "":
		args = append(args, flagSessionID+"="+sess.id)
	}
	if usageFile != "" {
		args = append(args, flagUsageFile+"="+usageFile)
	}
	return args
}

// resumableSession returns id when it is a session id this provider could
// have issued — a UUID — and "" otherwise. The CLI's --resume also takes a
// name or an id prefix, and a value from elsewhere must not pick one.
func resumableSession(id string) string {
	id = strings.TrimSpace(id)
	if id == "" {
		return ""
	}
	parsed, err := uuid.Parse(id)
	if err != nil {
		return ""
	}
	return parsed.String()
}

// childEnv is the CLI's environment: this process's, with two defaults it may
// override, and then what the caller adds for this call.
func childEnv(opts provider.Options) []string {
	env := []string{
		// The CLI downloads newer versions of itself by default. A harness
		// should run the version that was installed, not one that arrived
		// mid-run, and a sandbox should not spend its egress on it.
		"COPILOT_AUTO_UPDATE=false",
		// The output is parsed, never shown on a terminal.
		"NO_COLOR=1",
	}
	env = append(env, os.Environ()...)
	// Appended last: exec keeps the last occurrence of a key, and these are
	// meant to win — the review gate's push hold (Task 20357), an outbox.
	return append(env, opts.Env...)
}

// Complete runs the CLI once.
//
// Unlike claudecode there is no retry on an authentication failure. The CLI
// refreshes its own credential and retries rate limits and server errors
// itself before it gives up, so a failure that reaches here is one a second
// attempt would meet again.
func (p *Provider) Complete(ctx context.Context, prompt string, opts provider.Options) (*provider.Result, error) {
	// The CLI takes no system prompt, so one the caller sets leads the
	// message rather than being dropped: the plan assistant's is the plan.
	if sp := strings.TrimSpace(opts.SystemPrompt); sp != "" {
		prompt = sp + "\n\n" + prompt
	}
	sess := session{resume: resumableSession(opts.ResumeSession)}
	for attempt := 0; ; attempt++ {
		if sess.resume == "" && flagSupported(flagSessionID) {
			// Every conversation gets a known id, so a caller can continue it:
			// a task whose agent ended its turn mid-work is handed the turn
			// back in the same conversation (Task 20349).
			sess.id = uuid.NewString()
		} else {
			sess.id = ""
		}
		res, refused, err := p.run(ctx, prompt, opts, sess)
		if refused == "" || attempt >= len(optionalFlags) {
			return res, err
		}
		unsupportedFlags.Store(refused, struct{}{})
	}
}

// run performs one CLI invocation. refused names an optional flag the CLI
// rejected as unknown, in which case the call should be made again without it.
func (p *Provider) run(ctx context.Context, prompt string, opts provider.Options, sess session) (
	res *provider.Result, refused string, err error) {

	if opts.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, opts.Timeout)
		defer cancel()
	}

	usageFile := ""
	if flagSupported(flagUsageFile) {
		usageFile = newUsageFile()
		if usageFile != "" {
			defer os.Remove(usageFile)
		}
	}

	cmd := exec.CommandContext(ctx, FindBinary(), buildArgs(opts, sess, usageFile)...)
	// Its own process group, so cancellation can kill the whole tree and the
	// work it leaves behind can be found once it exits; WaitDelay bounds Wait
	// should a grandchild keep a pipe open past the group kill.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.WaitDelay = 5 * time.Second
	cmd.Env = childEnv(opts)
	if opts.WorkDir != "" {
		cmd.Dir = opts.WorkDir
	}
	cmd.Stdin = strings.NewReader(prompt)
	var stdout bytes.Buffer
	stderr := &cappedBuffer{max: maxStderr}
	cmd.Stdout = io.Writer(&stdout)
	if opts.OnToken != nil {
		// The CLI writes the agent's words as they arrive; passing them on
		// makes a live log of a call that may run for an hour.
		cmd.Stdout = io.MultiWriter(&stdout, tokenWriter(opts.OnToken))
	}
	cmd.Stderr = stderr

	start := time.Now()
	if err := cmd.Start(); err != nil {
		return nil, "", fmt.Errorf("copilot CLI start error: %w", err)
	}
	waitCh := make(chan error, 1)
	go func() { waitCh <- cmd.Wait() }()

	var waitErr error
	var background *provider.BackgroundActivity
	select {
	case waitErr = <-waitCh:
		// Before trusting its output, settle whatever it left running: a
		// "done" from an agent that started its work in the background and
		// exited is a claim about work that has barely begun.
		background = agentproc.Settle(ctx, cmd.Process.Pid, p.Background, opts.OnBackgroundWait)
	case <-ctx.Done():
		if err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL); err != nil {
			_ = cmd.Process.Kill()
		}
		<-waitCh
		return nil, "", fmt.Errorf("copilot CLI cancelled: %w", ctx.Err())
	}
	duration := time.Since(start)

	// A deadline that passed while the CLI was exiting is still a deadline:
	// returning the partial output as an answer would record a truncated
	// step as a successful one.
	if ctxErr := ctx.Err(); ctxErr != nil {
		return nil, "", fmt.Errorf("copilot CLI cancelled: %w", ctxErr)
	}

	output := strings.TrimSpace(stdout.String())
	diag := strings.TrimSpace(stderr.String())
	if waitErr != nil {
		var exitErr *exec.ExitError
		if !errors.As(waitErr, &exitErr) {
			return nil, "", fmt.Errorf("copilot CLI error: %w", waitErr)
		}
		if flag := rejectedFlag(diag); flag != "" {
			return nil, flag, fmt.Errorf("copilot CLI does not know %s", flag)
		}
		return nil, "", cliFailure(exitErr.ExitCode(), diag, output)
	}
	if output == "" && diag != "" {
		// Exit 0 and nothing said: the reason, if there is one, is on stderr,
		// and an empty answer reported as an answer would hide it.
		return nil, "", fmt.Errorf("copilot CLI returned no response: %s", truncateForError(diag))
	}

	res = &provider.Result{
		Output:     output,
		Duration:   duration,
		Provider:   ProviderName,
		Model:      strings.TrimSpace(opts.Model),
		Background: background,
	}
	if sess.resume != "" {
		res.SessionID = sess.resume
	} else {
		res.SessionID = sess.id
	}
	if usageFile != "" {
		if u, ok := readUsage(usageFile); ok {
			res.InputTokens, res.OutputTokens = u.input, u.output
			if u.model != "" {
				res.Model = u.model
			}
		}
	}
	return res, "", nil
}

// rejectedFlagRe matches the CLI's refusal of an argument it does not know:
// "error: unexpected argument '--no-ask-user' found".
var rejectedFlagRe = regexp.MustCompile(`unexpected argument '(--[a-z0-9-]+)`)

// rejectedFlag returns the optional flag the CLI refused as unknown, or "".
// A refusal of any other argument is a real failure and is reported as one.
// Whether another call has already recorded the refusal does not matter: this
// call sent the flag, so it is made again without it either way.
func rejectedFlag(stderr string) string {
	m := rejectedFlagRe.FindStringSubmatch(stderr)
	if m == nil {
		return ""
	}
	for _, f := range optionalFlags {
		if m[1] == f {
			return f
		}
	}
	return ""
}

// authMarkers are what the CLI says when it has no credential or its
// credential is refused (lower-cased).
var authMarkers = []string{
	"no authentication information found",
	"authentication failed",
	"bad credentials",
	"not authorized to use copilot",
	"does not have access to copilot",
	"copilot is not enabled",
	"(http 401)",
	"(http 403)",
}

// cliFailure renders a failed run: the CLI's own diagnostics, with
// ErrAuthFailure on the ones no retry fixes.
func cliFailure(code int, diag, output string) error {
	reason := diag
	if reason == "" {
		reason = output
	}
	lower := strings.ToLower(reason)
	for _, m := range authMarkers {
		if strings.Contains(lower, m) {
			return fmt.Errorf("%w (exit %d): %s — sign the CLI in with `copilot login`, or set %s to a "+
				"fine-grained GitHub token with the Copilot Requests permission", ErrAuthFailure, code,
				truncateForError(reason), EnvGitHubToken)
		}
	}
	return fmt.Errorf("copilot CLI failed (exit %d): %s", code, truncateForError(reason))
}

// truncateForError caps an error's embedded output at a length useful for log
// readability without flooding the state or the terminal.
func truncateForError(s string) string {
	const max = 512
	if len(s) <= max {
		return s
	}
	return s[:max] + "...(truncated)"
}

// maxStderr bounds what is kept of the CLI's stderr: enough for any error it
// prints, while a CLI logging at debug level cannot grow the hub's memory.
const maxStderr = 64 << 10

// cappedBuffer keeps the first max bytes written to it and discards the rest,
// reporting every write as complete so the CLI is never blocked by it.
type cappedBuffer struct {
	buf bytes.Buffer
	max int
}

func (c *cappedBuffer) Write(p []byte) (int, error) {
	if room := c.max - c.buf.Len(); room > 0 {
		if len(p) > room {
			c.buf.Write(p[:room])
		} else {
			c.buf.Write(p)
		}
	}
	return len(p), nil
}

func (c *cappedBuffer) String() string { return c.buf.String() }

// tokenWriter passes what the CLI writes to stdout on to an OnToken callback.
type tokenWriter func(string)

func (w tokenWriter) Write(p []byte) (int, error) {
	w(string(p))
	return len(p), nil
}

// newUsageFile reserves a path for the CLI's usage report, or returns "" when
// none can be made — the call then runs without token counts.
func newUsageFile() string {
	f, err := os.CreateTemp("", "cloop-copilot-usage-*.json")
	if err != nil {
		return ""
	}
	name := f.Name()
	_ = f.Close()
	return name
}

// usage is what a call cost, as the CLI reports it.
type usage struct {
	input, output int
	model         string
}

// usageReport is the part of --usage-output-file's report this package reads.
type usageReport struct {
	CurrentModel string `json:"currentModel"`
	ModelMetrics map[string]struct {
		Usage struct {
			InputTokens  int `json:"inputTokens"`
			OutputTokens int `json:"outputTokens"`
		} `json:"usage"`
	} `json:"modelMetrics"`
}

// maxUsageReport bounds the report read back. It lists the files the session
// changed, which is the only part that grows; the counts read are at its top.
const maxUsageReport = 4 << 20

// readUsage reads the CLI's usage report, summed over every model the session
// used. ok is false when there is none to read: a CLI that wrote none, or one
// that wrote something else.
func readUsage(path string) (usage, bool) {
	f, err := os.Open(path)
	if err != nil {
		return usage{}, false
	}
	defer f.Close()
	var rep usageReport
	if err := json.NewDecoder(io.LimitReader(f, maxUsageReport)).Decode(&rep); err != nil {
		return usage{}, false
	}
	var u usage
	for _, m := range rep.ModelMetrics {
		u.input += m.Usage.InputTokens
		u.output += m.Usage.OutputTokens
	}
	u.model = strings.TrimSpace(rep.CurrentModel)
	return u, true
}
