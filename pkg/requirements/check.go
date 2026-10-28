package requirements

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/blechschmidt/cloop/pkg/redact"
	"github.com/blechschmidt/cloop/pkg/rootkey"
)

// Options say where and how Check runs.
type Options struct {
	// Dir is the project's root, where every test runs. Empty is the
	// current directory.
	Dir string
	// Env is the environment the tests start from; nil is this process's.
	// The hub's root key never reaches a test (see testEnv).
	Env []string
	// Assess answers for a requirement with no tests. Nil leaves such a
	// requirement unverified.
	Assess func(ctx context.Context, r Requirement) (Assessment, error)
	// OnResult is told each result as it is made, for a caller printing
	// progress.
	OnResult func(Result)
	// Now is the clock; nil is time.Now.
	Now func() time.Time
}

// hubSecretEnv names the variables that hold the hub's own root of trust. A
// test never needs them, and on a hub that runs its projects on its own host
// (executors.allow_host_process) the workload's environment is the hub's: a
// test that printed one would put it in a report every project reader sees.
var hubSecretEnv = []string{
	rootkey.EnvKey, rootkey.EnvKeyFile, rootkey.EnvPrevious, rootkey.EnvPreviousFile,
	rootkey.EnvCredentialsDirectory,
}

// waitDelay bounds how long a test's exit waits for output pipes held open by
// something it left behind. Its whole process group is killed first, so this
// is only a backstop for a process that left the group.
const waitDelay = 5 * time.Second

// Check checks each requirement in turn: a tested one by running its tests,
// in order, in opts.Dir; an untested one through opts.Assess, or not at all.
// A context that ends stops the check: the test running is killed, and what
// was not reached is reported as an error, not as unfulfilled.
func Check(ctx context.Context, reqs []Requirement, opts Options) []Result {
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	env, scrub := testEnv(opts.Env)
	results := make([]Result, 0, len(reqs))
	for _, req := range reqs {
		r := checkOne(ctx, req, opts, env, scrub, now)
		results = append(results, r)
		if opts.OnResult != nil {
			opts.OnResult(r)
		}
	}
	return results
}

func checkOne(ctx context.Context, req Requirement, opts Options, env []string, scrub func(string) string, now func() time.Time) (res Result) {
	start := now()
	res = Result{RequirementID: req.ID, Fingerprint: req.Fingerprint(), StartedAt: start.UTC()}
	defer func() { res.DurationMS = now().Sub(start).Milliseconds() }()
	if ctx.Err() != nil {
		res.Method, res.Verdict, res.Summary = methodFor(req), VerdictError, "the check was stopped before it reached this requirement"
		return res
	}
	if req.Tested() {
		res.Method = MethodTests
		reqEnv := append(env[:len(env):len(env)],
			"CLOOP_REQUIREMENT_ID="+strconv.Itoa(req.ID), "CLOOP_REQUIREMENT="+Key(req.ID))
		for _, t := range req.Tests {
			res.Tests = append(res.Tests, runTest(ctx, opts.Dir, reqEnv, t, scrub))
		}
		res.Verdict, res.Summary = TestsVerdict(res.Tests)
		return res
	}
	if opts.Assess == nil {
		res.Method, res.Verdict, res.Summary = MethodNone, VerdictUnverified, "no tests, and the model was not asked"
		return res
	}
	res.Method = MethodAI
	a, err := opts.Assess(ctx, req)
	if err != nil {
		res.Verdict, res.Summary = VerdictError, truncateRunes("the model could not assess it: "+scrub(oneLine(err.Error())), MaxSummaryRunes)
		return res
	}
	res.Verdict, res.Summary, res.Evidence = a.verdict(), truncateRunes(scrub(oneLine(a.Rationale)), MaxRationaleRunes), nil
	for _, e := range a.Evidence {
		if e = truncateRunes(scrub(oneLine(e)), MaxEvidenceRunes); e != "" && len(res.Evidence) < MaxEvidence {
			res.Evidence = append(res.Evidence, e)
		}
	}
	return res
}

// testEnv is the environment the tests start from, and the scrubber for what
// they print: the credentials a lease gave the workload (redact.FromEnviron),
// the hub's root key wherever it was found, and anything shaped like a
// credential (redact.Scrub).
func testEnv(base []string) ([]string, func(string) string) {
	if base == nil {
		base = os.Environ()
	}
	env := make([]string, 0, len(base)+2)
	var hidden []string
	for _, kv := range base {
		name, value, _ := strings.Cut(kv, "=")
		if isHubSecret(name) {
			if len(value) >= 8 {
				hidden = append(hidden, value)
			}
			continue
		}
		env = append(env, kv)
	}
	leased := redact.FromEnviron(base)
	extra := redact.New(hidden...)
	return env, func(s string) string { return redact.Scrub(extra.String(leased.String(s))) }
}

func isHubSecret(name string) bool {
	for _, n := range hubSecretEnv {
		if name == n {
			return true
		}
	}
	return false
}

// runTest runs one test in its own process group, which is killed when the
// test ends however it ends: a test cannot leave work running behind it in a
// long-lived executor, nor hold the check open past its timeout through a
// child that kept its output pipe.
func runTest(ctx context.Context, dir string, env []string, t Test, scrub func(string) string) TestResult {
	res := TestResult{Name: t.Name, Command: t.Command}
	timeout := t.Timeout()
	tctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	out := &tailBuffer{max: MaxOutputBytes}
	cmd := exec.CommandContext(tctx, "/bin/sh", "-c", t.Command)
	cmd.Dir = dir
	cmd.Env = env
	cmd.Stdout, cmd.Stderr = out, out
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return os.ErrProcessDone
		}
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		return os.ErrProcessDone
	}
	cmd.WaitDelay = waitDelay

	start := time.Now()
	err := cmd.Start()
	if err == nil {
		err = cmd.Wait()
		// Whatever the test left in its group goes with it.
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
	res.DurationMS = time.Since(start).Milliseconds()
	res.Output, res.Truncated = out.String()
	res.Output = scrub(res.Output)

	var exitErr *exec.ExitError
	switch {
	case err == nil:
		res.Outcome = OutcomePass
	case errors.Is(err, exec.ErrWaitDelay):
		// It exited 0 and left something holding its output open, which went
		// with its process group.
		res.Outcome = OutcomePass
		res.Output += "\n[cloop: the test left a process running; it was stopped]"
	case errors.Is(tctx.Err(), context.DeadlineExceeded) && ctx.Err() == nil:
		res.Outcome, res.ExitCode = OutcomeTimeout, -1
		res.Error = "timed out after " + timeout.String()
	case ctx.Err() != nil:
		res.Outcome, res.ExitCode = OutcomeError, -1
		res.Error = "the check was stopped"
	case errors.As(err, &exitErr) && exitErr.ExitCode() > 0:
		res.Outcome, res.ExitCode = OutcomeFail, exitErr.ExitCode()
	case errors.As(err, &exitErr):
		// Killed by a signal: 128 plus the signal, as a shell reports it.
		res.Outcome, res.ExitCode = OutcomeFail, 128
		if ws, ok := exitErr.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
			res.ExitCode = 128 + int(ws.Signal())
			res.Error = "killed by " + ws.Signal().String()
		}
	default:
		res.Outcome, res.ExitCode = OutcomeError, -1
		res.Error = truncateRunes(scrub(oneLine(err.Error())), MaxSummaryRunes)
	}
	return res
}

// tailBuffer keeps the last max bytes written to it.
type tailBuffer struct {
	mu        sync.Mutex
	max       int
	buf       []byte
	truncated bool
}

func (b *tailBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	n := len(p)
	if len(p) >= b.max {
		b.buf = append(b.buf[:0], p[len(p)-b.max:]...)
		b.truncated = true
		return n, nil
	}
	if over := len(b.buf) + len(p) - b.max; over > 0 {
		b.buf = append(b.buf[:0], b.buf[over:]...)
		b.truncated = true
	}
	b.buf = append(b.buf, p...)
	return n, nil
}

// String is what was kept, cut to whole runes, and whether it is the end only.
func (b *tailBuffer) String() (string, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	s := string(b.buf)
	if b.truncated {
		s = strings.ToValidUTF8(s, "")
	} else {
		s = strings.ToValidUTF8(s, "�")
	}
	return s, b.truncated
}

// WorkTree reports HEAD of the git checkout at dir and whether it has
// uncommitted changes, or nothing when dir is not one (or git is missing).
// Changes under .cloop/ are cloop's own bookkeeping and do not count.
func WorkTree(ctx context.Context, dir string) (commit string, dirty bool) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	git := func(args ...string) (string, error) {
		cmd := exec.CommandContext(ctx, "git", args...)
		cmd.Dir = dir
		cmd.Env = append(os.Environ(), "GIT_OPTIONAL_LOCKS=0", "GIT_TERMINAL_PROMPT=0")
		var stdout bytes.Buffer
		cmd.Stdout = &stdout
		err := cmd.Run()
		return stdout.String(), err
	}
	head, err := git("rev-parse", "--verify", "HEAD")
	if err != nil {
		return "", false
	}
	status, err := git("status", "--porcelain", "--untracked-files=normal", "--", ".", ":(exclude).cloop")
	return cleanCommit(head), err == nil && strings.TrimSpace(status) != ""
}

// Describe is a one-line account of r, for a terminal.
func Describe(r Result) string {
	return fmt.Sprintf("%-5s %-11s %s", Key(r.RequirementID), r.Verdict, r.Summary)
}
