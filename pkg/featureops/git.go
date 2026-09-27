// Package featureops performs the operations on features that need git or the
// network: creating a feature's worktree, removing it, and publishing it as a
// pull request (Task 20341). The model — layout, records, discovery — is in
// pkg/feature, which runs nothing and is what the dashboard reads.
//
// Every function here is called from the `cloop feature` CLI, which the hub
// dispatches through the project's executor rather than running itself. So
// the git that runs is the git of wherever the project runs: the hub host for a
// local project, the sandbox for an isolated one — with that sandbox's
// credentials and nothing else.
package featureops

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// gitTimeout bounds one git invocation that touches only the local
// repository. Network operations (push) take their own, longer bound.
const gitTimeout = 2 * time.Minute

// pushTimeout bounds a push. A feature branch is usually small, but the first
// push of a long-lived one can carry a lot of history over a slow link.
const pushTimeout = 5 * time.Minute

// gitError is a failed git invocation, carrying git's own words.
type gitError struct {
	args   []string
	code   int
	stderr string
	err    error
}

func (e *gitError) Error() string {
	msg := strings.TrimSpace(e.stderr)
	if msg == "" {
		msg = e.err.Error()
	}
	return fmt.Sprintf("git %s: %s", strings.Join(redactArgs(e.args), " "), msg)
}

func (e *gitError) Unwrap() error { return e.err }

// exitCode returns git's exit status for a failed invocation, or -1.
func exitCode(err error) int {
	var ge *gitError
	if errors.As(err, &ge) {
		return ge.code
	}
	return -1
}

// redactArgs hides the value of any -c key=value pair that could carry a
// credential, so an error message can be shown to a user or logged.
func redactArgs(args []string) []string {
	out := make([]string, len(args))
	copy(out, args)
	for i := 0; i+1 < len(out); i++ {
		if out[i] == "-c" && strings.Contains(strings.ToLower(out[i+1]), "header") {
			k, _, _ := strings.Cut(out[i+1], "=")
			out[i+1] = k + "=<redacted>"
		}
	}
	return out
}

// gitEnv is the environment every git invocation here runs with.
//
// Prompts are disabled outright: these commands run inside an HTTP request
// on the hub or in a sandbox, where a credential prompt is not a question
// anybody can answer — it is a hang until the timeout. LC_ALL=C keeps git's
// messages in the language the error handling below expects.
func gitEnv(extra ...string) []string {
	env := append(os.Environ(),
		"GIT_TERMINAL_PROMPT=0",
		"GCM_INTERACTIVE=never",
		"LC_ALL=C",
	)
	return append(env, extra...)
}

// runGit runs git in dir and returns its trimmed stdout.
func runGit(ctx context.Context, dir string, args ...string) (string, error) {
	return runGitEnv(ctx, dir, nil, args...)
}

// runGitEnv is runGit with additional environment entries.
func runGitEnv(ctx context.Context, dir string, extraEnv []string, args ...string) (string, error) {
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, gitTimeout)
		defer cancel()
	}
	cmd := exec.CommandContext(ctx, "git", args...)
	cmd.Dir = dir
	cmd.Env = gitEnv(extraEnv...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		code := -1
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			code = ee.ExitCode()
		}
		if ctx.Err() != nil {
			err = fmt.Errorf("%w (%v)", ctx.Err(), err)
		}
		return strings.TrimSpace(stdout.String()), &gitError{args: args, code: code, stderr: stderr.String(), err: err}
	}
	return strings.TrimSpace(stdout.String()), nil
}

// refExists reports whether a fully qualified ref resolves to a commit.
func refExists(ctx context.Context, dir, ref string) bool {
	_, err := runGit(ctx, dir, "rev-parse", "--verify", "--quiet", ref+"^{commit}")
	return err == nil
}

// validBranchName asks git whether name is an acceptable branch name. It is
// the authority — hand-rolled rules drift from git's — and it also refuses a
// leading dash, which is what keeps a name from being read as an option.
func validBranchName(ctx context.Context, dir, name string) error {
	if name == "" {
		return errors.New("branch name is empty")
	}
	if strings.HasPrefix(name, "-") {
		return fmt.Errorf("branch name %q may not start with a dash", name)
	}
	if _, err := runGit(ctx, dir, "check-ref-format", "--branch", name); err != nil {
		return fmt.Errorf("%q is not a valid branch name", name)
	}
	return nil
}

// resolveBase finds the ref a feature based on branch should start from: the
// local branch when there is one, otherwise the remote-tracking branch on
// origin. It returns the ref in the form git accepts as a start point.
func resolveBase(ctx context.Context, dir, branch string) (string, error) {
	if refExists(ctx, dir, "refs/heads/"+branch) {
		return "refs/heads/" + branch, nil
	}
	if refExists(ctx, dir, "refs/remotes/origin/"+branch) {
		return "refs/remotes/origin/" + branch, nil
	}
	return "", fmt.Errorf("base branch %q exists neither locally nor as origin/%s", branch, branch)
}

// DefaultBase picks the branch a new feature is cut from and its pull request
// targets when the caller names none: the remote's default branch, then main,
// then master, then whatever the project has checked out.
//
// The remote's default comes first because the pull request is opened against
// the forge, and the forge's idea of "main" is the one that matters there. A
// clone whose origin/HEAD was never set falls through to the conventional
// names.
func DefaultBase(ctx context.Context, dir string) (string, error) {
	if out, err := runGit(ctx, dir, "symbolic-ref", "--quiet", "--short", "refs/remotes/origin/HEAD"); err == nil {
		if b := strings.TrimPrefix(out, "origin/"); b != "" && b != out {
			return b, nil
		}
	}
	for _, b := range []string{"main", "master"} {
		if refExists(ctx, dir, "refs/heads/"+b) || refExists(ctx, dir, "refs/remotes/origin/"+b) {
			return b, nil
		}
	}
	out, err := runGit(ctx, dir, "symbolic-ref", "--quiet", "--short", "HEAD")
	if err == nil && out != "" {
		return out, nil
	}
	return "", errors.New("could not determine a base branch: no origin/HEAD, no main or master, and HEAD is detached — pass one explicitly")
}

// repoTopLevel returns the top level of the work tree containing dir.
func repoTopLevel(ctx context.Context, dir string) (string, error) {
	out, err := runGit(ctx, dir, "rev-parse", "--show-toplevel")
	if err != nil {
		return "", err
	}
	return out, nil
}

// commonDir returns the repository's shared git directory, absolute. For a
// linked worktree that is the main repository's .git, which is where the
// shared exclude file lives.
func commonDir(ctx context.Context, dir string) (string, error) {
	out, err := runGit(ctx, dir, "rev-parse", "--git-common-dir")
	if err != nil {
		return "", err
	}
	if !filepath.IsAbs(out) {
		out = filepath.Join(dir, out)
	}
	return filepath.Clean(out), nil
}

// sameDir reports whether two directories are the same after symlink
// resolution. git reports kernel-canonical paths; a project may be registered
// through a symlink.
func sameDir(a, b string) bool {
	if filepath.Clean(a) == filepath.Clean(b) {
		return true
	}
	ra, errA := filepath.EvalSymlinks(a)
	rb, errB := filepath.EvalSymlinks(b)
	return errA == nil && errB == nil && ra == rb
}

// aheadCount returns how many commits head has that base does not.
func aheadCount(ctx context.Context, dir, base, head string) (int, error) {
	out, err := runGit(ctx, dir, "rev-list", "--count", base+".."+head)
	if err != nil {
		return 0, err
	}
	n, err := strconv.Atoi(strings.TrimSpace(out))
	if err != nil {
		return 0, fmt.Errorf("unexpected rev-list output %q", out)
	}
	return n, nil
}

// dirtyFiles returns git's porcelain status lines for dir: modified,
// staged and untracked files that are not ignored.
func dirtyFiles(ctx context.Context, dir string) ([]string, error) {
	out, err := runGit(ctx, dir, "status", "--porcelain", "--untracked-files=normal")
	if err != nil {
		return nil, err
	}
	if out == "" {
		return nil, nil
	}
	return strings.Split(out, "\n"), nil
}
