// Package featurehub is the hub's half of running a feature on an executor that
// isolates from the hub's filesystem (Task 20367).
//
// A feature (pkg/feature) is a linked git worktree of a project's repository,
// on the hub, on a branch of its own. A sandbox cannot use that worktree: its
// .git names the parent repository by an absolute host path, and handing the
// sandbox the parent's .git to make it resolve would let hooks and
// configuration written there run on the hub at the next git command anything
// here runs in that repository. So a feature travels as a branch instead:
//
//   - Ship turns the feature's branch into a size-capped git bundle that the
//     executor builds a standalone checkout from — the commits on top of an
//     upstream clone when the parent's upstream already holds the feature's
//     base, otherwise the whole branch, shallow when the whole branch is too
//     large;
//   - Land takes the write-back bundle the run returns, vets it in quarantine
//     (pkg/writeback), and fast-forwards the hub's worktree onto it when the
//     worktree is clean and the work builds on its HEAD — and otherwise parks
//     it on a branch of its own and reports a conflict, never forcing anything;
//   - Create, Remove, OpenPR and RefreshPR are pkg/featureops's operations,
//     run here, in hub mode, for a project whose executor cannot see the hub's
//     worktrees and so cannot run them itself.
//
// # Why the hub runs git at all
//
// The source of truth for a feature is the branch in the hub's copy of the
// repository, and only something that can read the hub's filesystem can ship
// it or land work onto it. Every executor that could is, by construction, not
// the one the feature runs on — the point of the exercise is that the run
// happens somewhere the hub's files are not. So this package is part of the
// executor boundary (tests/security treats pkg/executor/... as the sanctioned
// place a process may be started from): it runs git, and only git, with fixed
// subcommands, in the hub's own repositories, and never a harness or anything a
// repository can name. Every invocation runs with a closed environment —
// no system or global configuration — and with executor.HardenedGitConfig, so
// a hook, a filter, an fsmonitor or a signing program configured in the
// repository does not run. That matters because the repository is not always
// only the hub's to write: a project bound to a container executor has its
// directory, .git included, mounted into its own sandbox.
package featurehub

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/executor/gitprovision"
)

// gitTimeout bounds one git invocation. Bundling a large branch is the slowest
// thing here and is still local work.
const gitTimeout = 5 * time.Minute

// gitRunner runs hardened git in one repository on the hub.
type gitRunner struct {
	dir string
	// env renders the closed, hardened environment with extra configuration
	// folded into its one block.
	env func(extra ...[2]string) []string
}

// newGitRunner prepares hardened git for the repository at dir — a project, or
// one of its features' worktrees, which shares the project's configuration.
func newGitRunner(ctx context.Context, dir string) (*gitRunner, error) {
	drivers, err := gitprovision.FilterDrivers(ctx, dir, nil, hubOwnershipConfig)
	if err != nil {
		return nil, err
	}
	hardened := append(executor.HardenedGitConfig(drivers), hubOwnershipConfig)
	return &gitRunner{dir: dir, env: func(extra ...[2]string) []string {
		pairs := append(append([][2]string(nil), hardened...), extra...)
		pairs = append(pairs, gitprovision.TransportConfig()...)
		return append(append(executor.GitEnv(pairs...), gitprovision.TransportEnv()...), "LC_ALL=C")
	}}, nil
}

// hubOwnershipConfig lets the hub's git work in a project its account does not
// own.
//
// git refuses a repository owned by another user, so that a repository planted
// in a shared directory cannot make whoever runs git there honour its
// configuration. Here that is the ordinary case rather than an attack: a
// project bound to a container executor is owned by the unprivileged uid its
// sandbox runs as (that is how the driver chooses the uid), while the hub may
// run under an account of its own. And the protection's purpose is already
// served another way — every invocation in this package neutralises the
// repository's configuration (executor.HardenedGitConfig) and runs in a
// project the hub itself manages, never in a directory a request named.
var hubOwnershipConfig = [2]string{"safe.directory", "*"}

// HubEnv returns the environment renderer for pkg/featureops's hub mode
// (featureops.WithHubEnv), for the repository at dir.
func HubEnv(ctx context.Context, dir string) (func(extra ...[2]string) []string, error) {
	g, err := newGitRunner(ctx, dir)
	if err != nil {
		return nil, err
	}
	return g.env, nil
}

// TrackingCommit returns the commit the repository at dir records for
// origin/<branch> — the origin's tip as the hub last fetched it — for a run
// whose work is pushed back and measured from it (Task 20390). The hub's own
// git, hardened as every invocation here is: the repository's configuration
// runs nothing.
func TrackingCommit(ctx context.Context, dir, branch string) (string, error) {
	branch = strings.TrimSpace(branch)
	if branch == "" || strings.HasPrefix(branch, "-") || strings.ContainsAny(branch, " \t\n:^~?*[\\") {
		return "", fmt.Errorf("featurehub: %q is not a branch name", branch)
	}
	g, err := newGitRunner(ctx, dir)
	if err != nil {
		return "", err
	}
	sha, err := g.run(ctx, "rev-parse", "--verify", "--quiet", "refs/remotes/origin/"+branch+"^{commit}")
	if err != nil {
		return "", fmt.Errorf("featurehub: no refs/remotes/origin/%s in %s", branch, dir)
	}
	if err := executor.ValidateCommitSHA(sha); err != nil {
		return "", fmt.Errorf("featurehub: refs/remotes/origin/%s does not name a commit: %w", branch, err)
	}
	return sha, nil
}

// run executes one git command and returns its stdout, trimmed of the trailing
// newline. A failure carries git's own words.
func (g *gitRunner) run(ctx context.Context, args ...string) (string, error) {
	return g.runIn(ctx, g.dir, nil, args...)
}

// runIn is run in another directory, with extra configuration.
func (g *gitRunner) runIn(ctx context.Context, dir string, extra [][2]string, args ...string) (string, error) {
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, gitTimeout)
		defer cancel()
	}
	cmd := exec.CommandContext(ctx, "git", append([]string{"-C", dir}, args...)...)
	cmd.Env = g.env(extra...)
	cmd.Dir = dir
	gitprovision.BoundChild(cmd)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return "", fmt.Errorf("git %s: %w", args[0], ctxErr)
		}
		return strings.TrimRight(stdout.String(), "\n"), &gitError{
			args: args, err: err, stderr: gitprovision.Collapse(stderr.String())}
	}
	return strings.TrimRight(stdout.String(), "\n"), nil
}

// gitError is a failed git invocation.
type gitError struct {
	args   []string
	err    error
	stderr string
}

func (e *gitError) Error() string {
	if e.stderr != "" {
		return fmt.Sprintf("git %s: %s", e.args[0], e.stderr)
	}
	return fmt.Sprintf("git %s: %v", e.args[0], e.err)
}

func (e *gitError) Unwrap() error { return e.err }

// exitCode returns git's exit status for a failed invocation, or -1.
func exitCode(err error) int {
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return ee.ExitCode()
	}
	return -1
}

// isAncestor reports whether a is an ancestor of b (or equal to it). Any
// failure other than "no" is returned as an error, so a broken repository is
// not mistaken for diverged history.
func (g *gitRunner) isAncestor(ctx context.Context, a, b string) (bool, error) {
	_, err := g.run(ctx, "merge-base", "--is-ancestor", a, b)
	if err == nil {
		return true, nil
	}
	if exitCode(err) == 1 {
		return false, nil
	}
	return false, err
}

// commitOf resolves a ref to its commit.
func (g *gitRunner) commitOf(ctx context.Context, ref string) (string, error) {
	out, err := g.run(ctx, "rev-parse", "--verify", "--quiet", "--end-of-options", ref+"^{commit}")
	if err != nil {
		return "", err
	}
	sha := strings.TrimSpace(out)
	if err := executor.ValidateCommitSHA(sha); err != nil {
		return "", err
	}
	return sha, nil
}
