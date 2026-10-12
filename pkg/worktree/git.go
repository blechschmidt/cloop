package worktree

// How this package runs git, and for whom (Task 20418).
//
// Two callers, two authorities. The orchestrator creates, commits and keeps a
// task's worktree inside the run — in its sandbox, as the task — and its git
// is the task's own: the repository's hooks and signing apply to the task's
// commits as they would to anyone's (taskGit).
//
// The hub's background sweep (pkg/executor/reconcile, every fifteen minutes on
// a strict hub) lists and removes leaked worktrees in repositories a sandbox
// could write, from a process holding the hub's secrets. Before Task 20418 it
// ran a bare exec.Command: the hub's whole environment, no deadline, and
// whatever programs the repository's own configuration named. Now its git runs
// as executor.HardenedGitConfig describes for any git cloop runs outside the
// sandbox that wrote the repository — a closed environment (executor.GitEnv),
// no hooks, no fsmonitor, no filters, no signing — with .git pinned to the
// directory the hub named, bounded by a deadline and killed with its whole
// process group (gitprovision.BoundChild).

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/executor/gitprovision"
)

// gitRunner runs one git command in dir and returns its combined output.
type gitRunner func(dir string, args ...string) (string, error)

// gitTimeout bounds one git command of the sweep. A healthy one over a local
// repository takes milliseconds; one that does not finish is waiting on a lock
// or on something it should not have started, and the sweep has other
// repositories to get to.
var gitTimeout = 2 * time.Minute

// redirectFiles inside .git make git read another directory's objects, refs or
// configuration (gitprovision has the same list). A repository holding one is
// not swept: the sweep would act on whatever it points at.
var redirectFiles = []string{
	"commondir",
	filepath.Join("objects", "info", "alternates"),
	filepath.Join("objects", "info", "http-alternates"),
}

// runGit is the sweep's git: hardened, pinned to repoDir's own .git, bounded.
// See the file comment.
func runGit(repoDir string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), gitTimeout)
	defer cancel()
	env, err := sweepEnv(ctx, repoDir)
	if err != nil {
		return "", err
	}
	return execGit(ctx, repoDir, env, args...)
}

// sweepEnv is the environment of the sweep's git commands in repoDir.
//
// .git must be repoDir's own directory: a .git file or link points git at a
// repository of the writer's choosing — another project's, or the hub's own —
// and the sweep would then remove and prune *its* worktrees. A repository
// holding a redirect file is refused rather than repaired: it is not this
// package's to change, and alternates are a legitimate thing for a person to
// have configured.
//
// safe.directory names repoDir, because the repository is commonly owned by
// the sandbox's uid and not the hub's; what makes trusting it safe is
// everything else in this environment.
func sweepEnv(ctx context.Context, repoDir string) ([]string, error) {
	gitDir := filepath.Join(repoDir, ".git")
	info, err := os.Lstat(gitDir)
	if err != nil {
		return nil, fmt.Errorf("worktree: %s is not a git repository: %w", repoDir, err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("worktree: %s/.git is not a directory (a gitdir file or a link would point git "+
			"at another repository), so the sweep does not run git in it", repoDir)
	}
	for _, rel := range redirectFiles {
		if _, err := os.Lstat(filepath.Join(gitDir, rel)); err == nil {
			return nil, fmt.Errorf("worktree: %s holds %s, which points git at another repository, so the "+
				"sweep does not run git in it", gitDir, rel)
		} else if !errors.Is(err, fs.ErrNotExist) {
			return nil, fmt.Errorf("worktree: inspect %s: %w", filepath.Join(gitDir, rel), err)
		}
	}
	pinned := []string{"GIT_DIR=" + gitDir, "GIT_WORK_TREE=" + repoDir}
	trust := [2]string{"safe.directory", repoDir}
	drivers, err := gitprovision.FilterDrivers(ctx, repoDir, pinned, trust)
	if err != nil {
		return nil, fmt.Errorf("worktree: read %s's filter drivers: %w", repoDir, err)
	}
	pairs := append(executor.HardenedGitConfig(drivers), trust)
	return append(executor.GitEnv(pairs...), pinned...), nil
}

// probeEnv is the environment of IsGitRepo's one question, which both callers
// ask: hardened like the sweep's, but not pinned, because a feature's
// worktree — whose .git is a file — is a repository the orchestrator works in.
// rev-parse runs nothing a repository could configure.
func probeEnv(dir string) []string {
	return executor.GitEnv(append(executor.HardenedGitConfig(nil), [2]string{"safe.directory", dir})...)
}

// taskGit is the task's own git, run by the orchestrator in the worktree it
// works in: the inherited environment, so the repository's hooks and signing
// apply to the task's commits. Bounded by BoundChild like the sweep's, but not
// by a deadline — a commit hook may legitimately take long.
func taskGit(dir string, args ...string) (string, error) {
	return execGit(context.Background(), dir, nil, args...)
}

// execGit runs git with env (nil inherits this process's).
func execGit(ctx context.Context, dir string, env []string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, "git", args...)
	cmd.Dir = dir
	cmd.Env = env
	gitprovision.BoundChild(cmd)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("git %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return string(out), nil
}
