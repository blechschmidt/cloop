// Package worktree manages git worktrees for isolating parallel task execution.
//
// When cloop runs multiple tasks in parallel under git mode, each task gets its
// own git worktree in .cloop/worktrees/task-<id>/ on a dedicated branch
// (cloop/task-<id>-<slug>). Tasks can modify files independently without
// stepping on each other; their changes are later merged back to the base
// branch sequentially via pkg/mergequeue.
package worktree

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/blechschmidt/cloop/pkg/pm"
)

// slugRe matches any character that is not alphanumeric or hyphen.
var slugRe = regexp.MustCompile(`[^a-z0-9]+`)

// taskSlug converts a task title to a lowercase URL-safe slug.
func taskSlug(title string) string {
	s := strings.ToLower(title)
	s = slugRe.ReplaceAllString(s, "-")
	s = strings.Trim(s, "-")
	if len(s) > 40 {
		s = s[:40]
		s = strings.TrimRight(s, "-")
	}
	return s
}

// BranchName returns the branch name used for a task worktree.
func BranchName(task *pm.Task) string {
	return fmt.Sprintf("cloop/task-%d-%s", task.ID, taskSlug(task.Title))
}

// Path returns the absolute path to the worktree directory for a task.
// The directory lives under <repoDir>/.cloop/worktrees/task-<id>.
func Path(repoDir string, task *pm.Task) string {
	return filepath.Join(repoDir, ".cloop", "worktrees", fmt.Sprintf("task-%d", task.ID))
}

// IsGitRepo reports whether dir is inside a git repository (working tree or
// linked worktree). Useful as a guard before invoking worktree machinery.
func IsGitRepo(dir string) bool {
	cmd := exec.Command("git", "rev-parse", "--is-inside-work-tree")
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		return false
	}
	return strings.TrimSpace(string(out)) == "true"
}

// Worktree represents a single live git worktree for a task.
type Worktree struct {
	// Path is the absolute path to the worktree directory.
	Path string
	// Branch is the branch checked out in the worktree.
	Branch string
	// BaseBranch is the branch the worktree was created from (the merge target).
	BaseBranch string
	// TaskID is the cloop task ID this worktree was created for.
	TaskID int
}

// Create provisions a fresh worktree for the given task at .cloop/worktrees/task-<id>
// off the current HEAD of repoDir. If a stale worktree exists at that path it is
// removed first (git worktree remove --force). The created branch is
// cloop/task-<id>-<slug>; if a branch by that name already exists it is reset
// to the current HEAD so the worktree always starts from a clean baseline.
func Create(repoDir string, task *pm.Task) (*Worktree, error) {
	if task == nil {
		return nil, errors.New("worktree: nil task")
	}
	if !IsGitRepo(repoDir) {
		return nil, fmt.Errorf("worktree: %q is not a git repository", repoDir)
	}
	baseBranch, err := currentBranch(repoDir)
	if err != nil {
		return nil, fmt.Errorf("worktree: determine current branch: %w", err)
	}
	wtPath := Path(repoDir, task)
	branch := BranchName(task)

	// If a worktree already exists at this path (from a crashed prior run or a
	// stale entry in .git/worktrees), tear it down before re-creating.
	_ = forceRemoveWorktree(repoDir, wtPath)

	// Ensure the parent directory exists; git worktree add will create wtPath itself.
	if err := os.MkdirAll(filepath.Dir(wtPath), 0o755); err != nil {
		return nil, fmt.Errorf("worktree: mkdir parent: %w", err)
	}

	// Try to create the worktree with a brand-new branch.
	if _, err := runGit(repoDir, "worktree", "add", "-b", branch, wtPath, "HEAD"); err != nil {
		// Branch may already exist (leftover from a previous run). Fall back to
		// reusing it: reset the branch to HEAD and check it out in the new worktree.
		if _, resetErr := runGit(repoDir, "branch", "-f", branch, "HEAD"); resetErr != nil {
			return nil, fmt.Errorf("worktree: reset existing branch %q: %w (initial add error: %v)", branch, resetErr, err)
		}
		if _, addErr := runGit(repoDir, "worktree", "add", wtPath, branch); addErr != nil {
			return nil, fmt.Errorf("worktree: add reusing branch %q: %w (initial add error: %v)", branch, addErr, err)
		}
	}

	return &Worktree{
		Path:       wtPath,
		Branch:     branch,
		BaseBranch: baseBranch,
		TaskID:     task.ID,
	}, nil
}

// HasChanges reports whether the worktree contains any uncommitted or untracked
// changes. Used by callers to decide whether a merge is even meaningful.
func (w *Worktree) HasChanges() (bool, error) {
	if w == nil {
		return false, errors.New("worktree: nil receiver")
	}
	out, err := runGit(w.Path, "status", "--porcelain")
	if err != nil {
		return false, fmt.Errorf("worktree status: %w", err)
	}
	return strings.TrimSpace(out) != "", nil
}

// Commit stages all changes in the worktree and commits them with a task-scoped
// message. Returns the new commit SHA. If the worktree is clean, returns "" and
// a nil error (no-op).
func (w *Worktree) Commit(task *pm.Task) (string, error) {
	if w == nil {
		return "", errors.New("worktree: nil receiver")
	}
	if task == nil {
		return "", errors.New("worktree: nil task")
	}
	dirty, err := w.HasChanges()
	if err != nil {
		return "", err
	}
	if !dirty {
		return "", nil
	}
	if _, err := runGit(w.Path, "add", "-A"); err != nil {
		return "", fmt.Errorf("worktree git add: %w", err)
	}
	// Re-check after staging — `git add -A` can produce nothing to commit when
	// every change was already tracked-and-staged before the call (rare but
	// possible) or when only gitignored files were dirty.
	staged, err := runGit(w.Path, "diff", "--cached", "--name-only")
	if err != nil {
		return "", fmt.Errorf("worktree diff --cached: %w", err)
	}
	if strings.TrimSpace(staged) == "" {
		return "", nil
	}
	msg := fmt.Sprintf("cloop(task-%d): %s", task.ID, task.Title)
	if _, err := runGit(w.Path, "commit", "-m", msg); err != nil {
		return "", fmt.Errorf("worktree git commit: %w", err)
	}
	sha, err := runGit(w.Path, "rev-parse", "HEAD")
	if err != nil {
		return "", fmt.Errorf("worktree rev-parse HEAD: %w", err)
	}
	return strings.TrimSpace(sha), nil
}

// Remove tears down the worktree directory and prunes git's bookkeeping. The
// underlying branch is left intact so merge history (and any unmerged work)
// remains recoverable. Errors are returned but callers usually treat them as
// non-fatal cleanup failures.
func (w *Worktree) Remove(repoDir string) error {
	if w == nil {
		return errors.New("worktree: nil receiver")
	}
	return forceRemoveWorktree(repoDir, w.Path)
}

// forceRemoveWorktree runs `git worktree remove --force` against the given
// path; if that fails it also rm-rfs the directory and runs `git worktree
// prune` so a future Create() can re-use the same path.
func forceRemoveWorktree(repoDir, wtPath string) error {
	if wtPath == "" {
		return nil
	}
	// Best-effort removal; ignore the error from git but always try to prune
	// stale entries afterwards so the path can be re-used.
	_, gitErr := runGit(repoDir, "worktree", "remove", "--force", wtPath)
	if _, statErr := os.Stat(wtPath); statErr == nil {
		if rmErr := os.RemoveAll(wtPath); rmErr != nil && gitErr != nil {
			return fmt.Errorf("worktree remove: git=%v fs=%w", gitErr, rmErr)
		}
	}
	_, _ = runGit(repoDir, "worktree", "prune")
	return nil
}

// currentBranch returns the current branch name in repoDir, or the commit SHA
// when HEAD is detached.
func currentBranch(repoDir string) (string, error) {
	out, err := runGit(repoDir, "rev-parse", "--abbrev-ref", "HEAD")
	if err != nil {
		return "", err
	}
	branch := strings.TrimSpace(out)
	if branch == "HEAD" {
		out, err = runGit(repoDir, "rev-parse", "HEAD")
		if err != nil {
			return "", err
		}
		branch = strings.TrimSpace(out)
	}
	return branch, nil
}

// runGit executes a git command in dir and returns combined stdout+stderr.
func runGit(dir string, args ...string) (string, error) {
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("git %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return string(out), nil
}
