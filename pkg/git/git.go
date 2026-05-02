// Package git provides helpers for integrating cloop task execution with git
// workflows. Each PM task can be executed on its own branch, committed when done,
// and merged back to the original branch on success.
package git

import (
	"fmt"
	"os/exec"
	"regexp"
	"strings"

	"github.com/blechschmidt/cloop/pkg/pm"
)

// slugRe matches any character that is not alphanumeric or hyphen.
var slugRe = regexp.MustCompile(`[^a-z0-9]+`)

// taskSlug converts a task title to a lowercase URL-safe slug.
// e.g. "Add REST API endpoint" → "add-rest-api-endpoint"
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

// BranchName returns the branch name for a task: cloop/task-<id>-<slug>.
func BranchName(task *pm.Task) string {
	return fmt.Sprintf("cloop/task-%d-%s", task.ID, taskSlug(task.Title))
}

// CurrentBranch returns the name of the currently checked-out git branch.
// Returns an error if the working directory is not inside a git repository.
func CurrentBranch(workDir string) (string, error) {
	out, err := run(workDir, "git", "rev-parse", "--abbrev-ref", "HEAD")
	if err != nil {
		return "", fmt.Errorf("git current branch: %w", err)
	}
	branch := strings.TrimSpace(out)
	if branch == "HEAD" {
		// Detached HEAD — get the commit hash instead so we can return to it.
		out, err = run(workDir, "git", "rev-parse", "HEAD")
		if err != nil {
			return "", fmt.Errorf("git detached HEAD rev: %w", err)
		}
		branch = strings.TrimSpace(out)
	}
	return branch, nil
}

// CreateTaskBranch creates (and checks out) a new branch named
// cloop/task-<id>-<slug> from HEAD. If the branch already exists it is
// checked out as-is (idempotent). Returns the new branch name.
func CreateTaskBranch(workDir string, task *pm.Task) (string, error) {
	branch := BranchName(task)

	// Check if branch already exists locally.
	_, err := run(workDir, "git", "rev-parse", "--verify", branch)
	if err == nil {
		// Branch exists — just check it out.
		if _, err := run(workDir, "git", "checkout", branch); err != nil {
			return "", fmt.Errorf("git checkout existing branch %q: %w", branch, err)
		}
		return branch, nil
	}

	// Create and switch to the new branch.
	if _, err := run(workDir, "git", "checkout", "-b", branch); err != nil {
		return "", fmt.Errorf("git checkout -b %q: %w", branch, err)
	}
	return branch, nil
}

// CommitTaskArtifacts stages all modified/untracked files and creates a commit
// referencing the task ID and title. The commit message follows the format:
//
//	cloop(task-<id>): <title>
//
// If there is nothing to commit (clean tree), the function returns nil without
// creating an empty commit.
func CommitTaskArtifacts(workDir string, task *pm.Task) error {
	// Stage everything (modified + untracked, excluding gitignored files).
	if _, err := run(workDir, "git", "add", "-A"); err != nil {
		return fmt.Errorf("git add -A: %w", err)
	}

	// Check whether there are staged changes; skip commit on clean tree.
	out, err := run(workDir, "git", "diff", "--cached", "--name-only")
	if err != nil {
		return fmt.Errorf("git diff --cached: %w", err)
	}
	if strings.TrimSpace(out) == "" {
		// Nothing staged — nothing to commit.
		return nil
	}

	msg := fmt.Sprintf("cloop(task-%d): %s", task.ID, task.Title)
	if _, err := run(workDir, "git", "commit", "-m", msg); err != nil {
		return fmt.Errorf("git commit: %w", err)
	}
	return nil
}

// CheckoutBranch checks out the named branch (or commit SHA for detached HEAD)
// without performing any merge. Use this to return to the original branch after
// a failed task in git mode.
func CheckoutBranch(workDir, branch string) error {
	if _, err := run(workDir, "git", "checkout", branch); err != nil {
		return fmt.Errorf("git checkout %q: %w", branch, err)
	}
	return nil
}

// MergeBranch merges taskBranch into targetBranch (typically the branch that
// was active before CreateTaskBranch was called). After a successful merge the
// working directory is left on targetBranch.
//
// Uses --no-ff so each task always produces a visible merge commit in the log.
func MergeBranch(workDir, targetBranch, taskBranch string) error {
	// Switch back to the target branch.
	if _, err := run(workDir, "git", "checkout", targetBranch); err != nil {
		return fmt.Errorf("git checkout %q: %w", targetBranch, err)
	}

	mergeMsg := fmt.Sprintf("Merge branch '%s' into %s", taskBranch, targetBranch)
	if _, err := run(workDir, "git", "merge", "--no-ff", "-m", mergeMsg, taskBranch); err != nil {
		return fmt.Errorf("git merge %q into %q: %w", taskBranch, targetBranch, err)
	}
	return nil
}

// run executes a git command in workDir and returns combined stdout+stderr.
func run(workDir string, args ...string) (string, error) {
	cmd := exec.Command(args[0], args[1:]...)
	cmd.Dir = workDir
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("%w\n%s", err, strings.TrimSpace(string(out)))
	}
	return string(out), nil
}
