package featureops

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/blechschmidt/cloop/pkg/feature"
)

// DirtyError is returned when removing a feature would discard work that was
// never committed.
type DirtyError struct {
	Slug  string
	Files []string
}

func (e *DirtyError) Error() string {
	shown := e.Files
	more := ""
	if len(shown) > 8 {
		more = fmt.Sprintf(" and %d more", len(shown)-8)
		shown = shown[:8]
	}
	return fmt.Sprintf("feature %q has uncommitted changes (%s%s) — commit them, or remove with force to discard them",
		e.Slug, strings.Join(shown, "; "), more)
}

// RemoveOptions describes a feature to remove.
type RemoveOptions struct {
	ProjectDir string
	Slug       string
	// DeleteBranch also deletes the feature's branch — only when git
	// considers it merged, unless Force.
	DeleteBranch bool
	// Force discards uncommitted changes, and with DeleteBranch deletes an
	// unmerged branch.
	Force bool
}

// RemoveResult reports what Remove did.
type RemoveResult struct {
	Path          string `json:"path"`
	Branch        string `json:"branch"`
	BranchDeleted bool   `json:"branch_deleted"`
	// BranchKept explains why a requested branch deletion did not happen.
	BranchKept string `json:"branch_kept,omitempty"`
}

// Remove deletes a feature's worktree — and with it the feature's task list
// and history — and optionally its branch.
//
// The branch is kept by default, because it is the only copy of any commit
// that was never pushed or merged; removing a feature is a statement about the
// dashboard, not about the work. When asked to delete it, `git branch -d`
// decides whether it is merged, so being wrong about that fails the deletion
// instead of losing commits. A pull request merged by squash is not "merged"
// by that test; Force is the explicit way past it.
//
// The caller is responsible for making sure no run is executing in the
// feature: a worktree removed under a running harness takes its working
// directory away mid-task.
func Remove(ctx context.Context, opts RemoveOptions) (*RemoveResult, error) {
	if err := feature.ValidSlug(opts.Slug); err != nil {
		return nil, err
	}
	dest := feature.Path(opts.ProjectDir, opts.Slug)
	branch := feature.BranchName(opts.Slug)
	res := &RemoveResult{Path: dest, Branch: branch}

	_, statErr := os.Lstat(dest)
	present := statErr == nil
	if !present && !errors.Is(statErr, os.ErrNotExist) {
		return nil, fmt.Errorf("inspect %s: %w", dest, statErr)
	}
	if !present && !refExists(ctx, opts.ProjectDir, "refs/heads/"+branch) {
		return nil, fmt.Errorf("no feature %q in %s", opts.Slug, opts.ProjectDir)
	}

	// The record lives inside the worktree, so it is read before the worktree
	// goes: it names the base the branch is judged merged into.
	meta, _ := feature.LoadMeta(dest)

	if present {
		nested := nestedWorktrees(ctx, opts.ProjectDir, dest)
		if !opts.Force {
			// A parallel run of the feature works in task worktrees under the
			// feature's own .cloop/worktrees — excluded from the feature's
			// status, so their uncommitted work is invisible to the check
			// below and would be deleted with the tree.
			if len(nested) > 0 {
				return nil, &DirtyError{Slug: opts.Slug, Files: prefixAll("task worktree: ", nested)}
			}
			// Commits made on a detached HEAD are held by no branch, and the
			// worktree's own reflog goes with it; removing it loses them.
			if lost := unreferencedHead(ctx, dest); lost != "" {
				return nil, fmt.Errorf("feature %q has HEAD detached at %s, holding commits no branch contains — "+
					"check out a branch there first, or remove with force to discard them", opts.Slug, lost)
			}
		}
		dirty, err := dirtyFiles(ctx, dest)
		switch {
		case err != nil && !opts.Force:
			return nil, fmt.Errorf("cannot tell whether feature %q has uncommitted work (%v) — remove with force to discard it regardless", opts.Slug, err)
		case len(dirty) > 0 && !opts.Force:
			return nil, &DirtyError{Slug: opts.Slug, Files: dirty}
		}

		// Forced: the task worktrees go first, through git, so the repository
		// is not left with records of worktrees whose directories vanished.
		for _, wt := range nested {
			_, _ = runGit(ctx, opts.ProjectDir, "worktree", "unlock", wt)
			_, _ = runGit(ctx, opts.ProjectDir, "worktree", "remove", "--force", wt)
		}

		// The lock is ours; it exists to keep everything else's hands off.
		_, _ = runGit(ctx, opts.ProjectDir, "worktree", "unlock", dest)
		args := []string{"worktree", "remove"}
		if opts.Force {
			args = append(args, "--force")
		}
		args = append(args, dest)
		if _, err := runGit(ctx, opts.ProjectDir, args...); err != nil {
			if !opts.Force {
				// Put the lock back so a failed removal does not leave the
				// feature collectable by the next prune.
				_, _ = runGit(ctx, opts.ProjectDir, "worktree", "lock", "--reason", "cloop feature "+opts.Slug, dest)
				return nil, fmt.Errorf("remove the worktree: %w", err)
			}
			// A worktree git no longer recognises (its bookkeeping was pruned)
			// cannot be removed through git; with force the directory goes.
			if rmErr := os.RemoveAll(dest); rmErr != nil {
				return nil, fmt.Errorf("remove the worktree: %v; and deleting the directory failed: %w", err, rmErr)
			}
		}
	}
	_, _ = runGit(ctx, opts.ProjectDir, "worktree", "prune")

	if opts.DeleteBranch && refExists(ctx, opts.ProjectDir, "refs/heads/"+branch) {
		flag := "-d"
		if opts.Force {
			flag = "-D"
		} else if why := notMergedIntoBase(ctx, opts.ProjectDir, branch, meta); why != "" {
			// `git branch -d` asks whether the branch is merged into its
			// upstream — and a feature's upstream is its own pushed copy, so
			// any pushed feature would pass. Merged means merged into the base.
			res.BranchKept = why
			return res, nil
		}
		if _, err := runGit(ctx, opts.ProjectDir, "branch", flag, branch); err != nil {
			res.BranchKept = "git refused to delete it: " + strings.TrimPrefix(err.Error(), "git branch "+flag+" "+branch+": ")
		} else {
			res.BranchDeleted = true
			_, _ = runGit(ctx, opts.ProjectDir, "config", "--remove-section", "branch."+branch)
		}
	}
	return res, nil
}

// notMergedIntoBase explains why branch is not merged into the feature's base
// branch, or returns "" when it is.
func notMergedIntoBase(ctx context.Context, project, branch string, meta *feature.Meta) string {
	base := ""
	if meta != nil {
		base = meta.Base
	}
	if base == "" {
		b, err := DefaultBase(ctx, project)
		if err != nil {
			return "its base branch is unknown, so whether it is merged cannot be told"
		}
		base = b
	}
	baseRef, err := resolveBase(ctx, project, base)
	if err != nil {
		return "its base branch " + base + " is gone, so whether it is merged cannot be told"
	}
	if _, err := runGit(ctx, project, "merge-base", "--is-ancestor", "refs/heads/"+branch, baseRef); err != nil {
		return "it is not merged into " + base + " (a squash-merged pull request is not, by this test) — remove with force to delete it anyway"
	}
	return ""
}

// nestedWorktrees returns the worktrees git has registered below dest — a
// feature's own parallel-task worktrees.
func nestedWorktrees(ctx context.Context, project, dest string) []string {
	out, err := runGit(ctx, project, "worktree", "list", "--porcelain")
	if err != nil {
		return nil
	}
	prefix := filepath.Clean(dest) + string(os.PathSeparator)
	resolved := dest
	if r, err := filepath.EvalSymlinks(dest); err == nil {
		resolved = r
	}
	rprefix := filepath.Clean(resolved) + string(os.PathSeparator)
	var nested []string
	for _, line := range strings.Split(out, "\n") {
		path, ok := strings.CutPrefix(line, "worktree ")
		if !ok {
			continue
		}
		if strings.HasPrefix(path, prefix) || strings.HasPrefix(path, rprefix) {
			nested = append(nested, path)
		}
	}
	return nested
}

// unreferencedHead returns the commit a detached HEAD in dir points at when no
// ref contains it, and "" otherwise.
func unreferencedHead(ctx context.Context, dir string) string {
	if _, err := runGit(ctx, dir, "symbolic-ref", "--quiet", "HEAD"); err == nil {
		return "" // on a branch, which keeps its commits
	}
	sha, err := runGit(ctx, dir, "rev-parse", "--verify", "--quiet", "HEAD")
	if err != nil || sha == "" {
		return ""
	}
	refs, err := runGit(ctx, dir, "for-each-ref", "--contains", sha, "--count=1", "--format=%(refname)")
	if err != nil || strings.TrimSpace(refs) != "" {
		return ""
	}
	if len(sha) > 12 {
		sha = sha[:12]
	}
	return sha
}

func prefixAll(prefix string, in []string) []string {
	out := make([]string, len(in))
	for i, s := range in {
		out[i] = prefix + s
	}
	return out
}
