package featureops

import (
	"context"

	"github.com/blechschmidt/cloop/pkg/feature"
)

// GitStatus is where a feature's branch stands relative to its base.
type GitStatus struct {
	// Head is the commit the feature's branch points at.
	Head string `json:"head,omitempty"`
	// Ahead counts commits on the feature that its base does not have — what
	// a pull request would carry. Behind counts the reverse.
	Ahead  int `json:"ahead"`
	Behind int `json:"behind"`
	// Dirty counts uncommitted changes in the worktree.
	Dirty int `json:"dirty"`
	// OnBranch reports that the worktree still has the feature's branch
	// checked out.
	OnBranch bool `json:"on_branch"`
	// Error explains a status that could not be determined.
	Error string `json:"error,omitempty"`
}

// Status reports a feature's branch position. It never fails outright: a
// listing of several features should not be lost to one broken worktree, so
// what could not be read is described in Error instead.
func Status(ctx context.Context, info feature.Info) GitStatus {
	var st GitStatus
	dir := info.Path
	meta := info.Meta
	head, err := runGit(ctx, dir, "rev-parse", "--verify", "--quiet", "refs/heads/"+meta.Branch)
	if err != nil {
		st.Error = "the feature's branch " + meta.Branch + " does not exist"
		return st
	}
	st.Head = head
	if cur, err := runGit(ctx, dir, "symbolic-ref", "--quiet", "--short", "HEAD"); err == nil {
		st.OnBranch = cur == meta.Branch
	}
	if baseRef, err := resolveBase(ctx, dir, meta.Base); err == nil {
		if n, err := aheadCount(ctx, dir, baseRef, "refs/heads/"+meta.Branch); err == nil {
			st.Ahead = n
		}
		if n, err := aheadCount(ctx, dir, "refs/heads/"+meta.Branch, baseRef); err == nil {
			st.Behind = n
		}
	} else {
		st.Error = err.Error()
	}
	if files, err := dirtyFiles(ctx, dir); err == nil {
		st.Dirty = len(files)
	} else if st.Error == "" {
		st.Error = err.Error()
	}
	return st
}
