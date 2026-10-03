package featurehub

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/feature"
	"github.com/blechschmidt/cloop/pkg/writeback"
)

// LandOutcome is what became of a feature run's returned work.
type LandOutcome string

const (
	// LandNothing: the run returned no commits.
	LandNothing LandOutcome = "nothing"
	// LandFastForwarded: the feature's branch and worktree moved onto the
	// returned work.
	LandFastForwarded LandOutcome = "fast_forwarded"
	// LandConflict: the work was vetted and kept on a branch of its own,
	// because moving the feature onto it would have been more than a
	// fast-forward of a clean worktree.
	LandConflict LandOutcome = "conflict"
)

// ReturnedBranchPrefix is where work that could not be fast-forwarded is
// kept, under the feature's slug. Not under feature.BranchPrefix: a branch
// there would read as another feature's.
const ReturnedBranchPrefix = "cloop/returned/"

// LandRequest is one feature run's returned work.
type LandRequest struct {
	// FeatureDir is the feature's worktree on the hub.
	FeatureDir string
	// Reported is what the executor said the sandbox produced.
	Reported executor.WriteBackResult
	// Bundle is the bundle the executor returned.
	Bundle []byte
	// ShippedHead is the commit the run's tree was built at — the head of
	// the branch Ship produced. Work built on anything else is refused: the
	// hub sent that commit, and a run claiming another base is describing
	// history that did not come from here.
	ShippedHead string
	// Label names the run, for the branch conflicting work is kept on; a
	// timestamp is used when it is empty.
	Label string
	// MaxBytes caps the returned bundle — the same cap the sandbox was told
	// to stay under, enforced again here because the sandbox is the party it
	// constrains. 0 is executor.DefaultWriteBackBundleBytes.
	MaxBytes int64
	// Emit receives progress. May be nil.
	Emit func(string)
}

// LandResult reports what Land did.
type LandResult struct {
	Outcome LandOutcome
	// Branch is the feature's branch.
	Branch string
	// CommitSHA is the returned tip.
	CommitSHA    string
	Commits      int
	FilesChanged int
	// KeptOn is the branch conflicting work was kept on.
	KeptOn string
	// Reason says why the work was kept rather than fast-forwarded.
	Reason string
}

// Describe renders the result for the feature's journal.
func (r LandResult) Describe() string {
	switch r.Outcome {
	case LandFastForwarded:
		return fmt.Sprintf("The run's work was written back: %s fast-forwarded to %s (%d commit(s), %d file(s) changed).",
			r.Branch, executor.ShortSHA(r.CommitSHA), r.Commits, r.FilesChanged)
	case LandConflict:
		return fmt.Sprintf("The run's work came back but was not applied to %s: %s. It was vetted and kept on "+
			"branch %s at %s (%d commit(s)) — merge it into the feature's worktree by hand when you are ready "+
			"(git merge %s). Nothing was forced.",
			r.Branch, r.Reason, r.KeptOn, executor.ShortSHA(r.CommitSHA), r.Commits, r.KeptOn)
	default:
		return "The run made no commits to write back."
	}
}

// labelSafe keeps a run label usable as one component of a branch name.
var labelUnsafe = regexp.MustCompile(`[^A-Za-z0-9_-]+`)

// Land vets a feature run's returned bundle and moves the feature onto it, or
// parks it when that would take more than a fast-forward of a clean worktree.
//
// Refusals — a bundle that is not what the run was sent, or that fails the
// write-back content policy — return an error and leave nothing behind. A
// conflict is not an error: the work exists, vetted, on its own branch, and
// the result says where and why.
func Land(ctx context.Context, req LandRequest) (LandResult, error) {
	var res LandResult
	parent, slug, ok := feature.ParentOf(req.FeatureDir)
	if !ok {
		return res, fmt.Errorf("%w: %s is not a feature", executor.ErrWriteBackUnavailable, req.FeatureDir)
	}
	meta, err := feature.LoadMeta(req.FeatureDir)
	if err != nil {
		return res, fmt.Errorf("%w: the feature's record cannot be read: %v", executor.ErrWriteBackUnavailable, err)
	}
	res.Branch = meta.Branch

	rep := req.Reported
	if rep.Err != "" {
		return res, fmt.Errorf("%w: %s", executor.ErrWriteBackUnavailable, rep.Err)
	}
	if rep.Skipped || !rep.Delivered() {
		res.Outcome = LandNothing
		return res, nil
	}
	// What the run was sent is the only thing it may return onto. Checked
	// before anything is fetched, so a mismatch never reaches the repository.
	reject := func(code executor.WriteBackReason, reason string) (LandResult, error) {
		err := &executor.WriteBackRejection{Branch: rep.Branch, CommitSHA: rep.CommitSHA, Code: code, Reason: reason}
		writeback.RecordOutcome(false, err)
		return res, err
	}
	if strings.TrimSpace(rep.Branch) != meta.Branch {
		return reject(executor.WriteBackReasonBadBranch, fmt.Sprintf(
			"the run returned work on %q, but it was sent the feature's branch %s", rep.Branch, meta.Branch))
	}
	if strings.TrimSpace(rep.BaseSHA) != strings.TrimSpace(req.ShippedHead) {
		return reject(executor.WriteBackReasonBadCommit, fmt.Sprintf(
			"the run returned work built on %s, but its tree was sent at %s",
			executor.ShortSHA(rep.BaseSHA), executor.ShortSHA(req.ShippedHead)))
	}

	limit := req.MaxBytes
	if limit <= 0 || limit > executor.MaxWriteBackBundleBytes {
		limit = executor.DefaultWriteBackBundleBytes
	}
	if n := int64(len(req.Bundle)); n > limit || rep.BundleBytes > limit {
		if rep.BundleBytes > n {
			n = rep.BundleBytes
		}
		err := fmt.Errorf("%w: the returned bundle is %s, over the %s limit for a feature's work "+
			"(executors.feature_bundle_mb); nothing was applied — commit less per run, or raise the limit",
			executor.ErrWriteBackRejected, mib(n), mib(limit))
		writeback.RecordOutcome(false, err)
		return res, err
	}

	v, err := writeback.Vet(ctx, writeback.Request{
		RepoDir:  parent,
		Reported: rep,
		Bundle:   req.Bundle,
		Emit:     req.Emit,
	})
	writeback.RecordOutcome(v == nil && err == nil, err)
	if err != nil {
		return res, err
	}
	if v == nil {
		res.Outcome = LandNothing
		return res, nil
	}
	defer v.Discard()
	res.CommitSHA, res.Commits, res.FilesChanged = v.CommitSHA, v.Commits, len(v.Entries)

	repo, err := newGitRunner(ctx, parent)
	if err != nil {
		return res, fmt.Errorf("%w: %v", executor.ErrWriteBackUnavailable, err)
	}
	conflict := func(reason string) (LandResult, error) {
		kept, err := park(ctx, repo, slug, req.Label, v.CommitSHA)
		if err != nil {
			return res, fmt.Errorf("%w: the returned work could not be fast-forwarded (%s), and keeping it "+
				"on a branch of its own failed too: %v", executor.ErrWriteBackUnavailable, reason, err)
		}
		res.Outcome, res.KeptOn, res.Reason = LandConflict, kept, reason
		return res, nil
	}

	wt, err := newGitRunner(ctx, req.FeatureDir)
	if err != nil {
		return res, fmt.Errorf("%w: %v", executor.ErrWriteBackUnavailable, err)
	}
	branchRef := "refs/heads/" + meta.Branch
	if cur, err := wt.run(ctx, "symbolic-ref", "--quiet", "HEAD"); err != nil || strings.TrimSpace(cur) != branchRef {
		return conflict(fmt.Sprintf("the feature's worktree is not on its branch %s", meta.Branch))
	}
	tip, err := repo.commitOf(ctx, branchRef)
	if err != nil {
		return res, fmt.Errorf("%w: the feature's branch cannot be read: %v", executor.ErrWriteBackUnavailable, err)
	}
	if tip == v.CommitSHA {
		// Landed already — the same run's result collected twice.
		res.Outcome = LandFastForwarded
		return res, nil
	}
	builds, err := repo.isAncestor(ctx, tip, v.CommitSHA)
	if err != nil {
		return res, fmt.Errorf("%w: %v", executor.ErrWriteBackUnavailable, err)
	}
	if !builds {
		return conflict(fmt.Sprintf("the feature's branch moved to %s while the run was out, and the "+
			"returned work does not build on it", executor.ShortSHA(tip)))
	}
	if p := controlDirEntry(v.Entries); p != "" {
		// In the worktree .cloop/ is the hub's own copy of the feature's
		// state; a fast-forward that wrote a tracked file there would replace
		// it, and one that put a file where the directory is would remove it.
		return conflict(fmt.Sprintf("the returned commits change %s, and .cloop/ in the feature's worktree "+
			"is the hub's own project state", p))
	}
	dirty, err := wt.run(ctx, "status", "--porcelain", "--untracked-files=normal")
	if err != nil {
		return res, fmt.Errorf("%w: cannot tell whether the feature's worktree is clean: %v",
			executor.ErrWriteBackUnavailable, err)
	}
	if lines := nonEmptyLines(dirty); len(lines) > 0 {
		return conflict(fmt.Sprintf("the feature's worktree on the hub has uncommitted changes (%s)",
			summarise(lines)))
	}
	if _, err := wt.runIn(ctx, req.FeatureDir, [][2]string{{"merge.verifySignatures", "false"}},
		"merge", "--ff-only", "--no-edit", "--quiet", v.CommitSHA); err != nil {
		return conflict(fmt.Sprintf("git would not fast-forward the worktree: %v", err))
	}
	if now, err := repo.commitOf(ctx, branchRef); err != nil || now != v.CommitSHA {
		return res, fmt.Errorf("%w: the fast-forward left %s at %s, not at %s",
			executor.ErrWriteBackUnavailable, meta.Branch, executor.ShortSHA(now), executor.ShortSHA(v.CommitSHA))
	}
	if req.Emit != nil {
		req.Emit(fmt.Sprintf("writeback: %s fast-forwarded to %s\n", meta.Branch, executor.ShortSHA(v.CommitSHA)))
	}
	res.Outcome = LandFastForwarded
	return res, nil
}

// park keeps vetted work on a branch of its own and returns its name. The
// branch is created, never moved: an existing one with the same name gets the
// commit's short hash appended rather than being overwritten.
func park(ctx context.Context, g *gitRunner, slug, label, commit string) (string, error) {
	label = strings.Trim(labelUnsafe.ReplaceAllString(strings.TrimSpace(label), "-"), "-")
	if label == "" {
		label = time.Now().UTC().Format("20060102-150405")
	}
	if len(label) > 64 {
		label = label[:64]
	}
	base := ReturnedBranchPrefix + slug + "/" + label
	const zero = "0000000000000000000000000000000000000000"
	for _, name := range []string{base, base + "-" + executor.ShortSHA(commit)[:8]} {
		if err := executor.ValidateWriteBackBranch(name); err != nil {
			return "", err
		}
		_, err := g.run(ctx, "update-ref", "-m", "cloop: feature work kept for a manual merge",
			"refs/heads/"+name, commit, zero)
		if err == nil {
			return name, nil
		}
		var ge *gitError
		if !errors.As(err, &ge) {
			return "", err
		}
	}
	return "", fmt.Errorf("branches %s and its fallback already exist", base)
}

// controlDirEntry returns the first changed path that is the project's control
// directory or inside it, or "".
func controlDirEntry(entries []executor.BundleEntry) string {
	for _, e := range entries {
		if e.Path == feature.ControlDir || strings.HasPrefix(e.Path, feature.ControlDir+"/") {
			return e.Path
		}
	}
	return ""
}

func nonEmptyLines(s string) []string {
	var out []string
	for _, l := range strings.Split(s, "\n") {
		if strings.TrimSpace(l) != "" {
			out = append(out, strings.TrimSpace(l))
		}
	}
	return out
}

// summarise lists a few lines of git status for a message.
func summarise(lines []string) string {
	shown := lines
	more := ""
	if len(shown) > 5 {
		more = fmt.Sprintf(" and %d more", len(shown)-5)
		shown = shown[:5]
	}
	return strings.Join(shown, "; ") + more
}
