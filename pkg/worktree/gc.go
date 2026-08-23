// Garbage collection for cloop-managed worktrees (Task 20191).
//
// # What leaked before this file
//
// Create tears down the stale worktree at *its own* task path before
// re-creating it, and Remove deletes the directory while deliberately leaving
// the branch. Both are right in isolation and neither is a sweep: nothing ever
// looked at .cloop/worktrees as a whole. A parallel run that crashed — the hub
// was killed, the machine rebooted, a task panicked between Create and Remove —
// left behind a directory holding a full checkout and a cloop/task-N-<slug>
// branch, and nothing would ever touch either again unless the same task ID
// happened to be re-run. On a repo that runs tasks in parallel for a few weeks
// that is a directory of abandoned checkouts and a branch list nobody can read.
//
// # Why deleting things here is dangerous, and what that buys the API
//
// This package's directory contains the working trees of runs that are
// happening *right now*. A sweep that gets its liveness test wrong does not
// leave litter behind, it deletes a running agent's uncommitted work, and git
// cannot restore what was never committed. Every default in this file is chosen
// on that basis:
//
//   - MinAge defaults to DefaultMinAge rather than to zero, so the zero value
//     of PruneOptions — which is what a caller writes by accident — protects
//     everything recent instead of deleting everything. Disabling the guard
//     takes a negative duration, which nobody types by mistake.
//   - Active/KeepTaskIDs is the authoritative signal and MinAge is the backstop,
//     not the other way round. A caller that knows which tasks are running is
//     expected to say so; mtime is a heuristic (see entryModTime) and is only
//     asked to cover the tasks the caller has forgotten about.
//   - DeleteBranches is off by default and, when on, refuses any branch that is
//     not already merged into the base. An unmerged cloop/task-N branch is the
//     only copy of that task's work, so "delete unmerged work" is not a policy
//     this API offers at any setting.
//   - Errors are per-entry. One worktree wedged by a permission error or a busy
//     mount must not stop the other twenty from being collected, because the
//     sweep that gives up is the sweep that never runs again.
//
// # Why the listing reconciles two sources
//
// `git worktree list` is the source of truth for what git believes, and the
// directory is the source of truth for what is on disk, and the interesting
// cases are exactly the ones where they disagree. A directory with no
// registration is what a `git worktree prune` (or a hand-deleted .git/worktrees
// entry) leaves: git will never mention it again, so a git-only sweep is blind
// to it. A registration with no directory is what a `rm -rf` leaves: there is
// nothing on disk, so a directory-only sweep is blind to it. Both are leaks and
// both are listable here.

package worktree

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// DefaultMinAge is the age below which Prune refuses to touch a worktree when
// the caller did not choose one.
//
// It is a compromise between two failure modes with very different costs. Too
// low and a sweep can delete the tree of a task that is merely thinking — an
// agent waiting on a slow model call writes nothing for minutes at a time, and
// the work it loses is unrecoverable. Too high and leaked directories sit
// around longer, which costs disk. Two hours is long enough to cover any
// plausible quiet period inside a running task and short enough that a daily
// sweep still collects yesterday's crash.
const DefaultMinAge = 2 * time.Hour

var (
	// taskDirRe matches the directory names Path() generates.
	taskDirRe = regexp.MustCompile(`^task-(\d+)$`)
	// cloopBranchRe matches the branch names BranchName() generates. The task
	// ID is captured because it is the only link between a branch and the
	// worktree it belongs to once the directory is gone.
	cloopBranchRe = regexp.MustCompile(`^cloop/task-(\d+)(?:-|$)`)
)

// Entry is one cloop-managed worktree, as reconciled from git's registration
// and from the directory on disk. Either source alone can be missing; see the
// file header for why both cases matter.
type Entry struct {
	// Path is the absolute path of the worktree directory, whether or not it
	// still exists.
	Path string
	// Branch is the branch checked out there, without the refs/heads/ prefix.
	// Empty when git no longer registers the worktree and no single
	// cloop/task-<id>-* branch could be matched to it — see List for why an
	// ambiguous match is deliberately left empty rather than guessed.
	Branch string
	// TaskID is the cloop task this worktree was created for, parsed from the
	// directory name or, failing that, from the branch. Zero means the entry
	// could not be attributed to a task, which makes it invisible to
	// PruneOptions.Active and therefore protected only by MinAge.
	TaskID int
	// DirExists reports whether the directory is on disk.
	DirExists bool
	// Registered reports whether `git worktree list` still knows about it.
	Registered bool
	// Locked reports that the worktree carries git's own lock marker
	// (`git worktree lock`), which is an operator saying "do not collect this".
	// Prune honours it unconditionally.
	Locked bool
	// LockReason is the message passed to `git worktree lock`, if any.
	LockReason string
	// ModTime is the most recent modification observed for this worktree. It is
	// a heuristic, not a liveness signal: see entryModTime.
	ModTime time.Time
}

// String renders an entry for a log line.
func (e Entry) String() string {
	state := "ok"
	switch {
	case !e.DirExists && !e.Registered:
		state = "vanished"
	case !e.DirExists:
		state = "registered but missing from disk"
	case !e.Registered:
		state = "on disk but unregistered"
	}
	return fmt.Sprintf("%s (task %d, branch %q, %s)", e.Path, e.TaskID, e.Branch, state)
}

// List enumerates the cloop-managed worktrees of repoDir, reconciling git's
// registrations with the contents of .cloop/worktrees.
//
// Only entries under <repoDir>/.cloop/worktrees are returned. That containment
// rule is what keeps the main worktree — and any worktree the operator created
// by hand elsewhere — out of a sweep's reach: `git worktree list` reports the
// main working tree first and reports every linked worktree regardless of where
// it lives, so filtering by branch name alone would happily list (and Prune
// would then happily delete) the checkout the operator is sitting in, if they
// happened to have a cloop/task-N branch checked out there.
//
// A failure of `git worktree list` is fatal rather than degraded. The
// alternative — falling back to the directory scan — would report every
// registered worktree as unregistered, which is not a partial answer but a
// wrong one, and Prune acts on it.
func List(repoDir string) ([]Entry, error) {
	if !IsGitRepo(repoDir) {
		return nil, fmt.Errorf("worktree: %q is not a git repository", repoDir)
	}
	registered, err := gitWorktreeList(repoDir)
	if err != nil {
		return nil, err
	}

	root := WorktreesDir(repoDir)
	byPath := make(map[string]*Entry)
	var order []string

	// First writer wins, which is why the registration loop runs first: a
	// worktree that is both registered and on disk must keep the branch and
	// lock state git reported, and the directory scan has neither.
	add := func(e Entry) {
		key := resolvePath(e.Path)
		if _, ok := byPath[key]; ok {
			return
		}
		byPath[key] = &e
		order = append(order, key)
	}

	for _, reg := range registered {
		if !underDir(root, reg.path) {
			continue
		}
		add(Entry{
			Path:       reg.path,
			Branch:     reg.branch,
			Registered: true,
			Locked:     reg.locked,
			LockReason: reg.lockReason,
		})
	}

	// The directory half. Anything sitting in .cloop/worktrees is this
	// package's to account for, including a name that does not parse as
	// task-<id>: an entry with an unrecognised name is still a leak, and
	// omitting it would make it permanently invisible.
	dirents, err := os.ReadDir(root)
	if err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("worktree: read %s: %w", root, err)
	}
	for _, de := range dirents {
		if !de.IsDir() {
			continue
		}
		add(Entry{Path: filepath.Join(root, de.Name()), Registered: false})
	}

	// Both of these are enrichment, and both degrade quietly on failure rather
	// than failing the listing, because both degrade in the safe direction: no
	// admin directory means an entry looks *undateable*, which keepReason turns
	// into "keep", and no branch list means an unregistered checkout's branch
	// stays empty, which pruneBranch turns into "keep the branch". Neither
	// absence can cause something to be deleted that otherwise would not be.
	adminRoot, adminErr := worktreeAdminDir(repoDir)
	branches, branchErr := ListBranches(repoDir)
	byTask := make(map[int][]string)
	if branchErr == nil {
		for _, b := range branches {
			if m := cloopBranchRe.FindStringSubmatch(b); m != nil {
				id, _ := strconv.Atoi(m[1])
				byTask[id] = append(byTask[id], b)
			}
		}
	}

	out := make([]Entry, 0, len(order))
	for _, key := range order {
		e := byPath[key]
		if _, err := os.Stat(e.Path); err == nil {
			e.DirExists = true
		}
		e.TaskID = entryTaskID(*e)
		if e.Branch == "" && e.TaskID > 0 {
			// Recover the branch for a worktree git no longer registers, but
			// only when the match is unambiguous. Two branches for one task ID
			// happen when a task is retitled between runs (the slug changes),
			// and picking one of them would mean DeleteBranches could delete
			// the branch holding the *other* run's only copy of its work.
			if names := byTask[e.TaskID]; len(names) == 1 {
				e.Branch = names[0]
			}
		}
		if adminErr == nil {
			e.ModTime = entryModTime(e.Path, adminRoot)
		} else {
			e.ModTime = entryModTime(e.Path, "")
		}
		out = append(out, *e)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].TaskID != out[j].TaskID {
			return out[i].TaskID < out[j].TaskID
		}
		return out[i].Path < out[j].Path
	})
	return out, nil
}

// ListBranches returns the cloop/task-<id>-* branches of repoDir, ordered by
// task ID.
//
// for-each-ref rather than `git branch --list`: the latter decorates the
// current branch with an asterisk and indents the rest, which is a display
// format that has changed before and would silently start yielding branch
// names with a leading "* " if it changed again.
func ListBranches(repoDir string) ([]string, error) {
	out, err := runGit(repoDir, "for-each-ref", "--format=%(refname:short)", "refs/heads/cloop/")
	if err != nil {
		return nil, err
	}
	var branches []string
	for _, line := range strings.Split(out, "\n") {
		name := strings.TrimSpace(line)
		if name != "" && cloopBranchRe.MatchString(name) {
			branches = append(branches, name)
		}
	}
	sort.Slice(branches, func(i, j int) bool {
		bi, bj := branchTaskID(branches[i]), branchTaskID(branches[j])
		if bi != bj {
			return bi < bj
		}
		return branches[i] < branches[j]
	})
	return branches, nil
}

// KeepCode is the machine-readable reason a worktree was spared. Callers should
// switch on this rather than parse KeptEntry.Reason, which is prose for humans.
type KeepCode string

const (
	// KeepActive: the caller told us this task is running.
	KeepActive KeepCode = "active"
	// KeepTooYoung: the worktree is younger than PruneOptions.MinAge, or its
	// age could not be determined at all.
	KeepTooYoung KeepCode = "too-young"
	// KeepLocked: `git worktree lock` was used on it.
	KeepLocked KeepCode = "locked"
)

// PruneOptions configures a sweep. The zero value is safe: it prunes nothing
// younger than DefaultMinAge and deletes no branches at all.
type PruneOptions struct {
	// DryRun computes and reports the whole plan without changing anything.
	// The merged-branch check still runs, because it is read-only, so a dry run
	// reports the branch deletions a real run would attempt. It cannot report
	// the outcome of git's own second gate — `git branch -d` applies a stricter
	// merged test of its own, against HEAD rather than against BaseBranch — so
	// a real run can keep a branch a dry run listed for deletion. It can never
	// go the other way and delete one a dry run did not list.
	DryRun bool

	// MinAge is the single most important safety property in this package.
	//
	// A live parallel run's worktrees are in this directory *right now*, and
	// pruning one destroys in-flight, uncommitted work that no git operation
	// can bring back. Nothing younger than MinAge is touched under any
	// circumstance.
	//
	// Zero means DefaultMinAge — the zero value of this struct must be safe,
	// because it is what a caller writes when they have not thought about it.
	// A *negative* value disables the guard entirely, which is deliberately
	// something a caller has to type on purpose; it is meant for tests and for
	// an operator who has already established that nothing is running.
	MinAge time.Duration

	// Active names the task IDs that are executing right now. This is the
	// authoritative liveness signal and MinAge is only the backstop for tasks
	// the caller has lost track of: a caller that has a task table should pass
	// it, because mtime cannot distinguish "finished an hour ago" from "still
	// running and quiet for an hour".
	Active map[int]bool

	// KeepTaskIDs is the same instruction in slice form, for callers that have
	// a list rather than a set. The two are unioned; neither overrides the
	// other.
	KeepTaskIDs []int

	// DeleteBranches also removes each collected worktree's cloop/task-N-*
	// branch — but only when that branch's commits are already contained in
	// BaseBranch. An unmerged branch is the only copy of its task's work, so it
	// is kept and the reason recorded. Off by default.
	DeleteBranches bool

	// BaseBranch is the branch a task branch must be merged into before
	// DeleteBranches will remove it. Empty means the current branch of repoDir,
	// which is the branch a task worktree was created from and merged back to.
	BaseBranch string
}

// normalize applies the defaults documented on the fields. It is a value
// receiver returning a copy so a caller's struct is never mutated behind their
// back — a sweep that silently rewrote the options it was handed would make
// DryRun and the real run take different inputs.
func (o PruneOptions) normalize() PruneOptions {
	switch {
	case o.MinAge == 0:
		o.MinAge = DefaultMinAge
	case o.MinAge < 0:
		o.MinAge = 0
	}
	return o
}

// isActive reports whether the caller has claimed this task is running.
// Task ID zero is never active: it means "could not be attributed to a task",
// and treating an unattributable entry as task 0 would let a caller who happens
// to pass 0 in KeepTaskIDs pin every unparseable directory forever.
func (o PruneOptions) isActive(taskID int) bool {
	if taskID <= 0 {
		return false
	}
	if o.Active[taskID] {
		return true
	}
	for _, id := range o.KeepTaskIDs {
		if id == taskID {
			return true
		}
	}
	return false
}

// PrunedEntry is a worktree that was removed, or that a dry run would remove.
type PrunedEntry struct {
	Entry
	// BranchDeleted reports whether the task branch was deleted too.
	BranchDeleted bool
	// BranchKept explains why it was not, and is empty when it was deleted or
	// when DeleteBranches was off. The common value is "not merged", which is
	// the API refusing to destroy the only copy of a task's work.
	BranchKept string
}

// KeptEntry is a worktree the sweep deliberately left alone.
type KeptEntry struct {
	Entry
	Code   KeepCode
	Reason string
}

// PruneError is one entry's failure. The sweep records it and moves on.
type PruneError struct {
	Path   string
	TaskID int
	Err    error
}

func (e *PruneError) Error() string {
	return fmt.Sprintf("worktree %s (task %d): %v", e.Path, e.TaskID, e.Err)
}

func (e *PruneError) Unwrap() error { return e.Err }

// PruneResult reports what a sweep did, what it declined to do, and why.
//
// It reports kept entries as prominently as removed ones on purpose: the
// question an operator actually has after a sweep is "why is this directory
// still full", and a result that only listed successes could not answer it.
type PruneResult struct {
	// DryRun echoes the option, so a caller holding only the result can tell
	// whether Removed describes the past or a plan.
	DryRun bool
	// Removed lists the worktrees collected, or that would be.
	Removed []PrunedEntry
	// Kept lists the worktrees spared, each with the reason.
	Kept []KeptEntry
	// Errors lists per-entry failures. A non-empty Errors does not mean the
	// sweep failed; it means these entries were skipped and the rest were done.
	Errors []*PruneError
}

// Summary renders a one-line report for a startup log.
func (r *PruneResult) Summary() string {
	if r == nil {
		return "worktree gc: no result"
	}
	verb := "removed"
	if r.DryRun {
		verb = "would remove"
	}
	branches := 0
	for _, p := range r.Removed {
		if p.BranchDeleted {
			branches++
		}
	}
	return fmt.Sprintf("worktree gc: %s %d worktree(s) and %d branch(es); kept %d; %d error(s)",
		verb, len(r.Removed), branches, len(r.Kept), len(r.Errors))
}

// Prune removes leaked cloop worktrees from repoDir and, when asked, their
// merged task branches.
//
// The only fatal errors are the ones that make the whole sweep meaningless: a
// repoDir that is not a git repository, or a `git worktree list` that fails. A
// failure on one entry is recorded in PruneResult.Errors and the sweep
// continues, because a single worktree wedged by an open file handle or a
// permission error must not stop the other twenty from being collected.
func Prune(repoDir string, opts PruneOptions) (*PruneResult, error) {
	opts = opts.normalize()
	entries, err := List(repoDir)
	if err != nil {
		return nil, err
	}
	res := &PruneResult{DryRun: opts.DryRun}

	// Resolved once for the whole sweep rather than per entry: it costs two git
	// invocations, and doing it per branch would make a sweep over fifty
	// worktrees fifty times slower for an answer that cannot change mid-sweep.
	var (
		base   string
		merged map[string]bool
	)
	if opts.DeleteBranches {
		base = strings.TrimSpace(opts.BaseBranch)
		if base == "" {
			base, err = currentBranch(repoDir)
			if err != nil {
				return nil, fmt.Errorf("worktree: determine base branch for branch deletion: %w", err)
			}
		}
		merged, err = mergedBranches(repoDir, base)
		if err != nil {
			// Fatal, and deliberately so. Continuing with an empty set would
			// silently keep every branch, which looks like "nothing was merged"
			// and is indistinguishable from the safe outcome — so the operator
			// would never learn that the check never ran.
			return nil, fmt.Errorf("worktree: list branches merged into %q: %w", base, err)
		}
	}

	now := time.Now()
	for _, e := range entries {
		if code, reason, keep := keepReason(opts, e, now); keep {
			res.Kept = append(res.Kept, KeptEntry{Entry: e, Code: code, Reason: reason})
			continue
		}

		pruned := PrunedEntry{Entry: e}
		if !opts.DryRun {
			if err := removeEntry(repoDir, e); err != nil {
				res.Errors = append(res.Errors, &PruneError{Path: e.Path, TaskID: e.TaskID, Err: err})
				continue
			}
		}

		if opts.DeleteBranches {
			pruned.BranchDeleted, pruned.BranchKept = pruneBranch(repoDir, e, base, merged, opts.DryRun)
		}
		res.Removed = append(res.Removed, pruned)
	}
	return res, nil
}

// keepReason decides whether an entry is off limits, and says why.
//
// The order is the order of authority. An explicit "this task is running" beats
// everything, because the caller knows something mtime cannot. A git lock beats
// age, because it is an operator's explicit instruction. Age is last: it is the
// guess that covers what nobody told us about.
func keepReason(opts PruneOptions, e Entry, now time.Time) (KeepCode, string, bool) {
	if opts.isActive(e.TaskID) {
		return KeepActive, fmt.Sprintf("task %d was named as running by the caller", e.TaskID), true
	}
	if e.Locked {
		reason := e.LockReason
		if reason == "" {
			reason = "no reason given"
		}
		return KeepLocked, fmt.Sprintf("git worktree lock is set (%s)", reason), true
	}
	if opts.MinAge <= 0 {
		return "", "", false
	}
	if e.ModTime.IsZero() {
		if e.DirExists {
			// A directory whose age cannot be read is the one case where the
			// age guard has to fail closed: it may be a live run's tree, and
			// the cost of being wrong is unrecoverable work.
			return KeepTooYoung, "the directory's age could not be determined", true
		}
		// No directory and no timestamp of any kind — not even from the git
		// admin directory, which normally survives a deleted checkout. There is
		// nothing on disk left to destroy, so the guard has nothing to guard,
		// and keeping the entry would make a stale registration immortal for
		// any sweep whose MinAge it could never satisfy.
		return "", "", false
	}
	// Note what is deliberately *not* special-cased here: a registration whose
	// directory is missing but whose admin directory is recent is still spared.
	// That is the shape a `git worktree add` in flight has for the moment
	// between git writing its bookkeeping and the checkout appearing, and
	// collecting it would make a concurrent Create fail. Age is what tells the
	// two apart.
	if age := now.Sub(e.ModTime); age < opts.MinAge {
		return KeepTooYoung, fmt.Sprintf("last modified %s ago, under the %s minimum age",
			age.Round(time.Second), opts.MinAge), true
	}
	return "", "", false
}

// removeEntry tears one worktree down and verifies it is really gone.
//
// The verification is the point. forceRemoveWorktree is best-effort by design
// (it swallows git's error whenever the filesystem removal succeeded), which is
// right for its callers in Create but wrong for a sweep: reporting a removal
// that did not happen would let a caller conclude the disk had been reclaimed
// while the tree is still sitting there. The stat is the honest check, and it
// also covers the registration case, since `git worktree prune` — which
// forceRemoveWorktree always runs — unregisters exactly those worktrees whose
// directory has gone.
func removeEntry(repoDir string, e Entry) error {
	if err := forceRemoveWorktree(repoDir, e.Path); err != nil {
		return err
	}
	if _, err := os.Stat(e.Path); err == nil {
		return fmt.Errorf("the directory is still present after git worktree remove and rm -rf")
	}
	return nil
}

// pruneBranch deletes an entry's task branch when — and only when — its
// commits are already contained in base.
//
// Two independent gates stand between this function and destroying work, and
// that redundancy is deliberate. The first is the `merged` set computed from
// `git for-each-ref --merged`, which is this package deciding. The second is
// `git branch -d`, which refuses an unmerged branch on its own authority; `-D`
// is never used anywhere in this package, so a bug in the first gate still
// cannot delete unmerged work.
//
// Squash-merged branches are kept, and that is the intended trade. A squash
// merge produces a commit that is not a descendant of the branch, so no
// ancestry test can see the relationship; `git cherry`'s patch-id matching does
// not recover it either, because the squash is one commit and the branch is
// several. The cost of keeping a branch that was in fact merged is a stale ref;
// the cost of deleting one that was not is somebody's work. The API errs
// towards the ref.
func pruneBranch(repoDir string, e Entry, base string, merged map[string]bool, dryRun bool) (deleted bool, kept string) {
	if e.Branch == "" {
		return false, "no branch could be attributed to this worktree"
	}
	if !cloopBranchRe.MatchString(e.Branch) {
		// Refuse anything outside this package's own namespace. A worktree
		// under .cloop/worktrees with, say, `main` checked out is not something
		// a cloop sweep gets to delete the branch of.
		return false, fmt.Sprintf("%q is not a cloop task branch", e.Branch)
	}
	if e.Branch == base {
		return false, "it is the base branch"
	}
	if !merged[e.Branch] {
		return false, fmt.Sprintf("it is not merged into %q, so it holds the only copy of task %d's work",
			base, e.TaskID)
	}
	if dryRun {
		return true, ""
	}
	if out, err := runGit(repoDir, "branch", "-d", e.Branch); err != nil {
		// Reported as "kept", not as a sweep error. git refusing to delete a
		// branch is the safe outcome — most often because base is not the
		// checked-out branch, which makes `-d` apply its own stricter test —
		// and surfacing it as an error would fill an operator's log with
		// failures for something that worked exactly as intended.
		return false, fmt.Sprintf("git refused to delete it: %s", strings.TrimSpace(out))
	}
	return true, ""
}

// mergedBranches returns the set of cloop task branches whose commits are all
// contained in base.
func mergedBranches(repoDir, base string) (map[string]bool, error) {
	out, err := runGit(repoDir, "for-each-ref", "--merged", base,
		"--format=%(refname:short)", "refs/heads/cloop/")
	if err != nil {
		return nil, err
	}
	set := make(map[string]bool)
	for _, line := range strings.Split(out, "\n") {
		if name := strings.TrimSpace(line); name != "" {
			set[name] = true
		}
	}
	return set, nil
}

// WorktreesDir is the directory this package owns: the only place Prune will
// remove anything from. Exported so a caller wiring a startup sweep can log it
// (and so a test can assert that Prune's blast radius is what it claims).
func WorktreesDir(repoDir string) string {
	return filepath.Join(repoDir, ".cloop", "worktrees")
}

// --- git plumbing -----------------------------------------------------

// registration is one record from `git worktree list --porcelain`, reduced to
// the fields a sweep acts on. The format carries `detached`, `bare` and
// `prunable` too; none of them changes a decision here, because a detached
// worktree simply has no branch (which Entry.Branch already renders as empty),
// a bare repository is never under .cloop/worktrees, and `prunable` says
// nothing Entry.DirExists does not.
type registration struct {
	path       string
	branch     string
	locked     bool
	lockReason string
}

// gitWorktreeList parses `git worktree list --porcelain`.
//
// Porcelain rather than the human format because the human format aligns
// columns and abbreviates the SHA, and a path containing a space is
// unparseable from it. Records are separated by blank lines; each line is a
// key, optionally followed by one space and a value that runs to end of line —
// which is why the split below is on the first space only, and why a `locked`
// with no reason has to be handled as a bare key.
func gitWorktreeList(repoDir string) ([]registration, error) {
	out, err := runGit(repoDir, "worktree", "list", "--porcelain")
	if err != nil {
		return nil, err
	}
	var (
		all []registration
		cur registration
		got bool
	)
	flush := func() {
		if got && cur.path != "" {
			all = append(all, cur)
		}
		cur, got = registration{}, false
	}
	for _, raw := range strings.Split(out, "\n") {
		line := strings.TrimRight(raw, "\r")
		if strings.TrimSpace(line) == "" {
			flush()
			continue
		}
		key, value, _ := strings.Cut(line, " ")
		switch key {
		case "worktree":
			flush()
			cur.path = value
			got = true
		case "branch":
			cur.branch = strings.TrimPrefix(value, "refs/heads/")
		case "locked":
			cur.locked = true
			cur.lockReason = value
		}
	}
	flush()
	return all, nil
}

// worktreeAdminDir returns <git-common-dir>/worktrees, where git keeps the
// per-worktree bookkeeping. Used only as a secondary mtime source for a
// worktree whose directory has gone.
func worktreeAdminDir(repoDir string) (string, error) {
	out, err := runGit(repoDir, "rev-parse", "--git-common-dir")
	if err != nil {
		return "", err
	}
	common := strings.TrimSpace(out)
	if common == "" {
		return "", fmt.Errorf("worktree: git reported no common dir for %q", repoDir)
	}
	if !filepath.IsAbs(common) {
		common = filepath.Join(repoDir, common)
	}
	return filepath.Join(common, "worktrees"), nil
}

// --- age -------------------------------------------------------------

// entryModTime estimates when a worktree was last touched.
//
// It is explicitly an estimate, and the estimate is the reason MinAge is only
// the backstop and PruneOptions.Active is the authority. A directory's own
// mtime changes when entries are created or removed *in that directory*, not
// when a file three levels down is edited, so an agent quietly rewriting
// pkg/foo/bar.go for an hour does not move the worktree root's mtime at all.
//
// Two cheap sources are combined to blunt that:
//
//   - the worktree root and its immediate children, which catches the common
//     shapes (a new file at the top level, a rewritten README, a touched
//     .git pointer file);
//   - the git admin directory for this worktree, whose HEAD and index are
//     rewritten by every commit, checkout and index refresh, so an active
//     run moves it even when its edits are deep in the tree. It is also the
//     only source left when the directory itself has been deleted.
//
// A full recursive walk was rejected: it is O(size of every checkout) on every
// sweep, on a path that runs at hub startup, to refine a signal that a caller
// with a task table should not be relying on in the first place.
func entryModTime(path, adminRoot string) time.Time {
	newest := newestInDir(path)
	if adminRoot != "" {
		if admin := newestInDir(filepath.Join(adminRoot, filepath.Base(path))); admin.After(newest) {
			newest = admin
		}
	}
	return newest
}

// newestInDir returns the newest mtime among dir itself and its immediate
// children, or the zero time when dir cannot be read.
func newestInDir(dir string) time.Time {
	info, err := os.Stat(dir)
	if err != nil {
		return time.Time{}
	}
	newest := info.ModTime()
	entries, err := os.ReadDir(dir)
	if err != nil {
		return newest
	}
	for _, de := range entries {
		fi, err := de.Info()
		if err != nil {
			continue
		}
		if fi.ModTime().After(newest) {
			newest = fi.ModTime()
		}
	}
	return newest
}

// --- path and id helpers ----------------------------------------------

// entryTaskID attributes an entry to a task, preferring the directory name
// because that is what Path() generates and what survives a branch rename.
func entryTaskID(e Entry) int {
	if m := taskDirRe.FindStringSubmatch(filepath.Base(e.Path)); m != nil {
		id, err := strconv.Atoi(m[1])
		if err == nil {
			return id
		}
	}
	return branchTaskID(e.Branch)
}

// branchTaskID parses the task ID out of a cloop branch name, or returns 0.
func branchTaskID(branch string) int {
	if m := cloopBranchRe.FindStringSubmatch(branch); m != nil {
		if id, err := strconv.Atoi(m[1]); err == nil {
			return id
		}
	}
	return 0
}

// resolvePath renders p in a form two spellings of the same location agree on.
//
// It matters because the two listing sources spell paths differently: git
// reports the path it recorded at `worktree add` time, while the directory scan
// builds one by joining repoDir. On a host where the repo sits under a symlink
// — /tmp on macOS, /home on some NFS setups — those differ textually while
// naming the same directory, and treating them as two entries would make the
// sweep try to remove the same worktree twice and report the second attempt as
// a leak.
//
// EvalSymlinks fails for a path that no longer exists, which is the normal case
// for the registration-with-no-directory leak; the cleaned absolute path is
// then the best available answer and is stable for the duration of a sweep.
func resolvePath(p string) string {
	if abs, err := filepath.Abs(p); err == nil {
		p = abs
	}
	if real, err := filepath.EvalSymlinks(p); err == nil {
		return filepath.Clean(real)
	}
	return filepath.Clean(p)
}

// underDir reports whether child lies inside parent, comparing both the literal
// and the symlink-resolved spellings of each. It never reports true for
// parent == child: the containing directory is not one of its own entries.
func underDir(parent, child string) bool {
	candidates := map[string]struct{}{
		filepath.Clean(parent): {},
		resolvePath(parent):    {},
	}
	for _, c := range []string{filepath.Clean(child), resolvePath(child)} {
		for p := range candidates {
			rel, err := filepath.Rel(p, c)
			if err != nil {
				continue
			}
			if rel != "." && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
				return true
			}
		}
	}
	return false
}
