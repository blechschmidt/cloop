// Package mergequeue serializes git merges of task branches back to a base
// branch. Multiple parallel tasks can produce divergent commits on independent
// worktree branches; the merge queue drains them one at a time so each merge
// sees a clean, up-to-date base and conflicts (if any) surface against a
// well-defined parent.
//
// Usage:
//
//	q := mergequeue.New(repoDir, baseBranch)
//	q.Start(ctx)
//	defer q.Stop()
//	res := q.Submit(mergequeue.Request{Branch: "cloop/task-42-foo", TaskID: 42})
//	<-res.Done
//	if res.Err != nil { ... }
//
// A single internal goroutine processes requests in FIFO order so the merges
// happen one after the other without conflicts (each subsequent merge sees the
// previous merge's commits already on the base branch).
package mergequeue

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Resolver attempts to automatically resolve a git merge conflict.
//
// The Queue calls Resolve after `git merge` reports a conflict and before
// running `git merge --abort`. The implementation receives the list of
// conflicted files (with conflict markers intact) and returns the resolved
// contents for any file it was able to handle. The Queue then writes those
// files back, stages them, and finishes the merge via `git commit`. If
// Resolve returns an error, returns fewer resolutions than conflicts, or any
// resolution still contains conflict markers, the Queue aborts the merge so
// the original "leave branch for manual resolution" behaviour is preserved.
//
// Implementations must be safe for concurrent calls — the Queue serializes
// merges itself, but a Resolver may be shared across queues.
type Resolver interface {
	Resolve(ctx context.Context, info ResolveInfo, files []ConflictFile) ([]ResolvedFile, error)
}

// ResolveInfo gives the Resolver the merge context it needs to make sensible
// choices when the two sides disagree on the same line.
type ResolveInfo struct {
	BaseBranch   string
	SourceBranch string
	TaskID       int
	TaskTitle    string
}

// ConflictFile is one entry in the set the Resolver is asked to fix. Content
// is the on-disk file with `<<<<<<<`, `=======`, `>>>>>>>` markers intact.
type ConflictFile struct {
	Path    string
	Content string
}

// ResolvedFile is the Resolver's verdict for a single ConflictFile. Path must
// match the input ConflictFile.Path; Content is the fully-merged file body
// with no conflict markers and ends with a newline.
type ResolvedFile struct {
	Path    string
	Content string
}

// Request is a single merge job submitted to the queue.
type Request struct {
	// Branch is the source branch to merge into BaseBranch (e.g. cloop/task-42-foo).
	Branch string
	// TaskID is the cloop task this branch corresponds to (for logging).
	TaskID int
	// Title is a short human-readable label used in the merge commit message.
	Title string
}

// Result reports the outcome of a single merge. Callers wait on Done.
type Result struct {
	// Done is closed once the merge has been attempted.
	Done chan struct{}
	// Err is nil on success, or describes the merge failure (conflict, abort, etc.).
	// Safe to read after Done is closed.
	Err error
	// CommitSHA is the SHA of the merge commit (or "" when nothing was merged).
	CommitSHA string
}

// Queue serializes git merges back to BaseBranch.
type Queue struct {
	RepoDir    string
	BaseBranch string

	// MergeTimeout bounds how long any single git merge / abort step is allowed
	// to run. Defaults to 2 minutes when zero.
	MergeTimeout time.Duration

	mu       sync.Mutex
	resolver Resolver
	jobs     chan job
	started  bool
	stopped  bool
	stop     chan struct{}
	done     chan struct{}
}

type job struct {
	req Request
	res *Result
}

// SetResolver installs an automatic conflict resolver. Pass nil to remove a
// previously-installed resolver. Safe to call before or after Start; the
// worker reads the field under a mutex on each merge.
func (q *Queue) SetResolver(r Resolver) {
	q.mu.Lock()
	q.resolver = r
	q.mu.Unlock()
}

// currentResolver returns the installed Resolver (or nil) under the mutex.
func (q *Queue) currentResolver() Resolver {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.resolver
}

// New returns a Queue ready to be Start()ed. baseBranch is the branch that all
// task branches are merged back into.
func New(repoDir, baseBranch string) *Queue {
	return &Queue{
		RepoDir:      repoDir,
		BaseBranch:   baseBranch,
		MergeTimeout: 2 * time.Minute,
		jobs:         make(chan job, 64),
		stop:         make(chan struct{}),
		done:         make(chan struct{}),
	}
}

// Start launches the background worker. Safe to call once.
// If ctx is cancelled the worker drains in-flight submissions and exits.
func (q *Queue) Start(ctx context.Context) {
	q.mu.Lock()
	if q.started {
		q.mu.Unlock()
		return
	}
	q.started = true
	q.mu.Unlock()

	go q.run(ctx)
}

// Stop signals the worker to drain and exit. Blocks until the worker has
// finished. Safe to call multiple times.
func (q *Queue) Stop() {
	q.mu.Lock()
	if !q.started || q.stopped {
		q.mu.Unlock()
		return
	}
	q.stopped = true
	close(q.stop)
	q.mu.Unlock()
	<-q.done
}

// Submit enqueues a merge request. The returned Result.Done channel is closed
// when the merge has been attempted. If the queue has been stopped, the result
// is returned pre-closed with an error.
func (q *Queue) Submit(req Request) *Result {
	res := &Result{Done: make(chan struct{})}
	q.mu.Lock()
	stopped := q.stopped
	q.mu.Unlock()
	if stopped {
		res.Err = errors.New("mergequeue: queue stopped")
		close(res.Done)
		return res
	}
	select {
	case q.jobs <- job{req: req, res: res}:
	case <-q.stop:
		res.Err = errors.New("mergequeue: queue stopped")
		close(res.Done)
	}
	return res
}

// run is the worker goroutine. Processes jobs strictly in FIFO order so each
// merge sees the cumulative result of all prior merges.
func (q *Queue) run(ctx context.Context) {
	defer close(q.done)
	for {
		select {
		case <-ctx.Done():
			q.drain(ctx.Err())
			return
		case <-q.stop:
			q.drain(errors.New("mergequeue: queue stopped"))
			return
		case j, ok := <-q.jobs:
			if !ok {
				return
			}
			sha, err := q.mergeOne(ctx, j.req)
			j.res.CommitSHA = sha
			j.res.Err = err
			close(j.res.Done)
		}
	}
}

// drain rejects any remaining queued jobs with err so callers waiting on
// Done don't block forever after a stop/cancel.
func (q *Queue) drain(err error) {
	for {
		select {
		case j := <-q.jobs:
			j.res.Err = err
			close(j.res.Done)
		default:
			return
		}
	}
}

// mergeOne executes a single git merge of req.Branch into BaseBranch. On
// conflict it runs `git merge --abort` so the working tree is restored, and
// returns a descriptive error. The merge uses --no-ff so each task always
// produces a visible merge commit in the history.
func (q *Queue) mergeOne(ctx context.Context, req Request) (string, error) {
	if req.Branch == "" {
		return "", errors.New("mergequeue: empty branch")
	}
	if q.BaseBranch == "" {
		return "", errors.New("mergequeue: empty base branch")
	}

	timeout := q.MergeTimeout
	if timeout <= 0 {
		timeout = 2 * time.Minute
	}

	// Always operate from BaseBranch in the main worktree. If we're somewhere
	// else (e.g. a previous task was merged from a detached HEAD), checkout.
	if _, err := q.git(ctx, timeout, "checkout", q.BaseBranch); err != nil {
		return "", fmt.Errorf("mergequeue: checkout %q: %w", q.BaseBranch, err)
	}

	// Compose a descriptive merge commit message.
	msg := fmt.Sprintf("Merge branch '%s' into %s (cloop task %d)", req.Branch, q.BaseBranch, req.TaskID)
	if strings.TrimSpace(req.Title) != "" {
		msg = fmt.Sprintf("Merge branch '%s' into %s (cloop task %d: %s)", req.Branch, q.BaseBranch, req.TaskID, req.Title)
	}

	if _, err := q.git(ctx, timeout, "merge", "--no-ff", "-m", msg, req.Branch); err != nil {
		// Merge failed. If the failure is a content conflict and a Resolver is
		// installed, give the AI a chance to fix the conflicted files in
		// place. On success we stage the resolutions and commit the merge so
		// the queue's invariants hold (each subsequent merge sees a clean
		// base). On any failure we fall through to `git merge --abort` and
		// surface the original error.
		if resolver := q.currentResolver(); resolver != nil {
			if sha, rerr := q.tryAutoResolve(ctx, timeout, req, msg, resolver); rerr == nil {
				return sha, nil
			}
		}
		// Conflict (or any merge failure) — abort to leave the tree clean,
		// then return the original error so callers know the merge did not
		// land. Without the abort the working tree would be stuck in a
		// MERGING state, breaking the next task's checkout.
		_, _ = q.git(ctx, timeout, "merge", "--abort")
		return "", fmt.Errorf("mergequeue: merge %q into %q failed: %w", req.Branch, q.BaseBranch, err)
	}

	sha, err := q.git(ctx, timeout, "rev-parse", "HEAD")
	if err != nil {
		return "", fmt.Errorf("mergequeue: rev-parse HEAD: %w", err)
	}
	return strings.TrimSpace(sha), nil
}

// tryAutoResolve attempts to drive a conflicted merge to completion by
// delegating to the installed Resolver. The function inspects the index for
// "both modified" entries (UU), reads their on-disk content (with markers),
// calls the resolver, and on success writes the resolutions back, stages
// them, and commits the merge. Any structural conflict (add/add, deletes,
// renames) causes a clean failure — those need human attention.
//
// On any failure the caller is responsible for `git merge --abort`. This
// function leaves the merge in a mid-state intentionally so the caller can
// log and recover uniformly.
func (q *Queue) tryAutoResolve(ctx context.Context, timeout time.Duration, req Request, mergeMsg string, resolver Resolver) (string, error) {
	conflicts, err := q.collectConflicts(ctx, timeout)
	if err != nil {
		return "", err
	}
	if len(conflicts) == 0 {
		// Not a content conflict (could be a hook failure, dirty tree, etc.).
		// Don't try to "resolve" anything — let the caller abort.
		return "", errors.New("mergequeue: merge failed without conflicted files")
	}
	info := ResolveInfo{
		BaseBranch:   q.BaseBranch,
		SourceBranch: req.Branch,
		TaskID:       req.TaskID,
		TaskTitle:    req.Title,
	}
	resolutions, err := resolver.Resolve(ctx, info, conflicts)
	if err != nil {
		return "", fmt.Errorf("mergequeue: resolver: %w", err)
	}
	if len(resolutions) != len(conflicts) {
		return "", fmt.Errorf("mergequeue: resolver returned %d/%d files", len(resolutions), len(conflicts))
	}
	byPath := make(map[string]ResolvedFile, len(resolutions))
	for _, r := range resolutions {
		byPath[r.Path] = r
	}
	for _, c := range conflicts {
		r, ok := byPath[c.Path]
		if !ok {
			return "", fmt.Errorf("mergequeue: resolver omitted %q", c.Path)
		}
		if containsConflictMarkers(r.Content) {
			return "", fmt.Errorf("mergequeue: resolver left conflict markers in %q", c.Path)
		}
		abs := filepath.Join(q.RepoDir, c.Path)
		if err := os.MkdirAll(filepath.Dir(abs), 0o755); err != nil {
			return "", fmt.Errorf("mergequeue: mkdir for resolved file: %w", err)
		}
		if err := os.WriteFile(abs, []byte(r.Content), 0o644); err != nil {
			return "", fmt.Errorf("mergequeue: write resolved %q: %w", c.Path, err)
		}
		if _, err := q.git(ctx, timeout, "add", "--", c.Path); err != nil {
			return "", fmt.Errorf("mergequeue: stage resolved %q: %w", c.Path, err)
		}
	}
	commitMsg := mergeMsg + "\n\nConflicts auto-resolved by cloop AI resolver."
	if _, err := q.git(ctx, timeout, "commit", "--no-edit", "-m", commitMsg); err != nil {
		return "", fmt.Errorf("mergequeue: commit auto-resolved merge: %w", err)
	}
	sha, err := q.git(ctx, timeout, "rev-parse", "HEAD")
	if err != nil {
		return "", fmt.Errorf("mergequeue: rev-parse after auto-resolve: %w", err)
	}
	return strings.TrimSpace(sha), nil
}

// collectConflicts returns the set of "both modified" (UU) files git reports
// in the index after a failed merge, paired with their on-disk content. Any
// other conflict status (add/add, modify/delete, rename/rename, etc.) is
// treated as a structural conflict the resolver should not silently touch —
// the function returns an error in that case so the caller aborts.
func (q *Queue) collectConflicts(ctx context.Context, timeout time.Duration) ([]ConflictFile, error) {
	// `git status --porcelain` emits a two-char XY status code followed by
	// the path. For unmerged content conflicts both X and Y are 'U'.
	out, err := q.git(ctx, timeout, "status", "--porcelain")
	if err != nil {
		return nil, fmt.Errorf("mergequeue: status: %w", err)
	}
	var conflicts []ConflictFile
	for _, line := range strings.Split(out, "\n") {
		if len(line) < 4 {
			continue
		}
		code := line[:2]
		path := strings.TrimSpace(line[3:])
		// Quoted paths can occur when names contain special chars; refuse to
		// touch those to avoid mis-parsing.
		if strings.HasPrefix(path, "\"") {
			return nil, fmt.Errorf("mergequeue: quoted path in status output (%q) — refusing auto-resolve", path)
		}
		switch code {
		case "UU":
			abs := filepath.Join(q.RepoDir, path)
			content, rerr := os.ReadFile(abs)
			if rerr != nil {
				return nil, fmt.Errorf("mergequeue: read conflicted %q: %w", path, rerr)
			}
			conflicts = append(conflicts, ConflictFile{Path: path, Content: string(content)})
		case "AA", "DD", "AU", "UA", "DU", "UD":
			// Structural conflict — out of scope for AI auto-resolve.
			return nil, fmt.Errorf("mergequeue: structural conflict %s on %q — manual merge required", strings.TrimSpace(code), path)
		}
	}
	return conflicts, nil
}

// containsConflictMarkers reports whether s still has any of the standard
// `<<<<<<<`/`=======`/`>>>>>>>` markers at the start of a line. A single
// false negative is acceptable (the next merge will fail loudly); a false
// positive on legitimate documentation text would block valid resolutions
// so we require the marker to appear at line start.
func containsConflictMarkers(s string) bool {
	for _, line := range strings.Split(s, "\n") {
		switch {
		case strings.HasPrefix(line, "<<<<<<< "),
			line == "=======",
			strings.HasPrefix(line, ">>>>>>> "):
			return true
		}
	}
	return false
}

// git executes a git command in q.RepoDir with a bounded timeout.
func (q *Queue) git(parent context.Context, timeout time.Duration, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "git", args...)
	cmd.Dir = q.RepoDir
	out, err := cmd.CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("git %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return string(out), nil
}
