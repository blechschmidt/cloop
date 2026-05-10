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
	"os/exec"
	"strings"
	"sync"
	"time"
)

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

	mu      sync.Mutex
	jobs    chan job
	started bool
	stopped bool
	stop    chan struct{}
	done    chan struct{}
}

type job struct {
	req Request
	res *Result
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
