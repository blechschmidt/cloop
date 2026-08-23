// startup.go: what a control plane does about the mess left by the control
// plane it is replacing (Task 20191).
//
// Rehydration — teaching each driver to reattach to workloads it dispatched
// before the restart — lives in the drivers, because only a driver knows how
// to re-open `docker logs -f` or re-watch a Pod. This file owns the three
// things that are left over afterwards, none of which any single driver can
// see:
//
//	(1) session rows still marked `running` whose handle nothing owns. Drain
//	    counts these, so one stale row makes `cloop executor drain` and the UI
//	    drain button time out forever on that executor.
//	(2) orphaned containers and Pods, from drivers whose handle rows do not
//	    account for them.
//	(3) task worktrees and their branches, leaked by a parallel run that was
//	    killed between `git worktree add` and its merge.
//
// Ordering between them is not incidental and is enforced by Sweep:
// rehydration must have already run (it happens during driver construction,
// which FromConfig does before it calls in here), then sessions are settled,
// and only then are worktrees pruned — because the set of task IDs that are
// still legitimately running is exactly the set of sessions that survived
// step (1). Pruning first would delete the worktree of a task that is still
// being worked on, which is unrecoverable.
//
// Every step is best-effort and independently recoverable. A hub whose state
// database is momentarily locked must still come up: it just comes up with
// the mess still there, and sweeps it on the next restart.

package reconcile

import (
	"context"
	"errors"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/executor/container"
	"github.com/blechschmidt/cloop/pkg/executor/kubernetes"
	"github.com/blechschmidt/cloop/pkg/executorstore"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
	"github.com/blechschmidt/cloop/pkg/worktree"
)

// sweepTimeout bounds the whole restart sweep. It is generous because the
// expensive parts are runtime and API round-trips against backends that may
// be slow, and cheap to abandon because everything in here is idempotent: a
// sweep that runs out of time leaves the residue for the next restart rather
// than leaving anything half-done.
const sweepTimeout = 2 * time.Minute

// handleStoreAttacher is implemented by every driver that can adopt persisted
// handles. It is declared here rather than in pkg/executor because it is a
// wiring concern: pkg/executor defines what a store *is*, and this package
// decides which registered drivers get one.
//
// Matching structurally rather than type-switching over the four concrete
// drivers is deliberate. localprocess is a process-wide singleton registered
// from three different entry points and remote executors appear when a device
// dials in, so the set of drivers needing a store is not knowable from this
// file's imports — and a type switch would silently skip any driver added
// later, reintroducing exactly the bug this task fixes.
type handleStoreAttacher interface {
	AttachHandleStore(executor.HandleStore)
}

var (
	handleStoreMu    sync.Mutex
	handleStoreCache = map[string]executor.HandleStore{}
)

// handleStore resolves the store for dir, honouring an explicit override and
// the opt-out, and caching the default one per directory.
//
// The cache exists because FromConfig is idempotent and called repeatedly —
// Bootstrap alone calls it twice — and each miss would otherwise open another
// SQLite handle that nothing ever closes. Keyed by the absolute directory so
// two spellings of the same path share one handle.
//
// The handle is deliberately never closed, matching the Kubernetes driver's
// credential source: a driver holds its store for as long as the process
// runs and needs it on every Start. Process exit closes it, which for both a
// CLI invocation and a long-running hub is the intended lifetime.
func (o Options) handleStore(dir string) executor.HandleStore {
	if o.DisableHandleStore {
		return nil
	}
	if o.HandleStore != nil {
		return o.HandleStore
	}
	if strings.TrimSpace(dir) == "" {
		return nil
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		abs = dir
	}

	handleStoreMu.Lock()
	defer handleStoreMu.Unlock()
	if st, ok := handleStoreCache[abs]; ok {
		return st
	}
	db, err := statedb.Open(state.DBPath(abs))
	if err != nil {
		// Not fatal, and not even loud on the common path: a `cloop` command
		// run outside a project has no database and wants no persistence.
		// What it costs is that this process cannot survive its own restart,
		// which is the pre-Task-20191 behaviour.
		o.logf("executor: handle persistence unavailable (%v); "+
			"workloads dispatched by this process will not survive a restart", err)
		handleStoreCache[abs] = nil
		return nil
	}
	st, err := executorstore.NewHandles(db)
	if err != nil {
		_ = db.Close()
		o.logf("executor: handle persistence unavailable: %v", err)
		handleStoreCache[abs] = nil
		return nil
	}
	handleStoreCache[abs] = st
	return st
}

// attachHandleStores hands the store to every registered driver that can take
// one, so drivers registered outside this package — the localprocess
// singleton, and a remote executor whose device dialled in — rehydrate too.
//
// Drivers built by this package already receive the store through their
// Options and rehydrated during construction; their AttachHandleStore is
// documented idempotent, so passing it again is a no-op rather than a
// double-adopt.
func attachHandleStores(reg *executor.Registry, store executor.HandleStore) {
	if store == nil || reg == nil {
		return
	}
	for _, ex := range reg.List() {
		if a, ok := ex.(handleStoreAttacher); ok {
			a.AttachHandleStore(store)
		}
	}
}

// Sweep reconciles the durable residue of a control plane that died mid-run.
//
// It is safe to call on every start and does nothing a second time: closed
// session rows stay closed, reaped containers stay reaped, and a pruned
// worktree is gone. It never returns an error — a hub must come up whether or
// not it could tidy up — and reports what it did through opts.Logf.
func Sweep(ctx context.Context, dir string, opts Options) {
	defer func() {
		if r := recover(); r != nil {
			opts.logf("executor: panic during restart sweep: %v", r)
		}
	}()
	if strings.TrimSpace(dir) == "" {
		return
	}
	if ctx == nil {
		ctx = context.Background()
	}
	ctx, cancel := context.WithTimeout(ctx, sweepTimeout)
	defer cancel()

	// Sessions before worktrees: the surviving sessions are what tells the
	// worktree sweep which task IDs are still legitimately in flight.
	active := sweepSessions(ctx, dir, opts)
	pruneWorktrees(dir, active, opts)
}

// sweepSessions closes `running` session rows whose workload no longer exists,
// and returns the project→task IDs that survived.
//
// This is consequence (b) of Task 20191. openSessionFor writes a `running`
// row and an in-memory goroutine closes it; a hub that dies takes that
// goroutine with it. Nothing else ever touched those rows: RunningSessions is
// called from exactly one place, inside failOver, reachable only from a live
// healthy→unreachable transition — and a restarted hub sees its local and
// container executors as healthy, so no transition fires. WaitForDrain loops
// on CountRunning until zero, so a single stale row made drain time out
// forever on that executor.
//
// The test applied to each row is "does its executor still own its handle?",
// which is only answerable *after* rehydration, and which is why this runs
// from FromConfig rather than from the supervisor. Three outcomes:
//
//   - the executor is registered and reports a live handle: the row is real,
//     rehydration adopted the workload, leave it alone. Its task ID is
//     returned so the worktree sweep spares it.
//   - the executor is registered and does not know the handle: the workload
//     is gone. Close the row with the terminal state the driver reports, or
//     failed when it reports nothing.
//   - the executor is not registered at all: it was removed from config, or
//     is an edge device that has not dialled back in. Closing the row is
//     still right — the *session* is over either way, and a device that
//     reconnects opens a new one — but it is recorded as failed rather than
//     finished, because we genuinely do not know how the work ended.
func sweepSessions(ctx context.Context, dir string, opts Options) map[string]map[int]bool {
	active := map[string]map[int]bool{}

	db, err := statedb.Open(state.DBPath(dir))
	if err != nil {
		// No database means no sessions to reconcile, which is the normal
		// case for a directory that has never run anything.
		return active
	}
	defer db.Close()

	sched, err := executorstore.NewScheduler(db)
	if err != nil {
		opts.logf("executor: could not reconcile in-flight sessions: %v", err)
		return active
	}
	sessions, err := sched.RunningSessions("")
	if err != nil {
		opts.logf("executor: could not list in-flight sessions: %v", err)
		return active
	}
	if len(sessions) == 0 {
		return active
	}

	reg := opts.registry()
	now := time.Now().UTC()
	var closed, kept int
	for _, sess := range sessions {
		if ctx.Err() != nil {
			opts.logf("executor: session sweep stopped early: %v", ctx.Err())
			break
		}
		state, live := sessionOutcome(ctx, reg, sess)
		if live {
			kept++
			if sess.TaskID > 0 {
				if active[sess.ProjectPath] == nil {
					active[sess.ProjectPath] = map[int]bool{}
				}
				active[sess.ProjectPath][sess.TaskID] = true
			}
			continue
		}
		// A row already claimed by a failover has left `running` between the
		// listing and here, and closing it again would be a no-op at best.
		// ErrExecutorSessionNotFound is therefore expected, not a problem.
		if err := sched.CloseSession(sess.ID, state, now); err != nil &&
			!errors.Is(err, statedb.ErrExecutorSessionNotFound) {
			opts.logf("executor: could not close stale session %s: %v", sess.ID, err)
			continue
		}
		closed++
	}

	if closed > 0 {
		opts.logf("executor: closed %d stale in-flight session(s) left by a previous control plane "+
			"(drain would otherwise have waited on them forever)", closed)
	}
	if kept > 0 {
		opts.logf("executor: %d in-flight session(s) reattached to a still-running workload", kept)
	}
	return active
}

// sessionOutcome decides whether a session's workload is still alive, and if
// not, what terminal state to record for it.
//
// A driver that cannot answer — Status returned an error that is not
// ErrHandleNotFound, e.g. a cluster that is unreachable right now — is treated
// as *live*. That bias is deliberate and it is the safe direction: closing a
// session whose workload is actually running would let the scheduler re-place
// its task, producing two agents editing one repository. Leaving it open costs
// a drain that waits, and the next restart re-evaluates it.
func sessionOutcome(ctx context.Context, reg *executor.Registry, sess executor.Session) (string, bool) {
	if strings.TrimSpace(sess.HandleID) == "" {
		// A session that never obtained a handle cannot have a workload to
		// reattach to: Start failed, or the hub died inside it.
		return statedb.ExecutorSessionFailed, false
	}
	ex, err := reg.Get(sess.ExecutorID)
	if err != nil {
		return statedb.ExecutorSessionFailed, false
	}

	stCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	st, err := ex.Status(stCtx, sess.HandleID)
	if errors.Is(err, executor.ErrHandleNotFound) {
		return statedb.ExecutorSessionFailed, false
	}
	if err != nil {
		return "", true
	}
	if !st.State.Terminal() {
		return "", true
	}
	if st.State == executor.StateExited && st.ExitCode == 0 {
		return statedb.ExecutorSessionFinished, false
	}
	return statedb.ExecutorSessionFailed, false
}

// pruneWorktrees collects task worktrees and merged task branches that a
// crashed parallel run left behind.
//
// This is consequence (d). pkg/worktree cleaned only the same task path on the
// next Create, and Remove deliberately left the branch, so a run killed
// between `git worktree add` and its merge leaked both the directory and the
// cloop/task-N-* branch permanently.
//
// Two guards, and they are the reason this is safe to run unattended:
//
//   - MinAge. A live parallel run's worktrees are in this directory *right
//     now*, and deleting one destroys in-flight work with no way back. Age is
//     the guard that holds even when the caller's idea of what is running is
//     wrong or missing, which is why worktree.Prune defaults it rather than
//     treating zero as "no limit".
//   - The surviving sessions from sweepSessions, passed as Active. This is
//     the precise answer where MinAge is only the conservative one: a task
//     that has been running for six hours is older than any sane MinAge, and
//     is exactly the task whose worktree must not be touched.
//
// Branches are never deleted here. worktree.Prune can delete merged ones, but
// an unattended sweep that removes branches has to be certain about what
// "merged" means for a repository it did not configure, and the cost of being
// wrong is destroyed work against a saved disk-space figure of nearly zero.
// `cloop worktree prune --delete-branches` is where an operator can ask for it
// deliberately.
func pruneWorktrees(dir string, active map[string]map[int]bool, opts Options) {
	for _, project := range worktreeProjects(dir, active) {
		if !worktree.IsGitRepo(project) {
			continue
		}
		res, err := worktree.Prune(project, worktree.PruneOptions{
			MinAge: opts.WorktreeMinAge,
			Active: active[project],
			// Never from an unattended sweep; see the doc comment.
			DeleteBranches: false,
		})
		if err != nil {
			opts.logf("executor: could not prune worktrees in %s: %v", project, err)
			continue
		}
		for _, e := range res.Errors {
			opts.logf("executor: worktree %s could not be pruned: %v", e.Path, e.Err)
		}
		if len(res.Removed) > 0 {
			opts.logf("executor: pruned %d leaked task worktree(s) in %s: %s",
				len(res.Removed), project, res.Summary())
		}
	}
}

// worktreeProjects is the set of repositories worth sweeping: this control
// plane's own directory plus every project that had a session in flight.
//
// Scoping to those rather than to every project the hub has ever seen keeps
// the sweep proportional to the crash — a hub with two hundred registered
// projects should not shell out to git four hundred times on every restart —
// and it covers the case that produces leaks, since a worktree can only exist
// where a run was dispatched.
func worktreeProjects(dir string, active map[string]map[int]bool) []string {
	seen := map[string]bool{}
	var out []string
	add := func(p string) {
		p = strings.TrimSpace(p)
		if p == "" {
			return
		}
		if abs, err := filepath.Abs(p); err == nil {
			p = abs
		}
		if seen[p] {
			return
		}
		seen[p] = true
		out = append(out, p)
	}
	add(dir)
	for project := range active {
		add(project)
	}
	sort.Strings(out)
	return out
}

// sweepOrphans garbage-collects Pods a previous control plane left running.
//
// Detached and bounded: a cluster slow to answer must not delay the hub's
// startup, and a sweep that cannot finish in a minute is one the next restart
// can finish instead.
//
// Since Task 20191 this can only reach Pods whose handle row is *also* gone:
// the driver rehydrates from the store during construction, and an adopted
// Pod is in the tracked set before this goroutine is spawned. That ordering is
// what makes the sweep safe to run on a hub whose workloads are still going.
func sweepOrphans(ex *kubernetes.Executor, opts Options) {
	defer func() {
		if r := recover(); r != nil {
			opts.logf("executor: panic during orphaned-Pod sweep: %v", r)
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	removed, err := ex.ReconcileOrphans(ctx)
	if err != nil {
		opts.logf("executor %s: could not reconcile orphaned Pods: %v", ex.ID(), err)
		return
	}
	if len(removed) > 0 {
		opts.logf("executor %s: garbage-collected %d orphaned Pod(s) from a previous run: %s",
			ex.ID(), len(removed), strings.Join(removed, ", "))
	}
}

// sweepContainerOrphans is the container driver's half of the same sweep, and
// closes consequence (c).
//
// Until Task 20191 nothing called container.ReapOrphans outside the manual
// `cloop executor reap` CLI, and that call could only ever remove *exited*
// containers. A hub killed mid-run therefore left a RUNNING sandbox container
// burning CPU indefinitely, with no reaper anywhere. The containers already
// carried the labels needed to find them; the driver now applies the same
// grace-period approach Kubernetes uses, and this is the caller that makes it
// run on the path that matters.
func sweepContainerOrphans(ex *container.Executor, opts Options) {
	defer func() {
		if r := recover(); r != nil {
			opts.logf("executor: panic during orphaned-container sweep: %v", r)
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	removed, err := ex.ReapOrphans(ctx)
	if err != nil {
		opts.logf("executor %s: could not reap orphaned containers: %v", ex.ID(), err)
		// Not a return: ReapOrphans reports the exited half's real removals
		// alongside an error from the running half, and a partial success is
		// still worth telling the operator about.
	}
	if len(removed) == 0 {
		return
	}
	// The running ones are the newsworthy half — a container that was still
	// executing a harness when it was collected is a very different event from
	// a dead one being tidied away, and an operator debugging a vanished run
	// needs to be able to tell them apart in the log.
	var running, exited []string
	for _, name := range removed {
		if strings.HasSuffix(name, container.ReapedRunningSuffix) {
			running = append(running, strings.TrimSuffix(name, container.ReapedRunningSuffix))
			continue
		}
		exited = append(exited, name)
	}
	if len(exited) > 0 {
		opts.logf("executor %s: garbage-collected %d exited container(s) from a previous run: %s",
			ex.ID(), len(exited), strings.Join(exited, ", "))
	}
	if len(running) > 0 {
		opts.logf("executor %s: killed %d container(s) still running from a previous control plane: %s",
			ex.ID(), len(running), strings.Join(running, ", "))
	}
}
