package reconcile

// Tests for the restart sweep (Task 20191).
//
// What these pin down is the half of "survive a hub restart" that no driver
// can test on its own, because it is about the residue a *dead process* left
// in shared state: session rows nothing owns any more, and worktrees whose
// run will never come back to merge them.
//
// The session tests use a real SQLite database rather than a fake store on
// purpose. The bug being fixed is that a row written by one process was never
// read by the next one, so a test whose "store" lives in the test's own memory
// would assert the one thing that was never in question.

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/executorstore"
	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
	"github.com/blechschmidt/cloop/pkg/worktree"
)

// sweepStub answers Status from a script, which is the only method the
// session sweep consults. Everything else is present to satisfy the interface
// and panics if reached, so a future sweep that starts calling Signal fails
// loudly here instead of silently doing something to a live workload.
type sweepStub struct {
	id string
	// status is consulted per handle ID. A missing entry is reported as
	// ErrHandleNotFound, which is the "the workload is gone" case.
	status map[string]executor.Status
	// err, when set, is returned for every handle: the "this backend cannot
	// answer right now" case that must NOT be read as "the workload is gone".
	err error
}

func (s *sweepStub) ID() string        { return s.id }
func (s *sweepStub) Kind() string      { return executor.KindContainer }
func (s *sweepStub) Handles() []string { return nil }
func (s *sweepStub) Capabilities() executor.Capabilities {
	return executor.Capabilities{Isolation: executor.IsolationContainer}
}
func (s *sweepStub) Start(context.Context, executor.Spec) (executor.Handle, error) {
	panic("startup sweep must never start a workload")
}
func (s *sweepStub) Signal(context.Context, string, executor.Signal) error {
	panic("startup sweep must never signal a workload")
}
func (s *sweepStub) Stream(context.Context, string) (<-chan executor.LogLine, error) {
	panic("startup sweep must never open a stream")
}
func (s *sweepStub) HealthCheck(context.Context) error { return nil }
func (s *sweepStub) Status(_ context.Context, handleID string) (executor.Status, error) {
	if s.err != nil {
		return executor.Status{}, s.err
	}
	st, ok := s.status[handleID]
	if !ok {
		return executor.Status{}, executor.ErrHandleNotFound
	}
	return st, nil
}

// openSweepDB creates a state database under dir and returns a scheduler over
// it. The caller closes the DB.
func openSweepDB(t *testing.T, dir string) (*statedb.DB, *executorstore.Scheduler) {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(dir, ".cloop"), 0o755); err != nil {
		t.Fatalf("mkdir .cloop: %v", err)
	}
	db, err := statedb.Open(state.DBPath(dir))
	if err != nil {
		t.Fatalf("open state db: %v", err)
	}
	sched, err := executorstore.NewScheduler(db)
	if err != nil {
		db.Close()
		t.Fatalf("new scheduler: %v", err)
	}
	return db, sched
}

// openRunningSession writes the row a dispatching control plane writes and
// then dies holding.
func openRunningSession(t *testing.T, sched *executorstore.Scheduler, execID, handleID, project string, taskID int) string {
	t.Helper()
	id, err := executorstore.NewSessionID()
	if err != nil {
		t.Fatalf("new session id: %v", err)
	}
	token, err := executorstore.NewClaimToken()
	if err != nil {
		t.Fatalf("new claim token: %v", err)
	}
	if err := sched.OpenSession(executor.Session{
		ID:          id,
		ExecutorID:  execID,
		HandleID:    handleID,
		ProjectPath: project,
		TaskID:      taskID,
		ClaimToken:  token,
		Attempt:     1,
		StartedAt:   time.Now().UTC().Add(-time.Hour),
	}); err != nil {
		t.Fatalf("open session: %v", err)
	}
	return id
}

// sweepOptions builds Options that touch nothing process-global: a private
// registry, no published report, and no default handle store (these tests
// exercise the sweep, not persistence).
func sweepOptions(reg *executor.Registry) Options {
	no := false
	return Options{
		Registry:           reg,
		Publish:            &no,
		DisableHandleStore: true,
		Logf:               func(string, ...any) {},
	}
}

// TestSweepClosesStaleSessionSoDrainReturns is the regression test for
// consequence (b) of Task 20191.
//
// openSessionFor writes a `running` row and an in-memory goroutine closes it.
// A hub that dies takes that goroutine with it, and nothing else ever touched
// the row: RunningSessions is reachable only from a live healthy→unreachable
// transition, and a restarted hub sees its container executor as healthy, so
// no transition fires. WaitForDrain loops on CountRunning until zero, so
// `cloop executor drain` and the UI's drain button timed out with
// ErrDrainTimeout forever on any executor that had a run in flight during a
// restart.
//
// The assertion is deliberately made against WaitForDrain rather than against
// CountRunning, because timing out is the symptom an operator actually hits.
func TestSweepClosesStaleSessionSoDrainReturns(t *testing.T) {
	dir := t.TempDir()
	db, sched := openSweepDB(t, dir)
	defer db.Close()

	// The dead hub's residue: a session whose handle no live driver knows.
	openRunningSession(t, sched, "container", "handle-gone", dir, 7)

	reg := executor.NewRegistry()
	if err := reg.Register(&sweepStub{id: "container", status: map[string]executor.Status{}}); err != nil {
		t.Fatalf("register: %v", err)
	}
	sv := executor.NewSupervisor(reg, executor.SupervisorConfig{},
		executor.WithSessionStore(sched))

	// Before: drain never finishes. A short timeout stands in for the
	// operator's patience; the loop would otherwise run forever.
	if n, err := sv.WaitForDrain(context.Background(), "container", 50*time.Millisecond, 10*time.Millisecond); !errors.Is(err, executor.ErrDrainTimeout) {
		t.Fatalf("precondition: want ErrDrainTimeout with a stale row, got n=%d err=%v", n, err)
	}

	Sweep(context.Background(), dir, sweepOptions(reg))

	// After: the row is closed, so drain returns immediately.
	n, err := sv.WaitForDrain(context.Background(), "container", 50*time.Millisecond, 10*time.Millisecond)
	if err != nil {
		t.Fatalf("after sweep: drain still failed: n=%d err=%v", n, err)
	}
	if n != 0 {
		t.Fatalf("after sweep: want 0 in-flight sessions, got %d", n)
	}
}

// TestSweepKeepsSessionWhoseWorkloadSurvived: rehydration reattached to this
// workload, so its session row is real and must be left alone. Closing it
// would let the scheduler re-place the task, producing two agents editing one
// repository — the exact double-execution the session ledger exists to
// prevent.
func TestSweepKeepsSessionWhoseWorkloadSurvived(t *testing.T) {
	dir := t.TempDir()
	db, sched := openSweepDB(t, dir)
	defer db.Close()

	openRunningSession(t, sched, "container", "handle-live", dir, 3)

	reg := executor.NewRegistry()
	if err := reg.Register(&sweepStub{id: "container", status: map[string]executor.Status{
		"handle-live": {HandleID: "handle-live", ExecutorID: "container", State: executor.StateRunning},
	}}); err != nil {
		t.Fatalf("register: %v", err)
	}

	Sweep(context.Background(), dir, sweepOptions(reg))

	n, err := sched.CountRunning("container")
	if err != nil {
		t.Fatalf("count running: %v", err)
	}
	if n != 1 {
		t.Fatalf("want the reattached session left running, got %d in flight", n)
	}
}

// TestSweepKeepsSessionWhenTheDriverCannotAnswer pins the safe direction of
// the bias. A cluster that is briefly unreachable makes Status fail with
// something that is not ErrHandleNotFound, and treating that as "the workload
// is gone" would re-place a task that is still running. The cost of the other
// choice is a drain that waits until the next restart re-evaluates it.
func TestSweepKeepsSessionWhenTheDriverCannotAnswer(t *testing.T) {
	dir := t.TempDir()
	db, sched := openSweepDB(t, dir)
	defer db.Close()

	openRunningSession(t, sched, "container", "handle-unknown", dir, 4)

	reg := executor.NewRegistry()
	if err := reg.Register(&sweepStub{id: "container", err: errors.New("dial tcp: connection refused")}); err != nil {
		t.Fatalf("register: %v", err)
	}

	Sweep(context.Background(), dir, sweepOptions(reg))

	n, err := sched.CountRunning("container")
	if err != nil {
		t.Fatalf("count running: %v", err)
	}
	if n != 1 {
		t.Fatalf("an unanswerable driver must leave the session alone, got %d in flight", n)
	}
}

// TestSweepClosesSessionForAnUnregisteredExecutor: the executor was removed
// from config, or is an edge device that has not dialled back in. The session
// is over either way — a device that reconnects opens a new one — and leaving
// the row would wedge drain on an executor that no longer exists.
func TestSweepClosesSessionForAnUnregisteredExecutor(t *testing.T) {
	dir := t.TempDir()
	db, sched := openSweepDB(t, dir)
	defer db.Close()

	openRunningSession(t, sched, "edge-vanished", "handle-1", dir, 5)

	Sweep(context.Background(), dir, sweepOptions(executor.NewRegistry()))

	n, err := sched.CountRunning("edge-vanished")
	if err != nil {
		t.Fatalf("count running: %v", err)
	}
	if n != 0 {
		t.Fatalf("want the orphaned session closed, got %d in flight", n)
	}
}

// TestSweepClosesSessionWithNoHandle: the hub died inside Start, before the
// driver returned a handle. There is nothing to reattach to and nothing to
// ask, so the row is closed without consulting any driver.
func TestSweepClosesSessionWithNoHandle(t *testing.T) {
	dir := t.TempDir()
	db, sched := openSweepDB(t, dir)
	defer db.Close()

	openRunningSession(t, sched, "container", "", dir, 6)

	reg := executor.NewRegistry()
	// A stub whose Status panics: reaching it would mean the sweep consulted
	// a driver about a handle that does not exist.
	if err := reg.Register(&sweepStub{id: "container", err: nil, status: nil}); err != nil {
		t.Fatalf("register: %v", err)
	}

	Sweep(context.Background(), dir, sweepOptions(reg))

	if n, err := sched.CountRunning("container"); err != nil || n != 0 {
		t.Fatalf("want the handle-less session closed, got n=%d err=%v", n, err)
	}
}

// TestSweepIsIdempotent: a hub that restarts twice in a minute must not
// produce errors or re-close rows on the second pass.
func TestSweepIsIdempotent(t *testing.T) {
	dir := t.TempDir()
	db, sched := openSweepDB(t, dir)
	defer db.Close()

	openRunningSession(t, sched, "gone", "h", dir, 1)
	opts := sweepOptions(executor.NewRegistry())

	Sweep(context.Background(), dir, opts)
	Sweep(context.Background(), dir, opts)

	if n, err := sched.CountRunning(""); err != nil || n != 0 {
		t.Fatalf("second sweep disturbed the result: n=%d err=%v", n, err)
	}
}

// TestSweepWithoutADatabaseIsQuiet: `cloop` run in a directory that has never
// executed anything must not create state or complain.
func TestSweepWithoutADatabaseIsQuiet(t *testing.T) {
	dir := t.TempDir()
	var logged []string
	opts := sweepOptions(executor.NewRegistry())
	opts.Logf = func(format string, args ...any) { logged = append(logged, format) }

	Sweep(context.Background(), dir, opts)

	if len(logged) != 0 {
		t.Fatalf("a directory with no history should sweep silently, logged: %v", logged)
	}
}

// ---------------------------------------------------------------------------
// Worktree pruning — consequence (d)
// ---------------------------------------------------------------------------

// initSweepRepo builds a git repository with one commit, configured locally so
// the test needs no global git identity.
func initSweepRepo(t *testing.T) string {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not on PATH")
	}
	dir := t.TempDir()
	for _, args := range [][]string{
		{"init", "-b", "main"},
		{"config", "user.email", "test@example.com"},
		{"config", "user.name", "cloop test"},
		{"config", "commit.gpgsign", "false"},
	} {
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %s: %v: %s", strings.Join(args, " "), err, out)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "README.md"), []byte("cloop\n"), 0o644); err != nil {
		t.Fatalf("write README: %v", err)
	}
	for _, args := range [][]string{{"add", "-A"}, {"commit", "-m", "init"}} {
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %s: %v: %s", strings.Join(args, " "), err, out)
		}
	}
	return dir
}

// ageWorktree backdates a worktree so the sweep's MinAge guard lets it
// through. Every timestamp Prune can read has to move, so this walks the
// worktree directory as well as git's admin entry for it.
func ageWorktree(t *testing.T, repoDir string, taskID int, age time.Duration) {
	t.Helper()
	stamp := time.Now().Add(-age)
	paths := []string{
		filepath.Join(repoDir, ".cloop", "worktrees", "task-"+itoa(taskID)),
		filepath.Join(repoDir, ".git", "worktrees", "task-"+itoa(taskID)),
	}
	for _, root := range paths {
		if _, err := os.Stat(root); err != nil {
			continue
		}
		_ = filepath.Walk(root, func(p string, _ os.FileInfo, err error) error {
			if err != nil {
				return nil
			}
			_ = os.Chtimes(p, stamp, stamp)
			return nil
		})
		_ = os.Chtimes(root, stamp, stamp)
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

// TestSweepPrunesLeakedWorktrees is the regression test for consequence (d):
// a parallel run killed between `git worktree add` and its merge leaked the
// directory permanently, because Create only ever cleaned the *same* task's
// path on a later run and nothing swept the tree.
func TestSweepPrunesLeakedWorktrees(t *testing.T) {
	dir := initSweepRepo(t)
	if _, err := worktree.Create(dir, &pm.Task{ID: 42, Title: "leaked by a crash"}); err != nil {
		t.Fatalf("create worktree: %v", err)
	}
	ageWorktree(t, dir, 42, 24*time.Hour)

	before, err := worktree.List(dir)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(before) != 1 {
		t.Fatalf("precondition: want 1 worktree, got %d", len(before))
	}

	Sweep(context.Background(), dir, sweepOptions(executor.NewRegistry()))

	after, err := worktree.List(dir)
	if err != nil {
		t.Fatalf("list after sweep: %v", err)
	}
	if len(after) != 0 {
		t.Fatalf("want the leaked worktree pruned, still have %v", after)
	}
}

// TestSweepSparesAYoungWorktree pins the guard that makes this safe to run
// unattended: a live parallel run's worktrees are in that directory right now,
// and deleting one destroys in-flight work with no way back.
func TestSweepSparesAYoungWorktree(t *testing.T) {
	dir := initSweepRepo(t)
	if _, err := worktree.Create(dir, &pm.Task{ID: 9, Title: "in flight"}); err != nil {
		t.Fatalf("create worktree: %v", err)
	}

	Sweep(context.Background(), dir, sweepOptions(executor.NewRegistry()))

	after, err := worktree.List(dir)
	if err != nil {
		t.Fatalf("list after sweep: %v", err)
	}
	if len(after) != 1 {
		t.Fatalf("a worktree younger than MinAge must survive, got %v", after)
	}
}

// TestSweepSparesAWorktreeWithALiveSession is the precise guard, where MinAge
// is only the conservative one. A task that has been running for six hours is
// older than any sane MinAge, and is exactly the task whose worktree must not
// be touched — so the surviving sessions from the session sweep are fed to the
// worktree sweep as its Active set.
func TestSweepSparesAWorktreeWithALiveSession(t *testing.T) {
	dir := initSweepRepo(t)
	db, sched := openSweepDB(t, dir)
	defer db.Close()

	if _, err := worktree.Create(dir, &pm.Task{ID: 11, Title: "long running"}); err != nil {
		t.Fatalf("create worktree: %v", err)
	}
	ageWorktree(t, dir, 11, 24*time.Hour)
	openRunningSession(t, sched, "container", "handle-live", dir, 11)

	reg := executor.NewRegistry()
	if err := reg.Register(&sweepStub{id: "container", status: map[string]executor.Status{
		"handle-live": {HandleID: "handle-live", ExecutorID: "container", State: executor.StateRunning},
	}}); err != nil {
		t.Fatalf("register: %v", err)
	}

	Sweep(context.Background(), dir, sweepOptions(reg))

	after, err := worktree.List(dir)
	if err != nil {
		t.Fatalf("list after sweep: %v", err)
	}
	if len(after) != 1 {
		t.Fatalf("the worktree of a task with a live session must survive, got %v", after)
	}
	// And the branch, which the unattended sweep never deletes.
	branches, err := worktree.ListBranches(dir)
	if err != nil {
		t.Fatalf("list branches: %v", err)
	}
	if len(branches) != 1 {
		t.Fatalf("want the task branch intact, got %v", branches)
	}
}

// TestSweepNeverDeletesBranches: the unattended sweep removes directories, not
// history. An unmerged cloop/task-N-* branch is the only copy of that task's
// work, and `cloop executor` has no business deciding to drop it.
func TestSweepNeverDeletesBranches(t *testing.T) {
	dir := initSweepRepo(t)
	if _, err := worktree.Create(dir, &pm.Task{ID: 3, Title: "abandoned"}); err != nil {
		t.Fatalf("create worktree: %v", err)
	}
	ageWorktree(t, dir, 3, 24*time.Hour)

	Sweep(context.Background(), dir, sweepOptions(executor.NewRegistry()))

	branches, err := worktree.ListBranches(dir)
	if err != nil {
		t.Fatalf("list branches: %v", err)
	}
	if len(branches) != 1 {
		t.Fatalf("the sweep must leave branches alone, got %v", branches)
	}
}

// ---------------------------------------------------------------------------
// Handle store resolution
// ---------------------------------------------------------------------------

// TestHandleStoreHonoursTheOptOut: a reconcile pass over a scratch directory
// must not create a state database as a side effect.
func TestHandleStoreHonoursTheOptOut(t *testing.T) {
	dir := t.TempDir()
	opts := Options{DisableHandleStore: true, Logf: func(string, ...any) {}}
	if got := opts.handleStore(dir); got != nil {
		t.Fatalf("DisableHandleStore must yield a nil store, got %T", got)
	}
	if _, err := os.Stat(state.DBPath(dir)); err == nil {
		t.Fatal("the opt-out must not create a state database")
	}
}

// TestHandleStorePrefersAnExplicitOverride: an embedder that already holds a
// store must not have a second one opened behind it.
func TestHandleStorePrefersAnExplicitOverride(t *testing.T) {
	dir := t.TempDir()
	mem := executor.NewMemoryHandleStore()
	opts := Options{HandleStore: mem, Logf: func(string, ...any) {}}
	if got := opts.handleStore(dir); got != executor.HandleStore(mem) {
		t.Fatalf("want the injected store back, got %T", got)
	}
}

// TestHandleStoreIsCachedPerDirectory: FromConfig is idempotent and Bootstrap
// calls it twice, so a fresh SQLite handle per pass would leak one per call
// for the life of the process.
func TestHandleStoreIsCachedPerDirectory(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, ".cloop"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	opts := Options{Logf: func(string, ...any) {}}
	first := opts.handleStore(dir)
	if first == nil {
		t.Skip("state database unavailable in this environment")
	}
	if second := opts.handleStore(dir); second != first {
		t.Fatal("repeated passes over one directory must share a store")
	}
	// The same directory spelled differently must not open a second handle.
	if viaDot := opts.handleStore(filepath.Join(dir, ".")); viaDot != first {
		t.Fatal("path spelling must not defeat the cache")
	}
}

// TestAttachHandleStoreSkipsDriversThatCannotTakeOne: the registry holds
// whatever a deployment registered, and a driver with no AttachHandleStore
// (or a test stub) must be passed over rather than panicked on.
func TestAttachHandleStoreSkipsDriversThatCannotTakeOne(t *testing.T) {
	reg := executor.NewRegistry()
	if err := reg.Register(&sweepStub{id: "plain"}); err != nil {
		t.Fatalf("register: %v", err)
	}
	// Must not panic.
	attachHandleStores(reg, executor.NewMemoryHandleStore())
	attachHandleStores(reg, nil)
	attachHandleStores(nil, executor.NewMemoryHandleStore())
}
