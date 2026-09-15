package hubdoctor

// smoke_test.go covers the two properties that decide whether this command is
// safe to ship, and a third that decides whether it is useful.
//
// Safe: it must not run unless it was asked for, and it must leave nothing
// behind — not on the happy path, not when a stage fails, and not when an
// operator hits ctrl-C halfway through. A diagnostic that leaks credentials,
// containers or workspaces onto the machines nobody is watching is worse than
// no diagnostic at all, so the leak assertion here is the load-bearing test in
// this file.
//
// Useful: when it fails it must name the first broken stage and the fix. A
// smoke test that reports a bare Go error has moved the operator's problem
// from "which of my ten devices is broken" to "what does this error mean",
// which is not progress.
//
// The executor is a fake because the point is the *orchestration* — stage
// ordering, cleanup registration, attribution, remediation. Whether a real
// container runs a shell is tests/flagship's job, and it does it against a
// real Docker daemon; duplicating that here with a second harness is the fork
// this task was written to avoid.

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/executorstore"
	"github.com/blechschmidt/cloop/pkg/secretbroker"
	"github.com/blechschmidt/cloop/pkg/secretstore"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// --- the fake executor -------------------------------------------------

// fakeSmokeExecutor stands in for a driver and, crucially, keeps a ledger of
// what it was asked to create.
//
// The ledger is the whole point. "Did the smoke test clean up" cannot be
// answered by looking at the smoke test's own bookkeeping — that is the thing
// under test — so it is answered by asking the executor what it still holds,
// which is the same question `docker ps` answers for the real thing.
type fakeSmokeExecutor struct {
	id   string
	kind string
	caps executor.Capabilities

	mu sync.Mutex
	// live maps handle id to whether the workload is still running. A handle
	// that is present and true after the run is a leaked container.
	live map[string]bool
	// killed is closed per handle when the workload is signalled.
	//
	// It exists because executor.Run, after cancelling, kills the handle and
	// then drains the log channel until the *driver* closes it. A real driver
	// closes it when the workload dies; a fake that ignored the signal and
	// waited only on its own context would hang Run forever — and would do so
	// by violating the driver contract rather than by finding a bug.
	killed map[string]chan struct{}
	// specs records every Spec dispatched, so a test can assert on what the
	// lease machinery actually put in it.
	specs []executor.Spec
	// signals records every Signal call, by handle.
	signals map[string][]executor.Signal

	// output is what the workload "prints". Tests substitute this to simulate
	// a sandbox that could not see its lease, produced no logs, and so on.
	output func(spec executor.Spec) string
	// startErr makes Start fail, simulating an image with no shell.
	startErr error
	// blockUntilCancel makes the workload hang, so a test can interrupt it.
	blockUntilCancel bool
	// writeBack is what Status reports, for a driver advertising the capability.
	writeBack *executor.WriteBackResult
	// noRevocation models a driver that cannot take a credential back, which
	// the hub refuses to place credential-carrying work on at all.
	noRevocation bool

	// revoked records every RevokeLease call, so a test can tell a lease the
	// driver was actually asked to drop from one the hub merely forgot about.
	revoked []string
}

// The fake implements Revoker because the real container and remote drivers
// do, and because executor.Run refuses a credential-carrying spec on a driver
// that does not. A fake without it could only ever exercise the credential-less
// path, which is the half of the circuit that was never in doubt.
var _ executor.Revoker = (*fakeSmokeExecutor)(nil)

func (f *fakeSmokeExecutor) SupportsRevocation() bool { return !f.noRevocation }

func (f *fakeSmokeExecutor) HoldsLease(leaseID string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, spec := range f.specs {
		for _, b := range spec.Secrets {
			if b.LeaseID == leaseID {
				return true
			}
		}
	}
	return false
}

func (f *fakeSmokeExecutor) Leases() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	seen := map[string]bool{}
	var out []string
	for _, spec := range f.specs {
		for _, b := range spec.Secrets {
			if b.LeaseID != "" && !seen[b.LeaseID] {
				seen[b.LeaseID] = true
				out = append(out, b.LeaseID)
			}
		}
	}
	return out
}

func (f *fakeSmokeExecutor) RevokeLease(_ context.Context, req executor.RevokeRequest) executor.RevokeOutcome {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.revoked = append(f.revoked, req.LeaseID)
	return executor.RevokeOutcome{
		LeaseID: req.LeaseID, ExecutorID: f.id,
		State: executor.RevokeStateRevoked, SentAt: time.Now(), AckedAt: time.Now(),
	}
}

func (f *fakeSmokeExecutor) Revocations() []executor.RevokeOutcome { return nil }

func newFakeExecutor(id string) *fakeSmokeExecutor {
	return &fakeSmokeExecutor{
		id:   id,
		kind: executor.KindContainer,
		caps: executor.Capabilities{
			Isolation:           executor.IsolationContainer,
			SupportsSignal:      true,
			SupportsSecretFiles: true,
			// The interesting default: this driver places the files itself,
			// which is the delivery path with the most moving parts.
			SecretFilesFromHostPath: false,
			SharesHostFilesystem:    false,
		},
		live:    map[string]bool{},
		killed:  map[string]chan struct{}{},
		signals: map[string][]executor.Signal{},
	}
}

func (f *fakeSmokeExecutor) ID() string                          { return f.id }
func (f *fakeSmokeExecutor) Kind() string                        { return f.kind }
func (f *fakeSmokeExecutor) Capabilities() executor.Capabilities { return f.caps }
func (f *fakeSmokeExecutor) HealthCheck(context.Context) error   { return nil }

func (f *fakeSmokeExecutor) Start(ctx context.Context, spec executor.Spec) (executor.Handle, error) {
	if f.startErr != nil {
		return executor.Handle{}, f.startErr
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	id := fmt.Sprintf("h-%d", len(f.specs)+1)
	f.specs = append(f.specs, spec)
	f.live[id] = true
	f.killed[id] = make(chan struct{})
	return executor.Handle{ID: id, ExecutorID: f.id, StartedAt: time.Now()}, nil
}

func (f *fakeSmokeExecutor) Signal(_ context.Context, handleID string, sig executor.Signal) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.live[handleID]; !ok {
		return executor.ErrHandleNotFound
	}
	f.signals[handleID] = append(f.signals[handleID], sig)
	if sig == executor.SignalKill {
		f.live[handleID] = false
		// Closing the stream is what a real driver does when the workload
		// dies, and what executor.Run blocks on after issuing the kill.
		if ch, ok := f.killed[handleID]; ok {
			select {
			case <-ch:
			default:
				close(ch)
			}
		}
	}
	return nil
}

func (f *fakeSmokeExecutor) Status(_ context.Context, handleID string) (executor.Status, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	running, ok := f.live[handleID]
	if !ok {
		return executor.Status{}, executor.ErrHandleNotFound
	}
	st := executor.Status{HandleID: handleID, ExecutorID: f.id, State: executor.StateExited}
	if running {
		st.State = executor.StateRunning
	}
	if f.writeBack != nil {
		st.WriteBack = f.writeBack
	}
	return st, nil
}

func (f *fakeSmokeExecutor) Stream(ctx context.Context, handleID string) (<-chan executor.LogLine, error) {
	f.mu.Lock()
	spec := f.specs[len(f.specs)-1]
	killed := f.killed[handleID]
	f.mu.Unlock()

	ch := make(chan executor.LogLine, 4)
	go func() {
		defer close(ch)
		if f.blockUntilCancel {
			// Simulate a workload that never finishes, so a test can cancel
			// the run and check that cleanup still happens. It ends on the
			// kill signal, as a real workload does.
			select {
			case <-ctx.Done():
			case <-killed:
			}
			return
		}
		text := defaultFakeOutput(spec)
		if f.output != nil {
			text = f.output(spec)
		}
		select {
		case ch <- executor.LogLine{HandleID: handleID, Text: text, Seq: 1, Time: time.Now()}:
		case <-ctx.Done():
			return
		}
		f.mu.Lock()
		f.live[handleID] = false
		f.mu.Unlock()
	}()
	return ch, nil
}

// defaultFakeOutput is what a healthy sandbox would print: it answers the same
// questions smokeWorkload asks, derived from the Spec it was actually given.
//
// Deriving it from the Spec rather than hard-coding a happy answer is what
// makes the fake worth having — if the lease machinery stops putting the
// credential in the spec, this output changes and the lease stage fails, which
// is exactly the real failure being modelled.
func defaultFakeOutput(spec executor.Spec) string {
	nonce := envValue(spec.Env, "CLOOP_SMOKE_NONCE")
	lease := "absent"
	if kubeconfig := envValue(spec.Env, "KUBECONFIG"); kubeconfig != "" {
		lease = "env-without-file"
		for _, f := range spec.SecretFiles {
			if f.Path() == kubeconfig && strings.Contains(string(f.Content), "cloop-smoke-"+nonce) {
				lease = "delivered"
			}
		}
		// A hub-materialised lease has the file on the real filesystem.
		if data, err := os.ReadFile(kubeconfig); err == nil {
			if strings.Contains(string(data), "cloop-smoke-"+nonce) {
				lease = "delivered"
			} else {
				lease = "wrong-content"
			}
		}
	}
	marker := "absent"
	if data, err := os.ReadFile(filepath.Join(spec.WorkDir, "cloop-smoke-marker")); err == nil {
		marker = string(data)
	}
	return strings.Join([]string{
		"smoke_nonce=" + nonce,
		"smoke_uid=65532",
		"smoke_marker=" + marker,
		"smoke_writable=yes",
		"smoke_lease=" + lease,
		"smoke_done=ok",
		"",
	}, "\n")
}

func envValue(env []string, key string) string {
	for _, kv := range env {
		if name, value, ok := strings.Cut(kv, "="); ok && name == key {
			return value
		}
	}
	return ""
}

// liveHandles returns the handles still running — the fake's answer to
// `docker ps`.
func (f *fakeSmokeExecutor) liveHandles() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for id, running := range f.live {
		if running {
			out = append(out, id)
		}
	}
	return out
}

func (f *fakeSmokeExecutor) lastSpec(t *testing.T) executor.Spec {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.specs) == 0 {
		t.Fatal("nothing was dispatched")
	}
	return f.specs[len(f.specs)-1]
}

// --- fixtures ----------------------------------------------------------

// smokeWorld is a hub directory with a migrated database and a registered
// executor.
type smokeWorld struct {
	dir string
	ex  *fakeSmokeExecutor
	cfg *config.Config
}

// executorSeq hands out unique executor ids across the package's tests.
var executorSeq atomic.Int64

func nextExecutorSeq() int64 { return executorSeq.Add(1) }

// newSmokeWorld builds a control plane the smoke check can run against, and
// unregisters the executor afterwards so tests cannot leak into each other
// through the process-global registry.
func newSmokeWorld(t *testing.T) *smokeWorld {
	t.Helper()
	dir := t.TempDir()
	mustInitStateDB(t, dir)

	// A real sealing key, so the lease stage exercises the real broker rather
	// than the skip path. The skip path has its own test.
	var key [32]byte
	if _, err := rand.Read(key[:]); err != nil {
		t.Fatalf("rand: %v", err)
	}
	t.Setenv("CLOOP_SECRET_KEY", base64.StdEncoding.EncodeToString(key[:]))

	// The executor registry is process-global, and other tests in this package
	// reconcile real drivers into it (checkExecutors does exactly that). A
	// smoke test that ran against whatever those left behind would dispatch to
	// a real container runtime and assert on the wrong executor — so take the
	// registry over for the duration and hand it back.
	//
	// Registered before the fake's own cleanup so that it runs *after* it:
	// t.Cleanup is LIFO, and restoring the originals has to happen once the
	// fake is gone.
	saved := executor.DefaultRegistry.List()
	for _, prior := range saved {
		executor.DefaultRegistry.Unregister(prior.ID())
	}
	t.Cleanup(func() {
		for _, prior := range saved {
			_ = executor.DefaultRegistry.Ensure(prior)
		}
	})

	// A unique id per world. DefaultRegistry.Ensure is idempotent by id, so two
	// worlds sharing one would silently leave the first world's executor
	// registered and smoke that instead — a test that passes while exercising
	// the wrong object.
	ex := newFakeExecutor(fmt.Sprintf("fake-exec-%d", nextExecutorSeq()))
	if err := executor.DefaultRegistry.Ensure(ex); err != nil {
		t.Fatalf("register fake executor: %v", err)
	}
	t.Cleanup(func() { executor.DefaultRegistry.Unregister(ex.ID()) })

	return &smokeWorld{dir: dir, ex: ex, cfg: &config.Config{}}
}

// run drives checkSmoke alone and returns the report it filled in.
func (w *smokeWorld) run(t *testing.T, opts Options) *Report {
	t.Helper()
	return w.runCtx(t, context.Background(), opts)
}

func (w *smokeWorld) runCtx(t *testing.T, ctx context.Context, opts Options) *Report {
	t.Helper()
	opts.Smoke = true
	if opts.SmokeTimeout == 0 {
		opts.SmokeTimeout = 20 * time.Second
	}
	rep := &Report{Dir: w.dir}
	checkSmoke(ctx, w.dir, w.cfg, opts, rep,
		func(f Finding) { rep.Findings = append(rep.Findings, f) })
	return rep
}

// only returns the single smoke result, failing if there is not exactly one.
func (w *smokeWorld) only(t *testing.T, rep *Report) SmokeResult {
	t.Helper()
	if len(rep.Smoke) != 1 {
		t.Fatalf("got %d smoke results, want 1: %+v", len(rep.Smoke), rep.Smoke)
	}
	return rep.Smoke[0]
}

// registerExtraExecutor adds a second executor to the process registry for the
// duration of one test.
func registerExtraExecutor(t *testing.T) *fakeSmokeExecutor {
	t.Helper()
	ex := newFakeExecutor(fmt.Sprintf("fake-exec-%d", nextExecutorSeq()))
	if err := executor.DefaultRegistry.Ensure(ex); err != nil {
		t.Fatalf("register: %v", err)
	}
	t.Cleanup(func() { executor.DefaultRegistry.Unregister(ex.ID()) })
	return ex
}

func stageOf(t *testing.T, res SmokeResult, name SmokeStage) StageResult {
	t.Helper()
	for _, s := range res.Stages {
		if s.Stage == name {
			return s
		}
	}
	t.Fatalf("stage %q missing from the report: %+v", name, res.Stages)
	return StageResult{}
}

// --- the safety properties ---------------------------------------------

// TestSmokeIsOptIn. Every other check in this package reads; this one starts a
// workload and mints a credential. A plain `cloop hub doctor` — what people run
// against production to see what is wrong — must not do either.
func TestSmokeIsOptIn(t *testing.T) {
	w := newSmokeWorld(t)
	rep := &Report{Dir: w.dir}
	checkSmoke(context.Background(), w.dir, w.cfg, Options{}, rep,
		func(f Finding) { rep.Findings = append(rep.Findings, f) })

	if len(rep.Findings) != 0 || len(rep.Smoke) != 0 || rep.SmokeRan {
		t.Fatalf("the smoke test ran without --smoke: %+v", rep)
	}
	if got := w.ex.liveHandles(); len(got) != 0 {
		t.Errorf("a workload was started without --smoke: %v", got)
	}
}

// TestSmokeWithOfflineSaysSoInsteadOfSkipping: --offline and --smoke
// contradict each other. Silently doing nothing would let an operator believe
// they had proved something.
func TestSmokeWithOfflineSaysSoInsteadOfSkipping(t *testing.T) {
	w := newSmokeWorld(t)
	rep := w.run(t, Options{Offline: true})

	if len(rep.Smoke) != 0 {
		t.Errorf("--offline still dispatched: %+v", rep.Smoke)
	}
	if len(rep.Findings) != 1 || rep.Findings[0].Severity != SeverityWarn {
		t.Fatalf("want one warning explaining the contradiction, got %+v", rep.Findings)
	}
	if !strings.Contains(rep.Findings[0].Message, "offline") {
		t.Errorf("the finding does not name the flag that suppressed it: %q", rep.Findings[0].Message)
	}
}

// TestSmokeLeavesNothingBehind is the load-bearing test in this file.
//
// It checks all six kinds of residue the command can produce: a running
// workload, the throwaway workspace, the credential files, the lease inside
// the broker, and the two state rows (secret and grant) that minting one
// creates. A diagnostic an operator runs hourly against a fleet must be
// exactly as clean afterwards as before.
func TestSmokeLeavesNothingBehind(t *testing.T) {
	w := newSmokeWorld(t)
	rep := w.run(t, Options{})
	res := w.only(t, rep)

	if !res.OK() {
		t.Fatalf("the happy path failed, so the cleanup assertions below are meaningless: %+v", res)
	}

	// 1. No workload still running — the fake's answer to `docker ps`, and the
	//    stand-in for a container, a Pod and its NetworkPolicy.
	if live := w.ex.liveHandles(); len(live) != 0 {
		t.Errorf("workload(s) still running after the smoke run: %v", live)
	}

	// 2. No workspace left on disk. The whole smoke root should be empty:
	//    anything under it is a directory this run created and did not remove.
	smokeRoot := filepath.Join(w.dir, ".cloop", "smoke")
	if entries, err := os.ReadDir(smokeRoot); err == nil && len(entries) > 0 {
		var names []string
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Errorf("workspace(s) left behind under %s: %v", smokeRoot, names)
	}

	// 3. No credential material anywhere the lease could have staged it.
	assertNoLeaseDirs(t)

	// 4 and 5. No secret or grant rows in the database. These are the "state
	//    row" case, and the one most likely to accumulate invisibly: nothing
	//    about a stale grant makes a hub misbehave until someone audits it.
	assertBrokerEmpty(t, w.dir)

	// 6. And the report agrees, which is what an operator actually reads.
	if len(res.Leaked) != 0 {
		t.Errorf("the report names leaks: %v", res.Leaked)
	}
	if cleanup := stageOf(t, res, StageCleanup); cleanup.Outcome != StagePass {
		t.Errorf("cleanup stage = %q: %s", cleanup.Outcome, cleanup.Message)
	}
}

// TestSmokeCleansUpWhenInterrupted is the ctrl-C case.
//
// It is separate from the happy path because it exercises a different code
// path — the deferred stack running under a context the caller already
// cancelled — and because it is the case an operator will actually hit. A
// smoke test that takes ninety seconds against a cold fleet is one people
// interrupt.
func TestSmokeCleansUpWhenInterrupted(t *testing.T) {
	w := newSmokeWorld(t)
	w.ex.blockUntilCancel = true

	ctx, cancel := context.WithCancel(context.Background())
	// Cancel once the workload is running, the way ctrl-C would.
	go func() {
		deadline := time.Now().Add(10 * time.Second)
		for time.Now().Before(deadline) {
			if len(w.ex.liveHandles()) > 0 {
				break
			}
			time.Sleep(5 * time.Millisecond)
		}
		cancel()
	}()

	rep := w.runCtx(t, ctx, Options{})
	res := w.only(t, rep)

	// The run itself must be reported as failed — it was interrupted, and
	// claiming otherwise would let a CI step treat a ctrl-C as a pass.
	if res.FirstFailure != StageDispatch {
		t.Errorf("first failure = %q, want %q: an interrupted run is not a successful one",
			res.FirstFailure, StageDispatch)
	}

	// But everything it created is gone anyway. This is the assertion that
	// matters: cancellation must not be able to skip cleanup.
	if live := w.ex.liveHandles(); len(live) != 0 {
		t.Errorf("interrupting the run leaked a running workload: %v", live)
	}
	if len(res.Leaked) != 0 {
		t.Errorf("interrupting the run leaked: %v", res.Leaked)
	}
	smokeRoot := filepath.Join(w.dir, ".cloop", "smoke")
	if entries, err := os.ReadDir(smokeRoot); err == nil && len(entries) > 0 {
		t.Errorf("interrupting the run left a workspace under %s", smokeRoot)
	}
	assertNoLeaseDirs(t)
	assertBrokerEmpty(t, w.dir)
}

// TestSmokeCleansUpWhenAStageFails: a failure mid-circuit must not skip the
// removals registered before it. This is the same stack as the happy path, but
// unwound from a different point, and "cleanup runs on success" is a much
// weaker claim than "cleanup runs always".
func TestSmokeCleansUpWhenAStageFails(t *testing.T) {
	w := newSmokeWorld(t)
	w.ex.startErr = errors.New("exec /bin/sh: no such file or directory")

	res := w.only(t, w.run(t, Options{}))
	if res.FirstFailure != StageDispatch {
		t.Fatalf("first failure = %q, want dispatch: %+v", res.FirstFailure, res.Stages)
	}
	if len(res.Leaked) != 0 {
		t.Errorf("a failed run leaked: %v", res.Leaked)
	}
	smokeRoot := filepath.Join(w.dir, ".cloop", "smoke")
	if entries, err := os.ReadDir(smokeRoot); err == nil && len(entries) > 0 {
		t.Errorf("a failed run left a workspace under %s", smokeRoot)
	}
	assertNoLeaseDirs(t)
	assertBrokerEmpty(t, w.dir)
}

// assertBrokerEmpty checks that no secret or grant row survives.
func assertBrokerEmpty(t *testing.T, dir string) {
	t.Helper()
	db, err := statedb.Open(state.DBPath(dir))
	if err != nil {
		t.Fatalf("open state db: %v", err)
	}
	defer func() { _ = db.Close() }()

	store, err := secretstore.New(db)
	if err != nil {
		t.Fatalf("secretstore: %v", err)
	}
	broker, err := secretbroker.New(store)
	if err != nil {
		t.Fatalf("broker: %v", err)
	}
	secrets, err := broker.ListSecrets()
	if err != nil {
		t.Fatalf("list secrets: %v", err)
	}
	for _, s := range secrets {
		if strings.HasPrefix(s.Name, "cloop-smoke-") {
			t.Errorf("a throwaway secret row survived the run: %s (%s)", s.Name, s.ID)
		}
	}
	grants, err := broker.ListGrants(secretbroker.GrantFilter{})
	if err != nil {
		t.Fatalf("list grants: %v", err)
	}
	for _, g := range grants {
		if g.RevokedAt.IsZero() {
			t.Errorf("a live grant row survived the run: %s", g.ID)
		}
	}
}

// assertNoLeaseDirs checks the machine-global staging locations a lease can
// use. Both are shared, which is why a leak here would be a leak of credential
// material into a directory other tenants can list.
func assertNoLeaseDirs(t *testing.T) {
	t.Helper()
	// The three places a lease can stage material. /run/cloop is the preferred
	// one on a systemd host, and omitting it would make this assertion pass
	// while missing the leak it is written to catch.
	for _, base := range []string{"/run/cloop", "/dev/shm", os.TempDir()} {
		matches, err := filepath.Glob(filepath.Join(base, "cloop-lease-*"))
		if err != nil || len(matches) == 0 {
			continue
		}
		// Only complain about directories this process could have made: the
		// box may be running a real hub, and failing a unit test because a
		// production lease is live would be a false positive with a very
		// confusing message.
		for _, m := range matches {
			info, statErr := os.Stat(m)
			if statErr != nil {
				continue
			}
			if time.Since(info.ModTime()) < time.Minute {
				t.Errorf("credential staging directory left behind: %s", m)
			}
		}
	}
}

// --- targeting ---------------------------------------------------------

// TestSmokeTargetsEveryExecutorByDefault is requirement one: "which of my ten
// devices is broken" has to be one command, not ten.
func TestSmokeTargetsEveryExecutorByDefault(t *testing.T) {
	w := newSmokeWorld(t)
	second := registerExtraExecutor(t)

	rep := w.run(t, Options{})
	if len(rep.Smoke) != 2 {
		t.Fatalf("smoked %d executors, want both: %+v", len(rep.Smoke), rep.Smoke)
	}
	seen := map[string]bool{}
	for _, r := range rep.Smoke {
		seen[r.ExecutorID] = true
	}
	for _, want := range []string{w.ex.ID(), second.ID()} {
		if !seen[want] {
			t.Errorf("executor %q was not smoked", want)
		}
	}
}

// TestSmokeExecutorFlagNarrowsToOne.
func TestSmokeExecutorFlagNarrowsToOne(t *testing.T) {
	w := newSmokeWorld(t)
	second := registerExtraExecutor(t)

	rep := w.run(t, Options{ProbeExecutorID: second.ID()})
	res := w.only(t, rep)
	if res.ExecutorID != second.ID() {
		t.Errorf("smoked %q, want %q", res.ExecutorID, second.ID())
	}
	if live := w.ex.liveHandles(); len(live) != 0 {
		t.Errorf("the executor that was not named was dispatched to anyway: %v", live)
	}
}

// TestSmokeNamingAnUnknownExecutorSaysWhichOne: a typo must not silently smoke
// nothing and report a clean run.
func TestSmokeNamingAnUnknownExecutorSaysWhichOne(t *testing.T) {
	w := newSmokeWorld(t)
	rep := w.run(t, Options{ProbeExecutorID: "typo-exec"})

	if len(rep.Smoke) != 0 {
		t.Fatalf("something was smoked: %+v", rep.Smoke)
	}
	if len(rep.Findings) != 1 {
		t.Fatalf("want one finding, got %+v", rep.Findings)
	}
	if !strings.Contains(rep.Findings[0].Message, "typo-exec") {
		t.Errorf("the finding does not name the executor asked for: %q", rep.Findings[0].Message)
	}
}

// TestSmokeSkipsCordonedExecutorsAndSaysSo.
//
// Both halves matter. Skipping a cordoned node is right — it is deliberately
// out of rotation. Doing it silently is not: an operator sweeping ten devices
// would read a clean report having looked at seven.
func TestSmokeSkipsCordonedExecutorsAndSaysSo(t *testing.T) {
	w := newSmokeWorld(t)
	cordonExecutor(t, w.dir, w.ex.ID())

	rep := w.run(t, Options{})
	if len(rep.Smoke) != 0 {
		t.Errorf("a cordoned executor was smoked: %+v", rep.Smoke)
	}
	var told bool
	for _, f := range rep.Findings {
		if strings.Contains(f.Message, "cordoned") {
			told = true
		}
	}
	if !told {
		t.Errorf("nothing in the report says the fleet was narrowed: %+v", rep.Findings)
	}
}

// TestSmokeNamingACordonedExecutorSmokesItAnyway.
//
// "This device is cordoned because it was misbehaving — is it fixed yet" is
// the exact question an operator has, and refusing to answer it would send
// them to uncordon a node before they know whether it works.
func TestSmokeNamingACordonedExecutorSmokesItAnyway(t *testing.T) {
	w := newSmokeWorld(t)
	cordonExecutor(t, w.dir, w.ex.ID())

	rep := w.run(t, Options{ProbeExecutorID: w.ex.ID()})
	if len(rep.Smoke) != 1 {
		t.Fatalf("naming a cordoned executor did not smoke it: %+v", rep.Smoke)
	}
}

// cordonExecutor marks an executor administratively held, the way the hub's
// cordon command does.
func cordonExecutor(t *testing.T, dir, id string) {
	t.Helper()
	db, err := statedb.Open(state.DBPath(dir))
	if err != nil {
		t.Fatalf("open state db: %v", err)
	}
	defer func() { _ = db.Close() }()
	sched, err := executorstore.NewScheduler(db)
	if err != nil {
		t.Fatalf("scheduler: %v", err)
	}
	h, _ := sched.LoadHealth(id)
	h.ExecutorID = id
	h, _ = executor.Cordon(h, "under investigation", time.Now())
	if err := sched.SaveHealth(h); err != nil {
		t.Fatalf("save health: %v", err)
	}
}

// --- what the report says ----------------------------------------------

// TestSmokeNamesTheFirstFailedStage is requirement two.
//
// When the circuit breaks, the stages after the break are consequences. An
// operator reading a wall of red needs to be told which line to act on, and a
// report that does not distinguish cause from consequence has just relocated
// the diagnosis rather than performed it.
func TestSmokeNamesTheFirstFailedStage(t *testing.T) {
	w := newSmokeWorld(t)
	// A sandbox that runs but never receives its credential: dispatch and
	// logs succeed, the lease stage is the real fault.
	w.ex.output = func(spec executor.Spec) string {
		return strings.Replace(defaultFakeOutput(spec), "smoke_lease=delivered", "smoke_lease=absent", 1)
	}

	res := w.only(t, w.run(t, Options{}))
	if res.FirstFailure != StageLease {
		t.Fatalf("first failure = %q, want %q: %+v", res.FirstFailure, StageLease, res.Stages)
	}
	if d := stageOf(t, res, StageDispatch); d.Outcome != StagePass {
		t.Errorf("dispatch = %q, but the workload did run; the report blames the wrong stage", d.Outcome)
	}

	// And the finding an operator reads leads with that stage and its fix.
	var found bool
	for _, f := range w.run(t, Options{}).Findings {
		if f.Check == "smoke.dispatch" && f.Severity == SeverityFail {
			found = true
			if !strings.Contains(f.Message, string(StageLease)) {
				t.Errorf("the finding does not name the failing stage: %q", f.Message)
			}
			if strings.TrimSpace(f.Remediation) == "" {
				t.Error("the finding carries no remediation")
			}
		}
	}
	if !found {
		t.Error("no failing finding was emitted for a broken circuit")
	}
}

// TestEverySmokeStageCarriesRemediation mirrors this package's existing
// contract: a diagnostic that reports a problem without naming its fix is the
// failure mode the whole command exists to remove.
//
// It sweeps the real failure modes rather than a synthetic one, so a new stage
// added without a remediation is caught by the case that produces it.
func TestEverySmokeStageCarriesRemediation(t *testing.T) {
	cases := []struct {
		name  string
		setup func(*smokeWorld)
	}{
		{"credential never arrives", func(w *smokeWorld) {
			w.ex.output = func(spec executor.Spec) string {
				return strings.Replace(defaultFakeOutput(spec), "smoke_lease=delivered", "smoke_lease=absent", 1)
			}
		}},
		{"image has no shell", func(w *smokeWorld) {
			w.ex.startErr = errors.New("exec: \"/bin/sh\": executable file not found in $PATH")
		}},
		{"no output at all", func(w *smokeWorld) {
			w.ex.output = func(executor.Spec) string { return "" }
		}},
		{"workspace not writable", func(w *smokeWorld) {
			w.ex.output = func(spec executor.Spec) string {
				return strings.Replace(defaultFakeOutput(spec), "smoke_writable=yes", "smoke_writable=no", 1)
			}
		}},
		{"driver advertises write-back but returns nothing", func(w *smokeWorld) {
			w.ex.caps.SupportsWriteBack = true
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := newSmokeWorld(t)
			tc.setup(w)
			res := w.only(t, w.run(t, Options{}))
			for _, s := range res.Stages {
				if s.Outcome == StagePass {
					continue
				}
				if strings.TrimSpace(s.Remediation) == "" {
					t.Errorf("stage %q is %q with no remediation: %q",
						s.Stage, s.Outcome, s.Message)
				}
				if strings.TrimSpace(s.Message) == "" {
					t.Errorf("stage %q is %q with no message", s.Stage, s.Outcome)
				}
			}
		})
	}
}

// TestSmokeReportsEveryStageInOrder: a reader comparing two executors should
// not have to account for one of them having fewer rows.
func TestSmokeReportsEveryStageInOrder(t *testing.T) {
	w := newSmokeWorld(t)
	res := w.only(t, w.run(t, Options{}))

	var last int
	for _, s := range res.Stages {
		idx := -1
		for i, name := range smokeStageOrder {
			if name == s.Stage {
				idx = i
			}
		}
		if idx < 0 {
			t.Fatalf("stage %q is not in smokeStageOrder", s.Stage)
		}
		if idx < last {
			t.Errorf("stage %q is out of order", s.Stage)
		}
		last = idx
	}
	// No stage should appear twice: the provisional/refined verdicts for
	// workspace and lease must collapse to one row each.
	seen := map[SmokeStage]int{}
	for _, s := range res.Stages {
		seen[s.Stage]++
	}
	for stage, n := range seen {
		if n > 1 {
			t.Errorf("stage %q reported %d times; the refinement did not collapse", stage, n)
		}
	}
}

// TestSmokeAttributesOutputToThisRun.
//
// Output that arrives carrying another workload's id means the stream is
// crossed, which on a multi-tenant hub is a confidentiality problem rather
// than merely a bug. It must not read as a healthy circuit.
func TestSmokeAttributesOutputToThisRun(t *testing.T) {
	w := newSmokeWorld(t)
	w.ex.output = func(spec executor.Spec) string {
		return strings.Replace(defaultFakeOutput(spec),
			"smoke_nonce="+envValue(spec.Env, "CLOOP_SMOKE_NONCE"), "smoke_nonce=someone-else", 1)
	}
	res := w.only(t, w.run(t, Options{}))
	if got := stageOf(t, res, StageLogs); got.Outcome != StageFail {
		t.Errorf("logs stage = %q for output belonging to another run", got.Outcome)
	}
}

// --- the credential ----------------------------------------------------

// TestSmokeLeaseIsShortLivedAndRevoked is requirement five: mint nothing that
// outlives the run.
//
// The TTL is checked against the constant rather than a literal so the test
// tracks the policy, but the bound is asserted independently: whatever the
// constant says, a credential minted by a diagnostic must be measured in
// seconds. A future edit raising it to an hour should fail here.
func TestSmokeLeaseIsShortLivedAndRevoked(t *testing.T) {
	if smokeLeaseTTL > 5*time.Minute {
		t.Errorf("smokeLeaseTTL is %s; a diagnostic's credential must be measured in seconds",
			smokeLeaseTTL)
	}

	w := newSmokeWorld(t)
	res := w.only(t, w.run(t, Options{}))

	lease := stageOf(t, res, StageLease)
	if lease.Outcome != StagePass {
		t.Fatalf("the lease stage did not pass, so revocation proves nothing: %+v", lease)
	}
	rev := stageOf(t, res, StageRevocation)
	if rev.Outcome != StagePass {
		t.Errorf("revocation = %q: %s", rev.Outcome, rev.Message)
	}

	// The spec really did carry the credential — otherwise "revoked" would be
	// trivially true because nothing was ever delivered.
	spec := w.ex.lastSpec(t)
	if len(spec.SecretFiles) == 0 {
		t.Error("no credential file was put in the spec, so the lease stage proved nothing")
	}
	var revocable bool
	for _, b := range spec.Secrets {
		if b.Revocable() {
			revocable = true
		}
		if b.ExpiresAt.IsZero() {
			t.Error("a binding carries no expiry, so a disconnected driver could not expire it")
		}
	}
	if !revocable {
		t.Error("the spec carries no revocable binding, so a driver could not take the credential back")
	}
}

// TestSmokeWorkloadIsHermetic: no network, and nothing from the hub's own
// environment. The second is the defect the flagship test found in the hub's
// dispatch path — an Env seeded from os.Environ forwarded CLOOP_SECRET_KEY into
// a sandbox — and a diagnostic that reintroduced it would be handing the hub's
// master key to every executor in the fleet, on a command people run hourly.
func TestSmokeWorkloadIsHermetic(t *testing.T) {
	t.Setenv("CLOOP_SMOKE_CANARY", "must-not-leak")
	w := newSmokeWorld(t)
	w.run(t, Options{})

	spec := w.ex.lastSpec(t)
	if !spec.DisableNetwork {
		t.Error("the smoke workload was not denied the network")
	}
	for _, kv := range spec.Env {
		name, _, _ := strings.Cut(kv, "=")
		switch name {
		case "CLOOP_SMOKE_CANARY", "CLOOP_SECRET_KEY", "CLOOP_UI_TOKEN":
			t.Errorf("the hub's own environment reached the sandbox: %s", name)
		}
	}
	if spec.Workspace.NeedsProvisioning() {
		t.Error("the smoke workload asked for a repository; it must clone nothing")
	}
}

// TestSmokeWithoutSealingKeySkipsRatherThanFails.
//
// A hub with no CLOOP_SECRET_KEY can still dispatch work that needs no
// credential, and checkSecretKey already reports the missing key in detail.
// Failing here as well would make one problem look like two — but passing
// would be worse, because nothing about credential delivery was proved.
func TestSmokeWithoutSealingKeySkipsRatherThanFails(t *testing.T) {
	w := newSmokeWorld(t)
	t.Setenv("CLOOP_SECRET_KEY", "")

	res := w.only(t, w.run(t, Options{}))
	lease := stageOf(t, res, StageLease)
	if lease.Outcome != StageSkip {
		t.Errorf("lease stage = %q, want skip: %s", lease.Outcome, lease.Message)
	}
	if rev := stageOf(t, res, StageRevocation); rev.Outcome != StageSkip {
		t.Errorf("revocation = %q, want skip when nothing was minted", rev.Outcome)
	}
	// The dispatch itself still has to be proved — that is the half of the
	// circuit a keyless hub genuinely has.
	if d := stageOf(t, res, StageDispatch); d.Outcome != StagePass {
		t.Errorf("dispatch = %q: a hub with no sealing key can still run work", d.Outcome)
	}
}

// --- write-back --------------------------------------------------------

// TestWriteBackSkippedWhereTheBackendHasNone. The container driver's
// /workspace *is* the hub's directory, so there is nothing to ship. Reporting
// that as a pass would claim a capability that was never exercised.
func TestWriteBackSkippedWhereTheBackendHasNone(t *testing.T) {
	w := newSmokeWorld(t)
	res := w.only(t, w.run(t, Options{}))
	if got := stageOf(t, res, StageWriteBack); got.Outcome != StageSkip {
		t.Errorf("write-back = %q, want skip for a backend that does not advertise it", got.Outcome)
	}
}

// TestWriteBackAssertedWhereTheBackendAdvertisesIt.
func TestWriteBackAssertedWhereTheBackendAdvertisesIt(t *testing.T) {
	// Subtests rather than two worlds in one function: newSmokeWorld registers
	// its executor for the lifetime of the *test*, so building two in one
	// would leave both in the registry and smoke each of them twice.
	t.Run("returns the changes", func(t *testing.T) {
		w := newSmokeWorld(t)
		w.ex.caps.SupportsWriteBack = true
		w.ex.writeBack = &executor.WriteBackResult{
			Mode: executor.WriteBackBundle, Branch: "cloop/smoke", CommitSHA: strings.Repeat("a", 40),
		}
		res := w.only(t, w.run(t, Options{}))
		if got := stageOf(t, res, StageWriteBack); got.Outcome != StagePass {
			t.Errorf("write-back = %q, want pass: %s", got.Outcome, got.Message)
		}
	})

	// A driver that advertises the capability but returns nothing is a real
	// failure: a task's commits would be produced in the sandbox and silently
	// lost, which looks like an agent that did no work.
	t.Run("advertised but returns nothing", func(t *testing.T) {
		w := newSmokeWorld(t)
		w.ex.caps.SupportsWriteBack = true
		res := w.only(t, w.run(t, Options{}))
		if got := stageOf(t, res, StageWriteBack); got.Outcome != StageFail {
			t.Errorf("write-back = %q for a driver that advertised it and returned nothing",
				got.Outcome)
		}
	})
}

// --- exit codes --------------------------------------------------------

// TestSmokeExitCodes is requirement four. The values are a contract: a
// readiness gate and a CI step are both built on them, and changing one is a
// breaking change to every pipeline that greps it.
func TestSmokeExitCodes(t *testing.T) {
	failure := Finding{Check: "x", Severity: SeverityFail}
	cases := []struct {
		name string
		rep  Report
		want int
	}{
		{"smoke not requested falls back to the plain code",
			Report{Findings: []Finding{failure}}, SmokeExitConfig},
		{"all clear", Report{SmokeRan: true, Smoke: []SmokeResult{{ExecutorID: "a"}}}, SmokeExitOK},
		{"nothing to smoke", Report{SmokeRan: true}, SmokeExitNoTargets},
		{"a stage failed",
			Report{SmokeRan: true, Smoke: []SmokeResult{{ExecutorID: "a", FirstFailure: StageDispatch}}},
			SmokeExitFailed},
		{"a leak outranks a stage failure",
			Report{SmokeRan: true, Smoke: []SmokeResult{
				{ExecutorID: "a", FirstFailure: StageDispatch},
				{ExecutorID: "b", Leaked: []string{"container h-1"}},
			}}, SmokeExitLeaked},
		{"config failure with a healthy executor still reports misconfiguration",
			Report{SmokeRan: true, Findings: []Finding{failure}, Smoke: []SmokeResult{{ExecutorID: "a"}}},
			SmokeExitConfig},
		{"a stage failure outranks a config failure, because it is more specific",
			Report{SmokeRan: true, Findings: []Finding{failure},
				Smoke: []SmokeResult{{ExecutorID: "a", FirstFailure: StageLease}}},
			SmokeExitFailed},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.rep.SmokeExitCode(); got != tc.want {
				t.Errorf("SmokeExitCode() = %d, want %d", got, tc.want)
			}
		})
	}

	// The codes must stay distinct, which is the property that makes them
	// worth having at all.
	seen := map[int]string{}
	for name, code := range map[string]int{
		"ok": SmokeExitOK, "config": SmokeExitConfig, "no targets": SmokeExitNoTargets,
		"failed": SmokeExitFailed, "leaked": SmokeExitLeaked,
	} {
		if other, dup := seen[code]; dup {
			t.Errorf("exit code %d means both %q and %q", code, other, name)
		}
		seen[code] = name
	}
	if _, used := seen[2]; used {
		t.Error("exit code 2 is Cobra's usage error; the smoke codes must not reuse it")
	}
}

// TestSmokeCheckIDsAreStable pins the ids a pipeline greps for. Renaming one
// is a breaking change to every gate built on it.
func TestSmokeCheckIDsAreStable(t *testing.T) {
	w := newSmokeWorld(t)
	rep := w.run(t, Options{})
	var found bool
	for _, f := range rep.Findings {
		if f.Check == "smoke.dispatch" {
			found = true
		}
	}
	if !found {
		t.Errorf("no finding carries the stable id \"smoke.dispatch\": %+v", rep.Findings)
	}
	for _, stage := range smokeStageOrder {
		if strings.TrimSpace(string(stage)) == "" {
			t.Error("a stage has an empty id")
		}
	}
}
