package ui

// A takeover the store could not decide is tried again (Task 20451).
//
// The hub process adopting a run used to give up on a lease whose takeover
// ended undecided — the store unreadable for a moment, the database locked, a
// KMS down — with a line on stderr: resumeRun rewrote the owner row without
// it, nobody kept it alive, and the run's git proxy and Kubernetes monitor
// sessions went with it. These pin what happens instead: the lease is kept on
// the owner row and retried until it is held and its sessions are served; an
// error that lasts past the lease's expiry, or past its run, ends as a failure
// recorded on the run; and an egress session a live member serves is left
// with it, named on the row, taken over once that member stops, and ended by
// it when the run ends.

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/internal/statedbtest"
	"github.com/blechschmidt/cloop/pkg/auditaction"
	"github.com/blechschmidt/cloop/pkg/egressbroker"
	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/hubcluster"
	"github.com/blechschmidt/cloop/pkg/hubmetrics"
	"github.com/blechschmidt/cloop/pkg/secretbroker"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// takeoverTest paces retries at first, doubling to four times that, until the
// test ends — and then ends every takeover still kept and waits for its retry
// to stop, before the cleanups registered earlier put back what it reads. Call
// it after the rig and the hooks the retries read are in place.
func takeoverTest(t *testing.T, first time.Duration) {
	t.Helper()
	prevFirst, prevMax, prevNudge := takeoverRetryFirst, takeoverRetryMax, takeoverNudgeSpacing
	prevElsewhere, prevMoved := egressElsewhereCheck, movedEgressCheck
	takeoverRetryFirst, takeoverRetryMax, takeoverNudgeSpacing = first, 4*first, first
	egressElsewhereCheck, movedEgressCheck = first, first
	t.Cleanup(func() {
		for _, p := range pendingTakeovers.all() {
			if p.end("") {
				pendingTakeovers.removeIf(p)
			}
		}
		takeoverRetries.Wait()
		takeoverRetryFirst, takeoverRetryMax, takeoverNudgeSpacing = prevFirst, prevMax, prevNudge
		egressElsewhereCheck, movedEgressCheck = prevElsewhere, prevMoved
	})
}

// errStoreLocked is the undecided answer the tests' store gives.
var errStoreLocked = errors.New("statedb: open state.db: database is locked (SQLITE_BUSY)")

// failLeaseTakeovers makes every attempt to take leaseID over fail as a locked
// store would, until release is called, and counts the attempts.
func failLeaseTakeovers(t *testing.T, leaseID string) (attempts *atomic.Int32, release func()) {
	t.Helper()
	attempts = new(atomic.Int32)
	var released atomic.Bool
	prev := testRestoreSecretLease
	testRestoreSecretLease = func(id string) error {
		if id != leaseID || released.Load() {
			return nil
		}
		attempts.Add(1)
		return errStoreLocked
	}
	t.Cleanup(func() { testRestoreSecretLease = prev })
	return attempts, func() { released.Store(true) }
}

func takeoverCount(kind, outcome string) float64 {
	return value((&Server{}).gatherMetrics(),
		series("cloop_lease_takeovers_total", "kind", kind, "outcome", outcome))
}

// runOwnerOf reads workDir's run owner row.
func runOwnerOf(t *testing.T, node *hubcluster.Node, workDir string) runOwnerMeta {
	t.Helper()
	o, found, err := node.Lookup(ownerRun, workDir)
	if err != nil || !found {
		t.Fatalf("the run's owner row: found %v, %v", found, err)
	}
	var meta runOwnerMeta
	if err := o.Meta(&meta); err != nil {
		t.Fatalf("decode the owner row: %v", err)
	}
	return meta
}

// takeoverRows returns the run's lease_takeover journal rows, oldest first.
func takeoverRows(t *testing.T, workDir string) []state.EventRow {
	t.Helper()
	rows, err := state.ListEventsOfType(workDir, state.EventLeaseTakeover, 50)
	if err != nil {
		t.Fatalf("list the run's lease_takeover rows: %v", err)
	}
	for i, j := 0, len(rows)-1; i < j; i, j = i+1, j-1 {
		if rows[i].ID > rows[j].ID {
			rows[i], rows[j] = rows[j], rows[i]
		}
	}
	return rows
}

// TestAnUndecidedLeaseTakeoverIsRetriedUntilItIsHeld is the restart that met a
// locked store. The first attempt and the next few decide nothing; the lease
// stays named on the run's owner row, with the takeover named as undecided; a
// fetch the workload makes meanwhile waits rather than failing; and once the
// store answers, the lease is held here, its git and Kubernetes sessions are
// served again, a push goes through, and the row names the lease and nothing
// undecided.
func TestAnUndecidedLeaseTakeoverIsRetriedUntilItIsHeld(t *testing.T) {
	setSessionAdoptionWait(t, 30*time.Second)
	r := newRestoreRig(t)
	d := r.dispatch()
	leaseID := d.lease.lease.ID
	work := filepath.Join(t.TempDir(), "work")
	if out, err := r.git(d, "", "clone", r.gitSrv.URL+"/"+restoreRepo, work); err != nil {
		t.Fatalf("clone before the restart: %v\n%s", err, out)
	}

	node := joinTestNode(t, r.dir, nil)
	asProcess(t, node)
	if _, ok, err := node.Claim(ownerRun, r.dir, runOwnerMeta{Executor: r.ex.ID(), Handle: "h-1",
		Leases: []string{leaseID}}); err != nil || !ok {
		t.Fatalf("claim the adopted run = %v, %v", ok, err)
	}
	r.clock.Advance(time.Minute)
	r.restart(d, node.ID())
	attempts, release := failLeaseTakeovers(t, leaseID)
	takeoverTest(t, 20*time.Millisecond)
	retryingBefore := takeoverCount(hubmetrics.TakeoverKindRun, hubmetrics.TakeoverRetrying)
	takenBefore := takeoverCount(hubmetrics.TakeoverKindRun, hubmetrics.TakeoverTakenOver)

	s := &Server{WorkDir: r.dir, Cluster: node}
	s.takeOverRunLeases(r.dir, r.ex, "h-1", []string{leaseID})
	if registeredLease(leaseID) != nil {
		t.Fatal("the lease was held although its takeover failed")
	}
	if pendingTakeovers.get(takeoverRun, leaseID) == nil {
		t.Fatal("the undecided takeover was dropped instead of kept")
	}
	// resumeRun records the run from what this process holds: the lease it
	// could not take over is on the row still, and named as undecided.
	if err := s.recordRunDispatch(r.dir, "adopted", r.ex, "h-1"); err != nil {
		t.Fatalf("record the adopted run: %v", err)
	}
	meta := runOwnerOf(t, node, r.dir)
	if len(meta.Leases) != 1 || meta.Leases[0] != leaseID {
		t.Fatalf("the adopted run's owner row names leases %v, want [%s]", meta.Leases, leaseID)
	}
	if len(meta.Takeovers) != 1 || meta.Takeovers[0].Kind != takeoverRun || meta.Takeovers[0].ID != leaseID ||
		!strings.Contains(meta.Takeovers[0].Reason, "database is locked") || meta.Takeovers[0].Until.IsZero() {
		t.Fatalf("the owner row's undecided takeovers = %+v", meta.Takeovers)
	}
	if rows := takeoverRows(t, r.dir); len(rows) != 1 || !strings.Contains(rows[0].Message, "could not be taken over") ||
		!strings.Contains(rows[0].Message, "database is locked") || !strings.Contains(rows[0].Details, `"outcome":"retrying"`) {
		t.Fatalf("the run's history = %+v, want one row saying the takeover is retried", rows)
	}

	// The workload fetches while the store is still locked: held, not refused.
	fetched := make(chan error, 1)
	go func() {
		out, err := r.git(d, work, "fetch", "origin")
		if err != nil {
			err = errors.New(err.Error() + ": " + out)
		}
		fetched <- err
	}()
	waitFor(t, 10*time.Second, "the workload's fetch to be held", func() bool { return heldSessionWaits() > 0 })
	waitFor(t, 10*time.Second, "a few retries", func() bool { return attempts.Load() >= 4 })
	if registeredLease(leaseID) != nil {
		t.Fatal("the lease was held while every attempt failed")
	}

	release()
	waitFor(t, 10*time.Second, "the lease to be taken over", func() bool { return registeredLease(leaseID) != nil })
	taken := registeredLease(leaseID)
	stopKeepaliveForTest(taken)
	if err := <-fetched; err != nil {
		t.Fatalf("the fetch held across the retries failed: %v", err)
	}
	if rec, _ := r.db.GetSecretLease(leaseID); rec.Holder != node.ID() {
		t.Fatalf("the lease's record is held by %q after the retry, want %s", rec.Holder, node.ID())
	}
	git, kube := activeGitProxy(), activeKubeGuard()
	if !git.reg.Known(d.gitID) || !kube.reg.Known(d.kubeID) {
		t.Fatalf("restored after the retry: git %v, kube %v", git.reg.Known(d.gitID), kube.reg.Known(d.kubeID))
	}
	if code := r.kube(d, "/api/v1/namespaces/app/pods"); code != 200 {
		t.Fatalf("kubectl after the retried takeover = %d", code)
	}
	if err := os.WriteFile(filepath.Join(work, "retried.txt"), []byte("after the retry\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{
		{"add", "retried.txt"},
		{"-c", "user.email=a@b.invalid", "-c", "user.name=t", "commit", "-qm", "after the retry"},
		{"push", "origin", "HEAD:refs/heads/cloop/after-retry"},
	} {
		if out, err := r.git(d, work, args...); err != nil {
			t.Fatalf("git %s after the retried takeover: %v\n%s", args[0], err, out)
		}
	}
	if r.forge.Ref(t, restoreRepo, "refs/heads/cloop/after-retry") == "" {
		t.Fatal("the push after the retried takeover did not reach the forge")
	}

	waitFor(t, 5*time.Second, "the takeover to be forgotten", func() bool {
		return pendingTakeovers.get(takeoverRun, leaseID) == nil
	})
	meta = runOwnerOf(t, node, r.dir)
	if len(meta.Leases) != 1 || meta.Leases[0] != leaseID || len(meta.Takeovers) != 0 {
		t.Fatalf("the owner row after the takeover names leases %v and undecided %+v", meta.Leases, meta.Takeovers)
	}
	rows := takeoverRows(t, r.dir)
	if len(rows) != 2 || !strings.Contains(rows[1].Message, "was taken over") ||
		!strings.Contains(rows[1].Details, `"outcome":"taken_over"`) {
		t.Fatalf("the run's history = %+v, want the retry and then the takeover", rows)
	}
	if got := takeoverCount(hubmetrics.TakeoverKindRun, hubmetrics.TakeoverRetrying) - retryingBefore; got < 4 {
		t.Errorf("retrying attempts counted %v, want every failed one (%d)", got, attempts.Load())
	}
	if got := takeoverCount(hubmetrics.TakeoverKindRun, hubmetrics.TakeoverTakenOver) - takenBefore; got != 1 {
		t.Errorf("taken_over counted %v, want 1", got)
	}
	taken.Close()
}

// TestAnUndecidedTakeoverThatOutlivesItsLeaseFails: the store stays locked past
// the lease's recorded expiry. The takeover is retried until then and no
// longer, recorded on the run as failed with the reason, and the lease leaves
// the owner row — its record is the janitor's to sweep.
func TestAnUndecidedTakeoverThatOutlivesItsLeaseFails(t *testing.T) {
	ex := newTakeoverExecutor("edge-undecided")
	h := newTakeoverHub(t, ex.ID())
	old := h.dispatch(t, ex, "h-9")
	leaseID := old.lease.ID
	liveLeases.removeIf(old)
	node := joinTestNode(t, h.dir, nil)
	h.holder = node.ID()
	if _, ok, err := node.Claim(ownerRun, h.dir, runOwnerMeta{Executor: ex.ID(), Handle: "h-9",
		Leases: []string{leaseID}}); err != nil || !ok {
		t.Fatalf("claim the adopted run = %v, %v", ok, err)
	}
	attempts, _ := failLeaseTakeovers(t, leaseID)
	prevNow := takeoverNow
	takeoverNow = h.clock.Now
	t.Cleanup(func() { takeoverNow = prevNow })
	takeoverTest(t, 10*time.Millisecond)
	failedBefore := takeoverCount(hubmetrics.TakeoverKindRun, hubmetrics.TakeoverFailed)

	s := &Server{WorkDir: h.dir, Cluster: node}
	s.takeOverRunLeases(h.dir, ex, "h-9", []string{leaseID})
	if err := s.recordRunDispatch(h.dir, "adopted", ex, "h-9"); err != nil {
		t.Fatalf("record the adopted run: %v", err)
	}
	rec, ok := h.record(t, leaseID)
	if !ok {
		t.Fatal("the lease has no record")
	}
	if meta := runOwnerOf(t, node, h.dir); len(meta.Takeovers) != 1 || !meta.Takeovers[0].Until.Equal(rec.ExpiresAt) {
		t.Fatalf("the undecided takeover is tried until %+v, want the lease's recorded expiry %s", meta.Takeovers,
			rec.ExpiresAt)
	}
	waitFor(t, 10*time.Second, "a few retries", func() bool { return attempts.Load() >= 3 })

	// The lease lapses with the store still locked.
	h.clock.advance(rec.ExpiresAt.Sub(h.clock.Now()) + time.Minute)
	waitFor(t, 10*time.Second, "the takeover to end", func() bool {
		return pendingTakeovers.get(takeoverRun, leaseID) == nil
	})
	if registeredLease(leaseID) != nil {
		t.Fatal("a lease whose every takeover failed is held")
	}
	rows := takeoverRows(t, h.dir)
	if len(rows) != 2 || !strings.Contains(rows[1].Message, "was never taken over") ||
		!strings.Contains(rows[1].Message, "lapsed") || !strings.Contains(rows[1].Message, "database is locked") ||
		!strings.Contains(rows[1].Details, `"outcome":"failed"`) {
		t.Fatalf("the run's history = %+v, want the retry and then the failure, with the reason", rows)
	}
	if got := takeoverCount(hubmetrics.TakeoverKindRun, hubmetrics.TakeoverFailed) - failedBefore; got != 1 {
		t.Errorf("failed takeovers counted %v, want 1", got)
	}
	meta := runOwnerOf(t, node, h.dir)
	if len(meta.Leases) != 0 || len(meta.Takeovers) != 0 {
		t.Fatalf("the owner row still names leases %v and undecided %+v after the lease lapsed", meta.Leases,
			meta.Takeovers)
	}
	if _, ok := h.record(t, leaseID); !ok {
		t.Error("the failed takeover retired the lease's record; that is the janitor's, once it can read it")
	}
}

// TestATakeoverUndecidedWhenItsRunEndsFails: the run ends while its lease is
// still undecided. The takeover is recorded as failed — the run never had it
// back — and the lease's record is retired, the store permitting.
func TestATakeoverUndecidedWhenItsRunEndsFails(t *testing.T) {
	ex := newTakeoverExecutor("edge-ended")
	h := newTakeoverHub(t, ex.ID())
	old := h.dispatch(t, ex, "h-8")
	leaseID := old.lease.ID
	liveLeases.removeIf(old)
	h.holder = "hub_adopter"
	failLeaseTakeovers(t, leaseID)
	takeoverTest(t, time.Hour)

	s := &Server{WorkDir: h.dir}
	s.takeOverRunLeases(h.dir, ex, "h-8", []string{leaseID})
	if pendingTakeovers.get(takeoverRun, leaseID) == nil {
		t.Fatal("the undecided takeover is not kept")
	}
	s.endRunTakeovers(ex, "h-8", "the run ended", true)
	if pendingTakeovers.get(takeoverRun, leaseID) != nil {
		t.Fatal("the takeover outlived its run")
	}
	rows := takeoverRows(t, h.dir)
	if len(rows) != 2 || !strings.Contains(rows[1].Message, "the run ended before it could be taken over") {
		t.Fatalf("the run's history = %+v, want the retry and then the failure", rows)
	}
	if _, ok := h.record(t, leaseID); ok {
		t.Error("the lease of a run that ended is still recorded")
	}
}

// TestAnUndecidedWorkspaceTakeoverIsRetried: the same for the workspace lease
// a device's push write-back stands on — kept on the owner row while
// undecided, then held, its pinned session served, and the write-back push
// landing.
func TestAnUndecidedWorkspaceTakeoverIsRetried(t *testing.T) {
	setSessionAdoptionWait(t, 20*time.Second)
	r := newWorkspaceRestoreRig(t)
	r.pinOrigin(r.forgeRepoURL())
	d := r.dispatchWorkspace()
	sessionID, leaseID := d.access.Credential.SessionID, d.access.Credential.LeaseID
	work := filepath.Join(t.TempDir(), "tool")
	if out, err := r.gitAs(d, "", "clone", "-q", d.access.Repo, work); err != nil {
		t.Fatalf("the provisioning fetch: %v\n%s", err, out)
	}
	r.restartWorkspace(d, "hub_new")
	attempts, release := failLeaseTakeovers(t, leaseID)
	takeoverTest(t, 20*time.Millisecond)

	s := &Server{WorkDir: r.dir}
	s.takeOverWorkspaceLease(r.dir, r.ex, "h-1", d.meta)
	if registeredLease(leaseID) != nil || pendingTakeovers.get(takeoverWorkspace, leaseID) == nil {
		t.Fatal("the undecided workspace takeover was not kept")
	}
	var meta runOwnerMeta
	fillRunCredentials(&meta, r.ex.ID(), "h-1")
	if meta.Workspace == nil || meta.Workspace.Lease != leaseID || meta.Workspace.Session != sessionID ||
		len(meta.Takeovers) != 1 || meta.Takeovers[0].Kind != takeoverWorkspace {
		t.Fatalf("the owner row would name workspace %+v and undecided %+v", meta.Workspace, meta.Takeovers)
	}
	waitFor(t, 10*time.Second, "a retry", func() bool { return attempts.Load() >= 2 })
	release()
	waitFor(t, 10*time.Second, "the workspace lease to be taken over", func() bool {
		sl := registeredLease(leaseID)
		return sl != nil && sl.isWorkspace()
	})
	stopKeepaliveForTest(registeredLease(leaseID))
	if row, _ := r.session(statedb.ProxySessionGit, sessionID); row.Holder != "hub_new" || !row.Open() {
		t.Fatalf("the pinned session's record after the retried takeover = %+v", row)
	}
	commitAndPush(t, r, d, work, "refs/heads/cloop/run-after-retry")
	if r.forge.Ref(t, restoreRepo, "refs/heads/cloop/run-after-retry") == "" {
		t.Fatal("the write-back push did not reach the forge")
	}
	if rows := takeoverRows(t, r.dir); len(rows) != 2 || !strings.Contains(rows[0].Message, "workspace lease") ||
		!strings.Contains(rows[1].Details, `"outcome":"taken_over"`) {
		t.Fatalf("the run's history = %+v", rows)
	}
}

// TestALiveMembersEgressSessionIsKeptAndTakenOverWhenItStops is the adopter's
// half of a run moving between two live members: the egress session the old
// member serves stays there — nothing forwards egress — but the run's owner
// row names it still, as nothing undecided, and once that member stops this
// one takes it over.
func TestALiveMembersEgressSessionIsKeptAndTakenOverWhenItStops(t *testing.T) {
	prevHolder := leaseHolderID
	var holder atomic.Value
	holder.Store("hub_old")
	leaseHolderID = func() string { return holder.Load().(string) }
	t.Cleanup(func() { leaseHolderID = prevHolder })
	var oldAlive atomic.Bool
	oldAlive.Store(true)
	prevAlive := egressHolderAlive
	egressHolderAlive = func(h string) bool { return h == "hub_old" && oldAlive.Load() }
	t.Cleanup(func() { egressHolderAlive = prevAlive })
	_, svc := hostEgress(t, nil)

	project := statedbtest.Dir(t)
	grantEgress(t, svc, "project:"+project, nil)
	ex := newEgressStub("egress-moved-adopter", executor.KindLocalProcess)
	_, egr, err := applyEgressSession(executor.Spec{Env: []string{}}, ex, project, nil, egressRun{runID: "run-m"})
	if err != nil || egr == nil {
		t.Fatalf("applyEgressSession = %v, %v", egr, err)
	}
	h, err := ex.Start(context.Background(), executor.Spec{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ex.finish(h.ID, 0, time.Second) })
	egr.bindHandle(ex, h.ID)
	id := egr.sess.ID

	holder.Store("hub_new")
	takeoverTest(t, 20*time.Millisecond)
	movedBefore := takeoverCount(hubmetrics.TakeoverKindEgress, hubmetrics.TakeoverMoved)
	takenBefore := takeoverCount(hubmetrics.TakeoverKindEgress, hubmetrics.TakeoverTakenOver)
	s := &Server{WorkDir: project}
	s.restoreRunEgress(project, ex, h.ID, []string{id})
	var meta runOwnerMeta
	fillRunCredentials(&meta, ex.ID(), h.ID)
	if len(meta.Egress) != 1 || meta.Egress[0] != id || len(meta.Takeovers) != 0 {
		t.Fatalf("the adopter's owner row would name egress %v and undecided %+v, want the session and nothing "+
			"undecided", meta.Egress, meta.Takeovers)
	}
	if got := takeoverCount(hubmetrics.TakeoverKindEgress, hubmetrics.TakeoverMoved) - movedBefore; got != 1 {
		t.Errorf("moved egress takeovers counted %v, want 1", got)
	}
	time.Sleep(100 * time.Millisecond) // several looks while the old member serves it
	if row, _ := svc.db.GetProxySession(statedb.ProxySessionEgress, id); row.Holder != "hub_old" {
		t.Fatalf("the session was taken from its live holder: %+v", row)
	}

	// The old member stops: its session is suspended for the adopter, and
	// the adopter takes it over.
	egr.suspend("the hub is shutting down")
	oldAlive.Store(false)
	wakeTakeoversHeldElsewhere()
	waitFor(t, 10*time.Second, "the adopter to take the session over", func() bool {
		return liveEgress.byHandle(h.ID) != nil
	})
	restored := liveEgress.byHandle(h.ID)
	t.Cleanup(func() { restored.close("test over") })
	waitFor(t, 10*time.Second, "the takeover to end", func() bool {
		return pendingTakeovers.get(takeoverEgress, id) == nil
	})
	if row, _ := svc.db.GetProxySession(statedb.ProxySessionEgress, id); row.Holder != "hub_new" || !row.Open() {
		t.Fatalf("the session's record after the takeover = %+v", row)
	}
	if got := takeoverCount(hubmetrics.TakeoverKindEgress, hubmetrics.TakeoverTakenOver) - takenBefore; got != 1 {
		t.Errorf("taken over egress sessions counted %v, want 1", got)
	}
	rows := takeoverRows(t, project)
	if len(rows) != 2 || !strings.Contains(rows[0].Message, "stays with hub process hub_old") ||
		!strings.Contains(rows[1].Message, "the one that served it stopped") {
		t.Fatalf("the run's history = %+v", rows)
	}
}

// TestAMovedRunsEgressSessionEndsWithTheRun is the old member's half: it keeps
// serving the session of a run another member adopted, and ends it as soon as
// the run's owner row no longer names the run — instead of renewing it for a
// day because it cannot ask the device about a run it no longer follows.
func TestAMovedRunsEgressSessionEndsWithTheRun(t *testing.T) {
	// A holder, so the session is recorded as the old member's.
	prevHolder := leaseHolderID
	leaseHolderID = func() string { return "hub_old" }
	t.Cleanup(func() { leaseHolderID = prevHolder })
	_, svc := hostEgress(t, nil)
	project := statedbtest.Dir(t)
	grantEgress(t, svc, "project:"+project, nil)
	ex := newEgressStub("egress-moved-old", executor.KindLocalProcess)
	_, egr, err := applyEgressSession(executor.Spec{Env: []string{}}, ex, project, nil, egressRun{runID: "run-o"})
	if err != nil || egr == nil {
		t.Fatalf("applyEgressSession = %v, %v", egr, err)
	}
	h, err := ex.Start(context.Background(), executor.Spec{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ex.finish(h.ID, 0, time.Second) })
	egr.bindHandle(ex, h.ID)
	t.Cleanup(func() { egr.close("test over") })
	if row, err := svc.db.GetProxySession(statedb.ProxySessionEgress, egr.sess.ID); err != nil || row.Holder != "hub_old" {
		t.Fatalf("the session's record = %+v, %v", row, err)
	}

	node := joinTestNode(t, project, nil)
	adopter := joinTestNode(t, project, nil)
	if _, ok, err := adopter.Claim(ownerRun, project, runOwnerMeta{Executor: ex.ID(), Handle: h.ID,
		Egress: []string{egr.sess.ID}}); err != nil || !ok {
		t.Fatalf("the adopter claims the run = %v, %v", ok, err)
	}
	takeoverTest(t, 20*time.Millisecond)
	s := &Server{WorkDir: project, Cluster: node}
	done := make(chan struct{})
	go func() {
		defer close(done)
		s.followMovedRunEgress(project, egr, ex.ID(), h.ID)
	}()
	time.Sleep(100 * time.Millisecond)
	if egr.sess.Closed() {
		t.Fatal("the session ended while its run was live on the member that adopted it")
	}

	// The run ends on the adopter, which releases its claim.
	if ok, err := adopter.Release(ownerRun, project); err != nil || !ok {
		t.Fatalf("release the run's claim = %v, %v", ok, err)
	}
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("the session outlived its run")
	}
	if !egr.sess.Closed() || !strings.Contains(egr.sess.CloseReason(), "its run ended on the hub process that adopted it") {
		t.Fatalf("the session closed %v: %q", egr.sess.Closed(), egr.sess.CloseReason())
	}
	if row, _ := svc.db.GetProxySession(statedb.ProxySessionEgress, egr.sess.ID); row.Open() {
		t.Fatalf("the session's record is still open: %+v", row)
	}

	// The project's next run, claimed by this member before it names a
	// workload, is no run of this session's either.
	if _, ok, err := node.Claim(ownerRun, project, runOwnerMeta{
		RunClaimMeta: hubcluster.RunClaimMeta{Dispatching: true}}); err != nil || !ok {
		t.Fatalf("claim the next run = %v, %v", ok, err)
	}
	if v, why := s.movedRunEgressVerdict(project, egr, ex.ID(), h.ID); v != movedEgressOver {
		t.Fatalf("a claim of this member's naming no workload reads as %d (%s), want the run over", v, why)
	}
}

// TestARetryNeverTakesBackALeaseTheRunsNewOwnerHolds: the run moved to
// another live member, which took its lease over, while this member's
// takeover was undecided. This member's next attempt ends its takeover as
// moved and leaves the lease where it is — and the broker's own guard, asked
// just before the conditional write, refuses the take as well.
func TestARetryNeverTakesBackALeaseTheRunsNewOwnerHolds(t *testing.T) {
	ex := newTakeoverExecutor("edge-moved-on")
	h := newTakeoverHub(t, ex.ID())
	old := h.dispatch(t, ex, "h-7")
	leaseID := old.lease.ID
	liveLeases.removeIf(old)
	a := joinTestNode(t, h.dir, nil)
	b := joinTestNode(t, h.dir, nil)
	h.holder = a.ID()
	meta := runOwnerMeta{Executor: ex.ID(), Handle: "h-7", Leases: []string{leaseID}}
	if _, ok, err := a.Claim(ownerRun, h.dir, meta); err != nil || !ok {
		t.Fatalf("claim the adopted run = %v, %v", ok, err)
	}
	_, release := failLeaseTakeovers(t, leaseID)
	takeoverTest(t, time.Hour) // the test makes the attempts
	sa := &Server{WorkDir: h.dir, Cluster: a}
	sa.takeOverRunLeases(h.dir, ex, "h-7", []string{leaseID})
	p := pendingTakeovers.get(takeoverRun, leaseID)
	if p == nil {
		t.Fatal("the undecided takeover is not kept")
	}

	// The agent reconnects to B, which adopts the run and takes the lease.
	o, found, err := b.Lookup(ownerRun, h.dir)
	if err != nil || !found {
		t.Fatalf("B reads the run's row: %v, %v", found, err)
	}
	if ok, err := b.Adopt(o, meta); err != nil || !ok {
		t.Fatalf("B adopts the run = %v, %v", ok, err)
	}
	db, err := statedb.Open(state.DBPath(h.dir))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if ok, err := db.TakeSecretLease(leaseID, "hub_dispatcher", b.ID()); err != nil || !ok {
		t.Fatalf("B takes the lease = %v, %v", ok, err)
	}

	release()
	if !sa.attemptPending(p) {
		t.Fatal("the retry did not end once the run had moved")
	}
	if rec, _ := h.record(t, leaseID); rec.Holder != b.ID() {
		t.Fatalf("the lease is held by %q, want the run's new owner %s", rec.Holder, b.ID())
	}
	if registeredLease(leaseID) != nil {
		t.Fatal("the member the run moved away from holds the lease")
	}

	// Asked directly, the guard refuses too: this member does not own the run.
	if _, err := restoreSecretLease(h.dir, h.dir, leaseID, sa.takeoverGuard(h.dir)); !errors.Is(err, secretbroker.ErrLeaseMoved) {
		t.Fatalf("a takeover by a member that does not own the run = %v, want ErrLeaseMoved", err)
	}
	if rec, _ := h.record(t, leaseID); rec.Holder != b.ID() {
		t.Fatalf("the guarded takeover moved the lease to %q", rec.Holder)
	}
}

// TestAnAttemptEndedWhileItRunsLetsGoOfWhatItTook: the run ends while a retry
// is in the middle of taking its lease over. The record is not retired under
// the attempt, and the attempt, finding its takeover over, releases the lease
// it took — once.
func TestAnAttemptEndedWhileItRunsLetsGoOfWhatItTook(t *testing.T) {
	ex := newTakeoverExecutor("edge-raced")
	h := newTakeoverHub(t, ex.ID())
	old := h.dispatch(t, ex, "h-6")
	leaseID := old.lease.ID
	liveLeases.removeIf(old)
	h.holder = "hub_adopter"
	entered, proceed := make(chan struct{}), make(chan struct{})
	var calls atomic.Int32
	var once sync.Once
	prev := testRestoreSecretLease
	testRestoreSecretLease = func(id string) error {
		if id != leaseID {
			return nil
		}
		if calls.Add(1) == 1 {
			return errStoreLocked
		}
		once.Do(func() { close(entered) })
		<-proceed
		return nil
	}
	t.Cleanup(func() { testRestoreSecretLease = prev })
	takeoverTest(t, 10*time.Millisecond)

	s := &Server{WorkDir: h.dir}
	s.takeOverRunLeases(h.dir, ex, "h-6", []string{leaseID})
	select {
	case <-entered:
	case <-time.After(10 * time.Second):
		t.Fatal("the retry never started")
	}
	s.endRunTakeovers(ex, "h-6", "the run ended", true)
	if _, ok := h.record(t, leaseID); !ok {
		t.Fatal("the lease's record was retired under a running attempt")
	}
	close(proceed)
	waitFor(t, 10*time.Second, "the attempt to let go of the lease", func() bool {
		_, recorded := h.record(t, leaseID)
		return registeredLease(leaseID) == nil && !recorded
	})
	if n := len(h.audit(t, auditaction.Action(secretbroker.ActionRelease), leaseID)); n != 1 {
		t.Errorf("release rows = %d, want one", n)
	}
	rows := takeoverRows(t, h.dir)
	if len(rows) != 2 || !strings.Contains(rows[1].Details, `"outcome":"failed"`) {
		t.Fatalf("the run's history = %+v, want the retry and the failure only", rows)
	}
}

// TestUndecidedTakeoversAreNamedApartFromWhatIsHeld: the owner row names what
// this process holds and what it keeps trying in one list each — a later
// adopter takes both over — and only the undecided ones among the takeovers
// the doctor reports.
func TestUndecidedTakeoversAreNamedApartFromWhatIsHeld(t *testing.T) {
	takeoverTest(t, time.Hour)
	ex := newTakeoverExecutor("edge-names")
	s := &Server{}
	for _, c := range []struct{ kind, id, holder string }{
		{takeoverRun, "lea_b", ""}, {takeoverRun, "lea_a", ""}, {takeoverEgress, "egs_1", ""}, {takeoverEgress, "egs_2", "hub_x"},
	} {
		res := takeoverResult{outcome: hubmetrics.TakeoverRetrying, err: errStoreLocked}
		if c.holder != "" {
			res = takeoverResult{outcome: hubmetrics.TakeoverMoved, holder: c.holder}
		}
		s.settleFirstTakeover(c.kind, "", ex, "h-n", c.id, "", res)
	}
	var meta runOwnerMeta
	fillRunCredentials(&meta, ex.ID(), "h-n")
	if strings.Join(meta.Leases, ",") != "lea_a,lea_b" || strings.Join(meta.Egress, ",") != "egs_1,egs_2" {
		t.Fatalf("the row names leases %v and egress %v", meta.Leases, meta.Egress)
	}
	var undecided []string
	for _, tk := range meta.Takeovers {
		undecided = append(undecided, tk.Kind+"/"+tk.ID)
	}
	if strings.Join(undecided, ",") != "egress/egs_1,run/lea_a,run/lea_b" {
		t.Fatalf("undecided takeovers on the row = %v", undecided)
	}
	// Another workload's are not this one's.
	fillRunCredentials(&meta, ex.ID(), "h-other")
	if len(meta.Leases)+len(meta.Egress)+len(meta.Takeovers) != 0 {
		t.Fatalf("another handle's row names %+v", meta)
	}

	// Handed over with the run, each counts as moved once: the session left
	// with its holder counted when it was.
	movedBefore := takeoverCount(hubmetrics.TakeoverKindEgress, hubmetrics.TakeoverMoved)
	s.handOverRunTakeovers(ex, "h-n")
	if got := takeoverCount(hubmetrics.TakeoverKindEgress, hubmetrics.TakeoverMoved) - movedBefore; got != 1 {
		t.Errorf("egress takeovers counted moved %v times on the handover, want once (the undecided one)", got)
	}
	if left := pendingTakeovers.forHandle(ex.ID(), "h-n"); len(left) != 0 {
		t.Errorf("kept after the handover: %d", len(left))
	}
}

// The default deadline, for a record that cannot be read at all, is the
// longest a lease or a session is issued for.
func TestATakeoverWhoseRecordCannotBeReadIsTriedForAsLongAsItCouldLive(t *testing.T) {
	controlPlaneDirMu.Lock()
	prev := controlPlaneDirValue
	controlPlaneDirValue = filepath.Join(t.TempDir(), "nowhere")
	controlPlaneDirMu.Unlock()
	t.Cleanup(func() {
		controlPlaneDirMu.Lock()
		controlPlaneDirValue = prev
		controlPlaneDirMu.Unlock()
	})
	since := time.Date(2026, 10, 27, 4, 30, 0, 0, time.UTC)
	if got := takeoverDeadline(takeoverRun, "lea_x", since); !got.Equal(since.Add(15 * time.Minute)) {
		t.Errorf("an unreadable lease is tried until %s", got)
	}
	if got := takeoverDeadline(takeoverEgress, "egs_x", since); !got.Equal(since.Add(egressbroker.DefaultSessionTTL)) {
		t.Errorf("an unreadable egress session is tried until %s", got)
	}
}

// TestAHandedOverRunIsMarkedBeforeItsStreamIsCancelled: the consumer of a run's
// output, which the cancel wakes, asks takeHandedOver whether to settle the
// run. Marked only afterwards, a run another member adopted was settled here
// as well — its egress session closed, its result merged, and the records of
// what this member had not taken over yet retired under the member that owns
// the run now.
func TestAHandedOverRunIsMarkedBeforeItsStreamIsCancelled(t *testing.T) {
	takeoverTest(t, time.Hour)
	dir := statedbtest.Dir(t)
	s := &Server{WorkDir: dir}
	ex := newTakeoverExecutor("edge-detach")
	var markedAtCancel bool
	s.trackRunWithCancel(dir, ex, "h-d", func() { markedAtCancel = s.takeHandedOver("h-d") })
	if !s.detachRun(dir) {
		t.Fatal("detachRun found no run to let go of")
	}
	if !markedAtCancel {
		t.Fatal("the run's stream was cancelled before the run was marked handed over: its consumer would " +
			"settle a run another member owns")
	}
	if s.takeHandedOver("h-d") {
		t.Error("a mark nobody takes was left behind")
	}

	// Detached twice — on the bus's word and the watcher's — it is marked
	// once: a second mark would be taken by the next run of the same handle,
	// should the run come back here, which then would never be settled.
	markedAtCancel = false
	s.trackRunWithCancel(dir, ex, "h-e", func() { markedAtCancel = s.takeHandedOver("h-e") })
	s.runHandleMu.Lock()
	cur := s.runHandles[dir]
	cur.handedOver = true // the first detach, still under way
	s.runHandles[dir] = cur
	s.runHandleMu.Unlock()
	if !s.detachRun(dir) {
		t.Fatal("a run being let go of was reported as not tracked")
	}
	if markedAtCancel || s.takeHandedOver("h-e") {
		t.Fatal("the second detach marked the run again, or cancelled its stream")
	}
}

// TestALeaseLostWhileThisMemberOwnsTheRunIsTriedAgain: losing the lease's
// conditional write while this member owns the run means a process that does
// not own it took the lease — a retry it made as the run moved here — so the
// takeover is tried again, and taken from that process; losing it when the
// run is another member's leaves it moved.
func TestALeaseLostWhileThisMemberOwnsTheRunIsTriedAgain(t *testing.T) {
	takeoverTest(t, time.Hour)
	dir := statedbtest.Dir(t)
	a := joinTestNode(t, dir, nil)
	b := joinTestNode(t, dir, nil)
	ex := newTakeoverExecutor("edge-lost-write")
	meta := runOwnerMeta{Executor: ex.ID(), Handle: "h-w"}
	if _, ok, err := a.Claim(ownerRun, dir, meta); err != nil || !ok {
		t.Fatalf("claim = %v, %v", ok, err)
	}
	moved := takeoverResult{outcome: hubmetrics.TakeoverMoved, err: errors.New("lease taken over by another hub process first")}
	sa, sb := &Server{WorkDir: dir, Cluster: a}, &Server{WorkDir: dir, Cluster: b}
	if got := sa.lostWhileOwned(dir, ex, "h-w", moved); !got.undecided() {
		t.Fatalf("lost by the run's owner = %+v, want it tried again", got)
	}
	if got := sb.lostWhileOwned(dir, ex, "h-w", moved); got.outcome != hubmetrics.TakeoverMoved {
		t.Fatalf("lost by a member that does not own the run = %+v, want moved", got)
	}
	if got := sa.lostWhileOwned(dir, ex, "h-other", moved); got.outcome != hubmetrics.TakeoverMoved {
		t.Fatalf("lost for a workload that is not the run on record = %+v, want moved", got)
	}
	if got := (&Server{WorkDir: dir}).lostWhileOwned(dir, ex, "h-w", moved); got.outcome != hubmetrics.TakeoverMoved {
		t.Fatalf("lost by a hub with no cluster = %+v, want moved", got)
	}
}
