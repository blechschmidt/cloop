package ui

// A workspace's pinned git proxy session lives exactly as long as its run
// needs it (Task 20422): ended once the driver is done with it, renewed while
// the run lives — by the source that minted it, and after a restart by the
// hub process that adopted the run — so a run longer than session_minutes
// still writes its work back. On the restore rig: real git through the proxy,
// on a clock the test drives.

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/auditaction"
	"github.com/blechschmidt/cloop/pkg/gitproxy"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// shortSessionRig is the restore rig minting 20-minute workspace sessions,
// renewed as soon as one is due.
func shortSessionRig(t *testing.T) *restoreRig {
	t.Helper()
	prev := workspaceSessionRenewEvery
	workspaceSessionRenewEvery = 2 * time.Millisecond
	t.Cleanup(func() { workspaceSessionRenewEvery = prev })
	r := newRestoreRig(t)
	r.gitTTL = 20 * time.Minute
	r.startProcess()
	r.pinOrigin(r.forgeRepoURL())
	return r
}

// liveSession returns the session the dispatching process's registry serves.
func liveSession(t *testing.T, id string) *gitproxy.Session {
	t.Helper()
	s, err := activeGitProxy().reg.Session(id)
	if err != nil {
		t.Fatalf("the session is not served: %v", err)
	}
	return s
}

// TestAWorkspaceSessionEndsWhenItsRunIsDoneWithIt is the defect: a session the
// sandbox had used kept its full TTL — an hour by default, up to twelve —
// after its run ended, for anything that lifted its token out of the sandbox.
// Now the driver's release, which it makes once the workload is terminal and
// its write-back has run, ends it at once, with the lease it stood on.
func TestAWorkspaceSessionEndsWhenItsRunIsDoneWithIt(t *testing.T) {
	r := newRestoreRig(t)
	r.pinOrigin(r.forgeRepoURL())
	d := r.dispatchWorkspace()
	sessionID, leaseID := d.access.Credential.SessionID, d.access.Credential.LeaseID
	work := filepath.Join(t.TempDir(), "tool")
	if out, err := r.gitAs(d, "", "clone", "-q", d.access.Repo, work); err != nil {
		t.Fatalf("the provisioning fetch: %v\n%s", err, out)
	}
	commitAndPush(t, r, d, work, "refs/heads/cloop/run-done")

	d.release()

	if activeGitProxy().reg.Known(sessionID) {
		t.Fatal("the session outlived the driver's release")
	}
	row, _ := r.session(statedb.ProxySessionGit, sessionID)
	if row.Open() || !strings.Contains(row.CloseReason, "done with its workspace credential") {
		t.Fatalf("the session's record = %+v, want it closed as the run's", row)
	}
	if registeredLease(leaseID) != nil {
		t.Fatal("the workspace lease outlived its session")
	}
	if err := pushFrom(r, d, work, "refs/heads/cloop/after-the-run"); err == nil {
		t.Fatal("the token pushed after its run was done with it")
	}
	if r.forge.Ref(t, restoreRepo, "refs/heads/cloop/after-the-run") != "" {
		t.Fatal("a push after the run reached the forge")
	}
}

// TestAWorkspaceSessionIsRenewedWhileItsRunLives: a run longer than
// session_minutes still writes its work back, because the session is renewed
// while the driver holds it — recorded, so a restart keeps the renewal, and on
// the trail.
func TestAWorkspaceSessionIsRenewedWhileItsRunLives(t *testing.T) {
	r := shortSessionRig(t)
	d := r.dispatchWorkspace()
	sessionID := d.access.Credential.SessionID
	ctx := context.Background()
	work := filepath.Join(t.TempDir(), "tool")
	if out, err := r.gitAs(d, "", "clone", "-q", d.access.Repo, work); err != nil {
		t.Fatalf("the provisioning fetch: %v\n%s", err, out)
	}
	sess := liveSession(t, sessionID)
	first := sess.ExpiresAt()

	r.clock.Advance(12 * time.Minute)
	if !d.lease.keepAlive(ctx, r.clock.Now()) {
		t.Fatal("the workspace lease stopped extending")
	}
	r.clock.Advance(7 * time.Minute) // a minute before the first deadline
	waitFor(t, 10*time.Second, "the session's renewal", func() bool { return sess.ExpiresAt().After(first) })

	row, _ := r.session(statedb.ProxySessionGit, sessionID)
	if !row.ExpiresAt.Equal(sess.ExpiresAt()) || row.RenewedAt.IsZero() {
		t.Fatalf("the renewal was not recorded: %+v", row)
	}
	if got := r.auditRows(auditaction.ActionGitProxySessionRenewed, sessionID); len(got) == 0 {
		t.Fatal("the renewal is not on the trail")
	}

	// Past the first deadline, the run's write-back push is served.
	r.clock.Advance(6 * time.Minute)
	d.lease.keepAlive(ctx, r.clock.Now())
	commitAndPush(t, r, d, work, "refs/heads/cloop/long-run")
	if r.forge.Ref(t, restoreRepo, "refs/heads/cloop/long-run") == "" {
		t.Fatal("the long run's push did not reach the forge")
	}

	d.release()
	if activeGitProxy().reg.Known(sessionID) {
		t.Fatal("the renewed session outlived its run")
	}
}

// TestAnAdoptedRunsWorkspaceSessionIsRenewedAndEndsWithIt: a session renewed
// past its first period is restored by the hub process that adopts the run —
// its deadline held from the renewal, not from its issue — then renewed by
// that process while the run lives, and ended with the workload.
func TestAnAdoptedRunsWorkspaceSessionIsRenewedAndEndsWithIt(t *testing.T) {
	setSessionAdoptionWait(t, 20*time.Second)
	r := shortSessionRig(t)
	d := r.dispatchWorkspace()
	sessionID, leaseID := d.access.Credential.SessionID, d.access.Credential.LeaseID
	ctx := context.Background()
	work := filepath.Join(t.TempDir(), "tool")
	if out, err := r.gitAs(d, "", "clone", "-q", d.access.Repo, work); err != nil {
		t.Fatalf("the provisioning fetch: %v\n%s", err, out)
	}
	sess := liveSession(t, sessionID)
	first := sess.ExpiresAt()
	r.clock.Advance(12 * time.Minute)
	d.lease.keepAlive(ctx, r.clock.Now())
	r.clock.Advance(7 * time.Minute)
	waitFor(t, 10*time.Second, "the session's renewal", func() bool { return sess.ExpiresAt().After(first) })
	renewed := sess.ExpiresAt()

	// Past the first period, the dispatching process stops — suspending the
	// sessions it served, as a shutdown does — and another adopts the run.
	r.clock.Advance(3 * time.Minute)
	d.lease.keepAlive(ctx, r.clock.Now())
	old := activeGitProxy().reg
	r.restartWorkspace(d, "hub_new")
	old.Suspend(sessionID, "the hub is shutting down")
	(&Server{WorkDir: r.dir}).takeOverWorkspaceLease(r.dir, r.ex, "h-1", d.meta)
	taken := registeredLease(leaseID)
	if taken == nil {
		t.Fatal("the adopting process holds no workspace lease")
	}
	stopKeepaliveForTest(taken)
	restored := liveSession(t, sessionID)
	if !restored.ExpiresAt().Equal(renewed) {
		t.Fatalf("restored until %s, want the renewed %s", restored.ExpiresAt(), renewed)
	}
	commitAndPush(t, r, d, work, "refs/heads/cloop/adopted-early")

	// With nothing due, the workload is not asked whether it still runs: on a
	// device that is a round trip, and the keepalive ticks every minute.
	probes := r.ex.statusCalls()
	taken.renewWorkspaceSessions(ctx)
	if got := r.ex.statusCalls(); got != probes {
		t.Fatalf("the workload was asked %d times with no session due", got-probes)
	}

	// The adopter renews it while the run lives.
	r.clock.Advance(14 * time.Minute) // four minutes before the renewed deadline
	if !taken.keepAlive(ctx, r.clock.Now()) {
		t.Fatal("the taken-over lease stopped extending")
	}
	taken.renewWorkspaceSessions(ctx)
	if !restored.ExpiresAt().After(renewed) {
		t.Fatalf("the adopter did not renew the session: still until %s", restored.ExpiresAt())
	}
	r.clock.Advance(6 * time.Minute) // past the deadline it was restored with
	taken.keepAlive(ctx, r.clock.Now())
	commitAndPush(t, r, d, work, "refs/heads/cloop/adopted-late")
	if r.forge.Ref(t, restoreRepo, "refs/heads/cloop/adopted-late") == "" {
		t.Fatal("the adopted run's late push did not reach the forge")
	}

	// The workload ends: lease and session go with it.
	r.ex.finish()
	waitFor(t, 10*time.Second, "the workspace lease's release", func() bool {
		_, err := r.db.GetSecretLease(leaseID)
		return err != nil
	})
	if row, _ := r.session(statedb.ProxySessionGit, sessionID); row.Open() {
		t.Fatalf("the session outlived its adopted run: %+v", row)
	}
	// And a finished run's session is renewed no more.
	before := restored.ExpiresAt()
	taken.renewWorkspaceSessions(ctx)
	if !restored.ExpiresAt().Equal(before) {
		t.Fatal("a session was renewed after its run ended")
	}
}
