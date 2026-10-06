package ui

// A workspace's pinned git proxy session survives its hub restarting
// (Task 20390), in one process: the workspace credential is leased through
// the source an edge device gets in production (workspaceCredentialFactory),
// the device's provisioning fetch and write-back push are played by real git
// against the rig's proxy, and the restart drops the dispatching process's
// registries as a dying process does. tests/e2e/hubrestart_workspace_test.go
// runs it with real processes.

import (
	"context"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/auditaction"
	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/secretbroker"
	"github.com/blechschmidt/cloop/pkg/secretbroker/secretbrokertest"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// workspaceDispatch is what the dispatching process handed a device for its
// workspace, and what it kept.
type workspaceDispatch struct {
	access  executor.WorkspaceAccess
	release func()
	lease   *secretLease
	meta    *runWorkspaceMeta
}

// pinOrigin makes the rig's control-plane directory a checkout whose origin is
// the forge's repository, as a project bound to a device is.
func (r *restoreRig) pinOrigin(origin string) {
	gitBin, _ := secretbrokertest.GitTools(r.t)
	for _, args := range [][]string{{"init", "-q", r.dir}, {"-C", r.dir, "remote", "add", "origin", origin}} {
		if out, err := exec.Command(gitBin, args...).CombinedOutput(); err != nil {
			r.t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
}

// setOrigin moves the checkout's origin.
func (r *restoreRig) setOrigin(origin string) {
	gitBin, _ := secretbrokertest.GitTools(r.t)
	if out, err := exec.Command(gitBin, "-C", r.dir, "remote", "set-url", "origin", origin).CombinedOutput(); err != nil {
		r.t.Fatalf("git remote set-url: %v\n%s", err, out)
	}
}

func (r *restoreRig) forgeRepoURL() string { return r.forge.URL + "/" + restoreRepo }

// dispatchWorkspace leases the workspace credential as the remote driver does
// at dispatch, through the source workspaceCredentialFactory builds, and keeps
// it for a push write-back bound to handle h-1.
func (r *restoreRig) dispatchWorkspace() workspaceDispatch {
	t := r.t
	src := workspaceCredentialFactory(r.db)(r.ex.ID())
	if src == nil {
		t.Fatal("no workspace credential source")
	}
	access, release, err := src.ForWorkspace(context.Background(), r.dir, executor.Workspace{
		Kind: executor.WorkspaceGit, Repo: r.forgeRepoURL(), Ref: "main", CredentialGrant: r.appGrant.ID,
	})
	if err != nil {
		t.Fatalf("ForWorkspace: %v", err)
	}
	cred := access.Credential
	if cred.SessionID == "" || cred.Username != cred.SessionID || cred.LeaseID == "" {
		t.Fatalf("the workspace credential is not a proxy session: %+v", cred)
	}
	if !strings.HasPrefix(access.Repo, r.gitSrv.URL+"/") {
		t.Fatalf("the workspace is not routed through the proxy: %s", access.Repo)
	}
	sl := liveLeases.get(cred.LeaseID)
	if sl == nil || !sl.isWorkspace() {
		t.Fatal("the workspace lease is not kept alive")
	}
	stopKeepaliveForTest(sl)
	sl.bindWorkspace(r.ex.ID(), "h-1", cred.SessionID)
	meta := liveLeases.workspaceForHandle(r.ex.ID(), "h-1")
	if meta == nil || meta.Lease != cred.LeaseID || meta.Session != cred.SessionID {
		t.Fatalf("the owner row would name %+v, want lease %s and session %s", meta, cred.LeaseID, cred.SessionID)
	}
	if ids := liveLeases.forHandle(r.ex.ID(), "h-1"); len(ids) != 0 {
		t.Fatalf("the workspace lease is named among the run's own leases: %v", ids)
	}
	return workspaceDispatch{access: access, release: release, lease: sl, meta: meta}
}

// gitAs runs git against the proxy presenting the workspace session.
func (r *restoreRig) gitAs(d workspaceDispatch, dir string, args ...string) (string, error) {
	return r.git(dispatched{gitID: d.access.Credential.SessionID, gitToken: d.access.Credential.Password}, dir, args...)
}

// restartWorkspace drops the dispatching process and starts a new one as
// holder.
func (r *restoreRig) restartWorkspace(d workspaceDispatch, holder string) {
	liveLeases.removeIf(d.lease)
	r.startProcess()
	r.holder.Store(holder)
}

// TestAWorkspaceSessionSurvivesARestart is the task: the pinned session a
// device was handed for its workspace — recorded, its lease kept alive and
// named for the run — is taken over with the run by the process that adopts
// it, and the device's write-back push, presenting the token the stopped
// process minted, lands through it. The App token behind it is re-minted at
// the scope recorded for it.
func TestAWorkspaceSessionSurvivesARestart(t *testing.T) {
	setSessionAdoptionWait(t, 20*time.Second)
	r := newRestoreRig(t)
	r.pinOrigin(r.forgeRepoURL())
	d := r.dispatchWorkspace()
	sessionID, leaseID := d.access.Credential.SessionID, d.access.Credential.LeaseID

	row, ok := r.session(statedb.ProxySessionGit, sessionID)
	if !ok || row.LeaseID != leaseID || row.Holder != "hub_old" || !row.Open() {
		t.Fatalf("the pinned session's record = %+v (found %v)", row, ok)
	}
	if strings.Contains(row.Scope, d.access.Credential.Password) {
		t.Fatal("the record carries the session token")
	}
	if rec, err := r.db.GetSecretLease(leaseID); err != nil || rec.Holder != "hub_old" {
		t.Fatalf("the workspace lease's record = %+v, %v", rec, err)
	}
	slots, err := r.db.ListAppTokenSlots(leaseID)
	if err != nil || len(slots) != 1 || !slots[0].Guarded {
		t.Fatalf("the workspace lease's App token slots = %+v, %v; want one, held by the proxy", slots, err)
	}

	// The provisioning fetch, before the restart.
	work := filepath.Join(t.TempDir(), "tool")
	if out, err := r.gitAs(d, "", "clone", "-q", d.access.Repo, work); err != nil {
		t.Fatalf("the provisioning fetch: %v\n%s", err, out)
	}
	mintsBefore := len(r.gh.Scoped())

	r.restartWorkspace(d, "hub_new")
	(&Server{WorkDir: r.dir}).takeOverWorkspaceLease(r.dir, r.ex, "h-1", d.meta)
	taken := registeredLease(leaseID)
	if taken == nil || !taken.isWorkspace() {
		t.Fatal("the restarted process holds no workspace lease")
	}
	stopKeepaliveForTest(taken)
	if rec, _ := r.db.GetSecretLease(leaseID); rec.Holder != "hub_new" {
		t.Fatalf("the workspace lease is held by %q after the takeover", rec.Holder)
	}
	if row, _ := r.session(statedb.ProxySessionGit, sessionID); row.Holder != "hub_new" || !row.Open() {
		t.Fatalf("the session's record after the takeover = %+v", row)
	}
	if got := r.auditRows(auditaction.ActionGitProxySessionRestored, sessionID); len(got) != 1 ||
		!strings.Contains(got[0].Payload, "hub_old") {
		t.Fatalf("restored rows = %v, want one naming hub_old", got)
	}
	if got := liveLeases.workspaceForHandle(r.ex.ID(), "h-1"); got == nil || got.Session != sessionID {
		t.Fatalf("the adopted run's owner row would name %+v", got)
	}
	scoped := r.gh.Scoped()
	if len(scoped) != mintsBefore+1 {
		t.Fatalf("App tokens minted by the restore = %d, want one", len(scoped)-mintsBefore)
	}

	// The write-back push, presenting the stopped process's token.
	commitAndPush(t, r, d, work, "refs/heads/cloop/run-after-restart")
	if r.forge.Ref(t, restoreRepo, "refs/heads/cloop/run-after-restart") == "" {
		t.Fatal("the push did not reach the forge")
	}

	// The workload ends: the lease is released by the process holding it, and
	// the session with it.
	r.ex.finish()
	waitFor(t, 10*time.Second, "the workspace lease's release", func() bool {
		_, err := r.db.GetSecretLease(leaseID)
		return err != nil
	})
	if row, _ := r.session(statedb.ProxySessionGit, sessionID); row.Open() {
		t.Fatalf("the session outlived its workload: %+v", row)
	}
}

// TestAWorkspacePushBeforeAdoptionWaits: a write-back push arriving after the
// restart but before the agent has reconnected waits for the adoption, as any
// recorded session's request does, and is then served.
func TestAWorkspacePushBeforeAdoptionWaits(t *testing.T) {
	setSessionAdoptionWait(t, 20*time.Second)
	r := newRestoreRig(t)
	r.pinOrigin(r.forgeRepoURL())
	d := r.dispatchWorkspace()
	work := filepath.Join(t.TempDir(), "tool")
	if out, err := r.gitAs(d, "", "clone", "-q", d.access.Repo, work); err != nil {
		t.Fatalf("the provisioning fetch: %v\n%s", err, out)
	}
	r.restartWorkspace(d, "hub_new")

	pushed := make(chan error, 1)
	go func() {
		pushed <- pushFrom(r, d, work, "refs/heads/cloop/run-early")
	}()
	waitFor(t, 10*time.Second, "the push to be held", func() bool { return heldSessionWaits() > 0 })
	(&Server{WorkDir: r.dir}).takeOverWorkspaceLease(r.dir, r.ex, "h-1", d.meta)
	if sl := registeredLease(d.access.Credential.LeaseID); sl != nil {
		stopKeepaliveForTest(sl)
	}
	select {
	case err := <-pushed:
		if err != nil {
			t.Fatalf("the held push: %v", err)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("the held push never finished")
	}
	if r.forge.Ref(t, restoreRepo, "refs/heads/cloop/run-early") == "" {
		t.Fatal("the held push did not reach the forge")
	}
}

// TestAWorkspaceSessionIsHeldToTheProjectAndTheGrant: a pinned session is
// restored only toward the repository the project's origin names now, only
// while its grant stands, and only on a workspace lease; anything else closes
// it with the reason, and the device's push is refused.
func TestAWorkspaceSessionIsHeldToTheProjectAndTheGrant(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(r *restoreRig)
		closed string
	}{
		{
			name:   "origin moved",
			change: func(r *restoreRig) { r.setOrigin(r.forge.URL + "/acme/other") },
			closed: "the project's origin is",
		},
		{
			name: "grant revoked",
			change: func(r *restoreRig) {
				broker, closeDB, err := openUIBroker(r.dir)
				if err != nil {
					r.t.Fatal(err)
				}
				defer closeDB()
				if err := broker.Revoke(context.Background(), r.appGrant.ID, "test"); err != nil {
					r.t.Fatal(err)
				}
			},
			closed: "lease",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			setSessionAdoptionWait(t, time.Second)
			r := newRestoreRig(t)
			r.pinOrigin(r.forgeRepoURL())
			d := r.dispatchWorkspace()
			sessionID := d.access.Credential.SessionID
			work := filepath.Join(t.TempDir(), "tool")
			if out, err := r.gitAs(d, "", "clone", "-q", d.access.Repo, work); err != nil {
				t.Fatalf("the provisioning fetch: %v\n%s", err, out)
			}
			r.restartWorkspace(d, "hub_new")
			tc.change(r)
			(&Server{WorkDir: r.dir}).takeOverWorkspaceLease(r.dir, r.ex, "h-1", d.meta)
			if sl := registeredLease(d.access.Credential.LeaseID); sl != nil {
				stopKeepaliveForTest(sl)
			}
			if err := pushFrom(r, d, work, "refs/heads/cloop/run-refused"); err == nil {
				t.Fatal("the push through a session that may not be restored was served")
			}
			if r.forge.Ref(t, restoreRepo, "refs/heads/cloop/run-refused") != "" {
				t.Fatal("the refused push reached the forge")
			}
			row, ok := r.session(statedb.ProxySessionGit, sessionID)
			if ok && row.Open() {
				t.Fatalf("the session is still open: %+v", row)
			}
			if ok && !strings.Contains(row.CloseReason, tc.closed) {
				t.Fatalf("closed for %q, want %q", row.CloseReason, tc.closed)
			}
			if got := r.auditRows(auditaction.ActionGitProxySessionRestored, sessionID); len(got) != 0 {
				t.Fatalf("a refused session was restored: %v", got)
			}
		})
	}
}

// TestAWorkspaceLeaseLivesAsLongAsItsSession: the dispatching process keeps the
// workspace lease alive past its issued deadline while the session stands on
// it — the leader's sweep would otherwise retire both records — and releases
// it when the session ends.
func TestAWorkspaceLeaseLivesAsLongAsItsSession(t *testing.T) {
	r := newRestoreRig(t)
	r.pinOrigin(r.forgeRepoURL())
	d := r.dispatchWorkspace()
	leaseID := d.access.Credential.LeaseID
	issued := d.lease.ExpiresAt()
	r.clock.Advance(secretbroker.DefaultMaxLeaseTTL - leaseKeepaliveMargin/2)
	if !d.lease.keepAlive(context.Background(), r.clock.Now()) {
		t.Fatal("the keepalive stopped extending a live workspace lease")
	}
	if !d.lease.ExpiresAt().After(issued) {
		t.Fatalf("the workspace lease was not extended: %s, issued until %s", d.lease.ExpiresAt(), issued)
	}
	if rec, err := r.db.GetSecretLease(leaseID); err != nil || !rec.ExpiresAt.After(issued) {
		t.Fatalf("the lease's record was not extended: %+v, %v", rec, err)
	}

	// The session ends — the driver hands back a credential nothing used —
	// and the lease goes with it.
	d.release()
	if registeredLease(leaseID) != nil {
		t.Fatal("the workspace lease outlived its session")
	}
	if _, err := r.db.GetSecretLease(leaseID); err == nil {
		t.Fatal("the workspace lease's record outlived its session")
	}
	if row, _ := r.session(statedb.ProxySessionGit, d.access.Credential.SessionID); row.Open() {
		t.Fatalf("the unused session is still open: %+v", row)
	}
}

func commitAndPush(t *testing.T, r *restoreRig, d workspaceDispatch, work, ref string) {
	t.Helper()
	if err := pushFrom(r, d, work, ref); err != nil {
		t.Fatal(err)
	}
}

// pushFrom commits a change in work and pushes it to ref through the proxy,
// presenting the workspace session.
func pushFrom(r *restoreRig, d workspaceDispatch, work, ref string) error {
	gitBin, _ := secretbrokertest.GitTools(r.t)
	stamp := time.Now().Format(time.RFC3339Nano)
	for _, args := range [][]string{
		{"-C", work, "-c", "user.email=e@example.com", "-c", "user.name=E", "commit", "-q", "--allow-empty", "-m", "work " + stamp},
	} {
		if out, err := exec.Command(gitBin, args...).CombinedOutput(); err != nil {
			return &pushError{what: "commit", out: string(out), err: err}
		}
	}
	if out, err := r.gitAs(d, work, "push", "-q", d.access.Repo, "HEAD:"+ref); err != nil {
		return &pushError{what: "push", out: out, err: err}
	}
	return nil
}

type pushError struct {
	what, out string
	err       error
}

func (e *pushError) Error() string { return e.what + ": " + e.err.Error() + "\n" + e.out }

// TestAHandoverOfAnUnrecordedWorkspaceSessionReturns: a workspace session that
// could not be recorded is closed, not suspended, when its lease is handed
// over to the process that adopted its run — and its end must not try to
// close the lease from inside the handover, which holds the lease's restore
// lock.
func TestAHandoverOfAnUnrecordedWorkspaceSessionReturns(t *testing.T) {
	r := newRestoreRig(t)
	r.pinOrigin(r.forgeRepoURL())
	activeGitProxy().reg.Store = nil // the record could not be written
	d := r.dispatchWorkspace()
	if row, ok := r.session(statedb.ProxySessionGit, d.access.Credential.SessionID); ok {
		t.Fatalf("an unrecorded session has a record: %+v", row)
	}
	done := make(chan struct{})
	go func() {
		d.lease.handOver()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("handing the workspace lease over deadlocked")
	}
	if activeGitProxy().reg.Known(d.access.Credential.SessionID) {
		t.Fatal("the handed-over lease's session is still served here")
	}
}

// TestAWorkspaceLeaseOfAnotherRunIsNotTakenOver: the owner row is read back
// from a database, so the workspace lease it names must have been issued for
// the adopted run's executor and project.
func TestAWorkspaceLeaseOfAnotherRunIsNotTakenOver(t *testing.T) {
	setSessionAdoptionWait(t, time.Second)
	r := newRestoreRig(t)
	r.pinOrigin(r.forgeRepoURL())
	d := r.dispatchWorkspace()
	r.restartWorkspace(d, "hub_new")
	other := newTakeoverExecutor("edge-other")
	(&Server{WorkDir: r.dir}).takeOverWorkspaceLease(r.dir, other, "h-1", d.meta)
	if registeredLease(d.access.Credential.LeaseID) != nil {
		t.Fatal("a workspace lease issued to another executor was taken over")
	}
	if rec, _ := r.db.GetSecretLease(d.access.Credential.LeaseID); rec.Holder != "hub_old" {
		t.Fatalf("the lease moved to %q", rec.Holder)
	}
	if got := r.auditRows(auditaction.ActionGitProxySessionRestored, d.access.Credential.SessionID); len(got) != 0 {
		t.Fatalf("its session was restored: %v", got)
	}
}
