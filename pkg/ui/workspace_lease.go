package ui

// workspace_lease.go: the lease a workspace's pinned git proxy session stands
// on outlives the hub process that issued it (Task 20390).
//
// A git workspace on an edge device is provisioned through a pinned session:
// gitproxycreds.Source leases the grant's forge credential, keeps it on the
// hub, and hands the device a session token for exactly the workspace's
// repository. A device that writes its work back by push presents the same
// token once its workload finishes. The session lived in the memory of the
// process that minted it and stood on a lease nobody kept alive or took over,
// so a hub restarted mid-run answered that push with a 401 and the run's work
// stayed on the device.
//
// Now the lease is kept alive here for as long as its session lives, and is
// listed and revocable like any other; the session is recorded (Durable) when
// its lease is; and a driver that keeps the credential for a push write-back
// names both in the run's owner row (runOwnerMeta.Workspace). The process that
// adopts the run takes the lease over and restores the session exactly as it
// restores a lease-path session (session_restore.go): a conditional write on
// the holder, the scope re-checked against the grant and this hub's proxy
// policy and never widened, the upstream taken from the project's own origin
// and never from the record, the deadline clamped, a GitHub App token
// re-minted at the slot's recorded scope. A push that arrives before the agent
// has reconnected waits for that, as any other session's request does
// (session_hold.go).

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/executor/gitcreds"
	"github.com/blechschmidt/cloop/pkg/gitproxy"
	"github.com/blechschmidt/cloop/pkg/secretbroker"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// runWorkspaceMeta names, in a run's owner row, the workspace lease and the
// pinned git proxy session a driver keeps for the run's push write-back.
type runWorkspaceMeta struct {
	Lease   string `json:"lease"`
	Session string `json:"session,omitempty"`
}

// keptWorkspaceSource is the workspace credential source of an edge device: a
// broker source whose proxied leases are kept alive, listed and revocable for
// as long as the git proxy session standing on one lives.
//
// It decorates only what gitproxycreds hands to the proxy. A credential handed
// to the device itself — no proxy runs — is leased and released by the driver
// around delivery, exactly as before: it never outlives the dispatch, except
// parked for a push write-back, and nothing could restore it.
type keptWorkspaceSource struct {
	inner *gitcreds.BrokerSource
	// db is the hub's own handle on the control plane, open for the life of
	// the process: the keepalive writes its lease.refresh rows through it.
	db *statedb.DB
}

// ForWorkspace implements executor.WorkspaceCredentialSource.
func (k keptWorkspaceSource) ForWorkspace(ctx context.Context, projectID string, w executor.Workspace) (executor.WorkspaceAccess, func(), error) {
	return k.inner.ForWorkspace(ctx, projectID, w)
}

// ForProxiedWorkspace implements gitproxycreds.HeldSource: the lease is kept
// alive from here on, and ended by the release returned — which the proxy
// runs when the session standing on the lease ends.
func (k keptWorkspaceSource) ForProxiedWorkspace(ctx context.Context, projectID string, w executor.Workspace) (executor.WorkspaceAccess, func(), error) {
	access, release, err := k.inner.ForProxiedWorkspace(ctx, projectID, w)
	if err != nil || access.Credential.LeaseID == "" || k.inner.Broker == nil {
		return access, release, err
	}
	lease, ok := k.inner.Broker.HeldLease(access.Credential.LeaseID)
	if !ok {
		return access, release, nil
	}
	sl := &secretLease{
		broker: k.inner.Broker, lease: lease, expiry: lease.ExpiresAt, auditDB: k.db,
		workDir: executor.PolicyProjectPath(projectID), workspace: true,
	}
	sl.startKeepalive(leaseKeepaliveTick)
	liveLeases.add(sl)
	// Close releases the lease at the broker, as release did. It runs when
	// the session standing on the lease ends — and a session also ends from
	// inside Close (closeGuardedSessions) and from inside handOver
	// (suspendLeaseSessions closes one it holds no record of), both while
	// restoreMu is held, so neither may run Close again: it would wait on
	// that lock forever. A lease another process took over is that
	// process's to release.
	return access, func() {
		if !sl.isClosing() && !sl.isHandedOver() {
			sl.Close()
		}
	}, nil
}

// RefreshWorkspaceCredential implements gitproxycreds.RefreshingSource.
func (k keptWorkspaceSource) RefreshWorkspaceCredential(ctx context.Context, cred executor.GitCredential, held string) (executor.GitCredential, func(), error) {
	return k.inner.RefreshWorkspaceCredential(ctx, cred, held)
}

// LeasesRecorded implements gitproxycreds.RecordedSource.
func (k keptWorkspaceSource) LeasesRecorded() bool { return k.inner.LeasesRecorded() }

var _ executor.WorkspaceCredentialSource = keptWorkspaceSource{}

// bindWorkspaceLease records which workload the workspace lease a driver kept
// for handleID's push write-back belongs to, so the run's owner row names it.
func bindWorkspaceLease(ex executor.Executor, handleID string) {
	holder, ok := ex.(executor.WorkspaceCredentialHolder)
	if !ok {
		return
	}
	held, ok := holder.HeldWorkspaceCredential(handleID)
	if !ok {
		return
	}
	if sl := liveLeases.get(held.LeaseID); sl != nil && sl.isWorkspace() {
		sl.bindWorkspace(ex.ID(), handleID, held.SessionID)
	}
}

// bindWorkspace binds a workspace lease to the workload its session's
// credential was handed to, and names the session.
func (sl *secretLease) bindWorkspace(executorID, handleID, sessionID string) {
	if sl == nil {
		return
	}
	sl.mu.Lock()
	sl.executorID, sl.handleID = executorID, handleID
	if sessionID != "" {
		sl.workspaceSession = sessionID
	}
	sl.mu.Unlock()
}

// workspaceForHandle returns the workspace lease bound to handleID on
// executorID, and the session it feeds, for the run's owner row. Nil when
// there is none.
func (lr *leaseRegistry) workspaceForHandle(executorID, handleID string) *runWorkspaceMeta {
	if executorID == "" || handleID == "" {
		return nil
	}
	lr.mu.Lock()
	defer lr.mu.Unlock()
	for id, sl := range lr.active {
		if !sl.isWorkspace() {
			continue
		}
		if ex, h := sl.boundHandle(); ex == executorID && h == handleID {
			sl.mu.Lock()
			session := sl.workspaceSession
			sl.mu.Unlock()
			return &runWorkspaceMeta{Lease: id, Session: session}
		}
	}
	return nil
}

// takeOverWorkspaceLease takes over the workspace lease an adopted run's
// owner row names, and restores the pinned session it feeds, for the run's
// push write-back (Task 20390). It ends with the workload, as the run's own
// leases do.
func (s *Server) takeOverWorkspaceLease(workDir string, ex executor.Executor, handleID string, ws *runWorkspaceMeta) {
	if ws == nil || strings.TrimSpace(ws.Lease) == "" || liveLeases.held(ws.Lease) {
		return
	}
	// The owner row is read back from a database: the lease it names must
	// be one issued for this run's executor and project, or a pinned session
	// of another run's would be revived on its say-so.
	if why := workspaceLeaseMismatch(ws.Lease, ex, workDir); why != "" {
		fmt.Fprintf(os.Stderr, "ui: not taking over workspace lease %s of the run on %s: %s\n", ws.Lease, ex.ID(), why)
		return
	}
	sl, err := restoreSecretLease(controlPlaneDir(), workDir, ws.Lease)
	switch {
	case err == nil:
	case leaseRefusedForGood(err):
		// Nothing of it is on the device — its session token is the device's,
		// and the session is not restored — so there is nothing to scrub:
		// the record and the session's go.
		retireLeaseRecord(ws.Lease, fmt.Sprintf("the hub process that adopted its run could not take the "+
			"workspace lease over: %v", secretbroker.RedactString(err.Error())))
		return
	default:
		// Taken over by another process, released, or not readable just
		// now: either way nothing for this one to restore.
		return
	}
	sl.mu.Lock()
	sl.workspace = true
	sl.mu.Unlock()
	sl.bindWorkspace(ex.ID(), handleID, ws.Session)
	liveLeases.add(sl)
	go wipeLeaseOnExit(ex, handleID, sl, nil)
	s.log().Info("cluster", 0, "took over the workspace lease of an adopted run",
		map[string]interface{}{"project": workDir, "lease": ws.Lease, "session": ws.Session,
			"executor": ex.ID(), "handle": handleID})
	restoreLeaseSessions(sl)
}

// workspaceLeaseMismatch reports why leaseID's record is not a workspace lease
// issued for a run of workDir on ex, or "". It fails closed — a record that
// cannot be read just now is not taken over on an owner row's say-so — except
// for one that does not exist, which restoreSecretLease refuses taking
// nothing over.
func workspaceLeaseMismatch(leaseID string, ex executor.Executor, workDir string) string {
	dir := controlPlaneDir()
	if dir == "" {
		return "this hub process keeps no lease records"
	}
	db, err := statedb.Open(state.DBPath(dir))
	if err != nil {
		return "its record could not be read: " + err.Error()
	}
	defer db.Close()
	row, err := db.GetSecretLease(leaseID)
	switch {
	case errors.Is(err, statedb.ErrSecretLeaseNotFound):
		return ""
	case err != nil:
		return "its record could not be read: " + err.Error()
	}
	if row.ExecutorID != ex.ID() {
		return fmt.Sprintf("it was issued to executor %q, not %q", row.ExecutorID, ex.ID())
	}
	if want := secretbroker.NormalizeProjectID(executor.PolicyProjectPath(workDir)); row.ProjectID != want {
		return fmt.Sprintf("it was issued for project %q, not %q", row.ProjectID, want)
	}
	return ""
}

// ── restoring a pinned session ───────────────────────────────────────────────

// workspaceUpstreamNow is the https URL of the repository workDir's workspace
// is fetched from now, as applyWorkspace derives it: the project's own git
// origin. A restored pinned session presents its credential there and nowhere
// else — the record names a repository, and is held to this one.
func workspaceUpstreamNow(workDir string) (string, error) {
	if strings.TrimSpace(workDir) == "" {
		return "", fmt.Errorf("the run names no project to read its origin from")
	}
	origin, err := readGitOrigin(workDir)
	if err != nil {
		return "", err
	}
	return normalizeRemoteToHTTPS(origin.Remote)
}

// pinnedUpstream holds a pinned session's recorded upstream to the repository
// the project's origin names now, and returns that — taken from the project's
// configuration, never from the record — or why the two differ.
func pinnedUpstream(rec gitproxy.SessionRecord, workDir string) (string, string) {
	now, err := workspaceUpstreamNow(workDir)
	if err != nil {
		return "", "the project's git origin cannot be read to restore it against: " + err.Error()
	}
	recHost, err1 := repoURLHost(rec.Upstream)
	nowHost, err2 := repoURLHost(now)
	recPath, err3 := gitproxy.UpstreamRepoPath(rec.Upstream)
	nowPath, err4 := gitproxy.UpstreamRepoPath(now)
	if err1 != nil || err2 != nil || err3 != nil || err4 != nil ||
		recHost != nowHost || !strings.EqualFold(recPath, nowPath) {
		return "", fmt.Sprintf("it is pinned to %q, and the project's origin is %q now", rec.Upstream, now)
	}
	return now, ""
}

// repoURLHost returns the scheme and host of an https repository URL, the
// host lower-cased: where a credential presented to it goes.
func repoURLHost(raw string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return "", err
	}
	if u.Scheme != "https" || u.Host == "" || u.User != nil {
		return "", fmt.Errorf("%q is not an https repository URL", raw)
	}
	return "https://" + strings.ToLower(u.Host), nil
}

// workspaceSessionPolicy is the policy gitproxycreds mints a workspace's
// pinned session with now: the hub's, narrowed to the grant's branches
// (Task 20340).
func workspaceSessionPolicy(hub gitproxy.Policy, c secretbroker.Constraints) gitproxy.Policy {
	pol := hub
	if pol.IsZero() {
		pol = gitproxy.WriteBackPolicy()
		pol.AllowFetch = true
	}
	pol.AllowedRefs = append([]string(nil), pol.AllowedRefs...)
	pol.RestrictRefs = nil
	if branches := c.BranchNames(); len(branches) > 0 {
		pol.RestrictRefs = append([]string(nil), branches...)
	}
	return pol
}
