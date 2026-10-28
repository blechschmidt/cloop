package kubernetes

// workspace_adopt.go: a Pod's workspace credential outlives the hub process
// that minted it (Task 20455).
//
// A Pod fetches its workspace after Start returns: its init container runs
// `cloop workspace provision` once the kubelet gets to it, which on a busy node
// or behind a large image pull is minutes later. With the git proxy in the path
// the credential it presents is a pinned proxy session, which lives in the
// memory of the hub process that minted it. A process that stopped in that
// window — a restart, a cluster member's death, a rolling upgrade of the chart
// — took the session with it, and the init container's fetch got a 401.
//
// So the driver now says what it holds. HeldWorkspaceCredential names the
// lease and the session a run's workspace stands on, for as long as the Pod may
// still present them — until the fetch is confirmed, or, for a push
// write-back, until the workload is over — and the hub names both in the run's
// owner row. The handle row records which containers read the workspace Secret
// (metaWorkspaceSecret), so a process that adopts the Pod rebuilds the state
// that drops the Secret when the dispatcher would have. And the hub process
// that takes the lease over and restores the session hands the driver the
// function that ends both (AdoptWorkspaceCredential), which the adopted record
// runs exactly where the dispatcher would have run its own release.

import (
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor"
)

// metaWorkspaceSecret is the HandleRecord.Meta key recording that a run's
// workspace credential is in its cloop-ws-<handle> Secret, and which of the
// Pod's containers read it: workspaceSecretFetch — the init container alone —
// or workspaceSecretPush — the harness too, whose push write-back presents the
// same credential after the work is done. A row without it — a public
// repository, or one written before Task 20455 — leaves an adopted Pod's
// Secret to the ownerReference, as before.
const metaWorkspaceSecret = "workspace_secret"

const (
	workspaceSecretFetch = "fetch"
	workspaceSecretPush  = "push"
)

// withWorkspaceMeta records in meta which containers read ws's Secret, when
// there is one.
func withWorkspaceMeta(meta map[string]string, ws *workspaceState) map[string]string {
	if ws == nil || ws.secret() == "" {
		return meta
	}
	mode := workspaceSecretFetch
	if ws.harnessNeedsSecret() {
		mode = workspaceSecretPush
	}
	if meta == nil {
		meta = map[string]string{}
	}
	meta[metaWorkspaceSecret] = mode
	return meta
}

// adoptedWorkspace rebuilds an adopted record's workspace state from its row:
// the Secret's name, which is a function of the handle, and which containers
// read it. Nil when the row records no workspace Secret.
//
// It holds no lease. Until the hub process that adopted the run hands it the
// release of the lease it took over — or when it took nothing over — the state
// only drops the Secret when the dispatcher would have.
func adoptedWorkspace(meta map[string]string, namespace, handleID, projectPath string, startedAt time.Time) *workspaceState {
	var push bool
	switch strings.TrimSpace(meta[metaWorkspaceSecret]) {
	case workspaceSecretFetch:
	case workspaceSecretPush:
		push = true
	default:
		return nil
	}
	name := workspaceSecretName(handleID)
	return &workspaceState{
		plannedName:    name,
		secretName:     name,
		namespace:      namespace,
		handleID:       handleID,
		projectPath:    projectPath,
		startedAt:      startedAt,
		keepForHarness: push,
		adopted:        true,
	}
}

// noteFetched records that the init container's termination was seen, and
// whether it failed. It reports whether this is the first time.
func (s *workspaceState) noteFetched(failed bool) bool {
	if s == nil {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.fetched {
		return false
	}
	s.fetched, s.fetchFailed = true, failed
	return true
}

// Compile-time proof that the driver says which workspace credential it holds
// and takes an adopted one's release (Task 20455).
var (
	_ executor.WorkspaceCredentialHolder  = (*Executor)(nil)
	_ executor.WorkspaceCredentialAdopter = (*Executor)(nil)
)

// HeldWorkspaceCredential implements executor.WorkspaceCredentialHolder: the
// workspace credential handleID's Pod may still present, while this driver
// holds its release — from Start until the init container's fetch is
// confirmed, or until the workload is over for a push write-back.
func (e *Executor) HeldWorkspaceCredential(handleID string) (executor.HeldWorkspaceCredential, bool) {
	rec, err := e.lookup(handleID)
	if err != nil {
		return executor.HeldWorkspaceCredential{}, false
	}
	st := rec.workspace()
	if st == nil {
		return executor.HeldWorkspaceCredential{}, false
	}
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.release == nil || strings.TrimSpace(st.leaseID) == "" {
		return executor.HeldWorkspaceCredential{}, false
	}
	return executor.HeldWorkspaceCredential{LeaseID: st.leaseID, GrantID: st.grantID, SessionID: st.sessionID}, true
}

// AdoptWorkspaceCredential implements executor.WorkspaceCredentialAdopter. The
// adopted record runs release where its dispatcher would have run the lease's
// own: when the init container's fetch is seen to end and nothing reads the
// Secret after it, or when the workload is over (observeWorkspace, finish). It
// runs it at once when that already happened — the record may have seen the
// fetch end before the takeover, which waits on the store, decided.
func (e *Executor) AdoptWorkspaceCredential(handleID string, held executor.HeldWorkspaceCredential, release func()) bool {
	if release == nil {
		return false
	}
	e.mu.Lock()
	closed := e.closed
	e.mu.Unlock()
	if closed {
		// This process is walking away from its Pods: the credential is the
		// next adopter's, as it was this one's.
		return false
	}
	rec, err := e.lookup(handleID)
	if err != nil {
		return false
	}
	st := rec.workspace()
	if st == nil || !st.adopted {
		return false
	}
	st.mu.Lock()
	st.leaseID, st.grantID, st.sessionID = held.LeaseID, held.GrantID, held.SessionID
	// Over already: the Secret went — the fetch it served ended with no
	// push to serve, or the workload ended — or the fetch failed, which no
	// push follows.
	over := st.deleted || (st.fetched && (!st.keepForHarness || st.fetchFailed))
	var prev func()
	if !over {
		prev, st.release = st.release, release
	}
	st.mu.Unlock()
	if prev != nil {
		// A second takeover of the same lease cannot happen while the first
		// holds it; ending what the first parked is what a second would
		// have to do anyway.
		prev()
	}
	if over {
		release()
	}
	return true
}
