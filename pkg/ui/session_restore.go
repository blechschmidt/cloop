package ui

// session_restore.go: what an adopted run's lease feeds comes back with the
// lease (Task 20383).
//
// Since Task 20382 the hub process adopting a run takes over its secret lease.
// The lease is a record of grants; what the run spends is the sessions those
// grants were delivered as — the git proxy session its git presents, the
// Kubernetes monitor session its kubectl presents, the egress session its
// HTTPS_PROXY names — and the GitHub App tokens behind them. Each lived in the
// memory of the process that minted it, so after a restart the run's next
// fetch, push or kubectl call got a 401.
//
// Each such session is recorded (proxy_session_store.go). When this process
// takes a lease over it restores the lease's sessions here:
//
//  1. a session past its TTL is retired with a reason — nothing restores it;
//  2. the record moves to this process by a conditional write on its holder,
//     so of two processes adopting the same run only one restores it;
//  3. the grant is re-checked, and the session's recorded scope is held to
//     what the grant and this hub's proxy policy allow now — never wider;
//  4. the upstream credential is re-derived through the broker: a PAT or a
//     kubeconfig opened from the grant's secret, a GitHub App token minted at
//     the slot's recorded scope (which also resumes its refresh);
//  5. the session goes back into this process's registry under its id and
//     token hash, and the sandbox's next request is served.
//
// A grant revoked or expired while no process held the lease refuses the lease
// itself, and the lease path closes its sessions and scrubs the device
// (run_takeover.go). A session refused on its own is closed with the reason. A
// failure that may pass — the store busy, GitHub unreachable — leaves the
// session held here and unrestored, and the lease's keepalive tries again each
// tick; a request presenting it meanwhile waits for that (session_hold.go).
//
// An egress session belongs to the run rather than to a lease, and is restored
// with the run (restoreRunEgress): its grant re-read, its counters resumed.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/blechschmidt/cloop/pkg/auditaction"
	"github.com/blechschmidt/cloop/pkg/egressbroker"
	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/gitproxy"
	"github.com/blechschmidt/cloop/pkg/hubmetrics"
	"github.com/blechschmidt/cloop/pkg/kubeguard"
	"github.com/blechschmidt/cloop/pkg/secretbroker"
	"github.com/blechschmidt/cloop/pkg/secretstore"
	"github.com/blechschmidt/cloop/pkg/sessionrecord"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// sessionRestoreTimeout bounds one session's restore: an App token mint at
// GitHub, with room to spare.
const sessionRestoreTimeout = 45 * time.Second

// sessionNow is the clock restores, the janitor and the hold judge a
// session's expiry by: the registries' clock in production, a test's in tests.
var sessionNow = time.Now

// errSessionRefused marks a restore refused for a reason that will not change:
// the record cannot be read, its scope is wider than its grant allows now, or
// this process has no proxy to serve it.
var errSessionRefused = errors.New("session not restored")

// beforeSessionTake, when set, runs between reading a session's record and
// taking it over: where a test puts the other process that wins the race.
// Nil in production.
var beforeSessionTake func(row statedb.ProxySessionRow)

// errSessionLive: the session is already served here.
var errSessionLive = errors.New("session already served by this hub process")

func refusedf(format string, args ...any) error {
	return fmt.Errorf("%w: %s", errSessionRefused, fmt.Sprintf(format, args...))
}

// sessionRefusedForGood reports whether a restore failed for a reason that
// will not change, so the session is closed rather than retried.
func sessionRefusedForGood(err error) bool {
	if leaseRefusedForGood(err) {
		return true
	}
	for _, final := range []error{
		errSessionRefused,
		secretbroker.ErrRefreshRefused,
		secretbroker.ErrInvalidKind,
		secretbroker.ErrLeaseNotFound,
		gitproxy.ErrSessionLapsed,
		kubeguard.ErrSessionLapsed,
	} {
		if errors.Is(err, final) {
			return true
		}
	}
	return false
}

// restoreKindLabel maps a record's kind to its metric label.
func restoreKindLabel(kind string) string {
	switch kind {
	case statedb.ProxySessionGit:
		return hubmetrics.RestoreKindGit
	case statedb.ProxySessionKube:
		return hubmetrics.RestoreKindKube
	default:
		return hubmetrics.RestoreKindEgress
	}
}

// pendingKey names a session awaiting a retried restore.
func pendingKey(kind, id string) string { return kind + "/" + id }

// restoreLeaseSessions brings back the git proxy and Kubernetes monitor
// sessions the lease sl has just taken over feeds.
func restoreLeaseSessions(sl *secretLease) {
	if sl == nil || sl.lease == nil || sl.auditDB == nil {
		return
	}
	rows, err := sl.auditDB.ListProxySessions(statedb.ProxySessionFilter{
		LeaseIDs: []string{sl.lease.ID}, OpenOnly: true,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "ui: read the sessions lease %s feeds: %v\n", sl.lease.ID, err)
		return
	}
	for _, row := range rows {
		if row.Kind != statedb.ProxySessionGit && row.Kind != statedb.ProxySessionKube {
			continue
		}
		sl.restoreSession(row, "")
	}
	// The App tokens the lease carries as files resume refreshing on the
	// keepalive's tick: their slots came with the lease (Broker.Restore,
	// which counts them).
}

// restoreSession brings back one session sl's lease feeds, and returns the
// outcome it counted. origin names the process that held it before this one,
// for a retry whose record names this one; "" for a first attempt. Restores of one lease's sessions run one at a time: a
// request-triggered retry racing the adoption must not mint a second upstream
// token for the same session.
func (sl *secretLease) restoreSession(row statedb.ProxySessionRow, origin string) string {
	sl.restoreMu.Lock()
	defer sl.restoreMu.Unlock()
	outcome := hubmetrics.RestoreLost
	if sl.isHandedOver() || sl.isClosing() {
		// The lease moved on, or its run ended: what it fed is not this
		// process's to serve.
		sl.dropPending(row)
	} else {
		outcome = sl.tryRestoreSession(row, origin)
	}
	hubmetrics.SessionRestores.Inc(restoreKindLabel(row.Kind), outcome)
	return outcome
}

// isClosing reports whether Close has begun.
func (sl *secretLease) isClosing() bool {
	sl.mu.Lock()
	defer sl.mu.Unlock()
	return sl.closing
}

func (sl *secretLease) tryRestoreSession(row statedb.ProxySessionRow, origin string) string {
	db := sl.auditDB
	self := leaseHolderID()
	if self == "" {
		return hubmetrics.RestoreFailed
	}
	if !sessionNow().Before(row.ExpiresAt) {
		retireSessionRow(db, row, fmt.Sprintf("lapsed at %s while no hub process held it",
			row.ExpiresAt.UTC().Format(time.RFC3339)))
		sl.dropPending(row)
		return hubmetrics.RestoreExpired
	}
	from := row.Holder
	if origin == "" {
		origin = from
	}
	if from != self {
		if beforeSessionTake != nil {
			beforeSessionTake(row)
		}
		took, err := db.TakeProxySession(row.Kind, row.SessionID, from, self)
		if err != nil {
			sl.addPending(row, origin)
			fmt.Fprintf(os.Stderr, "ui: take over %s session %s (will retry): %v\n", row.Kind, row.SessionID, err)
			return hubmetrics.RestoreFailed
		}
		if !took {
			// Another process restored it first, or it was closed meanwhile.
			sl.dropPending(row)
			return hubmetrics.RestoreLost
		}
		row.Holder = self
	} else {
		// A retry of a session this process took over earlier: the record is
		// read again, so one another process has taken over since — with the
		// lease — is left to it rather than served here as well.
		cur, err := db.GetProxySession(row.Kind, row.SessionID)
		switch {
		case errors.Is(err, statedb.ErrProxySessionNotFound):
			sl.dropPending(row)
			return hubmetrics.RestoreLost
		case err != nil:
			sl.addPending(row, origin)
			return hubmetrics.RestoreFailed
		case !cur.Open() || cur.Holder != self:
			sl.dropPending(row)
			return hubmetrics.RestoreLost
		}
		row = cur
	}

	ctx, cancel := context.WithTimeout(context.Background(), sessionRestoreTimeout)
	defer cancel()
	var err error
	switch row.Kind {
	case statedb.ProxySessionGit:
		err = sl.restoreGitSession(ctx, row, origin)
	case statedb.ProxySessionKube:
		err = sl.restoreKubeSession(row, origin)
	default:
		err = refusedf("a %s session is not restored with a lease", row.Kind)
	}
	switch {
	case err == nil, errors.Is(err, errSessionLive):
		sl.dropPending(row)
		fmt.Fprintf(os.Stderr, "ui: restored %s session %s of lease %s, held until then by %s\n",
			row.Kind, row.SessionID, sl.lease.ID, origin)
		return hubmetrics.RestoreRestored
	case sessionRefusedForGood(err):
		sl.dropPending(row)
		closeHeldSession(db, row, "not restored by the hub process that adopted its run: "+
			secretbroker.RedactString(err.Error()))
		if errors.Is(err, gitproxy.ErrSessionLapsed) || errors.Is(err, kubeguard.ErrSessionLapsed) {
			return hubmetrics.RestoreExpired
		}
		return hubmetrics.RestoreRefused
	default:
		sl.addPending(row, origin)
		fmt.Fprintf(os.Stderr, "ui: restore %s session %s of lease %s (will retry): %v\n",
			row.Kind, row.SessionID, sl.lease.ID, secretbroker.RedactString(err.Error()))
		return hubmetrics.RestoreFailed
	}
}

// restoreGitSession re-derives a git proxy session's upstream credential and
// restores it into this process's registry.
func (sl *secretLease) restoreGitSession(ctx context.Context, row statedb.ProxySessionRow, from string) error {
	svc := activeGitProxy()
	if svc == nil || svc.reg == nil {
		return refusedf("this hub process runs no git proxy to serve it")
	}
	if svc.reg.Known(row.SessionID) {
		return errSessionLive
	}
	rec, err := sessionrecord.GitRecord(row)
	if err != nil {
		return refusedf("%v", err)
	}
	// Where the credential goes is this hub's to say, never the record's. A
	// lease-path session is scoped to its grant's allowlist on the forge this
	// hub's proxy fronts, which is what Mint was given (gitguard.go); a
	// workspace's pinned session to the one repository the project's origin
	// names (Task 20390, workspace_lease.go). A record that names anything
	// else was not written for this hub.
	pinned := len(rec.RepoPatterns) == 0
	if pinned {
		if !sl.isWorkspace() {
			return refusedf("it is pinned to one repository, and only a workspace lease feeds a pinned session")
		}
		up, why := pinnedUpstream(rec, sl.workDir)
		if why != "" {
			return refusedf("%s", why)
		}
		rec.Upstream = up
	} else if why := gitUpstreamMismatch(rec, svc.githubUpstream); why != "" {
		return refusedf("%s", why)
	}
	g, err := sl.broker.HeldGrant(sl.lease.ID, row.GrantID)
	if err != nil {
		return err
	}
	// What a session minted for this grant on this hub would be allowed now.
	want, _ := guardPolicy(svc.policy, g.Constraints.Permissions, g.Constraints.Branches)
	if pinned {
		want = workspaceSessionPolicy(svc.policy, g.Constraints)
	}
	if why := gitScopeWider(rec, g.Constraints, want); why != "" {
		return refusedf("its recorded scope is wider than its grant and this hub's git proxy policy allow now: %s", why)
	}
	// Nor longer than this hub mints a session for.
	rec.ExpiresAt = clampRestoredExpiry(rec.IssuedAt, rec.ExpiresAt, svc.ttl, gitproxy.DefaultSessionTTL)
	// Everything Restore would check, before anything is minted for it: a
	// token minted for a session that is then refused would sit at GitHub
	// with nothing presenting it.
	if err := svc.reg.CheckRestore(rec); err != nil {
		switch {
		case errors.Is(err, gitproxy.ErrSessionExists):
			return errSessionLive
		case errors.Is(err, gitproxy.ErrSessionLapsed):
			return err
		}
		return refusedf("%v", err)
	}
	up, err := sl.broker.GitHubUpstream(ctx, sl.lease.ID, row.GrantID, row.SessionID)
	if err != nil {
		return err
	}
	req := gitproxy.RestoreRequest{
		Record: rec,
		Credential: gitproxy.Credential{
			Username: secretbroker.GitHubUsername, Password: up.Token,
			GrantID: row.GrantID, LeaseID: row.LeaseID,
		},
		From: from,
	}
	if up.Refresh != nil {
		// An App token, renewed from the session's request path as a minted
		// session's is (Task 20375).
		req.CredentialExpiresAt = up.ExpiresAt
		req.Refresh = sessionRefresher(secretbroker.GitGuardRequest{
			Refresh: up.Refresh, TokenExpiresAt: up.ExpiresAt, GrantID: row.GrantID, LeaseID: row.LeaseID,
		})
	}
	if _, err := svc.reg.Restore(req); err != nil {
		if errors.Is(err, gitproxy.ErrSessionExists) {
			return errSessionLive
		}
		if errors.Is(err, gitproxy.ErrSessionLapsed) {
			return err
		}
		return refusedf("%v", err)
	}
	return nil
}

// restoreKubeSession re-derives a Kubernetes monitor session's cluster
// credential and restores it, its policy narrowed to what this hub's floor and
// the grant allow now.
func (sl *secretLease) restoreKubeSession(row statedb.ProxySessionRow, from string) error {
	svc := activeKubeGuard()
	if svc == nil || svc.reg == nil {
		return refusedf("this hub process runs no Kubernetes access monitor to serve it")
	}
	if s, ok := svc.reg.Session(row.SessionID); ok {
		if s.Closed() {
			// Closed here and not reaped yet: it ended, whatever the record
			// says.
			return refusedf("the session was closed by this hub process: %s", s.CloseReason())
		}
		return errSessionLive
	}
	rec, err := sessionrecord.KubeRecord(row)
	if err != nil {
		return refusedf("%v", err)
	}
	rec.ExpiresAt = clampRestoredExpiry(rec.IssuedAt, rec.ExpiresAt, svc.ttl, kubeguard.DefaultSessionTTL)
	g, err := sl.broker.HeldGrant(sl.lease.ID, row.GrantID)
	if err != nil {
		return err
	}
	// What a fresh mint would compute now, intersected with what the session
	// was given: never wider than either.
	now, err := svc.policy.Intersect(kubeguard.Policy{
		Verbs: g.Constraints.KubeVerbs(), Namespaces: g.Constraints.Namespaces,
	})
	if err != nil {
		return refusedf("its grant cannot be honoured under this hub's kube_guard policy now: %v", err)
	}
	narrowed, err := now.Intersect(rec.Policy)
	if err != nil {
		return refusedf("its recorded policy has nothing in common with what its grant allows now: %v", err)
	}
	rec.Policy = narrowed
	doc, err := sl.broker.KubeconfigUpstream(sl.lease.ID, row.GrantID)
	if err != nil {
		return err
	}
	defer zeroBytes(doc)
	if _, err := svc.reg.Restore(kubeguard.RestoreRequest{Record: rec, Kubeconfig: doc, From: from}); err != nil {
		if errors.Is(err, kubeguard.ErrSessionExists) {
			return errSessionLive
		}
		if errors.Is(err, kubeguard.ErrSessionLapsed) {
			return err
		}
		return refusedf("%v", err)
	}
	return nil
}

// gitUpstreamMismatch reports why a git session's recorded upstream is not the
// one this hub's proxy would mint it for now, or "". configured is the proxy's
// GitHub upstream, empty for github.com.
func gitUpstreamMismatch(rec gitproxy.SessionRecord, configured string) string {
	if len(rec.RepoPatterns) == 0 {
		return "it is pinned to one repository, and only a session scoped to its grant's allowlist is minted " +
			"for a lease"
	}
	want := githubUpstreamBase
	if configured != "" {
		want = configured
	}
	wantBase, err := gitproxy.UpstreamHostBase(want)
	if err != nil {
		return "this hub's git proxy upstream is unusable: " + err.Error()
	}
	got, err := gitproxy.UpstreamHostBase(rec.Upstream)
	if err != nil || !strings.EqualFold(got, wantBase) {
		return fmt.Sprintf("it names upstream %q, and this hub's git proxy presents its credentials to %s only",
			rec.Upstream, wantBase)
	}
	return ""
}

// clampRestoredExpiry holds a recorded deadline to the session TTL this hub
// mints with now (fallback when it configures none), counted from when the
// session was issued — or from now, for an issue time in the future.
func clampRestoredExpiry(issued, expires time.Time, ttl, fallback time.Duration) time.Time {
	if ttl <= 0 {
		ttl = fallback
	}
	from := issued
	if now := sessionNow(); from.IsZero() || from.After(now) {
		from = now
	}
	if limit := from.Add(ttl); expires.After(limit) {
		return limit
	}
	return expires
}

// gitScopeWider reports how a git session's recorded scope exceeds what its
// grant allows now, and want — the policy a session minted for it on this hub
// would get now — or "". The comparison is conservative — membership, not glob
// arithmetic — so a scope it cannot prove within bounds is refused rather than
// restored.
func gitScopeWider(rec gitproxy.SessionRecord, c secretbroker.Constraints, want gitproxy.Policy) string {
	if len(rec.RepoPatterns) > 0 {
		allowed := map[string]bool{}
		for _, p := range c.Repos {
			n := gitproxy.NormalizeRepoPath(p)
			if n == "*" {
				n = "*/*"
			}
			allowed[n] = true
		}
		for _, p := range rec.RepoPatterns {
			n := gitproxy.NormalizeRepoPath(p)
			if n == "*" {
				n = "*/*"
			}
			if !allowed[n] {
				return fmt.Sprintf("repository pattern %q is not in the grant's allowlist", p)
			}
		}
	} else if repo := gitproxy.NormalizeRepoPath(rec.RepoPath); repo == "" || !c.AllowsRepo(repo) {
		return fmt.Sprintf("repository %q is not one the grant admits", rec.RepoPath)
	}

	want.AllowedRefs = append([]string(nil), want.AllowedRefs...)
	want.RestrictRefs = append([]string(nil), want.RestrictRefs...)
	want.Normalize()
	got := rec.Policy
	got.AllowedRefs = append([]string(nil), got.AllowedRefs...)
	got.RestrictRefs = append([]string(nil), got.RestrictRefs...)
	got.Normalize()
	for _, r := range got.AllowedRefs {
		if !containsRef(want.AllowedRefs, r) {
			return fmt.Sprintf("ref pattern %q is outside this hub's allowlist (%s)", r, strings.Join(want.AllowedRefs, ","))
		}
	}
	for _, flag := range []struct {
		name      string
		got, want bool
	}{
		{"create", got.AllowCreate, want.AllowCreate},
		{"update", got.AllowUpdate, want.AllowUpdate},
		{"delete", got.AllowDelete, want.AllowDelete},
		{"fetch", got.AllowFetch, want.AllowFetch},
	} {
		if flag.got && !flag.want {
			return "it may " + flag.name + " refs, which the grant and this hub no longer allow"
		}
	}
	if len(want.RestrictRefs) > 0 {
		if len(got.RestrictRefs) == 0 {
			return "the grant now limits pushes to " + strings.Join(want.RestrictRefs, ",")
		}
		for _, r := range got.RestrictRefs {
			if !containsRef(want.RestrictRefs, r) {
				return fmt.Sprintf("branch pattern %q is outside the grant's branches", r)
			}
		}
	}
	if got.MaxCommands > want.MaxCommands || got.MaxPackBytes > want.MaxPackBytes {
		return "its push limits exceed this hub's"
	}
	return ""
}

func containsRef(list []string, want string) bool {
	for _, v := range list {
		if v == want {
			return true
		}
	}
	return false
}

// zeroBytes overwrites a buffer that held a credential.
func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// ── retries ──────────────────────────────────────────────────────────────────

// pendingSession is a session restore to try again: its record as last read,
// and the process that held it before this one took it over.
type pendingSession struct {
	row  statedb.ProxySessionRow
	from string
}

// addPending keeps a session to retry its restore on the keepalive's tick.
func (sl *secretLease) addPending(row statedb.ProxySessionRow, from string) {
	sl.mu.Lock()
	defer sl.mu.Unlock()
	if sl.pendingSessions == nil {
		sl.pendingSessions = map[string]pendingSession{}
	}
	sl.pendingSessions[pendingKey(row.Kind, row.SessionID)] = pendingSession{row: row, from: from}
}

// dropPending forgets a session whose restore was decided.
func (sl *secretLease) dropPending(row statedb.ProxySessionRow) {
	sl.mu.Lock()
	defer sl.mu.Unlock()
	delete(sl.pendingSessions, pendingKey(row.Kind, row.SessionID))
}

// retryPendingSessions retries every restore that failed for a reason that
// may pass. Called on the keepalive's tick; cheap when there is none.
func (sl *secretLease) retryPendingSessions() {
	if sl == nil || sl.isHandedOver() {
		return
	}
	sl.mu.Lock()
	rows := make([]pendingSession, 0, len(sl.pendingSessions))
	for _, p := range sl.pendingSessions {
		rows = append(rows, p)
	}
	sl.mu.Unlock()
	if len(rows) == 0 {
		return
	}
	if sl.broker != nil && sl.lease != nil && sl.broker.HeldElsewhere(sl.lease.ID) {
		// Another process took the lease over since: what it feeds is that
		// process's to restore, and this one lets go of it now rather than
		// at its next extension.
		sl.handOver()
		return
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].row.SessionID < rows[j].row.SessionID })
	for _, p := range rows {
		sl.restoreSession(p.row, p.from)
	}
}

// retryPendingSessionNow retries the restore of one session this process holds
// and has not restored yet, at once — for a request presenting it. It reports
// whether the session is served here afterwards.
func retryPendingSessionNow(kind, id string) bool {
	if kind == statedb.ProxySessionEgress {
		return retryPendingEgressNow(id)
	}
	key := pendingKey(kind, id)
	for _, sl := range liveLeases.snapshot() {
		sl.mu.Lock()
		p, ok := sl.pendingSessions[key]
		sl.mu.Unlock()
		if ok {
			return sl.restoreSession(p.row, p.from) == hubmetrics.RestoreRestored
		}
	}
	return false
}

// ── retiring records ─────────────────────────────────────────────────────────

// closeHeldSession closes this process's record of a session that never made
// it back into a registry, and writes the close row its registry would have.
func closeHeldSession(db *statedb.DB, row statedb.ProxySessionRow, reason string) {
	if db == nil {
		return
	}
	if ok, err := db.CloseProxySession(row.Kind, row.SessionID, leaseHolderID(), sessionNow().UTC(), reason, ""); err != nil || !ok {
		return
	}
	auditSessionEnd(db, row, reason)
}

// retireSessionRow ends and forgets a record — the janitor's, for a session
// that closed or lapsed with nobody holding it. A record that was still open
// gets the close row nobody wrote. Fenced on the holder the caller read.
func retireSessionRow(db *statedb.DB, row statedb.ProxySessionRow, reason string) bool {
	if db == nil {
		return false
	}
	deleted, err := db.DeleteProxySession(row.Kind, row.SessionID, row.Holder)
	if err != nil || !deleted {
		return false
	}
	if row.Open() {
		auditSessionEnd(db, row, reason)
	}
	return true
}

// retireLeaseSessionRecords ends and forgets every record of a session leaseID
// fed: its lease was retired, so nothing will restore them.
func retireLeaseSessionRecords(db *statedb.DB, leaseID, reason string) int {
	if db == nil || leaseID == "" {
		return 0
	}
	rows, err := db.ListProxySessions(statedb.ProxySessionFilter{LeaseIDs: []string{leaseID}})
	if err != nil {
		return 0
	}
	n := 0
	for _, row := range rows {
		if retireSessionRow(db, row, reason) {
			n++
		}
	}
	return n
}

// auditSessionEnd writes the close row for a session whose registry will
// never write one: it ended while no process served it.
func auditSessionEnd(db *statedb.DB, row statedb.ProxySessionRow, reason string) {
	switch row.Kind {
	case statedb.ProxySessionGit:
		// The same payload the registry's own close rows carry
		// (gitProxyAuditSink), so a reader finds it where they look — only
		// the reason says nobody's registry wrote it.
		appendSessionEndRow(db, row, auditaction.ActionGitProxySessionClosed, "gitproxy", map[string]any{
			"kind": string(gitproxy.EventSessionClosed), "session_id": row.SessionID,
			"repo": sessionRowScope(row), "project_id": row.ProjectID, "task_id": row.TaskID,
			"detail": reason,
		})
	case statedb.ProxySessionKube:
		scope, _ := sessionrecord.KubeScopeOf(row)
		appendSessionEndRow(db, row, auditaction.ActionKubeGuardSessionClosed, "kubeguard", map[string]any{
			"kind": string(kubeguard.EventSessionClosed), "session_id": row.SessionID,
			"cluster": scope.ClusterURL, "context": scope.Context, "project_id": row.ProjectID,
			"task_id": row.TaskID, "executor_id": row.ExecutorID, "grant_id": row.GrantID,
			"lease_id": row.LeaseID, "detail": reason,
		})
	case statedb.ProxySessionEgress:
		c := sessionrecord.EgressCounters(row)
		secretstore.NewAuditor(db).Audit(secretbroker.Redact(secretbroker.Event{
			Time: time.Now().UTC(), Action: secretbroker.ActionEgressClose, Decision: secretbroker.DecisionAllow,
			Actor: row.Actor, LeaseID: row.SessionID, GrantID: row.GrantID, ExecutorID: row.ExecutorID,
			ProjectID: row.ProjectID, TaskID: row.TaskID, RunID: row.RunID,
			BytesUp: c.BytesUp, BytesDown: c.BytesDown, Reason: reason,
		}))
	}
}

// ── egress ───────────────────────────────────────────────────────────────────

// restoreRunEgress brings back the egress sessions an adopted run held, by
// the ids its owner row names.
func (s *Server) restoreRunEgress(workDir string, ex executor.Executor, handleID string, ids []string) {
	if len(ids) == 0 || ex == nil {
		return
	}
	db, closeDB := egressRecordDB()
	if db == nil {
		return
	}
	defer closeDB()
	for _, id := range ids {
		countEgressRestore(id, restoreOneEgress(db, workDir, ex, handleID, id), workDir, ex, handleID)
	}
}

// countEgressRestore counts an egress restore's outcome and keeps a session
// whose restore failed for a reason that may pass, to try again.
func countEgressRestore(id, outcome, workDir string, ex executor.Executor, handleID string) {
	switch outcome {
	case "":
		dropPendingEgress(id)
		return
	case hubmetrics.RestoreFailed:
		addPendingEgress(id, pendingEgressRestore{workDir: workDir, ex: ex, handleID: handleID})
	default:
		dropPendingEgress(id)
	}
	hubmetrics.SessionRestores.Inc(hubmetrics.RestoreKindEgress, outcome)
}

// pendingEgressRestore is an adopted run's egress session whose restore failed
// for a reason that may pass: the store busy, the grant unreadable.
type pendingEgressRestore struct {
	workDir  string
	ex       executor.Executor
	handleID string
	// next is when the watcher's tick may try again.
	next time.Time
}

// egressRetryInterval spaces the watcher's retries of one session.
const egressRetryInterval = 30 * time.Second

// pendingEgress holds the egress restores to try again, by session id: on the
// watcher's tick, and at once for a request presenting one (Task 20383).
var pendingEgress = struct {
	sync.Mutex
	m map[string]pendingEgressRestore
}{m: map[string]pendingEgressRestore{}}

func addPendingEgress(id string, p pendingEgressRestore) {
	p.next = time.Now().Add(egressRetryInterval)
	pendingEgress.Lock()
	pendingEgress.m[id] = p
	pendingEgress.Unlock()
}

func dropPendingEgress(id string) {
	pendingEgress.Lock()
	delete(pendingEgress.m, id)
	pendingEgress.Unlock()
}

// retryPendingEgress retries, off the caller's goroutine, the egress restores
// that are due. Called on the watcher's tick; cheap when there is none.
func retryPendingEgress(now time.Time) {
	pendingEgress.Lock()
	due := map[string]pendingEgressRestore{}
	for id, p := range pendingEgress.m {
		if !now.Before(p.next) {
			due[id] = p
			// Claimed for this attempt, so the next tick does not start
			// another while it runs.
			p.next = now.Add(egressRetryInterval)
			pendingEgress.m[id] = p
		}
	}
	pendingEgress.Unlock()
	if len(due) == 0 {
		return
	}
	go func() {
		defer recoverGoroutine("retry egress session restores")
		db, closeDB := egressRecordDB()
		if db == nil {
			return
		}
		defer closeDB()
		for id, p := range due {
			countEgressRestore(id, restoreOneEgress(db, p.workDir, p.ex, p.handleID, id), p.workDir, p.ex, p.handleID)
		}
	}()
}

// retryPendingEgressNow retries one pending egress restore at once, for a
// request presenting it, and reports whether the session is served here now.
func retryPendingEgressNow(id string) bool {
	pendingEgress.Lock()
	p, ok := pendingEgress.m[id]
	pendingEgress.Unlock()
	if !ok {
		return false
	}
	db, closeDB := egressRecordDB()
	if db == nil {
		return false
	}
	defer closeDB()
	outcome := restoreOneEgress(db, p.workDir, p.ex, p.handleID, id)
	countEgressRestore(id, outcome, p.workDir, p.ex, p.handleID)
	return outcome == hubmetrics.RestoreRestored
}

// egressRecordDB returns a handle on the control plane's database: the hosted
// proxy's own when there is one.
func egressRecordDB() (*statedb.DB, func()) {
	if svc := activeEgressProxy(); svc != nil && svc.db != nil {
		return svc.db, func() {}
	}
	dir := controlPlaneDir()
	if dir == "" {
		return nil, nil
	}
	db, err := statedb.Open(state.DBPath(dir))
	if err != nil {
		return nil, nil
	}
	return db, func() { _ = db.Close() }
}

// restoreOneEgress restores one egress session of an adopted run, and returns
// the outcome, or "" for a session with no record to restore.
func restoreOneEgress(db *statedb.DB, workDir string, ex executor.Executor, handleID, id string) string {
	row, err := db.GetProxySession(statedb.ProxySessionEgress, id)
	switch {
	case errors.Is(err, statedb.ErrProxySessionNotFound):
		return ""
	case err != nil:
		fmt.Fprintf(os.Stderr, "ui: read egress session %s (will retry): %v\n", id, err)
		return hubmetrics.RestoreFailed
	case !row.Open():
		return ""
	}
	if !sessionNow().Before(row.ExpiresAt) {
		retireSessionRow(db, row, fmt.Sprintf("lapsed at %s while no hub process held it",
			row.ExpiresAt.UTC().Format(time.RFC3339)))
		logEgress(workDir, fmt.Sprintf("egress: proxy session %s was not restored — it lapsed while no hub process "+
			"held it; the run's next start redeems a new one", id))
		return hubmetrics.RestoreExpired
	}
	self := leaseHolderID()
	from := row.Holder
	if self == "" {
		return hubmetrics.RestoreFailed
	}
	if from != self && from != "" && egressHolderAlive(from) {
		// Its holder still serves it, and nothing forwards egress to another
		// process: the workload's proxy address may be that process's own.
		// Left with it (Task 20383).
		return ""
	}
	if from != self {
		took, err := db.TakeProxySession(row.Kind, id, from, self)
		if err != nil {
			fmt.Fprintf(os.Stderr, "ui: take over egress session %s (will retry): %v\n", id, err)
			return hubmetrics.RestoreFailed
		}
		if !took {
			return hubmetrics.RestoreLost
		}
		row.Holder = self
	}
	refuse := func(why string) string {
		closeHeldSession(db, row, "not restored by the hub process that adopted its run: "+why)
		logEgress(workDir, fmt.Sprintf("egress: proxy session %s was not restored by the hub process that adopted "+
			"this run — %s", id, why))
		return hubmetrics.RestoreRefused
	}
	svc := activeEgressProxy()
	if svc == nil {
		return refuse(egressProxyUnavailable())
	}
	if svc.broker.Session(id) != nil {
		return hubmetrics.RestoreRestored
	}
	rec, err := sessionrecord.EgressRecord(row)
	if err != nil {
		return refuse(err.Error())
	}
	ctx, cancel := egressProxyContext()
	sess, err := svc.broker.RestoreSession(ctx, egressbroker.RestoreRequest{Record: rec, From: from})
	cancel()
	if err != nil {
		if errors.Is(err, egressbroker.ErrSessionExists) {
			return hubmetrics.RestoreRestored
		}
		if errors.Is(err, egressbroker.ErrStoreUnavailable) || errors.Is(err, context.DeadlineExceeded) ||
			errors.Is(err, context.Canceled) {
			// Says nothing about the grant: held here, tried again.
			fmt.Fprintf(os.Stderr, "ui: restore egress session %s (will retry): %v\n", id,
				secretbroker.RedactString(err.Error()))
			return hubmetrics.RestoreFailed
		}
		outcome := refuse(egressEndReason(err))
		if errors.Is(err, egressbroker.ErrSessionExpired) {
			return hubmetrics.RestoreExpired
		}
		return outcome
	}
	egr := &runEgress{svc: svc, sess: sess, grantID: rec.GrantID, workDir: workDir, executorID: ex.ID()}
	liveEgress.add(egr)
	egr.bindHandle(ex, handleID)
	egr.startKeepalive()
	// Ended with the workload, as the dispatching process's watch would have.
	go wipeLeaseOnExit(ex, handleID, nil, egr)
	logEgress(workDir, fmt.Sprintf("egress: proxy session %s restored by the hub process that adopted this run "+
		"(held until then by %s); it counts on from %s up and %s down against its grant's quota",
		id, from, egressByteCount(sess.BytesUp()), egressByteCount(sess.BytesDown())))
	return hubmetrics.RestoreRestored
}

// egressHolderAlive reports whether the hub process holding an egress
// session's record is a live cluster member. A variable so tests can stand in
// for a cluster.
var egressHolderAlive = func(holder string) bool {
	n := currentCluster()
	return n != nil && n.IsAlive(holder)
}

// retireRunEgressRecords ends the egress records of a run that ended while no
// hub process held it.
func retireRunEgressRecords(ids []string, reason string) {
	if len(ids) == 0 {
		return
	}
	db, closeDB := egressRecordDB()
	if db == nil {
		return
	}
	defer closeDB()
	for _, id := range ids {
		if row, err := db.GetProxySession(statedb.ProxySessionEgress, id); err == nil {
			retireSessionRow(db, row, reason)
		}
	}
}

// suspendLeaseTokensForShutdown lets go of the GitHub App tokens every lease
// this process holds feeds to a proxy session, for a hub stopping gracefully:
// see Broker.SuspendLeaseTokens. The leases themselves stay recorded, for the
// processes that adopt their runs.
func suspendLeaseTokensForShutdown() {
	for _, sl := range liveLeases.snapshot() {
		if sl == nil || sl.broker == nil || sl.lease == nil {
			continue
		}
		sl.broker.SuspendLeaseTokens(sl.lease.ID, "the hub is shutting down")
	}
}

// sessionRowScope renders what a git session admits, as its audit rows name
// it: the allowlist of a scoped session, the repository of a pinned one.
func sessionRowScope(row statedb.ProxySessionRow) string {
	scope, err := sessionrecord.GitScopeOf(row)
	if err != nil {
		return ""
	}
	if len(scope.RepoPatterns) > 0 {
		return strings.Join(scope.RepoPatterns, ",")
	}
	return scope.RepoPath
}

// appendSessionEndRow writes one close row for a session nobody's registry
// closed.
func appendSessionEndRow(db *statedb.DB, row statedb.ProxySessionRow, action auditaction.Action, entity string,
	fields map[string]any) {
	payload, err := json.Marshal(fields)
	if err != nil {
		payload = []byte(`{}`)
	}
	if err := db.AppendAuditEvent(&statedb.AuditEvent{
		Timestamp: time.Now().UTC(), Actor: row.Actor, EventType: string(action),
		EntityType: entity, EntityID: row.SessionID, Payload: string(payload),
	}); err != nil {
		fmt.Fprintf(os.Stderr, "ui: audit the end of %s session %s: %v\n", row.Kind, row.SessionID, err)
	}
}
