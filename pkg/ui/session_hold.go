package ui

// session_hold.go: what a request presenting a session gets in the moments
// between its holder stopping and the process adopting its run restoring it
// (Task 20383).
//
// A hub restarted while a device runs a task comes back before the device's
// agent has reconnected, and it is the reconnect that adopts the run, takes
// its lease over and restores its sessions. A git fetch or a kubectl call the
// workload makes in that gap names a session no process serves yet.
//
// Two answers were possible. Restoring the session on demand, in whichever
// process the request reaches, would separate a session from the lease that
// governs it: the lease — and with it revocation, renewal and the release that
// ends the session with its run — stays with whichever process adopts the run,
// which need not be this one, while the session would live here with nothing
// to end it but its TTL. So the request is not served by anyone who does not
// hold the lease.
//
// Instead it waits. A request whose credential matches a recorded session —
// the token hashes to the record's, which proves possession without telling a
// guesser anything — whose holder is not a live hub process, and which has not
// lapsed or been closed, is held for up to sessionAdoptionWait while the run is
// adopted. When the session is restored here the request is served here; when
// a live peer restored it, it is forwarded there; otherwise it gets the 401 it
// would have got before. A request that does not match a record is refused at
// once, as before. Requests presenting one session share one wait, and the
// sessions waited for at a time are bounded, so a workload cannot hold the
// hub's goroutines hostage; a proxy stopping ends every wait.
//
// To git and kubectl the gap is a slow response rather than an
// authentication failure, which neither retries.

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/blechschmidt/cloop/pkg/statedb"
)

// sessionAdoptionWait bounds how long a request presenting a session whose
// holder stopped waits for the session to be restored. A device's agent
// reconnects with a backoff that has grown to tens of seconds by the time a
// restarted hub is back, and the adoption follows the reconnect. A variable so
// tests can change it.
var sessionAdoptionWait = 60 * time.Second

// sessionAdoptionPoll is how often a wait looks again.
var sessionAdoptionPoll = 200 * time.Millisecond

const (
	// maxSessionAdoptionWaits bounds the sessions waited for at once, across
	// every proxy in the process. One wait serves every request presenting
	// its session, so a workload's burst — kubectl's discovery, parallel
	// fetches — takes one, and the cap is on what the waits cost: a poll each.
	maxSessionAdoptionWaits = 64
	// maxSessionAdoptionWaiters bounds the requests sharing one wait.
	maxSessionAdoptionWaiters = 256
)

// sessionWait is one session's wait, shared by every request presenting it.
type sessionWait struct {
	done chan struct{}
	// here and elsewhere are its answer, set before done closes.
	here, elsewhere bool
	// waiters counts the requests sharing it. Guarded by sessionWaits.mu.
	waiters int
}

// sessionWaits are the waits in progress, by kind and session id, and the
// channel that ends them all when the proxies stop.
var sessionWaits = struct {
	mu    sync.Mutex
	m     map[string]*sessionWait
	abort chan struct{}
}{m: map[string]*sessionWait{}, abort: make(chan struct{})}

// abortSessionHolds ends every wait in progress at once: the proxies serving
// them are stopping, and a held request must not hold up their shutdown.
func abortSessionHolds() {
	sessionWaits.mu.Lock()
	close(sessionWaits.abort)
	sessionWaits.abort = make(chan struct{})
	sessionWaits.mu.Unlock()
}

// recordedSessionAwaitingRestore reports whether a request presenting token
// for session id may wait for it: the record exists, is open and unexpired,
// the token hashes to the record's, and no live hub process other than this
// one holds it. It returns the record.
func recordedSessionAwaitingRestore(db *statedb.DB, kind, id, token string) (statedb.ProxySessionRow, bool) {
	if db == nil || id == "" || token == "" {
		return statedb.ProxySessionRow{}, false
	}
	row, err := db.GetProxySession(kind, id)
	if err != nil || !row.Open() || !sessionNow().Before(row.ExpiresAt) {
		return statedb.ProxySessionRow{}, false
	}
	want, err := hex.DecodeString(row.TokenSHA256)
	if err != nil || len(want) != sha256.Size {
		return statedb.ProxySessionRow{}, false
	}
	got := sha256.Sum256([]byte(token))
	if subtle.ConstantTimeCompare(got[:], want) != 1 {
		return statedb.ProxySessionRow{}, false
	}
	if row.Holder != "" && row.Holder != leaseHolderID() {
		if n := currentCluster(); n != nil && n.IsAlive(row.Holder) {
			// Held by a live peer that does not claim to serve it: that
			// peer's business, and nothing a wait here would change.
			return statedb.ProxySessionRow{}, false
		}
	}
	return row, true
}

// awaitSessionRestore waits, bounded, for the session row names to be served
// here (served) or claimed by a live peer (claimedElsewhere, which may be
// nil). It reports which, or neither once the wait is over. Requests
// presenting one session share one wait; each was checked against the record
// on its own before it joined.
func awaitSessionRestore(ctx context.Context, row statedb.ProxySessionRow, served func() bool,
	claimedElsewhere func() bool) (here, elsewhere bool) {
	key := pendingKey(row.Kind, row.SessionID)
	sessionWaits.mu.Lock()
	w := sessionWaits.m[key]
	switch {
	case w != nil && w.waiters >= maxSessionAdoptionWaiters,
		w == nil && len(sessionWaits.m) >= maxSessionAdoptionWaits:
		sessionWaits.mu.Unlock()
		return false, false
	case w == nil:
		w = &sessionWait{done: make(chan struct{})}
		sessionWaits.m[key] = w
		go w.run(key, row, served, claimedElsewhere, sessionWaits.abort)
	}
	w.waiters++
	sessionWaits.mu.Unlock()
	defer func() {
		sessionWaits.mu.Lock()
		w.waiters--
		sessionWaits.mu.Unlock()
	}()
	select {
	case <-w.done:
		return w.here, w.elsewhere
	case <-ctx.Done():
		return false, false
	}
}

// run is a wait's one poller.
func (w *sessionWait) run(key string, row statedb.ProxySessionRow, served, claimedElsewhere func() bool,
	abort <-chan struct{}) {
	defer recoverGoroutine("await session restore")
	defer func() {
		sessionWaits.mu.Lock()
		if sessionWaits.m[key] == w {
			delete(sessionWaits.m, key)
		}
		sessionWaits.mu.Unlock()
		close(w.done)
	}()
	w.here, w.elsewhere = pollSessionRestore(row, served, claimedElsewhere, abort)
}

// pollSessionRestore is a wait's loop: until the session is served here or
// claimed by a live peer, the wait is over, the session lapses, or the
// proxies stop.
func pollSessionRestore(row statedb.ProxySessionRow, served, claimedElsewhere func() bool,
	abort <-chan struct{}) (here, elsewhere bool) {
	if row.Holder == leaseHolderID() {
		// This process took the session over with its lease or run and could
		// not restore it at the time; the request is the occasion to try
		// again.
		if retryPendingSessionNow(row.Kind, row.SessionID) && served() {
			return true, false
		}
	}
	deadline := time.Now().Add(sessionAdoptionWait)
	t := time.NewTicker(sessionAdoptionPoll)
	defer t.Stop()
	for {
		if served() {
			return true, false
		}
		if claimedElsewhere != nil && claimedElsewhere() {
			return false, true
		}
		if !time.Now().Before(deadline) || !sessionNow().Before(row.ExpiresAt) {
			return false, false
		}
		select {
		case <-abort:
			return false, false
		case <-t.C:
		}
	}
}

// proxySessionHold is the second half of a git proxy or Kubernetes monitor
// fallback: a request naming a session nobody live serves waits for its run to
// be adopted, and is then served here or forwarded to the member that restored
// it. It reports whether it answered the request.
func proxySessionHold(w http.ResponseWriter, r *http.Request, owner, internalPath, sessionID string) bool {
	var (
		kind   string
		token  string
		db     *statedb.DB
		local  http.Handler
		served func() bool
	)
	switch owner {
	case ownerGitProxy:
		svc := activeGitProxy()
		if svc == nil || svc.reg == nil || svc.proxy == nil {
			return false
		}
		_, token, _ = r.BasicAuth()
		kind, db, local = statedb.ProxySessionGit, svc.auditDB, svc.proxy
		served = func() bool { return svc.reg.Known(sessionID) }
	case ownerKubeGuard:
		svc := activeKubeGuard()
		if svc == nil || svc.reg == nil || svc.proxy == nil {
			return false
		}
		token, _ = cutBearerToken(r.Header.Get("Authorization"))
		kind, db, local = statedb.ProxySessionKube, svc.auditDB, svc.proxy
		served = func() bool { return svc.reg.Known(sessionID) }
	default:
		return false
	}
	row, ok := recordedSessionAwaitingRestore(db, kind, sessionID, token)
	if !ok {
		return false
	}
	var claimed func() bool
	if n := currentCluster(); n != nil {
		claimed = func() bool {
			o, found, err := n.Lookup(owner, sessionID)
			return err == nil && found && !o.Self && o.Alive
		}
	}
	here, elsewhere := awaitSessionRestore(r.Context(), row, served, claimed)
	switch {
	case here:
		local.ServeHTTP(w, r)
		return true
	case elsewhere:
		return forwardProxyRequest(w, r, owner, internalPath, sessionID)
	}
	return false
}

// cutBearerToken extracts the token of an "Authorization: Bearer x" header.
func cutBearerToken(header string) (string, bool) {
	const scheme = "bearer "
	h := strings.TrimSpace(header)
	if len(h) <= len(scheme) || !strings.EqualFold(h[:len(scheme)], scheme) {
		return "", false
	}
	tok := strings.TrimSpace(h[len(scheme):])
	return tok, tok != ""
}

// egressSessionHold is the egress proxy's AwaitSession: the same wait, for a
// session the egress broker does not hold. There is no forwarding — a member's
// egress proxy serves the sessions it redeemed or restored — so it reports
// only whether the session is served here now.
func egressSessionHold(ctx context.Context, id, token string) bool {
	svc := activeEgressProxy()
	if svc == nil {
		return false
	}
	row, ok := recordedSessionAwaitingRestore(svc.db, statedb.ProxySessionEgress, id, token)
	if !ok {
		return false
	}
	here, _ := awaitSessionRestore(ctx, row, func() bool { return svc.broker.Session(id) != nil }, nil)
	return here
}
