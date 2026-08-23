package remote

// hub.go is the control plane's front door for agents.
//
// It owns the inverted-direction handshake: an agent dials in, presents either
// an enrollment token (first contact) or a long-lived credential (every
// reconnect), and the hub turns that into a registered executor.Executor that
// projects can be bound to. Because the agent dials out, this endpoint is the
// only network surface the whole remote-executor feature needs — no inbound
// route to the device, no port forwarding, no VPN.
//
// The hub is mounted as a plain http.Handler (see ServeHTTP) so the Web UI can
// expose it at /api/executors/connect without this package knowing anything
// about the UI's routing or middleware.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"nhooyr.io/websocket"

	"github.com/blechschmidt/cloop/pkg/executor"
)

// HubOptions configures a Hub.
type HubOptions struct {
	// Store is the enrollment/credential persistence. Required.
	Store Store
	// Registry is where connected agents are registered as executors. Nil
	// uses executor.DefaultRegistry.
	Registry *executor.Registry
	// OnStatusChange mirrors executor connectivity into durable storage. It
	// is a callback rather than a *statedb.DB so this package stays free of
	// a storage dependency, matching how the registry takes a binding lookup.
	OnStatusChange func(executorID, status string, at time.Time)
	// OnEnroll is called after a device successfully redeems an enrollment
	// token, so the caller can write an executors-table row for it.
	OnEnroll func(agent AgentRecord, caps AgentCapabilities)
	// OnRevokeAck receives an agent's acknowledgement of a lease revocation,
	// so the caller can write the audit row. It fires for replayed
	// revocations too — the ones delivered long after the operator pressed
	// the button — which is the only signal that a queued revocation landed.
	OnRevokeAck func(executorID, leaseID string, ack RevokedPayload)
	// HandleStore persists handle identity for every executor this hub builds,
	// so a restart still recognises the workloads its devices are running
	// (Task 20191). Nil is the pre-Task-20191 behaviour; see
	// Options.HandleStore for what that costs.
	//
	// One store for the whole hub rather than one per agent: rows are scoped by
	// executor ID inside the store, and a per-agent factory — the shape
	// WorkspaceSource needs, because a *grant* is issued to a subject — would
	// invite an implementation that scoped by something else and let one
	// device's executor adopt another's handles.
	HandleStore executor.HandleStore
	// WorkspaceSource builds the credential source for one agent's executor.
	//
	// It is a factory rather than a single source because a grant is issued to
	// a *subject*: pkg/executor/gitcreds binds the executor ID at construction
	// so that a lease taken for edge-1 can never be satisfied by a grant issued
	// to edge-2. Nil leaves every executor without one, in which case a
	// workload naming a grant is refused rather than dispatched to fetch a
	// private repository anonymously.
	WorkspaceSource func(executorID string) executor.WorkspaceCredentialSource
	// ExternalURL is what this deployment calls itself, e.g.
	// https://cloop.example.com. Its host is always an accepted WebSocket
	// Origin, which is what makes the Executors panel work when a reverse
	// proxy rewrites Host so the same-origin check cannot fire.
	ExternalURL string
	// AllowedOrigins lists additional browser Origins permitted to open an
	// agent WebSocket, on top of loopback, same-origin, and ExternalURL.
	// Entries may be full origins, host:port, or bare hosts.
	AllowedOrigins []string
	// Logf receives operational messages. Nil discards them.
	Logf func(format string, args ...any)
	// Now overrides the clock for tests.
	Now func() time.Time
}

func (o HubOptions) now() time.Time {
	if o.Now != nil {
		return o.Now()
	}
	return time.Now()
}

func (o HubOptions) logf(format string, args ...any) {
	if o.Logf != nil {
		o.Logf(format, args...)
	}
}

// Hub accepts agent connections and maintains the executors they back.
type Hub struct {
	opts HubOptions
	reg  *executor.Registry

	mu        sync.RWMutex
	executors map[string]*Executor
}

// NewHub builds a hub. Executors for previously-enrolled agents are created
// lazily on first connect rather than at startup: an executor with no session
// would advertise itself as bindable while being unable to run anything, and
// Restore exists for callers that do want them present-but-offline.
func NewHub(opts HubOptions) (*Hub, error) {
	if opts.Store == nil {
		return nil, fmt.Errorf("remote: hub requires a store")
	}
	reg := opts.Registry
	if reg == nil {
		reg = executor.DefaultRegistry
	}
	return &Hub{
		opts:      opts,
		reg:       reg,
		executors: make(map[string]*Executor),
	}, nil
}

// Restore registers an offline executor for every enrolled, unrevoked agent.
//
// This is what makes a control-plane restart survivable from the operator's
// point of view: without it, a project bound to edge-1 fails Resolve with
// "executor not registered" until the device happens to reconnect, which reads
// as a configuration error rather than as "the device is offline". With it,
// the executor exists and fails Start with ErrAgentUnreachable — the truthful
// and actionable error.
func (h *Hub) Restore() error {
	agents, err := h.opts.Store.ListAgents()
	if err != nil {
		return fmt.Errorf("remote: restore agents: %w", err)
	}
	for _, a := range agents {
		if a.Revoked() {
			continue
		}
		if _, err := h.executorFor(a, AgentCapabilities{
			WorkDirRoot: a.WorkDirRoot,
			Labels:      a.Labels,
		}); err != nil {
			h.opts.logf("remote: restore agent %s: %v", a.AgentID, err)
		}
	}
	return nil
}

// Executor returns the driver for an agent ID, if the hub knows it.
func (h *Hub) Executor(agentID string) (*Executor, bool) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	ex, ok := h.executors[agentID]
	return ex, ok
}

// Executors lists every remote executor this hub manages.
func (h *Hub) Executors() []*Executor {
	h.mu.RLock()
	defer h.mu.RUnlock()
	out := make([]*Executor, 0, len(h.executors))
	for _, ex := range h.executors {
		out = append(out, ex)
	}
	return out
}

// executorFor returns the durable executor for an agent, creating and
// registering it on first use.
func (h *Hub) executorFor(agent AgentRecord, caps AgentCapabilities) (*Executor, error) {
	h.mu.Lock()
	if ex, ok := h.executors[agent.AgentID]; ok {
		h.mu.Unlock()
		return ex, nil
	}
	opts := Options{
		ID:             agent.AgentID,
		Name:           agent.Name,
		Capabilities:   caps,
		OnStatusChange: h.opts.OnStatusChange,
		OnRevokeAck:    h.opts.OnRevokeAck,
		// Passed at construction rather than attached afterwards, because
		// NewExecutor rehydrates and this is called from ServeHTTP: an agent
		// that dials in immediately after a restart must find its handles
		// already adopted, and an attach one statement later would be a race
		// whose losing side terminates the device's work.
		HandleStore: h.opts.HandleStore,
		Now:         h.opts.Now,
	}
	if h.opts.WorkspaceSource != nil {
		opts.Workspace = h.opts.WorkspaceSource(agent.AgentID)
	}
	ex, err := NewExecutor(opts)
	if err != nil {
		h.mu.Unlock()
		return nil, err
	}
	h.executors[agent.AgentID] = ex
	h.mu.Unlock()

	if err := h.reg.Ensure(ex); err != nil {
		return nil, fmt.Errorf("remote: register executor %s: %w", agent.AgentID, err)
	}
	return ex, nil
}

// Revoke revokes an agent's credential and immediately drops its live session.
//
// Both halves are necessary. Revoking only in storage would leave an already
// connected device running work until it happened to reconnect — which, for a
// long-lived outbound WebSocket, could be never. Dropping the session without
// revoking would let it reconnect a second later.
func (h *Hub) Revoke(agentID string) error {
	now := h.opts.now()
	if _, err := Revoke(h.opts.Store, agentID, now); err != nil {
		return err
	}
	h.mu.RLock()
	ex := h.executors[agentID]
	h.mu.RUnlock()
	if ex == nil {
		return nil
	}
	if sess := ex.currentSession(); sess != nil {
		// Tell the agent not to come back before cutting the link, so it
		// stops retrying a control plane that will refuse it forever.
		sess.sendBye("credential revoked", false)
		sess.closeWithReason("credential revoked")
	}
	ex.failAllHandles("agent credential was revoked")
	ex.setStatus(StatusOffline)
	return nil
}

// RevokeLease takes one secret lease back from every agent holding it.
//
// The fan-out is over executors that actually hold the lease rather than over
// all of them: a revoke frame to a device that was never given the credential
// is noise on someone's LTE uplink, and its "not known here" ack would clutter
// the panel with rows that mean nothing.
//
// An empty result is not an error. It means no connected agent was holding
// the lease — the ordinary case for a hub-local executor, whose material the
// caller wipes directly. The caller decides what to say about that; this
// method's job is to report exactly what the remote fleet did.
func (h *Hub) RevokeLease(ctx context.Context, p RevokePayload) []RevokeResult {
	leaseID := strings.TrimSpace(p.LeaseID)
	if leaseID == "" {
		return nil
	}
	holders := make([]*Executor, 0, 4)
	for _, ex := range h.Executors() {
		if ex.HoldsLease(leaseID) {
			holders = append(holders, ex)
		}
	}
	if len(holders) == 0 {
		return nil
	}

	// Concurrent because each is a round trip to a different device, and an
	// operator revoking across a fleet should wait for the slowest link, not
	// for their sum.
	results := make([]RevokeResult, len(holders))
	var wg sync.WaitGroup
	for i, ex := range holders {
		wg.Add(1)
		go func(i int, ex *Executor) {
			defer wg.Done()
			defer func() {
				if r := recover(); r != nil {
					results[i] = RevokeResult{
						LeaseID: leaseID, GrantID: p.GrantID, ExecutorID: ex.ID(),
						State: RevokeStateFailed, SentAt: h.opts.now(),
						Error: fmt.Sprintf("panic revoking lease: %v", r),
					}
				}
			}()
			results[i] = ex.RevokeLease(ctx, p)
		}(i, ex)
	}
	wg.Wait()

	for _, res := range results {
		h.opts.logf("remote: revoke lease %s on %s: %s%s",
			res.LeaseID, res.ExecutorID, res.State, errSuffix(res.Error))
	}
	return results
}

// RevokeExecutorLeases takes back every lease an executor is holding.
//
// This is the cordon/drain trigger. Taking a device out of rotation is an
// operator saying "I no longer trust this to be running my work" — most often
// because it is being decommissioned, has misbehaved, or is suspected
// compromised. Leaving it holding live credentials until its in-flight tasks
// happen to finish would answer that with "in a few hours".
func (h *Hub) RevokeExecutorLeases(ctx context.Context, executorID, reason string, action RevokeAction) []RevokeResult {
	ex, ok := h.Executor(strings.TrimSpace(executorID))
	if !ok {
		return nil
	}
	leases := ex.Leases()
	out := make([]RevokeResult, 0, len(leases))
	for _, leaseID := range leases {
		out = append(out, ex.RevokeLease(ctx, RevokePayload{
			LeaseID: leaseID,
			Reason:  reason,
			Action:  action,
		}))
	}
	return out
}

// LeaseHolders reports which connected agents hold a lease, so a caller can
// tell "nobody has this" apart from "three devices have it and two are
// offline" before deciding what to promise the operator.
func (h *Hub) LeaseHolders(leaseID string) []string {
	id := strings.TrimSpace(leaseID)
	if id == "" {
		return nil
	}
	var out []string
	for _, ex := range h.Executors() {
		if ex.HoldsLease(id) {
			out = append(out, ex.ID())
		}
	}
	sort.Strings(out)
	return out
}

// Revocations reports the whole fleet's revocation log for the Secrets panel.
func (h *Hub) Revocations() []RevokeResult {
	var out []RevokeResult
	for _, ex := range h.Executors() {
		out = append(out, ex.Revocations()...)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].SentAt.After(out[j].SentAt) })
	return out
}

// ExpiredLeaseSweeper is the callback a janitor uses to find leases whose TTL
// has run out. It returns the lease IDs that should be taken back, along with
// a human-readable reason for the audit trail.
//
// It is a callback rather than a lease store because leases are minted by
// whoever is spawning work (pkg/ui), not by this package: the hub knows which
// agent holds which lease, and the caller knows when each lease expires.
// Neither half can sweep alone.
type ExpiredLeaseSweeper func(now time.Time) []ExpiredLease

// ExpiredLease is one lapsed lease the janitor should take back.
type ExpiredLease struct {
	LeaseID string
	Reason  string
}

// StartLeaseJanitor sweeps expired leases off live agents until ctx is done.
//
// This is the second of the three revocation triggers, and it is the one that
// makes a TTL mean anything. Before it, Lease.Expired was consulted only by
// the caller that minted the lease: an executor handed the material simply
// kept it, so a fifteen-minute TTL bounded nothing for a task that ran for
// three hours. Sweeping *live sessions* rather than re-checking at mint time
// is the whole difference.
//
// It returns a stop function so a caller that owns the hub's lifetime can shut
// the janitor down deterministically instead of leaking a ticker goroutine per
// server restart in tests.
func (h *Hub) StartLeaseJanitor(ctx context.Context, interval time.Duration, sweep ExpiredLeaseSweeper) (stop func()) {
	if sweep == nil {
		return func() {}
	}
	if interval <= 0 {
		interval = DefaultLeaseJanitorInterval
	}
	ctx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})

	go func() {
		defer close(done)
		defer func() {
			if r := recover(); r != nil {
				h.opts.logf("remote: lease janitor panicked and stopped: %v", r)
			}
		}()
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				h.sweepExpiredLeases(ctx, sweep)
			}
		}
	}()

	return func() {
		cancel()
		<-done
	}
}

// DefaultLeaseJanitorInterval is how often expired leases are swept off live
// agents. It is a fraction of DefaultMaxLeaseTTL (15 minutes in
// pkg/secretbroker) so a lapsed credential is taken back within a minute of
// lapsing rather than at the end of the following lease period.
const DefaultLeaseJanitorInterval = time.Minute

// sweepExpiredLeases revokes every lease the sweeper reports as lapsed.
func (h *Hub) sweepExpiredLeases(ctx context.Context, sweep ExpiredLeaseSweeper) {
	defer func() {
		// One bad sweep must not kill the janitor: the next tick is the only
		// thing standing between an expired credential and an agent that will
		// keep using it.
		if r := recover(); r != nil {
			h.opts.logf("remote: lease sweep failed: %v", r)
		}
	}()
	for _, expired := range sweep(h.opts.now()) {
		if strings.TrimSpace(expired.LeaseID) == "" {
			continue
		}
		reason := expired.Reason
		if reason == "" {
			reason = "lease TTL expired"
		}
		// Scrub, never kill. An expiring lease is routine — it happens every
		// fifteen minutes to every long run — and terminating tasks on a timer
		// would make the TTL a self-inflicted outage. A task that still needs
		// the credential renews; one that does not carries on.
		h.RevokeLease(ctx, RevokePayload{
			LeaseID: expired.LeaseID,
			Reason:  reason,
			Action:  RevokeScrub,
		})
	}
}

func errSuffix(msg string) string {
	if msg == "" {
		return ""
	}
	return ": " + msg
}

// Deregister removes an agent's executor from the registry entirely.
func (h *Hub) Deregister(agentID string) {
	h.mu.Lock()
	ex := h.executors[agentID]
	delete(h.executors, agentID)
	h.mu.Unlock()
	if ex == nil {
		return
	}
	if sess := ex.currentSession(); sess != nil {
		sess.sendBye("executor deregistered", false)
		sess.closeWithReason("executor deregistered")
	}
	ex.failAllHandles("executor was deregistered from the control plane")
	h.reg.Unregister(agentID)
}

// ServeHTTP upgrades an agent connection and runs its session.
//
// Authentication is by bearer token in the Authorization header. Two token
// shapes are accepted and they mean different things:
//
//   - an enrollment token (clet1.…) is redeemed here, single-use: the agent
//     receives its long-lived credential in the welcome frame;
//   - an agent credential (clac1.…) authenticates a reconnect.
//
// Failures return 401 with no detail about which check failed. The agent's own
// error frame carries a usable message once the connection is up, but an
// unauthenticated caller probing this endpoint learns nothing about whether a
// token exists, is expired, or was already redeemed.
//
// The Origin check runs first, ahead of any token handling. That ordering is
// load-bearing, not tidiness: redemption is single-use and destructive, so a
// cross-origin request that reached Redeem would consume the operator's
// enrollment token — turning a refused connection into a token that must be
// re-minted. Checking origin first means a rejected request changes no state.
func (h *Hub) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if d := h.checkOrigin(r); !d.allowed {
		h.opts.logf("remote: connect refused from %s: %s", r.RemoteAddr, d.reason)
		writeHTTPError(w, http.StatusForbidden, d.reason)
		return
	}

	token := bearerToken(r)
	if token == "" {
		writeHTTPError(w, http.StatusUnauthorized, "missing bearer token")
		return
	}

	now := h.opts.now()
	var (
		agent      AgentRecord
		issued     string
		enrolledNw bool
		err        error
	)

	switch {
	case strings.HasPrefix(token, enrollTokenPrefix+"."):
		issued, agent, err = Redeem(h.opts.Store, token, RedeemOptions{Now: h.opts.Now})
		enrolledNw = err == nil
	default:
		agent, err = Authenticate(h.opts.Store, token, now)
	}
	if err != nil {
		// Logged in full server-side; the client gets nothing specific.
		h.opts.logf("remote: connect rejected from %s: %v", r.RemoteAddr, err)
		writeHTTPError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	caps := AgentCapabilities{WorkDirRoot: agent.WorkDirRoot, Labels: agent.Labels}
	ex, err := h.executorFor(agent, caps)
	if err != nil {
		h.opts.logf("remote: executor for %s: %v", agent.AgentID, err)
		writeHTTPError(w, http.StatusInternalServerError, "executor unavailable")
		return
	}

	// InsecureSkipVerify tells the websocket library to skip *its* built-in
	// OriginPatterns matching, which cannot express "no Origin header is
	// fine, and this proxy's hostname is fine". checkOrigin above is the
	// replacement, and it already ran — see its file header for the policy.
	conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		InsecureSkipVerify: true, // origin already validated by checkOrigin
	})
	if err != nil {
		h.opts.logf("remote: websocket upgrade for %s: %v", agent.AgentID, err)
		return
	}

	sess, err := Accept(r.Context(), NewWSConn(conn), AcceptOptions{
		Agent:            agent,
		Executor:         ex,
		IssuedCredential: issued,
		Now:              h.opts.Now,
	})
	if err != nil {
		h.opts.logf("remote: handshake with %s failed: %v", agent.AgentID, err)
		return
	}

	if enrolledNw && h.opts.OnEnroll != nil {
		h.opts.OnEnroll(agent, sess.Capabilities())
	}
	h.opts.logf("remote: agent %s (%s) connected, protocol v%d",
		agent.AgentID, agent.Name, sess.Version())

	// Block until the session ends. The HTTP handler's lifetime is the
	// connection's lifetime; returning early would let net/http tear the
	// hijacked connection down underneath the session.
	<-sess.Done()
	h.opts.logf("remote: agent %s disconnected", agent.AgentID)
}

// bearerToken extracts the credential from the request. The Authorization
// header is the supported form; the query parameter exists because some
// constrained WebSocket clients on embedded devices cannot set headers on the
// upgrade request.
func bearerToken(r *http.Request) string {
	if h := r.Header.Get("Authorization"); h != "" {
		if after, ok := strings.CutPrefix(h, "Bearer "); ok {
			return strings.TrimSpace(after)
		}
	}
	return strings.TrimSpace(r.URL.Query().Get("token"))
}

func writeHTTPError(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

// sendBye tells the peer the session is ending and whether to reconnect.
// Best-effort: the link may already be gone, which is why every caller closes
// the session immediately afterwards regardless of the outcome.
func (s *Session) sendBye(reason string, reconnect bool) {
	frame, err := s.frame(TypeBye, "", "", ByePayload{Reason: reason, Reconnect: reconnect})
	if err != nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_ = s.write(ctx, frame)
}
