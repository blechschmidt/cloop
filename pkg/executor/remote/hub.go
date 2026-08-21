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
	ex, err := NewExecutor(Options{
		ID:             agent.AgentID,
		Name:           agent.Name,
		Capabilities:   caps,
		OnStatusChange: h.opts.OnStatusChange,
		Now:            h.opts.Now,
	})
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
func (h *Hub) ServeHTTP(w http.ResponseWriter, r *http.Request) {
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

	// Origin checking is deliberately skipped: the peer is a headless agent
	// authenticated by bearer token, not a browser, so there is no ambient
	// credential for a cross-site request to abuse. The token is the whole
	// authentication story here.
	conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{InsecureSkipVerify: true})
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
	frame, err := NewFrame(TypeBye, "", "", ByePayload{Reason: reason, Reconnect: reconnect})
	if err != nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_ = s.write(ctx, frame)
}
