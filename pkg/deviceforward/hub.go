package deviceforward

// hub.go is the control plane's front door for forwarders.
//
// It is mounted as a plain http.Handler at /api/forwarders/connect. A forwarder
// dials in, presents an enrollment token (first contact) or its credential
// (every reconnect), and the hub turns that into a live session that the rest
// of the hub can open device streams against. Because the forwarder dials out,
// this endpoint is the whole network surface — no inbound route to the device.
//
// The authoritative description of what a forwarder carries is the enrollment
// record, not the hello: the operator decided which device when they minted
// the token, so a compromised forwarder cannot claim to carry a different one.
// The hello's device is advisory, used only to show the resolved hardware and
// to warn when the two disagree.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/coder/websocket"
)

// HubOptions configures a Hub.
type HubOptions struct {
	// Store is the enrollment/credential persistence. Required.
	Store Store
	// OnConnect is called after every successful handshake, with the record
	// and what the forwarder advertised, so the caller can refresh a row.
	OnConnect func(rec ForwarderRecord, hello HelloPayload)
	// OnEnroll is called once, when a token is first redeemed.
	OnEnroll func(rec ForwarderRecord)
	// OnStatusChange mirrors connectivity into durable storage.
	OnStatusChange func(forwarderID, status string, at time.Time)
	// CheckOrigin decides whether a browser Origin may open the socket. Nil
	// accepts same-origin and no-Origin (an agent sets no Origin). The caller
	// passes the hub's own origin policy so the two endpoints judge alike.
	CheckOrigin func(*http.Request) (bool, string)
	// Logf receives operational messages. Now overrides the clock.
	Logf func(format string, args ...any)
	Now  func() time.Time
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

// Hub accepts forwarder connections and tracks the sessions they back.
type Hub struct {
	opts HubOptions

	mu       sync.RWMutex
	sessions map[string]*session
}

// NewHub builds a hub.
func NewHub(opts HubOptions) (*Hub, error) {
	if opts.Store == nil {
		return nil, fmt.Errorf("deviceforward: hub requires a store")
	}
	return &Hub{opts: opts, sessions: make(map[string]*session)}, nil
}

// Session returns the live session for a forwarder, if connected.
func (h *Hub) Session(forwarderID string) (*session, bool) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	s, ok := h.sessions[forwarderID]
	return s, ok
}

// Connected reports the IDs of forwarders with a live session.
func (h *Hub) Connected() []string {
	h.mu.RLock()
	defer h.mu.RUnlock()
	out := make([]string, 0, len(h.sessions))
	for id := range h.sessions {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

// OpenStream opens a fresh stream to a connected forwarder's device. The
// caller splices it to a consumer (a loopback connection, a TAP) and closes it
// when done.
func (h *Hub) OpenStream(ctx context.Context, forwarderID, purpose string) (*muxChannel, error) {
	s, ok := h.Session(forwarderID)
	if !ok {
		return nil, ErrForwarderOffline
	}
	return s.openStream(ctx, purpose)
}

// Resolved returns what a connected forwarder reported its USB identity
// resolving to, for the dashboard. Nil when offline or not a USB device.
func (h *Hub) Resolved(forwarderID string) *HelloPayload {
	s, ok := h.Session(forwarderID)
	if !ok {
		return nil
	}
	hp := s.hello
	return &hp
}

// Revoke revokes a forwarder's credential and drops its live session.
func (h *Hub) Revoke(forwarderID string) error {
	if _, err := Revoke(h.opts.Store, forwarderID, h.opts.now()); err != nil {
		return err
	}
	h.DropSession(forwarderID, "credential revoked")
	return nil
}

// DropSession ends a forwarder's live session without touching storage.
//
// It exists for the caller that persists a revocation against the control-plane
// database directly — the source of truth a cluster shares — and then wants the
// live connection this member happens to hold cut, rather than routing the
// whole revocation through this hub's own store. It is a no-op when this member
// holds no session for the forwarder.
func (h *Hub) DropSession(forwarderID, reason string) {
	h.mu.RLock()
	s := h.sessions[forwarderID]
	h.mu.RUnlock()
	if s != nil {
		s.sendBye(reason, false)
		s.close()
	}
}

// ServeHTTP upgrades a forwarder connection and runs its session.
func (h *Hub) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if h.opts.CheckOrigin != nil {
		if ok, reason := h.opts.CheckOrigin(r); !ok {
			h.opts.logf("deviceforward: connect refused from %s: %s", r.RemoteAddr, reason)
			writeHTTPError(w, http.StatusForbidden, reason)
			return
		}
	}
	token := bearerToken(r)
	if token == "" {
		writeHTTPError(w, http.StatusUnauthorized, "missing bearer token")
		return
	}

	now := h.opts.now()
	var (
		rec      ForwarderRecord
		issued   string
		enrolled bool
		err      error
	)
	switch {
	case strings.HasPrefix(token, enrollTokenPrefix+"."):
		issued, rec, err = Redeem(h.opts.Store, token, now)
		enrolled = err == nil
	default:
		rec, err = Authenticate(h.opts.Store, token, now)
	}
	if err != nil {
		h.opts.logf("deviceforward: connect rejected from %s: %v", r.RemoteAddr, err)
		writeHTTPError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{InsecureSkipVerify: true})
	if err != nil {
		h.opts.logf("deviceforward: websocket upgrade for %s: %v", rec.ForwarderID, err)
		return
	}
	fc := newWSConn(conn)

	hello, err := h.handshake(r.Context(), fc, rec, issued)
	if err != nil {
		h.opts.logf("deviceforward: handshake with %s failed: %v", rec.ForwarderID, err)
		_ = conn.Close(websocket.StatusProtocolError, "handshake failed")
		return
	}

	if enrolled && h.opts.OnEnroll != nil {
		h.opts.OnEnroll(rec)
	}
	if h.opts.OnConnect != nil {
		h.opts.OnConnect(rec, hello)
	}

	sess := newSession(rec, fc, hello, negotiate(hello.Version), h.opts.logf)
	h.register(rec.ForwarderID, sess)
	h.opts.logf("deviceforward: forwarder %s (%s) connected, carries %s",
		rec.ForwarderID, rec.Name, rec.Device.Describe())
	if h.opts.OnStatusChange != nil {
		h.opts.OnStatusChange(rec.ForwarderID, "online", now)
	}

	sess.run(r.Context())

	h.deregister(rec.ForwarderID, sess)
	if h.opts.OnStatusChange != nil {
		h.opts.OnStatusChange(rec.ForwarderID, "offline", h.opts.now())
	}
	h.opts.logf("deviceforward: forwarder %s disconnected", rec.ForwarderID)
}

// handshake reads the hello and sends the welcome.
func (h *Hub) handshake(ctx context.Context, conn frameConn, rec ForwarderRecord, issued string) (HelloPayload, error) {
	rctx, cancel := context.WithTimeout(ctx, sessionTimeout)
	frame, err := conn.ReadFrame(rctx)
	cancel()
	if err != nil {
		return HelloPayload{}, fmt.Errorf("read hello: %w", err)
	}
	if frame.Type != TypeHello {
		return HelloPayload{}, fmt.Errorf("%w: expected hello, got frame type %d", ErrProtocol, frame.Type)
	}
	var hello HelloPayload
	if err := unmarshalJSON(frame.Payload, &hello); err != nil {
		return HelloPayload{}, err
	}
	if hello.Version < MinProtocolVersion {
		return HelloPayload{}, fmt.Errorf("%w: forwarder speaks v%d, the hub needs at least v%d",
			ErrProtocol, hello.Version, MinProtocolVersion)
	}
	// The record's device is authoritative; warn on a mismatch rather than
	// trusting the hello.
	if ad, _ := hello.Device.Normalize(); ad.Describe() != rec.Device.Describe() {
		h.opts.logf("deviceforward: forwarder %s advertised %q but was enrolled for %q; using the enrolled device",
			rec.ForwarderID, hello.Device.Describe(), rec.Device.Describe())
	}
	welcome := WelcomePayload{
		Version:     negotiate(hello.Version),
		ForwarderID: rec.ForwarderID,
		Credential:  issued,
	}
	wctx, wcancel := context.WithTimeout(ctx, writeTimeout)
	err = conn.WriteFrame(wctx, Frame{Type: TypeWelcome, Payload: marshalJSON(welcome)})
	wcancel()
	if err != nil {
		return HelloPayload{}, fmt.Errorf("send welcome: %w", err)
	}
	return hello, nil
}

func (h *Hub) register(id string, s *session) {
	h.mu.Lock()
	// A reconnect replaces any stale session for the same identity.
	if old := h.sessions[id]; old != nil {
		old.sendBye("replaced by a newer connection", false)
		old.close()
	}
	h.sessions[id] = s
	h.mu.Unlock()
}

func (h *Hub) deregister(id string, s *session) {
	h.mu.Lock()
	if h.sessions[id] == s {
		delete(h.sessions, id)
	}
	h.mu.Unlock()
}

func (s *session) sendBye(reason string, reconnect bool) {
	ctx, cancel := context.WithTimeout(context.Background(), writeTimeout)
	defer cancel()
	_ = s.conn.WriteFrame(ctx, Frame{Type: TypeBye, Payload: marshalJSON(ByePayload{Reason: reason, Reconnect: reconnect})})
}

// negotiate picks the version a session runs at: the lower of the peer's and
// ours, floored at the minimum.
func negotiate(peer int) int {
	v := peer
	if v > ProtocolVersion {
		v = ProtocolVersion
	}
	if v < MinProtocolVersion {
		v = MinProtocolVersion
	}
	return v
}

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
