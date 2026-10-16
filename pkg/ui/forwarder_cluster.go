// Device forwarders in a hub cluster (Task 20430).
//
// A forwarder's tunnel lives on whichever member it dialled, like an edge
// agent's. Everything that needs the tunnel follows the edge-agent pattern
// (cluster_leases.go): the holding member records an "forwarder" owner row,
// requests that need the tunnel are routed to it, and connectivity is read
// from that shared row rather than from the local hub — so a member the
// forwarder did not dial lists it as connected, through the member that holds
// it, instead of offline.
//
// Three things travel between members:
//
//   - a device stream: a member dispatching a run whose agent it holds, or
//     whose container runs on its host, opens the forwarder's stream through
//     the holding member, over a signed peer WebSocket (DialStream);
//   - the dashboard's probe, which is forwarded whole to the holder;
//   - a revocation: a forwarder or binding revoked on any member, or from the
//     CLI, is announced on the bus, and every member cuts what it holds at
//     once — the holder drops the live session, every member detaches the
//     device from the runs it relays it to. Each acts only on what the shared
//     database confirms, so an announcement is a prompt, never an authority.

package ui

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/coder/websocket"

	"github.com/blechschmidt/cloop/pkg/deviceforward"
	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/hubcluster"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// ownerForwarder: the member holding a device forwarder's tunnel. Key:
// forwarder id. Meta: what the forwarder's hello reported (forwarderOwnerMeta).
const ownerForwarder = "forwarder"

// invalidateForwarder: a forwarder or a binding was revoked (Task 20430); each
// member confirms it against the database and cuts what it holds.
const invalidateForwarder = "forwarder"

// clusterAPIForwarderStream is where a member asks the member holding a
// forwarder's tunnel for a stream to its device.
const clusterAPIForwarderStream = clusterAPIPrefix + "forwarders/stream"

// Response headers the holding member describes a stream with.
const (
	headerForwarderBusID     = "X-Cloop-Forwarder-Bus-Id"
	headerForwarderInterface = "X-Cloop-Forwarder-Interface"
)

// forwarderOwnerMeta is what the holding member records about a forwarder's
// live session, for the other members' dashboards.
type forwarderOwnerMeta struct {
	Available    bool                `json:"available"`
	Detail       string              `json:"detail,omitempty"`
	Resolved     *executor.USBDevice `json:"resolved,omitempty"`
	AgentVersion string              `json:"agent_version,omitempty"`
}

// forwarderInvalidation is invalidateForwarder's payload. A forwarder id
// alone means the forwarder was revoked; a binding id means that binding was.
type forwarderInvalidation struct {
	ForwarderID string `json:"forwarder_id,omitempty"`
	BindingID   string `json:"binding_id,omitempty"`
	Reason      string `json:"reason,omitempty"`
}

// recordForwarderHeld records that this member holds a forwarder's tunnel.
func (s *Server) recordForwarderHeld(rec deviceforward.ForwarderRecord, hello deviceforward.HelloPayload) {
	n := s.clusterNode()
	if n == nil {
		return
	}
	meta := forwarderOwnerMeta{Available: hello.Available, Detail: hello.Detail, Resolved: hello.Resolved, AgentVersion: hello.AgentVersion}
	if err := n.Assert(ownerForwarder, rec.ForwarderID, meta); err != nil {
		fmt.Fprintf(os.Stderr, "ui: record that forwarder %s is connected here: %v\n", rec.ForwarderID, err)
	}
}

// forwarderGoneHere reports whether this member should speak for a
// forwarder going offline: only the member that held it. A forwarder that
// reconnected elsewhere is seen leaving the member it left a moment later,
// and that member writing "offline" would overwrite the new holder's
// "online". It releases the owner row when it does speak.
func (s *Server) forwarderGoneHere(forwarderID string) bool {
	n := s.clusterNode()
	if n == nil {
		return true
	}
	if !n.Owns(ownerForwarder, forwarderID) {
		return false
	}
	_, _ = n.Release(ownerForwarder, forwarderID)
	return true
}

// releaseForwarderOwnership gives up every forwarder this member holds, as it
// shuts down: they will reconnect to another member.
func (s *Server) releaseForwarderOwnership() {
	n := s.clusterNode()
	if n == nil {
		return
	}
	owned, err := n.Owned(ownerForwarder)
	if err != nil {
		return
	}
	for _, o := range owned {
		if o.Self {
			_, _ = n.Release(ownerForwarder, o.Key)
		}
	}
}

// forwarderPeerView reports, for a forwarder another live member holds,
// that member and what it recorded about the session.
func (s *Server) forwarderPeerView(forwarderID string) (member string, meta forwarderOwnerMeta, ok bool) {
	n := s.clusterNode()
	if n == nil {
		return "", meta, false
	}
	o, found, err := n.Lookup(ownerForwarder, forwarderID)
	if err != nil || !found || o.Self || !o.Alive {
		return "", meta, false
	}
	if o.Row.Meta != "" {
		_ = json.Unmarshal([]byte(o.Row.Meta), &meta)
	}
	return o.InstanceID, meta, true
}

// dialPeerForwarderStream opens a stream to a forwarder's device through the
// member holding its tunnel.
func dialPeerForwarderStream(ctx context.Context, n *hubcluster.Node, m hubcluster.Member, forwarderID, purpose, bindingID string) (io.ReadWriteCloser, deviceforward.ExportedDevice, error) {
	q := url.Values{"id": {forwarderID}, "purpose": {purpose}}
	if bindingID != "" {
		q.Set("binding", bindingID)
	}
	conn, hdr, err := n.DialStream(ctx, m, clusterAPIForwarderStream+"?"+q.Encode())
	if err != nil {
		return nil, deviceforward.ExportedDevice{}, fmt.Errorf("open forwarder %s's device through hub member %s: %w", forwarderID, m.ID, err)
	}
	exp := deviceforward.ExportedDevice{BusID: hdr.Get(headerForwarderBusID), Interface: hdr.Get(headerForwarderInterface)}
	return conn, exp, nil
}

// handleClusterForwarderStream serves a peer's request for a stream to a
// forwarder this member holds. The peer signature is checked before this runs
// (clusterInternalBypass); what is checked here is that the request is one a
// run may make: the forwarder is not revoked and, for an attach, the binding
// it names is in force and names this forwarder.
func (s *Server) handleClusterForwarderStream(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimSpace(r.URL.Query().Get("id"))
	purpose := strings.TrimSpace(r.URL.Query().Get("purpose"))
	bindingID := strings.TrimSpace(r.URL.Query().Get("binding"))
	if id == "" {
		jsonErr(w, "forwarder id is required", http.StatusBadRequest)
		return
	}
	db, err := s.controlPlaneDB()
	if err != nil {
		jsonErr(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	row, err := db.GetForwarder(id)
	if err != nil || !row.RevokedAt.IsZero() {
		db.Close()
		jsonErr(w, "no such forwarder, or it was revoked", http.StatusNotFound)
		return
	}
	// Only a run's device travels this way, and only under a binding in
	// force for this forwarder: the dashboard's probe is forwarded to this
	// member as the request it is, through the user's own authorization.
	if purpose != "attach" {
		db.Close()
		jsonErr(w, "a member opens a forwarder's device only to attach it for a run", http.StatusBadRequest)
		return
	}
	b, berr := db.GetForwarderBinding(bindingID)
	if berr != nil || b.ForwarderID != id || !b.Active(time.Now()) {
		db.Close()
		jsonErr(w, "the binding this stream is for is not in force", http.StatusForbidden)
		return
	}
	db.Close()
	hub, err := s.forwarderHub()
	if err != nil {
		jsonErr(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	ds, err := hub.OpenDevice(ctx, id, purpose)
	cancel()
	if err != nil {
		jsonErr(w, exposeErrorMessage(err), http.StatusConflict)
		return
	}
	w.Header().Set(headerForwarderBusID, ds.Exported.BusID)
	w.Header().Set(headerForwarderInterface, ds.Exported.Interface)
	ws, err := websocket.Accept(w, r, &websocket.AcceptOptions{InsecureSkipVerify: true})
	if err != nil {
		_ = ds.Close()
		return
	}
	ws.SetReadLimit(1 << 20)
	conn := websocket.NetConn(context.Background(), ws, websocket.MessageBinary)
	relay := &peerForwardRelay{forwarderID: id, bindingID: bindingID}
	peerForwards.add(relay)
	defer peerForwards.remove(relay)
	relay.closer = func() { _ = conn.Close(); _ = ds.Close() }
	spliceStreams(conn, ds)
}

// peerForwardRelay is a stream this member serves to a peer, closable by a
// revocation of its binding or forwarder.
type peerForwardRelay struct {
	forwarderID string
	bindingID   string
	closer      func()
	once        sync.Once
}

func (p *peerForwardRelay) close() {
	p.once.Do(func() {
		if p.closer != nil {
			p.closer()
		}
	})
}

var peerForwards = &peerForwardSet{all: map[*peerForwardRelay]struct{}{}}

type peerForwardSet struct {
	mu  sync.Mutex
	all map[*peerForwardRelay]struct{}
}

func (p *peerForwardSet) add(r *peerForwardRelay) {
	p.mu.Lock()
	p.all[r] = struct{}{}
	p.mu.Unlock()
}

func (p *peerForwardSet) remove(r *peerForwardRelay) {
	p.mu.Lock()
	delete(p.all, r)
	p.mu.Unlock()
}

func (p *peerForwardSet) closeWhere(pred func(*peerForwardRelay) bool) {
	p.mu.Lock()
	var hit []*peerForwardRelay
	for r := range p.all {
		if pred(r) {
			hit = append(hit, r)
		}
	}
	p.mu.Unlock()
	for _, r := range hit {
		r.close()
	}
}

// spliceStreams copies between two streams until either ends, then closes
// both.
func spliceStreams(a, b io.ReadWriteCloser) {
	var once sync.Once
	stop := func() {
		once.Do(func() {
			_ = a.Close()
			_ = b.Close()
		})
	}
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(a, b); stop(); done <- struct{}{} }()
	go func() { _, _ = io.Copy(b, a); stop(); done <- struct{}{} }()
	<-done
	<-done
}

// ── revocation ───────────────────────────────────────────────────────────────

// cutRevokedForwarder ends, on this member, everything a revoked forwarder
// had: its live session, if this member holds it, and its device in every run
// relayed from here. Confirmed against the database first.
func (s *Server) cutRevokedForwarder(forwarderID, reason string) {
	if forwarderID == "" {
		return
	}
	db, err := s.controlPlaneDB()
	if err == nil {
		row, gerr := db.GetForwarder(forwarderID)
		db.Close()
		if gerr == nil && row.RevokedAt.IsZero() {
			return // not revoked: an announcement is a prompt, not an authority
		}
	}
	if reason == "" {
		reason = "the forwarder was revoked"
	}
	if hub := activeForwarderHub(); hub != nil {
		hub.DropSession(forwarderID, "credential revoked")
	}
	closeForwardsForForwarder(forwarderID, reason)
	peerForwards.closeWhere(func(r *peerForwardRelay) bool { return r.forwarderID == forwarderID })
}

// cutRevokedBinding detaches a revoked binding's device from every run
// relayed from this member. Confirmed against the database first.
func (s *Server) cutRevokedBinding(bindingID, reason string) {
	if bindingID == "" {
		return
	}
	if db, err := s.controlPlaneDB(); err == nil {
		b, gerr := db.GetForwarderBinding(bindingID)
		db.Close()
		if gerr == nil && b.Active(time.Now()) {
			return
		}
	}
	if reason == "" {
		reason = "its binding was revoked"
	}
	closeForwardsForBinding(bindingID, reason)
	peerForwards.closeWhere(func(r *peerForwardRelay) bool { return r.bindingID == bindingID })
}

// onForwarderInvalidation handles the bus notice.
func (s *Server) onForwarderInvalidation(p forwarderInvalidation) {
	if p.BindingID != "" {
		s.cutRevokedBinding(p.BindingID, p.Reason)
		return
	}
	s.cutRevokedForwarder(p.ForwarderID, p.Reason)
}

// announceForwarderRevocation cuts what this member holds and tells every
// other member to do the same.
func (s *Server) announceForwarderRevocation(p forwarderInvalidation) {
	s.onForwarderInvalidation(p)
	s.publishInvalidate(invalidateForwarder, p)
}

// AnnounceForwarderRevocation is the CLI's announcement of a forwarder or
// binding revoked in db: `cloop forward revoke` and `cloop forward unbind`,
// which are no hub member. Every member cuts the session and the relays it
// holds within a bus poll; one that missed the notice does it within its own
// re-check of the database (deviceforward.DefaultRevocationRecheck for the
// session, forwardRecheckInterval for a run's device).
func AnnounceForwarderRevocation(db *statedb.DB, origin, forwarderID, bindingID, reason string) error {
	return appendInvalidations(db, origin, invalidateForwarder, []any{forwarderInvalidation{
		ForwarderID: forwarderID, BindingID: bindingID, Reason: reason,
	}})
}

// startForwarderSupervision runs, for this member's life, the re-check of the
// devices it holds open for runs and — on the leader — the sweep that stamps
// lapsed bindings and requests.
func (s *Server) startForwarderSupervision(ctx context.Context) {
	go func() {
		defer recoverGoroutine("forwarded device supervision")
		t := time.NewTicker(forwardRecheckInterval)
		defer t.Stop()
		lastSweep := time.Time{}
		for {
			select {
			case <-ctx.Done():
				return
			case now := <-t.C:
				recheckForwards(now)
				if s.isLeader() && now.Sub(lastSweep) >= time.Minute {
					lastSweep = now
					sweepLapsedForwarderBindings(now)
				}
			}
		}
	}()
}

// controlPlaneDBPath is the control plane's database path, for package-level
// code that has no Server.
func controlPlaneDBPath() string { return state.DBPath(controlPlaneDir()) }
