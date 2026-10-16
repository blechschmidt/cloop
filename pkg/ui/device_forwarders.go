// Device forwarder endpoint (Task 20429).
//
// This mounts /api/forwarders/connect, where on-prem forwarders dial in — the
// one network surface the feature needs, for the same reason the executor
// agent endpoint is the only one it needs: the device is behind NAT and
// connects outward. A forwarder is NOT an executor (it runs no work), so it
// has its own hub, its own tables and its own credential; a forwarder
// credential can never authenticate as something that runs work.
//
// The endpoint sits outside the dashboard's user auth, like the executor one:
// a forwarder authenticates with its own enrollment token or long-lived
// credential, verified against hashes in statedb, not with a dashboard token.

package ui

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/blechschmidt/cloop/pkg/deviceforward"
	"github.com/blechschmidt/cloop/pkg/forwarderstore"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// forwarderConnectPath is where forwarders dial in.
const forwarderConnectPath = "/api/forwarders/connect"

var (
	forwarderHubOnce sync.Once
	forwarderHubInst *deviceforward.Hub
	forwarderHubErr  error
	// forwarderHubLive is forwarderHubInst for readers outside the Once:
	// the dispatch path asks whether this process holds a forwarder's
	// session without building the hub (Task 20430).
	forwarderHubLive atomic.Pointer[deviceforward.Hub]
)

// activeForwarderHub returns the process's forwarder hub if it has been
// built, without building it.
func activeForwarderHub() *deviceforward.Hub { return forwarderHubLive.Load() }

// forwarderHub returns the process-wide forwarder hub, building it on first use.
//
// Process-wide for the same reason the executor hub is: a forwarder's live
// session is held by one process, and two Server instances in one process
// (as several tests construct) must not race to hold two sessions for one
// forwarder identity.
func (s *Server) forwarderHub() (*deviceforward.Hub, error) {
	forwarderHubOnce.Do(func() {
		db, err := statedb.Open(state.DBPath(s.WorkDir))
		if err != nil {
			forwarderHubErr = fmt.Errorf("open control-plane database: %w", err)
			return
		}
		store, err := forwarderstore.New(db)
		if err != nil {
			_ = db.Close()
			forwarderHubErr = err
			return
		}
		hub, err := deviceforward.NewHub(deviceforward.HubOptions{
			Store: store,
			// Same WebSocket-origin rule as every other upgrade endpoint: a
			// forwarder sends no Origin, so this only ever turns away a
			// browser that was tricked into opening the socket.
			CheckOrigin: func(r *http.Request) (bool, string) {
				if s.wsOriginAllowed(r) {
					return true, ""
				}
				s.recordAgentOriginRefusal(r)
				return false, "origin not allowed"
			},
			// Mirror connectivity into storage and push it to open dashboards,
			// so the Forwarders panel's status is event-driven like the
			// Executors panel's.
			OnStatusChange: s.makeForwarderStatusMirror(db),
			OnConnect:      s.makeForwarderConnectMirror(db),
			// A revocation recorded where this process could not hear of it —
			// the CLI, a member that missed the bus — still ends the session
			// within this (Task 20430).
			RevocationRecheck: deviceforward.DefaultRevocationRecheck,
			Logf: func(format string, args ...any) {
				fmt.Fprintf(os.Stderr, format+"\n", args...)
			},
		})
		if err != nil {
			_ = db.Close()
			forwarderHubErr = err
			return
		}
		forwarderHubInst = hub
		forwarderHubLive.Store(hub)
	})
	return forwarderHubInst, forwarderHubErr
}

// makeForwarderStatusMirror keeps device_forwarders.status in step with live
// connectivity and broadcasts the change to open dashboards. In a cluster only
// the member that holds a forwarder's tunnel speaks for it (Task 20430): one a
// forwarder left a moment after it reconnected elsewhere writes nothing, so it
// cannot overwrite the new holder's "online".
func (s *Server) makeForwarderStatusMirror(db *statedb.DB) func(string, string, time.Time) {
	return func(forwarderID, status string, at time.Time) {
		if status == "offline" {
			// The relays this member ran for the forwarder ended with its
			// session; close what is left of them now rather than at their
			// relay's next read.
			closeForwardsForForwarder(forwarderID, "the forwarder disconnected")
			if !s.forwarderGoneHere(forwarderID) {
				return
			}
		}
		if err := db.SetForwarderStatus(forwarderID, status, at); err != nil {
			fmt.Fprintf(os.Stderr, "ui: record forwarder %s status %s: %v\n", forwarderID, status, err)
		}
		s.broadcastToAll(wsMessage{Type: "forwarder_status", Data: forwarderStatusPayload(forwarderID, status)})
	}
}

// makeForwarderConnectMirror persists the device the forwarder advertised the
// first time its credential row needs one, and touches last-seen. The
// enrollment already wrote the authoritative device; this only fills the
// credential row's copy so a list before any dashboard reload shows it.
func (s *Server) makeForwarderConnectMirror(db *statedb.DB) func(deviceforward.ForwarderRecord, deviceforward.HelloPayload) {
	return func(rec deviceforward.ForwarderRecord, hello deviceforward.HelloPayload) {
		// Recorded as held here before anything can ask for its device: a
		// member dispatching a run looks the holder up in the shared owner
		// rows (Task 20430).
		s.recordForwarderHeld(rec, hello)
		_ = db.TouchForwarder(rec.ForwarderID, time.Now())
		s.broadcastToAll(wsMessage{Type: "forwarder_status", Data: forwarderStatusPayload(rec.ForwarderID, "online")})
	}
}

// handleForwarderConnect upgrades a forwarder connection and serves its session.
func (s *Server) handleForwarderConnect(w http.ResponseWriter, r *http.Request) {
	hub, err := s.forwarderHub()
	if err != nil {
		http.Error(w, "device forwarders unavailable: "+err.Error(), http.StatusServiceUnavailable)
		return
	}
	hub.ServeHTTP(w, r)
}

// forwarderConnectBypass routes the forwarder endpoint around the dashboard's
// user authentication, which does not apply to it, exactly as
// executorConnectBypass does for agents.
func (s *Server) forwarderConnectBypass(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == forwarderConnectPath {
			s.handleForwarderConnect(w, r)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// forwarderStatusPayload builds the WebSocket payload for a connectivity change.
func forwarderStatusPayload(id, status string) json.RawMessage {
	raw, _ := json.Marshal(map[string]any{"id": id, "status": status})
	return raw
}
