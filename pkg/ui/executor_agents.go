// Remote executor agent endpoint (Task 20158).
//
// This file mounts the one network surface the whole remote-executor feature
// needs: /api/executors/connect, where NAT'd devices dial in. Everything else
// about a remote executor — dispatching work, streaming logs, signalling —
// travels over the connection an agent establishes here, so there is no
// inbound path to a device to secure, and no port to forward.
//
// The endpoint deliberately sits outside the dashboard's token/OIDC auth.
// Agents are not users: they authenticate with their own enrollment token or
// long-lived credential, verified by the hub against hashes in statedb. Making
// them also carry the dashboard token would mean every edge device held a
// credential that grants full UI access — a much worse blast radius than the
// scoped, individually revocable agent credential they carry instead.

package ui

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/executor/remote"
	"github.com/blechschmidt/cloop/pkg/executorstore"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// executorConnectPath is where agents dial in.
const executorConnectPath = "/api/executors/connect"

var (
	executorHubOnce sync.Once
	executorHub     *remote.Hub
	executorHubErr  error
)

// remoteHub returns the process-wide agent hub, building it on first use.
//
// It is process-wide rather than per-Server because the executor registry it
// feeds is process-wide: two Server instances in one process (as several tests
// construct) must not race to register two executors for the same agent ID.
func (s *Server) remoteHub() (*remote.Hub, error) {
	executorHubOnce.Do(func() {
		db, err := statedb.Open(state.DBPath(s.WorkDir))
		if err != nil {
			executorHubErr = fmt.Errorf("open control-plane database: %w", err)
			return
		}
		store, err := executorstore.New(db)
		if err != nil {
			_ = db.Close()
			executorHubErr = err
			return
		}
		handles, err := executorstore.NewHandles(db)
		if err != nil {
			_ = db.Close()
			executorHubErr = err
			return
		}
		hub, err := remote.NewHub(remote.HubOptions{
			Store:    store,
			Registry: executor.DefaultRegistry,
			// Durable handle identity for every device executor this hub
			// builds (Task 20191). Without it a hub restart empties the
			// in-memory handle map, every resume offer from a reconnecting
			// agent is refused, and the harness on the edge device runs on
			// forever — invisible, its output discarded, with no reaper
			// anywhere. Passed at construction rather than attached after,
			// so a device that dials in during startup finds its handles
			// already adopted.
			//
			// Over the hub's own database handle, for the same reason
			// WorkspaceSource is: the hub is a process-wide singleton whose
			// *statedb.DB deliberately outlives every request.
			HandleStore: handles,
			// Where an edge device's git credential comes from (Task 20179).
			//
			// A factory, not a single source, because a grant is issued to a
			// *subject*: binding the executor ID at construction is what stops
			// a fetch for edge-1 being satisfied by a grant issued to edge-2.
			//
			// It is built over this hub's own database handle rather than a
			// fresh one. The hub is a process-wide singleton whose *statedb.DB
			// deliberately outlives every request, so reusing it costs no
			// second SQLite connection and no second WAL lock — where opening
			// a broker per workload, or per agent, would leak a handle on
			// every dispatch.
			WorkspaceSource: workspaceCredentialFactory(db),
			// Agents send no Origin, so these only ever affect browsers.
			//
			// The hub gets AllowedOrigins but NOT AllowedWSOrigins: an entry
			// in the latter is scoped to the dashboard socket, and forwarding
			// it here would silently grant every such origin the ability to
			// open an agent connection. ExternalURL is shared because it is
			// the one name the whole deployment answers to.
			ExternalURL:    s.ExternalURL,
			AllowedOrigins: s.AllowedOrigins,
			// Mirror into storage, then push the change to open dashboards
			// so the Executors panel's status dot is event-driven rather
			// than polled (Tasks 20126/20134, 20160).
			OnStatusChange: s.makeExecutorStatusBroadcaster(makeExecutorStatusMirror(db)),
			OnEnroll:       s.makeExecutorEnrollBroadcaster(makeExecutorEnrollRecorder(db)),
			Logf: func(format string, args ...any) {
				fmt.Fprintf(os.Stderr, format+"\n", args...)
			},
		})
		if err != nil {
			_ = db.Close()
			executorHubErr = err
			return
		}
		// Register an offline executor for every previously enrolled agent.
		// Without this, a project bound to edge-1 fails Resolve with
		// "executor not registered" after a control-plane restart, which
		// reads as a misconfiguration rather than as "the device is offline".
		if err := hub.Restore(); err != nil {
			fmt.Fprintf(os.Stderr, "ui: restore remote executors: %v\n", err)
		}
		executorHub = hub
	})
	return executorHub, executorHubErr
}

// makeExecutorStatusMirror keeps the executors table in step with live
// connectivity, so the Executors panel and `cloop executor list` report what
// is actually true rather than what was true at enrollment.
func makeExecutorStatusMirror(db *statedb.DB) func(string, string, time.Time) {
	return func(executorID, status string, at time.Time) {
		if err := db.TouchExecutorHeartbeat(executorID, status, at); err != nil {
			fmt.Fprintf(os.Stderr, "ui: record executor %s status %s: %v\n", executorID, status, err)
		}
	}
}

// makeExecutorEnrollRecorder writes the executors-table row for a device the
// first time it enrolls, so a newly enrolled agent is immediately visible and
// bindable rather than appearing only after someone reloads a page.
func makeExecutorEnrollRecorder(db *statedb.DB) func(remote.AgentRecord, remote.AgentCapabilities) {
	return func(agent remote.AgentRecord, caps remote.AgentCapabilities) {
		row := statedb.ExecutorRow{
			ID:         agent.AgentID,
			Name:       agent.Name,
			Kind:       executor.KindRemoteAgent,
			Status:     remote.StatusOnline,
			Labels:     agent.Labels,
			CreatedAt:  agent.CreatedAt,
			EnrolledBy: agent.EnrollmentID,
		}
		// Store the agent's full advertised capabilities, not the projected
		// executor.Capabilities: the scheduler-relevant extras (CPU count,
		// memory, container runtimes, installed harnesses) are exactly what
		// makes remote executors matchable, and they have nowhere else to go.
		if encoded, err := json.Marshal(caps); err == nil {
			row.Capabilities = encoded
		}
		if err := db.UpsertExecutor(row); err != nil {
			fmt.Fprintf(os.Stderr, "ui: record enrolled executor %s: %v\n", agent.AgentID, err)
		}
	}
}

// handleExecutorConnect upgrades an agent connection and serves its session.
func (s *Server) handleExecutorConnect(w http.ResponseWriter, r *http.Request) {
	hub, err := s.remoteHub()
	if err != nil {
		http.Error(w, "remote executors unavailable: "+err.Error(), http.StatusServiceUnavailable)
		return
	}
	hub.ServeHTTP(w, r)
}

// executorConnectBypass routes the agent endpoint around the dashboard's user
// authentication, which does not apply to it (see the file header).
//
// It is a separate layer rather than a case in probeBypass because the two
// have different requirements: probes skip rate limiting so a load balancer
// cannot be starved by user traffic, whereas agent connects deliberately stay
// behind the limiter — an unauthenticated flood of upgrade attempts is exactly
// what it is there to absorb, and a legitimate agent's capped backoff means it
// will never come close to the threshold.
func (s *Server) executorConnectBypass(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == executorConnectPath {
			s.handleExecutorConnect(w, r)
			return
		}
		next.ServeHTTP(w, r)
	})
}
