package ui

// cluster_misc.go: small pieces of the hub's cluster wiring (Task 20354) that
// several files share.

import (
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/executorstore"
	"github.com/blechschmidt/cloop/pkg/hubcluster"
	"github.com/blechschmidt/cloop/pkg/multiui"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// headerPeerWorkdir carries, on a forwarded request, the project directory the
// forwarding member resolved. Only read from verified peer requests.
const headerPeerWorkdir = "X-Cloop-Peer-Workdir"

// forwardProject forwards r to m, naming workDir as the project it is about.
func (s *Server) forwardProject(w http.ResponseWriter, r *http.Request, m hubcluster.Member, workDir string) bool {
	if workDir != "" {
		r.Header.Set(headerPeerWorkdir, workDir)
	}
	return s.forwardTo(w, r, m)
}

// peerWorkDir returns the project a verified peer resolved for r, if it named
// one this member also knows.
func (s *Server) peerWorkDir(r *http.Request) (string, bool) {
	if r == nil {
		return "", false
	}
	if _, ok := peerCallFrom(r); !ok {
		return "", false
	}
	dir := strings.TrimSpace(r.Header.Get(headerPeerWorkdir))
	if dir == "" {
		return "", false
	}
	for _, e := range s.visibleProjectEntries(r) {
		if e.Path == dir {
			return dir, true
		}
	}
	// A project this caller cannot see here is refused rather than resolved:
	// the forwarding member's view must never widen this one's.
	return "", false
}

// peerEntry resolves a forwarded /api/projects/{idx}/… request by the path the
// forwarding member named. forwarded reports whether r carried one at all.
func (s *Server) peerEntry(r *http.Request) (e multiui.ProjectEntry, ok, forwarded bool) {
	if r == nil {
		return multiui.ProjectEntry{}, false, false
	}
	if _, peer := peerCallFrom(r); !peer {
		return multiui.ProjectEntry{}, false, false
	}
	dir := strings.TrimSpace(r.Header.Get(headerPeerWorkdir))
	if dir == "" {
		return multiui.ProjectEntry{}, false, false
	}
	for _, entry := range s.visibleProjectEntries(r) {
		if entry.Path == dir {
			return entry, true, true
		}
	}
	return multiui.ProjectEntry{}, false, true
}

// writeJSONBody encodes body to w, after the caller wrote the status.
func writeJSONBody(w http.ResponseWriter, body any) error {
	return json.NewEncoder(w).Encode(body)
}

// virtualParentOf returns the edge agent a virtual executor runs on, or "".
func virtualParentOf(id string) string {
	ex, err := executor.Get(id)
	if err != nil || ex == nil {
		return ""
	}
	if v, ok := ex.(interface{ ParentID() string }); ok {
		return strings.TrimSpace(v.ParentID())
	}
	return ""
}

// controlPlaneHandleStore returns a handle store over the control plane's
// database, or nil before bootstrap. Opened per call and not closed: the
// reconcile package caches one per directory for the process's life, and this
// asks it for that same one.
func controlPlaneHandleStore() executor.HandleStore {
	dir := controlPlaneDir()
	if dir == "" {
		return nil
	}
	handleStoreOnce.Do(func() {
		db, err := statedb.Open(state.DBPath(dir))
		if err != nil {
			return
		}
		store, err := executorstore.NewHandles(db)
		if err != nil {
			_ = db.Close()
			return
		}
		handleStoreShared = store
	})
	return handleStoreShared
}

var (
	handleStoreOnce   sync.Once
	handleStoreShared executor.HandleStore
)

// processCluster is the cluster membership of this process, for the
// package-level executor plumbing that has no Server to ask (bootstrap, the
// supervisor, lease materialisation) — the same reason controlPlaneDir is
// package-level. Nil for a standalone hub and for every test that does not
// build a cluster.
var processCluster atomic.Pointer[hubcluster.Node]

func setProcessCluster(n *hubcluster.Node) {
	if n == nil {
		return
	}
	processCluster.Store(n)
}

// currentCluster returns this process's cluster membership, or nil.
func currentCluster() *hubcluster.Node { return processCluster.Load() }

// processInstanceID names this process in rows other members read, or "".
func processInstanceID() string {
	if n := currentCluster(); n != nil {
		return n.ID()
	}
	return ""
}
