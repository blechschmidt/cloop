package ui

// adopt_api.go: asking a running project's run to adopt this hub's build at
// its next task boundary (Task 20389).
//
// A deploy replaces the hub and leaves the runs it started alone, so a run in
// auto-evolve keeps executing whatever build it started with. Every reader of
// the project now sees which one (the run-owner record, compared with the
// reader's own build — Overview, Tasks run bar, /api/state, `cloop status`,
// hub doctor). This is the one-shot action beside that: it files a request,
// addressed to the run's process, that the run acts on at its next task
// boundary — validating the binary at the path it was started from, and
// refusing it with a journalled reason if it is not strictly newer or does not
// embed the database's schema. The request itself changes nothing else, so it
// is gated like Start — the same permission, the same executor audience — and
// audited as run.adopt_requested.
//
// Host-process runs only. A run in a container or on a device executes the
// binary its image or its agent provides, and moves with them (the Upgrade
// dialog, a rebuilt image); the dashboard says so instead of offering this.

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"time"

	"github.com/blechschmidt/cloop/pkg/logger"
	"github.com/blechschmidt/cloop/pkg/runbuild"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// handleAdoptBuild files the request. POST /api/run/adopt-build.
func (s *Server) handleAdoptBuild(w http.ResponseWriter, r *http.Request) {
	if !requirePOST(w, r) {
		return
	}
	workDir := s.resolveWorkDir(r)
	// Gated like starting a run: the route carries run.start, and this asks
	// whether this identity may use the executor the project is on.
	if !s.admitExecutorAudienceForProject(w, r, workDir) {
		return
	}
	ps, err := state.LoadLite(workDir)
	if err != nil {
		jsonErr(w, "no project found", http.StatusNotFound)
		return
	}
	hub := state.SelfBuild()
	st := ps.RunBuild
	if msg := adoptRefusal(ps, st, hub); msg != "" {
		jsonErr(w, msg, http.StatusConflict)
		return
	}
	req := &runbuild.Request{
		ID:          newAdoptRequestID(),
		RequestedAt: time.Now().UTC(),
		RequestedBy: s.auditActor(r),
		Run:         ps.RunOwner.Ident,
		Hub:         hub,
	}
	if err := state.RequestAdoption(workDir, req); err != nil {
		jsonErr(w, "could not file the request: "+err.Error(), http.StatusInternalServerError)
		return
	}
	s.auditAdoptRequested(workDir, req, st)
	if fresh, err := state.LoadLite(workDir); err == nil {
		s.broadcastStateDiff(workDir, fresh)
	}
	jsonOK(w, map[string]interface{}{
		"ok":      true,
		"request": req,
		"message": fmt.Sprintf("Requested: the run (pid %d) adopts %s at its next task boundary", req.Run.PID, hub.Short()),
	})
}

// adoptRefusal says why a request would be pointless or impossible, or "".
func adoptRefusal(ps *state.ProjectState, st *runbuild.Status, hub runbuild.Build) string {
	switch {
	case ps.RunOwner == nil || st == nil:
		return "this project's run has not reported its build: it started on a cloop from before build " +
			"adoption existed (or no run has started yet). Restart it once; from then on it can adopt newer builds"
	case !st.LiveKnown:
		return fmt.Sprintf("the run's process (pid %d on %s) cannot be checked from this hub's host", st.PID, ps.RunOwner.Host)
	case !st.Live:
		return "no run of this project is running"
	case !st.Adoptable:
		return fmt.Sprintf("this run is on a %s executor, which keeps its own upgrade path: upgrade the device "+
			"or rebuild the image", st.Executor)
	case st.Comparable && st.Behind == 0:
		return fmt.Sprintf("the run is not behind this hub: it runs %s and this hub runs %s", st.Build.Label(), hub.Label())
	}
	return ""
}

// auditAdoptRequested records the request on the project's trail, where the
// run's own run.reexecuted row will answer it. Best effort, as every emitter
// here: the request is already filed.
func (s *Server) auditAdoptRequested(workDir string, req *runbuild.Request, st *runbuild.Status) {
	db, err := statedb.Open(state.DBPath(workDir))
	if err != nil {
		s.log().Warn(logger.EventAuthz, 0, "audit: open project db for an adoption request",
			map[string]interface{}{"error": err.Error(), "workdir": workDir})
		return
	}
	defer db.Close()
	statedb.AuditAdoptRequested(db, statedb.AdoptRequestInput{
		ProjectPath: workDir, RequestID: req.ID, PID: req.Run.PID,
		RunBuild: st.Build, HubBuild: req.Hub, Behind: st.Behind, Actor: req.RequestedBy,
	})
	s.broadcastAuditAppend("run.adopt_requested")
}

func newAdoptRequestID() string {
	var b [12]byte
	if _, err := rand.Read(b[:]); err != nil {
		return fmt.Sprintf("adopt_t%x", time.Now().UnixNano())
	}
	return "adopt_" + hex.EncodeToString(b[:])
}
