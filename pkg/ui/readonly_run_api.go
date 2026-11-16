package ui

// readonly_run_api.go: a run's questions about the other projects it was given
// to read (Task 20501).
//
//	POST /api/run/knowledge/readonly            {}             which may it still read?
//	POST /api/run/knowledge/readonly/snapshot   {"slug": …}    a snapshot of one of them
//
// Both are asked with the run's knowledge session (knowledge_run.go), which
// records the projects the run was given at its dispatch, and nothing a
// request says can add to them. Both answer from the readers lists as they are
// at that request, through runMayRead: the run's orchestrator asks the first at
// every task boundary and ends the run there when a project it reads no longer
// lists it; an executor that does not share the hub's filesystem — a
// Kubernetes Pod's workspace container, a device's agent — asks the second for
// the snapshot it places for the run, and is refused one the moment the list
// stops naming the run's project.

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/blechschmidt/cloop/pkg/apierror"
	"github.com/blechschmidt/cloop/pkg/auditaction"
	"github.com/blechschmidt/cloop/pkg/executor/readonlysnap"
	"github.com/blechschmidt/cloop/pkg/knowledgerun"
)

// readOnlySnapshotSlots bounds the snapshots this process builds at once: each
// reads a project's whole tree and writes up to readonlysnap.MaxArchiveBytes.
var readOnlySnapshotSlots = make(chan struct{}, 2)

// maxSnapshotsPerProject bounds the snapshots of one project a session is
// served by this process: the executor placing it fetches one, and a retry or
// two is all a failed fetch needs.
const maxSnapshotsPerProject = 3

// snapshotGate holds, per session, whether a build is in flight and how many
// snapshots of each project it was served, so that one run cannot keep the
// hub building snapshots for it.
var snapshotGate = &readOnlySnapshotGate{sessions: map[string]*snapshotSession{}}

type readOnlySnapshotGate struct {
	mu       sync.Mutex
	sessions map[string]*snapshotSession
}

type snapshotSession struct {
	building bool
	served   map[string]int
	last     time.Time
}

// take admits one snapshot build of slug for session, returning its release,
// or why it is refused.
func (g *readOnlySnapshotGate) take(session, slug string) (func(), string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	now := time.Now()
	if len(g.sessions) > 4096 {
		for id, s := range g.sessions {
			if !s.building && now.Sub(s.last) > time.Hour {
				delete(g.sessions, id)
			}
		}
	}
	s := g.sessions[session]
	if s == nil {
		s = &snapshotSession{served: map[string]int{}}
		g.sessions[session] = s
	}
	switch {
	case s.building:
		return nil, "this run's session is already fetching a snapshot; fetch one at a time"
	case s.served[slug] >= maxSnapshotsPerProject:
		return nil, fmt.Sprintf("this run's session was already served %d snapshots of that project", maxSnapshotsPerProject)
	}
	s.building, s.last = true, now
	s.served[slug]++
	return func() {
		g.mu.Lock()
		defer g.mu.Unlock()
		s.building = false
	}, ""
}

// readOnlyGrants are the projects the session's run was given to read at its
// dispatch.
func (c *runKnowledgeCall) readOnlyGrants() []readOnlyGrant {
	var scope knowledgeScope
	if json.Unmarshal([]byte(c.row.Scope), &scope) != nil {
		return nil
	}
	return scope.ReadOnly
}

// readOnlyTarget is the project the run was given under slug, when its readers
// list names the run's project now; an error wrapping errRunRead otherwise,
// saying why — the run is told only runReadNotFound.
func (c *runKnowledgeCall) readOnlyTarget(slug string) (readOnlyGrant, error) {
	for _, g := range c.readOnlyGrants() {
		if g.Slug != strings.TrimSpace(slug) || slug == "" {
			continue
		}
		if err := runMayRead(c.db, c.workDir, g.Project); err != nil {
			return g, err
		}
		return g, nil
	}
	return readOnlyGrant{}, fmt.Errorf("%w: the run was given no project under %q", errRunRead, oneLineText(slug))
}

// handleRunReadOnly serves POST /api/run/knowledge/readonly: every project the
// run was given to read, and whether its readers list still names the run's
// project. A change is on the audit trail; an unchanged answer is not, being
// asked at every task boundary.
func (s *Server) handleRunReadOnly(w http.ResponseWriter, r *http.Request) {
	call, ok := s.openRunKnowledgeCall(w, r)
	if !ok {
		return
	}
	defer call.close()
	var req struct{}
	if !call.decode(w, r, &req) {
		return
	}
	action := auditaction.ActionKnowledgeRunReadOnly
	fields := map[string]any{"reader": call.workDir}
	if !call.allow(w, action, fields) {
		return
	}
	grants := call.readOnlyGrants()
	out := knowledgerun.ReadOnlyResponse{Projects: make([]knowledgerun.ReadOnlyStatus, 0, len(grants))}
	var gone, why []string
	for _, g := range grants {
		_, err := call.readOnlyTarget(g.Slug)
		if errors.Is(err, errRunReadUnavailable) {
			// Not the lists' answer: the run asks again, or waits, rather
			// than stop as though it had been taken off one.
			apierror.WriteError(w, apierror.New(apierror.CodeUnavailable,
				"the hub could not read the readers lists; ask again"))
			return
		}
		out.Projects = append(out.Projects, knowledgerun.ReadOnlyStatus{Slug: g.Slug, Project: g.Project,
			Readable: err == nil})
		if err != nil {
			gone = append(gone, g.Project)
			why = append(why, strings.TrimPrefix(err.Error(), errRunRead.Error()+": "))
		}
	}
	if len(gone) > 0 {
		call.audit(action, "changed", strings.Join(why, "; "), withField(fields, "read_projects", gone))
	}
	jsonOK(w, out)
}

// handleRunReadOnlySnapshot serves POST /api/run/knowledge/readonly/snapshot:
// a snapshot of the project the run was given under the slug, built now from
// its tree on the hub (pkg/executor/readonlysnap) — refused, 404, when the
// run was given no project under it or its readers list no longer names the
// run's project.
func (s *Server) handleRunReadOnlySnapshot(w http.ResponseWriter, r *http.Request) {
	call, ok := s.openRunKnowledgeCall(w, r)
	if !ok {
		return
	}
	defer call.close()
	var req knowledgerun.SnapshotRequest
	if !call.decode(w, r, &req) {
		return
	}
	action := auditaction.ActionKnowledgeRunSnapshot
	fields := map[string]any{"reader": call.workDir, "slug": oneLineText(req.Slug)}
	if !call.allow(w, action, fields) {
		return
	}
	g, err := call.readOnlyTarget(req.Slug)
	if g.Project != "" {
		fields["read_project"] = g.Project
	}
	if errors.Is(err, errRunReadUnavailable) {
		call.audit(action, "error", strings.TrimPrefix(err.Error(), errRunRead.Error()+": "), fields)
		apierror.WriteError(w, apierror.New(apierror.CodeUnavailable,
			"the hub could not read the readers lists; ask again"))
		return
	}
	if err != nil {
		call.audit(action, "refused", strings.TrimPrefix(err.Error(), errRunRead.Error()+": "), fields)
		apierror.WriteError(w, apierror.New(apierror.CodeNotFound, runReadNotFound))
		return
	}
	// Whatever the list says, never the hub's own directory, nor one that
	// breaks the hub's confinement, nor nothing.
	if why := readOnlyRefusal(g.Project); why != "" {
		call.audit(action, "refused", why, fields)
		apierror.WriteError(w, apierror.New(apierror.CodeNotFound, runReadNotFound))
		return
	}
	// One build at a time for a session, and a few per project it was given:
	// an executor fetches each once, and a run asking for more is not asking
	// for anything it needs.
	release, why := snapshotGate.take(call.row.SessionID, g.Slug)
	if why != "" {
		call.audit(action, "refused", why, fields)
		w.Header().Set("Retry-After", "5")
		apierror.WriteError(w, apierror.New(apierror.CodeRateLimited, why))
		return
	}
	defer release()
	select {
	case readOnlySnapshotSlots <- struct{}{}:
		defer func() { <-readOnlySnapshotSlots }()
	case <-r.Context().Done():
		return
	}
	tmp, err := os.CreateTemp("", "cloop-readonly-snapshot-*.tar.gz")
	if err != nil {
		call.audit(action, "error", "no temporary file for the snapshot: "+err.Error(), fields)
		apierror.WriteError(w, apierror.New(apierror.CodeUnavailable, "the hub could not build the snapshot"))
		return
	}
	defer func() {
		_ = tmp.Close()
		_ = os.Remove(tmp.Name())
	}()
	snap, err := readonlysnap.Build(r.Context(), g.Project, tmp)
	switch {
	case errors.Is(err, readonlysnap.ErrTooLarge):
		call.audit(action, "refused", err.Error(), fields)
		apierror.WriteError(w, apierror.New(apierror.CodePayloadTooLarge,
			strings.TrimPrefix(err.Error(), "readonlysnap: ")))
		return
	case err != nil:
		call.audit(action, "error", oneLineText(err.Error()), fields)
		apierror.WriteError(w, apierror.New(apierror.CodeInternal, "the hub could not build the snapshot"))
		return
	}
	if _, err := tmp.Seek(0, io.SeekStart); err != nil {
		call.audit(action, "error", err.Error(), fields)
		apierror.WriteError(w, apierror.New(apierror.CodeInternal, "the hub could not build the snapshot"))
		return
	}
	fields["files"], fields["links"], fields["bytes"], fields["archive_bytes"] = snap.Files, snap.Links, snap.Bytes,
		snap.Archive
	if len(snap.Skipped) > 0 {
		fields["skipped"] = len(snap.Skipped)
	}
	call.audit(action, "ok", "", fields)
	w.Header().Set("Content-Type", "application/gzip")
	w.Header().Set("Content-Length", strconv.FormatInt(snap.Archive, 10))
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = io.Copy(w, tmp)
}
