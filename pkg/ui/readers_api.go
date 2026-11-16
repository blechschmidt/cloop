package ui

// A project's readers list over REST (Task 20498):
//
//	GET    /api/projects/{idx}/readers                the projects that may read this one, and what it may read
//	PUT    /api/projects/{idx}/readers                add one: {"reader": "<path>"} or {"reader_idx": <index>}
//	DELETE /api/projects/{idx}/readers?reader=<path>  take one off (or ?id=<entry id>)
//
// The list is deny-by-default (pkg/projectreaders): a project's runs may read
// another project only when the other's list names it.
//
// # Who may do what
//
// Reading the list takes project.read: everybody on a project may see which
// other projects can read it, and which it can read. Changing it takes
// project.readers on the project, which only its administrators hold — its
// owner, a member at admin, the hub's administrators, and on a hub without
// sign-in the static admin — and both writes ask for a recent sign-in on a hub
// with single sign-on. An entry hands this project's source to every run of
// another project, and nobody on that project is bounded by a role here.
//
// # What the caller is told about other projects
//
// Only projects the caller can see are named, on either side: a reader the
// caller cannot see, or one no longer on the hub, is counted and never named.
// Its administrator still gets each such entry's id, who added it and when,
// so a project's administrators can always take back what was given, without
// learning anything about the project it was given to. Adding a reader needs
// the caller to see it, in the list every {idx} route resolves through, so
// nobody lists a project they could not otherwise know of.
//
// The reader travels in the query string on DELETE because several clients
// and proxies drop a DELETE body (members_api.go gives the same reason).
//
// # What an administrator is offered
//
// A caller who may change the list is also sent the projects they could add,
// as candidates: the projects they can see that are not this one, not a
// feature and not on the list already — the PUT's own rules, so the
// dashboard's picker offers what the hub takes. When who sees which project
// changes, every open Readers section is sent its candidates again.
//
// # Open dashboards
//
// A change to a list is pushed to every dashboard showing either project of
// the entry, rendered for that dashboard as its own GET would answer
// (readers_push.go).

import (
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/apierror"
	"github.com/blechschmidt/cloop/pkg/auditaction"
	"github.com/blechschmidt/cloop/pkg/authz"
	"github.com/blechschmidt/cloop/pkg/jsonbody"
	"github.com/blechschmidt/cloop/pkg/logger"
	"github.com/blechschmidt/cloop/pkg/multiui"
	"github.com/blechschmidt/cloop/pkg/projectreaders"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// maxReaderBodyBytes bounds a PUT body: one path, or one index.
const maxReaderBodyBytes = 8 << 10

// readerEntryID is the shape of an entry id the store issues.
var readerEntryID = regexp.MustCompile(`^prd_[0-9a-f]{24}$`)

// readerView is another project on one side of a list, as the caller sees it.
type readerView struct {
	// ID is the entry's id: on the readers side, the entry letting that
	// project read this one; on the readable side, the entry letting this one
	// read that project.
	ID string `json:"id"`
	// Project is the other project's registry name, Path its path on the
	// hub, Idx its index in the caller's project list.
	Project string    `json:"project"`
	Path    string    `json:"path"`
	Idx     int       `json:"idx"`
	AddedBy string    `json:"added_by,omitempty"`
	AddedAt time.Time `json:"added_at"`
}

// hiddenReaderView is an entry on this project's list naming a project the
// caller cannot see, or one no longer on the hub: enough for an administrator
// to remove it, nothing about the other project.
type hiddenReaderView struct {
	ID      string    `json:"id"`
	AddedBy string    `json:"added_by,omitempty"`
	AddedAt time.Time `json:"added_at"`
}

// readersResponse is what GET returns.
type readersResponse struct {
	Project string `json:"project"`
	Path    string `json:"path"`

	// Readers are the projects that may read this one and that the caller can
	// see; HiddenReaders counts the entries naming any other project.
	Readers       []readerView `json:"readers"`
	HiddenReaders int          `json:"hidden_readers"`
	// Hidden are those other entries, for a caller who may change the list.
	Hidden []hiddenReaderView `json:"hidden,omitempty"`

	// Readable are the projects this one may read and that the caller can
	// see; HiddenReadable counts the rest. They are on the other projects'
	// lists, which only those projects' administrators change.
	Readable       []readerView `json:"readable"`
	HiddenReadable int          `json:"hidden_readable"`

	// CanManage reports whether the caller may change this project's list:
	// project.readers on it.
	CanManage bool `json:"can_manage"`
	// Candidates are the projects a caller who may change the list could add
	// to it: those they can see that are neither this project, a feature, nor
	// on the list already. Sent only with CanManage.
	Candidates []readerCandidate `json:"candidates,omitempty"`

	// Feature is set when the project at the index is a feature, which has no
	// list of its own and reads nothing by its project's.
	Feature bool   `json:"feature,omitempty"`
	Note    string `json:"note,omitempty"`
}

// readerCandidate is a project the caller could add to the list.
type readerCandidate struct {
	Project string `json:"project"`
	Path    string `json:"path"`
	Idx     int    `json:"idx"`
}

// readerRequest is the PUT body: the reader by its path, or by its index in
// the caller's project list.
type readerRequest struct {
	Reader    string `json:"reader"`
	ReaderIdx *int   `json:"reader_idx"`
}

// ── handlers ────────────────────────────────────────────────────────────────

// handleProjectReaders serves GET /api/projects/{idx}/readers.
func (s *Server) handleProjectReaders(w http.ResponseWriter, r *http.Request) {
	entry, ok := s.projectAtIdx(w, r)
	if !ok {
		return
	}
	var res *projectreaders.Resolver
	if !entry.IsFeature() {
		var err error
		if res, err = s.loadReaders(); err != nil {
			s.writeReadersStoreError(w, err)
			return
		}
	}
	jsonOK(w, s.readersViewFor(entry, s.grantFor(r), s.visibleProjectEntries(r), res))
}

// readersViewFor is entry's lists as a caller holding g is shown them, when
// visible is that caller's project list — the index space every idx in the
// answer counts in. The GET answers with it, and a push sends each dashboard
// what it makes for that dashboard's credential (readers_push.go), so the
// two can never disagree about who is named to whom.
func (s *Server) readersViewFor(entry multiui.ProjectEntry, g *grant, visible []multiui.ProjectEntry, res *projectreaders.Resolver) readersResponse {
	resp := readersResponse{Project: entry.Name, Path: entry.Path, Readers: []readerView{}, Readable: []readerView{}}
	if entry.IsFeature() {
		resp.Feature = true
		resp.Note = "A feature has no readers list of its own, and reads no other project by its project's list. " +
			"The list of " + s.featureParentLabel(entry) + " names the projects that may read it."
		return resp
	}
	resp.CanManage = g.decide(s.entryScope(entry)).Allows(authz.PermProjectReaders)
	seen := s.seenProjectsIn(g, visible)
	listed := map[string]bool{}
	for _, e := range res.ReadersOf(entry.Path) {
		listed[e.ReaderPath] = true
		if v, ok := seen.view(e, e.ReaderPath); ok {
			resp.Readers = append(resp.Readers, v)
			continue
		}
		resp.HiddenReaders++
		if resp.CanManage {
			resp.Hidden = append(resp.Hidden, hiddenReaderView{ID: e.ID, AddedBy: e.AddedBy, AddedAt: e.AddedAt})
		}
	}
	for _, e := range res.EntriesReadableBy(entry.Path) {
		if v, ok := seen.view(e, e.ProjectPath); ok {
			resp.Readable = append(resp.Readable, v)
			continue
		}
		resp.HiddenReadable++
	}
	if resp.CanManage {
		// The PUT's rules (readerFromRequest), in the order of the caller's
		// own project list: one they can see, not a feature, not this
		// project, not listed already, and named by a path the PUT takes
		// back unchanged.
		for i, e := range visible {
			if _, ok := seen[e.Path]; !ok || listed[projectreaders.NormalizePath(e.Path)] ||
				!readerCandidatePath(e.Path) || projectreaders.CheckPair(entry.Path, e.Path) != nil {
				continue
			}
			resp.Candidates = append(resp.Candidates, readerCandidate{Project: e.Name, Path: e.Path, Idx: i})
		}
	}
	return resp
}

// handleProjectReaderAdd serves PUT /api/projects/{idx}/readers.
func (s *Server) handleProjectReaderAdd(w http.ResponseWriter, r *http.Request) {
	entry, ok := s.readersTarget(w, r)
	if !ok {
		return
	}
	var req readerRequest
	if !jsonbody.Decode(w, r, &req, jsonbody.Options{Limit: maxReaderBodyBytes, Strict: true}) {
		return
	}
	reader, idx, ok := s.readerFromRequest(w, r, entry, req)
	if !ok {
		return
	}
	db, err := s.controlPlaneDB()
	if err != nil {
		s.writeReadersStoreError(w, err)
		return
	}
	stored, added, err := projectreaders.Add(db, entry.Path, reader.Path, s.auditActor(r), s.readerAudit(r, ""))
	db.Close()
	if err != nil {
		s.writeReadersStoreError(w, err)
		return
	}
	if added {
		// Both sides' dashboards: this project's readers and the reader's
		// list of what it may read changed.
		s.readersChanged(entry.Path, reader.Path)
	}
	jsonOK(w, map[string]any{
		"added": added,
		"reader": readerView{ID: stored.ID, Project: reader.Name, Path: reader.Path, Idx: idx,
			AddedBy: stored.AddedBy, AddedAt: stored.AddedAt},
	})
}

// handleProjectReaderRemove serves DELETE /api/projects/{idx}/readers.
//
// Taking an entry off needs no sight of the project it names: a project's
// administrators may always take back what was given, and the caller names
// either the path they typed or an id this list issued.
func (s *Server) handleProjectReaderRemove(w http.ResponseWriter, r *http.Request) {
	entry, ok := s.readersTarget(w, r)
	if !ok {
		return
	}
	q := r.URL.Query()
	rawReader, id := strings.TrimSpace(q.Get("reader")), strings.TrimSpace(q.Get("id"))
	switch {
	case rawReader != "" && id != "":
		apierror.WriteError(w, apierror.New(apierror.CodeInvalidInput,
			"name the entry by ?reader=<path> or by ?id=<entry id>, not both"))
		return
	case rawReader == "" && id == "":
		apierror.WriteError(w, apierror.New(apierror.CodeInvalidInput,
			"name the project to take off the list: ?reader=<its path>, or ?id=<the entry's id> for one you cannot see"))
		return
	case id != "" && !readerEntryID.MatchString(id):
		apierror.WriteError(w, apierror.New(apierror.CodeInvalidInput, "that is not an entry id: it looks like prd_ and 24 hex digits"))
		return
	}
	var readerPath string
	if rawReader != "" {
		p, err := projectreaders.ParsePath(rawReader)
		if err != nil {
			writeReadersInputError(w, err)
			return
		}
		readerPath = p
	}
	db, err := s.controlPlaneDB()
	if err != nil {
		s.writeReadersStoreError(w, err)
		return
	}
	audit := s.readerAudit(r, "")
	var removed *projectreaders.Reader
	if id != "" {
		removed, err = projectreaders.RemoveByID(db, entry.Path, id, audit)
	} else {
		removed, err = projectreaders.Remove(db, entry.Path, readerPath, audit)
	}
	db.Close()
	if err != nil {
		s.writeReadersStoreError(w, err)
		return
	}
	if removed == nil {
		apierror.WriteError(w, apierror.New(apierror.CodeNotFound, "this project's readers list has no such entry"))
		return
	}
	s.readersChanged(entry.Path, removed.ReaderPath)
	out := map[string]any{"ok": true, "id": removed.ID}
	// Named back only when the caller named it, or can see it.
	if readerPath != "" {
		out["reader"] = removed.ReaderPath
	} else if v, ok := s.seenProjects(r).view(*removed, removed.ReaderPath); ok {
		out["reader"] = v.Path
	}
	jsonOK(w, out)
}

// ── shared steps ────────────────────────────────────────────────────────────

// readersTarget resolves the project whose list a change is about, refusing a
// feature: it has no list of its own.
func (s *Server) readersTarget(w http.ResponseWriter, r *http.Request) (multiui.ProjectEntry, bool) {
	entry, ok := s.projectAtIdx(w, r)
	if !ok {
		return multiui.ProjectEntry{}, false
	}
	if entry.IsFeature() {
		parent := s.featureParentLabel(entry)
		apierror.WriteError(w, apierror.New(apierror.CodeConflict,
			"a feature has no readers list of its own — change the list of "+parent+" instead").
			WithDetails(map[string]any{"project": parent}))
		return multiui.ProjectEntry{}, false
	}
	return entry, true
}

// readerFromRequest resolves the project a PUT names as the reader, in the
// caller's own project list, and refuses one that may not be listed: not
// there, a feature, or the project itself. It returns the reader and its
// index in that list.
func (s *Server) readerFromRequest(w http.ResponseWriter, r *http.Request, target multiui.ProjectEntry, req readerRequest) (multiui.ProjectEntry, int, bool) {
	raw := strings.TrimSpace(req.Reader)
	switch {
	case raw != "" && req.ReaderIdx != nil:
		apierror.WriteError(w, apierror.New(apierror.CodeInvalidInput,
			"name the reader by reader (its path) or by reader_idx (its index in your project list), not both"))
		return multiui.ProjectEntry{}, 0, false
	case raw == "" && req.ReaderIdx == nil:
		apierror.WriteError(w, apierror.New(apierror.CodeInvalidInput,
			"name the project that may read this one: reader (its path) or reader_idx (its index in your project list)"))
		return multiui.ProjectEntry{}, 0, false
	}
	entries := s.visibleProjectEntries(r)
	idx := -1
	if req.ReaderIdx != nil {
		if i := *req.ReaderIdx; i >= 0 && i < len(entries) {
			idx = i
		}
	} else {
		path, err := projectreaders.ParsePath(raw)
		if err != nil {
			writeReadersInputError(w, err)
			return multiui.ProjectEntry{}, 0, false
		}
		for i, e := range entries {
			if e.Path == path {
				idx = i
				break
			}
		}
	}
	// A project the caller may not read is one they cannot see: answered the
	// same as one that does not exist.
	if idx < 0 || !s.grantFor(r).decide(s.entryScope(entries[idx])).Allows(authz.PermProjectRead) {
		apierror.WriteError(w, apierror.New(apierror.CodeNotFound,
			"there is no such project among the ones you can see"))
		return multiui.ProjectEntry{}, 0, false
	}
	reader := entries[idx]
	if reader.IsFeature() {
		parent := s.featureParentLabel(reader)
		apierror.WriteError(w, apierror.New(apierror.CodeInvalidInput,
			reader.Name+" is a feature of "+parent+", and a feature is never on a readers list — list "+parent+" instead").
			WithDetails(map[string]any{"project": parent}))
		return multiui.ProjectEntry{}, 0, false
	}
	if err := projectreaders.CheckPair(target.Path, reader.Path); err != nil {
		writeReadersInputError(w, err)
		return multiui.ProjectEntry{}, 0, false
	}
	return reader, idx, true
}

// featureParentLabel names a feature's project: its registry name, or its path
// when the registry no longer lists it.
func (s *Server) featureParentLabel(e multiui.ProjectEntry) string {
	if name := s.projectNameForPath(e.Parent); name != "" {
		return name
	}
	return e.Parent
}

// seenProjects indexes the caller's project list by path, for naming the
// other side of each entry only to a caller who can see it.
type seenProjects map[string]struct {
	idx   int
	entry multiui.ProjectEntry
}

func (s *Server) seenProjects(r *http.Request) seenProjects {
	return s.seenProjectsIn(s.grantFor(r), s.visibleProjectEntries(r))
}

// seenProjectsIn is seenProjects for a caller holding g whose project list is
// entries.
func (s *Server) seenProjectsIn(g *grant, entries []multiui.ProjectEntry) seenProjects {
	out := make(seenProjects, len(entries))
	for i, e := range entries {
		if e.IsFeature() || !g.decide(s.entryScope(e)).Allows(authz.PermProjectRead) {
			continue
		}
		out[e.Path] = struct {
			idx   int
			entry multiui.ProjectEntry
		}{i, e}
	}
	return out
}

// view renders the project at path on one side of e, if the caller sees it.
func (p seenProjects) view(e projectreaders.Reader, path string) (readerView, bool) {
	seen, ok := p[path]
	if !ok {
		return readerView{}, false
	}
	return readerView{ID: e.ID, Project: seen.entry.Name, Path: path, Idx: seen.idx,
		AddedBy: e.AddedBy, AddedAt: e.AddedAt}, true
}

// loadReaders reads every list from the control plane. A hub that has none
// yet has no lists.
func (s *Server) loadReaders() (*projectreaders.Resolver, error) {
	if _, err := os.Stat(state.DBPath(s.WorkDir)); errors.Is(err, os.ErrNotExist) {
		return projectreaders.New(nil), nil
	}
	db, err := s.controlPlaneDB()
	if err != nil {
		return nil, err
	}
	defer db.Close()
	res, err := projectreaders.Load(db)
	if err != nil {
		return nil, err
	}
	for _, e := range res.Skipped() {
		s.log().Warn(logger.EventAuthz, 0, "project readers: an entry no list may hold is ignored",
			map[string]interface{}{"id": e.ID, "project": e.ProjectPath, "reader": e.ReaderPath})
	}
	return res, nil
}

// readerAudit builds the audit row committed with each change to a list.
// reason says why, for a change nobody asked for by name: a project leaving
// the hub.
func (s *Server) readerAudit(r *http.Request, reason string) projectreaders.Audit {
	actor := s.auditActor(r)
	names := projectNamesByPath(s.allProjectEntries())
	return func(prev, next *projectreaders.Reader) ([]*statedb.AuditEvent, error) {
		action, e := auditaction.ActionProjectReaderAdd, next
		if next == nil {
			action, e = auditaction.ActionProjectReaderRemove, prev
		}
		if e == nil {
			return nil, nil
		}
		payload := map[string]any{
			"id": e.ID, "project": names[e.ProjectPath], "project_path": e.ProjectPath,
			"reader": names[e.ReaderPath], "reader_path": e.ReaderPath, "via": "api",
		}
		if reason != "" {
			payload["reason"] = reason
		}
		return []*statedb.AuditEvent{readerAuditEvent(actor, action, e, payload)}, nil
	}
}

// readerAuditEvent is one project_reader audit row.
func readerAuditEvent(actor string, action auditaction.Action, e *projectreaders.Reader, payload map[string]any) *statedb.AuditEvent {
	body, err := json.Marshal(payload)
	if err != nil {
		body = []byte(`{}`)
	}
	return &statedb.AuditEvent{
		Actor:      actor,
		EventType:  string(action),
		EntityType: "project_reader",
		// The pair is what changed; an auditor filtering on either project
		// must find it.
		EntityID: e.ProjectPath + "|" + e.ReaderPath,
		Payload:  string(body),
	}
}

// dropProjectReaders removes every entry naming a project that is leaving the
// hub, on either side of a list, and returns the projects on the other side of
// them, whose dashboards lose a reader or a project they could read: the
// caller pushes those once the project is off the registry, so that no list
// pushed offers it. Entries are keyed by path, and one outliving its project
// would hand the access to whatever is registered at that path next. Called
// before the registry change, which does not happen if this fails.
func (s *Server) dropProjectReaders(r *http.Request, entry multiui.ProjectEntry) ([]string, error) {
	if _, err := os.Stat(state.DBPath(s.WorkDir)); err != nil {
		// No control plane yet, so no list.
		return nil, nil
	}
	db, err := s.controlPlaneDB()
	if err != nil {
		return nil, err
	}
	defer db.Close()
	removed, err := projectreaders.RemoveProject(db, entry.Path, s.readerAudit(r, "the project was removed from the hub"))
	if err != nil {
		return nil, err
	}
	var others []string
	for _, e := range removed {
		for _, p := range []string{e.ProjectPath, e.ReaderPath} {
			if p != projectreaders.NormalizePath(entry.Path) {
				others = append(others, p)
			}
		}
	}
	return others, nil
}

// writeReadersInputError answers a refused path or pair with 400.
func writeReadersInputError(w http.ResponseWriter, err error) {
	apierror.WriteError(w, apierror.New(apierror.CodeInvalidInput, strings.TrimPrefix(err.Error(), "projectreaders: ")))
}

// writeReadersStoreError reports a failed read or write of the lists: a
// refused pair as the caller's mistake, anything else as the hub's.
func (s *Server) writeReadersStoreError(w http.ResponseWriter, err error) {
	if errors.Is(err, projectreaders.ErrInvalidPath) || errors.Is(err, projectreaders.ErrSelf) ||
		errors.Is(err, projectreaders.ErrFeature) {
		writeReadersInputError(w, err)
		return
	}
	s.log().Warn(logger.EventAuthz, 0, "project readers: store failed",
		map[string]interface{}{"error": err.Error()})
	apierror.WriteError(w, apierror.New(apierror.CodeInternal, "could not read or change the readers list: "+err.Error()))
}
