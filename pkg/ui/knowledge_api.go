package ui

// Knowledge sources REST API (Task 20467): connect an enterprise knowledge
// source, bind it to projects, and search what the projects may read.
//
// The rules live in pkg/knowledge, which every handler here goes through with
// a Principal built from the request's own grant — the decision the route gate
// just made, resting on authz.Enforced like every route's. The gate admits a
// caller to the family (secret.own for the sources, project.read or
// project.write on the project); an operation that also needs knowledge.admin
// — anything done to an organisation source, or to another person's personal
// one — asks authorize for it first, so the claims behind it are fresh and the
// decision lands on the audit trail like the gate's own.
//
// Unsafe requests pass the hub's origin and JSON guards (originguard.go)
// before they get here, read their bodies through decodeJSON, and those that
// create, change or delete a source, or bind one, ask a session for a recent
// sign-in (Sudo). Taking a source off a project does not: it only takes
// access away.

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/apierror"
	"github.com/blechschmidt/cloop/pkg/auditaction"
	"github.com/blechschmidt/cloop/pkg/authz"
	"github.com/blechschmidt/cloop/pkg/knowledge"
	// The connectors this build reads sources with register themselves.
	_ "github.com/blechschmidt/cloop/pkg/knowledge/confluence"
	"github.com/blechschmidt/cloop/pkg/logger"
	"github.com/blechschmidt/cloop/pkg/multiui"
	"github.com/blechschmidt/cloop/pkg/secretbroker"
	"github.com/blechschmidt/cloop/pkg/state"
)

// knowledgeRoutes returns this feature's routes, spliced into the table like
// forwarderRoutes.
func (s *Server) knowledgeRoutes() []routeSpec {
	return []routeSpec{
		{Pattern: "GET /api/knowledge/sources", Handler: s.handleKnowledgeSources, Perm: authz.PermSecretOwn, Scope: scopeGlobal},
		{Pattern: "POST /api/knowledge/sources", Handler: s.handleKnowledgeSourceCreate, Perm: authz.PermSecretOwn, Scope: scopeGlobal, Sudo: sudoWrites},
		{Pattern: "GET /api/knowledge/sources/{id}", Handler: s.handleKnowledgeSource, Perm: authz.PermSecretOwn, Scope: scopeGlobal},
		{Pattern: "PATCH /api/knowledge/sources/{id}", Handler: s.handleKnowledgeSourceUpdate, Perm: authz.PermSecretOwn, Scope: scopeGlobal, Sudo: sudoWrites},
		{Pattern: "DELETE /api/knowledge/sources/{id}", Handler: s.handleKnowledgeSourceDelete, Perm: authz.PermSecretOwn, Scope: scopeGlobal, Sudo: sudoWrites},
		{Pattern: "GET /api/projects/{idx}/knowledge/sources", Handler: s.handleProjectKnowledgeSources, Perm: authz.PermProjectRead, Scope: scopeProjectIdx},
		{Pattern: "POST /api/projects/{idx}/knowledge/bindings", Handler: s.handleProjectKnowledgeBind, Perm: authz.PermProjectWrite, Scope: scopeProjectIdx, Sudo: sudoWrites},
		{Pattern: "DELETE /api/projects/{idx}/knowledge/bindings/{bid}", Handler: s.handleProjectKnowledgeUnbind, Perm: authz.PermProjectWrite, Scope: scopeProjectIdx},
		{Pattern: "GET /api/projects/{idx}/knowledge/search", Handler: s.handleProjectKnowledgeSearch, Perm: authz.PermProjectRead, Scope: scopeProjectIdx},
	}
}

// ── Views ───────────────────────────────────────────────────────────────────

type knowledgeSyncView struct {
	Status  string `json:"status"`
	Error   string `json:"error,omitempty"`
	At      string `json:"at,omitempty"`
	Resumes bool   `json:"resumes"`
}

// knowledgeSourceView is a source as the dashboard shows it. The secret
// reference is shown only to a caller who may manage the source; everyone else
// learns only that one is set.
type knowledgeSourceView struct {
	ID            int64             `json:"id"`
	Kind          string            `json:"kind"`
	Name          string            `json:"name"`
	Scope         string            `json:"scope"`
	Owner         string            `json:"owner,omitempty"`
	Mine          bool              `json:"mine"`
	Manageable    bool              `json:"manageable"`
	Config        json.RawMessage   `json:"config,omitempty"`
	SecretRef     string            `json:"secret_ref,omitempty"`
	HasCredential bool              `json:"has_credential"`
	Enabled       bool              `json:"enabled"`
	Sync          knowledgeSyncView `json:"sync"`
	Documents     int               `json:"documents"`
	Chunks        int               `json:"chunks"`
	Bindings      int               `json:"bindings"`
	CreatedAt     string            `json:"created_at,omitempty"`
	CreatedBy     string            `json:"created_by,omitempty"`
	UpdatedAt     string            `json:"updated_at,omitempty"`
	UpdatedBy     string            `json:"updated_by,omitempty"`
}

type knowledgeBindingView struct {
	ID         int64    `json:"id"`
	SourceID   int64    `json:"source_id"`
	Project    string   `json:"project"`
	Spaces     []string `json:"spaces"`
	Query      string   `json:"query,omitempty"`
	NarrowedAt string   `json:"narrowed_at,omitempty"`
	CreatedAt  string   `json:"created_at,omitempty"`
	CreatedBy  string   `json:"created_by,omitempty"`
	UpdatedAt  string   `json:"updated_at,omitempty"`
}

type knowledgeHitView struct {
	ChunkID    int64              `json:"chunk_id"`
	DocumentID int64              `json:"document_id"`
	Source     knowledgeSourceRef `json:"source"`
	Title      string             `json:"title"`
	URL        string             `json:"url,omitempty"`
	Space      string             `json:"space,omitempty"`
	ExternalID string             `json:"external_id"`
	Heading    string             `json:"heading,omitempty"`
	// Ancestors place the document at its source, outermost first: the
	// pages above a Confluence page, for a citation.
	Ancestors []string `json:"ancestors,omitempty"`
	Snippet   string   `json:"snippet"`
	// Rank is the hit's place, from 1. Its BM25 score is not given out: it is
	// weighed against every project's sources (see knowledge.Access.Search).
	Rank int `json:"rank"`
}

type knowledgeSourceRef struct {
	ID   int64  `json:"id"`
	Name string `json:"name"`
	Kind string `json:"kind"`
}

func knowledgeTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

func knowledgeSourceViewOf(acc *knowledge.Access, src knowledge.Source) knowledgeSourceView {
	manageable := acc.CanManage(src)
	v := knowledgeSourceView{
		ID: src.ID, Kind: src.Kind, Name: src.Name, Scope: src.Scope, Owner: src.Owner,
		Mine:       src.Owner != "" && src.Owner == acc.Principal().Identity,
		Manageable: manageable, Config: src.Config, HasCredential: src.SecretRef != "", Enabled: src.Enabled,
		Sync: knowledgeSyncView{
			Status: src.Sync.Status, Error: src.Sync.Error, At: knowledgeTime(src.Sync.At), Resumes: src.Sync.Resumes,
		},
		Documents: src.Counts.Documents, Chunks: src.Counts.Chunks, Bindings: src.Counts.Bindings,
		CreatedAt: knowledgeTime(src.CreatedAt), CreatedBy: src.CreatedBy,
		UpdatedAt: knowledgeTime(src.UpdatedAt), UpdatedBy: src.UpdatedBy,
	}
	if manageable {
		v.SecretRef = src.SecretRef
	}
	return v
}

func knowledgeBindingViewOf(b knowledge.Binding) knowledgeBindingView {
	spaces := b.Filter.Spaces
	if spaces == nil {
		spaces = []string{}
	}
	return knowledgeBindingView{
		ID: b.ID, SourceID: b.SourceID, Project: b.Project, Spaces: spaces, Query: b.Filter.Query,
		NarrowedAt: knowledgeTime(b.NarrowedAt), CreatedAt: knowledgeTime(b.CreatedAt), CreatedBy: b.CreatedBy,
		UpdatedAt: knowledgeTime(b.UpdatedAt),
	}
}

// ── Plumbing ────────────────────────────────────────────────────────────────

// knowledgeAccess opens the knowledge service over the control plane and binds
// it to the request's caller, as g decides for them. close releases the
// database.
func (s *Server) knowledgeAccess(w http.ResponseWriter, r *http.Request, g *grant, opts ...knowledge.Option) (*knowledge.Access, func(), bool) {
	db, err := s.controlPlaneDB()
	if err != nil {
		s.log().Error(logger.EventAuthz, 0, "knowledge: open control-plane db", map[string]interface{}{"error": err.Error()})
		apierror.WriteError(w, apierror.New(apierror.CodeUnavailable, "the hub's database is not available"))
		return nil, nil, false
	}
	return knowledge.New(db, opts...).For(s.knowledgePrincipal(r, g)), func() { _ = db.Close() }, true
}

// knowledgeAccessWithSecrets is knowledgeAccess with the secret store, which
// creating or changing a source needs to check its secret reference. The
// broker and the knowledge service share one database handle.
func (s *Server) knowledgeAccessWithSecrets(w http.ResponseWriter, r *http.Request, g *grant) (*knowledge.Access, func(), bool) {
	bs, err := s.openBrokers()
	if err != nil {
		s.log().Error(logger.EventAuthz, 0, "knowledge: open control plane", map[string]interface{}{"error": err.Error()})
		apierror.WriteError(w, apierror.New(apierror.CodeUnavailable, "the hub's database is not available"))
		return nil, nil, false
	}
	var opts []knowledge.Option
	if bs.secret != nil {
		opts = append(opts, knowledge.WithCredentials(bs.secret))
	}
	return knowledge.New(bs.db.AsControlPlane(), opts...).For(s.knowledgePrincipal(r, g)), bs.close, true
}

// knowledgePrincipal is the caller as pkg/knowledge sees them: who they are,
// how the audit trail names them, and the grant that decides for them.
func (s *Server) knowledgePrincipal(r *http.Request, g *grant) knowledge.Principal {
	if g == nil {
		g = s.grantFor(r)
	}
	return knowledge.Principal{
		Identity: secretbroker.NormalizeOwner(s.recipientIdentity(r).OwnerKey()),
		Actor:    s.auditActor(r),
		Decide:   g.decide,
	}
}

// knowledgeAdminGrant asks the gate's question for knowledge.admin when an
// operation on src needs it — every organisation source, and another person's
// personal one — so its claims are fresh and its decision audited. It returns
// the grant to act with, or false once it has written the refusal.
func (s *Server) knowledgeAdminGrant(w http.ResponseWriter, r *http.Request, src knowledge.Source) (*grant, bool) {
	identity := secretbroker.NormalizeOwner(s.recipientIdentity(r).OwnerKey())
	if src.Scope == knowledge.ScopePersonal && identity != "" && src.Owner == identity {
		return s.grantFor(r), true
	}
	return s.authorize(w, r, authz.PermKnowledgeAdmin, authz.GlobalScope)
}

// knowledgeID parses a positive id from the path segment name.
func knowledgeID(w http.ResponseWriter, r *http.Request, name string) (int64, bool) {
	id, err := strconv.ParseInt(strings.TrimSpace(r.PathValue(name)), 10, 64)
	if err != nil || id <= 0 {
		apierror.WriteError(w, apierror.New(apierror.CodeInvalidInput, name+" must be a positive number"))
		return 0, false
	}
	return id, true
}

// knowledgeProject is the project an /api/projects/{idx}/… request is about:
// a feature's parent, since a feature reads its project's knowledge.
func (s *Server) knowledgeProject(w http.ResponseWriter, r *http.Request) (knowledge.Project, bool) {
	entry, ok := s.projectAtIdx(w, r)
	if !ok {
		return knowledge.Project{}, false
	}
	scope := s.entryScope(entry)
	return knowledge.Project{Path: scope.ProjectPath, Name: scope.Project}, true
}

// writeKnowledgeError answers a pkg/knowledge error with its status.
func (s *Server) writeKnowledgeError(w http.ResponseWriter, err error, what string) {
	var fe *knowledge.ForbiddenError
	switch {
	case errors.As(err, &fe):
		apierror.WriteError(w, apierror.New(apierror.CodeForbidden, fe.Reason).
			WithDetails(map[string]any{"required_permission": string(fe.Permission)}))
	case errors.Is(err, knowledge.ErrNotFound):
		apierror.WriteError(w, apierror.New(apierror.CodeNotFound, "the requested resource does not exist"))
	case errors.Is(err, knowledge.ErrInvalid):
		apierror.WriteError(w, apierror.New(apierror.CodeInvalidInput, knowledgeMessage(err)))
	case errors.Is(err, knowledge.ErrConflict):
		apierror.WriteError(w, apierror.New(apierror.CodeConflict, knowledgeMessage(err)))
	case errors.Is(err, knowledge.ErrUnavailable):
		apierror.WriteError(w, apierror.New(apierror.CodeUnavailable, knowledgeMessage(err)))
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		apierror.WriteError(w, apierror.New(apierror.CodeUnavailable, "the request ended before "+what+" finished"))
	default:
		s.log().Error(logger.EventAuthz, 0, "knowledge: "+what, map[string]interface{}{"error": err.Error()})
		apierror.WriteError(w, apierror.New(apierror.CodeInternal, "could not "+what))
	}
}

// knowledgeMessage is a pkg/knowledge error's text without the package's
// "knowledge: <kind>:" lead, which says nothing to the person reading it.
func knowledgeMessage(err error) string {
	msg := err.Error()
	for _, lead := range []string{"knowledge: invalid: ", "knowledge: conflict: ", "knowledge: unavailable: "} {
		if strings.HasPrefix(msg, lead) {
			return strings.TrimPrefix(msg, lead)
		}
	}
	return msg
}

// ── Sources ─────────────────────────────────────────────────────────────────

// handleKnowledgeSources serves GET /api/knowledge/sources: the sources the
// caller may see, the connectors this build has, and what the caller may
// create.
func (s *Server) handleKnowledgeSources(w http.ResponseWriter, r *http.Request) {
	acc, done, ok := s.knowledgeAccess(w, r, nil)
	if !ok {
		return
	}
	defer done()
	sources, err := acc.Sources(r.Context())
	if err != nil {
		s.writeKnowledgeError(w, err, "list knowledge sources")
		return
	}
	views := make([]knowledgeSourceView, 0, len(sources))
	for _, src := range sources {
		views = append(views, knowledgeSourceViewOf(acc, src))
	}
	decision := s.grantFor(r).decide(authz.GlobalScope)
	jsonOK(w, map[string]any{
		"sources":             views,
		"connectors":          knowledge.DefaultRegistry().Kinds(),
		"can_create_org":      decision.Allows(authz.PermKnowledgeAdmin),
		"can_create_personal": decision.Allows(authz.PermSecretOwn) && acc.Principal().Identity != "",
	})
}

// handleKnowledgeSource serves GET /api/knowledge/sources/{id}: one source,
// and to a caller who may manage it, its bindings.
func (s *Server) handleKnowledgeSource(w http.ResponseWriter, r *http.Request) {
	id, ok := knowledgeID(w, r, "id")
	if !ok {
		return
	}
	acc, done, ok := s.knowledgeAccess(w, r, nil)
	if !ok {
		return
	}
	defer done()
	src, bindings, err := acc.Source(r.Context(), id)
	if err != nil {
		s.writeKnowledgeError(w, err, "read the knowledge source")
		return
	}
	resp := map[string]any{"source": knowledgeSourceViewOf(acc, src)}
	if bindings != nil {
		views := make([]knowledgeBindingView, 0, len(bindings))
		for _, b := range bindings {
			views = append(views, knowledgeBindingViewOf(b))
		}
		resp["bindings"] = views
	}
	jsonOK(w, resp)
}

// knowledgeSourceRequest is the body of POST and PATCH /api/knowledge/sources.
// PATCH applies the fields present; kind and scope are fixed at creation.
type knowledgeSourceRequest struct {
	Kind      string          `json:"kind"`
	Name      *string         `json:"name"`
	Scope     string          `json:"scope"`
	Config    json.RawMessage `json:"config"`
	SecretRef *string         `json:"secret_ref"`
	Enabled   *bool           `json:"enabled"`
}

// handleKnowledgeSourceCreate serves POST /api/knowledge/sources.
func (s *Server) handleKnowledgeSourceCreate(w http.ResponseWriter, r *http.Request) {
	var req knowledgeSourceRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	g := s.grantFor(r)
	if strings.TrimSpace(req.Scope) == knowledge.ScopeOrg {
		var ok bool
		if g, ok = s.authorize(w, r, authz.PermKnowledgeAdmin, authz.GlobalScope); !ok {
			return
		}
	}
	acc, done, ok := s.knowledgeAccessWithSecrets(w, r, g)
	if !ok {
		return
	}
	defer done()
	in := knowledge.SourceInput{Kind: req.Kind, Scope: req.Scope, Config: req.Config, Enabled: req.Enabled}
	if req.Name != nil {
		in.Name = *req.Name
	}
	if req.SecretRef != nil {
		in.SecretRef = *req.SecretRef
	}
	src, err := acc.CreateSource(r.Context(), in)
	if err != nil {
		s.writeKnowledgeError(w, err, "create the knowledge source")
		return
	}
	s.broadcastAuditAppend(string(auditaction.ActionKnowledgeSourceCreate))
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(map[string]any{"source": knowledgeSourceViewOf(acc, src)})
}

// handleKnowledgeSourceUpdate serves PATCH /api/knowledge/sources/{id}.
func (s *Server) handleKnowledgeSourceUpdate(w http.ResponseWriter, r *http.Request) {
	id, ok := knowledgeID(w, r, "id")
	if !ok {
		return
	}
	var req knowledgeSourceRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if req.Kind != "" || req.Scope != "" {
		apierror.WriteError(w, apierror.New(apierror.CodeInvalidInput,
			"a source's kind and scope are fixed when it is created; connect a new source instead"))
		return
	}
	acc, done, ok := s.knowledgeAccess(w, r, nil)
	if !ok {
		return
	}
	src, _, err := acc.Source(r.Context(), id)
	done()
	if err != nil {
		s.writeKnowledgeError(w, err, "change the knowledge source")
		return
	}
	g, ok := s.knowledgeAdminGrant(w, r, src)
	if !ok {
		return
	}
	acc, done, ok = s.knowledgeAccessWithSecrets(w, r, g)
	if !ok {
		return
	}
	defer done()
	updated, err := acc.UpdateSource(r.Context(), id, knowledge.SourceUpdate{
		Name: req.Name, Config: req.Config, SecretRef: req.SecretRef, Enabled: req.Enabled,
	})
	if err != nil {
		s.writeKnowledgeError(w, err, "change the knowledge source")
		return
	}
	s.broadcastAuditAppend(string(auditaction.ActionKnowledgeSourceUpdate))
	jsonOK(w, map[string]any{"source": knowledgeSourceViewOf(acc, updated)})
}

// handleKnowledgeSourceDelete serves DELETE /api/knowledge/sources/{id}.
func (s *Server) handleKnowledgeSourceDelete(w http.ResponseWriter, r *http.Request) {
	id, ok := knowledgeID(w, r, "id")
	if !ok {
		return
	}
	acc, done, ok := s.knowledgeAccess(w, r, nil)
	if !ok {
		return
	}
	defer done()
	src, _, err := acc.Source(r.Context(), id)
	if err != nil {
		s.writeKnowledgeError(w, err, "delete the knowledge source")
		return
	}
	g, ok := s.knowledgeAdminGrant(w, r, src)
	if !ok {
		return
	}
	deleted, counts, err := s.knowledgeWith(acc, r, g).DeleteSource(r.Context(), id)
	if err != nil {
		s.writeKnowledgeError(w, err, "delete the knowledge source")
		return
	}
	s.broadcastAuditAppend(string(auditaction.ActionKnowledgeSourceDelete))
	jsonOK(w, map[string]any{
		"deleted": knowledgeSourceRef{ID: deleted.ID, Name: deleted.Name, Kind: deleted.Kind},
		"removed": map[string]int{"documents": counts.Documents, "chunks": counts.Chunks, "bindings": counts.Bindings},
	})
}

// knowledgeWith is acc acting with grant g instead — the fresh one an
// administrator's operation was authorized with.
func (s *Server) knowledgeWith(acc *knowledge.Access, r *http.Request, g *grant) *knowledge.Access {
	return acc.Service().For(s.knowledgePrincipal(r, g))
}

// ── Projects ────────────────────────────────────────────────────────────────

type knowledgeBoundView struct {
	Binding knowledgeBindingView `json:"binding"`
	Source  knowledgeSourceView  `json:"source"`
}

// handleProjectKnowledgeSources serves GET /api/projects/{idx}/knowledge/sources:
// the sources the project can search, without their configuration or secret
// references.
func (s *Server) handleProjectKnowledgeSources(w http.ResponseWriter, r *http.Request) {
	project, ok := s.knowledgeProject(w, r)
	if !ok {
		return
	}
	acc, done, ok := s.knowledgeAccess(w, r, nil)
	if !ok {
		return
	}
	defer done()
	bound, err := acc.ProjectSources(r.Context(), project)
	if err != nil {
		s.writeKnowledgeError(w, err, "list the project's knowledge sources")
		return
	}
	views := make([]knowledgeBoundView, 0, len(bound))
	for _, b := range bound {
		v := knowledgeSourceViewOf(acc, b.Source)
		v.Config, v.SecretRef = nil, ""
		views = append(views, knowledgeBoundView{Binding: knowledgeBindingViewOf(b.Binding), Source: v})
	}
	jsonOK(w, map[string]any{"project": project.Path, "sources": views})
}

// dropProjectKnowledge takes a project's knowledge bindings with it when it
// leaves the hub. Fatal to the removal, like its roster: a failure leaves the
// project listed with its bindings rather than unlisted with them waiting at
// its path. A hub with no control-plane database yet has none to remove.
func (s *Server) dropProjectKnowledge(r *http.Request, entry multiui.ProjectEntry) error {
	if _, err := os.Stat(state.DBPath(s.WorkDir)); err != nil {
		return nil
	}
	db, err := s.controlPlaneDB()
	if err != nil {
		return err
	}
	defer db.Close()
	scope := s.entryScope(entry)
	n, err := knowledge.New(db).For(s.knowledgePrincipal(r, nil)).ForgetProject(r.Context(),
		knowledge.Project{Path: scope.ProjectPath, Name: scope.Project})
	if err != nil {
		return err
	}
	if n > 0 {
		s.broadcastAuditAppend(string(auditaction.ActionKnowledgeSourceUnbind))
	}
	return nil
}

// knowledgeBindRequest is the body of POST /api/projects/{idx}/knowledge/bindings.
type knowledgeBindRequest struct {
	SourceID int64    `json:"source_id"`
	Spaces   []string `json:"spaces"`
	Query    string   `json:"query"`
}

// handleProjectKnowledgeBind serves POST /api/projects/{idx}/knowledge/bindings:
// make a source searchable from the project, or change its binding's
// narrowing.
func (s *Server) handleProjectKnowledgeBind(w http.ResponseWriter, r *http.Request) {
	project, ok := s.knowledgeProject(w, r)
	if !ok {
		return
	}
	var req knowledgeBindRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if req.SourceID <= 0 {
		apierror.WriteError(w, apierror.New(apierror.CodeInvalidInput, "source_id must name a knowledge source"))
		return
	}
	acc, done, ok := s.knowledgeAccess(w, r, nil)
	if !ok {
		return
	}
	defer done()
	// Whether the source can be seen at all is the source's own question,
	// asked before the administrator's: a person's source is not found by
	// anyone else, whatever their role.
	src, _, err := acc.Source(r.Context(), req.SourceID)
	if err != nil {
		s.writeKnowledgeError(w, err, "bind the knowledge source")
		return
	}
	g, ok := s.knowledgeAdminGrant(w, r, src)
	if !ok {
		return
	}
	b, created, err := s.knowledgeWith(acc, r, g).Bind(r.Context(), project, req.SourceID,
		knowledge.Filter{Spaces: req.Spaces, Query: req.Query})
	if err != nil {
		s.writeKnowledgeError(w, err, "bind the knowledge source")
		return
	}
	s.broadcastAuditAppend(string(auditaction.ActionKnowledgeSourceBind))
	status := http.StatusOK
	if created {
		status = http.StatusCreated
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"binding": knowledgeBindingViewOf(b), "created": created})
}

// handleProjectKnowledgeUnbind serves
// DELETE /api/projects/{idx}/knowledge/bindings/{bid}.
func (s *Server) handleProjectKnowledgeUnbind(w http.ResponseWriter, r *http.Request) {
	project, ok := s.knowledgeProject(w, r)
	if !ok {
		return
	}
	id, ok := knowledgeID(w, r, "bid")
	if !ok {
		return
	}
	acc, done, ok := s.knowledgeAccess(w, r, nil)
	if !ok {
		return
	}
	defer done()
	b, err := acc.Unbind(r.Context(), project, id)
	if err != nil {
		s.writeKnowledgeError(w, err, "unbind the knowledge source")
		return
	}
	s.broadcastAuditAppend(string(auditaction.ActionKnowledgeSourceUnbind))
	jsonOK(w, map[string]any{"binding": knowledgeBindingViewOf(b)})
}

// handleProjectKnowledgeSearch serves
// GET /api/projects/{idx}/knowledge/search?q=…&k=…: the k best chunks of the
// project's knowledge for q, best first.
func (s *Server) handleProjectKnowledgeSearch(w http.ResponseWriter, r *http.Request) {
	project, ok := s.knowledgeProject(w, r)
	if !ok {
		return
	}
	q := r.URL.Query()
	k := 0
	if raw := strings.TrimSpace(q.Get("k")); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 1 {
			apierror.WriteError(w, apierror.New(apierror.CodeInvalidInput, "k must be a positive number"))
			return
		}
		k = n
	}
	acc, done, ok := s.knowledgeAccess(w, r, nil)
	if !ok {
		return
	}
	defer done()
	hits, err := acc.Search(r.Context(), project, q.Get("q"), k)
	if err != nil {
		s.writeKnowledgeError(w, err, "search the project's knowledge")
		return
	}
	views := make([]knowledgeHitView, 0, len(hits))
	for _, h := range hits {
		views = append(views, knowledgeHitView{
			ChunkID: h.ChunkID, DocumentID: h.DocumentID,
			Source: knowledgeSourceRef{ID: h.Source.ID, Name: h.Source.Name, Kind: h.Source.Kind},
			Title:  h.Title, URL: h.URL, Space: h.Space, ExternalID: h.ExternalID, Heading: h.Heading,
			Ancestors: h.Ancestors, Snippet: h.Snippet, Rank: h.Rank,
		})
	}
	jsonOK(w, map[string]any{"query": q.Get("q"), "hits": views})
}
