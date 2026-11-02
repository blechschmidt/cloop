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
	_ "github.com/blechschmidt/cloop/pkg/knowledge/jira"
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
		{Pattern: "POST /api/knowledge/sources/{id}/sync", Handler: s.handleKnowledgeSourceSync, Perm: authz.PermSecretOwn, Scope: scopeGlobal},
		{Pattern: "GET /api/projects/{idx}/knowledge/sources", Handler: s.handleProjectKnowledgeSources, Perm: authz.PermProjectRead, Scope: scopeProjectIdx},
		{Pattern: "POST /api/projects/{idx}/knowledge/bindings", Handler: s.handleProjectKnowledgeBind, Perm: authz.PermProjectWrite, Scope: scopeProjectIdx, Sudo: sudoWrites},
		{Pattern: "DELETE /api/projects/{idx}/knowledge/bindings/{bid}", Handler: s.handleProjectKnowledgeUnbind, Perm: authz.PermProjectWrite, Scope: scopeProjectIdx},
		{Pattern: "GET /api/projects/{idx}/knowledge/search", Handler: s.handleProjectKnowledgeSearch, Perm: authz.PermProjectRead, Scope: scopeProjectIdx},
	}
}

// ── Views ───────────────────────────────────────────────────────────────────

// knowledgeSyncView is how a source's syncs are going: the last one, the one
// running, and the next.
type knowledgeSyncView struct {
	// Status is "" (never synced), ok, error or interrupted; Error the last
	// sync's error, scrubbed of credentials; At when it ended.
	Status  string `json:"status"`
	Error   string `json:"error,omitempty"`
	At      string `json:"at,omitempty"`
	Resumes bool   `json:"resumes"`
	// IntervalMinutes is how often the hub syncs the source; DefaultInterval
	// says the source takes the hub's default rather than setting its own.
	IntervalMinutes int  `json:"interval_minutes"`
	DefaultInterval bool `json:"default_interval"`
	// StartedAt, DurationMS, Origin and Counts describe the last sync, and
	// More says it stopped before its listing's end.
	StartedAt  string                `json:"started_at,omitempty"`
	DurationMS int64                 `json:"duration_ms,omitempty"`
	Origin     string                `json:"origin,omitempty"`
	Counts     *knowledge.SyncCounts `json:"counts,omitempty"`
	More       bool                  `json:"more,omitempty"`
	LastOKAt   string                `json:"last_ok_at,omitempty"`
	// NextAt is when the schedule next syncs the source; absent for a
	// disabled one.
	NextAt  string                `json:"next_at,omitempty"`
	Running *knowledgeRunningView `json:"running,omitempty"`
	// Warning is what went wrong in the last sync without failing it — the
	// embedding endpoint down, say — scrubbed of credentials.
	Warning string `json:"warning,omitempty"`
}

// knowledgeRunningView is a sync in progress.
type knowledgeRunningView struct {
	// Member is the hub process running it.
	Member string `json:"member"`
	Origin string `json:"origin"`
	// Actor is who asked for a manual sync, shown to whoever may manage the
	// source.
	Actor string `json:"actor,omitempty"`
	Since string `json:"since"`
}

func knowledgeRunningViewOf(r *knowledge.RunningSync, withActor bool) *knowledgeRunningView {
	if r == nil {
		return nil
	}
	v := &knowledgeRunningView{Member: r.Member, Origin: r.Origin, Since: knowledgeTime(r.Since)}
	if withActor {
		v.Actor = r.Actor
	}
	return v
}

func knowledgeSyncViewOf(src knowledge.Source, manageable bool) knowledgeSyncView {
	st := src.Sync
	v := knowledgeSyncView{
		Status: st.Status, Error: st.Error, At: knowledgeTime(st.At), Resumes: st.Resumes,
		IntervalMinutes: int(src.Interval() / time.Minute), DefaultInterval: src.SyncInterval == 0,
		StartedAt: knowledgeTime(st.StartedAt), DurationMS: st.Duration.Milliseconds(), Origin: st.Origin,
		More: st.More, LastOKAt: knowledgeTime(st.OKAt), NextAt: knowledgeTime(st.NextAt),
		Running: knowledgeRunningViewOf(st.Running, manageable), Warning: st.Warning,
	}
	if !st.StartedAt.IsZero() {
		counts := st.Counts
		v.Counts = &counts
	}
	return v
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
	// Vectors counts the chunks with a vector of the hub's embedding model;
	// 0 while knowledge.embeddings is off.
	Vectors   int    `json:"vectors"`
	CreatedAt string `json:"created_at,omitempty"`
	CreatedBy string `json:"created_by,omitempty"`
	UpdatedAt string `json:"updated_at,omitempty"`
	UpdatedBy string `json:"updated_by,omitempty"`
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
	// weighed against every project's sources (see knowledge.Access.Retrieve).
	Rank int `json:"rank"`
	// FoundBy says what found the hit: "lexical" (its words), "semantic"
	// (its meaning), or both.
	FoundBy []string `json:"found_by"`
}

// knowledgeRetrievalView is how a search ranked.
type knowledgeRetrievalView struct {
	// Mode is "hybrid" — the words' ranking fused with the vectors' — or
	// "lexical", by words alone.
	Mode string `json:"mode"`
	// Model is the embedding model whose vectors were compared, or would
	// have been.
	Model string `json:"model,omitempty"`
	// Candidates counts the vectors the query was compared with; Capped
	// says the project's sources hold more than one search compares.
	Candidates int  `json:"candidates,omitempty"`
	Capped     bool `json:"capped,omitempty"`
	// Warning says why a search that would have been hybrid ranked by
	// words alone.
	Warning string `json:"warning,omitempty"`
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
		Sync:      knowledgeSyncViewOf(src, manageable),
		Documents: src.Counts.Documents, Chunks: src.Counts.Chunks, Bindings: src.Counts.Bindings,
		Vectors:   src.Counts.Vectors,
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
	opts = append([]knowledge.Option{knowledge.WithEmbeddings(s.knowledgeEmbeddings())}, opts...)
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
	opts := []knowledge.Option{knowledge.WithEmbeddings(s.knowledgeEmbeddings())}
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
	case errors.Is(err, knowledge.ErrDisabled):
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
	for _, lead := range []string{"knowledge: invalid: ", "knowledge: conflict: ", "knowledge: unavailable: ",
		"knowledge: "} {
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
		"embeddings":          knowledgeEmbeddingsViewOf(acc.Service().Embeddings(), decision.Allows(authz.PermKnowledgeAdmin)),
	})
}

// knowledgeEmbeddingsView is the hub's semantic retrieval, as the sources
// listing shows it: whether it is on, with which model, and — to an
// administrator, who configures it — where chunk text is sent.
type knowledgeEmbeddingsView struct {
	Enabled  bool   `json:"enabled"`
	Model    string `json:"model,omitempty"`
	Endpoint string `json:"endpoint,omitempty"`
	// Broken says why a section an administrator turned on is not used.
	Broken string `json:"broken,omitempty"`
}

func knowledgeEmbeddingsViewOf(e knowledge.Embeddings, admin bool) knowledgeEmbeddingsView {
	v := knowledgeEmbeddingsView{Enabled: e.Model() != "", Model: e.Model()}
	if admin {
		v.Broken = e.Broken
		if e.Embedder != nil && v.Enabled {
			v.Endpoint = e.Embedder.Endpoint()
		}
	}
	return v
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
	// SyncIntervalMinutes is how often the hub syncs the source: 5 to 1440,
	// or 0 for the hub's default (30).
	SyncIntervalMinutes *int `json:"sync_interval_minutes"`
}

// syncInterval is the request's interval, or nil when it names none. A value
// beyond any interval's bounds is passed on as one, for pkg/knowledge to
// refuse with its bounds.
func (req knowledgeSourceRequest) syncInterval() *time.Duration {
	if req.SyncIntervalMinutes == nil {
		return nil
	}
	m := *req.SyncIntervalMinutes
	if m > int(knowledge.MaxSyncInterval/time.Minute)*2 || m < -1 {
		m = -1
	}
	d := time.Duration(m) * time.Minute
	return &d
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
	if d := req.syncInterval(); d != nil {
		in.SyncInterval = *d
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
		SyncInterval: req.syncInterval(),
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
	res, err := acc.Retrieve(r.Context(), project, q.Get("q"), k)
	if err != nil {
		s.writeKnowledgeError(w, err, "search the project's knowledge")
		return
	}
	views := make([]knowledgeHitView, 0, len(res.Hits))
	for _, h := range res.Hits {
		foundBy := []string{}
		if h.Lexical {
			foundBy = append(foundBy, knowledge.RetrievalLexical)
		}
		if h.Semantic {
			foundBy = append(foundBy, "semantic")
		}
		views = append(views, knowledgeHitView{
			ChunkID: h.ChunkID, DocumentID: h.DocumentID,
			Source: knowledgeSourceRef{ID: h.Source.ID, Name: h.Source.Name, Kind: h.Source.Kind},
			Title:  h.Title, URL: h.URL, Space: h.Space, ExternalID: h.ExternalID, Heading: h.Heading,
			Ancestors: h.Ancestors, Snippet: h.Snippet, Rank: h.Rank, FoundBy: foundBy,
		})
	}
	rt := res.Retrieval
	jsonOK(w, map[string]any{"query": q.Get("q"), "hits": views, "retrieval": knowledgeRetrievalView{
		Mode: rt.Mode, Model: rt.Model, Candidates: rt.Candidates, Capped: rt.Capped, Warning: rt.Warning,
	}})
}
