package ui

// knowledge_run_api.go: the run-scoped knowledge search (Task 20472).
//
//	POST /api/run/knowledge/search     {"query", "k", "task", "purpose"}
//	POST /api/run/knowledge/get        {"document_id"|"url"|"key", "max_bytes", "task", "purpose"}
//	POST /api/run/knowledge/citations  {"task"}
//
// A run calls these with its knowledge session token (knowledge_run.go) and
// nothing else: it holds no hub session and no API token, by design, so the
// routes are served before the hub's authentication and authenticate the
// token themselves, as the model relay does. A token is good only while its
// session is open and unexpired — the run is live — and only for the project
// the session names: everything is read through pkg/knowledge as
// knowledge.RunPrincipal, viewer of that project and of nothing else, so a
// search joins through that project's bindings and narrowing exactly as a
// person's does, and another project's document is not found.
//
// Each session is held to a rate (runKnowledgeRate, burst runKnowledgeBurst),
// each answer to a size (knowledgerun's bounds), and every query is on the
// audit trail with the run, the task and the documents it was answered with.
// What leaves the hub is the index's text passed once more through
// pkg/redact: a credential pasted into a wiki page, which the index scrubbed
// when it was synced, is scrubbed again with whatever patterns this build
// knows, before a sandbox sees it. The credentials the hub reads the sources
// with are never part of any of it.

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/blechschmidt/cloop/pkg/apierror"
	"github.com/blechschmidt/cloop/pkg/auditaction"
	"github.com/blechschmidt/cloop/pkg/authz"
	"github.com/blechschmidt/cloop/pkg/jsonbody"
	"github.com/blechschmidt/cloop/pkg/knowledge"
	"github.com/blechschmidt/cloop/pkg/knowledgerun"
	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/redact"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// knowledgeRunRoutes are the run-scoped search's routes, public to the route
// gate because the handlers authenticate the run's token.
func (s *Server) knowledgeRunRoutes() []routeSpec {
	mount := knowledgerun.MountPath
	return []routeSpec{
		{Pattern: "POST " + mount + knowledgerun.PathSearch, Handler: s.handleRunKnowledgeSearch, Perm: authz.PermPublic, Scope: scopeGlobal},
		{Pattern: "POST " + mount + knowledgerun.PathGet, Handler: s.handleRunKnowledgeGet, Perm: authz.PermPublic, Scope: scopeGlobal},
		{Pattern: "POST " + mount + knowledgerun.PathCitations, Handler: s.handleRunKnowledgeCitations, Perm: authz.PermPublic, Scope: scopeGlobal},
	}
}

// isKnowledgeRunEndpoint reports whether a request is for the run-scoped
// knowledge search, which authenticates a run's knowledge session token the
// hub's middleware cannot check: the run holds no hub session by design.
func isKnowledgeRunEndpoint(r *http.Request) bool {
	return r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, knowledgerun.MountPath+"/")
}

// Each knowledge session's rate: what a run's orchestrator spends assembling
// a task's reference material — a search and a few lookups — fits the burst,
// and an agent searching as it works gets one request a second.
var (
	runKnowledgeRate  = 1.0
	runKnowledgeBurst = 30.0
)

// runKnowledgeBucket is one session's token bucket.
type runKnowledgeBucket struct {
	tokens float64
	last   time.Time
}

// runKnowledgeLimiter holds every session's bucket in this process. A cluster
// member holds its own, so a run whose requests land on several members gets
// a share of the rate at each.
var runKnowledgeLimiter = struct {
	mu      sync.Mutex
	buckets map[string]*runKnowledgeBucket
}{buckets: map[string]*runKnowledgeBucket{}}

// allowRunKnowledge takes a request from session id's bucket.
func allowRunKnowledge(id string, now time.Time) bool {
	runKnowledgeLimiter.mu.Lock()
	defer runKnowledgeLimiter.mu.Unlock()
	if len(runKnowledgeLimiter.buckets) > 4096 {
		// Forget buckets nobody drew from for a while: a full one is what
		// a session without a bucket gets anyway.
		for k, b := range runKnowledgeLimiter.buckets {
			if now.Sub(b.last) > time.Minute {
				delete(runKnowledgeLimiter.buckets, k)
			}
		}
	}
	b := runKnowledgeLimiter.buckets[id]
	if b == nil {
		b = &runKnowledgeBucket{tokens: runKnowledgeBurst, last: now}
		runKnowledgeLimiter.buckets[id] = b
	}
	b.tokens = min(runKnowledgeBurst, b.tokens+now.Sub(b.last).Seconds()*runKnowledgeRate)
	b.last = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// runKnowledgeCall is one authenticated request: the session it presented,
// the project that session reads, and the control plane it is answered from.
type runKnowledgeCall struct {
	s       *Server
	db      *statedb.DB
	row     statedb.ProxySessionRow
	project knowledge.Project
	access  *knowledge.Access
}

// errRunKnowledgeToken is the one answer for every token that does not open
// a live session: malformed, unknown, wrong, ended or lapsed alike, so the
// answer says nothing about which sessions exist.
const errRunKnowledgeToken = "a live run's knowledge session token is required: this one is not valid, or its run has ended"

// openRunKnowledgeCall authenticates r's knowledge session token and opens
// what answering it needs. It writes the refusal and returns false when the
// token does not open a live session.
func (s *Server) openRunKnowledgeCall(w http.ResponseWriter, r *http.Request) (*runKnowledgeCall, bool) {
	token := runBearer(r)
	id, ok := knowledgeTokenID(token)
	if !ok {
		writeRunKnowledgeUnauthorized(w)
		return nil, false
	}
	db, err := s.controlPlaneDB()
	if err != nil {
		apierror.WriteError(w, apierror.New(apierror.CodeUnavailable, "the hub's database is not available"))
		return nil, false
	}
	row, err := db.GetProxySession(statedb.ProxySessionKnowledge, id)
	if err != nil {
		_ = db.Close()
		if errors.Is(err, statedb.ErrProxySessionNotFound) {
			writeRunKnowledgeUnauthorized(w)
			return nil, false
		}
		apierror.WriteError(w, apierror.New(apierror.CodeUnavailable, "the hub's database is not available"))
		return nil, false
	}
	presented := tokenSHA256(token)
	if subtle.ConstantTimeCompare([]byte(presented), []byte(row.TokenSHA256)) != 1 ||
		!row.Open() || !time.Now().Before(row.ExpiresAt) || strings.TrimSpace(row.ProjectID) == "" {
		_ = db.Close()
		writeRunKnowledgeUnauthorized(w)
		return nil, false
	}
	project := knowledge.Project{Path: row.ProjectID, Name: s.projectNameForPath(row.ProjectID)}
	svc := knowledge.New(db, knowledge.WithEmbeddings(s.knowledgeEmbeddings()))
	return &runKnowledgeCall{
		s: s, db: db, row: row, project: project,
		access: svc.For(knowledge.RunPrincipal(project, runKnowledgeActor(row))),
	}, true
}

// close releases the call's database.
func (c *runKnowledgeCall) close() { _ = c.db.Close() }

// runBearer is the bearer token r presents, or "".
func runBearer(r *http.Request) string {
	h := strings.TrimSpace(r.Header.Get("Authorization"))
	if len(h) < 7 || !strings.EqualFold(h[:7], "bearer ") {
		return ""
	}
	return strings.TrimSpace(h[7:])
}

func writeRunKnowledgeUnauthorized(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
	apierror.WriteError(w, apierror.New(apierror.CodeUnauthorized, errRunKnowledgeToken))
}

// runKnowledgeActor names a run in the audit trail: whom it acts for, else
// the run.
func runKnowledgeActor(row statedb.ProxySessionRow) string {
	if a := strings.TrimSpace(row.Actor); a != "" {
		return a
	}
	if row.RunID != "" {
		return "run " + row.RunID
	}
	return "run"
}

// decode reads the request's JSON body, bounded.
func (c *runKnowledgeCall) decode(w http.ResponseWriter, r *http.Request, dst any) bool {
	return jsonbody.Decode(w, r, dst, jsonbody.Options{Limit: knowledgerun.MaxRequestBytes})
}

// allow takes the request from the session's rate, and refuses it — 429, on
// the audit trail — when the session has spent it.
func (c *runKnowledgeCall) allow(w http.ResponseWriter, action auditaction.Action, fields map[string]any) bool {
	if allowRunKnowledge(c.row.SessionID, time.Now()) {
		return true
	}
	c.audit(action, "refused", "the session's rate limit", fields)
	w.Header().Set("Retry-After", "2")
	apierror.WriteError(w, apierror.New(apierror.CodeRateLimited,
		fmt.Sprintf("this run's knowledge session asks too often: at most %.0f requests a second, in bursts of %.0f",
			runKnowledgeRate, runKnowledgeBurst)))
	return false
}

// audit writes one row of the session's on the control plane's trail.
func (c *runKnowledgeCall) audit(action auditaction.Action, outcome, reason string, fields map[string]any) {
	payload := map[string]any{
		"session_id": c.row.SessionID, "run_id": c.row.RunID, "project": c.project.Path,
		"executor_id": c.row.ExecutorID, "outcome": outcome,
	}
	if reason != "" {
		payload["reason"] = reason
	}
	for k, v := range fields {
		payload[k] = v
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		raw = []byte(`{}`)
	}
	if err := c.db.AppendAuditEvent(&statedb.AuditEvent{
		Timestamp: time.Now().UTC(), Actor: runKnowledgeActor(c.row), EventType: string(action),
		EntityType: "knowledge_session", EntityID: c.row.SessionID, Payload: string(raw),
	}); err != nil {
		c.s.log().Warn("knowledge", 0, "could not audit a run's knowledge request",
			map[string]interface{}{"session": c.row.SessionID, "error": err.Error()})
		return
	}
	c.s.broadcastAuditAppend(string(action))
}

// recordReads records documents the run's agent was served for task, for the
// task's citations — not what the orchestrator asked for its prompt, which it
// cites itself.
func (c *runKnowledgeCall) recordReads(task int, purpose string, ids []int64) {
	if purpose == knowledgerun.PurposeInject || len(ids) == 0 {
		return
	}
	if err := c.db.RecordKnowledgeRunReads(c.row.SessionID, task, ids, time.Now()); err != nil {
		c.s.log().Warn("knowledge", 0, "could not record a run's knowledge reads",
			map[string]interface{}{"session": c.row.SessionID, "error": err.Error()})
	}
}

// fail answers a pkg/knowledge error for a run, and audits the refusal.
func (c *runKnowledgeCall) fail(w http.ResponseWriter, action auditaction.Action, err error, fields map[string]any) {
	reason := knowledgeMessage(err)
	switch {
	case errors.Is(err, knowledge.ErrInvalid):
		c.audit(action, "refused", reason, fields)
	case errors.Is(err, knowledge.ErrNotFound):
		reason = "the project is not this run's"
		c.audit(action, "refused", reason, fields)
	default:
		msg, _ := clipText(redact.Scrub(err.Error()), 512)
		c.audit(action, "error", msg, fields)
	}
	c.s.writeKnowledgeError(w, err, "search the project's knowledge")
}

// scrubText is text as it may leave the hub for a run.
func scrubText(s string) string { return redact.Scrub(s) }

// clipText cuts s to n bytes on a rune boundary, and reports whether it did.
func clipText(s string, n int) (string, bool) {
	if len(s) <= n {
		return s, false
	}
	return strings.ToValidUTF8(s[:n], ""), true
}

// auditQuery is a query as the trail keeps it.
func auditQuery(q string) string {
	q, _ = clipText(redact.Scrub(strings.TrimSpace(q)), 512)
	return q
}

// handleRunKnowledgeSearch serves POST /api/run/knowledge/search: the
// passages of the run's project's knowledge that best match the query, best
// first, each with its text.
func (s *Server) handleRunKnowledgeSearch(w http.ResponseWriter, r *http.Request) {
	call, ok := s.openRunKnowledgeCall(w, r)
	if !ok {
		return
	}
	defer call.close()
	var req knowledgerun.SearchRequest
	if !call.decode(w, r, &req) {
		return
	}
	fields := map[string]any{"task": max(req.Task, 0), "purpose": req.Purpose, "query": auditQuery(req.Query)}
	action := auditaction.ActionKnowledgeRunSearch
	if !call.allow(w, action, fields) {
		return
	}
	k := req.K
	switch {
	case k < 0:
		call.audit(action, "refused", "k is negative", fields)
		apierror.WriteError(w, apierror.New(apierror.CodeInvalidInput, "k must be a positive number"))
		return
	case k == 0:
		k = knowledgerun.DefaultK
	}
	k = min(k, knowledgerun.MaxK)
	fields["k"] = k
	res, err := call.access.Retrieve(r.Context(), call.project, req.Query, k)
	if err != nil {
		call.fail(w, action, err, fields)
		return
	}
	ids := make([]int64, 0, len(res.Hits))
	for _, h := range res.Hits {
		ids = append(ids, h.ChunkID)
	}
	passages, err := call.access.Passages(r.Context(), call.project, ids)
	if err != nil {
		call.fail(w, action, err, fields)
		return
	}
	out := knowledgerun.SearchResponse{Hits: []knowledgerun.Hit{},
		Retrieval: knowledgerun.Retrieval{Mode: res.Retrieval.Mode, Warning: res.Retrieval.Warning}}
	budget := knowledgerun.MaxResponseBytes / 2
	var docs []int64
	seen := map[int64]bool{}
	for _, h := range res.Hits {
		p, ok := passages[h.ChunkID]
		if !ok {
			// Its binding went since the search found it.
			continue
		}
		text, cut := clipText(scrubText(p.Text), min(knowledgerun.MaxHitTextBytes, budget))
		if text == "" && budget <= 0 {
			break
		}
		budget -= len(text)
		out.Hits = append(out.Hits, knowledgerun.Hit{
			DocumentID: h.DocumentID, ChunkID: h.ChunkID, Title: scrubText(h.Title), URL: h.URL,
			Source: knowledgerun.SourceRef{ID: h.Source.ID, Name: h.Source.Name, Kind: h.Source.Kind},
			Space:  h.Space, Heading: scrubText(h.Heading), Ancestors: scrubAll(h.Ancestors), Text: text,
			Truncated: cut, Rank: len(out.Hits) + 1,
		})
		if !seen[h.DocumentID] {
			seen[h.DocumentID] = true
			docs = append(docs, h.DocumentID)
		}
	}
	fields["hits"], fields["documents"], fields["mode"] = len(out.Hits), docs, out.Retrieval.Mode
	call.recordReads(req.Task, req.Purpose, docs)
	call.audit(action, "ok", "", fields)
	jsonOK(w, out)
}

// handleRunKnowledgeGet serves POST /api/run/knowledge/get: one document of
// the run's project's knowledge, by its id, URL or issue key.
func (s *Server) handleRunKnowledgeGet(w http.ResponseWriter, r *http.Request) {
	call, ok := s.openRunKnowledgeCall(w, r)
	if !ok {
		return
	}
	defer call.close()
	var req knowledgerun.GetRequest
	if !call.decode(w, r, &req) {
		return
	}
	lookup := map[string]any{}
	switch {
	case req.DocumentID != 0:
		lookup["id"] = req.DocumentID
	case strings.TrimSpace(req.URL) != "":
		lookup["url"] = auditQuery(req.URL)
	case strings.TrimSpace(req.Key) != "":
		lookup["key"] = auditQuery(req.Key)
	}
	fields := map[string]any{"task": max(req.Task, 0), "purpose": req.Purpose, "lookup": lookup}
	action := auditaction.ActionKnowledgeRunGet
	if !call.allow(w, action, fields) {
		return
	}
	maxBytes := req.MaxBytes
	switch {
	case maxBytes < 0:
		call.audit(action, "refused", "max_bytes is negative", fields)
		apierror.WriteError(w, apierror.New(apierror.CodeInvalidInput, "max_bytes must be a positive number"))
		return
	case maxBytes == 0:
		maxBytes = knowledgerun.DefaultGetBytes
	}
	maxBytes = min(maxBytes, knowledgerun.MaxGetBytes)
	docs, err := call.access.Documents(r.Context(), call.project,
		knowledge.DocumentRef{ID: req.DocumentID, URL: req.URL, Key: req.Key}, maxBytes, false)
	if err != nil {
		call.fail(w, action, err, fields)
		return
	}
	out := knowledgerun.GetResponse{Documents: []knowledgerun.Document{}}
	budget := knowledgerun.MaxResponseBytes / 2
	ids := make([]int64, 0, len(docs))
	for _, d := range docs {
		text, cut := clipText(scrubText(d.Text), max(budget, 0))
		budget -= len(text)
		updated := ""
		if !d.UpdatedAt.IsZero() {
			updated = d.UpdatedAt.UTC().Format(time.RFC3339)
		}
		out.Documents = append(out.Documents, knowledgerun.Document{
			ID: d.ID, Title: scrubText(d.Title), URL: d.URL,
			Source: knowledgerun.SourceRef{ID: d.Source.ID, Name: d.Source.Name, Kind: d.Source.Kind},
			Space:  d.Space, Ancestors: scrubAll(d.Ancestors), UpdatedAt: updated, Text: text,
			Truncated: d.Truncated || cut,
		})
		ids = append(ids, d.ID)
	}
	fields["documents"] = ids
	call.recordReads(req.Task, req.Purpose, ids)
	call.audit(action, "ok", "", fields)
	jsonOK(w, out)
}

// handleRunKnowledgeCitations serves POST /api/run/knowledge/citations: the
// documents the run's agent was served for a task, as citations — and they
// are forgotten here, the run keeping them on the task from then on.
func (s *Server) handleRunKnowledgeCitations(w http.ResponseWriter, r *http.Request) {
	call, ok := s.openRunKnowledgeCall(w, r)
	if !ok {
		return
	}
	defer call.close()
	var req knowledgerun.CitationsRequest
	if !call.decode(w, r, &req) {
		return
	}
	if !allowRunKnowledge(call.row.SessionID, time.Now()) {
		w.Header().Set("Retry-After", "2")
		apierror.WriteError(w, apierror.New(apierror.CodeRateLimited, "this run's knowledge session asks too often"))
		return
	}
	ids, err := call.db.TakeKnowledgeRunReads(call.row.SessionID, max(req.Task, 0))
	if err != nil {
		s.writeKnowledgeError(w, err, "read the run's citations")
		return
	}
	out := knowledgerun.CitationsResponse{Citations: []pm.Citation{}}
	for _, id := range ids {
		if len(out.Citations) == pm.MaxTaskCitations {
			break
		}
		docs, err := call.access.Documents(r.Context(), call.project, knowledge.DocumentRef{ID: id}, 0, true)
		if err != nil || len(docs) == 0 {
			// Gone, or no longer the project's, since it was read.
			continue
		}
		d := docs[0]
		if c, ok := pm.CleanCitation(pm.Citation{
			Kind: pm.CitationFetched, Title: d.Title, URL: d.URL, Source: d.Source.Name, SourceKind: d.Source.Kind,
			DocumentID: d.ID, RunID: call.row.RunID,
		}, redact.Scrub); ok {
			out.Citations = append(out.Citations, c)
		}
	}
	jsonOK(w, out)
}

// scrubAll scrubs each of ss.
func scrubAll(ss []string) []string {
	if len(ss) == 0 {
		return nil
	}
	out := make([]string, len(ss))
	for i, v := range ss {
		out[i] = scrubText(v)
	}
	return out
}

// ── the project's setting ──────────────────────────────────────────────────

// knowledgeRunSettingView is a project's knowledge retrieval setting as the
// API shows it: every value resolved, and whether each is the default.
type knowledgeRunSettingView struct {
	Enabled     bool `json:"enabled"`
	K           int  `json:"k"`
	TokenBudget int  `json:"token_budget"`
	// Default reports a project that never set it.
	Default bool `json:"default"`
	// Sources counts the knowledge sources bound to the project: a run gets
	// knowledge only when there is one.
	Sources int `json:"sources"`
}

func knowledgeRunSettingViewOf(r *pm.KnowledgeRetrieval, sources int) knowledgeRunSettingView {
	return knowledgeRunSettingView{Enabled: r.Enabled(), K: r.Passages(), TokenBudget: r.Tokens(), Default: r == nil,
		Sources: sources}
}

// handleProjectKnowledgeRetrieval serves
// GET /api/projects/{idx}/knowledge/retrieval: how the project's runs are
// given its knowledge.
func (s *Server) handleProjectKnowledgeRetrieval(w http.ResponseWriter, r *http.Request) {
	entry, ok := s.projectAtIdx(w, r)
	if !ok {
		return
	}
	ps, err := state.LoadLite(entry.Path)
	if err != nil {
		jsonErr(w, "no project found", http.StatusNotFound)
		return
	}
	jsonOK(w, map[string]any{"retrieval": knowledgeRunSettingViewOf(ps.KnowledgeRetrieval,
		s.boundKnowledgeSources(r.Context(), entry.Path))})
}

// boundKnowledgeSources counts the sources bound to the project at path.
func (s *Server) boundKnowledgeSources(ctx context.Context, path string) int {
	db, err := s.controlPlaneDB()
	if err != nil {
		return 0
	}
	defer db.Close()
	rows, err := db.ListKnowledgeBindings(statedb.KnowledgeBindingFilter{ProjectPath: policyProjectPath(path)})
	if err != nil || ctx.Err() != nil {
		return 0
	}
	ids := map[int64]bool{}
	for _, b := range rows {
		ids[b.SourceID] = true
	}
	return len(ids)
}

// knowledgeRetrievalRequest is the body of PUT
// /api/projects/{idx}/knowledge/retrieval: each field present is set, 0 for k
// or token_budget returning it to the default.
type knowledgeRetrievalRequest struct {
	Enabled     *bool `json:"enabled"`
	K           *int  `json:"k"`
	TokenBudget *int  `json:"token_budget"`
}

// handleProjectKnowledgeRetrievalSet serves
// PUT /api/projects/{idx}/knowledge/retrieval. The setting is stored on its
// own, as the requirements gate is: a run may be saving its tasks right now,
// and picks the change up at its next sync.
func (s *Server) handleProjectKnowledgeRetrievalSet(w http.ResponseWriter, r *http.Request) {
	entry, ok := s.projectAtIdx(w, r)
	if !ok {
		return
	}
	var req knowledgeRetrievalRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if req.Enabled == nil && req.K == nil && req.TokenBudget == nil {
		apierror.WriteError(w, apierror.New(apierror.CodeInvalidInput,
			"nothing to change: give enabled, k, token_budget, or several"))
		return
	}
	ps, err := state.LoadLite(entry.Path)
	if err != nil {
		jsonErr(w, "no project found", http.StatusNotFound)
		return
	}
	next := ps.KnowledgeRetrieval.Clone()
	if next == nil {
		next = &pm.KnowledgeRetrieval{}
	}
	if req.Enabled != nil {
		next.Disabled = !*req.Enabled
	}
	if req.K != nil {
		next.K = *req.K
	}
	if req.TokenBudget != nil {
		next.TokenBudget = *req.TokenBudget
	}
	if err := next.Validate(); err != nil {
		apierror.WriteError(w, apierror.New(apierror.CodeInvalidInput, err.Error()))
		return
	}
	if *next == (pm.KnowledgeRetrieval{}) {
		next = nil
	}
	if err := state.SetKnowledgeRetrieval(entry.Path, next); err != nil {
		jsonErr(w, "save failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if fresh, err := state.LoadLite(entry.Path); err == nil {
		s.broadcastStateDiff(entry.Path, fresh)
	}
	jsonOK(w, map[string]any{"retrieval": knowledgeRunSettingViewOf(next, s.boundKnowledgeSources(r.Context(), entry.Path))})
}
