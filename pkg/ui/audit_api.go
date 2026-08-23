package ui

// The Audit panel's backend (Task 20167).
//
// Two endpoints, both admin-only via authz.PermAuditRead:
//
//	GET /api/audit         filtered, paged read of the trail + filter facets
//	GET /api/audit/verify  hash-chain integrity, for the green/red badge
//
// Filtering happens in SQLite, not in the browser. The trail grows without
// bound — every task mutation, every authorization decision, every credential
// lease — so shipping it wholesale to the client and filtering there would
// stop working on exactly the deployments that need it most.
//
// Both endpoints are registered with scopeGlobal. The trail is a fleet-level
// record: it spans projects, and audit.read is granted to admin alone, who
// holds fleet-wide authority by definition. ?project_idx=N selects *which*
// journal to read (each project keeps its own state.db, and the hub keeps
// one for global events), and is validated against the caller's visible
// project list so a wild index cannot address an unregistered path.

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/apierror"
	"github.com/blechschmidt/cloop/pkg/eventlog"
	"github.com/blechschmidt/cloop/pkg/logger"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

const (
	// auditPageDefault is the page size when the client does not ask.
	auditPageDefault = 100

	// auditPageMax bounds what one request can pull. The table can hold
	// millions of rows; an unbounded limit is a memory amplification lever
	// for anyone who can reach the endpoint.
	auditPageMax = 1000
)

// auditEventJSON is the wire shape of one row.
//
// Declared explicitly rather than marshalling statedb.AuditEvent so the
// frontend contract does not move when a Go field is renamed, and so the
// hashes ship under the names the verify badge and the export use.
type auditEventJSON struct {
	ID         int64  `json:"id"`
	Timestamp  string `json:"timestamp"`
	Actor      string `json:"actor"`
	EventType  string `json:"event_type"`
	EntityType string `json:"entity_type"`
	EntityID   string `json:"entity_id"`
	Payload    string `json:"payload"`
	PrevHash   string `json:"prev_hash"`
	RowHash    string `json:"row_hash"`
}

// auditListResponse is what GET /api/audit returns.
type auditListResponse struct {
	Events  []auditEventJSON `json:"events"`
	Total   int              `json:"total"`  // rows matching the filter
	All     int              `json:"all"`    // rows in the table, unfiltered
	Limit   int              `json:"limit"`  // effective page size
	Offset  int              `json:"offset"` // effective offset
	HasMore bool             `json:"has_more"`

	// Actors and EntityTypes populate the filter bar's dropdowns, so it
	// offers only values that actually occur. Sent with every page because
	// they are two cheap DISTINCT queries against indexed columns, and a
	// separate endpoint would be a second round trip for the panel's first
	// paint.
	Actors      []string `json:"actors"`
	EntityTypes []string `json:"entity_types"`
}

// auditVerifyResponse is what GET /api/audit/verify returns.
type auditVerifyResponse struct {
	OK           bool   `json:"ok"`
	Total        int    `json:"total"`
	BreakAtID    int64  `json:"break_at_id"`
	Reason       string `json:"reason"`
	ExpectedHash string `json:"expected_hash"`
	ActualHash   string `json:"actual_hash"`
	CheckedAt    string `json:"checked_at"`
}

// handleAuditList serves GET /api/audit.
func (s *Server) handleAuditList(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		apierror.WriteError(w, apierror.New(apierror.CodeMethodNotAllowed, "GET required"))
		return
	}
	if !s.requireVisibleProject(w, r) {
		return
	}

	filter, err := auditFilterFromQuery(r)
	if err != nil {
		apierror.WriteError(w, apierror.New(apierror.CodeInvalidInput, err.Error()))
		return
	}

	log, ok := s.openAuditLog(w, r)
	if !ok {
		return
	}
	defer log.Close()

	rows, all, err := log.List(filter)
	if err != nil {
		s.log().Error(logger.EventAuthz, 0, "audit: list events",
			map[string]interface{}{"error": err.Error()})
		apierror.WriteError(w, apierror.New(apierror.CodeInternal, "could not read the audit trail"))
		return
	}

	// The store returns the unfiltered table count; the filtered total needs
	// its own pass. Counting by re-querying without paging would double the
	// work on every page, so the count is derived from the page when the
	// filter is empty and computed once otherwise.
	total := all
	if filterIsNarrowing(filter) {
		total, err = s.countFilteredAudit(log, filter)
		if err != nil {
			s.log().Warn(logger.EventAuthz, 0, "audit: count filtered events",
				map[string]interface{}{"error": err.Error()})
			// Fall back to a lower bound rather than failing the whole read:
			// a paging hint being approximate is better than no trail.
			total = filter.Offset + len(rows)
		}
	}

	resp := auditListResponse{
		Events:  make([]auditEventJSON, 0, len(rows)),
		Total:   total,
		All:     all,
		Limit:   filter.Limit,
		Offset:  filter.Offset,
		HasMore: filter.Offset+len(rows) < total,
	}
	for _, ev := range rows {
		resp.Events = append(resp.Events, auditEventJSON{
			ID:         ev.ID,
			Timestamp:  ev.Timestamp.UTC().Format(time.RFC3339Nano),
			Actor:      ev.Actor,
			EventType:  ev.EventType,
			EntityType: ev.EntityType,
			EntityID:   ev.EntityID,
			Payload:    ev.Payload,
			PrevHash:   ev.PrevHash,
			RowHash:    ev.RowHash,
		})
	}
	// Facets are advisory; a failure here must not cost the caller the page
	// they asked for.
	if actors, aerr := log.DistinctActors(); aerr == nil {
		resp.Actors = actors
	}
	if types, terr := log.DistinctEntityTypes(); terr == nil {
		resp.EntityTypes = types
	}
	jsonOK(w, resp)
}

// handleAuditVerify serves GET /api/audit/verify.
func (s *Server) handleAuditVerify(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		apierror.WriteError(w, apierror.New(apierror.CodeMethodNotAllowed, "GET required"))
		return
	}
	if !s.requireVisibleProject(w, r) {
		return
	}

	log, ok := s.openAuditLog(w, r)
	if !ok {
		return
	}
	defer log.Close()

	report, err := log.Verify()
	if err != nil {
		s.log().Error(logger.EventAuthz, 0, "audit: verify chain",
			map[string]interface{}{"error": err.Error()})
		apierror.WriteError(w, apierror.New(apierror.CodeInternal, "could not verify the audit chain"))
		return
	}
	// A broken chain is a successful verification with a negative result,
	// not an HTTP error: the badge needs to render red, and a 500 would be
	// indistinguishable from the endpoint being down.
	jsonOK(w, auditVerifyResponse{
		OK:           report.OK,
		Total:        report.Total,
		BreakAtID:    report.BreakAtID,
		Reason:       report.Reason,
		ExpectedHash: report.ExpectedHash,
		ActualHash:   report.ActualHash,
		CheckedAt:    time.Now().UTC().Format(time.RFC3339),
	})
}

// openAuditLog resolves which journal to read and opens it, writing the
// error response itself when it cannot.
//
// An uninitialised workdir is answered with an empty-but-valid trail rather
// than an error: a hub whose own project has never been initialised still has
// a legitimate, empty audit history, and an Audit tab that renders an error
// on a fresh install teaches the operator nothing.
func (s *Server) openAuditLog(w http.ResponseWriter, r *http.Request) (*eventlog.Log, bool) {
	workDir := s.resolveWorkDir(r)
	log, err := eventlog.Open(workDir)
	if err == nil {
		return log, true
	}
	if err == eventlog.ErrNoProject {
		if strings.HasSuffix(r.URL.Path, "/verify") {
			jsonOK(w, auditVerifyResponse{
				OK:        true,
				Total:     0,
				CheckedAt: time.Now().UTC().Format(time.RFC3339),
			})
		} else {
			jsonOK(w, auditListResponse{Events: []auditEventJSON{}, Limit: auditPageDefault})
		}
		return nil, false
	}
	s.log().Error(logger.EventAuthz, 0, "audit: open event log",
		map[string]interface{}{"error": err.Error(), "workdir": workDir})
	apierror.WriteError(w, apierror.New(apierror.CodeInternal, "could not open the audit trail"))
	return nil, false
}

// ── Emission ────────────────────────────────────────────────────────────────

// auditActor names the acting identity for an audit row: the OIDC subject
// label when RBAC is in force, otherwise "local" or "static-token". Reusing
// the grant's label is what keeps the actor string identical to the one
// auditAuthz already writes, so an operator filtering by actor sees a
// person's whole session rather than half of it under a second spelling.
func (s *Server) auditActor(r *http.Request) string {
	return s.grantFor(r).subjectLabel()
}

// auditExecutorAction records an executor-fleet mutation in the hub's own
// journal.
//
// Executor lifecycle is the answer to "who attached this machine to the
// control plane, and when" — the question the whole trail exists to serve
// once workloads run off-host. It opens its own connection because the
// scheduling handlers work through the supervisor and have no DB in scope;
// the handlers that already hold one call statedb.AuditExecutorLifecycle
// directly instead.
//
// Best-effort, matching every other emitter: a wedged journal must not stop
// an operator from cordoning a misbehaving node.
func (s *Server) auditExecutorAction(r *http.Request, action, executorID string, detail map[string]any) {
	db, err := s.controlPlaneDB()
	if err != nil {
		s.log().Warn(logger.EventAuthz, 0, "audit: open control-plane db for executor event",
			map[string]interface{}{"error": err.Error(), "action": action})
		return
	}
	defer db.Close()
	statedb.AuditExecutorLifecycle(db, statedb.ExecutorAuditInput{
		Action:     action,
		ExecutorID: executorID,
		Actor:      s.auditActor(r),
		Detail:     detail,
	})
	s.broadcastAuditAppend(action)
}

// broadcastAuditAppend tells connected dashboards that the trail grew, so the
// Audit panel refreshes without polling.
//
// The envelope carries no event data, only the fact that something landed —
// the same shape as executor_update (Task 20162). That is deliberate: the
// trail is admin-only, and a broadcast fans out to every connected client
// regardless of role, so putting row contents in the envelope would leak the
// audit log to viewers over the WebSocket. Clients re-read GET /api/audit,
// where the permission is actually enforced.
//
// Scope: hub-global, deliberately (audited under Task 20189, which scoped
// broadcastLog). The audit trail is one hub-wide resource, not a per-project
// one, so there is no room to narrow this to. The payload is a bare verb —
// no project path, no actor, no row — precisely because reach here is wider
// than read permission on GET /api/audit. See the scope-vs-permission note
// in docs/security/threat-model.md.
func (s *Server) broadcastAuditAppend(action string) {
	payload, err := json.Marshal(map[string]any{"action": action})
	if err != nil {
		return
	}
	msg := wsMessage{Type: "audit_append", Data: json.RawMessage(payload)}

	s.hubMu.Lock()
	for _, clients := range s.hubClients {
		for hc := range clients {
			s.sendOrLag(hc, msg)
		}
	}
	s.hubMu.Unlock()
}

// countFilteredAudit returns how many rows match filter, ignoring paging.
//
// ListAuditEvents reports the table-wide count rather than the filtered one,
// so this asks for the matching ids with paging removed. The limit is capped
// at the store's internal 10 000 ceiling, which makes the count a lower bound
// on very large filtered sets — reported honestly as such by the UI's "N+"
// rendering rather than as a precise number that happens to be wrong.
func (s *Server) countFilteredAudit(log *eventlog.Log, filter eventlog.AuditFilter) (int, error) {
	counting := filter
	counting.Limit = 0 // store clamps to its 10 000 ceiling
	counting.Offset = 0
	rows, _, err := log.List(counting)
	if err != nil {
		return 0, err
	}
	return len(rows), nil
}

// filterIsNarrowing reports whether the filter restricts the row set at all.
// When it does not, the store's unfiltered count is already the right answer
// and the extra query is skipped.
func filterIsNarrowing(f eventlog.AuditFilter) bool {
	return f.Actor != "" || f.EntityType != "" || f.EntityID != "" ||
		f.EventType != "" || f.Search != "" ||
		!f.Since.IsZero() || !f.Until.IsZero() ||
		f.FromID > 0 || f.ToID > 0
}

// auditFilterFromQuery maps query parameters onto a storage filter,
// validating and bounding every numeric input.
func auditFilterFromQuery(r *http.Request) (eventlog.AuditFilter, error) {
	q := r.URL.Query()
	f := eventlog.AuditFilter{
		Actor:      strings.TrimSpace(q.Get("actor")),
		EntityType: strings.TrimSpace(q.Get("entity_type")),
		EntityID:   strings.TrimSpace(q.Get("entity_id")),
		EventType:  strings.TrimSpace(q.Get("event_type")),
		Search:     strings.TrimSpace(q.Get("q")),
		// Newest first: an operator opening the panel is asking "what just
		// happened", not "what happened when this deployment was installed".
		Order: "desc",
	}
	if strings.EqualFold(strings.TrimSpace(q.Get("order")), "asc") {
		f.Order = "asc"
	}

	limit, err := boundedIntParam(q.Get("limit"), auditPageDefault, 1, auditPageMax)
	if err != nil {
		return f, fmt.Errorf("limit: %w", err)
	}
	f.Limit = limit

	offset, err := boundedIntParam(q.Get("offset"), 0, 0, 0)
	if err != nil {
		return f, fmt.Errorf("offset: %w", err)
	}
	f.Offset = offset

	if v := strings.TrimSpace(q.Get("since")); v != "" {
		ts, perr := parseAuditTime(v)
		if perr != nil {
			return f, fmt.Errorf("since: %w", perr)
		}
		f.Since = ts
	}
	if v := strings.TrimSpace(q.Get("until")); v != "" {
		ts, perr := parseAuditTime(v)
		if perr != nil {
			return f, fmt.Errorf("until: %w", perr)
		}
		f.Until = ts
	}
	if !f.Since.IsZero() && !f.Until.IsZero() && f.Until.Before(f.Since) {
		return f, fmt.Errorf("until (%s) is before since (%s)",
			f.Until.Format(time.RFC3339), f.Since.Format(time.RFC3339))
	}
	return f, nil
}

// boundedIntParam parses an optional integer parameter, clamping it into
// [min, max]. A max of 0 means unbounded above. An unparseable value is an
// error rather than a silent fallback: a client sending limit=abc has a bug,
// and answering it with the default hides that.
func boundedIntParam(raw string, def, min, max int) (int, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return def, nil
	}
	v, err := strconv.Atoi(raw)
	if err != nil {
		return 0, fmt.Errorf("%q is not a number", raw)
	}
	if v < min {
		v = min
	}
	if max > 0 && v > max {
		v = max
	}
	return v, nil
}

// parseAuditTime accepts the same forms as the CLI's --since/--until so an
// operator moving between `cloop audit-log` and the dashboard does not have
// to learn two syntaxes: RFC3339, a bare date, or a relative duration.
func parseAuditTime(s string) (time.Time, error) {
	s = strings.TrimSpace(s)
	if d, err := time.ParseDuration(s); err == nil {
		return time.Now().Add(-d), nil
	}
	if strings.HasSuffix(s, "d") {
		var n int
		if _, err := fmt.Sscanf(s, "%dd", &n); err == nil && n > 0 {
			return time.Now().Add(-time.Duration(n) * 24 * time.Hour), nil
		}
	}
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t, nil
	}
	if t, err := time.Parse("2006-01-02", s); err == nil {
		return t, nil
	}
	return time.Time{}, fmt.Errorf("unrecognised time %q (try RFC3339, YYYY-MM-DD, or 30m / 2h / 7d)", s)
}
