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
//
// ?source= selects how many of those journals to read (Task 20292). The
// default, `project`, is the single-chain read described above. `all` merges
// the resolved project's journal with the hub's, because the question an
// operator actually asks — "what happened to project X" — spans both: the
// plan's own life is in the project's chain, while the executor that ran it,
// the image policy that admitted it and the credentials it held are in the
// hub's. A single-chain answer to that question is confidently incomplete,
// which is worse than a slow one.

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/apierror"
	"github.com/blechschmidt/cloop/pkg/auditmerge"
	"github.com/blechschmidt/cloop/pkg/eventlog"
	"github.com/blechschmidt/cloop/pkg/logger"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

const (
	// auditPageDefault is the page size when the client does not ask.
	auditPageDefault = 100

	// auditPageMax bounds what one request can pull. The table can hold
	// millions of rows; an unbounded limit is a memory amplification lever
	// for anyone who can reach the endpoint.
	auditPageMax = 1000

	// auditSourceProject reads only the journal the request resolved to. It
	// is the default because it is what every caller got before merged mode
	// existed, and a read endpoint that silently widened its scope would
	// change what an export or a saved query means.
	auditSourceProject = "project"

	// auditSourceAll reads the resolved project's journal together with the
	// hub's.
	auditSourceAll = "all"
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

	// Source and Dir say which chain the row came from, and are sent only
	// for a merged read. Omitted otherwise, so a single-chain response is
	// byte-identical to what it has always been — and because labelling a
	// row "project" when the caller asked for exactly one journal would be
	// noise, not provenance.
	//
	// ids are per-chain and collide across a merge, so (source, id) is the
	// pair that identifies a merged row; id alone does not.
	Source string `json:"source,omitempty"`
	Dir    string `json:"dir,omitempty"`
}

// auditChainJSON names one database a read covered.
//
// Sent so the panel can state its own coverage. An empty merged result means
// "nothing matched in these chains", and without naming them it reads
// identically to "one of them was not there" — which is the exact ambiguity
// merged mode exists to remove.
type auditChainJSON struct {
	Source string `json:"source"`
	Dir    string `json:"dir"`
}

// auditChainVerdictJSON is one chain's integrity result.
//
// Error is distinct from OK=false on purpose: "could not check this chain"
// and "checked it and found a break" call for different responses, and
// collapsing them is how an unreadable trail gets reported as an intact one.
type auditChainVerdictJSON struct {
	Source    string `json:"source"`
	Dir       string `json:"dir"`
	OK        bool   `json:"ok"`
	Total     int    `json:"total"`
	BreakAtID int64  `json:"break_at_id"`
	Reason    string `json:"reason,omitempty"`
	Error     string `json:"error,omitempty"`
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

	// Chains lists the databases this page was read from, and is sent only
	// for a merged read. The panel reports it verbatim: an operator acting on
	// the trail needs to know what was searched, not just what was found.
	Chains []auditChainJSON `json:"chains,omitempty"`
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

	// Retention context (Task 20218). A pruned chain verifies OK, and without
	// these the panel would render a green badge over a trail that no longer
	// starts at the beginning — technically true and materially misleading.
	// Anchored says the walk started from an anchor rather than from genesis;
	// the rest say where the history went so a reader can go and get it.
	Anchored       bool   `json:"anchored"`
	VerifiedFromID int64  `json:"verified_from_id"`
	PrunedCount    int64  `json:"pruned_count"`
	ArchivePath    string `json:"archive_path"`
	ArchiveSHA256  string `json:"archive_sha256"`

	// Chains carries one verdict per chain for a merged verification, and is
	// absent otherwise. The fields above stay populated from the resolved
	// project's chain so a client that predates merged mode reads the same
	// answer it always did — but they cannot speak for the other chain, and a
	// single boolean would let an intact project chain vouch for a broken hub
	// one. Clients that understand this array must fail if any entry does.
	Chains []auditChainVerdictJSON `json:"chains,omitempty"`
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
	source, err := auditSourceFromQuery(r)
	if err != nil {
		apierror.WriteError(w, apierror.New(apierror.CodeInvalidInput, err.Error()))
		return
	}
	if source == auditSourceAll {
		s.serveMergedAuditList(w, r, filter)
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
		resp.Events = append(resp.Events, auditEventWire(ev))
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

// auditEventWire renders one stored row for the client, without provenance —
// the merged path fills that in, and the single-chain path deliberately leaves
// it empty.
func auditEventWire(ev statedb.AuditEvent) auditEventJSON {
	return auditEventJSON{
		ID:         ev.ID,
		Timestamp:  ev.Timestamp.UTC().Format(time.RFC3339Nano),
		Actor:      ev.Actor,
		EventType:  ev.EventType,
		EntityType: ev.EntityType,
		EntityID:   ev.EntityID,
		Payload:    ev.Payload,
		PrevHash:   ev.PrevHash,
		RowHash:    ev.RowHash,
	}
}

// serveMergedAuditList answers ?source=all: the hub's journal and the resolved
// project's, read as one timestamp-ordered trail.
//
// A missing database is skipped rather than refused (auditmerge.Open), so a
// project that has never been run still answers with the hub's rows about it
// instead of an error — the same reasoning as openAuditLog's empty-but-valid
// response for an uninitialised workdir.
func (s *Server) serveMergedAuditList(w http.ResponseWriter, r *http.Request, filter eventlog.AuditFilter) {
	reader, err := auditmerge.Open(s.auditChains(r))
	if err != nil {
		s.log().Error(logger.EventAuthz, 0, "audit: open merged trail",
			map[string]interface{}{"error": err.Error()})
		apierror.WriteError(w, apierror.New(apierror.CodeInternal, "could not open the audit trail"))
		return
	}
	defer reader.Close()

	rows, all, err := reader.List(filter)
	if err != nil {
		s.log().Error(logger.EventAuthz, 0, "audit: list merged events",
			map[string]interface{}{"error": err.Error()})
		apierror.WriteError(w, apierror.New(apierror.CodeInternal, "could not read the audit trail"))
		return
	}

	// Same bargain as the single-chain path: the store reports the unfiltered
	// count, so a narrowing filter needs its own unpaged pass.
	total := all
	if filterIsNarrowing(filter) {
		counting := filter
		counting.Limit = 0 // store clamps to its 10 000 ceiling, per chain
		counting.Offset = 0
		matched, _, cerr := reader.List(counting)
		if cerr != nil {
			s.log().Warn(logger.EventAuthz, 0, "audit: count filtered merged events",
				map[string]interface{}{"error": cerr.Error()})
			total = filter.Offset + len(rows)
		} else {
			total = len(matched)
		}
	}

	chains := reader.Chains()
	resp := auditListResponse{
		Events:  make([]auditEventJSON, 0, len(rows)),
		Total:   total,
		All:     all,
		Limit:   filter.Limit,
		Offset:  filter.Offset,
		HasMore: filter.Offset+len(rows) < total,
		Chains:  make([]auditChainJSON, 0, len(chains)),
	}
	for _, row := range rows {
		ev := auditEventWire(row.AuditEvent)
		ev.Source = string(row.Source)
		ev.Dir = row.Dir
		resp.Events = append(resp.Events, ev)
	}
	for _, c := range chains {
		resp.Chains = append(resp.Chains, auditChainJSON{Source: string(c.Source), Dir: c.Dir})
	}
	resp.Actors, resp.EntityTypes = mergedAuditFacets(chains)
	jsonOK(w, resp)
}

// auditChains lists the databases a merged read covers.
//
// The hub's chain is listed first because auditmerge keeps the first label
// when two chains resolve to the same file — which they do whenever the
// request is scoped to the hub's own directory. Filing the fleet's executor,
// secret and image-policy rows under one project's name would misreport what
// they govern.
func (s *Server) auditChains(r *http.Request) []auditmerge.Chain {
	return []auditmerge.Chain{
		{Source: auditmerge.SourceControlPlane, Dir: s.WorkDir},
		{Source: auditmerge.SourceProject, Dir: s.resolveWorkDir(r)},
	}
}

// mergedAuditFacets unions the filter-bar dropdown values across the chains
// that were read.
//
// Offering one chain's actors over a two-chain view would leave the operator
// who merged precisely to find *who* enrolled an executor unable to select
// them. It costs a second read-only open per chain, which is the price of a
// filter bar that can name everything the table below it contains.
//
// Advisory, like the single-chain facets: a chain that will not answer is
// skipped rather than failing the page the caller asked for.
func mergedAuditFacets(chains []auditmerge.Chain) (actors, entityTypes []string) {
	seenActor, seenType := map[string]bool{}, map[string]bool{}
	collect := func(into []string, seen map[string]bool, values []string) []string {
		for _, v := range values {
			if !seen[v] {
				seen[v] = true
				into = append(into, v)
			}
		}
		return into
	}
	for _, c := range chains {
		log, err := eventlog.Open(c.Dir)
		if err != nil {
			continue
		}
		if got, gerr := log.DistinctActors(); gerr == nil {
			actors = collect(actors, seenActor, got)
		}
		if got, gerr := log.DistinctEntityTypes(); gerr == nil {
			entityTypes = collect(entityTypes, seenType, got)
		}
		log.Close()
	}
	sort.Strings(actors)
	sort.Strings(entityTypes)
	return actors, entityTypes
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

	source, err := auditSourceFromQuery(r)
	if err != nil {
		apierror.WriteError(w, apierror.New(apierror.CodeInvalidInput, err.Error()))
		return
	}
	if source == auditSourceAll {
		s.serveMergedAuditVerify(w, r)
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

		Anchored:       report.Anchored,
		VerifiedFromID: report.VerifiedFromID,
		PrunedCount:    report.PrunedCount,
		ArchivePath:    report.ExportPath,
		ArchiveSHA256:  report.ExportSHA256,
	})
}

// serveMergedAuditVerify answers GET /api/audit/verify?source=all.
//
// Each chain is verified on its own, because they are independent: one hash
// chain says nothing about the other. The top-level fields still describe the
// resolved project's chain — a client written before merged mode reads exactly
// what it used to — and the per-chain array carries the rest.
func (s *Server) serveMergedAuditVerify(w http.ResponseWriter, r *http.Request) {
	reader, err := auditmerge.Open(s.auditChains(r))
	if err != nil {
		s.log().Error(logger.EventAuthz, 0, "audit: open merged trail for verify",
			map[string]interface{}{"error": err.Error()})
		apierror.WriteError(w, apierror.New(apierror.CodeInternal, "could not verify the audit chain"))
		return
	}
	defer reader.Close()

	verdicts := reader.Verify()

	// An uninitialised workdir has no chain to check, and reports an empty
	// trail rather than a failure — the same answer openAuditLog gives.
	resp := auditVerifyResponse{
		OK:        true,
		CheckedAt: time.Now().UTC().Format(time.RFC3339),
		Chains:    make([]auditChainVerdictJSON, 0, len(verdicts)),
	}
	for _, v := range verdicts {
		entry := auditChainVerdictJSON{
			Source:    string(v.Source),
			Dir:       v.Dir,
			OK:        v.OK(),
			Total:     v.Report.Total,
			BreakAtID: v.Report.BreakAtID,
			Reason:    v.Report.Reason,
		}
		if v.Err != nil {
			entry.Error = v.Err.Error()
		}
		resp.Chains = append(resp.Chains, entry)
	}

	if primary, found := primaryAuditVerdict(verdicts, s.resolveWorkDir(r)); found {
		resp.OK = primary.OK()
		resp.Total = primary.Report.Total
		resp.BreakAtID = primary.Report.BreakAtID
		resp.Reason = primary.Report.Reason
		resp.ExpectedHash = primary.Report.ExpectedHash
		resp.ActualHash = primary.Report.ActualHash
		resp.Anchored = primary.Report.Anchored
		resp.VerifiedFromID = primary.Report.VerifiedFromID
		resp.PrunedCount = primary.Report.PrunedCount
		resp.ArchivePath = primary.Report.ExportPath
		resp.ArchiveSHA256 = primary.Report.ExportSHA256
		if primary.Err != nil && resp.Reason == "" {
			resp.Reason = primary.Err.Error()
		}
	}
	jsonOK(w, resp)
}

// primaryAuditVerdict picks the chain whose verdict fills the response's
// top-level fields: the one the request resolved to.
//
// A miss falls back to the first chain rather than to nothing, because the two
// chains collapse into one whenever the project asked about is the hub's own
// directory — and reporting "no chain" for the hub itself would be wrong in the
// most common case there is.
func primaryAuditVerdict(verdicts []auditmerge.Verdict, workDir string) (auditmerge.Verdict, bool) {
	if len(verdicts) == 0 {
		return auditmerge.Verdict{}, false
	}
	for _, v := range verdicts {
		if v.Dir == workDir {
			return v, true
		}
	}
	return verdicts[0], true
}

// auditSourceFromQuery reads ?source=, defaulting to the single-chain read.
//
// An unrecognised value is an error rather than a silent fallback, matching the
// numeric parameters: a caller asking for a scope this build does not have must
// not be answered with a narrower one that looks the same.
func auditSourceFromQuery(r *http.Request) (string, error) {
	switch v := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("source"))); v {
	case "", auditSourceProject:
		return auditSourceProject, nil
	case auditSourceAll:
		return auditSourceAll, nil
	default:
		return "", fmt.Errorf("source: %q is not one of %q, %q", v, auditSourceProject, auditSourceAll)
	}
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

// auditTaskStatus records a manual task status flip (Task 20282).
//
// This is the row that names a human. The orchestrator's task.dispatch and
// task.finish rows describe executions, and an execution has no opinion about
// who ended it — a task killed from the dashboard reaches the orchestrator as a
// kill_requests row, and the terminal row it eventually writes says "failed",
// not "because Alice pressed stop at 14:02". Without this emission the trail
// could say a task was killed and never say by whom.
//
// It opens the *project's* database, not the control plane's, because that is
// where the task's other rows live: the lifecycle rows are written by SaveState
// against the project it belongs to, and filing the human decision somewhere
// else would split one story across two hash chains.
//
// Best-effort, matching every other emitter here. The status has already been
// persisted by the time this runs; a wedged audit log must not turn a
// successful operator action into an HTTP error.
func (s *Server) auditTaskStatus(r *http.Request, workDir string, taskID int, oldStatus, newStatus string) {
	if oldStatus == newStatus {
		return
	}
	db, err := statedb.Open(state.DBPath(workDir))
	if err != nil {
		s.log().Warn(logger.EventAuthz, taskID, "audit: open project db for task status event",
			map[string]interface{}{"error": err.Error(), "task_id": taskID})
		return
	}
	defer db.Close()
	statedb.AuditTaskStatus(db, taskID, oldStatus, newStatus, s.auditActor(r))
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
