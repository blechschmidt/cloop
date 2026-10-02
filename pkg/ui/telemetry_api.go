package ui

// Browser telemetry: ingest and read-back (Task 20251).
//
// Six routes, split across two very different trust levels:
//
//	POST /api/telemetry                  dashboard ingest   — public
//	POST /api/glasses/telemetry          glasses ingest     — public, glasses-pinned
//	GET  /api/telemetry/config           may I send?        — public
//	GET  /api/glasses/telemetry/config   may I send?        — public, glasses-pinned
//	GET  /api/telemetry                  read a page        — audit.read, global
//	GET  /api/telemetry/sessions         roll-up by session — audit.read, global
//
// Editing the policy is a seventh and an eighth, in telemetry_config_api.go.
//
// # Why a page asks before it sends
//
// Collection is off unless an operator turned it on (Task 20311), and a front
// end that posted anyway and let the hub answer 404 would already have sent the
// trail — over the network, into a log line, past whatever sits in between. On
// a hub that collects nothing, that is precisely the data that was not supposed
// to leave the browser.
//
// So the two /config routes exist to be asked first. They disclose one boolean
// about the asking page, cost one small GET per page load, and are read off the
// idle path rather than during first paint. The hub still refuses ingest
// independently: a stale tab or a hand-written client must not be able to write
// rows into a hub whose answer was no.
//
// # Why ingest declares no permission
//
// The same reason POST /api/client-error does not: an instrument that records
// only while the page is healthy records nothing about the failures worth
// investigating, and a user whose role grants nothing still has a broken page.
// Requiring a permission to report a fault would gate reporting on exactly the
// authority whose absence is often the fault.
//
// Public here means no permission, not no credential. Only isPublicShell
// bypasses authMiddleware and it covers GET /glasses alone, so both ingest
// routes still require a session or a token. That is the deliberate line: a
// telemetry endpoint open to the anonymous internet is an abuse vector, and
// almost nothing worth recording happens before sign-in. The cost is that a
// glasses link which has already been revoked cannot deliver its final events
// — its credential stops working first — and that case is self-evident from
// the page's own message anyway.
//
// Bounded on top of that. Every write is clamped by the field budgets and
// batch cap in pkg/telemetry, credential-scrubbed before it is stored, subject
// to the per-IP rate limiter every route sits behind, and lands in a table that
// trims itself on the write path (see statedb.TelemetryMaxRows). Identity and
// address are stamped by the server from the request, so a batch reports rather
// than asserts who sent it. None of it happens unless an operator switched
// collection on (Task 20311): until then both ingest routes answer 404, and the
// front ends, having asked first, never post.
//
// # Why the glasses need their own path
//
// A display-glasses token is pinned by tokenKindAdmitted to /glasses and
// /api/glasses/, and that pin is load-bearing: it is what stops a credential
// that lives in a URL from reaching the routes that return agent transcripts.
// Widening it so the glasses could post to /api/telemetry would trade the
// whole of that containment for one endpoint. A second ingest route inside the
// existing prefix costs nothing and keeps the pin intact.
//
// # Why read-back is audit.read
//
// A trail contains URLs, view names, user agents and error text from other
// people's sessions. That is the same class of cross-tenant operational record
// the audit trail holds, gated by the same permission, for the same reason.

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/apierror"
	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/logger"
	"github.com/blechschmidt/cloop/pkg/statedb"
	"github.com/blechschmidt/cloop/pkg/telemetry"
)

// telemetryMaxBodyBytes caps an ingest POST independently of the 10 MiB
// default the other handlers use.
//
// Sized from the payload rather than inherited: a full batch of worst-case
// events is about 900 KiB, so 2 MiB is generous. The default would let an
// unauthenticated caller stream ten megabytes into a decoder per request,
// which is a memory amplification lever on the one route that does not
// require a credential.
const telemetryMaxBodyBytes int64 = 2 << 20

// handleTelemetryIngest serves POST /api/telemetry — the dashboard's trail.
func (s *Server) handleTelemetryIngest(w http.ResponseWriter, r *http.Request) {
	s.ingestTelemetry(w, r, telemetry.SourceDashboard)
}

// handleGlassesTelemetryIngest serves POST /api/glasses/telemetry.
//
// A separate handler rather than a query parameter on the shared one, because
// the source must be decided by the route and not by anything the caller can
// vary: it is what tells a reader which front end a trail describes.
func (s *Server) handleGlassesTelemetryIngest(w http.ResponseWriter, r *http.Request) {
	s.ingestTelemetry(w, r, telemetry.SourceGlasses)
}

// telemetryClientPolicy is what a front end is told about itself before it
// sends anything (Task 20311).
//
// One boolean, scoped to the asking page. A dashboard learns nothing about the
// glasses policy and vice versa, which keeps this the least informative route
// that can still do its job: the job is to let a page find out it should stay
// silent, and "should I speak" needs no more than a yes.
type telemetryClientPolicy struct {
	Source  string `json:"source"`
	Collect bool   `json:"collect"`
}

// handleTelemetryClientConfig serves GET /api/telemetry/config.
func (s *Server) handleTelemetryClientConfig(w http.ResponseWriter, r *http.Request) {
	s.writeTelemetryClientPolicy(w, telemetry.SourceDashboard)
}

// handleGlassesTelemetryClientConfig serves GET /api/glasses/telemetry/config.
//
// A second path for the same answer, for the same reason the ingest routes are
// split: a display-glasses token is pinned to the /api/glasses/ prefix, and
// widening that pin so the wearable could read the dashboard's path would trade
// the containment for a convenience.
func (s *Server) handleGlassesTelemetryClientConfig(w http.ResponseWriter, r *http.Request) {
	s.writeTelemetryClientPolicy(w, telemetry.SourceGlasses)
}

func (s *Server) writeTelemetryClientPolicy(w http.ResponseWriter, src telemetry.Source) {
	// Never cached. A response with no cache headers is eligible for heuristic
	// caching, and the stale answer that matters is the permissive one: a page
	// holding a cached "yes" after collection was switched off would keep
	// shipping the trail across the network for the hub to refuse. The bytes
	// leaving the browser are the thing this route exists to prevent.
	w.Header().Set("Cache-Control", "no-store")
	jsonOK(w, telemetryClientPolicy{
		Source:  string(src),
		Collect: s.telemetryCollects(src),
	})
}

// ingestTelemetry validates, normalizes and stores one batch.
//
// Answers 204 for everything it accepts and for everything it silently drops.
// A page must not learn from a status code whether its events were kept — and
// more practically, a reporting client that retried on failure would amplify
// exactly the runaway-loop case the batch cap exists to contain.
func (s *Server) ingestTelemetry(w http.ResponseWriter, r *http.Request, src telemetry.Source) {
	if !requirePOST(w, r) {
		return
	}
	// Asked per source, not once for the hub: `sources: [glasses]` is enabled
	// and must still refuse the dashboard. The refusal is the same either way —
	// a page learns that this hub does not want its trail, and nothing about
	// why (Task 20311).
	if !s.telemetryCollects(src) {
		apierror.WriteError(w, apierror.New(apierror.CodeNotFound, "telemetry collection is disabled on this hub"))
		return
	}

	limitJSONBody(w, r, telemetryMaxBodyBytes)
	var batch telemetry.Batch
	if err := json.NewDecoder(r.Body).Decode(&batch); err != nil {
		respondToBodyError(w, err)
		return
	}

	events := telemetry.Normalize(batch, telemetry.Context{
		Source:    src,
		At:        time.Now().UTC(),
		UserAgent: r.UserAgent(),
		ClientIP:  clientIP(r),
		Actor:     s.telemetryActor(r),
	})
	if len(events) == 0 {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	// Errors are additionally written to the structured logger, so that a hub
	// whose operator reads journald sees them without opening a panel, and so
	// that the behaviour predating this route is preserved for the events it
	// used to carry.
	s.logTelemetryErrors(r, events)

	db, err := s.controlPlaneDB()
	if err != nil {
		// Logged, not returned. A page cannot act on a storage failure, and
		// the one thing it must not do is retry.
		s.log().Warn(logger.EventStep, 0, "telemetry: open control-plane db",
			map[string]interface{}{"error": err.Error()})
		w.WriteHeader(http.StatusNoContent)
		return
	}
	defer db.Close()

	if err := db.AppendTelemetry(events); err != nil {
		s.log().Warn(logger.EventStep, 0, "telemetry: append batch",
			map[string]interface{}{"error": err.Error(), "events": len(events)})
	}
	w.WriteHeader(http.StatusNoContent)
}

// telemetryActor names the identity behind a batch, or "" when the request
// carries no credential — which is a normal case here, not an error.
func (s *Server) telemetryActor(r *http.Request) string {
	label := s.grantFor(r).subjectLabel()
	if label == "anonymous" {
		return ""
	}
	return label
}

// logTelemetryErrors mirrors error-kind events into the structured logger.
func (s *Server) logTelemetryErrors(r *http.Request, events []telemetry.Event) {
	for _, e := range events {
		if e.Kind != telemetry.KindError && e.Kind != telemetry.KindRejection {
			continue
		}
		msg := e.Message
		if msg == "" {
			msg = "(no message)"
		}
		s.log().WithContext(r.Context()).Error("client_error", 0, msg, map[string]interface{}{
			"kind":       string(e.Kind),
			"source":     string(e.Source),
			"session":    e.Session,
			"seq":        e.Seq,
			"view":       e.View,
			"client_url": e.URL,
			"user_agent": e.UserAgent,
			"client_ip":  e.ClientIP,
			"stack":      e.Stack,
		})
	}
}

// telemetryPolicy reads the hub's collection policy.
//
// Through the per-instance overlay (Task 20318), like the hub's other per-hub
// settings: where two dashboards share a working directory, whether one of
// them records its users is that hub's decision, and the panel saves it into
// that hub's overlay (see handleTelemetrySettingsSave).
//
// A config that will not load yields the zero policy, which collects nothing.
// That is the opposite of what this function used to do, and the change is the
// point of Task 20311: recording other people's browsing is not a behaviour to
// fall back into when the file that governs it is unreadable.
func (s *Server) telemetryPolicy() config.TelemetryConfig {
	cfg, err := s.loadHubConfig()
	if err != nil || cfg == nil {
		return config.TelemetryConfig{}
	}
	return cfg.UI.Telemetry
}

// telemetryEnabled reports whether collection is on at all — the master switch,
// for the places that need to describe the hub rather than admit one batch.
func (s *Server) telemetryEnabled() bool {
	return s.telemetryPolicy().Effective()
}

// telemetryCollects reports whether one front end's trail may be stored.
func (s *Server) telemetryCollects(src telemetry.Source) bool {
	return s.telemetryPolicy().Collects(string(src))
}

// ── read-back ───────────────────────────────────────────────────────────────

// telemetryEventJSON is the wire shape of one event.
//
// Declared here rather than marshalling telemetry.Event so the frontend
// contract does not move when a Go field is renamed, and so timestamps ship as
// formatted strings rather than as whatever Go's default happens to be.
type telemetryEventJSON struct {
	ID           int64  `json:"id"`
	At           string `json:"at"`
	ClientMillis int64  `json:"client_millis,omitempty"`
	Source       string `json:"source"`
	Kind         string `json:"kind"`
	Session      string `json:"session"`
	Seq          int64  `json:"seq"`
	Message      string `json:"message,omitempty"`
	Stack        string `json:"stack,omitempty"`
	URL          string `json:"url,omitempty"`
	View         string `json:"view,omitempty"`
	Detail       string `json:"detail,omitempty"`
	UserAgent    string `json:"user_agent,omitempty"`
	ClientIP     string `json:"client_ip,omitempty"`
	Actor        string `json:"actor,omitempty"`
	Release      string `json:"release,omitempty"`
}

type telemetryListResponse struct {
	Events  []telemetryEventJSON `json:"events"`
	Total   int                  `json:"total"`
	Limit   int                  `json:"limit"`
	Offset  int                  `json:"offset"`
	HasMore bool                 `json:"has_more"`
	Enabled bool                 `json:"enabled"`

	// Kinds and Sources populate the filter controls so the panel offers the
	// vocabulary this build actually records rather than a list hard-coded in
	// JavaScript that drifts from the Go constants.
	Kinds   []string `json:"kinds"`
	Sources []string `json:"sources"`
}

type telemetrySessionsResponse struct {
	Sessions []statedb.TelemetrySession `json:"sessions"`
	Enabled  bool                       `json:"enabled"`
}

// handleTelemetryList serves GET /api/telemetry.
func (s *Server) handleTelemetryList(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		apierror.WriteError(w, apierror.New(apierror.CodeMethodNotAllowed, "GET required"))
		return
	}

	filter, err := telemetryFilterFromQuery(r)
	if err != nil {
		apierror.WriteError(w, apierror.New(apierror.CodeInvalidInput, err.Error()))
		return
	}

	db, err := s.controlPlaneDB()
	if err != nil {
		s.log().Error(logger.EventStep, 0, "telemetry: open control-plane db",
			map[string]interface{}{"error": err.Error()})
		apierror.WriteError(w, apierror.New(apierror.CodeInternal, "could not open the telemetry store"))
		return
	}
	defer db.Close()

	rows, total, err := db.QueryTelemetry(filter)
	if err != nil {
		s.log().Error(logger.EventStep, 0, "telemetry: query",
			map[string]interface{}{"error": err.Error()})
		apierror.WriteError(w, apierror.New(apierror.CodeInternal, "could not read telemetry"))
		return
	}

	resp := telemetryListResponse{
		Events:  make([]telemetryEventJSON, 0, len(rows)),
		Total:   total,
		Limit:   filter.Limit,
		Offset:  filter.Offset,
		HasMore: filter.Offset+len(rows) < total,
		Enabled: s.telemetryEnabled(),
		Sources: []string{string(telemetry.SourceDashboard), string(telemetry.SourceGlasses)},
	}
	for _, k := range telemetry.Kinds {
		resp.Kinds = append(resp.Kinds, string(k))
	}
	for _, e := range rows {
		resp.Events = append(resp.Events, telemetryEventJSON{
			ID:           e.ID,
			At:           e.At.UTC().Format(time.RFC3339Nano),
			ClientMillis: e.ClientMillis,
			Source:       string(e.Source),
			Kind:         string(e.Kind),
			Session:      e.Session,
			Seq:          e.Seq,
			Message:      e.Message,
			Stack:        e.Stack,
			URL:          e.URL,
			View:         e.View,
			Detail:       e.Detail,
			UserAgent:    e.UserAgent,
			ClientIP:     e.ClientIP,
			Actor:        e.Actor,
			Release:      e.Release,
		})
	}
	jsonOK(w, resp)
}

// handleTelemetrySessions serves GET /api/telemetry/sessions.
func (s *Server) handleTelemetrySessions(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		apierror.WriteError(w, apierror.New(apierror.CodeMethodNotAllowed, "GET required"))
		return
	}

	source := strings.TrimSpace(r.URL.Query().Get("source"))
	if source != "" && !telemetry.Source(source).Valid() {
		apierror.WriteError(w, apierror.New(apierror.CodeInvalidInput,
			"source must be "+string(telemetry.SourceDashboard)+" or "+string(telemetry.SourceGlasses)))
		return
	}
	limit, err := telemetryIntParam(r, "limit", 100, statedb.TelemetryMaxLimit)
	if err != nil {
		apierror.WriteError(w, apierror.New(apierror.CodeInvalidInput, err.Error()))
		return
	}

	db, err := s.controlPlaneDB()
	if err != nil {
		s.log().Error(logger.EventStep, 0, "telemetry: open control-plane db",
			map[string]interface{}{"error": err.Error()})
		apierror.WriteError(w, apierror.New(apierror.CodeInternal, "could not open the telemetry store"))
		return
	}
	defer db.Close()

	sessions, err := db.ListTelemetrySessions(source, limit)
	if err != nil {
		s.log().Error(logger.EventStep, 0, "telemetry: list sessions",
			map[string]interface{}{"error": err.Error()})
		apierror.WriteError(w, apierror.New(apierror.CodeInternal, "could not read telemetry sessions"))
		return
	}
	if sessions == nil {
		sessions = []statedb.TelemetrySession{}
	}
	jsonOK(w, telemetrySessionsResponse{Sessions: sessions, Enabled: s.telemetryEnabled()})
}

// telemetryFilterFromQuery builds the store filter from the query string,
// rejecting values outside the closed sets rather than silently ignoring them:
// a reader who mistypes a kind should be told, not shown an unfiltered page
// they will read as filtered.
func telemetryFilterFromQuery(r *http.Request) (statedb.TelemetryFilter, error) {
	q := r.URL.Query()
	f := statedb.TelemetryFilter{
		Source:  strings.TrimSpace(q.Get("source")),
		Kind:    strings.TrimSpace(q.Get("kind")),
		Session: strings.TrimSpace(q.Get("session")),
		Search:  strings.TrimSpace(q.Get("q")),
	}
	if f.Source != "" && !telemetry.Source(f.Source).Valid() {
		return f, fmt.Errorf("unknown source %q", f.Source)
	}
	if f.Kind != "" && !telemetry.Kind(f.Kind).Valid() {
		return f, fmt.Errorf("unknown kind %q", f.Kind)
	}
	if v := strings.TrimSpace(q.Get("since")); v != "" {
		ts, err := time.Parse(time.RFC3339, v)
		if err != nil {
			return f, fmt.Errorf("since must be an RFC3339 timestamp")
		}
		f.Since = ts
	}
	var err error
	if f.Limit, err = telemetryIntParam(r, "limit", 200, statedb.TelemetryMaxLimit); err != nil {
		return f, err
	}
	if f.Offset, err = telemetryIntParam(r, "offset", 0, 1<<30); err != nil {
		return f, err
	}
	return f, nil
}

// telemetryIntParam reads a bounded non-negative integer, falling back to def
// when absent.
func telemetryIntParam(r *http.Request, name string, def, max int) (int, error) {
	raw := strings.TrimSpace(r.URL.Query().Get(name))
	if raw == "" {
		return def, nil
	}
	n, err := strconv.Atoi(raw)
	if err != nil {
		return 0, fmt.Errorf("%s must be a number", name)
	}
	if n < 0 {
		return 0, fmt.Errorf("%s must not be negative", name)
	}
	if n > max {
		n = max
	}
	return n, nil
}
