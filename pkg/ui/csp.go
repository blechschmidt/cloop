package ui

// Content-Security-Policy, and the endpoint browsers report violations to
// (Task 20408).
//
// The policy is the last line under the dashboard's escaping. The workload is
// hostile by the threat model and writes much of what the dashboard renders —
// task titles, summaries, output, feature names — and a project's directory
// name is chosen by anyone who may create one. Every innerHTML site is one
// missed esc() away from markup somebody else wrote, and until this task the
// policy let that markup run: script-src carried 'unsafe-inline' because the
// page was built from inline handlers, and a project named with the literal
// text &quot; closed the string an onclick attribute spliced it into. Now:
//
//   - script-src 'self', with neither 'unsafe-inline' nor 'unsafe-eval': only
//     the hub's own script files run. The dashboard routes every control
//     through one delegated dispatcher (assets/js/00-core.js), the glasses
//     page and the theme bootstrap are assets of their own, and the sign-in
//     documents load oidcauth's script — none of them carries inline script.
//   - base-uri 'none', form-action 'self' and object-src 'none', which do not
//     fall back to default-src: injected markup cannot re-point the page's
//     relative URLs, post a form off the hub, or load a plugin.
//   - style-src keeps 'unsafe-inline'. Inline styles are everywhere in the
//     markup, and the escape they open is styling, not script; out of scope
//     here, and the threat model says so.
//
// It is one policy for every response the hub sends, documents and API
// answers alike, so TestContentSecurityPolicyOnEveryDocument can assert it
// exactly; only frame-src (the identity provider, for silent renewal) and
// frame-ancestors (the two renewal documents) vary, and only with the hub's
// configuration.
//
// The report endpoint is how a mistake in all this shows up. Under the old
// policy a missed inline handler was a working button; under this one it is a
// button that does nothing, and nothing says why. So the policy names a
// same-origin endpoint, and every violation a browser reports is counted in
// cloop_csp_violations_total — by directive and by which of the hub's
// documents it was — and, within a budget, logged and recorded as a telemetry
// event where telemetry is on. Counted as reported: the endpoint cannot tell a
// browser's report from one written by hand, so a count is a reason to read
// the log lines' addresses and actors, not proof on its own. It is public because the documents that most
// need it carry no credential the browser would send with a report: the
// glasses page authenticates with a header its script adds, and the sign-in
// documents are shown to someone who is not signed in yet.

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/blechschmidt/cloop/pkg/hubmetrics"
	"github.com/blechschmidt/cloop/pkg/jsonbody"
	"github.com/blechschmidt/cloop/pkg/logger"
	"github.com/blechschmidt/cloop/pkg/telemetry"
)

// cspReportPath is where browsers send violation reports, named by the
// policy's report-uri.
//
// report-uri alone, not report-to beside it. A browser that knows report-to
// ignores report-uri when both are present, and report-to delivers through
// the Reporting API: batched, later, and only to an endpoint the browser
// considers trustworthy — a hub reached over plain HTTP on a LAN address gets
// nothing. Measured on Chrome 151 against this endpoint, report-uri arrived at
// once and report-to not at all inside ninety seconds. Deprecated in CSP3,
// report-uri is still what every current browser sends.
const cspReportPath = "/api/csp-report"

// cspReportMediaTypes are what a browser sends a report as: report-uri's
// application/csp-report, and the Reporting API's application/reports+json
// for a browser that converts. Both are JSON, and neither is a type a form on
// another page can produce.
var cspReportMediaTypes = []string{"application/csp-report", "application/reports+json"}

// contentSecurityPolicy is the policy every response carries. frameAncestors
// is 'none', or 'self' for the two documents the renewal frame loads.
func (s *Server) contentSecurityPolicy(frameAncestors string) string {
	return "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; " +
		"img-src 'self' data:; connect-src 'self'; " + s.frameSrcDirective() +
		"; frame-ancestors " + frameAncestors +
		"; base-uri 'none'; form-action 'self'; object-src 'none'" +
		"; report-uri " + cspReportPath
}

// cspReportMaxBytes caps a report POST: a Reporting API batch of a few
// reports, each with a 40-character sample, is a few kilobytes.
const cspReportMaxBytes int64 = 64 << 10

// cspReportMaxEach bounds the reports one POST is read for. A browser batches
// a page's reports; a page producing more than this between deliveries is
// looping, and the count of the first few says so.
const cspReportMaxEach = 32

// The recording budgets: a log line and, where telemetry is on, a row per
// violation, each drawn from one of two token buckets for the whole hub
// process, chosen by who sent the report.
//
// A signed-in browser's reports draw on the first: they carry its session
// cookie, which a browser sends with a same-origin report, and so does every
// report on a hub that asks for no credential at all. Every other report is
// anonymous — the glasses page and a static-token dashboard, whose
// credential is a header their scripts add, a sign-in error page, and anyone
// at all who can reach the hub — and draws on the second. That one is small
// enough that nobody can flood the log through it or push the telemetry
// table's history out (the table keeps its newest statedb.TelemetryMaxRows
// rows, so at this rate a flood takes weeks to turn it over), and anonymous
// senders cannot empty the bucket signed-in users' reports draw on. The
// counter is not budgeted — it is a few atomic adds — so it stays exact
// however many reports the budgets turn away.
const (
	cspSignedBurst     = 30
	cspSignedPerMinute = 60
	cspAnonBurst       = 10
	cspAnonPerMinute   = 1
)

// cspBudgets is the two buckets.
type cspBudgets struct {
	signed, anonymous cspRecordBudget
}

// take reports whether one more violation may be recorded at now, from the
// bucket of a signed-in or an anonymous sender.
func (b *cspBudgets) take(signed bool, now time.Time) bool {
	if signed {
		return b.signed.take(now, cspSignedBurst, cspSignedPerMinute)
	}
	return b.anonymous.take(now, cspAnonBurst, cspAnonPerMinute)
}

// cspRecordBudget is a token bucket. Its zero value is full.
type cspRecordBudget struct {
	mu     sync.Mutex
	tokens float64
	at     time.Time
}

// take reports whether one more violation may be recorded at now, from a
// bucket of burst tokens refilled at perMinute.
func (b *cspRecordBudget) take(now time.Time, burst, perMinute float64) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.at.IsZero() {
		b.tokens = burst
	} else if d := now.Sub(b.at); d > 0 {
		b.tokens += d.Minutes() * perMinute
		if b.tokens > burst {
			b.tokens = burst
		}
	}
	b.at = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// cspDirectives is the closed set the metric's directive label takes; any
// other value a report names is "other".
var cspDirectives = map[string]bool{
	"script-src-attr": true, "script-src-elem": true, "script-src": true,
	"style-src-attr": true, "style-src-elem": true, "style-src": true,
	"img-src": true, "connect-src": true, "frame-src": true, "frame-ancestors": true,
	"base-uri": true, "form-action": true, "object-src": true, "default-src": true,
	"worker-src": true, "font-src": true, "media-src": true, "manifest-src": true,
}

// cspViolation is one report, in either format, reduced to what is counted
// and recorded.
type cspViolation struct {
	directive   string // effective directive, as reported
	documentURL string
	blocked     string // "inline", "eval", or a URL
	sourceFile  string
	line, col   int
	sample      string
	disposition string // "enforce" or "report"
}

// directiveLabel maps the reported directive onto cspDirectives.
func (v cspViolation) directiveLabel() string {
	d := strings.ToLower(strings.TrimSpace(v.directive))
	if cspDirectives[d] {
		return d
	}
	return "other"
}

// documentLabel names which of the hub's documents the report is about, from
// its URL's path. A sender writes the URL, so anything unrecognised is "other".
func (v cspViolation) documentLabel() string {
	u, err := url.Parse(strings.TrimSpace(v.documentURL))
	if err != nil {
		return "other"
	}
	switch p := u.Path; {
	case p == "/" || p == "":
		return "dashboard"
	case p == "/glasses":
		return "glasses"
	case strings.HasPrefix(p, "/auth/"):
		return "sign-in"
	}
	return "other"
}

// legacyCSPReport is a report-uri report: {"csp-report": {...}}.
type legacyCSPReport struct {
	Report *struct {
		DocumentURI        string `json:"document-uri"`
		BlockedURI         string `json:"blocked-uri"`
		ViolatedDirective  string `json:"violated-directive"`
		EffectiveDirective string `json:"effective-directive"`
		SourceFile         string `json:"source-file"`
		LineNumber         int    `json:"line-number"`
		ColumnNumber       int    `json:"column-number"`
		ScriptSample       string `json:"script-sample"`
		Disposition        string `json:"disposition"`
	} `json:"csp-report"`
}

// reportingAPIReport is one entry of a Reporting API batch.
type reportingAPIReport struct {
	Type string `json:"type"`
	URL  string `json:"url"`
	Body struct {
		DocumentURL        string `json:"documentURL"`
		BlockedURL         string `json:"blockedURL"`
		EffectiveDirective string `json:"effectiveDirective"`
		SourceFile         string `json:"sourceFile"`
		LineNumber         int    `json:"lineNumber"`
		ColumnNumber       int    `json:"columnNumber"`
		Sample             string `json:"sample"`
		Disposition        string `json:"disposition"`
	} `json:"body"`
}

// parseCSPReports reads either format: a Reporting API batch is an array, a
// report-uri report an object. Entries of any other type, and any past
// cspReportMaxEach, are skipped.
func parseCSPReports(raw json.RawMessage) ([]cspViolation, error) {
	raw = bytes.TrimSpace(raw)
	if len(raw) > 0 && raw[0] == '[' {
		var batch []reportingAPIReport
		if err := json.Unmarshal(raw, &batch); err != nil {
			return nil, err
		}
		var out []cspViolation
		for _, r := range batch {
			if len(out) == cspReportMaxEach {
				break
			}
			if r.Type != "csp-violation" {
				continue
			}
			doc := r.Body.DocumentURL
			if doc == "" {
				doc = r.URL
			}
			out = append(out, cspViolation{
				directive: r.Body.EffectiveDirective, documentURL: doc, blocked: r.Body.BlockedURL,
				sourceFile: r.Body.SourceFile, line: r.Body.LineNumber, col: r.Body.ColumnNumber,
				sample: r.Body.Sample, disposition: r.Body.Disposition,
			})
		}
		return out, nil
	}
	var legacy legacyCSPReport
	if err := json.Unmarshal(raw, &legacy); err != nil {
		return nil, err
	}
	if legacy.Report == nil {
		return nil, nil
	}
	r := legacy.Report
	d := r.EffectiveDirective
	if d == "" {
		// Older browsers name only the violated directive, as written in the
		// policy: its first token is the directive's name.
		d, _, _ = strings.Cut(strings.TrimSpace(r.ViolatedDirective), " ")
	}
	return []cspViolation{{
		directive: d, documentURL: r.DocumentURI, blocked: r.BlockedURI,
		sourceFile: r.SourceFile, line: r.LineNumber, col: r.ColumnNumber,
		sample: r.ScriptSample, disposition: r.Disposition,
	}}, nil
}

// handleCSPReport serves POST /api/csp-report.
//
// Always 204 for a report it could read, kept or not: a browser does not read
// the answer, and nobody else needs to learn from it what was recorded.
func (s *Server) handleCSPReport(w http.ResponseWriter, r *http.Request) {
	var raw json.RawMessage
	if !jsonbody.Decode(w, r, &raw, jsonbody.Options{Limit: cspReportMaxBytes, MediaTypes: cspReportMediaTypes}) {
		return
	}
	reports, err := parseCSPReports(raw)
	if err != nil {
		jsonErr(w, "not a Content-Security-Policy report: "+err.Error(), http.StatusBadRequest)
		return
	}
	now := time.Now()
	if s.cspClock != nil {
		now = s.cspClock()
	}
	// Who sent it, read without counting the report as the user being active
	// — a page reports on its own behalf. Not grantFor: this route is served
	// before authentication, and a grant there takes a request without a
	// session for the static token's.
	id := s.OIDC.PeekIdentity(r)
	actor := subjectFromIdentity(id).Label()
	if actor == "anonymous" {
		actor = ""
	}
	signed := id != nil || s.openHub()
	var record []telemetry.WireEvent
	var sources []telemetry.Source
	for _, v := range reports {
		directive, document := v.directiveLabel(), v.documentLabel()
		hubmetrics.CSPViolations.Inc(directive, document)
		if !s.cspBudget.take(signed, now) {
			continue
		}
		// Scrubbed like a telemetry row, before anything is made of them: the
		// glasses page's URL carries its token, and a report's URLs are
		// whatever the sender wrote.
		blocked := truncate(telemetry.Scrub(v.blocked), 512)
		sourceFile := truncate(telemetry.Scrub(v.sourceFile), 512)
		sample := truncate(telemetry.Scrub(v.sample), 128)
		disposition := truncate(v.disposition, 16)
		s.log().WithContext(r.Context()).Warn("csp_violation", 0,
			directive+" blocked "+truncate(blocked, 200)+" on the "+document+" page", map[string]interface{}{
				"directive":    directive,
				"document":     document,
				"blocked":      blocked,
				"source_file":  sourceFile,
				"line":         v.line,
				"column":       v.col,
				"sample":       sample,
				"disposition":  disposition,
				"document_url": truncate(telemetry.Scrub(v.documentURL), 512),
				"client_ip":    s.clientIP(r),
				"actor":        actor,
			})
		// Without HTML escaping: json.Marshal writes '&' as \u0026, and the
		// scrubber Normalize runs over Detail would then read "\u0026code=" as
		// a key it does not know and keep the value.
		var detail bytes.Buffer
		enc := json.NewEncoder(&detail)
		enc.SetEscapeHTML(false)
		_ = enc.Encode(map[string]any{
			"directive": directive, "blocked": blocked, "source_file": sourceFile,
			"line": v.line, "column": v.col, "sample": sample, "disposition": disposition,
		})
		record = append(record, telemetry.WireEvent{
			Kind:    string(telemetry.KindCSP),
			Message: directive + " blocked " + blocked,
			URL:     v.documentURL,
			View:    document,
			Detail:  strings.TrimSuffix(detail.String(), "\n"),
		})
		src := telemetry.SourceDashboard
		if document == "glasses" {
			src = telemetry.SourceGlasses
		}
		sources = append(sources, src)
	}
	s.recordCSPTelemetry(r, actor, record, sources)
	w.WriteHeader(http.StatusNoContent)
}

// recordCSPTelemetry stores the recorded violations as telemetry events, each
// under its document's front end and only where that front end's trail is
// collected (Task 20311), stamped with actor: the signed-in sender, or nobody.
// A storage failure is logged, as ingest logs it.
func (s *Server) recordCSPTelemetry(r *http.Request, actor string, record []telemetry.WireEvent, sources []telemetry.Source) {
	var events []telemetry.Event
	for i, we := range record {
		if !s.telemetryCollects(sources[i]) {
			continue
		}
		we.Seq = int64(i)
		events = append(events, telemetry.Normalize(telemetry.Batch{Session: "csp-report", Events: []telemetry.WireEvent{we}},
			telemetry.Context{
				Source:    sources[i],
				At:        time.Now().UTC(),
				UserAgent: r.UserAgent(),
				ClientIP:  s.clientIP(r),
				Actor:     actor,
			})...)
	}
	if len(events) == 0 {
		return
	}
	db, err := s.controlPlaneDB()
	if err != nil {
		s.log().Warn(logger.EventStep, 0, "csp report: open control-plane db",
			map[string]interface{}{"error": err.Error()})
		return
	}
	defer db.Close()
	if err := db.AppendTelemetry(events); err != nil {
		s.log().Warn(logger.EventStep, 0, "csp report: append telemetry",
			map[string]interface{}{"error": err.Error(), "events": strconv.Itoa(len(events))})
	}
}
