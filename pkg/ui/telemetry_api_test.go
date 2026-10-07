package ui

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/internal/statedbtest"
	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
	"github.com/blechschmidt/cloop/pkg/telemetry"
)

// telemetryServer returns a Server whose control-plane database exists, which
// ingest needs because it writes there, and whose config switches collection on.
//
// The switch is explicit because collection is off by default (Task 20311).
// Every test below this line is about the mechanics of ingest, storage and
// read-back, and each one would otherwise be asserting the default rather than
// the thing it names. The default itself is tested by
// TestTelemetry_DefaultsToOff, which builds its server without this helper.
func telemetryServer(t *testing.T) *Server {
	t.Helper()
	srv := telemetryServerUnconfigured(t)
	writeTelemetryConfig(t, srv.WorkDir, true)
	return srv
}

// telemetryServerUnconfigured is the same hub with no telemetry configuration
// at all — the state a fresh deployment is in.
func telemetryServerUnconfigured(t *testing.T) *Server {
	t.Helper()
	dir := statedbtest.Dir(t)
	if _, err := state.Init(dir, "telemetry test", 1); err != nil {
		t.Fatalf("init project: %v", err)
	}
	return New(dir, 0, "")
}

func postTelemetry(t *testing.T, srv *Server, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	buf, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(buf))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	if strings.Contains(path, "/glasses/") {
		srv.handleGlassesTelemetryIngest(w, req)
	} else {
		srv.handleTelemetryIngest(w, req)
	}
	return w
}

func readTelemetry(t *testing.T, srv *Server, query string) telemetryListResponse {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/api/telemetry"+query, nil)
	w := httptest.NewRecorder()
	srv.handleTelemetryList(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("GET /api/telemetry%s = %d: %s", query, w.Code, w.Body.String())
	}
	var resp telemetryListResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v (body=%s)", err, w.Body.String())
	}
	return resp
}

// TestTelemetry_RoundTrip is the whole point of the feature in one test: a page
// posts a trail, an operator reads it back.
func TestTelemetry_RoundTrip(t *testing.T) {
	srv := telemetryServer(t)

	w := postTelemetry(t, srv, "/api/telemetry", map[string]any{
		"source":  "dashboard",
		"session": "abc123",
		"release": "b1",
		"events": []map[string]any{
			{"kind": "lifecycle", "seq": 1, "ts": 1, "message": "page load"},
			{"kind": "view", "seq": 2, "ts": 2, "message": "tasks"},
			{"kind": "error", "seq": 3, "ts": 3, "message": "boom", "stack": "at f()"},
		},
	})
	if w.Code != http.StatusNoContent {
		t.Fatalf("ingest = %d, want 204: %s", w.Code, w.Body.String())
	}

	resp := readTelemetry(t, srv, "")
	if resp.Total != 3 || len(resp.Events) != 3 {
		t.Fatalf("read back %d events (total %d), want 3", len(resp.Events), resp.Total)
	}
	if resp.Events[0].Seq != 3 || resp.Events[0].Kind != "error" {
		t.Errorf("newest event = seq %d kind %q, want seq 3 kind error",
			resp.Events[0].Seq, resp.Events[0].Kind)
	}
	if resp.Events[0].Session != "abc123" || resp.Events[0].Release != "b1" {
		t.Errorf("batch-level fields lost: %+v", resp.Events[0])
	}
	// The filter vocabulary must come from the Go constants, not from a list
	// hard-coded in JavaScript that drifts from them.
	if len(resp.Kinds) != len(telemetry.Kinds) || len(resp.Sources) != 2 {
		t.Errorf("kinds/sources = %v / %v, want the full vocabulary", resp.Kinds, resp.Sources)
	}
}

// TestTelemetry_GlassesRouteStampsItsOwnSource: the source is decided by the
// route, not by the payload, or a dashboard could file events into the glasses
// trail and make an investigation read the wrong device.
func TestTelemetry_GlassesRouteStampsItsOwnSource(t *testing.T) {
	srv := telemetryServer(t)

	w := postTelemetry(t, srv, "/api/glasses/telemetry", map[string]any{
		"source":  "dashboard", // a lie
		"session": "g1",
		"events":  []map[string]any{{"kind": "gesture", "seq": 1, "message": "next"}},
	})
	if w.Code != http.StatusNoContent {
		t.Fatalf("ingest = %d, want 204", w.Code)
	}

	resp := readTelemetry(t, srv, "?source=glasses")
	if len(resp.Events) != 1 {
		t.Fatalf("got %d glasses events, want 1 — the payload's claim was believed",
			len(resp.Events))
	}
	if resp.Events[0].Source != "glasses" {
		t.Errorf("source = %q, want glasses", resp.Events[0].Source)
	}
}

// TestTelemetry_ScrubsCredentialsBeforeStorage is the security property that
// justifies collecting URLs at all. The glasses link carries its bearer token
// in the page URL, so an unscrubbed trail copies a live thirty-day credential
// into a table a different permission can read.
func TestTelemetry_ScrubsCredentialsBeforeStorage(t *testing.T) {
	srv := telemetryServer(t)

	const live = "cloop_glasses_7f3a_2b91ccd04e5f"
	postTelemetry(t, srv, "/api/glasses/telemetry", map[string]any{
		"session": "g1",
		"events": []map[string]any{{
			"kind":    "fetch",
			"seq":     1,
			"message": "GET /glasses?token=" + live + " failed",
			"url":     "https://hub.example.com/glasses?token=" + live,
			"detail":  `{"href":"/glasses?token=` + live + `"}`,
		}},
	})

	resp := readTelemetry(t, srv, "")
	if len(resp.Events) != 1 {
		t.Fatalf("got %d events, want 1", len(resp.Events))
	}
	blob, _ := json.Marshal(resp.Events[0])
	if strings.Contains(string(blob), live) {
		t.Fatalf("a live credential survived into storage:\n%s", blob)
	}
	if !strings.Contains(resp.Events[0].URL, "/glasses") {
		t.Errorf("URL = %q — scrubbing destroyed the path too, which is the "+
			"part worth reading", resp.Events[0].URL)
	}
}

// TestTelemetry_IngestAlwaysAnswers204: a page must not learn from a status
// code whether its events were kept. A reporting client that retried on
// failure would amplify exactly the runaway-loop case the caps exist to
// contain.
func TestTelemetry_IngestAlwaysAnswers204(t *testing.T) {
	srv := telemetryServer(t)

	cases := []struct {
		name string
		body any
	}{
		{"empty batch", map[string]any{"events": []any{}}},
		{"no events key", map[string]any{"session": "x"}},
		{"unknown kind", map[string]any{"events": []map[string]any{{"kind": "telepathy", "message": "m"}}}},
		{"nothing legible", map[string]any{"events": []map[string]any{{"kind": "note"}}}},
		{"hostile session", map[string]any{
			"session": "'; DROP TABLE telemetry_events--",
			"events":  []map[string]any{{"kind": "note", "message": "m"}},
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if w := postTelemetry(t, srv, "/api/telemetry", tc.body); w.Code != http.StatusNoContent {
				t.Errorf("got %d, want 204: %s", w.Code, w.Body.String())
			}
		})
	}

	// The table must still be readable after all of that.
	if _, err := json.Marshal(readTelemetry(t, srv, "")); err != nil {
		t.Fatalf("the store is unreadable after hostile input: %v", err)
	}
}

func TestTelemetry_IngestRejectsNonPOST(t *testing.T) {
	srv := telemetryServer(t)
	for _, m := range []string{http.MethodGet, http.MethodPut, http.MethodDelete} {
		req := httptest.NewRequest(m, "/api/telemetry", nil)
		w := httptest.NewRecorder()
		srv.handleTelemetryIngest(w, req)
		if w.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s: got %d, want 405", m, w.Code)
		}
	}
}

func TestTelemetry_IngestRejectsMalformedJSON(t *testing.T) {
	srv := telemetryServer(t)
	req := httptest.NewRequest(http.MethodPost, "/api/telemetry", strings.NewReader("not json"))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.handleTelemetryIngest(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("got %d, want 400", w.Code)
	}
}

// TestTelemetry_IngestBodyIsCappedBelowTheDefault: this is the one route that
// takes a body without requiring a permission, so it must not inherit the
// 10 MiB default that every other handler uses.
func TestTelemetry_IngestBodyIsCappedBelowTheDefault(t *testing.T) {
	srv := telemetryServer(t)

	if telemetryMaxBodyBytes >= srv.effectiveMaxBodyBytes() {
		t.Fatalf("telemetry body cap is %d, not below the %d default",
			telemetryMaxBodyBytes, srv.effectiveMaxBodyBytes())
	}

	huge := strings.Repeat("x", int(telemetryMaxBodyBytes)+1024)
	req := httptest.NewRequest(http.MethodPost, "/api/telemetry",
		strings.NewReader(`{"events":[{"kind":"note","message":"`+huge+`"}]}`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.handleTelemetryIngest(w, req)
	if w.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("got %d, want 413", w.Code)
	}
}

// TestTelemetry_ErrorsReachTheStructuredLogger keeps the behaviour that
// predated this route: an operator who reads journald and never opens the
// panel must still see browser errors.
func TestTelemetry_ErrorsReachTheStructuredLogger(t *testing.T) {
	srv := telemetryServer(t)
	cap := &captureLogger{}
	srv.Log = cap

	postTelemetry(t, srv, "/api/telemetry", map[string]any{
		"session": "s1",
		"events": []map[string]any{
			{"kind": "gesture", "seq": 1, "message": "swipe"},  // not logged
			{"kind": "error", "seq": 2, "message": "boom"},     // logged
			{"kind": "rejection", "seq": 3, "message": "nope"}, // logged
		},
	})

	var logged []string
	for _, e := range cap.snapshot() {
		if e.Event == "client_error" {
			logged = append(logged, e.Message)
		}
	}
	if len(logged) != 2 {
		t.Fatalf("logged %v, want exactly the error and the rejection", logged)
	}
}

func TestTelemetry_Filters(t *testing.T) {
	srv := telemetryServer(t)

	postTelemetry(t, srv, "/api/telemetry", map[string]any{
		"session": "s1",
		"events": []map[string]any{
			{"kind": "gesture", "seq": 1, "message": "swipe right"},
			{"kind": "error", "seq": 2, "message": "kaboom"},
		},
	})
	postTelemetry(t, srv, "/api/glasses/telemetry", map[string]any{
		"session": "s2",
		"events":  []map[string]any{{"kind": "gesture", "seq": 1, "message": "swipe left"}},
	})

	cases := []struct {
		query string
		want  int
	}{
		{"", 3},
		{"?source=glasses", 1},
		{"?source=dashboard", 2},
		{"?kind=error", 1},
		{"?session=s2", 1},
		{"?q=swipe", 2},
		{"?limit=1", 1},
	}
	for _, tc := range cases {
		t.Run("query"+tc.query, func(t *testing.T) {
			if got := len(readTelemetry(t, srv, tc.query).Events); got != tc.want {
				t.Errorf("%q returned %d events, want %d", tc.query, got, tc.want)
			}
		})
	}
}

// TestTelemetry_ReadRejectsUnknownFilterValues: a reader who mistypes a kind
// must be told, not shown an unfiltered page they will read as filtered.
func TestTelemetry_ReadRejectsUnknownFilterValues(t *testing.T) {
	srv := telemetryServer(t)
	for _, q := range []string{"?source=nope", "?kind=nope", "?since=yesterday", "?limit=abc", "?offset=-1"} {
		req := httptest.NewRequest(http.MethodGet, "/api/telemetry"+q, nil)
		w := httptest.NewRecorder()
		srv.handleTelemetryList(w, req)
		if w.Code != http.StatusBadRequest {
			t.Errorf("%q returned %d, want 400", q, w.Code)
		}
	}
}

func TestTelemetry_Sessions(t *testing.T) {
	srv := telemetryServer(t)

	postTelemetry(t, srv, "/api/glasses/telemetry", map[string]any{
		"session": "g1",
		"events": []map[string]any{
			{"kind": "lifecycle", "seq": 1, "message": "load"},
			{"kind": "error", "seq": 2, "message": "boom"},
		},
	})

	req := httptest.NewRequest(http.MethodGet, "/api/telemetry/sessions", nil)
	w := httptest.NewRecorder()
	srv.handleTelemetrySessions(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("got %d: %s", w.Code, w.Body.String())
	}
	var resp telemetrySessionsResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(resp.Sessions) != 1 {
		t.Fatalf("got %d sessions, want 1", len(resp.Sessions))
	}
	if resp.Sessions[0].Events != 2 || resp.Sessions[0].Errors != 1 {
		t.Errorf("roll-up = %d events / %d errors, want 2/1",
			resp.Sessions[0].Events, resp.Sessions[0].Errors)
	}
}

// TestTelemetry_DisabledRefusesIngest proves the operator switch actually
// closes the door rather than silently discarding, so a deployment whose policy
// forbids storing user agents can verify the setting took effect.
func TestTelemetry_DisabledRefusesIngest(t *testing.T) {
	srv := telemetryServer(t)
	writeTelemetryConfig(t, srv.WorkDir, false)

	for _, path := range []string{"/api/telemetry", "/api/glasses/telemetry"} {
		w := postTelemetry(t, srv, path, map[string]any{
			"events": []map[string]any{{"kind": "note", "message": "m"}},
		})
		if w.Code != http.StatusNotFound {
			t.Errorf("%s with collection disabled = %d, want 404", path, w.Code)
		}
	}

	if got := readTelemetry(t, srv, "").Total; got != 0 {
		t.Errorf("%d events were stored while collection was disabled", got)
	}
}

// TestTelemetry_DefaultsToOff is the default flip of Task 20311, checked at the
// layer that matters: not whether the config struct says off, but whether a
// hub with no telemetry configuration refuses a batch and stores nothing.
//
// A regression here does not break a feature. It silently starts recording the
// URLs, user agents and addresses of everyone who opens the dashboard on a hub
// whose operator never asked for that.
func TestTelemetry_DefaultsToOff(t *testing.T) {
	srv := telemetryServerUnconfigured(t)

	if srv.telemetryEnabled() {
		t.Error("collection is on with no configuration — the default must be off")
	}
	for _, path := range []string{"/api/telemetry", "/api/glasses/telemetry"} {
		w := postTelemetry(t, srv, path, map[string]any{
			"events": []map[string]any{{"kind": "note", "message": "m"}},
		})
		if w.Code != http.StatusNotFound {
			t.Errorf("%s on an unconfigured hub = %d, want 404", path, w.Code)
		}
	}
	if got := readTelemetry(t, srv, "").Total; got != 0 {
		t.Errorf("%d events were stored on a hub that was never configured to collect", got)
	}

	writeTelemetryConfig(t, srv.WorkDir, true)
	if !srv.telemetryEnabled() {
		t.Error("telemetry is off with enabled: true")
	}
}

// TestTelemetry_ClientPolicyIsAskedBeforeAnythingIsSent covers the route that
// makes "off" mean *not submitted* rather than *submitted and refused*. A front
// end asks this first; a page that posted and read the 404 would already have
// sent the trail.
func TestTelemetry_ClientPolicyIsAskedBeforeAnythingIsSent(t *testing.T) {
	srv := telemetryServerUnconfigured(t)

	// Unconfigured: both front ends are told not to send.
	for _, src := range telemetry.AllSources() {
		if got := readTelemetryClientPolicy(t, srv, src); got.Collect {
			t.Errorf("%s is told to collect on an unconfigured hub", src)
		}
	}

	// Switched on for the glasses alone: each page is told about itself, and
	// neither learns the other's policy from its own answer.
	writeTelemetrySourceConfig(t, srv.WorkDir, true, "glasses")
	if got := readTelemetryClientPolicy(t, srv, telemetry.SourceGlasses); !got.Collect {
		t.Error("the glasses page is told not to send while sources: [glasses] is configured")
	}
	if got := readTelemetryClientPolicy(t, srv, telemetry.SourceDashboard); got.Collect {
		t.Error("the dashboard is told to send while only the glasses are configured")
	}
	if got := readTelemetryClientPolicy(t, srv, telemetry.SourceDashboard); got.Source != "dashboard" {
		t.Errorf("the dashboard's answer names source %q", got.Source)
	}
}

// TestTelemetry_SourcesNarrowIngest: the per-source switch has to be enforced
// on the write path, not only advertised by the probe. A client that ignores
// the probe must gain nothing.
func TestTelemetry_SourcesNarrowIngest(t *testing.T) {
	srv := telemetryServerUnconfigured(t)
	writeTelemetrySourceConfig(t, srv.WorkDir, true, "glasses")

	w := postTelemetry(t, srv, "/api/telemetry", map[string]any{
		"session": "dash", "events": []map[string]any{{"kind": "note", "message": "from the dashboard"}},
	})
	if w.Code != http.StatusNotFound {
		t.Errorf("dashboard ingest = %d, want 404 while sources: [glasses]", w.Code)
	}

	w = postTelemetry(t, srv, "/api/glasses/telemetry", map[string]any{
		"session": "specs", "events": []map[string]any{{"kind": "note", "message": "from the glasses"}},
	})
	if w.Code != http.StatusNoContent {
		t.Fatalf("glasses ingest = %d, want 204: %s", w.Code, w.Body.String())
	}

	got := readTelemetry(t, srv, "")
	if got.Total != 1 {
		t.Fatalf("stored %d events, want only the glasses one", got.Total)
	}
	if len(got.Events) > 0 && got.Events[0].Source != string(telemetry.SourceGlasses) {
		t.Errorf("stored a %q event while only the glasses are collected", got.Events[0].Source)
	}
}

// TestTelemetry_PolicyFailsClosedOnAnUnreadableConfig: the fallback when the
// config cannot be read is "collect nothing". Recording other people's browsing
// is not a behaviour to fall back into.
func TestTelemetry_PolicyFailsClosedOnAnUnreadableConfig(t *testing.T) {
	srv := telemetryServerUnconfigured(t)
	path := config.ConfigPath(srv.WorkDir)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(path, []byte("ui: [this is not a mapping\n"), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	if srv.telemetryEnabled() {
		t.Error("collection is on with an unparseable config")
	}
	if srv.telemetryCollects(telemetry.SourceGlasses) {
		t.Error("the glasses are collected with an unparseable config")
	}
}

// TestTelemetry_ClientPolicyIsNotCacheable: a page holding a stale permissive
// answer would keep shipping trails for the hub to refuse, which is precisely
// the network traffic the probe exists to prevent. A response with no cache
// headers is eligible for heuristic caching, so the header is not optional.
func TestTelemetry_ClientPolicyIsNotCacheable(t *testing.T) {
	srv := telemetryServerUnconfigured(t)
	for _, h := range []http.HandlerFunc{
		srv.handleTelemetryClientConfig,
		srv.handleGlassesTelemetryClientConfig,
	} {
		w := httptest.NewRecorder()
		h(w, httptest.NewRequest(http.MethodGet, "/api/telemetry/config", nil))
		if got := w.Header().Get("Cache-Control"); !strings.Contains(got, "no-store") {
			t.Errorf("Cache-Control = %q, want no-store", got)
		}
	}
}

func readTelemetryClientPolicy(t *testing.T, srv *Server, src telemetry.Source) telemetryClientPolicy {
	t.Helper()
	path := "/api/telemetry/config"
	handler := srv.handleTelemetryClientConfig
	if src == telemetry.SourceGlasses {
		path = "/api/glasses/telemetry/config"
		handler = srv.handleGlassesTelemetryClientConfig
	}
	w := httptest.NewRecorder()
	handler(w, httptest.NewRequest(http.MethodGet, path, nil))
	if w.Code != http.StatusOK {
		t.Fatalf("%s = %d: %s", path, w.Code, w.Body.String())
	}
	var out telemetryClientPolicy
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode %s: %v", path, err)
	}
	return out
}

func writeTelemetrySourceConfig(t *testing.T, dir string, enabled bool, sources ...string) {
	t.Helper()
	path := config.ConfigPath(dir)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	body := fmt.Sprintf("ui:\n  telemetry:\n    enabled: %t\n    sources: [%s]\n",
		enabled, strings.Join(sources, ", "))
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
}

// TestTelemetry_StoreIsBoundedByRowCeiling checks the constant the public
// ingest route depends on rather than writing 50k rows through HTTP.
func TestTelemetry_StoreIsBoundedByRowCeiling(t *testing.T) {
	if statedb.TelemetryMaxRows <= 0 {
		t.Fatal("there is no row ceiling — a public ingest route could fill the disk")
	}
	if statedb.TelemetryMaxLimit > statedb.TelemetryMaxRows {
		t.Errorf("one page (%d) can exceed the whole table (%d)",
			statedb.TelemetryMaxLimit, statedb.TelemetryMaxRows)
	}
}

func writeTelemetryConfig(t *testing.T, dir string, enabled bool) {
	t.Helper()
	path := config.ConfigPath(dir)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	body := fmt.Sprintf("ui:\n  telemetry:\n    enabled: %t\n", enabled)
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
}
