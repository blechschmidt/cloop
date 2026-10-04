package ui

// Tests for the Telemetry Settings panel's backend (Task 20311).
//
// The panel exists so that "does this hub record what its users' browsers did"
// is a switch rather than a YAML edit and a restart. Three properties make that
// safe, and each fails silently in the direction of "saved fine":
//
//	a save takes effect for the next batch, with no restart
//	a save that narrows actually narrows — on the write path, not just the view
//	a save leaves a row naming who turned collection on
//
// The fourth is the one the panel cannot check for itself: a stale or
// hand-written client must not be able to widen the policy by sending a source
// the hub does not know.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/internal/statedbtest"
	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/eventlog"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/telemetry"
)

// telemetrySettingsServer builds a hub with a real project, because the view
// counts stored rows and the save writes an audit row.
func telemetrySettingsServer(t *testing.T) *Server {
	t.Helper()
	dir := statedbtest.Dir(t)
	if _, err := state.Init(dir, "telemetry settings test", 1); err != nil {
		t.Fatalf("init project: %v", err)
	}
	return New(dir, 0, "")
}

func putTelemetrySettings(t *testing.T, srv *Server, body map[string]any) *httptest.ResponseRecorder {
	t.Helper()
	blob, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPut, "/api/config/telemetry", strings.NewReader(string(blob)))
	req.Header.Set("Content-Type", "application/json")
	srv.handleTelemetrySettingsSave(rec, req)
	return rec
}

func getTelemetrySettings(t *testing.T, srv *Server) telemetrySettingsView {
	t.Helper()
	rec := httptest.NewRecorder()
	srv.handleTelemetrySettings(rec, httptest.NewRequest(http.MethodGet, "/api/config/telemetry", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/config/telemetry = %d: %s", rec.Code, rec.Body.String())
	}
	var view telemetrySettingsView
	if err := json.Unmarshal(rec.Body.Bytes(), &view); err != nil {
		t.Fatalf("decode view: %v", err)
	}
	return view
}

// TestTelemetrySettings_FreshHubReportsOffAndUnconfigured: the panel has to be
// able to say "nobody has decided this yet", which is not the same as "somebody
// switched it off" even though both collect nothing.
func TestTelemetrySettings_FreshHubReportsOffAndUnconfigured(t *testing.T) {
	srv := telemetrySettingsServer(t)

	view := getTelemetrySettings(t, srv)
	if view.Enabled {
		t.Error("a hub with no telemetry block reports collection on")
	}
	if view.Configured {
		t.Error("a hub with no telemetry block reports itself configured")
	}
	if len(view.Sources) != len(telemetry.AllSources()) {
		t.Fatalf("view offers %d sources, want one per front end", len(view.Sources))
	}
	for _, s := range view.Sources {
		if s.Collect {
			t.Errorf("source %q is collected on a fresh hub", s.Name)
		}
		// Nothing was ever narrowed, so switching on means every front end.
		if !s.Selected {
			t.Errorf("source %q is not selected on a hub that never narrowed collection", s.Name)
		}
	}
	if view.MaxRows <= 0 {
		t.Error("the view does not report the row ceiling")
	}
}

// TestTelemetrySettings_NoDatabaseYetMeansNothingStored: a hub that has not
// created its control-plane database has stored nothing, and the panel says
// so rather than showing the operator a SQLite error.
func TestTelemetrySettings_NoDatabaseYetMeansNothingStored(t *testing.T) {
	srv := New(t.TempDir(), 0, "")
	view := getTelemetrySettings(t, srv)
	if view.Stored.Error != "" || view.Stored.Events != 0 {
		t.Errorf("stored = %+v on a hub with no database; want zero and no error", view.Stored)
	}
}

// TestTelemetrySettings_SaveTakesEffectImmediately is the property that makes
// this a panel rather than a config editor: nothing here is captured at
// startup, so the ingest path must honour a save without a restart.
func TestTelemetrySettings_SaveTakesEffectImmediately(t *testing.T) {
	srv := telemetrySettingsServer(t)

	if rec := putTelemetrySettings(t, srv, map[string]any{"enabled": true}); rec.Code != http.StatusOK {
		t.Fatalf("PUT = %d: %s", rec.Code, rec.Body.String())
	}
	if !srv.telemetryEnabled() {
		t.Fatal("the ingest path still reports collection off after a save that turned it on")
	}
	w := postTelemetry(t, srv, "/api/telemetry", map[string]any{
		"session": "s1", "events": []map[string]any{{"kind": "note", "message": "after the save"}},
	})
	if w.Code != http.StatusNoContent {
		t.Fatalf("ingest after enabling = %d, want 204: %s", w.Code, w.Body.String())
	}

	// And back off again, which is the direction an operator is more likely to
	// need in a hurry.
	if rec := putTelemetrySettings(t, srv, map[string]any{"enabled": false}); rec.Code != http.StatusOK {
		t.Fatalf("PUT off = %d: %s", rec.Code, rec.Body.String())
	}
	w = postTelemetry(t, srv, "/api/telemetry", map[string]any{
		"session": "s2", "events": []map[string]any{{"kind": "note", "message": "after switching off"}},
	})
	if w.Code != http.StatusNotFound {
		t.Errorf("ingest after disabling = %d, want 404", w.Code)
	}
}

// TestTelemetrySettings_NarrowingRefusesTheOtherFrontEnd checks that a
// narrowed policy is enforced where it counts rather than only rendered.
func TestTelemetrySettings_NarrowingRefusesTheOtherFrontEnd(t *testing.T) {
	srv := telemetrySettingsServer(t)

	rec := putTelemetrySettings(t, srv, map[string]any{
		"enabled": true,
		"sources": []string{"glasses"},
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("PUT = %d: %s", rec.Code, rec.Body.String())
	}

	var view telemetrySettingsView
	if err := json.Unmarshal(rec.Body.Bytes(), &view); err != nil {
		t.Fatalf("decode: %v", err)
	}
	for _, s := range view.Sources {
		want := s.Name == string(telemetry.SourceGlasses)
		if s.Collect != want {
			t.Errorf("view says collect=%v for %q, want %v", s.Collect, s.Name, want)
		}
	}
	if !srv.telemetryCollects(telemetry.SourceGlasses) {
		t.Error("the glasses are refused after a save that named them")
	}
	if srv.telemetryCollects(telemetry.SourceDashboard) {
		t.Error("the dashboard is still collected after a save that named only the glasses")
	}
}

// TestTelemetrySettings_SelectionSurvivesSwitchingOff: switched off, nothing is
// collected, but the view still says which front ends the stored policy names,
// because that is what the panel ticks — and what Save sends back when the
// switch goes on again. Rendered from Collect alone, every box would read clear
// and the next switch-on would widen collection to every front end.
func TestTelemetrySettings_SelectionSurvivesSwitchingOff(t *testing.T) {
	srv := telemetrySettingsServer(t)

	if rec := putTelemetrySettings(t, srv, map[string]any{
		"enabled": true, "sources": []string{"glasses"},
	}); rec.Code != http.StatusOK {
		t.Fatalf("seed PUT = %d: %s", rec.Code, rec.Body.String())
	}
	rec := putTelemetrySettings(t, srv, map[string]any{"enabled": false})
	if rec.Code != http.StatusOK {
		t.Fatalf("PUT off = %d: %s", rec.Code, rec.Body.String())
	}
	var view telemetrySettingsView
	if err := json.Unmarshal(rec.Body.Bytes(), &view); err != nil {
		t.Fatalf("decode: %v", err)
	}
	for _, s := range view.Sources {
		if s.Collect {
			t.Errorf("%q is collected while collection is off", s.Name)
		}
		if want := s.Name == string(telemetry.SourceGlasses); s.Selected != want {
			t.Errorf("%q selected=%v while off, want %v: the narrowing has to read the same "+
				"until somebody changes it", s.Name, s.Selected, want)
		}
	}
}

// TestTelemetrySettings_EveryBoxTickedStaysOpenEnded: all sources selected is
// stored as "no restriction", so a hub that later grows a third front end
// collects it. An operator who ticked everything meant all of it.
func TestTelemetrySettings_EveryBoxTickedStaysOpenEnded(t *testing.T) {
	srv := telemetrySettingsServer(t)

	all := make([]string, 0, len(telemetry.AllSources()))
	for _, s := range telemetry.AllSources() {
		all = append(all, string(s))
	}
	if rec := putTelemetrySettings(t, srv, map[string]any{
		"enabled": true, "sources": all,
	}); rec.Code != http.StatusOK {
		t.Fatalf("PUT = %d: %s", rec.Code, rec.Body.String())
	}

	cfg, err := config.Load(srv.WorkDir)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(cfg.UI.Telemetry.Sources) != 0 {
		t.Errorf("stored sources = %v, want an empty list meaning all",
			cfg.UI.Telemetry.Sources)
	}
	for _, s := range telemetry.AllSources() {
		if !cfg.UI.Telemetry.Collects(string(s)) {
			t.Errorf("%q is not collected after ticking every box", s)
		}
	}
}

// TestTelemetrySettings_UnknownSourceIsRefused: a source the hub does not know
// is an error, not something to drop quietly. Dropping it would leave the panel
// showing a narrower policy than was submitted, indistinguishable from a save
// that never happened.
func TestTelemetrySettings_UnknownSourceIsRefused(t *testing.T) {
	srv := telemetrySettingsServer(t)

	rec := putTelemetrySettings(t, srv, map[string]any{
		"enabled": true, "sources": []string{"glasses", "wiretap"},
	})
	if rec.Code == http.StatusOK {
		t.Fatalf("an unknown source was accepted: %s", rec.Body.String())
	}
	cfg, err := config.Load(srv.WorkDir)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.UI.Telemetry.Effective() {
		t.Error("a refused save still switched collection on — it must not write anything")
	}
}

// TestTelemetrySettings_PartialUpdateKeepsTheRest: the panel submits what it
// changed. An absent field must not clear the others — in particular, toggling
// the master switch must not silently widen a narrowed source list.
func TestTelemetrySettings_PartialUpdateKeepsTheRest(t *testing.T) {
	srv := telemetrySettingsServer(t)

	if rec := putTelemetrySettings(t, srv, map[string]any{
		"enabled": true, "sources": []string{"glasses"},
	}); rec.Code != http.StatusOK {
		t.Fatalf("seed PUT = %d: %s", rec.Code, rec.Body.String())
	}
	if rec := putTelemetrySettings(t, srv, map[string]any{"enabled": false}); rec.Code != http.StatusOK {
		t.Fatalf("PUT = %d: %s", rec.Code, rec.Body.String())
	}

	cfg, err := config.Load(srv.WorkDir)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(cfg.UI.Telemetry.Sources) != 1 || cfg.UI.Telemetry.Sources[0] != "glasses" {
		t.Errorf("sources = %v after a save that named only `enabled`; the narrowing was lost",
			cfg.UI.Telemetry.Sources)
	}
}

// TestTelemetrySettings_SwitchingOnIsAudited: "was this hub recording its
// users, and who decided that" has to be answerable afterwards.
func TestTelemetrySettings_SwitchingOnIsAudited(t *testing.T) {
	srv := telemetrySettingsServer(t)

	if rec := putTelemetrySettings(t, srv, map[string]any{"enabled": true}); rec.Code != http.StatusOK {
		t.Fatalf("PUT = %d: %s", rec.Code, rec.Body.String())
	}

	log, err := eventlog.Open(srv.WorkDir)
	if err != nil {
		t.Fatalf("open event log: %v", err)
	}
	defer log.Close()
	events, _, err := log.List(eventlog.AuditFilter{Limit: 200})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	var found *eventlog.AuditEvent
	for i := range events {
		if events[i].EventType == "telemetry.config.updated" {
			found = &events[i]
			break
		}
	}
	if found == nil {
		t.Fatal("switching collection on left no audit row")
	}
	if found.EntityID != "ui.telemetry" {
		t.Errorf("audit row entity = %q, want ui.telemetry", found.EntityID)
	}
	if !strings.Contains(found.Payload, `"enabled":true`) {
		t.Errorf("audit payload does not record the new state: %s", found.Payload)
	}

	// A re-submitted form is not an event: a second identical save must not
	// dilute the one query this row exists to answer. Counted by type rather
	// than in total, because config.Save emits its own config.set row on every
	// write and that is not this feature's to suppress.
	before := countAuditType(events, "telemetry.config.updated")
	if rec := putTelemetrySettings(t, srv, map[string]any{"enabled": true}); rec.Code != http.StatusOK {
		t.Fatalf("second PUT = %d", rec.Code)
	}
	after, _, err := log.List(eventlog.AuditFilter{Limit: 200})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if got := countAuditType(after, "telemetry.config.updated"); got != before {
		t.Errorf("an unchanged save wrote %d extra telemetry.config.updated row(s)", got-before)
	}
}

func countAuditType(events []eventlog.AuditEvent, eventType string) int {
	n := 0
	for _, e := range events {
		if e.EventType == eventType {
			n++
		}
	}
	return n
}

// TestTelemetrySettings_ViewCountsWhatIsAlreadyStored: switching collection off
// deletes nothing, and the panel has to say how much remains — otherwise an
// operator disabling it for a privacy reason believes they have cleaned up.
func TestTelemetrySettings_ViewCountsWhatIsAlreadyStored(t *testing.T) {
	srv := telemetrySettingsServer(t)
	writeTelemetryConfig(t, srv.WorkDir, true)

	postTelemetry(t, srv, "/api/telemetry", map[string]any{
		"session": "s1",
		"events": []map[string]any{
			{"kind": "note", "seq": 1, "message": "one"},
			{"kind": "note", "seq": 2, "message": "two"},
		},
	})

	view := getTelemetrySettings(t, srv)
	if view.Stored.Error != "" {
		t.Fatalf("stored count failed: %s", view.Stored.Error)
	}
	if view.Stored.Events != 2 {
		t.Errorf("view reports %d stored events, want 2", view.Stored.Events)
	}
	if view.Stored.Sessions != 1 {
		t.Errorf("view reports %d sessions, want 1", view.Stored.Sessions)
	}

	// Still counted after collection is switched off: that is the whole point.
	if rec := putTelemetrySettings(t, srv, map[string]any{"enabled": false}); rec.Code != http.StatusOK {
		t.Fatalf("PUT off = %d", rec.Code)
	}
	if got := getTelemetrySettings(t, srv).Stored.Events; got != 2 {
		t.Errorf("after disabling, view reports %d stored events; disabling must not appear to delete", got)
	}
}

// ── a hub with a per-instance overlay ───────────────────────────────────────
//
// Collection is a property of the hub, and where two dashboards share a
// working directory each has its own .cloop/config.ui-<port>.yaml (Task
// 20318). aiden.blechschmidt.io's :8888 is exactly that hub: its config.yaml,
// shared with an older dashboard, says `ui.telemetry.enabled: true`, and its
// overlay holds the SSO block and nothing about telemetry.

const liveSharedConfig = "provider: claudecode\nui:\n  telemetry:\n    enabled: true\n"

const liveOverlay = `# Read by cloop ui --port 8081 only.
ui:
  # nginx terminates TLS in front of this hub.
  allowed_origins:
    - https://hub.example:8888
`

// overlayServer is a hub on :8081 whose working directory carries the given
// shared config and overlay.
func overlayServer(t *testing.T, shared, overlay string) (*Server, string) {
	t.Helper()
	srv := telemetrySettingsServer(t)
	srv.Port = 8081
	if err := os.WriteFile(config.ConfigPath(srv.WorkDir), []byte(shared), 0o600); err != nil {
		t.Fatalf("write config.yaml: %v", err)
	}
	path := config.UIInstanceConfigPath(srv.WorkDir, srv.Port)
	if err := os.WriteFile(path, []byte(overlay), 0o600); err != nil {
		t.Fatalf("write overlay: %v", err)
	}
	return srv, path
}

// TestTelemetry_LiveHubKeepsCollectingAfterTheDefaultFlips pins the promise
// this task made about the hub it was written on: the default turned off, and
// a hub whose operator had already said yes must not stop collecting.
func TestTelemetry_LiveHubKeepsCollectingAfterTheDefaultFlips(t *testing.T) {
	srv, overlay := overlayServer(t, liveSharedConfig, liveOverlay)

	for _, src := range telemetry.AllSources() {
		if !srv.telemetryCollects(src) {
			t.Errorf("%s is refused on a hub whose config.yaml says enabled: true", src)
		}
		if got := readTelemetryClientPolicy(t, srv, src); !got.Collect {
			t.Errorf("%s is told not to send on a hub whose config.yaml says enabled: true", src)
		}
	}
	if view := getTelemetrySettings(t, srv); !view.Enabled || !view.Configured {
		t.Errorf("the panel reads enabled=%v configured=%v, want both", view.Enabled, view.Configured)
	}

	// The older dashboard sharing config.yaml drops keys it does not know when
	// it saves. Once the setting is in this hub's overlay, that cannot reach it.
	if rec := putTelemetrySettings(t, srv, map[string]any{"enabled": true}); rec.Code != http.StatusOK {
		t.Fatalf("PUT = %d: %s", rec.Code, rec.Body.String())
	}
	if err := os.WriteFile(config.ConfigPath(srv.WorkDir), []byte("provider: claudecode\n"), 0o600); err != nil {
		t.Fatalf("rewrite config.yaml: %v", err)
	}
	if !srv.telemetryCollects(telemetry.SourceDashboard) {
		t.Errorf("collection stopped when the shared config.yaml lost its telemetry block, "+
			"though the panel had saved it into %s", overlay)
	}
}

// TestTelemetrySettings_SaveGoesToTheHubsOverlay: once a hub has an overlay,
// the panel writes the setting there, keeps the rest of that file and its
// comments, and leaves the shared config.yaml exactly as it was.
func TestTelemetrySettings_SaveGoesToTheHubsOverlay(t *testing.T) {
	srv, overlay := overlayServer(t, liveSharedConfig, liveOverlay)

	rec := putTelemetrySettings(t, srv, map[string]any{"enabled": true, "sources": []string{"glasses"}})
	if rec.Code != http.StatusOK {
		t.Fatalf("PUT = %d: %s", rec.Code, rec.Body.String())
	}

	shared, err := os.ReadFile(config.ConfigPath(srv.WorkDir))
	if err != nil {
		t.Fatalf("read config.yaml: %v", err)
	}
	if string(shared) != liveSharedConfig {
		t.Errorf("the shared config.yaml was rewritten:\n%s", shared)
	}
	raw, err := os.ReadFile(overlay)
	if err != nil {
		t.Fatalf("read overlay: %v", err)
	}
	for _, want := range []string{"Read by cloop ui --port 8081 only.", "nginx terminates TLS", "https://hub.example:8888"} {
		if !strings.Contains(string(raw), want) {
			t.Errorf("the overlay lost %q:\n%s", want, raw)
		}
	}
	if !srv.telemetryCollects(telemetry.SourceGlasses) || srv.telemetryCollects(telemetry.SourceDashboard) {
		t.Errorf("after narrowing to the glasses: glasses=%v dashboard=%v",
			srv.telemetryCollects(telemetry.SourceGlasses), srv.telemetryCollects(telemetry.SourceDashboard))
	}
}

// TestTelemetrySettings_OverlayAllSourcesBeatsANarrowedSharedConfig: the
// overlay is merged over config.yaml key by key, so a save that ticks every
// front end has to say so in the overlay. Leaving `sources` out would let a
// narrowing in config.yaml show through, and the panel would show less being
// collected than was just saved.
func TestTelemetrySettings_OverlayAllSourcesBeatsANarrowedSharedConfig(t *testing.T) {
	srv, _ := overlayServer(t,
		"ui:\n  telemetry:\n    enabled: true\n    sources: [glasses]\n", liveOverlay)

	all := []string{}
	for _, s := range telemetry.AllSources() {
		all = append(all, string(s))
	}
	rec := putTelemetrySettings(t, srv, map[string]any{"enabled": true, "sources": all})
	if rec.Code != http.StatusOK {
		t.Fatalf("PUT = %d: %s", rec.Code, rec.Body.String())
	}
	for _, src := range telemetry.AllSources() {
		if !srv.telemetryCollects(src) {
			t.Errorf("%s is still refused after a save that ticked every front end", src)
		}
	}
	for _, s := range getTelemetrySettings(t, srv).Sources {
		if !s.Collect {
			t.Errorf("the panel shows %q unticked after a save that ticked it", s.Name)
		}
	}
}
