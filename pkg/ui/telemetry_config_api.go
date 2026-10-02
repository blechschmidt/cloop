package ui

// The Settings block that edits ui.telemetry (Task 20311).
//
// Two routes, global-scoped and gated on user.manage:
//
//	GET /api/config/telemetry   what is collected, and what has been
//	PUT /api/config/telemetry   change it
//
// # Why this is not config.write
//
// config.write is held by maintainers and covers provider selection, budgets,
// timeouts and run options — the settings that decide how this hub does its
// work. This one decides whether the hub records what *other people's* browsers
// did: the URLs they opened, the views they moved between, their user agent and
// their address.
//
// Reading that back is admin-only and pkg/authz explains why at PermAuditRead —
// the trail records the actions of people more privileged than the reader, so
// handing it to the role that brokers credentials would let an operator watch
// their own oversight. Switching the recording on is the same decision taken
// one step earlier. Granting it to maintainer would also produce the odd case
// of a role that can start collecting and cannot look at the result.
//
// So: user.manage, the only write-capable permission that is admin-only, and
// the same one the identity block uses for the same reason.
//
// # Why a save takes effect immediately
//
// Unlike ui.oidc, nothing here is captured at startup. Both ingest handlers and
// both client-policy handlers read the hub's configuration per request (its
// per-instance overlay included), so a save is in force for the next batch —
// and the next page load stops sending. There is no restart banner because
// there is nothing to restart.
//
// The one lag that does exist is a page already open: it asked once, at load,
// and believes the answer until it is reloaded. That is the right trade — the
// alternative is every front end re-polling a policy endpoint forever — and it
// is bounded in the direction that matters, because the hub refuses the ingest
// regardless of what the page believes.

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/apierror"
	"github.com/blechschmidt/cloop/pkg/auditaction"
	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/eventlog"
	"github.com/blechschmidt/cloop/pkg/janitor"
	"github.com/blechschmidt/cloop/pkg/logger"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
	"github.com/blechschmidt/cloop/pkg/telemetry"
)

// telemetrySourceView is one front end and whether its trail is collected.
//
// Served rather than hardcoded in the panel for the reason oidcSettingsView
// serves its enumerations: the set of front ends is a Go constant, and a second
// copy in JavaScript would be the one that goes stale.
type telemetrySourceView struct {
	Name    string `json:"name"`
	Collect bool   `json:"collect"`

	// Selected is whether the stored policy includes this front end, whether
	// or not collection is switched on. The panel ticks its boxes from it, so
	// a narrowing survives being switched off and on again: rendered from
	// Collect, every box would read clear while off, switching on would tick
	// them all, and Save would widen collection back to every front end.
	Selected bool `json:"selected"`
}

// telemetrySettingsView is the editable policy plus the context an operator
// needs to judge it: what is switched on, and what is already stored.
type telemetrySettingsView struct {
	// Enabled is the master switch as it will act.
	Enabled bool `json:"enabled"`

	// Configured distinguishes "explicitly off" from "never configured".
	// Behaviourally identical, and worth showing: the second is a hub whose
	// operator has not made the decision yet.
	Configured bool `json:"configured"`

	Sources []telemetrySourceView `json:"sources"`

	// Stored describes what collection has already produced, which is the
	// number that makes turning it off actionable — switching the instrument
	// off does not delete what it gathered, and an operator disabling it for a
	// privacy reason needs to be told that in the same place.
	Stored telemetryStoredView `json:"stored"`

	// RetentionDays is the janitor's age-out for these rows, reported so the
	// panel can answer "for how long" without the operator opening the
	// Retention page. Zero means the janitor keeps them indefinitely.
	//
	// Read-only here: it is written in the retention block, and a second writer
	// for one key would be a second thing to keep in sync.
	RetentionDays int `json:"retention_days"`

	// MaxRows is the hard ceiling the write path enforces.
	MaxRows int `json:"max_rows"`
}

// telemetryStoredView counts what is already in the table.
type telemetryStoredView struct {
	Events   int    `json:"events"`
	Sessions int    `json:"sessions"`
	Oldest   string `json:"oldest,omitempty"`
	Newest   string `json:"newest,omitempty"`

	// SessionsCapped says the session count hit the page limit and is a floor
	// rather than a total, so the panel can render "1000+" instead of asserting
	// a number it cannot support.
	SessionsCapped bool `json:"sessions_capped,omitempty"`

	// Error is set when the count could not be taken. Reported rather than
	// swallowed: a panel that silently shows zero stored events would be
	// making exactly the wrong claim about a hub whose database is unreachable.
	Error string `json:"error,omitempty"`
}

// handleTelemetrySettings serves GET /api/config/telemetry.
func (s *Server) handleTelemetrySettings(w http.ResponseWriter, r *http.Request) {
	cfg, err := s.loadHubConfig()
	if err != nil || cfg == nil {
		apierror.WriteError(w, apierror.New(apierror.CodeUnavailable, "load hub config"))
		return
	}
	jsonOK(w, s.telemetryViewOf(cfg.UI.Telemetry))
}

func (s *Server) telemetryViewOf(t config.TelemetryConfig) telemetrySettingsView {
	view := telemetrySettingsView{
		Enabled:       t.Effective(),
		Configured:    t.Enabled != nil,
		MaxRows:       statedb.TelemetryMaxRows,
		RetentionDays: s.telemetryRetentionDays(),
		Stored:        s.telemetryStored(),
	}
	named := map[string]bool{}
	for _, n := range t.Sources {
		named[strings.ToLower(strings.TrimSpace(n))] = true
	}
	for _, src := range telemetry.AllSources() {
		view.Sources = append(view.Sources, telemetrySourceView{
			Name:     string(src),
			Collect:  t.Collects(string(src)),
			Selected: len(t.Sources) == 0 || named[string(src)],
		})
	}
	return view
}

// telemetryRetentionDays reports the age-out that will actually be applied,
// resolved through the janitor rather than read off the config key.
//
// The default (30 days) lives in pkg/janitor, and the negative sentinel that
// means "keep everything" is resolved there too. Reading the raw key would make
// this panel say "0 days" on the overwhelmingly common hub that configured
// nothing — which is both wrong and alarming.
func (s *Server) telemetryRetentionDays() int {
	cfg, err := config.Load(s.WorkDir)
	if err != nil || cfg == nil {
		return int(janitor.DefaultTelemetryMaxAge / (24 * time.Hour))
	}
	age := janitor.PolicyFromConfig(cfg).TelemetryMaxAge
	if age <= 0 {
		// The operator asked to keep everything; say so with a zero rather than
		// a negative the panel would have to special-case.
		return 0
	}
	return int(age / (24 * time.Hour))
}

// telemetryStored counts the rows collection has already produced.
//
// Included because it is what makes switching collection off actionable: the
// switch stops the instrument and deletes nothing, and an operator turning it
// off for a privacy reason needs to be told that in the same place, with the
// number in front of them.
func (s *Server) telemetryStored() telemetryStoredView {
	var out telemetryStoredView
	// A hub with no control-plane database yet has stored nothing. That is the
	// answer, not an error to show the operator.
	if _, err := os.Stat(state.DBPath(s.WorkDir)); errors.Is(err, fs.ErrNotExist) {
		return out
	}
	db, err := s.controlPlaneDB()
	if err != nil {
		out.Error = err.Error()
		return out
	}
	defer db.Close()

	// Limit 1: the count is a COUNT(*) over the whole table and is exact
	// regardless, so there is no reason to carry a page of rows back for it.
	newest, total, err := db.QueryTelemetry(statedb.TelemetryFilter{Limit: 1})
	if err != nil {
		out.Error = err.Error()
		return out
	}
	out.Events = total
	if len(newest) > 0 {
		out.Newest = newest[0].At.UTC().Format(time.RFC3339)
	}

	// Sessions are counted from the roll-up the Telemetry panel itself lists,
	// so the two cannot disagree. Capped at one page: a hub with more distinct
	// page loads than that has long since answered the question this number
	// exists to answer, and an exact count would need a second query shape for
	// no gain.
	sessions, err := db.ListTelemetrySessions("", statedb.TelemetryMaxLimit)
	if err != nil {
		out.Error = err.Error()
		return out
	}
	out.Sessions = len(sessions)
	out.SessionsCapped = len(sessions) >= statedb.TelemetryMaxLimit
	var oldest time.Time
	for _, sess := range sessions {
		if sess.FirstSeen.IsZero() {
			continue
		}
		if oldest.IsZero() || sess.FirstSeen.Before(oldest) {
			oldest = sess.FirstSeen
		}
	}
	if !oldest.IsZero() {
		out.Oldest = oldest.UTC().Format(time.RFC3339)
	}
	return out
}

// telemetrySettingsRequest is a partial update.
//
// Pointers for the same reason oidcSettingsRequest uses them: every field has a
// meaningful zero, and a form that submits only what it changed must not clear
// the rest by omission.
type telemetrySettingsRequest struct {
	Enabled *bool `json:"enabled"`

	// Sources is the exact list to store. An empty (but present) list means
	// every source, which is what the panel sends when every box is ticked —
	// so a hub that later grows a third front end collects it, matching what
	// the operator saw when they ticked "all".
	Sources *[]string `json:"sources"`
}

// handleTelemetrySettingsSave serves PUT /api/config/telemetry.
func (s *Server) handleTelemetrySettingsSave(w http.ResponseWriter, r *http.Request) {
	var req telemetrySettingsRequest
	if !decodeSecretsBody(w, r, &req) {
		return
	}

	hubConfigMu.Lock()
	// Write where this hub reads (Task 20318). Once this hub has an overlay,
	// the setting lives there: the shared config.yaml is also read by any
	// other dashboard in this directory, and an older binary saving that file
	// drops keys it does not know, which would silently switch collection off
	// here. The destination is chosen before loading, so config.yaml is only
	// ever rewritten from itself — never from a view merged with the overlay,
	// which would copy this hub's SSO block into the shared file.
	overlay := s.hubConfigOverlay()
	var cfg *config.Config
	var err error
	if overlay != "" {
		cfg, err = s.loadHubConfig()
	} else {
		cfg, err = config.Load(s.WorkDir)
	}
	if err != nil || cfg == nil {
		hubConfigMu.Unlock()
		apierror.WriteError(w, apierror.New(apierror.CodeUnavailable, "load hub config"))
		return
	}
	was := cfg.UI.Telemetry
	if err := applyTelemetryRequest(&cfg.UI.Telemetry, req); err != nil {
		hubConfigMu.Unlock()
		apierror.WriteError(w, apierror.New(apierror.CodeInvalidInput, err.Error()))
		return
	}
	if overlay != "" {
		err = config.SaveUIInstanceTelemetry(overlay, cfg.UI.Telemetry)
	} else {
		err = config.Save(s.WorkDir, cfg)
	}
	if err != nil {
		hubConfigMu.Unlock()
		apierror.WriteError(w, apierror.New(apierror.CodeInternal, err.Error()))
		return
	}
	saved := cfg.UI.Telemetry
	hubConfigMu.Unlock()

	s.auditTelemetryConfig(r, was, saved)
	jsonOK(w, s.telemetryViewOf(saved))
}

// applyTelemetryRequest overlays the supplied fields, refusing a source name no
// front end answers to.
//
// Refused rather than dropped: a typo silently discarded would leave the panel
// showing a narrower policy than the operator typed, and the operator would
// have no way to tell that from a hub that had ignored the save entirely.
func applyTelemetryRequest(t *config.TelemetryConfig, req telemetrySettingsRequest) error {
	if req.Enabled != nil {
		v := *req.Enabled
		t.Enabled = &v
	}
	if req.Sources == nil {
		return nil
	}
	known := map[string]bool{}
	for _, src := range telemetry.AllSources() {
		known[string(src)] = true
	}
	seen := map[string]bool{}
	out := make([]string, 0, len(*req.Sources))
	for _, raw := range *req.Sources {
		name := strings.ToLower(strings.TrimSpace(raw))
		if name == "" {
			continue
		}
		if !known[name] {
			return fmt.Errorf("unknown telemetry source %q", raw)
		}
		if seen[name] {
			continue
		}
		seen[name] = true
		out = append(out, name)
	}
	// Every source ticked is stored as "no restriction", not as the full list.
	// The two behave identically today and diverge the day a third front end
	// ships: the operator who ticked everything meant "all of it", and a frozen
	// list would quietly exclude the newcomer.
	if len(out) == len(known) || len(out) == 0 {
		t.Sources = nil
		return nil
	}
	t.Sources = out
	return nil
}

// auditTelemetryConfig records the change.
//
// Worth a row for the reason the OIDC block is: this is the switch that decides
// whether the hub is recording its users, so "when did collection start, and
// who started it" has to be answerable later — including by the person who was
// recorded.
func (s *Server) auditTelemetryConfig(r *http.Request, was, now config.TelemetryConfig) {
	if was.Effective() == now.Effective() && sameStrings(was.Sources, now.Sources) {
		// A form re-submitted unchanged is not an event.
		return
	}
	blob, err := json.Marshal(map[string]any{
		"enabled":     now.Effective(),
		"was_enabled": was.Effective(),
		"sources":     strings.Join(now.Sources, ","),
		"was_sources": strings.Join(was.Sources, ","),
	})
	if err != nil {
		return
	}
	actor := s.auditActor(r)
	if actor == "" {
		actor = "anonymous"
	}
	// The hub's own journal: this is a property of the deployment, not of a
	// project. Best-effort, like every other emitter here — a wedged journal
	// must not stop an operator switching collection off.
	log, logErr := eventlog.Open(s.WorkDir)
	if logErr != nil {
		if logErr != eventlog.ErrNoProject {
			s.log().Warn(logger.EventAuthz, 0, "telemetry config audit: open event log",
				map[string]interface{}{"error": logErr.Error()})
		}
		return
	}
	defer log.Close()
	if err := log.Append(&eventlog.AuditEvent{
		Actor:      actor,
		EventType:  string(auditaction.ActionTelemetryConfigUpdated),
		EntityType: "config",
		EntityID:   "ui.telemetry",
		Payload:    string(blob),
	}); err != nil {
		s.log().Warn(logger.EventAuthz, 0, "telemetry config audit: append",
			map[string]interface{}{"error": err.Error()})
	}
}
