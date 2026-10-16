package ui

// model_relay_spend.go: what a relayed run is charged, and what it reported
// (Task 20435).
//
// Without the relay, the hub charges a run's payer what the run wrote to its
// project's cost ledger — inside the sandbox, which can write anything, and
// for the claudecode provider nothing at all: Claude Code's text output
// carries no token counts, so its rows are zero and no daily budget ever moved
// for it. With the relay, every response's usage is read from the API's own
// counts as it streams past and charged to the payer there and then
// (model_relay.go), and a call past the payer's budget is refused.
//
// Two things follow here. The spend drain, which books the ledger's rows into
// the payer's daily counters, must not book a relayed run's rows as well —
// that would charge it twice, once from the API and once from the run's own
// claim — so a relayed run is marked in the control plane at dispatch and the
// drain moves past its rows without charging them. And at the run's end its
// project ledger is brought to what the relay counted: one row carrying the
// difference, so the ledger's total for the run is the relay's, and the
// difference itself is an event in the run's history, an audit row and a
// metric.

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/auditaction"
	"github.com/blechschmidt/cloop/pkg/claudeproxy"
	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/cost"
	"github.com/blechschmidt/cloop/pkg/hubmetrics"
	"github.com/blechschmidt/cloop/pkg/sessionrecord"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// relayedRunKey names, in the control plane's hub metadata, the relay session
// of workDir's current run — what the spend drain asks before charging.
func relayedRunKey(workDir string) string { return "model_relay.run:" + workDir }

// setRelayedRun records whether workDir's run that was just dispatched is
// relayed: the session's id, or "" to clear a mark an earlier run left.
func setRelayedRun(workDir, sessionID string) {
	db, err := statedb.Open(state.DBPath(controlPlaneDir()))
	if err != nil {
		fmt.Fprintf(os.Stderr, "ui: record the relay of %s's run: %v\n", workDir, err)
		return
	}
	defer func() { _ = db.Close() }()
	if sessionID == "" {
		err = db.DeleteHubMeta(relayedRunKey(workDir))
	} else {
		err = db.SetHubMeta(relayedRunKey(workDir), sessionID)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "ui: record the relay of %s's run: %v\n", workDir, err)
	}
}

// relayedRunSession is the relay session of workDir's current run, "" for a
// run that is not relayed.
func relayedRunSession(db *statedb.DB, workDir string) string {
	if db == nil {
		return ""
	}
	v, ok, err := db.HubMeta(relayedRunKey(workDir))
	if err != nil || !ok {
		return ""
	}
	return strings.TrimSpace(v)
}

// projectRelayModelsKey names a project's own model allowlist.
func projectRelayModelsKey(policyPath string) string { return "model_relay.models:" + policyPath }

// projectRelayModels is the model allowlist a project's maintainers set for
// its relayed runs, nil for none: the hub's applies. A feature shares its
// parent's.
func projectRelayModels(workDir string) []string {
	db, err := statedb.Open(state.DBPath(controlPlaneDir()))
	if err != nil {
		return nil
	}
	defer func() { _ = db.Close() }()
	raw, ok, err := db.HubMeta(projectRelayModelsKey(policyProjectPath(workDir)))
	if err != nil || !ok {
		return nil
	}
	var models []string
	if json.Unmarshal([]byte(raw), &models) != nil || config.ValidateModelRelayModels(models) != nil {
		return nil
	}
	return models
}

// setProjectRelayModels stores a project's own allowlist; empty clears it.
func setProjectRelayModels(workDir string, models []string) error {
	if err := config.ValidateModelRelayModels(models); err != nil {
		return err
	}
	db, err := statedb.Open(state.DBPath(controlPlaneDir()))
	if err != nil {
		return err
	}
	defer func() { _ = db.Close() }()
	key := projectRelayModelsKey(policyProjectPath(workDir))
	if len(models) == 0 {
		return db.DeleteHubMeta(key)
	}
	raw, err := json.Marshal(models)
	if err != nil {
		return err
	}
	return db.SetHubMeta(key, string(raw))
}

// relayUsage is a relayed run's spend as the relay counted it, or as the run
// reported it.
type relayUsage struct {
	input, output int64
	usd           float64
}

func (u relayUsage) tokens() int64 { return u.input + u.output }

// settleModelRelayRun brings a relayed run's project ledger to what the relay
// counted, once the run is over and its own report merged, and records the
// difference. A run that was not relayed — or was settled already — is left
// alone.
func (s *Server) settleModelRelayRun(workDir string) {
	cdb, err := statedb.Open(state.DBPath(controlPlaneDir()))
	if err != nil {
		return
	}
	defer func() { _ = cdb.Close() }()
	id := relayedRunSession(cdb, workDir)
	if id == "" {
		return
	}
	// The run is over: its session ends here if this process serves it,
	// which writes its final account to the record.
	svc := activeModelRelay()
	if svc != nil && svc.reg.Known(id) {
		_ = svc.reg.Close(id, "the run ended")
	}
	binding, spend, payer, ok := relaySessionAccount(cdb, svc, id)
	if !ok {
		clearRelayedRunAfterDrain(s, workDir)
		return
	}
	measured := relayUsage{usd: spend.USD}
	model, most := "", int64(-1)
	for m, t := range spend.Models {
		measured.input += t.Input + t.CacheRead + t.CacheWrite
		measured.output += t.Output
		if n := t.Input + t.Output + t.CacheRead + t.CacheWrite; n > most {
			model, most = m, n
		}
	}
	reported := reportedSince(workDir, binding.LedgerFrom)
	gap := relayUsage{
		input:  measured.input - reported.input,
		output: measured.output - reported.output,
		usd:    measured.usd - reported.usd,
	}
	if gap.input != 0 || gap.output != 0 || gap.usd > 0.000001 || gap.usd < -0.000001 {
		if err := cost.AppendLedger(workDir, cost.LedgerEntry{
			Timestamp:    time.Now().UTC(),
			TaskTitle:    "Model relay: usage measured beyond what the run reported (session " + id + ")",
			Provider:     binding.Provider,
			Model:        model,
			InputTokens:  int(gap.input),
			OutputTokens: int(gap.output),
			EstimatedUSD: gap.usd,
			Identity:     payer,
		}); err != nil {
			fmt.Fprintf(os.Stderr, "ui: model relay: bring %s's ledger to the relay's count: %v\n", workDir, err)
		}
	}
	switch d := gap.tokens(); {
	case d > 0:
		hubmetrics.ModelRelayUsageGap.Add(float64(d), hubmetrics.ModelRelayUnreported)
	case d < 0:
		hubmetrics.ModelRelayUsageGap.Add(float64(-d), hubmetrics.ModelRelayOverreported)
	}
	msg := fmt.Sprintf("The model relay counted %s tokens (%s) for this run from the API's responses; "+
		"the run reported %s tokens (%s). The identity %q was charged the relay's count",
		groupDigits(measured.tokens()), relayUSD(measured.usd), groupDigits(reported.tokens()),
		relayUSD(reported.usd), payer)
	if gap.tokens() != 0 {
		msg += ", and the project's ledger now carries the difference"
	}
	state.LogEventDetails(workDir, state.EventRow{Type: state.EventModelRelay, Step: state.NoStep, Message: msg + "."},
		map[string]any{"session_id": id, "relay_tokens": measured.tokens(), "relay_usd": measured.usd,
			"reported_tokens": reported.tokens(), "reported_usd": reported.usd})
	payload, _ := json.Marshal(map[string]any{
		"project": policyProjectPath(workDir), "run_id": binding.runID, "session_ids": []string{id}, "payer": payer,
		"relay_tokens": measured.tokens(), "relay_usd": measured.usd,
		"reported_tokens": reported.tokens(), "reported_usd": reported.usd,
		"gap_tokens": gap.tokens(), "gap_usd": gap.usd,
	})
	if gap.tokens() != 0 {
		_ = cdb.AsControlPlane().AppendAuditEvent(&statedb.AuditEvent{
			Timestamp: time.Now().UTC(), Actor: payer, EventType: string(auditaction.ActionModelRelayUsageGap),
			EntityType: "project", EntityID: policyProjectPath(workDir), Payload: string(payload),
		})
	}
	clearRelayedRunAfterDrain(s, workDir)
}

// clearRelayedRunAfterDrain moves the spend drain past the run's rows —
// including the difference just written, which the relay charged already —
// while the run is still marked relayed, then clears the mark.
func clearRelayedRunAfterDrain(s *Server, workDir string) {
	if s != nil {
		_, _ = s.drainSpend(workDir)
	}
	setRelayedRun(workDir, "")
}

// relaySessionBinding is a session's run binding with the run id beside it.
type relaySessionBinding struct {
	modelRelayBinding
	runID string
}

// relaySessionAccount reads a session's binding, its spend and its payer: this
// process's account when it served the session, else the record's.
func relaySessionAccount(db *statedb.DB, svc *modelRelayService, id string) (relaySessionBinding, sessionrecord.ModelSpend, string, bool) {
	row, err := db.GetProxySession(statedb.ProxySessionModel, id)
	if err != nil {
		if svc == nil {
			return relaySessionBinding{}, sessionrecord.ModelSpend{}, "", false
		}
		// No record — the session was never written, as on a hub process
		// with no cluster member id: what this process kept is all there is.
		return relaySessionBinding{}, svc.spendOf(id), cost.IdentityLocal, true
	}
	rec, spend, err := sessionrecord.ModelRecord(row)
	if err != nil {
		return relaySessionBinding{}, sessionrecord.ModelSpend{}, "", false
	}
	if svc != nil {
		if held := svc.spendOf(id); held.USD >= spend.USD && len(held.Models) >= len(spend.Models) {
			spend = held
		}
	}
	var b modelRelayBinding
	_ = json.Unmarshal(rec.Claims, &b)
	payer := rec.Payer
	if payer == "" {
		payer = cost.IdentityLocal
	}
	return relaySessionBinding{modelRelayBinding: b, runID: rec.RunID}, spend, payer, true
}

// reportedSince sums what the run wrote to workDir's ledger after row from.
func reportedSince(workDir string, from int64) relayUsage {
	db, err := statedb.Open(state.DBPath(workDir))
	if err != nil {
		return relayUsage{}
	}
	defer func() { _ = db.Close() }()
	var u relayUsage
	at := from
	for {
		rows, err := db.ReadCostsAfterID(at, 500)
		if err != nil || len(rows) == 0 {
			return u
		}
		for _, r := range rows {
			u.input += int64(r.InputTokens)
			u.output += int64(r.OutputTokens) + int64(r.ThinkingTokens)
			u.usd += r.EstimatedUSD
			if r.RowID > at {
				at = r.RowID
			}
		}
		if len(rows) < 500 {
			return u
		}
	}
}

// relayUSD renders a relayed amount. Unlike cost.FormatCost, nothing is
// spent on a local model here: zero is a run that reported nothing.
func relayUSD(usd float64) string {
	if usd == 0 {
		return "$0.00"
	}
	return cost.FormatCost(usd)
}

// groupDigits renders n with thousands separators.
func groupDigits(n int64) string {
	neg := n < 0
	if neg {
		n = -n
	}
	s := fmt.Sprint(n)
	var b strings.Builder
	for i, c := range s {
		if i > 0 && (len(s)-i)%3 == 0 {
			b.WriteByte(',')
		}
		b.WriteRune(c)
	}
	if neg {
		return "-" + b.String()
	}
	return b.String()
}

// modelRelaySummary is what the project's Claude credential card shows about
// the relay: whether this project's runs would go through it, through which
// listener, with which models, and — when they would not — why.
type modelRelaySummary struct {
	// On: the hub runs the relay for sandboxed runs.
	On bool `json:"on"`
	// Relayed: this project's credential would be relayed.
	Relayed bool `json:"relayed"`
	// Listener is where sandboxes reach it: git_proxy or dashboard.
	Listener string `json:"listener,omitempty"`
	// Models is the allowlist its runs get; ProjectModels the project's own
	// narrowing, if any; HubModels the hub's.
	Models        []string `json:"models,omitempty"`
	ProjectModels []string `json:"project_models,omitempty"`
	HubModels     []string `json:"hub_models,omitempty"`
	// Kind is the credential kind the project's grant holds.
	Kind string `json:"kind,omitempty"`
	// Note says why a credential is not relayed, or what is wrong with the
	// relay.
	Note string `json:"note,omitempty"`
	// HubCredential: the hub's own key is allowed here.
	HubCredential bool `json:"hub_credential,omitempty"`
}

// modelRelaySummaryFor describes the relay for a project whose preflight
// report is rep.
func modelRelaySummaryFor(workDir string, rep harnessReport) *modelRelaySummary {
	if !modelRelayWanted.Load() {
		return nil
	}
	out := &modelRelaySummary{On: true}
	svc := activeModelRelay()
	cfg, _ := controlPlaneConfig()
	// The section a dispatch would be decided by: the running relay's, or,
	// with none running, what the file states.
	var (
		mr     config.ModelRelayConfig
		known  bool
		broken error
	)
	switch {
	case svc != nil:
		mr, broken = svc.settingsFrom(cfg)
		known = broken == nil
	case cfg != nil:
		mr, known = cfg.Executors.ModelRelay, true
	}
	if known {
		out.Listener = mr.ListenerName()
		out.HubModels = mr.EffectiveModels()
		out.HubCredential = mr.HubCredentialAllowed(policyProjectPath(workDir), rep.ExecutorID)
	}
	out.ProjectModels = projectRelayModels(workDir)
	out.Models = out.HubModels
	if len(out.ProjectModels) > 0 {
		out.Models = claudeproxy.IntersectModels(out.ProjectModels, out.HubModels)
	}
	if svc == nil {
		out.Note = "The relay is not running on this hub process: " + modelRelayUnavailableReason() +
			". Runs it would serve are refused."
		return out
	}
	if broken != nil {
		out.Note = "The relay's settings were edited into ones it cannot run — " + broken.Error() +
			". Runs it would serve are refused until they load."
		return out
	}
	if !rep.Isolates || len(relayKeysFor(rep.Provider)) == 0 {
		out.Note = "Runs here are not relayed: the relay serves claudecode and anthropic runs on executors that " +
			"isolate from the hub."
		return out
	}
	keys := map[string]string{}
	for _, k := range relayKeysFor(rep.Provider) {
		keys[k.Key] = k.Kind
	}
	for _, g := range rep.Satisfied {
		for _, k := range g.Keys {
			if kind, ok := keys[k]; ok && out.Kind == "" {
				out.Kind = kind
			}
		}
	}
	switch {
	case out.Kind == "" && out.HubCredential:
		out.Kind = relayKindAPIKey
		if !relayProven(out.Kind) {
			out.Note = "The hub's own anthropic.api_key is allowed for this project, but API keys have not been " +
				"proven through the relay against the real API yet, so it is not used; grant a Claude OAuth token."
			return out
		}
		out.Relayed = true
	case out.Kind == "":
		out.Note = "No Claude credential is granted for the relay to keep."
	case !relayProven(out.Kind):
		out.Note = fmt.Sprintf("A %s has not been proven through the relay against the real API, so it still "+
			"reaches the sandbox as before the relay; a Claude OAuth token would be relayed.", relayKindLabel(out.Kind))
	default:
		out.Relayed = true
	}
	sort.Strings(out.Models)
	return out
}
