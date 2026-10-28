package ui

// model_relay.go: the hub's model relay for sandboxed runs (Task 20435).
//
// A run on an executor that isolates from the hub — a container, a Pod, an
// enrolled device, a virtual executor — used to be handed its Claude
// credential as a leased environment variable. The workload held the
// plaintext for the whole run: it could print it, commit it or send it
// anywhere, a revocation could not take it out of a running device task, and
// the spend the hub charged was whatever the run said it spent.
//
// With executors.model_relay on, the run's lease still names the grant, but
// the credential is withheld from what the sandbox is given
// (model_relay_dispatch.go). The sandbox gets ANTHROPIC_BASE_URL pointing here
// and a session token worth only its run's model calls, and this process spends
// the credential upstream. It is pkg/claudeproxy — the CI relay's engine — with
// a session per run instead of per pipeline:
//
//   - the session carries the credential its run's grant holds, never the
//     hub's own unless an administrator allowed that for the project or the
//     executor;
//   - it stands on the run's secret lease: extended as the lease is, ended
//     with it — released at the run's end, revoked, lapsed — and with its
//     grant, so a revocation refuses the very next call;
//   - it is recorded (proxy_sessions, kind "model") and comes back with the
//     lease when another hub process adopts the run;
//   - each response's usage is read from the API's own counts and charged to
//     the identity the dispatch resolved, and a call that would pass that
//     identity's daily budget is refused with a 403 naming the cap — Claude
//     Code gives up on a 403 at once, where it retries a 401 for minutes.
//
// It is served on the git proxy's listener by default, at /_anthropic — a
// sandbox reaches it where it reaches the git proxy, through the same firewall
// rule, over TLS the hub's CA certifies — or on the dashboard's own listener.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/blechschmidt/cloop/pkg/auditaction"
	"github.com/blechschmidt/cloop/pkg/claudeproxy"
	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/cost"
	"github.com/blechschmidt/cloop/pkg/hubmetrics"
	"github.com/blechschmidt/cloop/pkg/quota"
	"github.com/blechschmidt/cloop/pkg/redact"
	"github.com/blechschmidt/cloop/pkg/sessionrecord"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

const (
	// modelRelayMount is where the relay is served, on either listener. One
	// path segment beginning with an underscore, so on the git proxy's
	// listener no repository path can be taken for it (gitproxy.Route).
	modelRelayMount = "/_anthropic"

	// modelRelayTokenPrefix starts every session token, so a secret scanner
	// recognises one (pkg/redact) and tells it from a CI pipeline's.
	modelRelayTokenPrefix = redact.RelayTokenPrefix

	// ownerModelRelay is the cluster ownership kind for relay sessions.
	ownerModelRelay = "modelrelay"

	// clusterAPIProxyModel is where another member forwards a relay call for
	// a session this one holds.
	clusterAPIProxyModel = clusterAPIPrefix + "proxy/model"

	// modelRelayReapInterval is how often lapsed sessions are swept; expiry
	// is enforced on every call regardless.
	modelRelayReapInterval = time.Minute

	// modelRelaySpendKeep is how long the spend of a session that ended is
	// kept in memory, for the run's settlement to read when the record could
	// not be written.
	modelRelaySpendKeep = time.Hour
)

// modelRelayCheckpointInterval is how often live sessions' counters and spend
// are written to their records: a hub killed outright loses at most this much
// of a session's account. A variable so tests can shorten it.
var modelRelayCheckpointInterval = 15 * time.Second

// modelRelayService is the running relay: the session registry, the proxy
// serving it, and the account of what each session spent.
type modelRelayService struct {
	// cfg is the section the relay was started from. The model allowlist and
	// the hub-credential allowance are read again at each dispatch.
	cfg config.ModelRelayConfig

	reg   *claudeproxy.Registry
	proxy *claudeproxy.Proxy

	// auditDB is the control plane, open for the service's life: the relay
	// writes one audit row per decision and one record per session, and a
	// second connection per event would contend with this process's own.
	auditDB *statedb.DB

	stop context.CancelFunc
	done chan struct{}

	mu sync.Mutex
	// spend is each session's priced spend, per model — what was charged to
	// its payer as each response arrived. Guarded by mu.
	spend map[string]*sessionrecord.ModelSpend
	// ended remembers when a session's spend stopped moving, so it is kept
	// for its run's settlement for a while and then dropped. Guarded by mu.
	ended map[string]time.Time
}

var (
	modelRelayOnce    sync.Once
	modelRelayCurrent atomic.Pointer[modelRelayService]
	// modelRelayWanted: the hub's configuration has the relay on. A dispatch
	// it would serve is then refused while the relay is not running, rather
	// than handed the credential the operator turned the relay on to keep.
	modelRelayWanted atomic.Bool
	// modelRelayFailure is why an enabled relay did not start.
	modelRelayFailure atomic.Pointer[string]
	// modelRelayHub is the Server whose quotas the relay charges and checks.
	// One per process in production; tests set it.
	modelRelayHub atomic.Pointer[Server]
)

// activeModelRelay returns the running relay, or nil.
func activeModelRelay() *modelRelayService { return modelRelayCurrent.Load() }

// setModelRelayServer names the Server whose quota enforcer the relay charges.
func setModelRelayServer(s *Server) {
	if s != nil {
		modelRelayHub.Store(s)
	}
}

// ensureModelRelay starts the relay the configuration asks for, once per
// process — like the git proxy, changing it takes a restart. A relay that
// cannot start is reported and leaves modelRelayWanted set: the runs it would
// have served are refused, not handed their credentials.
func ensureModelRelay(cfg *config.Config, dir string) {
	modelRelayOnce.Do(func() { bringUpModelRelay(cfg, dir) })
}

// bringUpModelRelay starts the relay cfg enables. One that cannot start —
// its section did not load as written, or its listener or database would not
// open — is still wanted: every run it would relay is refused.
func bringUpModelRelay(cfg *config.Config, dir string) {
	if cfg == nil || !cfg.Executors.ModelRelay.Enabled {
		return
	}
	modelRelayWanted.Store(true)
	var svc *modelRelayService
	err := modelRelayBrokenError(cfg.Executors.ModelRelay)
	if err == nil {
		svc, err = startModelRelay(cfg.Executors.ModelRelay, dir)
	}
	if err != nil {
		msg := err.Error()
		modelRelayFailure.Store(&msg)
		fmt.Fprintf(os.Stderr, "ui: model relay NOT started: %v\n"+
			"    executors.model_relay is enabled, so every run it would relay is refused\n"+
			"    rather than handed its Claude credential. Fix the section or set enabled: false.\n", err)
		return
	}
	modelRelayCurrent.Store(svc)
	fmt.Fprintf(os.Stderr, "ui: model relay on for sandboxed runs, served on the %s listener at %s; "+
		"models %s\n", svc.cfg.ListenerName(), modelRelayMount, strings.Join(svc.cfg.EffectiveModels(), ", "))
}

// modelRelayBrokenError is why mr cannot be run as the hub's configuration
// states it, nil when it can: Load keeps a section it could not take as
// written on, and marks it, so the runs it would relay are refused rather than
// handed their credential.
func modelRelayBrokenError(mr config.ModelRelayConfig) error {
	if mr.Broken == "" {
		return nil
	}
	return fmt.Errorf("executors.model_relay does not load as written: %s", mr.Broken)
}

// modelRelayUnavailableReason is why a wanted relay is not serving, "" when
// it is serving or not wanted.
func modelRelayUnavailableReason() string {
	if !modelRelayWanted.Load() || activeModelRelay() != nil {
		return ""
	}
	if p := modelRelayFailure.Load(); p != nil {
		return *p
	}
	return "it has not started"
}

// startModelRelay builds the registry, its durable store and the proxy.
func startModelRelay(mr config.ModelRelayConfig, dir string) (*modelRelayService, error) {
	db, err := statedb.Open(state.DBPath(dir))
	if err != nil {
		return nil, fmt.Errorf("open the control plane: %w", err)
	}
	svc := &modelRelayService{
		cfg:     mr,
		auditDB: db.AsControlPlane(),
		spend:   map[string]*sessionrecord.ModelSpend{},
		ended:   map[string]time.Time{},
		done:    make(chan struct{}),
	}
	// The base URL is the listener's, decided per dispatch; the registry's own
	// is never handed out.
	reg := claudeproxy.NewRegistryWithPrefix("", modelRelayTokenPrefix)
	reg.OnEvent = withProxySessionOwnership(ownerModelRelay, modelRelaySessionEvent, svc.observe)
	// Every session is recorded, so the process adopting its run restores it
	// with the lease. Without a cluster member id there is nobody to record
	// it as, and the record's write fails: the session works, unrecorded.
	reg.Store = sessionrecord.NewModelStore(svc.auditDB, sessionHolderID, svc.spendOf, logSessionStoreErr)
	svc.reg = reg
	px, err := claudeproxy.New(reg, claudeproxy.Options{
		PathPrefix:       modelRelayMount,
		SessionUpstreams: true,
		ExplainClosed:    true,
		UserAgent:        "cloop-model-relay/1",
		Unauthenticated: "the model relay session token was not accepted: this run's session is not one " +
			"this hub serves",
		Admit:    svc.admit,
		OnSpend:  svc.onSpend,
		Fallback: clusterProxyFallback(ownerModelRelay, clusterAPIProxyModel),
	})
	if err != nil {
		_ = svc.auditDB.Close()
		return nil, err
	}
	svc.proxy = px
	ctx, stop := context.WithCancel(context.Background())
	svc.stop = stop
	go svc.maintain(ctx)
	return svc, nil
}

// maintain checkpoints live sessions and sweeps lapsed ones until stop.
func (svc *modelRelayService) maintain(ctx context.Context) {
	defer close(svc.done)
	defer recoverGoroutine("model relay maintenance")
	cp := time.NewTicker(modelRelayCheckpointInterval)
	defer cp.Stop()
	reap := time.NewTicker(modelRelayReapInterval)
	defer reap.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-cp.C:
			svc.reg.Checkpoint()
		case <-reap.C:
			svc.reg.ReapExpired()
			svc.forgetEndedSpend(time.Now())
		}
	}
}

// close stops the relay for the hub's shutdown: a recorded session is
// suspended for the process that adopts its run, any other is closed.
func (svc *modelRelayService) close(reason string) {
	if svc == nil {
		return
	}
	if svc.stop != nil {
		svc.stop()
		<-svc.done
	}
	for _, s := range svc.reg.Sessions() {
		if s.Durable() {
			if svc.reg.Suspend(s.ID, reason) {
				releaseSuspendedSessions(ownerModelRelay, []string{s.ID})
			}
			continue
		}
		_ = svc.reg.Close(s.ID, reason)
	}
	_ = svc.auditDB.Close()
}

// closeModelRelay stops this process's relay at shutdown.
func closeModelRelay() {
	if svc := modelRelayCurrent.Swap(nil); svc != nil {
		svc.close("the hub is shutting down")
	}
}

// ServeHTTP serves a relay call that reached this process.
func (svc *modelRelayService) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	svc.proxy.ServeHTTP(w, r)
}

// serveModelRelayOnGitProxy is the git proxy listener's route for the relay:
// served there when the relay runs and is configured for that listener, and an
// API-shaped 404 otherwise, so a harness reports a missing relay rather than an
// unreadable response.
func serveModelRelayOnGitProxy(w http.ResponseWriter, r *http.Request) {
	svc := activeModelRelay()
	if svc == nil || svc.cfg.ListenerName() != config.ModelRelayListenerGitProxy {
		writeRelayNotHere(w)
		return
	}
	svc.ServeHTTP(w, r)
}

// handleModelRelay is the dashboard listener's route for the relay.
func (s *Server) handleModelRelay(w http.ResponseWriter, r *http.Request) {
	svc := activeModelRelay()
	if svc == nil || svc.cfg.ListenerName() != config.ModelRelayListenerDashboard {
		writeRelayNotHere(w)
		return
	}
	svc.ServeHTTP(w, r)
}

func writeRelayNotHere(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusNotFound)
	_, _ = w.Write([]byte(`{"type":"error","error":{"type":"not_found_error",` +
		`"message":"this hub serves no model relay on this listener"}}`))
}

// isModelRelayEndpoint reports whether a request is for the relay on the
// dashboard's listener. Like the CI relay it authenticates against something
// the hub's middleware cannot check — a session token this hub minted for a
// run — and the sandbox presenting it holds no hub session by design.
func isModelRelayEndpoint(r *http.Request) bool {
	p := r.URL.Path
	return p == modelRelayMount || strings.HasPrefix(p, modelRelayMount+"/")
}

// modelRelaySessionEvent extracts (session id, served, ended) for cluster
// ownership: a minted or restored session is claimed, a closed or suspended
// one released.
func modelRelaySessionEvent(ev claudeproxy.Event) (string, bool, bool) {
	served := ev.Kind == claudeproxy.EventSessionMinted || ev.Kind == claudeproxy.EventSessionRestored
	ended := ev.Kind == claudeproxy.EventSessionClosed || ev.Kind == claudeproxy.EventSessionSuspended
	return ev.SessionID, served, ended
}

// ── decisions ───────────────────────────────────────────────────────────────

// admit holds the identity paying for a run to its daily budgets before a
// call is relayed: daily_token_budget and daily_cost_usd, from the bindings
// and overrides that apply to it. A refusal is a 403 naming the cap — Claude
// Code ends the task on a 403 at once — and the next UTC day clears it.
func (svc *modelRelayService) admit(s *claudeproxy.Session, _ string) *claudeproxy.Denial {
	hub := modelRelayHub.Load()
	if hub == nil || s.Payer == "" {
		return nil
	}
	e := hub.quotas()
	if e == nil {
		return nil
	}
	err := e.CheckSpendIdentity(s.Payer)
	if err == nil {
		return nil
	}
	var d *quota.Denial
	if !errors.As(err, &d) {
		// The budget could not be read: relayed, as a run whose spend cannot
		// be checked is not a run over its budget. The charge still lands.
		return nil
	}
	return &claudeproxy.Denial{Reason: claudeproxy.DenyBudget, Status: http.StatusForbidden,
		Message: budgetRefusal(d)}
}

// budgetRefusal names the cap a payer has spent, for the harness to print.
func budgetRefusal(d *quota.Denial) string {
	what := string(d.Resource)
	amount := func(v float64) string { return fmt.Sprintf("%.0f tokens", v) }
	switch d.Resource {
	case quota.ResDailyTokens:
		what = "daily token budget (daily_token_budget)"
	case quota.ResDailyCostUSD:
		what = "daily spend budget (daily_cost_usd)"
		amount = func(v float64) string { return fmt.Sprintf("$%.2f", v) }
	}
	return fmt.Sprintf("the %s of %s for %s is spent: %s used today. The model relay refuses this run's "+
		"calls until it resets at 00:00 UTC or an administrator raises it", what, amount(d.Limit), d.Identity,
		amount(d.Used))
}

// onSpend charges what a response spent, as the API counted it, to the
// session's payer — tokens and estimated USD into the daily counters the
// quotas read — and keeps the session's priced account.
func (svc *modelRelayService) onSpend(s *claudeproxy.Session, sp claudeproxy.Spend) {
	usd, _ := cost.EstimateCached(sp.Model, cost.CachedUsage{
		Input: sp.Input, Output: sp.Output, CacheRead: sp.CacheRead,
		CacheWrite5m: sp.CacheWrite - sp.CacheWrite1h, CacheWrite1h: sp.CacheWrite1h,
	})
	svc.mu.Lock()
	acct := svc.spend[s.ID]
	if acct == nil {
		acct = &sessionrecord.ModelSpend{}
		svc.spend[s.ID] = acct
	}
	acct.USD += usd
	if acct.Models == nil {
		acct.Models = map[string]sessionrecord.ModelTokens{}
	}
	t := acct.Models[sp.Model]
	t.Input += sp.Input
	t.Output += sp.Output
	t.CacheRead += sp.CacheRead
	t.CacheWrite += sp.CacheWrite
	acct.Models[sp.Model] = t
	svc.mu.Unlock()

	hubmetrics.ModelRelayTokens.Add(float64(sp.Input), hubmetrics.ModelRelayInput)
	hubmetrics.ModelRelayTokens.Add(float64(sp.Output), hubmetrics.ModelRelayOutput)
	hubmetrics.ModelRelayTokens.Add(float64(sp.CacheRead), hubmetrics.ModelRelayCacheRead)
	hubmetrics.ModelRelayTokens.Add(float64(sp.CacheWrite), hubmetrics.ModelRelayCacheWrite)
	hubmetrics.ModelRelayCostUSD.Add(usd)

	if hub := modelRelayHub.Load(); hub != nil && s.Payer != "" {
		hub.RecordQuotaSpend(s.Payer, float64(sp.Tokens()), usd)
	}
}

// spendOf is a session's account, for its record.
func (svc *modelRelayService) spendOf(id string) sessionrecord.ModelSpend {
	svc.mu.Lock()
	defer svc.mu.Unlock()
	if a := svc.spend[id]; a != nil {
		return a.Clone()
	}
	return sessionrecord.ModelSpend{}
}

// seedSpend restores a session's account from its record, for a session this
// process restored.
func (svc *modelRelayService) seedSpend(id string, s sessionrecord.ModelSpend) {
	c := s.Clone()
	svc.mu.Lock()
	svc.spend[id] = &c
	delete(svc.ended, id)
	svc.mu.Unlock()
}

// dropSpend forgets an account seeded for a restore that did not happen.
func (svc *modelRelayService) dropSpend(id string) {
	svc.mu.Lock()
	delete(svc.spend, id)
	delete(svc.ended, id)
	svc.mu.Unlock()
}

// forgetEndedSpend drops the accounts of sessions that ended long enough ago.
func (svc *modelRelayService) forgetEndedSpend(now time.Time) {
	svc.mu.Lock()
	defer svc.mu.Unlock()
	for id, at := range svc.ended {
		if now.Sub(at) > modelRelaySpendKeep {
			delete(svc.ended, id)
			delete(svc.spend, id)
		}
	}
}

// ── what the relay records ─────────────────────────────────────────────────

// observe turns the relay's events into metrics and audit rows. A relayed call
// is counted, not written: a run makes hundreds, and the trail is for the
// decisions — sessions issued, ended, moved between processes, calls refused.
func (svc *modelRelayService) observe(e claudeproxy.Event) {
	var action auditaction.Action
	switch e.Kind {
	case claudeproxy.EventSessionMinted:
		hubmetrics.ModelRelaySessionsLive.Add(1)
		action = auditaction.ActionModelRelaySessionMinted
	case claudeproxy.EventSessionRestored:
		hubmetrics.ModelRelaySessionsLive.Add(1)
		action = auditaction.ActionModelRelaySessionRestored
	case claudeproxy.EventSessionClosed:
		hubmetrics.ModelRelaySessionsLive.Add(-1)
		svc.markEnded(e.SessionID)
		action = auditaction.ActionModelRelaySessionClosed
	case claudeproxy.EventSessionSuspended:
		hubmetrics.ModelRelaySessionsLive.Add(-1)
		svc.markEnded(e.SessionID)
		action = auditaction.ActionModelRelaySessionSuspended
	case claudeproxy.EventRelayAllowed:
		hubmetrics.ModelRelayRequests.Inc(hubmetrics.ModelRelayAllowed)
		return
	case claudeproxy.EventRelayDenied:
		hubmetrics.ModelRelayRequests.Inc(hubmetrics.ModelRelayRefused)
		reason := string(e.Reason)
		if reason == "" {
			reason = "upstream_unreachable"
		}
		hubmetrics.ModelRelayRefusals.Inc(reason)
		action = auditaction.ActionModelRelayDenied
	case claudeproxy.EventRejected:
		if e.SessionID == "" {
			// No usable token at all: a stray request, or a harness probing
			// the base URL. Counted, not written.
			hubmetrics.ModelRelayRequests.Inc(hubmetrics.ModelRelayRejected)
			return
		}
		hubmetrics.ModelRelayRequests.Inc(hubmetrics.ModelRelayEnded)
		action = auditaction.ActionModelRelayRejected
	default:
		return
	}
	svc.audit(action, e)
}

// markEnded starts the clock on keeping an ended session's account.
func (svc *modelRelayService) markEnded(id string) {
	svc.mu.Lock()
	svc.ended[id] = time.Now()
	svc.mu.Unlock()
}

// audit writes one decision to the control plane's trail. The event carries no
// credential by construction: claudeproxy.Event has no field a prompt, a
// completion, a session token or an upstream credential could travel in.
func (svc *modelRelayService) audit(action auditaction.Action, e claudeproxy.Event) {
	// The engine names its events after the CI relay it was written for;
	// the record names the action it is filed under.
	e.Kind = claudeproxy.EventKind(action)
	payload, err := json.Marshal(e)
	if err != nil {
		payload = []byte(`{}`)
	}
	actor := e.Payer
	if actor == "" {
		actor = "model-relay"
	}
	at := e.At
	if at.IsZero() {
		at = time.Now().UTC()
	}
	if err := svc.auditDB.AppendAuditEvent(&statedb.AuditEvent{
		Timestamp:  at,
		Actor:      actor,
		EventType:  string(action),
		EntityType: "model_relay_session",
		EntityID:   e.SessionID,
		Payload:    string(payload),
	}); err != nil {
		fmt.Fprintf(os.Stderr, "ui: model relay audit: %v (event: %s %s)\n", err, action, e.SessionID)
	}
}
