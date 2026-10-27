package ui

// hubhealth.go is Settings → Hub health (Task 20434): the hub doctor's checks,
// run by the hub on itself.
//
// pkg/hubdoctor holds some eighty checks of a hosted control plane — a hub CA
// nearing expiry, audit forwarding falling behind, edge devices lagging, an API
// token waiting for approval — and until this file they ran only as `cloop hub
// doctor`, in a shell on the hub host, in the hub's directory, with both of its
// configuration files in reach. An administrator of a Helm or compose
// deployment, or one without a shell there, never saw them, and nothing told
// anybody when one started failing.
//
// GET /api/hub/health runs them in this process instead (hubdoctor.Live):
// against this hub's directory and the configuration it runs under, overlay
// included, with this hub's port — the listener checks are about the process
// that answers, which is why the report names the cluster member it came from.
// What a run must not do inside a serving hub is hubdoctor's to keep out — no
// step that starts a workload, each step bounded and its panic recovered — and
// this file's to answer for it where the shell's doctor would ask from
// outside (hubHealthSelf): how the listener admits requests, the KMS clients
// the hub pinned, what its executor supervisor last recorded, what its own
// sign-in client holds of the identity provider.
//
// # When a report is made (Task 20446)
//
// Each member makes its report itself, at most one at a time: on a cadence
// (ui.hub_health_interval, five minutes by default), when one of its
// configuration files changes, when something happens that changes what the
// checks find — an executor enrolled, lost or reconfigured, a step of a CA
// rotation, a sealing key rotated — and when an administrator presses Run the
// checks again. A read is answered from the last report for as long as it is
// current. The heaviest checks are made less often still (hubdoctor's
// liveEvery), and the identity provider is read from the hub's own sign-in
// client rather than asked.
//
// It used to be the other way round: every open administrator's tab asked
// again at each report's one-minute expiry, so a member made one run a
// minute per tab and called its identity provider twice per run. Now the
// member pushes each report's summary — the failing count, its generation,
// when it was made and when the next is due — to the dashboards that may read
// it, and a page asks only when it cannot have heard: when its socket opens
// or reopens, and while Settings → Hub health is on screen.
//
// # Who hears it
//
// Only a stream whose identity may read the report — config.write across the
// hub, the route's own permission — is sent the summary (hubHealthMayRead),
// asked of the identity as it stands now rather than as it stood when the
// stream opened: the session's current claims, the token as it reads now.
// The same question is asked again whenever this member hears that a
// credential changed — a session's claims refreshed or ended, a token or the
// static token revoked — and every thirty seconds for a change nobody
// announced, such as a runtime role binding; a stream that could read the
// report and no longer may is told so, carrying no count, and one that has
// become able to is sent the current summary.
//
// Everything a check wrote passes through two redactions before it leaves:
// the exact credential values this hub's configuration and environment hold,
// and pkg/redact's registry of credential shapes — a password in an issuer's
// URL, a token in an error string from three packages down. The page renders
// what is left as text.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/blechschmidt/cloop/pkg/apitoken"
	"github.com/blechschmidt/cloop/pkg/authz"
	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/executorstore"
	"github.com/blechschmidt/cloop/pkg/hubdoctor"
	"github.com/blechschmidt/cloop/pkg/hubmetrics"
	"github.com/blechschmidt/cloop/pkg/kms"
	"github.com/blechschmidt/cloop/pkg/logger"
	"github.com/blechschmidt/cloop/pkg/oidcauth"
	"github.com/blechschmidt/cloop/pkg/redact"
	"github.com/blechschmidt/cloop/pkg/rootkey"
	"github.com/blechschmidt/cloop/pkg/secretbroker"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

const (
	// hubHealthRerunFloor is how fresh a report may be before "Run the checks
	// again" is answered from it rather than with a new run: the button
	// dials whatever the checks dial, and pressing it twice is not a reason
	// to do that twice.
	hubHealthRerunFloor = 10 * time.Second

	// hubHealthProbeTimeout bounds each network probe a check makes. Half the
	// CLI's default: a dashboard's report should come back in seconds, and a
	// check that needs longer to reach its issuer has found something to say.
	hubHealthProbeTimeout = 5 * time.Second

	// hubHealthWatchEvery is how often the member looks at its configuration
	// files' size and modification time. A change it sees on two looks in a
	// row — an editor that saves in two writes is one change — makes a report.
	hubHealthWatchEvery = 3 * time.Second

	// hubHealthFirstRun is how long after it starts a member makes its first
	// report unasked: long enough for its executors to settle. A dashboard
	// that asks sooner gets one made for it.
	hubHealthFirstRun = 30 * time.Second

	// hubHealthEventDelay is how long a report waits after an event that
	// changes findings, so a burst — a fleet reconnecting after a restart —
	// is one report; hubHealthEventSpacing is how soon after the last report
	// an event may make the next one at all.
	hubHealthEventDelay   = 5 * time.Second
	hubHealthEventSpacing = time.Minute

	// hubHealthAudienceEvery is how often a member asks again, of every
	// stream, whether its identity may read the report: the fallback for a
	// change of authority nobody announced.
	hubHealthAudienceEvery = 30 * time.Second

	// hubHealthIdPRetry is how often a report asks the hub's sign-in client to
	// resolve its issuer again while the client holds no usable resolution —
	// discovery missing, no keys, or a last fetch that failed — and
	// hubHealthIdPRetryFresh how often Run the checks again may. The client
	// asks the provider by itself only when a sign-in needs it, so a provider
	// that blipped as the hub started, or while a key set was refreshed, would
	// otherwise read as failing until somebody signed in. A client that holds
	// a resolution is never asked.
	hubHealthIdPRetry      = 15 * time.Minute
	hubHealthIdPRetryFresh = time.Minute

	// hubHealthDocsBase is the runbook page that explains each group of
	// checks, on the published documentation site.
	hubHealthDocsBase = "https://blechschmidt.github.io/cloop/docs/operations/runbook/"
)

// Why a report was made: the trigger label of cloop_hub_health_reports_total.
const (
	hubHealthTriggerSchedule = "schedule" // the cadence came round
	hubHealthTriggerConfig   = "config"   // a configuration file changed
	hubHealthTriggerEvent    = "event"    // an executor, CA rotation or key change
	hubHealthTriggerRerun    = "rerun"    // Run the checks again
	hubHealthTriggerRequest  = "request"  // a read found no report it could serve
)

// hubHealthState is one process's report and its schedule. The zero value is
// ready.
type hubHealthState struct {
	live hubdoctor.Live

	mu sync.Mutex
	// report is the last one made, and print the fingerprint of the
	// configuration files it was made under.
	report *hubHealthReport
	print  string
	// generation counts the reports this member has made; the latest
	// carries it.
	generation uint64
	// madeAt is when the latest report's run began and dueAt when the next
	// is due — the schedule's clock, kept monotonic, which the report's own
	// wall-clock times are not.
	madeAt, dueAt time.Time
	// inflight is the run under way, which everybody else waits for.
	inflight *hubHealthCall
	// eventAt is when the first event no report has seen yet arrived, zero
	// while none is waiting for one, and eventLast when the latest did.
	eventAt, eventLast time.Time
	// idpTriedAt is when a report last asked the sign-in client to resolve
	// its issuer again.
	idpTriedAt time.Time

	// deliverMu makes deliveries one at a time, each deciding and sending
	// with the latest report: two passes overlapping must not send a count
	// decided before a demotion after the withdrawal decided after it, or
	// an older report after a newer one. pushedGen, under it, is the latest
	// generation pushed to everybody.
	deliverMu sync.Mutex
	pushedGen uint64
	// looked is the fingerprint the scheduler's last look saw, and settled
	// the last one two looks agreed on: files that changed are reported on
	// once they have settled.
	looked, settled string
	// wake tells the scheduler an event arrived (cap 1, made by wakeLocked).
	wake chan struct{}

	// Test knobs, set before the server starts: the per-check deadline, the
	// cadence (which replaces ui.hub_health_interval, unbounded) and checks
	// added to the hub's own.
	checkTimeout time.Duration
	interval     time.Duration
	extra        []hubdoctor.Check
}

// hubHealthCall is one run that others wait on.
type hubHealthCall struct {
	done   chan struct{}
	report *hubHealthReport
}

// wakeLocked returns the scheduler's wake channel, making it the first time.
// h.mu is held.
func (h *hubHealthState) wakeLocked() chan struct{} {
	if h.wake == nil {
		h.wake = make(chan struct{}, 1)
	}
	return h.wake
}

// hubHealthReport is the response of GET /api/hub/health.
type hubHealthReport struct {
	// Member is the hub process that ran the checks.
	Member hubHealthMember `json:"member"`
	// Generation numbers this member's reports, the latest highest.
	Generation uint64    `json:"generation"`
	CheckedAt  time.Time `json:"checked_at"`
	// ExpiresAt is when the member's next report is due.
	ExpiresAt time.Time `json:"expires_at"`
	// ServedAt is when this response left the hub, so a page times the
	// report by the hub's clock rather than its own.
	ServedAt   time.Time `json:"served_at"`
	DurationMS int64     `json:"duration_ms"`
	// Config names the files the configuration was read from.
	Config     hubHealthConfig `json:"config"`
	StrictMode bool            `json:"strict_mode"`
	Counts     hubHealthCounts `json:"counts"`
	// Failing is the number of failed checks: what the header shows.
	Failing  int                    `json:"failing"`
	Findings []hubHealthFinding     `json:"findings,omitempty"`
	Steps    []hubdoctor.StepResult `json:"steps,omitempty"`
	// NotRun is what the dashboard leaves to `cloop hub doctor` on the host.
	NotRun []hubHealthNotRun `json:"not_run,omitempty"`
}

type hubHealthMember struct {
	ID        string `json:"id"`
	Hostname  string `json:"hostname,omitempty"`
	Port      int    `json:"port,omitempty"`
	Clustered bool   `json:"clustered"`
	Leader    bool   `json:"leader"`
}

type hubHealthConfig struct {
	Files []string `json:"files"`
	// Error is why the configuration could not be loaded, when it could not.
	Error string `json:"error,omitempty"`
}

type hubHealthCounts struct {
	Pass int `json:"pass"`
	Warn int `json:"warn"`
	Fail int `json:"fail"`
}

// hubHealthFinding is a hubdoctor.Finding as it leaves the hub: redacted, and
// with the documentation anchor of its group.
type hubHealthFinding struct {
	Check       string         `json:"check"`
	Title       string         `json:"title"`
	Severity    string         `json:"severity"`
	Message     string         `json:"message"`
	Remediation string         `json:"remediation,omitempty"`
	Details     map[string]any `json:"details,omitempty"`
	Docs        string         `json:"docs"`
	// AsOf is when a check made less often than reports are last ran; zero
	// is now.
	AsOf time.Time `json:"as_of,omitzero"`
}

type hubHealthNotRun struct {
	Check   string `json:"check"`
	Why     string `json:"why"`
	Command string `json:"command"`
}

// hubHealthRoutes is the report's route.
func (s *Server) hubHealthRoutes() []routeSpec {
	return []routeSpec{
		// config.write at global scope, as the hub-wide Settings around it
		// are: a report spells out the configuration's weak points, and the
		// people who need it are the ones who may change it. Through the
		// route gate, so authz.Enforced decides what the permission means.
		{Pattern: "GET /api/hub/health", Handler: s.handleHubHealth, Perm: authz.PermConfigWrite, Scope: scopeGlobal},
	}
}

// handleHubHealth answers with this member's report: the last one while it is
// current, otherwise a new run. ?summary=1 leaves the findings out — what the
// header needs — and ?fresh=1 asks for a new run unless the last one is
// seconds old.
//
// GET /api/hub/health
func (s *Server) handleHubHealth(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	out := *s.hubHealthReport(q.Get("fresh") == "1")
	out.ServedAt = time.Now().UTC()
	if q.Get("summary") == "1" {
		out.Findings, out.Steps, out.NotRun = nil, nil, nil
	}
	w.Header().Set("Cache-Control", "no-store")
	jsonOK(w, &out)
}

// hubHealthReport returns the report a read is answered with: the last one,
// while it was made under the configuration in force and its successor is not
// yet due — and, for a rerun, while it is seconds old — or else a new one.
func (s *Server) hubHealthReport(fresh bool) *hubHealthReport {
	h := &s.hubHealth
	fp := s.hubConfigFingerprint()
	trigger := hubHealthTriggerRequest
	if fresh {
		trigger = hubHealthTriggerRerun
	}
	return s.hubHealthRun(trigger, fp, fresh, func(now time.Time) bool {
		return h.print == fp && now.Before(h.dueAt) && !(fresh && now.Sub(h.madeAt) >= hubHealthRerunFloor)
	})
}

// hubHealthRun returns the last report while current says it may stand, and
// otherwise makes one. One run at a time: a caller that finds one under way
// waits for it rather than starting another. current is asked with h.mu held,
// and only when there is a report.
func (s *Server) hubHealthRun(trigger, fp string, fresh bool, current func(now time.Time) bool) *hubHealthReport {
	h := &s.hubHealth
	for {
		h.mu.Lock()
		if rep := h.report; rep != nil && current(time.Now()) {
			h.mu.Unlock()
			return rep
		}
		if c := h.inflight; c != nil {
			h.mu.Unlock()
			<-c.done
			if c.report != nil {
				return c.report
			}
			continue // that run died; this caller makes the next one
		}
		c := &hubHealthCall{done: make(chan struct{})}
		h.inflight = c
		h.mu.Unlock()
		return s.runHubHealth(c, trigger, fp, fresh)
	}
}

// runHubHealth makes one run, publishes it, counts it, and pushes its summary
// to the streams that may read it.
func (s *Server) runHubHealth(c *hubHealthCall, trigger, fp string, fresh bool) (rep *hubHealthReport) {
	h := &s.hubHealth
	start := time.Now()
	defer func() {
		h.mu.Lock()
		h.inflight = nil
		if rep != nil {
			h.generation++
			rep.Generation = h.generation
			h.report, h.print = rep, fp
			h.madeAt, h.dueAt = start, start.Add(rep.ExpiresAt.Sub(rep.CheckedAt))
			// Events that arrived before this run began are in it; one that
			// arrived while it ran may not be, and stays waiting.
			if !h.eventAt.IsZero() && !start.Before(h.eventAt) {
				if h.eventLast.After(start) {
					h.eventAt = h.eventLast
				} else {
					h.eventAt, h.eventLast = time.Time{}, time.Time{}
				}
			}
		}
		wake := h.wakeLocked()
		h.mu.Unlock()
		c.report = rep
		close(c.done)
		if rep != nil {
			hubmetrics.HubHealthReports.Inc(trigger)
			s.deliverHubHealth(true, nil)
			// The schedule counts from this report, whoever asked for it.
			select {
			case wake <- struct{}{}:
			default:
			}
		}
	}()

	cfg, cfgErr := s.loadHubConfig()
	files := []string{config.ConfigPath(s.WorkDir)}
	if overlay := s.hubConfigOverlay(); overlay != "" {
		files = append(files, overlay)
	}
	scrub := hubHealthScrub{set: redact.New(hubSecretValues(cfg, files, os.Environ())...)}
	s.hubHealthRetryIdP(cfg, fresh)
	lr := h.live.Run(context.Background(), s.WorkDir, cfg, hubdoctor.LiveOptions{
		Options: hubdoctor.Options{
			Timeout: hubHealthProbeTimeout,
			Port:    s.Port,
			Self:    s.hubHealthSelf(),
		},
		CheckTimeout: h.checkTimeout,
		Extra:        h.extra,
		Generation:   fp,
		Fresh:        fresh,
		OnPanic: func(step string, v any, stack []byte) {
			s.log().Error(logger.EventHealthCheck, 0, "a hub health check panicked", map[string]interface{}{
				"step": step, "panic": scrub.text(fmt.Sprint(v)), "stack": scrub.text(string(stack)),
			})
		},
	})
	every := h.interval
	if every <= 0 {
		every = config.HubHealthIntervalDefault
		if cfg != nil {
			every = cfg.UI.EffectiveHubHealthInterval()
		}
	}
	end := time.Now()
	// Built aside and published whole: a report that failed half-way must
	// not be kept as though it were one.
	out := &hubHealthReport{
		Member:     s.hubHealthMember(),
		CheckedAt:  start.UTC(),
		ExpiresAt:  start.Add(every).UTC(),
		DurationMS: end.Sub(start).Milliseconds(),
		Config:     hubHealthConfig{Files: s.hubConfigFiles()},
		StrictMode: lr.StrictMode,
	}
	if cfgErr != nil {
		// Scrubbed whole, then cut: cut first, a credential across the cut
		// would leave its first half behind.
		out.Config.Error = truncateRunes(scrub.text(cfgErr.Error()), 400)
	}
	for _, f := range lr.Findings {
		hf := hubHealthFinding{
			Check:       hubHealthCheckID(f.Check),
			Title:       scrub.text(f.Title),
			Severity:    string(f.Severity),
			Message:     scrub.text(f.Message),
			Remediation: scrub.text(f.Remediation),
			Details:     scrub.details(f.Details),
			AsOf:        f.AsOf,
		}
		hf.Docs = hubHealthDocsURL(hf.Check)
		switch f.Severity {
		case hubdoctor.SeverityFail:
			out.Counts.Fail++
		case hubdoctor.SeverityWarn:
			out.Counts.Warn++
		default:
			hf.Severity = string(hubdoctor.SeverityPass)
			out.Counts.Pass++
		}
		out.Findings = append(out.Findings, hf)
	}
	out.Failing = out.Counts.Fail
	for _, st := range lr.Steps {
		st.Title, st.Panic = scrub.text(st.Title), scrub.text(st.Panic)
		st.ID = hubHealthCheckID(st.ID)
		out.Steps = append(out.Steps, st)
	}
	for _, n := range lr.NotRun {
		out.NotRun = append(out.NotRun, hubHealthNotRun{Check: n.Check, Why: n.Why,
			Command: fmt.Sprintf("cloop hub doctor %s --port %d", n.Flag, s.Port)})
	}
	return out
}

// hubHealthRetryIdP asks the hub's sign-in client to resolve its issuer again,
// through the client's own preflight — the round trips a sign-in makes first,
// which warm its caches and clear its recorded failure — when the report will
// read the issuer from the client (it is the configured one), the client holds
// no usable resolution, and the last such request was hubHealthIdPRetry ago
// (hubHealthIdPRetryFresh for Run the checks again).
func (s *Server) hubHealthRetryIdP(cfg *config.Config, fresh bool) {
	if cfg == nil || !cfg.UI.OIDC.Enabled || !s.oidcEnabled() {
		return
	}
	norm := func(v string) string { return strings.TrimRight(strings.TrimSpace(v), "/") }
	if norm(cfg.UI.OIDC.Issuer) != norm(s.OIDC.Issuer()) {
		return // resolved by the report itself, at most every 15 minutes
	}
	if st := s.OIDC.IdPState(); st.Discovery != nil && st.SigningKeys > 0 && st.LastError == nil {
		return
	}
	every := hubHealthIdPRetry
	if fresh {
		every = hubHealthIdPRetryFresh
	}
	h := &s.hubHealth
	h.mu.Lock()
	due := h.idpTriedAt.IsZero() || time.Since(h.idpTriedAt) >= every
	if due {
		h.idpTriedAt = time.Now()
	}
	h.mu.Unlock()
	if !due {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), hubHealthProbeTimeout)
	defer cancel()
	_, _ = s.OIDC.Preflight(ctx)
}

// hubHealthSelf is what this process knows about itself that the doctor would
// otherwise ask from outside: how its listener admits a request, the KMS
// roots it pinned, what its supervisor last saw of each executor, and what its
// sign-in client holds of the identity provider (Task 20446).
func (s *Server) hubHealthSelf() *hubdoctor.Self {
	self := &hubdoctor.Self{
		SSO:         s.OIDC != nil,
		StaticToken: s.staticTokenConfigured(),
		TLS:         strings.TrimSpace(s.TLSCertFile) != "",
		KMS:         s.hubKMSRoots,
		Probe:       s.hubHealthProbe(s.recordedExecutorHealth()),
	}
	if s.oidcEnabled() {
		st := s.OIDC.IdPState()
		self.IdP = &st
	}
	return self
}

// hubKMSRoots are the roots `cloop ui` resolved and pinned for every keyring
// this process opens, with the providers it handed the server.
func (s *Server) hubKMSRoots() (kms.Roots, bool) {
	cur, prev, ok := secretbroker.PinnedRoots()
	if !ok {
		return kms.Roots{}, false
	}
	roots := kms.Roots{Current: cur, Previous: prev}
	if s.kms != nil {
		roots.Providers = append(roots.Providers, s.kms.providers...)
	}
	return roots, true
}

// recordedExecutorHealth is the executor supervisor's last word on each
// executor, by id: one read per report, of rows every member shares.
func (s *Server) recordedExecutorHealth() map[string]executor.Health {
	db, closeDB, err := s.openControlPlaneDB()
	if err != nil {
		return nil
	}
	defer closeDB()
	sched, err := executorstore.NewScheduler(db)
	if err != nil {
		return nil
	}
	hs, err := sched.ListHealth()
	if err != nil {
		return nil
	}
	out := make(map[string]executor.Health, len(hs))
	for _, h := range hs {
		out[h.ExecutorID] = h
	}
	return out
}

// hubHealthProbe answers the doctor's liveness question for one executor
// without probing it again: from the supervisor's record (the member that
// probes each executor is the one that should, and every member reads the
// same row), or — for a device another member holds and the supervisor has
// not recorded — from the cluster's ownership. Only an executor nobody has
// probed yet is asked, once.
func (s *Server) hubHealthProbe(recorded map[string]executor.Health) func(context.Context, executor.Executor) (string, error) {
	return func(ctx context.Context, ex executor.Executor) (string, error) {
		if h, ok := recorded[ex.ID()]; ok && !h.LastProbe.IsZero() {
			source := "as the hub's supervisor last probed it, at " + h.LastProbe.UTC().Format(time.RFC3339)
			if h.ConsecutiveFailures > 0 || h.State == executor.NodeUnreachable {
				reason := strings.TrimSpace(h.Reason)
				if reason == "" {
					reason = fmt.Sprintf("%d consecutive failed probe(s)", h.ConsecutiveFailures)
				}
				return source, errors.New(reason)
			}
			return source, nil
		}
		if member, held := s.agentHeldByPeer(ex); held {
			return "connected to hub member " + member, nil
		}
		return "probed now: the hub's supervisor has not recorded it yet", ex.HealthCheck(ctx)
	}
}

// hubHealthMember names this process among the hub's members.
func (s *Server) hubHealthMember() hubHealthMember {
	m := hubHealthMember{ID: s.hubInstanceID(), Port: s.Port, Leader: s.isLeader()}
	if n := s.clusterNode(); n != nil {
		m.Clustered = true
		m.Hostname = n.Self().Hostname
	}
	if m.Hostname == "" {
		m.Hostname, _ = os.Hostname()
	}
	if m.ID == "" {
		m.ID = "standalone"
	}
	return m
}

// hubConfigFiles names the files this hub's configuration is read from,
// relative to its directory.
func (s *Server) hubConfigFiles() []string {
	files := []string{".cloop/config.yaml"}
	if s.hubConfigOverlay() != "" {
		files = append(files, fmt.Sprintf(".cloop/config.ui-%d.yaml", s.Port))
	}
	return files
}

// hubConfigFingerprint changes whenever one of this hub's configuration files
// is written, created or removed.
func (s *Server) hubConfigFingerprint() string {
	var b strings.Builder
	paths := []string{config.ConfigPath(s.WorkDir)}
	if s.Port > 0 {
		paths = append(paths, config.UIInstanceConfigPath(s.WorkDir, s.Port))
	}
	for _, p := range paths {
		fi, err := os.Stat(p)
		if err != nil {
			b.WriteString("-;")
			continue
		}
		fmt.Fprintf(&b, "%d:%d;", fi.Size(), fi.ModTime().UnixNano())
	}
	return b.String()
}

// ── The schedule (Task 20446) ───────────────────────────────────────────────

// watchHubHealth makes this member's reports on its own: on the cadence, when
// the configuration changes, after events that change findings — and asks,
// every thirty seconds, who may still read them. Every member runs one: the
// listener checks are about the member that makes them.
func (s *Server) watchHubHealth(ctx context.Context) {
	defer recoverGoroutine("watchHubHealth")
	h := &s.hubHealth
	started := time.Now()
	fp := s.hubConfigFingerprint()
	h.mu.Lock()
	h.looked, h.settled = fp, fp
	wake := h.wakeLocked()
	h.mu.Unlock()

	look := time.NewTicker(hubHealthWatchEvery)
	defer look.Stop()
	timer := time.NewTimer(hubHealthFirstRun)
	defer timer.Stop()
	asked := time.Now()
	for {
		timer.Reset(time.Until(s.hubHealthTick(started)))
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		case <-wake:
		case <-look.C:
			s.hubHealthLook()
			if time.Since(asked) >= hubHealthAudienceEvery {
				asked = time.Now()
				func() {
					defer recoverGoroutine("hub health audience")
					s.recheckHubHealthAudience(nil)
				}()
			}
		}
	}
}

// hubHealthLook is one look at the configuration files: a fingerprint two
// looks in a row agree on is the configuration the next report is due under.
func (s *Server) hubHealthLook() {
	fp := s.hubConfigFingerprint()
	h := &s.hubHealth
	h.mu.Lock()
	if fp == h.looked {
		h.settled = fp
	}
	h.looked = fp
	h.mu.Unlock()
}

// hubHealthTick makes a report if one is due, and returns when the next one
// will be. started is when the schedule began.
//
// A report is labelled with the configuration files as they are when it is
// made, whoever made it; the looks only decide whether a change is due.
func (s *Server) hubHealthTick(started time.Time) (next time.Time) {
	h := &s.hubHealth
	live := s.hubConfigFingerprint()
	h.mu.Lock()
	due, why := h.dueLocked(live, started)
	gen := h.generation
	h.mu.Unlock()
	if due.After(time.Now()) {
		return due
	}
	func() {
		defer recoverGoroutine("hub health report")
		s.hubHealthRun(why, live, false, func(now time.Time) bool {
			d, _ := h.dueLocked(live, started)
			return d.After(now)
		})
	}()
	h.mu.Lock()
	next, _ = h.dueLocked(s.hubConfigFingerprint(), started)
	made := h.generation != gen
	h.mu.Unlock()
	if !made {
		// The run died without a report — a panic the log has — so it is
		// not tried again at once, or every few seconds.
		next = time.Now().Add(hubHealthEventSpacing)
	}
	return next
}

// dueLocked says when the next report is due, the configuration files being
// live, and why: the first one hubHealthFirstRun after the schedule started,
// then one a cadence after the last; at once for files the last was not made
// under, once two looks have agreed on them — an editor may still be writing
// — and soon after an event the last did not see. h.mu is held.
func (h *hubHealthState) dueLocked(live string, started time.Time) (time.Time, string) {
	rep := h.report
	if rep == nil {
		return started.Add(hubHealthFirstRun), hubHealthTriggerSchedule
	}
	if h.print != live && h.settled == live {
		return time.Time{}, hubHealthTriggerConfig
	}
	due, why := h.dueAt, hubHealthTriggerSchedule
	if !h.eventAt.IsZero() {
		at := h.eventAt.Add(hubHealthEventDelay)
		if floor := h.madeAt.Add(hubHealthEventSpacing); at.Before(floor) {
			at = floor
		}
		if at.Before(due) {
			due, why = at, hubHealthTriggerEvent
		}
	}
	return due, why
}

// hubHealthEvent says something changed what a report would find — an
// executor enrolled, lost or reconfigured, a CA rotation step, a sealing key
// rotated — so the scheduler makes the next report soon: hubHealthEventDelay
// after the first such event, so a burst is one report, and never sooner than
// hubHealthEventSpacing after the last report. Cheap and non-blocking, for
// the paths that announce those changes.
func (s *Server) hubHealthEvent() {
	h := &s.hubHealth
	now := time.Now()
	h.mu.Lock()
	if h.eventAt.IsZero() {
		h.eventAt = now
	}
	h.eventLast = now
	wake := h.wakeLocked()
	h.mu.Unlock()
	select {
	case wake <- struct{}{}:
	default:
	}
}

// AnnounceHubHealthChange posts the bus notice that something every member's
// Hub health report checks changed outside any member, for a writer that is
// not one: `cloop hub key`, whose rotations, retirements, rewraps, escrows and
// root changes are what the secret_key checks read (Task 20446). Every member
// reading the bus makes its next report soon rather than at its cadence. A
// failure is the caller's to report and never fatal: the next scheduled
// report sees the change anyway.
func AnnounceHubHealthChange(db *statedb.DB, origin, what string) error {
	return appendInvalidations(db, origin, invalidateHubHealth, []any{map[string]string{"what": what}})
}

// ── Who hears it (Task 20446) ───────────────────────────────────────────────

// hubHealthPush is what a hub_health message carries to a stream whose
// identity may read the report: what the header shows, and when.
//
// The generation is the member's own, so the member is named beside it: behind
// a load balancer the page's reads may be answered by another member than the
// one holding its socket.
type hubHealthPush struct {
	Member     hubHealthPushMember `json:"member"`
	Failing    int                 `json:"failing"`
	Generation uint64              `json:"generation"`
	CheckedAt  time.Time           `json:"checked_at"`
	ServedAt   time.Time           `json:"served_at"`
	ExpiresAt  time.Time           `json:"expires_at"`
}

// hubHealthPushMember names the member that made a pushed report, as the
// report's own member field does.
type hubHealthPushMember struct {
	ID string `json:"id"`
}

// hubHealthWithdrawn is the hub_health message of a stream that was sent the
// summary and may no longer read it. It carries no count; the page puts its
// indicator out and re-reads what it may do.
var hubHealthWithdrawn = json.RawMessage(`{"withdrawn":true}`)

// recheckHubHealthAudience asks again whether each stream match selects (every
// one for nil) may read the report: one that newly may is sent the current
// summary, one that newly may not is told it is withdrawn.
func (s *Server) recheckHubHealthAudience(match func(streamCredential) bool) {
	s.deliverHubHealth(false, match)
}

// deliverHubHealth sends the latest report's summary to the streams match
// selects (every one for nil) whose identity may read it — every such stream
// when push and the report has not been pushed to everybody yet, else only
// those not already sent one — and tells the streams that were sent it and
// may no longer read it that it is withdrawn.
//
// Deliveries are made one at a time (deliverMu), each with the report current
// when it begins, so a later pass never sends an older report or a verdict an
// earlier pass has overtaken. Who may read is decided with no stream lock
// held, once per credential: it reads the session and token stores. The
// streams are then sent to under their locks if they are still connected, as
// broadcastProjectsUpdate does.
func (s *Server) deliverHubHealth(push bool, match func(streamCredential) bool) {
	h := &s.hubHealth
	h.deliverMu.Lock()
	defer h.deliverMu.Unlock()
	h.mu.Lock()
	rep := h.report
	h.mu.Unlock()
	everyone := false
	if push && rep != nil && rep.Generation > h.pushedGen {
		everyone, h.pushedGen = true, rep.Generation
	}

	s.hubMu.Lock()
	var sockets []*hubClient
	for _, clients := range s.hubClients {
		for hc := range clients {
			if match == nil || match(hc.cred) {
				sockets = append(sockets, hc)
			}
		}
	}
	s.hubMu.Unlock()
	s.mu.Lock()
	var streams []*sseClient
	for c := range s.clients {
		if match == nil || match(c.cred) {
			streams = append(streams, c)
		}
	}
	s.mu.Unlock()
	if len(sockets) == 0 && len(streams) == 0 {
		return
	}

	verdicts := map[streamCredential]bool{}
	may := func(c streamCredential) bool {
		v, seen := verdicts[c]
		if !seen {
			v = s.hubHealthMayRead(c)
			verdicts[c] = v
		}
		return v
	}
	var summary json.RawMessage
	if rep != nil {
		raw, err := json.Marshal(hubHealthPush{Member: hubHealthPushMember{ID: rep.Member.ID}, Failing: rep.Failing,
			Generation: rep.Generation, CheckedAt: rep.CheckedAt, ServedAt: time.Now().UTC(), ExpiresAt: rep.ExpiresAt})
		if err == nil {
			summary = raw
		}
	}
	// decide is what one stream is sent, if anything, and what it was then
	// last sent: the summary (true) or nothing it may keep (false).
	decide := func(c streamCredential, told bool) (json.RawMessage, bool) {
		switch {
		case may(c) && summary != nil && (everyone || !told):
			return summary, true
		case !may(c) && told:
			return hubHealthWithdrawn, false
		}
		return nil, told
	}

	type wsSend struct {
		hc   *hubClient
		data json.RawMessage
		told bool
	}
	var wsSends []wsSend
	for _, hc := range sockets {
		if data, told := decide(hc.cred, hc.healthTold.Load()); data != nil {
			wsSends = append(wsSends, wsSend{hc, data, told})
		}
	}
	type sseSend struct {
		c    *sseClient
		data json.RawMessage
		told bool
	}
	var sseSends []sseSend
	for _, c := range streams {
		if data, told := decide(c.cred, c.healthTold.Load()); data != nil {
			sseSends = append(sseSends, sseSend{c, data, told})
		}
	}

	if len(wsSends) > 0 {
		s.hubMu.Lock()
		present := make(map[*hubClient]bool, len(wsSends))
		for _, clients := range s.hubClients {
			for hc := range clients {
				present[hc] = true
			}
		}
		for _, w := range wsSends {
			if present[w.hc] {
				w.hc.healthTold.Store(w.told)
				s.sendOrLag(w.hc, wsMessage{Type: "hub_health", Data: w.data})
			}
		}
		s.hubMu.Unlock()
	}
	if len(sseSends) > 0 {
		s.mu.Lock()
		for _, e := range sseSends {
			if _, still := s.clients[e.c]; still {
				e.c.healthTold.Store(e.told)
				s.sendSSEOrLag(e.c, sseEvent{Event: "hub_health", Data: string(e.data)})
			}
		}
		s.mu.Unlock()
	}
}

// hubHealthMayRead reports whether the identity behind a stream opened with c
// may read the report now: the route's question — config.write across the hub
// — asked of the credential as it stands, not as it stood when the stream
// opened. A session is read as it is now, with whatever claims the identity
// provider last asserted, so a refresh that narrowed them narrows this too; a
// token as it reads now; the static token unless it was retired. A credential
// that has ended reads nothing.
//
// The claims are not re-asserted here, as the route gate re-asserts them for
// an administrator's request whose claims have aged: that is a round trip to
// the identity provider, and this is asked of every stream for every report.
// It is the rule /api/me lights the indicator by, and what the project-list
// fan-out filters by, and the session's claims are re-asserted on its own
// requests and renewals, which say so (onSessionChanged) and are re-asked.
func (s *Server) hubHealthMayRead(c streamCredential) bool {
	var user *oidcauth.Identity
	var tok *apitoken.Token
	switch {
	case c.tokenID != "":
		// A token presented beside a session is what the request path
		// decides by, as newGrant does.
		t, err := s.recheckToken(c.tokenID)
		if err != nil {
			return false
		}
		tok = t
	case c.sessionHash != "":
		rec, st := s.OIDC.CheckSession(c.sessionHash)
		if st != oidcauth.SessionLive {
			return false
		}
		id := rec.Identity
		user = &id
	case c.static:
		if _, retired := s.ownStaticTokenRetirement(); retired {
			return false
		}
	default:
		// No credential at all: a hub with neither sign-on nor a static
		// token, where the route admits everybody. With sign-on, no stream
		// opens without one.
		if s.oidcEnabled() {
			return false
		}
	}
	return s.recipientGrant(user, tok).decide(authz.GlobalScope).Allows(authz.PermConfigWrite)
}

// urlCredentials is the userinfo credential of raw when it is a URL that has
// one: its password, or a username long enough to be a token presented as one.
func urlCredentials(raw string) []string {
	if !strings.Contains(raw, "://") || !strings.Contains(raw, "@") {
		return nil
	}
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.User == nil {
		return nil
	}
	if pw, ok := u.User.Password(); ok {
		return redact.Values([]byte(pw))
	}
	if name := u.User.Username(); len(name) >= 20 {
		return []string{name}
	}
	return nil
}

// ── Documentation anchors ───────────────────────────────────────────────────

// hubHealthDocAnchors maps a check id's group to its row in the runbook's
// table of `cloop hub doctor` checks. The longest matching prefix wins.
// TestHubHealthDocAnchorsExist holds every anchor to the page and every check
// id the doctor emits to an entry.
var hubHealthDocAnchors = []struct{ prefix, anchor string }{
	{"doctor.", "hub-health-in-the-dashboard"},
	{"policy.", "doctor-policy"},
	{"config.", "doctor-config"},
	{"oidc.", "doctor-oidc"},
	{"tls.", "doctor-tls"},
	{"ui.", "doctor-ui"},
	{"secret_key.", "doctor-secret_key"},
	{"secrets.", "doctor-secret_key"},
	{"rbac.", "doctor-rbac"},
	{"api_tokens.", "doctor-rbac"},
	{"scim.", "doctor-scim"},
	{"offboard.", "doctor-offboard"},
	{"images.", "doctor-images"},
	{"executors.", "doctor-executors"},
	{"runs.", "doctor-runs"},
	{"firewall.", "doctor-firewall"},
	{"gitproxy.", "doctor-gitproxy"},
	{"hubca.", "doctor-hubca"},
	{"kubeguard.", "doctor-kubeguard"},
	{"egress.", "doctor-egress"},
	{"projects.", "doctor-projects"},
	{"storage.", "doctor-storage"},
	{"statedb.", "doctor-storage"},
	{"retention.", "doctor-retention"},
	{"audit.", "doctor-audit"},
	{"quotas.", "doctor-quotas"},
	{"budget.", "doctor-quotas"},
	{"smoke.", "dispatch-health-cloop-hub-doctor---smoke"},
}

// hubHealthDocsFallback is the section itself, for a check no group names.
const hubHealthDocsFallback = "configuration-health-cloop-hub-doctor"

// hubHealthDocsURL is where check is explained.
func hubHealthDocsURL(check string) string {
	anchor, best := hubHealthDocsFallback, 0
	for _, d := range hubHealthDocAnchors {
		if strings.HasPrefix(check, d.prefix) && len(d.prefix) > best {
			anchor, best = d.anchor, len(d.prefix)
		}
	}
	return hubHealthDocsBase + "#" + anchor
}

// hubHealthCheckID keeps a check id to the characters ids are made of. The
// hub's own are constants; this is for a check added from elsewhere.
func hubHealthCheckID(id string) string {
	return checkIDJunk.ReplaceAllString(id, "_")
}

var checkIDJunk = regexp.MustCompile(`[^a-z0-9_.\-]`)

// ── Redaction ───────────────────────────────────────────────────────────────

// hubHealthScrub removes credentials from what a check wrote: the exact
// values in set first, then anything the credential-shape registry
// recognises in what is left.
type hubHealthScrub struct{ set *redact.Set }

func (sc hubHealthScrub) text(s string) string {
	if s == "" {
		return s
	}
	return redact.Scrub(sc.set.String(s))
}

// details scrubs a finding's details, whatever they hold, by way of the JSON
// they are sent as: every string in it, keys included, at any depth.
func (sc hubHealthScrub) details(d map[string]any) map[string]any {
	if len(d) == 0 {
		return nil
	}
	raw, err := json.Marshal(d)
	if err != nil {
		return map[string]any{"details": "could not be rendered"}
	}
	var generic map[string]any
	if err := json.Unmarshal(raw, &generic); err != nil {
		return map[string]any{"details": "could not be rendered"}
	}
	out, _ := sc.value(generic).(map[string]any)
	return out
}

func (sc hubHealthScrub) value(v any) any {
	switch x := v.(type) {
	case string:
		return sc.text(x)
	case []any:
		for i := range x {
			x[i] = sc.value(x[i])
		}
		return x
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, e := range x {
			out[sc.text(k)] = sc.value(e)
		}
		return out
	default:
		return x
	}
}

// hubSecretValues lists every credential the hub's configuration and
// environment hold by value.
//
// The checks name settings, not secrets, but they quote what they read — an
// issuer, a webhook, an error from a library that echoes its input — and a
// credential with no recognisable shape gets past the registry. These are the
// ones the hub knows outright.
//
// The configuration is read twice: as loaded, which carries what came from
// the environment (an OIDC client secret supplied as one), and as the files
// say, which still carry a section loading switched off — whose URL is exactly
// what the finding about switching it off quotes.
func hubSecretValues(cfg *config.Config, files []string, environ []string) []string {
	var out []string
	for _, kv := range environ {
		name, value, ok := strings.Cut(kv, "=")
		if !ok {
			continue
		}
		if secretEnvName(name) {
			out = append(out, redact.Values([]byte(value))...)
		}
		// HTTPS_PROXY=https://user:pass@proxy is a credential under a name
		// that is not.
		out = append(out, urlCredentials(value)...)
	}
	// The root key wherever it was read from: a file or a systemd credential
	// is not in the environment.
	if roots, err := rootkey.Resolve(); err == nil {
		out = append(out, redact.Values([]byte(roots.Current.Value))...)
		out = append(out, redact.Values([]byte(roots.Previous.Value))...)
	}
	var docs [][]byte
	if cfg != nil {
		if raw, err := yaml.Marshal(cfg); err == nil {
			docs = append(docs, raw)
		}
	}
	for _, f := range files {
		if raw, err := os.ReadFile(f); err == nil {
			docs = append(docs, raw)
		}
	}
	for _, raw := range docs {
		var tree any
		if yaml.Unmarshal(raw, &tree) == nil {
			collectConfigSecrets(tree, nil, &out)
		}
	}
	return out
}

var (
	// secretEnvWord and secretEnvKey are the variable names that hold a
	// credential: CLOOP_SECRET_KEY, ANTHROPIC_API_KEY, GITHUB_TOKEN, a
	// *_PASSWORD. notSecretEnv are the ones that only point at one.
	secretEnvWord = regexp.MustCompile(`(?i)(SECRET|TOKEN|PASSWORD|PASSWD|CREDENTIAL|PRIVATE)`)
	secretEnvKey  = regexp.MustCompile(`(?i)(^|_)(KEY|PAT|PASS)(_|$)`)
	notSecretEnv  = regexp.MustCompile(`(?i)_(FILE|PATH|DIR|DIRECTORY|NAME|ID|URL|ENDPOINT|HOST|PORT|TYPE)$`)
	// secretHeader is a header whose value is a credential, not a content
	// type or an accept list.
	secretHeader = regexp.MustCompile(`(?i)(auth|token|secret|key|cookie|signature|password|session)`)
)

func secretEnvName(name string) bool {
	return !notSecretEnv.MatchString(name) && (secretEnvWord.MatchString(name) || secretEnvKey.MatchString(name))
}

// secretConfigKeys are the configuration keys whose value is the credential
// itself, rather than the name of a secret in the store or a file holding
// one: the OIDC client secret, provider API keys, the GitHub and relay
// tokens, a webhook's signing secret.
var secretConfigKeys = map[string]bool{
	"api_key": true, "groq_api_key": true, "client_secret": true, "token": true,
	"upstream_auth_token": true, "secret": true, "password": true,
}

// collectConfigSecrets walks a configuration as YAML sees it. Besides the
// keys above, a webhook's URL is its credential (Slack's carries the secret
// in its path), so is an Authorization-like header a webhook is configured to
// send, and so is the password in any URL: a check that quotes the URL is
// redacted by the registry, but an error that quotes the password alone is
// not.
func collectConfigSecrets(v any, path []string, out *[]string) {
	switch x := v.(type) {
	case map[string]any:
		for k, e := range x {
			collectConfigSecrets(e, append(path[:len(path):len(path)], k), out)
		}
	case []any:
		for _, e := range x {
			collectConfigSecrets(e, path, out)
		}
	case string:
		if len(path) == 0 {
			return
		}
		*out = append(*out, urlCredentials(x)...)
		key := strings.ToLower(path[len(path)-1])
		joined := strings.ToLower(strings.Join(path, "."))
		webhook := strings.Contains(key, "webhook") || (key == "url" && strings.Contains(joined, "webhook"))
		if secretConfigKeys[key] || webhook ||
			(len(path) > 1 && strings.EqualFold(path[len(path)-2], "headers") && secretHeader.MatchString(key)) {
			*out = append(*out, redact.Values([]byte(x))...)
		}
		if u, err := url.Parse(strings.TrimSpace(x)); webhook && err == nil && len(u.Path) > 1 {
			// An error quotes the request it made: the path is the secret.
			*out = append(*out, u.Path, u.EscapedPath())
		}
	}
}
