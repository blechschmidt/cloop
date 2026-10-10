package ui

// The hub's half of pkg/hubmetrics (Task 20377): the scrape-time collectors,
// and the recorders for the runs, API tokens and sessions this package owns.
//
// # Which member exports what
//
// Counters are per process. Each member of a hub cluster counts the runs it
// dispatched or settled, the tokens it verified, the sessions its store deletes
// ended — and sum() over members is the cluster's total, which is what a
// counter is for.
//
// A gauge read from the shared database is different: every member reads the
// same rows, so three members exporting cloop_executors{state="ready"} 4 would
// read 12 under sum(). Those gauges are exported by the leader alone
// (metricsScrape.leader). A follower's collector exports nothing for them —
// the registry Resets a collector's families before it runs, so a member that
// stops leading stops reporting at its next scrape rather than freezing at its
// last value. During a hand-over no member reports them for up to a lease TTL,
// which reads as absent rather than wrong.
//
// Gauges of per-process state — the leases a member materialised, the
// egress sessions its broker issued, its merge queue — are exported by every
// member, because each one's value is its own share.

import (
	"errors"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/blechschmidt/cloop/pkg/apitoken"
	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/executor/remote"
	"github.com/blechschmidt/cloop/pkg/executorstore"
	"github.com/blechschmidt/cloop/pkg/hubmetrics"
	"github.com/blechschmidt/cloop/pkg/oidcauth"
	"github.com/blechschmidt/cloop/pkg/quota"
	"github.com/blechschmidt/cloop/pkg/secretbroker"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// ── the scrape ──────────────────────────────────────────────────────────────

// metricsScrape is one /metrics request in progress: the Server it is
// addressed to, whether that Server leads its cluster, and the control-plane
// database, opened once for every collector that needs it.
type metricsScrape struct {
	srv    *Server
	leader bool

	// mu guards the database handle. Collectors run one at a time, but a
	// Gather that is not this scrape's own can still be holding it after
	// close (see activeScrape).
	mu       sync.Mutex
	dbOpened bool
	closed   bool
	db       *statedb.DB
}

// activeScrape is the scrape being rendered. Stored and cleared under
// metricsMu, so for the whole of one gatherMetrics it names exactly one Server.
//
// The collectors are registered once per process, as the registry is; what
// only a Server can answer — whether it leads, where its database is, which
// enforcer and authenticator it holds — they ask through this. In production a
// process has one Server and this is always it. pkg/ui's tests build hundreds,
// in parallel, and a collector that captured the first would report a Server
// long gone.
//
// Atomic because a Gather that does not come through gatherMetrics — a test
// reading the registry directly — runs the collectors without metricsMu.
var activeScrape atomic.Pointer[metricsScrape]

// gatherMetrics renders the hub registry as s sees it.
func (s *Server) gatherMetrics() string {
	// Here as well as at startup, so a Server that never bootstrapped — the
	// struct literals tests build — still has its gauges collected. A no-op
	// after the first call.
	registerHubCollectors()

	metricsMu.Lock()
	defer metricsMu.Unlock()
	sc := &metricsScrape{srv: s, leader: s.isLeader()}
	activeScrape.Store(sc)
	defer func() {
		activeScrape.Store(nil)
		sc.close()
	}()
	return hubmetrics.Default.Gather()
}

// controlDB opens the control-plane database for this scrape, or returns nil
// when there is none. It never creates one: a WorkDir with no state.db is a
// hub with nothing persisted to report, and statedb.Open would otherwise
// create and migrate a database to say so.
func (sc *metricsScrape) controlDB() *statedb.DB {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	if sc.closed {
		return nil
	}
	if sc.dbOpened {
		return sc.db
	}
	sc.dbOpened = true
	path := state.DBPath(sc.srv.WorkDir)
	if _, err := os.Stat(path); err != nil {
		return nil
	}
	db, err := statedb.Open(path)
	if err != nil {
		return nil
	}
	sc.db = db
	return db
}

func (sc *metricsScrape) close() {
	sc.mu.Lock()
	db := sc.db
	sc.db, sc.closed = nil, true
	sc.mu.Unlock()
	if db != nil {
		_ = db.Close()
	}
}

// withScrape runs fn against the scrape in progress. A Gather that is not a
// /metrics request — a test reading the registry directly — has no Server to
// read from, and its Server-scoped families stay empty.
func withScrape(fn func(*metricsScrape)) hubmetrics.Collector {
	return func() {
		if sc := activeScrape.Load(); sc != nil {
			fn(sc)
		}
	}
}

// registerHubCollectors installs the scrape-time collectors, once per process.
// Called at hub startup (bootstrapExecutors) and before every scrape.
func registerHubCollectors() {
	hubmetrics.RegisterCollectors(
		hubmetrics.CollectorSpec{
			Name: "quota",
			Families: []*hubmetrics.Metric{
				hubmetrics.QuotaEnforcementEnabled, hubmetrics.QuotaLimit, hubmetrics.QuotaUsage,
				hubmetrics.QuotaIdentities, hubmetrics.ProjectsRegistered,
			},
			Collect: withScrape(collectQuota),
		},
		hubmetrics.CollectorSpec{
			Name:     "sessions",
			Families: []*hubmetrics.Metric{hubmetrics.SessionsLive},
			Collect:  withScrape(collectSessions),
		},
		hubmetrics.CollectorSpec{
			Name:     "executor_fleet",
			Families: []*hubmetrics.Metric{hubmetrics.ExecutorsByState, hubmetrics.ExecutorHeartbeatAgeMax},
			Collect:  withScrape(collectExecutorFleet),
		},
		hubmetrics.CollectorSpec{
			Name:     "secret_leases",
			Families: []*hubmetrics.Metric{hubmetrics.LeasesLive},
			Collect:  collectLiveLeases,
		},
		hubmetrics.CollectorSpec{
			Name:     "writeback_pinned",
			Families: []*hubmetrics.Metric{hubmetrics.WriteBackPinnedBytes, hubmetrics.WriteBackPinnedBytesMax},
			Collect:  collectPinnedWriteBack,
		},
		hubmetrics.CollectorSpec{
			Name:     "kek_rotation",
			Families: []*hubmetrics.Metric{hubmetrics.KEKRotationRecords, hubmetrics.KEKRotationActive},
			Collect:  withScrape(collectKEKRotation),
		},
		hubmetrics.CollectorSpec{
			Name:     "disk_free",
			Families: []*hubmetrics.Metric{hubmetrics.DiskFreeBytes},
			Collect:  withScrape(collectDiskFree),
		},
		hubmetrics.CollectorSpec{
			Name:     "statedb_wal",
			Families: []*hubmetrics.Metric{hubmetrics.StateDBWALBytes},
			Collect:  withScrape(collectStateDBWAL),
		},
	)
}

// collectStateDBWAL publishes the size of the control plane's write-ahead log
// (Task 20392). Leader only, as every gauge of the shared database is: each
// member would report the same file, and sum() would multiply it. A hub with
// no database yet has no log to report, which is not a zero.
func collectStateDBWAL(sc *metricsScrape) {
	if !sc.leader {
		return
	}
	dbPath := state.DBPath(sc.srv.WorkDir)
	if _, err := os.Stat(dbPath); err != nil {
		return
	}
	n, err := statedb.WALSize(dbPath)
	if err != nil {
		return
	}
	hubmetrics.StateDBWALBytes.Set(float64(n))
}

// collectDiskFree publishes the free space on each volume this process writes
// to (Task 20381): its control-plane .cloop first, then each registered
// project's .cloop and working tree, deduplicated by device. Every member
// reports its own, leader or not — what is measured is this process's disk,
// not a row in the shared database.
//
// Paths are probed one at a time so a project directory this process cannot
// read costs its own volume and not the scrape; a project with no local tree
// (one that only runs on a device) resolves to the nearest existing parent,
// which is a volume this host does have.
func collectDiskFree(sc *metricsScrape) {
	s := sc.srv
	paths := []string{filepath.Join(s.WorkDir, ".cloop")}
	for _, e := range s.allProjectEntries() {
		if e.Path != "" {
			paths = append(paths, filepath.Join(e.Path, ".cloop"), e.Path)
		}
	}
	seen := map[uint64]bool{}
	for _, p := range paths {
		if len(seen) >= hubmetrics.DiskVolumesMax {
			return
		}
		vols, err := s.probeVolumes(p)
		if err != nil || len(vols) == 0 || seen[vols[0].Device] {
			continue
		}
		seen[vols[0].Device] = true
		hubmetrics.DiskFreeBytes.Set(float64(vols[0].FreeBytes), vols[0].Mount)
	}
}

// ── collectors ──────────────────────────────────────────────────────────────

// collectQuota publishes the per-identity quota gauges from live enforcer
// state.
//
// Reset-then-Set (the registry Resets the owned families) rather than
// incremental updates is what keeps the identity-labelled pair bounded:
// cardinality becomes the number of identities the hub is accounting right
// now, not the number it has ever seen, and a departed identity's last usage
// is not exported forever as though it were live.
//
// The denials counter is each member's own refusals, so every member reports
// it; everything else is the shared policy and usage, so only the leader does.
func collectQuota(sc *metricsScrape) {
	s := sc.srv
	e := s.quotas()
	if e != nil {
		// Set, not Add: the enforcer holds the authoritative running total,
		// so mirroring the absolute value keeps the counter monotonic across
		// scrapes without this path tracking what it last published.
		denials := e.Denials()
		for _, res := range quota.AllResources {
			hubmetrics.QuotaDenials.Set(float64(denials[res]), string(res))
		}
	}
	if !sc.leader {
		return
	}

	entries := s.allProjectEntries()
	hubmetrics.ProjectsRegistered.Set(float64(len(entries)))
	if e == nil || !e.Enabled() {
		hubmetrics.QuotaEnforcementEnabled.Set(0)
	} else {
		hubmetrics.QuotaEnforcementEnabled.Set(1)
	}
	if e == nil {
		hubmetrics.QuotaIdentities.Set(0)
		return
	}

	var known []string
	for _, entry := range entries {
		if entry.Owner != "" {
			known = append(known, entry.Owner)
		}
	}
	snapshot := e.Snapshot(known)
	for _, v := range snapshot {
		for _, res := range quota.AllResources {
			if limit, ok := v.Limits.Get(res); ok {
				hubmetrics.QuotaLimit.Set(limit, v.Identity, string(res))
			}
			hubmetrics.QuotaUsage.Set(v.Usage[res], v.Identity, string(res))
		}
	}
	hubmetrics.QuotaIdentities.Set(float64(len(snapshot)))
}

// collectSessions publishes how many sessions are valid. Leader only: the
// durable session store is the shared database. A store that cannot be read
// exports nothing rather than a zero, which would claim nobody is signed in.
func collectSessions(sc *metricsScrape) {
	if !sc.leader {
		return
	}
	n, err := sc.srv.OIDC.LiveSessionCount() // nil-safe: 0 with sign-on off
	if err != nil {
		return
	}
	hubmetrics.SessionsLive.Set(float64(n))
}

// collectExecutorFleet publishes the fleet by kind and scheduling state, and
// the oldest successful liveness probe per kind. Leader only: health is the
// supervisor's record in the shared database.
//
// The executors are this member's registry, which every member keeps whole —
// an enrollment on one is broadcast to the rest — and an executor with no
// health record is ready, as placement treats it (Health.Normalize). A health
// store that cannot be read exports nothing: reporting every executor ready
// because the record of which ones are not was unreadable would be the worst
// answer available.
func collectExecutorFleet(sc *metricsScrape) {
	if !sc.leader {
		return
	}
	health := map[string]executor.Health{}
	if db := sc.controlDB(); db != nil {
		sched, err := executorstore.NewScheduler(db)
		if err != nil {
			return
		}
		rows, err := sched.ListHealth()
		if err != nil {
			return
		}
		for _, h := range rows {
			health[h.ExecutorID] = h
		}
	}

	now := time.Now()
	type kindState struct{ kind, state string }
	counts := map[kindState]int{}
	oldest := map[string]float64{}
	for _, ex := range executor.List() {
		h := health[ex.ID()]
		h.ExecutorID = ex.ID()
		h = h.Normalize()
		counts[kindState{ex.Kind(), string(h.State)}]++
		if age, ok := heartbeatAge(h, now); ok {
			if prev, seen := oldest[ex.Kind()]; !seen || age > prev {
				oldest[ex.Kind()] = age
			}
		}
	}
	for k, n := range counts {
		hubmetrics.ExecutorsByState.Set(float64(n), k.kind, k.state)
	}
	for kind, age := range oldest {
		hubmetrics.ExecutorHeartbeatAgeMax.Set(age, kind)
	}
}

// heartbeatAge is how long ago an executor last answered a probe, in seconds.
// One never seen healthy is aged from when it entered its current state, so a
// node that has been unreachable since the hub met it still rises without
// bound; one with no record at all has no age to report.
func heartbeatAge(h executor.Health, now time.Time) (float64, bool) {
	since := h.LastSeen
	if since.IsZero() {
		since = h.StateChangedAt
	}
	if since.IsZero() {
		return 0, false
	}
	age := now.Sub(since).Seconds()
	if age < 0 {
		age = 0
	}
	return age, true
}

// collectLiveLeases publishes the leases this process holds, by credential
// kind. Every member reports its own: a lease's material lives with the member
// that materialised it, so the members' values add up to the cluster's. Every
// kind is exported, zero included, so "no PATs are leased" reads as a zero
// rather than as a series nobody has seen.
func collectLiveLeases() {
	counts := map[secretbroker.Kind]int{}
	for _, k := range secretbroker.Kinds() {
		counts[k] = 0
	}
	now := time.Now()
	for _, sl := range liveLeases.snapshot() {
		if sl.Expired(now) {
			continue // the janitor sweeps it next; it is not live
		}
		for _, k := range sl.lease.Kinds() {
			counts[k]++
		}
	}
	for k, n := range counts {
		hubmetrics.LeasesLive.Set(float64(n), string(k))
	}
}

// collectPinnedWriteBack publishes the returned work this process holds for
// remote executors (Task 20399), from the budget that counts it. Per process,
// like the leases above: a member holds what reached it.
func collectPinnedWriteBack() {
	u := remote.DefaultResultBudget().Usage()
	hubmetrics.WriteBackPinnedBytes.Set(float64(u.Pinned))
	hubmetrics.WriteBackPinnedBytesMax.Set(float64(u.MaxPerExecutor))
}

// collectKEKRotation publishes the progress of the most recent key rotation,
// from the history `cloop hub key rotate` writes. Leader only: the history is
// in the shared database. A hub that has never rotated reports active 0 and no
// progress; one with no database reports nothing.
func collectKEKRotation(sc *metricsScrape) {
	if !sc.leader {
		return
	}
	db := sc.controlDB()
	if db == nil {
		return
	}
	rows, err := db.ListRotations(1)
	if err != nil {
		return
	}
	if len(rows) == 0 {
		hubmetrics.KEKRotationActive.Set(0)
		return
	}
	r := rows[0]
	hubmetrics.KEKRotationRecords.Set(float64(r.Total), hubmetrics.RotationTotal)
	hubmetrics.KEKRotationRecords.Set(float64(r.Rewrapped), hubmetrics.RotationRewrapped)
	hubmetrics.KEKRotationRecords.Set(float64(r.Skipped), hubmetrics.RotationSkipped)
	hubmetrics.KEKRotationRecords.Set(float64(r.Failed), hubmetrics.RotationFailed)
	active := 0.0
	if r.State == secretbroker.RotationRunning {
		active = 1
	}
	hubmetrics.KEKRotationActive.Set(active)
}

// ── runs ────────────────────────────────────────────────────────────────────

// runLabels are the two labels every task family carries: the driver and the
// isolation it provides. Never the executor's ID.
func runLabels(ex executor.Executor) (kind, isolation string) {
	return ex.Kind(), string(ex.Capabilities().Isolation)
}

// countRunStart records a run dispatched to ex — and, when err says it never
// began, its failure at start. A run refused before any executor was chosen
// (ex nil: nothing bound, or strict mode refusing the host) reached no driver
// and is not counted.
func countRunStart(ex executor.Executor, err error) {
	if ex == nil {
		return
	}
	kind, iso := runLabels(ex)
	hubmetrics.TaskStarts.Inc(kind, iso)
	if err != nil {
		hubmetrics.TaskFailures.Inc(kind, iso, hubmetrics.FailStart)
	}
}

// countRunSettled records how a dispatched run ended, given the driver's last
// word on it (st, or stErr when it had none) and whether the control plane had
// asked it to stop.
//
//   - cancelled: the hub stopped it — Stop pressed, a budget stop — or the
//     driver killed it at cloop's request. A run that exits zero after being
//     told to stop was withdrawn, not completed.
//   - completed: it exited zero.
//   - run: anything else, including an executor that could not say how the
//     run ended. "Not shown to have succeeded" is the reading an operator's
//     success rate needs.
//
// The duration is the driver's own account of the workload when it has one,
// and otherwise the time since this member began tracking the run.
func countRunSettled(ex executor.Executor, st executor.Status, stErr error, stopped bool, tracked time.Time) {
	if ex == nil {
		return
	}
	kind, iso := runLabels(ex)
	if reason := settledReason(st, stErr, stopped); reason != "" {
		hubmetrics.TaskFailures.Inc(kind, iso, reason)
	} else {
		hubmetrics.TaskCompletions.Inc(kind, iso)
	}
	if d, ok := runDuration(st, stErr, tracked, time.Now()); ok {
		hubmetrics.TaskDuration.Observe(d.Seconds(), kind, iso)
	}
}

// settledReason classifies a settled run: "" for a completion, otherwise the
// hubmetrics.Fail* reason it failed with.
func settledReason(st executor.Status, stErr error, stopped bool) string {
	requestedKill := stErr == nil && st.State == executor.StateKilled && !unrequestedKill(st)
	switch {
	case stErr == nil && st.Outcome == executor.OutcomeDiskLimit:
		// Ahead of the kill readings: it is a SIGKILL with exit 137, and
		// neither an operator's stop nor a crash (Task 20405).
		return hubmetrics.FailDiskLimit
	case stopped || requestedKill:
		return hubmetrics.FailCancelled
	case stErr == nil && st.State == executor.StateExited && st.ExitCode == 0:
		return ""
	}
	return hubmetrics.FailRun
}

// runDuration is how long a run ran: the driver's start-to-finish when it
// reported both, else from when it was tracked until now.
func runDuration(st executor.Status, stErr error, tracked, now time.Time) (time.Duration, bool) {
	if stErr == nil && !st.StartedAt.IsZero() && !st.FinishedAt.IsZero() && !st.FinishedAt.Before(st.StartedAt) {
		return st.FinishedAt.Sub(st.StartedAt), true
	}
	if !tracked.IsZero() && now.After(tracked) {
		return now.Sub(tracked), true
	}
	return 0, false
}

// ── API tokens ──────────────────────────────────────────────────────────────

// countTokenVerification records one API token verification's verdict. err is
// what apitoken.Manager.Verify returned, or the reason the token store could
// not be reached at all.
func countTokenVerification(err error) {
	if err == nil {
		hubmetrics.TokenAuth.Inc(hubmetrics.ResultSuccess)
		return
	}
	hubmetrics.TokenAuth.Inc(hubmetrics.ResultFailure)
	hubmetrics.TokenAuthFailures.Inc(tokenFailureMetric(err))
}

// tokenFailureMetric maps a verification error to its metric reason: one per
// pkg/apitoken sentinel, and store_error for anything else — every non-sentinel
// error Verify returns is its store failing, not the caller's credential.
//
// These are not tokenFailureReason's audit strings, and need not be: the audit
// trail and the catalog each name the sentinels in their own documented words.
func tokenFailureMetric(err error) string {
	switch {
	case errors.Is(err, apitoken.ErrMalformed):
		return hubmetrics.TokenMalformed
	case errors.Is(err, apitoken.ErrNotFound):
		return hubmetrics.TokenNotFound
	case errors.Is(err, apitoken.ErrBadSecret):
		return hubmetrics.TokenBadSecret
	case errors.Is(err, apitoken.ErrRevoked):
		return hubmetrics.TokenRevoked
	case errors.Is(err, apitoken.ErrExpired):
		return hubmetrics.TokenExpired
	case errors.Is(err, apitoken.ErrNoRoles):
		return hubmetrics.TokenNoRoles
	}
	return hubmetrics.TokenStoreError
}

// ── sessions ────────────────────────────────────────────────────────────────

// countSessionEvent mirrors a session lifecycle event into the session
// counters.
//
// The audit sink is the right tap: oidcauth emits a creation once per session
// and a termination only from the call whose store delete actually removed the
// row, so a session two requests both found expired, or a janitor pass racing a
// sign-out, ends once here as it does in the trail.
func countSessionEvent(ev oidcauth.SessionAudit) {
	switch ev.Event {
	case oidcauth.AuditSessionCreated:
		hubmetrics.SessionsCreated.Inc()
	case oidcauth.AuditSessionExpired, oidcauth.AuditSessionRevoked, oidcauth.AuditSessionIdPRevoked:
		hubmetrics.SessionsTerminated.Inc(sessionEndReason(ev))
	}
}

// sessionEndReason names why a session ended, in the catalog's vocabulary.
func sessionEndReason(ev oidcauth.SessionAudit) string {
	switch ev.Event {
	case oidcauth.AuditSessionIdPRevoked:
		return hubmetrics.SessionIdPRevoked
	case oidcauth.AuditSessionExpired:
		if ev.Reason == oidcauth.ReasonIdleTimeout {
			return hubmetrics.SessionIdleEvicted
		}
		return hubmetrics.SessionAbsoluteExpired
	}
	switch ev.Reason {
	case oidcauth.ReasonUserLogout, oidcauth.ReasonLogoutAll:
		return hubmetrics.SessionSelfLogout
	case oidcauth.ReasonSessionQuota:
		return hubmetrics.SessionQuotaEvicted
	}
	// Every other revocation is an operator's — the sessions panel, an
	// offboarding — each with its own reason text. (`cloop hub session
	// revoke` deletes rows from its own process, which no hub's registry
	// sees; cloop_sessions_live falls, and the audit trail has the rest.)
	return hubmetrics.SessionAdminRevoked
}
