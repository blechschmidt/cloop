package ui

// The hub metrics, proved through the hub's own /metrics (Task 20377).
//
// TestMetricsEndToEnd scrapes a real Server, through its router and its
// audit.read gate, after doing each thing a family exists to count: runs
// dispatched to an executor and settled three different ways, a sign-in and a
// sign-out, API tokens good and bad, an egress request, a fleet in mixed
// health and a key rotation under way. pkg/hubmetrics' TestEveryFamilyIsRecorded
// proves that something records every family; this proves the somethings fire.
//
// It is not parallel, and asserts deltas. The registry is process-wide and the
// executor registry with it; a parallel test dispatching runs or verifying
// tokens alongside it would move the very counters it reads.

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/apitoken"
	"github.com/blechschmidt/cloop/pkg/egressbroker"
	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/executorstore"
	"github.com/blechschmidt/cloop/pkg/hubmetrics"
	"github.com/blechschmidt/cloop/pkg/oidcauth"
	"github.com/blechschmidt/cloop/pkg/secretbroker"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// ── a driver whose runs the test controls ───────────────────────────────────

// metricsStubExecutor runs nothing. Each Start opens a run whose end the test
// chooses — finishing it, or letting an interrupt end it — and whose status
// carries the start and finish times the driver would report.
type metricsStubExecutor struct {
	id, kind  string
	isolation executor.Isolation
	startErr  error
	healthErr error

	mu   sync.Mutex
	seq  int
	runs map[string]*stubRun
}

type stubRun struct {
	done   chan struct{}
	status executor.Status
}

func newMetricsStub(id, kind string, iso executor.Isolation) *metricsStubExecutor {
	return &metricsStubExecutor{id: id, kind: kind, isolation: iso, runs: map[string]*stubRun{}}
}

func (e *metricsStubExecutor) ID() string   { return e.id }
func (e *metricsStubExecutor) Kind() string { return e.kind }
func (e *metricsStubExecutor) Capabilities() executor.Capabilities {
	// Shares the hub's filesystem, so the source tree is bound rather than
	// provisioned and the dispatch path has nothing to fetch.
	return executor.Capabilities{Isolation: e.isolation, SharesHostFilesystem: true}
}
func (e *metricsStubExecutor) HealthCheck(context.Context) error { return e.healthErr }

func (e *metricsStubExecutor) Start(_ context.Context, spec executor.Spec) (executor.Handle, error) {
	if e.startErr != nil {
		return executor.Handle{}, e.startErr
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	e.seq++
	id := fmt.Sprintf("%s-run-%d", e.id, e.seq)
	e.runs[id] = &stubRun{
		done:   make(chan struct{}),
		status: executor.Status{HandleID: id, ExecutorID: e.id, State: executor.StateRunning, StartedAt: time.Now()},
	}
	return executor.Handle{ID: id, ExecutorID: e.id}, nil
}

// finish ends handle's run with exit code code, reporting it as having run
// for d.
func (e *metricsStubExecutor) finish(handle string, code int, d time.Duration) {
	e.mu.Lock()
	defer e.mu.Unlock()
	r := e.runs[handle]
	if r == nil {
		return
	}
	select {
	case <-r.done:
		return
	default:
	}
	r.status.State = executor.StateExited
	r.status.ExitCode = code
	r.status.StartedAt = time.Now().Add(-d)
	r.status.FinishedAt = time.Now()
	close(r.done)
}

// latest returns the most recently started run's handle.
func (e *metricsStubExecutor) latest() string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return fmt.Sprintf("%s-run-%d", e.id, e.seq)
}

func (e *metricsStubExecutor) Signal(_ context.Context, handle string, sig executor.Signal) error {
	// An interrupt is how Stop reaches a run: it pauses, and exits zero.
	if sig == executor.SignalInterrupt {
		e.finish(handle, 0, 30*time.Second)
	}
	return nil
}

func (e *metricsStubExecutor) Status(_ context.Context, handle string) (executor.Status, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	r := e.runs[handle]
	if r == nil {
		return executor.Status{}, executor.ErrHandleNotFound
	}
	return r.status, nil
}

func (e *metricsStubExecutor) Stream(ctx context.Context, handle string) (<-chan executor.LogLine, error) {
	e.mu.Lock()
	r := e.runs[handle]
	e.mu.Unlock()
	if r == nil {
		return nil, executor.ErrHandleNotFound
	}
	ch := make(chan executor.LogLine)
	go func() {
		defer close(ch)
		select {
		case <-r.done:
		case <-ctx.Done():
		}
	}()
	return ch, nil
}

// registerStub puts ex in the process registry for the length of the test.
func registerStub(t *testing.T, ex executor.Executor) {
	t.Helper()
	registerBuiltinExecutors()
	if err := executor.DefaultRegistry.Register(ex); err != nil {
		t.Fatalf("register %s: %v", ex.ID(), err)
	}
	t.Cleanup(func() { executor.DefaultRegistry.Unregister(ex.ID()) })
}

// ── reading the scrape ──────────────────────────────────────────────────────

// series renders a series name the way the exposition does.
func series(family string, labels ...string) string {
	if len(labels) == 0 {
		return family
	}
	var parts []string
	for i := 0; i+1 < len(labels); i += 2 {
		parts = append(parts, labels[i]+`="`+labels[i+1]+`"`)
	}
	return family + "{" + strings.Join(parts, ",") + "}"
}

// sample reads one series out of a scrape: its value, and whether it is there.
func sample(body, name string) (float64, bool) {
	for _, line := range strings.Split(body, "\n") {
		if rest, ok := strings.CutPrefix(line, name+" "); ok {
			v, err := strconv.ParseFloat(strings.TrimSpace(rest), 64)
			return v, err == nil
		}
	}
	return 0, false
}

// value is sample with absent read as zero, for counters that may not have
// been touched yet.
func value(body, name string) float64 {
	v, _ := sample(body, name)
	return v
}

// ── the end-to-end scrape ───────────────────────────────────────────────────

func TestMetricsEndToEnd(t *testing.T) {
	idp := newUIFakeIdP(t)
	dir := setupProjectDir(t, cloopGoal, nil)
	// The stub runs nothing, so the project needs no Claude credential on the
	// isolating executor it is bound to below (Task 20379).
	setProvider(t, dir, "mock")
	srv := New(dir, 0, "")
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(func() {
		ts.Close()
		srv.closeTokenManager()
	})
	auth, err := oidcauth.New(oidcauth.Config{
		Enabled:      true,
		Issuer:       idp.server.URL,
		ClientID:     "cloop-dashboard",
		ClientSecret: "test-secret",
		RedirectURL:  ts.URL + "/auth/callback",
		Audit:        srv.SessionAuditSink(),
	})
	if err != nil {
		t.Fatalf("oidcauth.New: %v", err)
	}
	srv.OIDC = auth

	// The scraper: a service-account token holding audit.read, exactly as
	// docs/operations/metrics.md tells an operator to mint one. Every scrape
	// through it is itself one successful token verification.
	mgr, err := srv.tokenManager()
	if err != nil {
		t.Fatalf("tokenManager: %v", err)
	}
	minted, err := mgr.Mint(apitoken.MintOptions{Name: "prometheus", Roles: []string{"admin"}})
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	admin := minted.Plaintext
	call := func(method, path, tok string) (int, string) {
		t.Helper()
		req, err := http.NewRequest(method, ts.URL+path, strings.NewReader("{}"))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json")
		if tok != "" {
			req.Header.Set("Authorization", "Bearer "+tok)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("%s %s: %v", method, path, err)
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(body)
	}
	scrape := func() string {
		t.Helper()
		code, body := call(http.MethodGet, "/metrics", admin)
		if code != http.StatusOK {
			t.Fatalf("GET /metrics = %d: %.300s", code, body)
		}
		return body
	}

	const kind, iso = executor.KindKubernetes, string(executor.IsolationVM)
	labels := []string{"executor_kind", kind, "isolation", iso}
	starts := series("cloop_executor_task_starts_total", labels...)
	completions := series("cloop_executor_task_completions_total", labels...)
	failure := func(reason string) string {
		return series("cloop_executor_task_failures_total", append(labels, "reason", reason)...)
	}
	bucket := func(le string) string {
		return series("cloop_executor_task_duration_seconds_bucket", append(labels, "le", le)...)
	}
	durationCount := series("cloop_executor_task_duration_seconds_count", labels...)
	tokenSuccess := series("cloop_apitoken_auth_total", "result", "success")
	tokenFailure := series("cloop_apitoken_auth_total", "result", "failure")

	before := scrape()

	// ── runs: one completes, one never starts, one is stopped ─────────────
	runner := newMetricsStub("metrics-e2e-runner", kind, executor.IsolationVM)
	registerStub(t, runner)
	if err := executor.Bind(dir, runner.ID()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { executor.DefaultRegistry.Unbind(dir) })

	waitScrape := func(what string, cond func(string) bool) string {
		t.Helper()
		deadline := time.Now().Add(20 * time.Second)
		for {
			body := scrape()
			if cond(body) {
				return body
			}
			if time.Now().After(deadline) {
				t.Fatalf("timed out waiting for %s; scrape:\n%s", what, body)
			}
			time.Sleep(25 * time.Millisecond)
		}
	}
	// idle waits until the last run is settled: nothing executing, nothing
	// tracked. A start before then would be refused as a second harness.
	idle := func() {
		t.Helper()
		deadline := time.Now().Add(10 * time.Second)
		for {
			_, tracked := srv.trackedRun(dir)
			if !tracked && !srv.projectExecuting(dir) {
				return
			}
			if time.Now().After(deadline) {
				t.Fatal("the previous run never settled")
			}
			time.Sleep(10 * time.Millisecond)
		}
	}

	if code, body := call(http.MethodPost, "/api/run", admin); code != http.StatusOK {
		t.Fatalf("POST /api/run = %d: %s", code, body)
	}
	runner.finish(runner.latest(), 0, 2*time.Minute)
	waitScrape("the finished run to be counted", func(b string) bool {
		return value(b, completions)-value(before, completions) == 1
	})
	idle()

	refuser := newMetricsStub("metrics-e2e-refuser", kind, executor.IsolationVM)
	refuser.startErr = errors.New("the runtime refused the pod")
	registerStub(t, refuser)
	if err := executor.Bind(dir, refuser.ID()); err != nil {
		t.Fatal(err)
	}
	if code, body := call(http.MethodPost, "/api/run", admin); code == http.StatusOK {
		t.Fatalf("POST /api/run on a refusing executor = 200: %s", body)
	}
	idle()

	if err := executor.Bind(dir, runner.ID()); err != nil {
		t.Fatal(err)
	}
	if code, body := call(http.MethodPost, "/api/run", admin); code != http.StatusOK {
		t.Fatalf("POST /api/run (to be stopped) = %d: %s", code, body)
	}
	if code, body := call(http.MethodPost, "/api/stop", admin); code != http.StatusOK || !strings.Contains(body, `"ok":true`) {
		t.Fatalf("POST /api/stop = %d: %s", code, body)
	}
	runs := waitScrape("the stopped run to be counted", func(b string) bool {
		return value(b, failure(hubmetrics.FailCancelled))-value(before, failure(hubmetrics.FailCancelled)) == 1
	})
	idle()

	for name, want := range map[string]float64{
		starts:                            3,
		completions:                       1,
		failure(hubmetrics.FailStart):     1,
		failure(hubmetrics.FailCancelled): 1,
		failure(hubmetrics.FailRun):       0,
		durationCount:                     2, // the refused run never ran
		bucket("60"):                      1, // the stopped run, 30s by the driver's clock
		bucket("300"):                     2, // ...and the finished one, 2m
		bucket("15"):                      0,
	} {
		if got := value(runs, name) - value(before, name); got != want {
			t.Errorf("%s moved by %v, want %v", name, got, want)
		}
	}

	// ── a sign-in and a sign-out ───────────────────────────────────────────
	created := "cloop_sessions_created_total"
	selfLogout := series("cloop_sessions_terminated_total", "reason", hubmetrics.SessionSelfLogout)
	beforeLogin := scrape()
	c := jarClient(t)
	login(t, c, ts)
	afterLogin := scrape()
	if got := value(afterLogin, created) - value(beforeLogin, created); got != 1 {
		t.Errorf("a sign-in moved %s by %v, want 1", created, got)
	}
	if got, ok := sample(afterLogin, "cloop_sessions_live"); !ok || got != 1 {
		t.Errorf("cloop_sessions_live = %v (present %v) after one sign-in, want 1", got, ok)
	}
	resp, err := c.Post(ts.URL+"/auth/logout", "application/json", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	afterLogout := scrape()
	if got := value(afterLogout, selfLogout) - value(afterLogin, selfLogout); got != 1 {
		t.Errorf("a sign-out moved %s by %v, want 1", selfLogout, got)
	}
	if got, ok := sample(afterLogout, "cloop_sessions_live"); !ok || got != 0 {
		t.Errorf("cloop_sessions_live = %v (present %v) after signing out, want 0", got, ok)
	}

	// ── API tokens, good and bad ────────────────────────────────────────────
	viewer, err := mgr.Mint(apitoken.MintOptions{Name: "viewer", Roles: []string{"viewer"}})
	if err != nil {
		t.Fatal(err)
	}
	// Well-formed but issued by nobody, and not well-formed at all.
	unknown := apitoken.Prefix + "0123456789abcdef_" + strings.Repeat("a", 64)
	malformed := apitoken.Prefix + "not-a-token"
	beforeTokens := scrape()
	if code, _ := call(http.MethodGet, "/api/state", viewer.Plaintext); code != http.StatusOK {
		t.Errorf("a viewer token reading state = %d, want 200", code)
	}
	for _, bad := range []string{unknown, malformed} {
		if code, _ := call(http.MethodGet, "/api/state", bad); code != http.StatusUnauthorized {
			t.Errorf("token %.24s… = %d, want 401", bad, code)
		}
	}
	afterTokens := scrape()
	// One viewer request and one scrape between the two readings.
	if got := value(afterTokens, tokenSuccess) - value(beforeTokens, tokenSuccess); got != 2 {
		t.Errorf("%s moved by %v, want 2 (the viewer's request and one scrape)", tokenSuccess, got)
	}
	if got := value(afterTokens, tokenFailure) - value(beforeTokens, tokenFailure); got != 2 {
		t.Errorf("%s moved by %v, want 2", tokenFailure, got)
	}
	for _, reason := range []string{hubmetrics.TokenNotFound, hubmetrics.TokenMalformed} {
		name := series("cloop_apitoken_auth_failures_total", "reason", reason)
		if got := value(afterTokens, name) - value(beforeTokens, name); got != 1 {
			t.Errorf("%s moved by %v, want 1", name, got)
		}
	}

	// ── an egress request ───────────────────────────────────────────────────
	const page = "egress reached the origin"
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, page)
	}))
	t.Cleanup(origin.Close)
	beforeEgress := scrape()
	proxyGet(t, origin.URL, page)
	allowed := series("cloop_egress_requests_total", "result", "allowed")
	down := series("cloop_egress_bytes_total", "direction", "down")
	// The proxy records the verdict after the body is on the wire, so the
	// client can have read it first.
	afterEgress := waitScrape("the egress request to be counted", func(b string) bool {
		return value(b, allowed)-value(beforeEgress, allowed) >= 1
	})
	if got := value(afterEgress, allowed) - value(beforeEgress, allowed); got != 1 {
		t.Errorf("an egress request moved %s by %v, want 1", allowed, got)
	}
	if got := value(afterEgress, down) - value(beforeEgress, down); got != float64(len(page)) {
		t.Errorf("%s moved by %v, want the %d bytes of the page", down, got, len(page))
	}
	if got := value(afterEgress, "cloop_egress_sessions_live") - value(beforeEgress, "cloop_egress_sessions_live"); got != 1 {
		t.Errorf("cloop_egress_sessions_live moved by %v with one session open, want 1", got)
	}

	// ── the gauges read at scrape time ──────────────────────────────────────
	// A cordoned executor last seen 90 seconds ago, and a key rotation under
	// way, both written where the supervisor and `cloop hub key rotate`
	// would write them. Cordoned because a probe may never leave that state,
	// and a failing health check because a probe that succeeded would move
	// last-seen: the process supervisor can probe this executor mid-test.
	cordoned := newMetricsStub("metrics-e2e-cordoned", executor.KindVirtual, executor.IsolationContainer)
	cordoned.healthErr = errors.New("unreachable")
	registerStub(t, cordoned)
	db, err := statedb.Open(state.DBPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	sched, err := executorstore.NewScheduler(db)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	if err := sched.SaveHealth(executor.Health{
		ExecutorID: cordoned.ID(), State: executor.NodeCordoned, Reason: "maintenance",
		LastSeen: now.Add(-90 * time.Second), LastProbe: now, StateChangedAt: now.Add(-time.Minute),
	}); err != nil {
		t.Fatal(err)
	}
	stamp := now.UTC().Format(time.RFC3339Nano)
	if err := db.PutRotation(statedb.RotationRow{
		ID: "rot-metrics-e2e", ToKeyID: "kek-2", State: secretbroker.RotationRunning,
		StartedAt: stamp, UpdatedAt: stamp, StartedBy: "test", Total: 10, Rewrapped: 4, Skipped: 1,
	}); err != nil {
		t.Fatal(err)
	}

	gauges := scrape()
	for name, want := range map[string]float64{
		series("cloop_executors", "kind", executor.KindVirtual, "state", "cordoned"): 1,
		series("cloop_secret_kek_rotation_records", "phase", "total"):                10,
		series("cloop_secret_kek_rotation_records", "phase", "rewrapped"):            4,
		series("cloop_secret_kek_rotation_records", "phase", "skipped"):              1,
		series("cloop_secret_kek_rotation_records", "phase", "failed"):               0,
		"cloop_secret_kek_rotation_active":                                           1,
	} {
		if got, ok := sample(gauges, name); !ok || got != want {
			t.Errorf("%s = %v (present %v), want %v", name, got, ok, want)
		}
	}
	if got, ok := sample(gauges, series("cloop_executors", "kind", kind, "state", "ready")); !ok || got < 2 {
		t.Errorf("the two run executors are not in the fleet as ready: %v (present %v)", got, ok)
	}
	age, ok := sample(gauges, series("cloop_executor_heartbeat_age_seconds_max", "kind", executor.KindVirtual))
	if !ok || age < 90 || age > 300 {
		t.Errorf("heartbeat age for the cordoned executor = %v (present %v), want about 90s", age, ok)
	}
	for _, k := range secretbroker.Kinds() {
		if _, ok := sample(gauges, series("cloop_secret_leases_live", "kind", string(k))); !ok {
			t.Errorf("cloop_secret_leases_live has no series for %s; every kind is exported, zero included", k)
		}
	}
	if got, ok := sample(gauges, "cloop_projects_registered"); !ok || got < 1 {
		t.Errorf("cloop_projects_registered = %v (present %v)", got, ok)
	}
}

// proxyGet makes one request through an egress broker's proxy in this process
// — a grant for the origin, a redeemed session, a GET — and checks the body.
func proxyGet(t *testing.T, target, want string) {
	t.Helper()
	u, err := url.Parse(target)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(u.Port())
	if err != nil {
		t.Fatal(err)
	}
	b, err := egressbroker.New(egressbroker.NewMemStore())
	if err != nil {
		t.Fatal(err)
	}
	sub, err := secretbroker.ParseSubject("project:/srv/metrics-e2e")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.Grant(context.Background(), egressbroker.GrantRequest{
		Subject: sub, Hosts: []string{"127.0.0.1"}, CIDRs: []string{"127.0.0.0/8"},
		Ports: []int{port}, TTL: time.Hour, Actor: "test",
	}); err != nil {
		t.Fatal(err)
	}
	p, err := egressbroker.NewProxy(b, egressbroker.Options{ListenAddr: "127.0.0.1:0"})
	if err != nil {
		t.Fatal(err)
	}
	served := make(chan error, 1)
	go func() { served <- p.ListenAndServe() }()
	t.Cleanup(func() {
		_ = p.Close()
		<-served
	})
	for deadline := time.Now().Add(5 * time.Second); p.Addr() == ""; {
		if time.Now().After(deadline) {
			t.Fatal("the egress proxy never bound")
		}
		time.Sleep(time.Millisecond)
	}
	red, err := b.Redeem(context.Background(), egressbroker.RedeemRequest{
		Requester: secretbroker.Requester{ProjectID: "/srv/metrics-e2e"}, Actor: "test",
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { b.CloseSession(red.Session.ID, "test finished") })
	proxyURL, err := url.Parse(red.ProxyURL)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{
		Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL), DisableKeepAlives: true},
		Timeout:   10 * time.Second,
	}
	resp, err := client.Get(target)
	if err != nil {
		t.Fatalf("GET through the egress proxy: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK || string(body) != want {
		t.Fatalf("GET through the egress proxy = %d %q", resp.StatusCode, body)
	}
}

// ── a cluster ───────────────────────────────────────────────────────────────

// TestMetricsSharedGaugesComeFromTheLeaderOnly is the property that keeps a
// cluster's gauges from being multiplied under sum(): two members over one
// database, scraped side by side, and every gauge read from that database
// appears in exactly one scrape — the leader's — while the per-member
// families appear in both. Then the leader goes, and the survivor takes over
// reporting them.
func TestMetricsSharedGaugesComeFromTheLeaderOnly(t *testing.T) {
	_, a, b := clusterPair(t)

	shared := []string{
		"cloop_sessions_live",
		"cloop_secret_kek_rotation_active",
		"cloop_quota_enforcement_enabled",
		"cloop_quota_identities",
		"cloop_projects_registered",
		"cloop_statedb_wal_bytes",
	}
	perMember := series("cloop_secret_leases_live", "kind", string(secretbroker.KindGitHubPAT))

	// scrapeSettled scrapes both members while one of them leads, and returns
	// which — retrying if leadership moved under the scrapes, as a short test
	// lease can on a loaded machine.
	scrapeSettled := func() (leader, follower *clusterMember, lb, fb string) {
		t.Helper()
		deadline := time.Now().Add(10 * time.Second)
		for {
			if a.node.IsLeader() != b.node.IsLeader() {
				leader, follower = a, b
				if b.node.IsLeader() {
					leader, follower = b, a
				}
				lb, fb = leader.srv.gatherMetrics(), follower.srv.gatherMetrics()
				if leader.node.IsLeader() && !follower.node.IsLeader() {
					return leader, follower, lb, fb
				}
			}
			if time.Now().After(deadline) {
				t.Fatal("leadership never held still across a pair of scrapes")
			}
			time.Sleep(10 * time.Millisecond)
		}
	}

	leader, follower, lb, fb := scrapeSettled()
	for _, name := range shared {
		if _, ok := sample(lb, name); !ok {
			t.Errorf("the leader does not export %s", name)
		}
		if v, ok := sample(fb, name); ok {
			t.Errorf("a follower exports %s = %v; sum() over the cluster would count it twice", name, v)
		}
	}
	if strings.Contains(fb, "\ncloop_executors{") {
		t.Error("a follower exports cloop_executors; sum() over the cluster would count the fleet twice")
	}
	if !strings.Contains(lb, "\ncloop_executors{") {
		t.Error("the leader does not export cloop_executors")
	}
	for who, body := range map[string]string{"the leader": lb, "a follower": fb} {
		if _, ok := sample(body, perMember); !ok {
			t.Errorf("%s does not export its own %s", who, perMember)
		}
	}

	// The leader leaves; the other takes over, and with it the reporting.
	// The one that left must stop: a gauge it went on exporting would be
	// frozen at its last reading and double the new leader's under sum().
	if err := leader.node.Close(); err != nil {
		t.Fatalf("close the leader: %v", err)
	}
	waitCluster(t, "the survivor to lead", follower.node.IsLeader)
	body := follower.srv.gatherMetrics()
	former := leader.srv.gatherMetrics()
	for _, name := range shared {
		if _, ok := sample(body, name); !ok {
			t.Errorf("the new leader does not export %s", name)
		}
		if v, ok := sample(former, name); ok {
			t.Errorf("the former leader still exports %s = %v after stepping down", name, v)
		}
	}
}

// ── the parts, one at a time ────────────────────────────────────────────────

func TestSettledReason(t *testing.T) {
	t.Parallel()
	exited := func(code int) executor.Status {
		return executor.Status{State: executor.StateExited, ExitCode: code}
	}
	for _, tc := range []struct {
		name    string
		st      executor.Status
		err     error
		stopped bool
		want    string
	}{
		{"exit zero completes", exited(0), nil, false, ""},
		{"a non-zero exit fails", exited(2), nil, false, hubmetrics.FailRun},
		{"exit 137 is a kill nobody asked for", exited(137), nil, false, hubmetrics.FailRun},
		{"an unrequested SIGKILL fails", executor.Status{State: executor.StateKilled, Error: "signal: killed"}, nil, false, hubmetrics.FailRun},
		{"a kill cloop asked for is a cancellation", executor.Status{State: executor.StateKilled, Error: "stopped by request"}, nil, false, hubmetrics.FailCancelled},
		{"a driver failure fails", executor.Status{State: executor.StateFailed, Error: "lost"}, nil, false, hubmetrics.FailRun},
		{"an executor that cannot say fails", executor.Status{}, executor.ErrHandleNotFound, false, hubmetrics.FailRun},
		{"a run told to stop that exits zero was cancelled", exited(0), nil, true, hubmetrics.FailCancelled},
		{"a run told to stop whose driver is gone was cancelled", executor.Status{}, executor.ErrHandleNotFound, true, hubmetrics.FailCancelled},
	} {
		if got := settledReason(tc.st, tc.err, tc.stopped); got != tc.want {
			t.Errorf("%s: settledReason = %q, want %q", tc.name, got, tc.want)
		}
	}
}

func TestRunDuration(t *testing.T) {
	t.Parallel()
	t0 := time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)
	st := executor.Status{StartedAt: t0, FinishedAt: t0.Add(90 * time.Second)}
	if d, ok := runDuration(st, nil, t0.Add(-time.Hour), t0.Add(time.Hour)); !ok || d != 90*time.Second {
		t.Errorf("with the driver's times: %v %v, want 90s", d, ok)
	}
	if d, ok := runDuration(executor.Status{}, executor.ErrHandleNotFound, t0, t0.Add(time.Minute)); !ok || d != time.Minute {
		t.Errorf("from tracking: %v %v, want 1m", d, ok)
	}
	if _, ok := runDuration(executor.Status{}, executor.ErrHandleNotFound, time.Time{}, t0); ok {
		t.Error("a duration with nothing to measure it from")
	}
}

func TestSessionEndReason(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		ev   oidcauth.SessionAudit
		want string
	}{
		{oidcauth.SessionAudit{Event: oidcauth.AuditSessionExpired, Reason: oidcauth.ReasonIdleTimeout}, hubmetrics.SessionIdleEvicted},
		{oidcauth.SessionAudit{Event: oidcauth.AuditSessionExpired, Reason: oidcauth.ReasonAbsoluteTTL}, hubmetrics.SessionAbsoluteExpired},
		{oidcauth.SessionAudit{Event: oidcauth.AuditSessionRevoked, Reason: oidcauth.ReasonUserLogout}, hubmetrics.SessionSelfLogout},
		{oidcauth.SessionAudit{Event: oidcauth.AuditSessionRevoked, Reason: oidcauth.ReasonLogoutAll}, hubmetrics.SessionSelfLogout},
		{oidcauth.SessionAudit{Event: oidcauth.AuditSessionRevoked, Reason: oidcauth.ReasonSessionQuota}, hubmetrics.SessionQuotaEvicted},
		{oidcauth.SessionAudit{Event: oidcauth.AuditSessionRevoked, Reason: oidcauth.ReasonAdminRevoked}, hubmetrics.SessionAdminRevoked},
		{oidcauth.SessionAudit{Event: oidcauth.AuditSessionRevoked, Reason: "offboarded: left the company"}, hubmetrics.SessionAdminRevoked},
		{oidcauth.SessionAudit{Event: oidcauth.AuditSessionIdPRevoked, Reason: "idp_invalid_grant"}, hubmetrics.SessionIdPRevoked},
	} {
		if got := sessionEndReason(tc.ev); got != tc.want {
			t.Errorf("%s/%s: sessionEndReason = %q, want %q", tc.ev.Event, tc.ev.Reason, got, tc.want)
		}
	}
}

func TestTokenFailureMetric(t *testing.T) {
	t.Parallel()
	for err, want := range map[error]string{
		apitoken.ErrMalformed:            hubmetrics.TokenMalformed,
		apitoken.ErrNotFound:             hubmetrics.TokenNotFound,
		apitoken.ErrBadSecret:            hubmetrics.TokenBadSecret,
		apitoken.ErrRevoked:              hubmetrics.TokenRevoked,
		apitoken.ErrExpired:              hubmetrics.TokenExpired,
		apitoken.ErrNoRoles:              hubmetrics.TokenNoRoles,
		errors.New("database is locked"): hubmetrics.TokenStoreError,
	} {
		if got := tokenFailureMetric(fmt.Errorf("apitoken: verify: %w", err)); got != want {
			t.Errorf("tokenFailureMetric(%v) = %q, want %q", err, got, want)
		}
	}
}

// TestHubCollectorsOwnTheirFamilies: the collectors registered at startup own
// exactly the gauges this package derives at scrape time, and none of them is
// owned twice.
func TestHubCollectorsOwnTheirFamilies(t *testing.T) {
	t.Parallel()
	registerHubCollectors()
	got := hubmetrics.Default.CollectorFamilies()
	for family, collector := range map[string]string{
		"cloop_quota_enforcement_enabled":          "quota",
		"cloop_quota_limit":                        "quota",
		"cloop_quota_usage":                        "quota",
		"cloop_quota_identities":                   "quota",
		"cloop_projects_registered":                "quota",
		"cloop_sessions_live":                      "sessions",
		"cloop_executors":                          "executor_fleet",
		"cloop_executor_heartbeat_age_seconds_max": "executor_fleet",
		"cloop_secret_leases_live":                 "secret_leases",
		"cloop_secret_kek_rotation_records":        "kek_rotation",
		"cloop_secret_kek_rotation_active":         "kek_rotation",
	} {
		if got[family] != collector {
			t.Errorf("%s is owned by %q, want %q", family, got[family], collector)
		}
	}
}

// TestLiveLeasesCountsHeldUnexpiredLeasesByKind drives the lease collector
// with leases placed in the process registry directly — a held one carrying
// two kinds, and one past its deadline that the janitor has not swept yet.
//
// Read through a Server's scrape, as every reading in this package must be:
// a bare hubmetrics.Default.Gather runs the collectors outside metricsMu.
func TestLiveLeasesCountsHeldUnexpiredLeasesByKind(t *testing.T) {
	srv := &Server{WorkDir: t.TempDir()}
	read := func(k secretbroker.Kind) float64 {
		t.Helper()
		v, ok := sample(srv.gatherMetrics(), series("cloop_secret_leases_live", "kind", string(k)))
		if !ok {
			t.Fatalf("no cloop_secret_leases_live series for %s", k)
		}
		return v
	}
	pat0, kube0, reg0 := read(secretbroker.KindGitHubPAT), read(secretbroker.KindKubeconfig), read(secretbroker.KindRegistry)

	held := &secretLease{lease: &secretbroker.Lease{
		ID: "lease-metrics-held", IssuedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour),
		Materials: []secretbroker.Material{
			{Kind: secretbroker.KindGitHubPAT}, {Kind: secretbroker.KindGitHubPAT}, {Kind: secretbroker.KindKubeconfig},
		},
	}}
	lapsed := &secretLease{lease: &secretbroker.Lease{
		ID: "lease-metrics-lapsed", IssuedAt: time.Now().Add(-time.Hour), ExpiresAt: time.Now().Add(-time.Minute),
		Materials: []secretbroker.Material{{Kind: secretbroker.KindRegistry}},
	}}
	liveLeases.add(held)
	liveLeases.add(lapsed)
	t.Cleanup(func() {
		liveLeases.remove(held.lease.ID)
		liveLeases.remove(lapsed.lease.ID)
	})

	if d := read(secretbroker.KindGitHubPAT) - pat0; d != 1 {
		t.Errorf("a lease with two PATs moved github_pat by %v; it is one lease involving PATs", d)
	}
	if d := read(secretbroker.KindKubeconfig) - kube0; d != 1 {
		t.Errorf("kubeconfig moved by %v, want 1", d)
	}
	if d := read(secretbroker.KindRegistry) - reg0; d != 0 {
		t.Errorf("an expired lease moved registry by %v; it is not live", d)
	}
}
