package ui

// GET /api/hub/health (Task 20434): the hub doctor's checks, run by the hub on
// itself, cached for a minute, recomputed when the configuration changes,
// refused to anyone who may not write the hub's configuration, and with
// nothing secret in what it sends.

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/authz"
	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/executorstore"
	"github.com/blechschmidt/cloop/pkg/hubdoctor"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// hubHealthServer is an open hub over a fresh control plane. knobs runs before
// the listener does, which is the ordering the race detector needs.
func hubHealthServer(t *testing.T, knobs func(*Server)) (*Server, *httptest.Server) {
	t.Helper()
	dir := setupProjectDir(t, "hub health", nil)
	srv := New(dir, 0, "")
	srv.RPS, srv.Burst = 100000, 100000
	if knobs != nil {
		knobs(srv)
	}
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return srv, ts
}

// getHubHealth fetches path (with its query) with c and decodes the report.
func getHubHealth(t *testing.T, c *http.Client, base, query string) (int, hubHealthReport, string) {
	t.Helper()
	if c == nil {
		c = http.DefaultClient
	}
	resp, err := c.Get(base + "/api/hub/health" + query)
	if err != nil {
		t.Fatalf("GET /api/hub/health%s: %v", query, err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var rep hubHealthReport
	if resp.StatusCode == http.StatusOK {
		if err := json.Unmarshal(raw, &rep); err != nil {
			t.Fatalf("decode the report: %v\n%s", err, raw)
		}
		if cc := resp.Header.Get("Cache-Control"); cc != "no-store" {
			t.Errorf("Cache-Control = %q, want no-store: a report is somebody's view of the hub's weak points", cc)
		}
	}
	return resp.StatusCode, rep, string(raw)
}

func findingsByCheck(rep hubHealthReport) map[string][]hubHealthFinding {
	out := map[string][]hubHealthFinding{}
	for _, f := range rep.Findings {
		out[f.Check] = append(out[f.Check], f)
	}
	return out
}

func writeHubConfig(t *testing.T, path, yaml string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
}

// TestHubHealth_AnswersWithTheHubsOwnChecks: the report is this member's,
// carries the doctor's findings with their documentation, counts what it
// found, and leaves out — naming how to run them — the checks that start work.
func TestHubHealth_AnswersWithTheHubsOwnChecks(t *testing.T) {
	_, ts := hubHealthServer(t, nil)
	code, rep, body := getHubHealth(t, nil, ts.URL, "")
	if code != http.StatusOK {
		t.Fatalf("GET /api/hub/health = %d: %s", code, body)
	}
	host, _ := os.Hostname()
	if rep.Member.ID == "" || rep.Member.Hostname != host || !rep.Member.Leader || rep.Member.Clustered {
		t.Errorf("member = %+v, want this standalone process on %s", rep.Member, host)
	}
	if ttl := rep.ExpiresAt.Sub(rep.CheckedAt); ttl < 50*time.Second || ttl > 2*time.Minute {
		t.Errorf("the report is served for %s, want about a minute", ttl)
	}
	if len(rep.Findings) < 20 {
		t.Fatalf("only %d findings: %s", len(rep.Findings), body)
	}
	var counts hubHealthCounts
	for _, f := range rep.Findings {
		switch f.Severity {
		case "fail":
			counts.Fail++
		case "warn":
			counts.Warn++
		case "pass":
			counts.Pass++
		default:
			t.Errorf("%s has severity %q", f.Check, f.Severity)
		}
		if !strings.HasPrefix(f.Docs, hubHealthDocsBase+"#") {
			t.Errorf("%s links to %q, not the runbook", f.Check, f.Docs)
		}
		if f.Severity != "pass" && f.Remediation == "" {
			t.Errorf("%s is %s with no remedy", f.Check, f.Severity)
		}
	}
	if counts != rep.Counts || rep.Failing != counts.Fail {
		t.Errorf("counts %+v and failing %d, but the findings count %+v", rep.Counts, rep.Failing, counts)
	}
	if got := findingsByCheck(rep)["policy.host_execution"]; len(got) != 1 || got[0].Severity != "warn" {
		t.Errorf("policy.host_execution = %+v, want the warning an unset policy gets", got)
	}
	if len(rep.Config.Files) != 1 || rep.Config.Files[0] != ".cloop/config.yaml" {
		t.Errorf("config files = %v", rep.Config.Files)
	}
	var commands []string
	for _, n := range rep.NotRun {
		commands = append(commands, n.Command)
	}
	if strings.Join(commands, "|") != "cloop hub doctor --probe-network-policy --port 0|cloop hub doctor --smoke --port 0" {
		t.Errorf("not_run commands = %v", commands)
	}
	outcomes := map[string]hubdoctor.StepOutcome{}
	for _, s := range rep.Steps {
		if s.ID == "smoke" || s.ID == "executors.network_policy_probe" {
			t.Errorf("the report ran %s", s.ID)
		}
		if s.Outcome == hubdoctor.StepPanicked || s.Outcome == hubdoctor.StepStillRunning {
			t.Errorf("step %s ended %s", s.ID, s.Outcome)
		}
		outcomes[s.ID] = s.Outcome
	}
	for _, id := range []string{"policy", "storage.integrity", "storage", "ui.exposure"} {
		if outcomes[id] != hubdoctor.StepFinished {
			t.Errorf("step %s ended %q in a report's first run", id, outcomes[id])
		}
	}

	// The header's question leaves the findings out and answers the same.
	code, short, body := getHubHealth(t, nil, ts.URL, "?summary=1")
	if code != http.StatusOK || short.Findings != nil || short.Steps != nil || short.NotRun != nil ||
		short.Failing != rep.Failing || !short.CheckedAt.Equal(rep.CheckedAt) {
		t.Errorf("summary = %d %s, want the cached report's counts and nothing else", code, body)
	}
}

// TestHubHealth_RequiresConfigWrite: under an enforced role policy the report
// is an administrator's — config.write across the hub, as the Settings around
// it — and /api/me tells the page whether to ask, so a viewer's page never
// shows the indicator.
func TestHubHealth_RequiresConfigWrite(t *testing.T) {
	idp := newUIFakeIdP(t)
	srv, ts := newOIDCTestServer(t, idp, "", nil)
	resolver, err := authz.New(rbacPolicy())
	if err != nil {
		t.Fatalf("authz.New: %v", err)
	}
	srv.Authz = resolver
	loginAs := func(groups []string) *http.Client {
		idp.groups = groups
		c := jarClient(t)
		login(t, c, ts)
		return c
	}
	viewer, operator, admin := loginAs([]string{"readers"}), loginAs([]string{"engineers"}), loginAs([]string{"owners"})

	for name, c := range map[string]*http.Client{"viewer": viewer, "operator": operator} {
		code, _, body := getHubHealth(t, c, ts.URL, "")
		if code != http.StatusForbidden {
			t.Errorf("%s GET /api/hub/health = %d, want 403: %s", name, code, body)
		}
		if strings.Contains(body, "findings") || strings.Contains(body, "member") {
			t.Errorf("%s's refusal carries the report: %s", name, body)
		}
		if code, _, _ := getHubHealth(t, c, ts.URL, "?summary=1"); code != http.StatusForbidden {
			t.Errorf("%s GET /api/hub/health?summary=1 = %d, want 403", name, code)
		}
	}
	if code, _, _ := getHubHealth(t, http.DefaultClient, ts.URL, ""); code != http.StatusUnauthorized {
		t.Errorf("an anonymous GET /api/hub/health = %d, want 401", code)
	}
	code, rep, body := getHubHealth(t, admin, ts.URL, "")
	if code != http.StatusOK || len(rep.Findings) == 0 {
		t.Fatalf("admin GET /api/hub/health = %d: %s", code, body)
	}

	// What the page decides from: only the administrator's /api/me holds the
	// permission the indicator and the panel ask for.
	globalPerms := func(c *http.Client) map[string]bool {
		code, body := do(t, c, http.MethodGet, ts.URL+"/api/me", "")
		if code != http.StatusOK {
			t.Fatalf("GET /api/me = %d", code)
		}
		var me struct {
			Global []string `json:"global_permissions"`
		}
		if err := json.Unmarshal([]byte(body), &me); err != nil {
			t.Fatalf("decode /api/me: %v", err)
		}
		out := map[string]bool{}
		for _, p := range me.Global {
			out[p] = true
		}
		return out
	}
	if globalPerms(viewer)[string(authz.PermConfigWrite)] || globalPerms(operator)[string(authz.PermConfigWrite)] {
		t.Error("a viewer's or an operator's /api/me grants config.write: their page would ask for the report")
	}
	if !globalPerms(admin)[string(authz.PermConfigWrite)] {
		t.Error("the administrator's /api/me does not grant config.write: their page would never ask")
	}
}

// TestHubHealth_HangingAndPanickingChecksReportThemselves: a check that never
// returns and one that panics each become a finding about themselves, the
// report still answers — in about the time the hanging one was given — and
// every other check's findings are in it.
func TestHubHealth_HangingAndPanickingChecksReportThemselves(t *testing.T) {
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	var panicked atomic.Int32
	_, ts := hubHealthServer(t, func(s *Server) {
		s.hubHealth.extra = []hubdoctor.Check{
			{ID: "test.hang", Title: "A check that never returns", Timeout: 500 * time.Millisecond,
				Run: func(context.Context, func(hubdoctor.Finding)) { <-release }},
			{ID: "test.boom", Title: "A check that panics", Run: func(context.Context, func(hubdoctor.Finding)) {
				panicked.Add(1)
				panic("checked the wrong pointer")
			}},
		}
	})
	start := time.Now()
	code, rep, body := getHubHealth(t, nil, ts.URL, "")
	if code != http.StatusOK {
		t.Fatalf("GET /api/hub/health = %d: %s", code, body)
	}
	if took := time.Since(start); took > 15*time.Second {
		t.Errorf("the report took %s: the hanging check held it up", took)
	}
	got := findingsByCheck(rep)
	var hang, boom bool
	for _, f := range got[hubdoctor.CheckUnfinished] {
		hang = hang || (f.Title == "A check that never returns" && f.Severity == "warn" &&
			strings.Contains(f.Message, "did not finish within 500ms") &&
			strings.HasSuffix(f.Docs, "#hub-health-in-the-dashboard"))
	}
	for _, f := range got[hubdoctor.CheckPanicked] {
		boom = boom || (f.Title == "A check that panics" && strings.Contains(f.Message, "checked the wrong pointer"))
	}
	if !hang || !boom {
		t.Errorf("unfinished %+v, panicked %+v: want one about each test check", got[hubdoctor.CheckUnfinished],
			got[hubdoctor.CheckPanicked])
	}
	if len(got["policy.host_execution"]) != 1 || len(got["storage.integrity"]) != 1 {
		t.Errorf("the hub's own checks are missing beside the broken ones: %s", body)
	}
	outcomes := map[string]hubdoctor.StepOutcome{}
	for _, s := range rep.Steps {
		outcomes[s.ID] = s.Outcome
	}
	if outcomes["test.hang"] != hubdoctor.StepTimedOut || outcomes["test.boom"] != hubdoctor.StepPanicked ||
		outcomes["storage"] != hubdoctor.StepFinished {
		t.Errorf("step outcomes = %v", outcomes)
	}
	if panicked.Load() != 1 {
		t.Errorf("the panicking check ran %d times for one report", panicked.Load())
	}
}

// TestHubHealth_CachedThenRecomputedOnConfigChange: a second request inside
// the minute is answered from the first run; writing the configuration makes
// the next request run again — and tells this member's dashboards once.
func TestHubHealth_CachedThenRecomputedOnConfigChange(t *testing.T) {
	srv, ts := hubHealthServer(t, nil)
	hc := &hubClient{ch: make(chan wsMessage, 16), resync: make(chan struct{}, 1), id: "hub-health"}
	srv.hubMu.Lock()
	srv.hubClients[srv.WorkDir] = map[*hubClient]struct{}{hc: {}}
	srv.hubMu.Unlock()
	nudges := func() int {
		n := 0
		for {
			select {
			case m := <-hc.ch:
				if m.Type == "hub_health" {
					n++
				}
			default:
				return n
			}
		}
	}

	_, first, _ := getHubHealth(t, nil, ts.URL, "")
	_, again, _ := getHubHealth(t, nil, ts.URL, "")
	if !again.CheckedAt.Equal(first.CheckedAt) {
		t.Errorf("a second request inside the minute ran the checks again (%s, then %s)", first.CheckedAt, again.CheckedAt)
	}
	// A rerun asked for seconds after the last one is the last one.
	_, rerun, _ := getHubHealth(t, nil, ts.URL, "?fresh=1")
	if !rerun.CheckedAt.Equal(first.CheckedAt) {
		t.Error("?fresh=1 seconds after a run ran the checks again")
	}
	srv.hubHealthConfigTick()
	if n := nudges(); n != 0 {
		t.Errorf("%d nudge(s) with the configuration unchanged", n)
	}

	time.Sleep(10 * time.Millisecond) // a modification time the first write cannot share
	writeHubConfig(t, config.ConfigPath(srv.WorkDir), "executors:\n  allow_host_process: false\n")
	srv.hubHealthConfigTick()
	srv.hubHealthConfigTick()
	if n := nudges(); n != 1 {
		t.Errorf("%d nudge(s) for one configuration change, want 1", n)
	}
	_, changed, body := getHubHealth(t, nil, ts.URL, "")
	if changed.CheckedAt.Equal(first.CheckedAt) {
		t.Fatal("the configuration changed and the cached report was served")
	}
	if f := findingsByCheck(changed)["policy.host_execution"]; len(f) != 1 || f[0].Severity != "pass" || !changed.StrictMode {
		t.Errorf("after allow_host_process: false, policy.host_execution = %+v (strict %v): %s", f, changed.StrictMode, body)
	}
	// What the new run found differs from the last: every dashboard hears.
	if n := nudges(); n != 1 {
		t.Errorf("%d nudge(s) for a report that changed, want 1", n)
	}
	srv.hubHealthConfigTick()
	if n := nudges(); n != 0 {
		t.Errorf("%d nudge(s) after the report caught up with the configuration", n)
	}

	// Once the report expires, the next request runs again; one that finds
	// what the last found tells nobody.
	srv.hubHealth.mu.Lock()
	srv.hubHealth.report.ExpiresAt = time.Now().Add(-time.Second)
	srv.hubHealth.mu.Unlock()
	_, expired, _ := getHubHealth(t, nil, ts.URL, "")
	if expired.CheckedAt.Equal(changed.CheckedAt) {
		t.Error("an expired report was served")
	}
	if n := nudges(); n != 0 {
		t.Errorf("%d nudge(s) for a report that found the same", n)
	}
}

// TestHubHealth_OneRunAtATime: requests that arrive while a run is under way
// wait for it rather than starting their own.
func TestHubHealth_OneRunAtATime(t *testing.T) {
	var runs atomic.Int32
	gate := make(chan struct{})
	_, ts := hubHealthServer(t, func(s *Server) {
		s.hubHealth.extra = []hubdoctor.Check{{ID: "test.count", Title: "Counts its runs",
			Run: func(context.Context, func(hubdoctor.Finding)) { runs.Add(1); <-gate }}}
	})
	var wg sync.WaitGroup
	at := make([]time.Time, 5)
	for i := range at {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp, err := http.Get(ts.URL + "/api/hub/health?summary=1")
			if err != nil {
				return
			}
			defer resp.Body.Close()
			var rep hubHealthReport
			_ = json.NewDecoder(resp.Body).Decode(&rep)
			at[i] = rep.CheckedAt
		}()
	}
	time.Sleep(300 * time.Millisecond)
	close(gate)
	wg.Wait()
	if n := runs.Load(); n != 1 {
		t.Errorf("five concurrent requests made %d runs, want 1", n)
	}
	for i := range at {
		if !at[i].Equal(at[0]) || at[i].IsZero() {
			t.Errorf("request %d was answered with the report of %s, the first with %s", i, at[i], at[0])
		}
	}
}

// TestHubHealth_FollowsTheOverlay: the report is of the configuration this
// hub runs under — its own overlay merged over config.yaml — and says so.
func TestHubHealth_FollowsTheOverlay(t *testing.T) {
	port := pickFreePort(t) // nothing listens there: ui.exposure predicts
	srv, ts := hubHealthServer(t, func(s *Server) { s.Port = port })
	writeHubConfig(t, config.ConfigPath(srv.WorkDir), "executors:\n  allow_host_process: true\n")
	writeHubConfig(t, config.UIInstanceConfigPath(srv.WorkDir, port), "executors:\n  allow_host_process: false\n")
	_, rep, body := getHubHealth(t, nil, ts.URL, "")
	if !rep.StrictMode {
		t.Errorf("the overlay's allow_host_process: false was not read: %s", body)
	}
	if f := findingsByCheck(rep)["policy.host_execution"]; len(f) != 1 || f[0].Severity != "pass" {
		t.Errorf("policy.host_execution = %+v, want the overlay's strict mode", f)
	}
	want := []string{".cloop/config.yaml", fmt.Sprintf(".cloop/config.ui-%d.yaml", port)}
	if strings.Join(rep.Config.Files, " ") != strings.Join(want, " ") {
		t.Errorf("config files = %v, want %v", rep.Config.Files, want)
	}
	if rep.Member.Port != port {
		t.Errorf("member port = %d, want %d", rep.Member.Port, port)
	}
	for _, n := range rep.NotRun {
		if !strings.HasSuffix(n.Command, fmt.Sprintf("--port %d", port)) {
			t.Errorf("%q does not name this hub's port", n.Command)
		}
	}
}

// healthProbeExecutor counts the liveness probes made of it directly.
type healthProbeExecutor struct {
	stubExecutor
	id     string
	probes atomic.Int32
}

func (e *healthProbeExecutor) ID() string { return e.id }
func (e *healthProbeExecutor) HealthCheck(context.Context) error {
	e.probes.Add(1)
	return nil
}

// TestHubHealth_ExecutorsFromTheSupervisorsRecord: the report's liveness
// verdicts are what the hub's executor supervisor last recorded, which every
// member shares, so a report probes nothing it has a record of — and asks,
// once, only an executor nobody has probed yet.
func TestHubHealth_ExecutorsFromTheSupervisorsRecord(t *testing.T) {
	srv, ts := hubHealthServer(t, nil)
	nonce := time.Now().UnixNano()
	recorded := &healthProbeExecutor{id: fmt.Sprintf("hh-recorded-%d", nonce)}
	unrecorded := &healthProbeExecutor{id: fmt.Sprintf("hh-unrecorded-%d", nonce)}
	for _, ex := range []*healthProbeExecutor{recorded, unrecorded} {
		if err := executor.DefaultRegistry.Ensure(ex); err != nil {
			t.Fatal(err)
		}
		id := ex.id
		t.Cleanup(func() { executor.DefaultRegistry.Unregister(id) })
	}
	db, err := statedb.Open(state.DBPath(srv.WorkDir))
	if err != nil {
		t.Fatal(err)
	}
	sched, err := executorstore.NewScheduler(db)
	if err != nil {
		t.Fatal(err)
	}
	if err := sched.SaveHealth(executor.Health{ExecutorID: recorded.id, State: executor.NodeDegraded,
		Reason: "device asleep", ConsecutiveFailures: 2, LastProbe: time.Now()}); err != nil {
		t.Fatal(err)
	}
	_ = db.Close()

	_, rep, body := getHubHealth(t, nil, ts.URL, "")
	byTitle := map[string]hubHealthFinding{}
	for _, f := range findingsByCheck(rep)["executors.health"] {
		byTitle[f.Title] = f
	}
	r, ok := byTitle["Executor "+recorded.id]
	if !ok || r.Severity != "warn" || !strings.Contains(r.Message, "device asleep") ||
		!strings.HasPrefix(fmt.Sprint(r.Details["probed"]), "as the hub's supervisor last probed it") {
		t.Errorf("the recorded executor = %+v: %s", r, body)
	}
	if recorded.probes.Load() != 0 {
		t.Errorf("an executor the supervisor has a record of was probed %d time(s)", recorded.probes.Load())
	}
	u, ok := byTitle["Executor "+unrecorded.id]
	if !ok || u.Severity != "pass" || !strings.HasPrefix(fmt.Sprint(u.Details["probed"]), "probed now") ||
		unrecorded.probes.Load() != 1 {
		t.Errorf("the unrecorded executor = %+v after %d probe(s), want one probe now", u, unrecorded.probes.Load())
	}
}

// TestHubHealth_NothingSecretReachesTheResponse: credentials in the hub's
// configuration and environment — in URLs, as values, in an error a check
// quotes — never reach the response in any encoding, and markup a name
// carries arrives only as escaped text.
func TestHubHealth_NothingSecretReachesTheResponse(t *testing.T) {
	const (
		issuerPass   = "issuer-password-Zq81w"
		externalPass = "external-password-Kp42x"
		proxyPass    = "gitproxy-password-Rt77c"
		clientSecret = "client-secret-value-Jm93b"
		apiKey       = "anthropic-config-key-Vn55d"
		ghToken      = "github-config-token-Hs61e"
		webhookPath  = "/services/T0000/B0000/webhook-path-secret-Lw28f"
		envSecret    = "environment-secret-Pc14g"
		headerValue  = "header-bearer-value-Qa39h"
	)
	markup := `<img src=x onerror="window.__xss=1">`
	t.Setenv("CLOOP_TEST_HEALTH_TOKEN", envSecret)
	secrets := []string{issuerPass, externalPass, proxyPass, clientSecret, apiKey, ghToken, webhookPath,
		envSecret, headerValue}

	srv, ts := hubHealthServer(t, func(s *Server) {
		// A check that quotes what it was given, the way an error from three
		// packages down does: every secret, plain and in a URL, in its
		// message, its remedy and nested details.
		s.hubHealth.extra = []hubdoctor.Check{{ID: "test.echo", Title: "Echoes " + markup,
			Run: func(_ context.Context, add func(hubdoctor.Finding)) {
				plain := strings.Join(secrets, " ")
				add(hubdoctor.Finding{Check: "test.echo", Title: "Quotes " + markup, Severity: hubdoctor.SeverityFail,
					Message:     "saw " + plain + " at https://operator:" + issuerPass + "@idp.example.com/x " + markup,
					Remediation: "set it to " + clientSecret + " " + markup,
					Details: map[string]any{
						"plain": plain, "list": []string{apiKey, "https://u:" + proxyPass + "@h.example"},
						"nested": map[string]any{envSecret: headerValue, "markup": markup},
					}})
			}}}
	})
	writeHubConfig(t, config.ConfigPath(srv.WorkDir), `
anthropic:
  api_key: `+apiKey+`
github:
  token: `+ghToken+`
webhook:
  url: https://hooks.slack.com`+webhookPath+`
  headers:
    Authorization: `+headerValue+`
ui:
  external_url: https://ops:`+externalPass+`@hub.example.com
  oidc:
    enabled: true
    issuer: https://admin:`+issuerPass+`@idp.example.invalid/realms/`+url.PathEscape(markup)+`
    client_id: cloop
    client_secret: `+clientSecret+`
    redirect_url: https://hub.example.com/auth/callback
executors:
  git_proxy:
    enabled: true
    advertise_url: https://proxy:`+proxyPass+`@proxy.example.invalid:9443
`)
	code, rep, body := getHubHealth(t, nil, ts.URL, "")
	if code != http.StatusOK {
		t.Fatalf("GET /api/hub/health = %d: %s", code, body)
	}
	if len(findingsByCheck(rep)["test.echo"]) != 1 || len(findingsByCheck(rep)["oidc.enabled"]) == 0 {
		t.Fatalf("the hostile configuration was not diagnosed: %s", body)
	}
	for _, s := range secrets {
		for _, enc := range []string{s, url.QueryEscape(s), url.PathEscape(s), base64.StdEncoding.EncodeToString([]byte(s))} {
			if strings.Contains(body, enc) {
				t.Errorf("the response carries a secret (%q as %q)", s, enc)
			}
		}
	}
	if !strings.Contains(body, "[redacted]") {
		t.Error("nothing was redacted, so this test proves nothing about the redaction")
	}
	if strings.ContainsAny(body, "<>") {
		t.Error("markup reached the response unescaped")
	}
	echo := findingsByCheck(rep)["test.echo"][0]
	if !strings.Contains(echo.Title, markup) || !strings.Contains(echo.Message, markup) {
		t.Errorf("a name's markup was mangled rather than carried as text: %+v", echo)
	}
	// The redacted URL keeps what is not a secret.
	if !strings.Contains(echo.Message, "@idp.example.com/x") {
		t.Errorf("redaction took more than the credential: %q", echo.Message)
	}
}

// TestHubSecretValues: the exact half of the redaction knows the
// configuration's credentials and the environment's, and leaves the names
// and paths that only point at one.
func TestHubSecretValues(t *testing.T) {
	cfg := config.Default()
	cfg.UI.OIDC.ClientSecret = "oidc-client-secret-1"
	cfg.Anthropic.APIKey = "anthropic-api-key-1"
	cfg.UI.OIDC.Issuer = "https://idp.example.com/not-a-secret"
	env := []string{
		"CLOOP_SECRET_KEY=root-key-value-1", "CLOOP_SECRET_KEY_PREVIOUS=root-key-value-0",
		"GITHUB_TOKEN=github-env-token-1", "DB_PASSWORD=db-password-value",
		"CLOOP_SECRET_KEY_FILE=/etc/cloop/key-path", "HOME=/home/cloop-user", "PATH=/usr/bin:/bin",
	}
	got := strings.Join(hubSecretValues(cfg, nil, env), "\n")
	for _, want := range []string{"oidc-client-secret-1", "anthropic-api-key-1", "root-key-value-1",
		"root-key-value-0", "github-env-token-1", "db-password-value"} {
		if !strings.Contains(got, want) {
			t.Errorf("%q is not among the values redacted", want)
		}
	}
	for _, not := range []string{"/etc/cloop/key-path", "/home/cloop-user", "https://idp.example.com/not-a-secret"} {
		if strings.Contains(got, not) {
			t.Errorf("%q, which is not a credential, would be redacted", not)
		}
	}
}

// TestHubHealthDocAnchorsExist: every finding links somewhere that exists —
// each group's anchor is on the runbook page — and every check id the doctor
// emits belongs to a group, so a new group of checks is documented before it
// is linked to the section's top.
func TestHubHealthDocAnchorsExist(t *testing.T) {
	page, err := os.ReadFile(filepath.Join("..", "..", "docs", "operations", "runbook.md"))
	if err != nil {
		t.Fatalf("read the runbook: %v", err)
	}
	anchors := map[string]bool{}
	for _, m := range regexp.MustCompile(`id="([a-z0-9_-]+)"`).FindAllStringSubmatch(string(page), -1) {
		anchors[m[1]] = true
	}
	for _, line := range strings.Split(string(page), "\n") {
		if !strings.HasPrefix(line, "#") {
			continue
		}
		var slug strings.Builder
		for _, r := range strings.ToLower(strings.TrimSpace(strings.TrimLeft(line, "#"))) {
			switch {
			case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '_', r == '-':
				slug.WriteRune(r)
			case r == ' ':
				slug.WriteRune('-')
			}
		}
		anchors[slug.String()] = true
	}
	need := []string{hubHealthDocsFallback}
	for _, d := range hubHealthDocAnchors {
		need = append(need, d.anchor)
	}
	for _, a := range need {
		if !anchors[a] {
			t.Errorf("findings link to #%s, which docs/operations/runbook.md does not have", a)
		}
	}

	srcs, err := filepath.Glob(filepath.Join("..", "hubdoctor", "*.go"))
	if err != nil || len(srcs) == 0 {
		t.Fatalf("no hubdoctor sources: %v", err)
	}
	id := regexp.MustCompile(`(?:Check:\s*|[Cc]heck(?:, title)?\s*=\s*|Check[A-Za-z]*\s*=\s*)"([a-z_]+(?:\.[a-z0-9_]+)+)"`)
	seen := 0
	for _, p := range srcs {
		if strings.HasSuffix(p, "_test.go") {
			continue
		}
		src, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range id.FindAllStringSubmatch(string(src), -1) {
			seen++
			if u := hubHealthDocsURL(m[1]); strings.HasSuffix(u, "#"+hubHealthDocsFallback) {
				t.Errorf("%s emits %s, whose group has no documentation anchor in hubHealthDocAnchors", filepath.Base(p), m[1])
			}
		}
	}
	if seen < 80 {
		t.Fatalf("found only %d check ids in pkg/hubdoctor; the pattern has drifted and this gate has gone vacuous", seen)
	}
}
