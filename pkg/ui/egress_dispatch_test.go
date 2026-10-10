package ui

// Tests for the hub-hosted egress proxy and the session each run gets on it
// (Task 20378): which runs get one, what they are told, how long it lasts, how
// it ends, and what is never written down.

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/internal/statedbtest"
	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/egressbroker"
	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/redact"
	"github.com/blechschmidt/cloop/pkg/sandbox"
	"github.com/blechschmidt/cloop/pkg/secretbroker"
	"github.com/blechschmidt/cloop/pkg/secretstore"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// ── fixtures ────────────────────────────────────────────────────────────────

// hostEgress starts the hub's egress proxy over a fresh control plane, as
// bootstrapExecutors does, and stops it with the test.
func hostEgress(t *testing.T, mutate func(*config.EgressConfig)) (string, *egressProxyService) {
	t.Helper()
	if svc := activeEgressProxy(); svc != nil {
		t.Fatalf("an egress proxy for %s is still running from an earlier test", svc.dir)
	}
	dir := statedbtest.Dir(t)
	withControlPlaneDir(t, dir)
	cfg := &config.Config{}
	cfg.Executors.Egress = config.EgressConfig{Enabled: true, ListenAddr: "127.0.0.1:0", MaxSessionMinutes: 10}
	if mutate != nil {
		mutate(&cfg.Executors.Egress)
	}
	ensureEgressProxy(cfg, dir, 0)
	t.Cleanup(func() { closeEgressProxy(dir) })
	svc := activeEgressProxy()
	if svc == nil || svc.dir != dir {
		t.Fatalf("the egress proxy did not start: %s", egressProxyUnavailable())
	}
	return dir, svc
}

// grantEgress issues an egress grant through the hub's own broker.
func grantEgress(t *testing.T, svc *egressProxyService, subject string, mutate func(*egressbroker.GrantRequest)) egressbroker.Grant {
	t.Helper()
	sub, err := secretbroker.ParseSubject(subject)
	if err != nil {
		t.Fatal(err)
	}
	req := egressbroker.GrantRequest{Subject: sub, Hosts: []string{"api.example.com"}, TTL: time.Hour, Actor: "op"}
	if mutate != nil {
		mutate(&req)
	}
	g, err := svc.broker.Grant(context.Background(), req)
	if err != nil {
		t.Fatalf("grant: %v", err)
	}
	return g
}

// egressStub runs nothing. It records the spec each Start was given, and a
// test ends its runs through the embedded metrics stub.
type egressStub struct {
	*metricsStubExecutor
	caps     executor.Capabilities
	posture  *executor.EgressPosture
	protocol int

	specMu sync.Mutex
	specs  []executor.Spec
}

func newEgressStub(id, kind string) *egressStub {
	return &egressStub{
		metricsStubExecutor: newMetricsStub(id, kind, executor.IsolationContainer),
		caps: executor.Capabilities{Isolation: executor.IsolationContainer, NetworkEgress: true,
			SharesHostFilesystem: true},
	}
}

func (e *egressStub) Capabilities() executor.Capabilities { return e.caps }

// Signal takes an interrupt without ending the run, as a real run takes a
// moment to wind down: the session must be closed by the stop itself, not by
// the run's end racing it.
func (e *egressStub) Signal(_ context.Context, _ string, sig executor.Signal) error {
	if !sig.Valid() {
		return fmt.Errorf("bad signal %q", sig)
	}
	return nil
}

func (e *egressStub) Start(ctx context.Context, spec executor.Spec) (executor.Handle, error) {
	e.specMu.Lock()
	e.specs = append(e.specs, spec)
	e.specMu.Unlock()
	return e.metricsStubExecutor.Start(ctx, spec)
}

func (e *egressStub) lastSpec(t *testing.T) executor.Spec {
	t.Helper()
	e.specMu.Lock()
	defer e.specMu.Unlock()
	if len(e.specs) == 0 {
		t.Fatal("the stub was never started")
	}
	return e.specs[len(e.specs)-1]
}

// postured is an egressStub that reports a firewall posture and an agent
// protocol, the way a remote device does.
type postured struct{ *egressStub }

func (p postured) EgressPosture() executor.EgressPosture {
	if p.posture != nil {
		return *p.posture
	}
	return executor.EgressPosture{DeviceID: p.id}
}

func (p postured) ProtocolVersion() int { return p.protocol }

// envOf reads one variable out of an environment, last assignment winning.
func envOf(env []string, name string) (string, bool) {
	val, found := "", false
	for _, kv := range env {
		if k, v, ok := strings.Cut(kv, "="); ok && k == name {
			val, found = v, true
		}
	}
	return val, found
}

// egressRows returns the project's egress journal rows.
func egressRows(t *testing.T, workDir string) []string {
	t.Helper()
	rows, _, err := state.ListEvents(workDir, 0, 500)
	if err != nil {
		return nil
	}
	var out []string
	for _, r := range rows {
		if r.Type == state.EventEgress {
			out = append(out, r.Message)
		}
	}
	return out
}

// waitEgressRow waits for a journal row containing want.
func waitEgressRow(t *testing.T, workDir, want string) string {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		for _, r := range egressRows(t, workDir) {
			if strings.Contains(r, want) {
				return r
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("no egress journal row containing %q; rows:\n%s", want, strings.Join(egressRows(t, workDir), "\n"))
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// controlAudit returns the control plane's audit rows of one action.
func controlAudit(t *testing.T, dir string, action secretbroker.Action) []statedb.AuditEvent {
	t.Helper()
	db, err := statedb.Open(state.DBPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	rows, _, err := db.ListAuditEvents(statedb.AuditFilter{EventType: string(action)})
	if err != nil {
		t.Fatal(err)
	}
	return rows
}

// proxyClient is an HTTP client that goes through the proxy a workload's
// environment names, the way a harness honouring HTTPS_PROXY would.
func proxyClient(t *testing.T, env []string) *http.Client {
	t.Helper()
	raw, ok := envOf(env, "HTTP_PROXY")
	if !ok {
		t.Fatal("the workload's environment names no proxy")
	}
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	c := &http.Client{
		Transport: &http.Transport{Proxy: http.ProxyURL(u), DisableKeepAlives: true},
		Timeout:   10 * time.Second,
	}
	t.Cleanup(c.CloseIdleConnections)
	return c
}

// ── which runs get a session ────────────────────────────────────────────────

// TestEgressSessionOnlyForAMatchingActiveGrant: a project holding an active
// grant is issued a session and told how to use it; another project's grant
// gives a run nothing, and says nothing.
func TestEgressSessionOnlyForAMatchingActiveGrant(t *testing.T) {
	_, svc := hostEgress(t, nil)
	holder, other := statedbtest.Dir(t), statedbtest.Dir(t)
	g := grantEgress(t, svc, "project:"+holder, nil)
	ex := newEgressStub("egress-local", executor.KindLocalProcess)

	// Another project's grant never matches.
	spec, egr, err := applyEgressSession(executor.Spec{Env: []string{"PATH=/bin"}}, ex, other, nil,
		egressRun{runID: "run-other"})
	if err != nil || egr != nil {
		t.Fatalf("a project holding no grant = %v, %v; want no session", egr, err)
	}
	if _, ok := envOf(spec.Env, "HTTPS_PROXY"); ok || spec.EgressProxy != nil {
		t.Fatalf("a project holding no grant was given a proxy: %v", spec.Env)
	}
	if rows := egressRows(t, other); len(rows) != 0 {
		t.Errorf("a project that holds no grant was journaled about egress: %v", rows)
	}

	spec, egr, err = applyEgressSession(executor.Spec{Env: []string{"PATH=/bin"}}, ex, holder, nil,
		egressRun{runID: "run-1", identity: "alice"})
	if err != nil || egr == nil {
		t.Fatalf("the grant holder = %v, %v; want a session", egr, err)
	}
	t.Cleanup(func() { egr.close("test over") })

	proxyURL, _ := envOf(spec.Env, "HTTPS_PROXY")
	want := fmt.Sprintf("@127.0.0.1:%d", svc.bound.Port)
	if !strings.HasPrefix(proxyURL, "http://"+egr.sess.ID+":") || !strings.HasSuffix(proxyURL, want) {
		t.Errorf("HTTPS_PROXY = %q, want the session's credential at the bound address %s", proxyURL, want)
	}
	for _, k := range []string{"HTTP_PROXY", "http_proxy", "https_proxy"} {
		if v, _ := envOf(spec.Env, k); v != proxyURL {
			t.Errorf("%s does not carry the proxy URL", k)
		}
	}
	if v, _ := envOf(spec.Env, "NO_PROXY"); !strings.HasPrefix(v, "localhost,127.0.0.1,::1") {
		t.Errorf("NO_PROXY = %q", v)
	}
	if v, _ := envOf(spec.Env, "PATH"); v != "/bin" {
		t.Errorf("the environment the run already had was lost: PATH=%q", v)
	}
	if spec.EgressProxy == nil || spec.EgressProxy.Host != "127.0.0.1" || spec.EgressProxy.Port != svc.bound.Port {
		t.Errorf("route = %+v", spec.EgressProxy)
	}
	if s := egr.sess; s.GrantID != g.ID || s.ProjectID != holder || s.RunID != "run-1" || s.Actor != "alice" {
		t.Errorf("session issued to %+v", s)
	}
	row := waitEgressRow(t, holder, "issued under the grant "+g.ID)
	if strings.Contains(row, egr.sess.ID) == false || strings.Contains(row, proxyURL) {
		t.Errorf("the issue row should name the session and not carry its URL: %q", row)
	}

	egr.close("the run ended")
	if !egr.sess.Closed() || svc.broker.Session(egr.sess.ID) != nil {
		t.Error("closing the run's egress did not close its session")
	}
	if row := waitEgressRow(t, holder, "closed — the run ended"); !strings.Contains(row, "0 request(s), 0 B up, 0 B down") {
		t.Errorf("the close row should give the session's real counts: %q", row)
	}
}

func TestEgressByteCount(t *testing.T) {
	for n, want := range map[int64]string{0: "0 B", 1023: "1023 B", 1024: "1.0 KiB", 1536: "1.5 KiB",
		5 << 20: "5.0 MiB", 3 << 30: "3.0 GiB"} {
		if got := egressByteCount(n); got != want {
			t.Errorf("egressByteCount(%d) = %q, want %q", n, got, want)
		}
	}
}

// TestEgressSessionForAFeatureIsItsParents: a feature runs under its parent
// project's grants, and a grant made out to the feature's own path is never
// one of them.
func TestEgressSessionForAFeatureIsItsParents(t *testing.T) {
	_, svc := hostEgress(t, nil)
	parent := t.TempDir()
	feature := filepath.Join(parent, ".cloop", "features", "widget")
	if err := os.MkdirAll(feature, 0o755); err != nil {
		t.Fatal(err)
	}
	ex := newEgressStub("egress-feature", executor.KindLocalProcess)

	// A grant to the feature's own path: not a grant to its project.
	grantEgress(t, svc, "project:"+feature, nil)
	if _, egr, err := applyEgressSession(executor.Spec{}, ex, feature, nil, egressRun{runID: "run-f1"}); err != nil || egr != nil {
		egr.close("test")
		t.Fatalf("a grant to the feature's own path = %v, %v; want no session", egr, err)
	}

	g := grantEgress(t, svc, "project:"+parent, nil)
	_, egr, err := applyEgressSession(executor.Spec{}, ex, feature, nil, egressRun{runID: "run-f2"})
	if err != nil || egr == nil {
		t.Fatalf("the parent's grant = %v, %v; want a session", egr, err)
	}
	defer egr.close("test over")
	if egr.sess.GrantID != g.ID || egr.sess.ProjectID != parent {
		t.Errorf("the feature's session stands on %s for %s, want the parent's grant %s", egr.sess.GrantID,
			egr.sess.ProjectID, g.ID)
	}
}

// TestEgressSpentGrantGivesNoSessionAndSaysWhy: a revoked or expired grant
// aimed at a project gives its run no proxy, a journal row naming why, and the
// broker's own denial in the trail.
func TestEgressSpentGrantGivesNoSessionAndSaysWhy(t *testing.T) {
	dir, svc := hostEgress(t, nil)
	ex := newEgressStub("egress-spent", executor.KindLocalProcess)

	revoked := statedbtest.Dir(t)
	g := grantEgress(t, svc, "project:"+revoked, nil)
	if err := svc.broker.Revoke(context.Background(), g.ID, "op"); err != nil {
		t.Fatal(err)
	}
	spec, egr, err := applyEgressSession(executor.Spec{Env: []string{}}, ex, revoked, nil, egressRun{runID: "run-r"})
	if err != nil || egr != nil {
		t.Fatalf("a revoked grant = %v, %v; want no session and no refusal", egr, err)
	}
	if _, ok := envOf(spec.Env, "HTTPS_PROXY"); ok {
		t.Fatal("a revoked grant still produced proxy variables")
	}
	waitEgressRow(t, revoked, "grant revoked at")
	var denied bool
	for _, row := range controlAudit(t, dir, secretbroker.ActionEgressRedeem) {
		if strings.Contains(row.Payload, `"decision":"deny"`) && strings.Contains(row.Payload, g.ID) {
			denied = true
		}
	}
	if !denied {
		t.Error("the refused redemption is not in the audit trail")
	}

	// An expired grant: issued with a TTL that has already run out by the
	// time the run is dispatched.
	expired := statedbtest.Dir(t)
	grantEgress(t, svc, "project:"+expired, func(r *egressbroker.GrantRequest) { r.TTL = 10 * time.Millisecond })
	time.Sleep(30 * time.Millisecond)
	spec, egr, err = applyEgressSession(executor.Spec{Env: []string{}}, ex, expired, nil, egressRun{runID: "run-e"})
	if err != nil || egr != nil {
		t.Fatalf("an expired grant = %v, %v; want no session and no refusal", egr, err)
	}
	if _, ok := envOf(spec.Env, "HTTPS_PROXY"); ok {
		t.Fatal("an expired grant still produced proxy variables")
	}
	waitEgressRow(t, expired, "grant expired at")
}

// TestEgressNamedGrantTheHubCannotServeIsRefused: a .cloop/sandbox.yaml that
// names a grant is refused, with a 409 and a remedy, when the hub has no proxy
// to serve it from or no route to it from the bound executor.
func TestEgressNamedGrantTheHubCannotServeIsRefused(t *testing.T) {
	t.Run("no proxy on the hub", func(t *testing.T) {
		dir := statedbtest.Dir(t)
		withControlPlaneDir(t, dir)
		db, err := statedb.Open(state.DBPath(dir))
		if err != nil {
			t.Fatal(err)
		}
		store, err := secretstore.NewEgressStore(db)
		if err != nil {
			t.Fatal(err)
		}
		b, err := egressbroker.New(store)
		if err != nil {
			t.Fatal(err)
		}
		project := statedbtest.Dir(t)
		sub, _ := secretbroker.ParseSubject("project:" + project)
		g, err := b.Grant(context.Background(), egressbroker.GrantRequest{Subject: sub,
			Hosts: []string{"api.example.com"}, TTL: time.Hour})
		_ = db.Close()
		if err != nil {
			t.Fatal(err)
		}
		writeProjectSandbox(t, project, "capabilities:\n  network: "+g.ID+"\n")

		ex := newEgressStub("egress-none", executor.KindLocalProcess)
		spec, resolved, err := applySandbox(executor.Spec{Argv: []string{"x"}}, ex, project)
		if err != nil {
			t.Fatalf("applySandbox: %v — the project does hold the grant", err)
		}
		_, egr, err := applyEgressSession(spec, ex, project, resolved, egressRun{runID: "run-n"})
		var unservable *egressUnservableError
		if !errors.As(err, &unservable) || egr != nil {
			t.Fatalf("= %v, %v; want egressUnservableError", egr, err)
		}
		rec := httptest.NewRecorder()
		jsonWorkloadErr(rec, err)
		if rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), "sandbox_egress_unavailable") ||
			!strings.Contains(rec.Body.String(), "executors.egress") {
			t.Errorf("rendered = %d %s", rec.Code, rec.Body.String())
		}
	})

	t.Run("no route from the executor", func(t *testing.T) {
		_, svc := hostEgress(t, nil) // bound to loopback
		project := statedbtest.Dir(t)
		g := grantEgress(t, svc, "project:"+project, nil)
		writeProjectSandbox(t, project, "capabilities:\n  network: "+g.ID+"\n")
		ex := newEgressStub("egress-ctr", executor.KindContainer)
		spec, resolved, err := applySandbox(executor.Spec{Argv: []string{"x"}}, ex, project)
		if err != nil {
			t.Fatalf("applySandbox: %v", err)
		}
		_, egr, err := applyEgressSession(spec, ex, project, resolved, egressRun{runID: "run-c"})
		var unservable *egressUnservableError
		if !errors.As(err, &unservable) || egr != nil {
			t.Fatalf("= %v, %v; want egressUnservableError", egr, err)
		}
		if !strings.Contains(unservable.Reason, "loopback") || !strings.Contains(unservable.Remediation(), "0.0.0.0") {
			t.Errorf("refusal = %v", err)
		}
		if n := len(svc.broker.Sessions()); n != 0 {
			t.Errorf("a refused run left %d session(s) behind", n)
		}
	})

	t.Run("an unnamed grant the run cannot use is journaled, not refused", func(t *testing.T) {
		_, svc := hostEgress(t, nil)
		project := statedbtest.Dir(t)
		g := grantEgress(t, svc, "project:"+project, nil)
		ex := newEgressStub("egress-ctr2", executor.KindContainer)
		_, egr, err := applyEgressSession(executor.Spec{}, ex, project, nil, egressRun{runID: "run-c2"})
		if err != nil || egr != nil {
			t.Fatalf("= %v, %v; want neither", egr, err)
		}
		row := waitEgressRow(t, project, "gets no proxy session")
		if !strings.Contains(row, g.ID) || !strings.Contains(row, "loopback") {
			t.Errorf("row = %q", row)
		}
	})

	t.Run("no network to reach the proxy over", func(t *testing.T) {
		_, svc := hostEgress(t, nil)
		project := statedbtest.Dir(t)
		grantEgress(t, svc, "project:"+project, nil)
		ex := newEgressStub("egress-nonet", executor.KindLocalProcess)
		_, egr, err := applyEgressSession(executor.Spec{DisableNetwork: true}, ex, project, nil, egressRun{runID: "run-nn"})
		if err != nil || egr != nil {
			t.Fatalf("= %v, %v", egr, err)
		}
		waitEgressRow(t, project, "the run has no network")
	})
}

// writeProjectSandbox writes a .cloop/sandbox.yaml into an existing project.
func writeProjectSandbox(t *testing.T, project, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(project, ".cloop"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(project, sandbox.FileName), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

// ── routes ──────────────────────────────────────────────────────────────────

// TestEgressRouteForEachExecutorKind: the address a workload is pointed at is
// chosen for where it runs, and a route that cannot work is refused with why.
func TestEgressRouteForEachExecutorKind(t *testing.T) {
	svcAt := func(bound string, advertised string) *egressProxyService {
		host, port, _ := net.SplitHostPort(bound)
		p, _ := strconv.Atoi(port)
		return &egressProxyService{bound: &net.TCPAddr{IP: net.ParseIP(host), Port: p}, advertised: advertised}
	}
	stub := func(kind string) *egressStub { return newEgressStub("route-"+kind, kind) }

	cases := []struct {
		name   string
		svc    *egressProxyService
		ex     executor.Executor
		spec   executor.Spec
		want   executor.EgressProxyRoute
		whyHas string
		fixHas string
	}{
		{name: "host process uses the bound address", svc: svcAt("127.0.0.1:41000", ""),
			ex: stub(executor.KindLocalProcess), want: executor.EgressProxyRoute{Host: "127.0.0.1", Port: 41000}},
		{name: "host process reads an any-address bind as loopback", svc: svcAt("0.0.0.0:41000", ""),
			ex: stub(executor.KindLocalProcess), want: executor.EgressProxyRoute{Host: "127.0.0.1", Port: 41000}},
		{name: "container on an any-address bind is pinned to its gateway", svc: svcAt("0.0.0.0:41000", "hub.example:9"),
			ex:   stub(executor.KindContainer),
			want: executor.EgressProxyRoute{Host: executor.EgressGatewayHost, Port: 41000, Gateway: true}},
		{name: "container cannot reach a loopback bind", svc: svcAt("127.0.0.1:41000", ""),
			ex: stub(executor.KindContainer), whyHas: "loopback", fixHas: "0.0.0.0:41000"},
		{name: "container on one host address dials it", svc: svcAt("172.17.0.1:41000", ""),
			ex: stub(executor.KindContainer), want: executor.EgressProxyRoute{Host: "172.17.0.1", Port: 41000}},
		{name: "kubernetes needs an advertised address", svc: svcAt("0.0.0.0:41000", ""),
			ex: stub(executor.KindKubernetes), whyHas: "advertise_addr is not set", fixHas: "Service"},
		{name: "kubernetes with no filter takes the Service name", svc: svcAt("0.0.0.0:41000", "egress.cloop.svc:8899"),
			ex: stub(executor.KindKubernetes), whyHas: "cluster-internal"},
		{name: "kubernetes with an address", svc: svcAt("0.0.0.0:41000", "10.96.0.20:8899"),
			ex: stub(executor.KindKubernetes), want: executor.EgressProxyRoute{Host: "10.96.0.20", Port: 8899}},
		{name: "kubernetes rules that do not open the proxy", svc: svcAt("0.0.0.0:41000", "10.96.0.20:8899"),
			ex:     stub(executor.KindKubernetes),
			spec:   executor.Spec{EgressRules: &executor.FirewallRules{AllowPublicInternet: true, AllowPorts: []int{443}}},
			whyHas: "drop the proxy", fixHas: "egress_filter"},
		{name: "kubernetes rules that open it", svc: svcAt("0.0.0.0:41000", "10.96.0.20:8899"),
			ex:   stub(executor.KindKubernetes),
			spec: executor.Spec{EgressRules: &executor.FirewallRules{AllowCIDRs: []string{"10.96.0.20/32"}, AllowPorts: []int{8899}}},
			want: executor.EgressProxyRoute{Host: "10.96.0.20", Port: 8899}},
		{name: "a device cannot reach loopback", svc: svcAt("0.0.0.0:41000", "127.0.0.1:41000"),
			ex: postured{stub(executor.KindRemoteAgent)}, whyHas: "a loopback address"},
		{name: "a device cannot reach a container runtime's host alias", svc: svcAt("0.0.0.0:41000", "host.docker.internal:41000"),
			ex: postured{stub(executor.KindRemoteAgent)}, whyHas: "container runtime"},
		{name: "a device reaches the advertised address", svc: svcAt("0.0.0.0:41000", "hub.example.org:41000"),
			ex: postured{stub(executor.KindRemoteAgent)}, want: executor.EgressProxyRoute{Host: "hub.example.org", Port: 41000}},
		{name: "a firewalled device behind an old agent is refused", svc: svcAt("0.0.0.0:41000", "203.0.113.5:41000"),
			ex: func() executor.Executor {
				s := stub(executor.KindRemoteAgent)
				s.protocol = 17
				return postured{s}
			}(),
			spec:   executor.Spec{EgressRules: &executor.FirewallRules{AllowPublicInternet: true}},
			whyHas: "needs v18", fixHas: "",
		},
		{name: "a firewalled device needs an address, not a name", svc: svcAt("0.0.0.0:41000", "hub.example.org:41000"),
			ex: func() executor.Executor {
				s := stub(executor.KindRemoteAgent)
				s.protocol = 18
				return postured{s}
			}(),
			spec:   executor.Spec{EgressRules: &executor.FirewallRules{AllowPublicInternet: true}},
			whyHas: "advertised by name",
		},
		{name: "a firewalled device on a current agent", svc: svcAt("0.0.0.0:41000", "203.0.113.5:41000"),
			ex: func() executor.Executor {
				s := stub(executor.KindRemoteAgent)
				s.protocol = 18
				return postured{s}
			}(),
			spec: executor.Spec{EgressRules: &executor.FirewallRules{AllowPublicInternet: true}},
			want: executor.EgressProxyRoute{Host: "203.0.113.5", Port: 41000}},
		{name: "a device whose sandbox has no network", svc: svcAt("0.0.0.0:41000", "203.0.113.5:41000"),
			ex: func() executor.Executor {
				s := stub(executor.KindRemoteAgent)
				s.posture = &executor.EgressPosture{DeviceID: s.id, Own: &executor.FirewallRules{}, OwnName: "device x's sandbox network"}
				return postured{s}
			}(),
			whyHas: "no network"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, why, fix := c.svc.routeFor(c.ex, c.spec)
			if c.whyHas != "" {
				if !strings.Contains(why, c.whyHas) {
					t.Fatalf("why = %q, want it to mention %q (route %+v)", why, c.whyHas, got)
				}
				if c.fixHas != "" && !strings.Contains(fix, c.fixHas) {
					t.Errorf("remedy = %q, want it to mention %q", fix, c.fixHas)
				}
				return
			}
			if why != "" {
				t.Fatalf("refused: %s (%s)", why, fix)
			}
			if got != c.want {
				t.Fatalf("route = %+v, want %+v", got, c.want)
			}
			if err := got.Validate(); err != nil {
				t.Errorf("the route does not validate: %v", err)
			}
		})
	}
}

// ── redaction ───────────────────────────────────────────────────────────────

// TestEgressProxyURLIsNeverWrittenDown: the session's credential is in the
// workload's environment and nowhere else — scrubbed from captured output,
// left out of the stored spec, absent from the journal and the audit trail.
func TestEgressProxyURLIsNeverWrittenDown(t *testing.T) {
	dir, svc := hostEgress(t, nil)
	project := statedbtest.Dir(t)
	grantEgress(t, svc, "project:"+project, nil)
	ex := newEgressStub("egress-redact", executor.KindLocalProcess)

	// A lease already declared one sensitive variable; the session's are added
	// to the declaration rather than replacing it.
	base := executor.Spec{Argv: []string{"cloop", "run"}, WorkDir: project,
		Env: []string{"GITHUB_TOKEN=ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx", redact.EnvKey + "=GITHUB_TOKEN",
			"HTTPS_PROXY=http://corporate.example:3128"}}
	spec, egr, err := applyEgressSession(base, ex, project, nil, egressRun{runID: "run-x"})
	if err != nil || egr == nil {
		t.Fatalf("= %v, %v", egr, err)
	}
	defer egr.close("test over")
	proxyURL, _ := envOf(spec.Env, "HTTPS_PROXY")
	u, err := url.Parse(proxyURL)
	if err != nil {
		t.Fatal(err)
	}
	token, _ := u.User.Password()
	if len(token) < 32 {
		t.Fatalf("no token in the proxy URL %q", proxyURL)
	}
	n := 0
	for _, kv := range spec.Env {
		if strings.HasPrefix(kv, "HTTPS_PROXY=") {
			n++
		}
	}
	if n != 1 {
		t.Errorf("HTTPS_PROXY assigned %d times; the inherited one should have been replaced", n)
	}
	declared, _ := envOf(spec.Env, redact.EnvKey)
	for _, name := range []string{"GITHUB_TOKEN", "HTTPS_PROXY", "HTTP_PROXY", "https_proxy", "http_proxy"} {
		if !strings.Contains(","+declared+",", ","+name+",") {
			t.Errorf("%s = %q does not declare %s", redact.EnvKey, declared, name)
		}
	}

	// Output the workload prints is scrubbed by the executor's redactor...
	if out := spec.Redactor().String("proxy is " + proxyURL); strings.Contains(out, token) {
		t.Errorf("the executor's redactor leaves the token in %q", out)
	}
	// ...and by the workload's own, from its environment.
	if out := redact.FromEnviron(spec.Env).String("export HTTPS_PROXY=" + proxyURL); strings.Contains(out, token) {
		t.Errorf("the workload's redactor leaves the token in %q", out)
	}

	// The stored dispatch record.
	if id := openSessionFor(dir, ex, executor.Handle{ID: "h-redact", StartedAt: time.Now()}, spec); id == "" {
		t.Fatal("the session record was not written")
	}
	db, err := statedb.Open(state.DBPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	rows, err := db.ListExecutorSessions(ex.ID(), false)
	_ = db.Close()
	if err != nil || len(rows) == 0 {
		t.Fatalf("read the session record: %v (%d rows)", err, len(rows))
	}
	for _, r := range rows {
		if strings.Contains(r.SpecJSON, token) || strings.Contains(r.SpecJSON, "ghp_xxxx") {
			t.Errorf("the stored spec carries a credential: %s", r.SpecJSON)
		}
	}

	// Some traffic, so the trail has request rows to look through.
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "x") }))
	defer origin.Close()
	if resp, err := proxyClient(t, spec.Env).Get(origin.URL); err == nil {
		resp.Body.Close()
	}
	egr.close("the run ended")

	for _, row := range egressRows(t, project) {
		if strings.Contains(row, token) {
			t.Errorf("the journal carries the token: %q", row)
		}
	}
	db, err = statedb.Open(state.DBPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	all, _, err := db.ListAuditEvents(statedb.AuditFilter{})
	if err != nil {
		t.Fatal(err)
	}
	var egressRowsSeen int
	for _, row := range all {
		if strings.HasPrefix(row.EventType, "egress.") {
			egressRowsSeen++
		}
		if strings.Contains(row.Payload, token) {
			t.Errorf("audit row %s carries the token", row.EventType)
		}
	}
	if egressRowsSeen < 3 {
		t.Errorf("only %d egress audit rows; want the redemption, the request and the close", egressRowsSeen)
	}
}

// ── lifetime ────────────────────────────────────────────────────────────────

// TestEgressSessionIsRenewedWhileItsRunLives and is closed, tunnels and all,
// when its grant is revoked — in the dashboard, or from another process.
func TestEgressSessionIsRenewedWhileItsRunLives(t *testing.T) {
	prevTick, prevMargin := egressKeepaliveTick, egressKeepaliveMargin
	egressKeepaliveTick, egressKeepaliveMargin = 20*time.Millisecond, time.Hour
	t.Cleanup(func() { egressKeepaliveTick, egressKeepaliveMargin = prevTick, prevMargin })

	dir, svc := hostEgress(t, func(e *config.EgressConfig) { e.MaxSessionMinutes = 1 })
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { _, _ = io.Copy(c, c); _ = c.Close() }()
		}
	}()
	echoPort := ln.Addr().(*net.TCPAddr).Port

	ex := newEgressStub("egress-keep", executor.KindLocalProcess)
	run := func(project string) (*runEgress, executor.Spec) {
		g := grantEgress(t, svc, "project:"+project, func(r *egressbroker.GrantRequest) {
			r.Hosts, r.CIDRs, r.Ports = nil, []string{"127.0.0.0/8"}, []int{echoPort}
		})
		spec, egr, err := applyEgressSession(executor.Spec{Env: []string{}}, ex, project, nil, egressRun{runID: "run-" + g.ID})
		if err != nil || egr == nil {
			t.Fatalf("= %v, %v", egr, err)
		}
		t.Cleanup(func() { egr.close("test over") })
		return egr, spec
	}

	// Renewed while the run lives.
	project := statedbtest.Dir(t)
	egr, spec := run(project)
	issued := egr.sess.ExpiresAt()
	deadline := time.Now().Add(5 * time.Second)
	for !egr.sess.ExpiresAt().After(issued) {
		if time.Now().After(deadline) {
			t.Fatal("the session was never renewed")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if len(controlAudit(t, dir, secretbroker.ActionEgressRenew)) == 0 {
		t.Error("a renewal was not audited")
	}

	// Revoked from another process — a broker of its own over the same
	// database, as `cloop egress revoke` is — with a tunnel open.
	tunnel := openEgressTunnel(t, spec.Env, echoPort)
	db, err := statedb.Open(state.DBPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	store, _ := secretstore.NewEgressStore(db)
	cli, _ := egressbroker.New(store, egressbroker.WithAuditor(secretstore.NewAuditor(db)))
	if err := cli.Revoke(context.Background(), egr.grantID, "op"); err != nil {
		t.Fatal(err)
	}
	_ = db.Close()
	row := waitEgressRow(t, project, "its egress grant was revoked")
	if !strings.Contains(row, "1 live tunnel(s) were cut") {
		t.Errorf("the revocation row should say the open tunnel was cut: %q", row)
	}
	_ = tunnel.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := tunnel.Read(make([]byte, 1)); err == nil {
		t.Error("the tunnel outlived the revocation")
	}

	// Revoked in the dashboard: the hosted broker closes it on the spot.
	//
	// This run's keepalive must not tick while that happens. Revoke stamps the
	// grant revoked in the store and only then closes its sessions, and a
	// keepalive tick landing in between re-reads the grant, finds it revoked
	// and closes the session itself — "its egress grant was revoked" instead
	// of the hosted broker's "grant revoked", which is what this half proves.
	// It happened on a loaded CI runner. The keepalive reads the tick once,
	// when it starts, so the first run above keeps its 20 ms.
	egressKeepaliveTick = time.Hour
	project2 := statedbtest.Dir(t)
	egr2, spec2 := run(project2)
	tunnel2 := openEgressTunnel(t, spec2.Env, echoPort)
	bs, err := openBrokersAt(dir)
	if err != nil {
		t.Fatal(err)
	}
	if bs.egress != svc.broker {
		t.Error("the grants API does not revoke through the broker that holds the sessions")
	}
	if err := bs.egress.Revoke(context.Background(), egr2.grantID, "admin"); err != nil {
		t.Fatal(err)
	}
	bs.close()
	if !egr2.sess.Closed() {
		t.Error("a revocation through the hosted broker did not close the session at once")
	}
	row = waitEgressRow(t, project2, "closed — grant revoked")
	if !strings.Contains(row, "1 live tunnel(s) were cut") {
		t.Errorf("row = %q", row)
	}
	_ = tunnel2.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := tunnel2.Read(make([]byte, 1)); err == nil {
		t.Error("the tunnel outlived the revocation")
	}
}

// openEgressTunnel opens a CONNECT tunnel to the echo server through the
// proxy a workload's environment names, and proves it carries bytes.
func openEgressTunnel(t *testing.T, env []string, port int) net.Conn {
	t.Helper()
	raw, _ := envOf(env, "HTTPS_PROXY")
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	pass, _ := u.User.Password()
	conn, err := net.Dial("tcp", u.Host)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	target := fmt.Sprintf("127.0.0.1:%d", port)
	fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\nProxy-Authorization: %s\r\n\r\n",
		target, target, egressbroker.FormatProxyCredential(u.User.Username(), pass))
	br := bufio.NewReader(conn)
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	status, err := br.ReadString('\n')
	if err != nil || !strings.Contains(status, "200") {
		t.Fatalf("CONNECT = %q, %v", status, err)
	}
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			t.Fatal(err)
		}
		if strings.TrimSpace(line) == "" {
			break
		}
	}
	if _, err := conn.Write([]byte("hi")); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, 2)
	if _, err := io.ReadFull(br, got); err != nil || string(got) != "hi" {
		t.Fatalf("echo = %q, %v", got, err)
	}
	_ = conn.SetReadDeadline(time.Time{})
	return conn
}

// TestEgressSessionEndsWithItsRun: dispatched through the real start path, the
// session is closed when the workload ends, when the run is stopped, and when
// a run that never started gives it back.
func TestEgressSessionEndsWithItsRun(t *testing.T) {
	_, svc := hostEgress(t, nil)
	stub := newEgressStub("egress-run", executor.KindLocalProcess)
	registerStub(t, stub)

	start := func(project string) *runEgress {
		t.Helper()
		if err := executor.Bind(project, stub.ID()); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { executor.DefaultRegistry.Unbind(project) })
		_, handle, err := startWorkloadAs(nil, nil, "bob", project, []string{"cloop", "run"}, nil)
		if err != nil {
			t.Fatalf("start: %v", err)
		}
		// Every run ends with the test, so the watchers the dispatch started
		// for it — the exit watch, the session record's — end too.
		t.Cleanup(func() { stub.finish(handle.ID, 0, time.Second) })
		egr := liveEgress.byHandle(handle.ID)
		if egr == nil {
			t.Fatal("the dispatched run holds no egress session")
		}
		if _, ok := envOf(stub.lastSpec(t).Env, "HTTPS_PROXY"); !ok {
			t.Fatal("the dispatched spec carries no proxy")
		}
		if egr.sess.Actor != "bob" {
			t.Errorf("the session is issued to %q, want the run's user", egr.sess.Actor)
		}
		return egr
	}

	// The workload ends: the exit watcher closes the session.
	finished := statedbtest.Dir(t)
	grantEgress(t, svc, "project:"+finished, nil)
	egr := start(finished)
	stub.finish(stub.latest(), 0, time.Second)
	waitEgressRow(t, finished, "closed — the run ended")
	if !egr.sess.Closed() {
		t.Error("the session outlived its run")
	}

	// The run is stopped: closed the moment the interrupt is delivered.
	stopped := statedbtest.Dir(t)
	grantEgress(t, svc, "project:"+stopped, nil)
	egr = start(stopped)
	s := &Server{WorkDir: stopped}
	s.trackRunWithCancel(stopped, stub, stub.latest(), func() {})
	if d := s.interruptRun(stopped); d.Signalled == 0 {
		t.Fatalf("the stop was not delivered: %+v", d)
	}
	waitEgressRow(t, stopped, "closed — the run was stopped")
	if !egr.sess.Closed() {
		t.Error("a stopped run kept its session")
	}

	// runEnded closes it too — the path a run adopted from another member
	// settles through, where no exit watcher of this process is running.
	ended := statedbtest.Dir(t)
	grantEgress(t, svc, "project:"+ended, nil)
	egr = start(ended)
	(&Server{WorkDir: ended}).runEnded(ended, stub, stub.latest())
	if !egr.sess.Closed() {
		t.Error("runEnded left the session open")
	}

	// A run that does not start gives its session back.
	refused := statedbtest.Dir(t)
	grantEgress(t, svc, "project:"+refused, nil)
	if err := executor.Bind(refused, stub.ID()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { executor.DefaultRegistry.Unbind(refused) })
	stub.startErr = errors.New("engine unavailable")
	defer func() { stub.startErr = nil }()
	before := len(svc.broker.Sessions())
	if _, _, err := startWorkloadAs(nil, nil, "", refused, []string{"cloop", "run"}, nil); err == nil {
		t.Fatal("the start should have failed")
	}
	if after := len(svc.broker.Sessions()); after != before {
		t.Errorf("a run that never started left %d session(s) open", after-before)
	}
	waitEgressRow(t, refused, "closed — the run did not start")
}

// ── the proxy's own lifecycle ───────────────────────────────────────────────

// TestHostedEgressProxyBindsRecordsAndShutsDown: the proxy binds where the
// configuration says, records it for `cloop hub doctor`, and on shutdown
// closes its listener and its sessions, clears its record, and leaves no
// goroutine behind.
func TestHostedEgressProxyBindsRecordsAndShutsDown(t *testing.T) {
	baseline := egressGoroutines()

	dir := statedbtest.Dir(t)
	withControlPlaneDir(t, dir)
	cfg := &config.Config{}
	cfg.Executors.Egress = config.EgressConfig{Enabled: true, ListenAddr: "127.0.0.1:0",
		AdvertiseAddr: "hub.example.org", DefaultMaxBytesDown: "1m"}
	ensureEgressProxy(cfg, dir, 4242)
	svc := activeEgressProxy()
	if svc == nil {
		t.Fatalf("not started: %s", egressProxyUnavailable())
	}
	addr := svc.bound.String()
	if want := "hub.example.org:" + strconv.Itoa(svc.bound.Port); svc.defaultEndpoint() != want {
		t.Errorf("advertised as %s, want the bare host with the bound port, %s", svc.defaultEndpoint(), want)
	}
	if c, err := net.Dial("tcp", addr); err != nil {
		t.Fatalf("nothing listens on %s: %v", addr, err)
	} else {
		_ = c.Close()
	}
	st := readEgressStatus(t, dir)
	if len(st) != 1 || st[0].Listening != addr || st[0].Advertised != svc.defaultEndpoint() ||
		st[0].HubPort != 4242 || st[0].PID != os.Getpid() || st[0].Error != "" {
		t.Fatalf("recorded status = %+v", st)
	}

	// A session with a tunnel, so shutdown has something to close.
	project := statedbtest.Dir(t)
	grantEgress(t, svc, "project:"+project, nil)
	_, egr, err := applyEgressSession(executor.Spec{Env: []string{}}, newEgressStub("egress-life", executor.KindLocalProcess),
		project, nil, egressRun{runID: "run-life"})
	if err != nil || egr == nil {
		t.Fatalf("= %v, %v", egr, err)
	}
	if egr.sess.Grant.MaxBytesDown != 1<<20 {
		t.Errorf("the session's download quota is %d; the configured default is 1m", egr.sess.Grant.MaxBytesDown)
	}

	closeEgressProxy(dir)
	if activeEgressProxy() != nil {
		t.Fatal("the proxy is still registered")
	}
	if !egr.sess.Closed() {
		t.Error("shutdown left a session open")
	}
	waitEgressRow(t, project, "closed — the hub is shutting down")
	if c, err := net.DialTimeout("tcp", addr, time.Second); err == nil {
		_ = c.Close()
		t.Errorf("%s still accepts connections after shutdown", addr)
	}
	if st := readEgressStatus(t, dir); len(st) != 0 {
		t.Errorf("shutdown left the status row: %+v", st)
	}

	deadline := time.Now().Add(5 * time.Second)
	for {
		n := egressGoroutines()
		if len(n) <= len(baseline) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("%d egress goroutines before, %d after shutdown:\n%s", len(baseline), len(n),
				strings.Join(n, "\n\n"))
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// egressGoroutines returns the stacks of the goroutines the egress proxy and
// its sessions run — the server, the reaper, tunnels, a request's deadline
// watcher, a run's keepalive. Counting these rather than every goroutine
// keeps the leak check about this code: the rest of the package's tests leave
// timers and watchers of their own running.
func egressGoroutines() []string {
	buf := make([]byte, 4<<20)
	all := strings.Split(string(buf[:runtime.Stack(buf, true)]), "\n\n")
	var out []string
	for _, g := range all {
		if strings.Contains(g, "pkg/egressbroker.") || strings.Contains(g, "pkg/ui.(*runEgress)") ||
			strings.Contains(g, "pkg/ui.startEgressProxy") {
			out = append(out, g)
		}
	}
	return out
}

// TestHostedEgressProxyBindFailureIsReportedNotFatal: a listen address that is
// taken leaves the hub up, the reason recorded, and runs that need the proxy
// refused with it.
func TestHostedEgressProxyBindFailureIsReportedNotFatal(t *testing.T) {
	taken, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer taken.Close()

	dir := statedbtest.Dir(t)
	withControlPlaneDir(t, dir)
	cfg := &config.Config{}
	cfg.Executors.Egress = config.EgressConfig{Enabled: true, ListenAddr: taken.Addr().String()}
	ensureEgressProxy(cfg, dir, 4243)
	if activeEgressProxy() != nil {
		closeEgressProxy("")
		t.Fatal("the proxy claims to have bound an address in use")
	}
	t.Cleanup(func() {
		egressProxyWanted.Store(false)
		egressProxyFailure.Store(nil)
	})
	why := egressProxyUnavailable()
	if !strings.Contains(why, "bind executors.egress.listen_addr "+taken.Addr().String()) {
		t.Errorf("unavailable because %q", why)
	}
	st := readEgressStatus(t, dir)
	if len(st) != 1 || !strings.Contains(st[0].Error, "address already in use") {
		t.Errorf("recorded status = %+v", st)
	}
}

// readEgressStatus reads every recorded egress proxy status in dir.
func readEgressStatus(t *testing.T, dir string) []egressbroker.HostedStatus {
	t.Helper()
	_, rows, err := statedb.PeekHubCluster(state.DBPath(dir), egressbroker.HostedStatusKind)
	if err != nil {
		t.Fatal(err)
	}
	var out []egressbroker.HostedStatus
	for _, r := range rows {
		var st egressbroker.HostedStatus
		if err := json.Unmarshal([]byte(r.Meta), &st); err != nil {
			t.Fatalf("status row %s: %v", r.Key, err)
		}
		out = append(out, st)
	}
	return out
}

// ── metrics ─────────────────────────────────────────────────────────────────

// TestEgressFamiliesCarrySamplesThroughTheHub: once the hub hosts the proxy,
// the egress families a scrape exports move with a dispatched run's traffic.
func TestEgressFamiliesCarrySamplesThroughTheHub(t *testing.T) {
	_, svc := hostEgress(t, nil)
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "the origin answered")
	}))
	defer origin.Close()
	port, _ := strconv.Atoi(strings.TrimPrefix(origin.URL[strings.LastIndex(origin.URL, ":"):], ":"))

	project := statedbtest.Dir(t)
	grantEgress(t, svc, "project:"+project, func(r *egressbroker.GrantRequest) {
		r.Hosts, r.CIDRs, r.Ports = []string{"127.0.0.1"}, []string{"127.0.0.0/8"}, []int{port}
	})
	srv := &Server{WorkDir: project}
	before := srv.gatherMetrics()

	spec, egr, err := applyEgressSession(executor.Spec{Env: []string{}}, newEgressStub("egress-metrics",
		executor.KindLocalProcess), project, nil, egressRun{runID: "run-m"})
	if err != nil || egr == nil {
		t.Fatalf("= %v, %v", egr, err)
	}
	defer egr.close("test over")
	client := proxyClient(t, spec.Env)
	resp, err := client.Get(origin.URL)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	// A host the grant does not name.
	if resp, err := client.Get(fmt.Sprintf("http://127.0.0.1:%d/", port+1)); err == nil {
		resp.Body.Close()
	}

	allowed := series("cloop_egress_requests_total", "result", "allowed")
	denied := series("cloop_egress_requests_total", "result", "denied")
	down := series("cloop_egress_bytes_total", "direction", "down")
	var after string
	deadline := time.Now().Add(10 * time.Second)
	for {
		after = srv.gatherMetrics()
		if value(after, allowed) > value(before, allowed) && value(after, denied) > value(before, denied) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the egress families did not move:\n%s", after)
		}
		time.Sleep(20 * time.Millisecond)
	}
	if value(after, down) <= value(before, down) {
		t.Errorf("%s did not move", down)
	}
	if got := value(after, "cloop_egress_sessions_live"); got < 1 {
		t.Errorf("cloop_egress_sessions_live = %v with a session open", got)
	}
	if value(after, series("cloop_egress_denials_total", "reason", "port_not_allowed")) <=
		value(before, series("cloop_egress_denials_total", "reason", "port_not_allowed")) {
		t.Errorf("the refused request is not in cloop_egress_denials_total")
	}
}
