package ui

import (
	"bytes"
	"context"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/auditaction"
	"github.com/blechschmidt/cloop/pkg/auditforward"
	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/secretbroker"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// forwardCollector is an HTTPS NDJSON collector for the hub's audit sink.
type forwardCollector struct {
	srv   *httptest.Server
	mu    sync.Mutex
	lines []string
	auth  map[string]bool
}

func newForwardCollector(t *testing.T) *forwardCollector {
	t.Helper()
	c := &forwardCollector{auth: map[string]bool{}}
	c.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		c.mu.Lock()
		defer c.mu.Unlock()
		c.auth[r.Header.Get("Authorization")] = true
		for _, l := range bytes.Split(bytes.TrimSpace(body), []byte("\n")) {
			if len(l) > 0 {
				c.lines = append(c.lines, string(l))
			}
		}
	}))
	t.Cleanup(c.srv.Close)
	return c
}

func (c *forwardCollector) caFile(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.srv.Certificate().Raw}), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func (c *forwardCollector) verdict(t *testing.T) auditforward.StreamReport {
	t.Helper()
	c.mu.Lock()
	stream := strings.Join(c.lines, "\n")
	c.mu.Unlock()
	rep, err := auditforward.VerifyStream(strings.NewReader(stream))
	if err != nil {
		t.Fatal(err)
	}
	return rep
}

// forwardingCluster is a two-member cluster forwarding its control plane to a
// collector, with the token the sink presents in the hub's secret store.
func forwardingCluster(t *testing.T, hooks func(m *clusterMember) auditforward.Hooks) (dir string, a, b *clusterMember, c *forwardCollector) {
	t.Helper()
	t.Setenv(secretbroker.EnvPassphraseKey, "audit-forward-cluster-passphrase")
	dir, a, b = clusterPair(t)
	c = newForwardCollector(t)

	bs, err := openBrokersAt(dir)
	if err != nil {
		t.Fatal(err)
	}
	if bs.secret == nil {
		bs.close()
		t.Fatalf("no secret broker: %s", bs.status.Reason)
	}
	if _, err := bs.secret.Mint(context.Background(), secretbroker.MintRequest{
		Name: "collector-token", Kind: secretbroker.KindEnv, Payload: []byte("tok-from-the-store"), Actor: "admin",
	}); err != nil {
		bs.close()
		t.Fatal(err)
	}
	bs.close()

	cfg, err := config.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Audit.Forward = config.AuditForwardConfig{Sinks: []config.AuditForwardSink{{
		Name: "siem", Type: config.AuditSinkHTTPS, URL: c.srv.URL + "/ingest", CAFile: c.caFile(t),
		TokenSecret: "collector-token", BatchSize: 5,
	}}}
	if err := config.Save(dir, cfg); err != nil {
		t.Fatal(err)
	}
	for _, m := range []*clusterMember{a, b} {
		m.srv.auditForward.poll = 20 * time.Millisecond
		m.srv.auditForward.configPoll = 50 * time.Millisecond
		if hooks != nil {
			m.srv.auditForward.hooks = hooks(m)
		}
		m.srv.runLeaderDuty(context.Background(), "audit-forward", m.srv.watchAuditForward)
	}
	return dir, a, b, c
}

func appendHubRows(t *testing.T, dir string, n int) {
	t.Helper()
	db, err := statedb.Open(state.DBPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	db = db.AsControlPlane()
	for i := 0; i < n; i++ {
		var ev statedb.AuditEvent
		ev.Actor, ev.EventType, ev.EntityType = "admin", string(auditaction.ActionExecutorCordon), "executor"
		if err := db.AppendAuditEvent(&ev); err != nil {
			t.Fatal(err)
		}
	}
}

func hubHead(t *testing.T, dir string) int64 {
	t.Helper()
	db, err := statedb.Open(state.DBPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	id, err := db.MaxAuditID()
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func hubCursor(t *testing.T, dir string) int64 {
	t.Helper()
	db, err := statedb.Open(state.DBPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	cp, _ := filepath.Abs(state.DBPath(dir))
	c, _, err := db.AuditForwardCursorFor("siem", cp)
	if err != nil {
		t.Fatal(err)
	}
	return c.AckedID
}

// A hub cluster forwards each row once per sink, not once per member: the
// duty runs on the leader alone. The sink presents the token the hub's secret
// store holds, and the leader exports the sink's lag and backlog while a
// follower exports neither (Task 20426).
func TestAuditForwardRunsOnTheClusterLeaderAlone(t *testing.T) {
	dir, a, b, c := forwardingCluster(t, nil)
	appendHubRows(t, dir, 12)
	waitCluster(t, "the leader to forward the chain", func() bool {
		return hubHead(t, dir) > 0 && hubCursor(t, dir) == hubHead(t, dir)
	})
	// Give a second forwarder, were one running, time to send it all again.
	time.Sleep(300 * time.Millisecond)

	rep := c.verdict(t)
	if len(rep.Chains) != 1 || !rep.Chains[0].OK() {
		t.Fatalf("the collector's stream does not verify: %+v", rep)
	}
	if v := rep.Chains[0]; v.Duplicates != 0 || v.FirstID != 1 || v.LastID != hubHead(t, dir) {
		t.Fatalf("collector holds ids %d…%d with %d repeat(s); each row must arrive once", v.FirstID, v.LastID, v.Duplicates)
	}
	c.mu.Lock()
	auth := c.auth
	c.mu.Unlock()
	if len(auth) != 1 || !auth["Bearer tok-from-the-store"] {
		t.Fatalf("Authorization headers %v, want the token from the secret store", auth)
	}

	leader, follower := a, b
	if !a.node.IsLeader() {
		leader, follower = b, a
	}
	if follower.srv.auditForward.current() != nil {
		t.Fatal("the follower holds a forwarder")
	}
	if out := leader.srv.gatherMetrics(); !strings.Contains(out, `cloop_audit_forward_backlog_rows{sink="siem"} 0`) ||
		!strings.Contains(out, `cloop_audit_forward_lag_seconds{sink="siem"} 0`) {
		t.Errorf("the leader does not export the sink's lag and backlog:\n%s", grepLines(out, "audit_forward"))
	}
	if out := follower.srv.gatherMetrics(); strings.Contains(out, `cloop_audit_forward_backlog_rows{`) {
		t.Errorf("a follower exports the sink's backlog:\n%s", grepLines(out, "audit_forward"))
	}
	if n := len(auditRowsOf(t, dir, auditaction.ActionAuditForwardConfigured)); n != 1 {
		t.Errorf("%d audit.forward.configured rows, want one: the configuration is recorded once, by the leader", n)
	}
}

// The leader dies after the sink acknowledged a batch and before it recorded
// that: the other member takes the duty over and resends from the cursor in
// the control plane. Nothing is missing; the repeats are the same rows.
func TestAuditForwardResumesFromTheCursorWhenTheLeaderDies(t *testing.T) {
	type acked struct {
		m           *clusterMember
		first, last int64
	}
	died := make(chan acked, 1)
	var once sync.Once
	dir, _, _, c := forwardingCluster(t, func(m *clusterMember) auditforward.Hooks {
		return auditforward.Hooks{AfterAck: func(_ string, _ auditforward.Chain, first, last int64) {
			once.Do(func() {
				died <- acked{m, first, last}
				// The worker stops here, as a killed process would: the
				// sink holds the batch, the cursor does not say so.
				runtime.Goexit()
			})
		}}
	})
	appendHubRows(t, dir, 23)
	var victim acked
	select {
	case victim = <-died:
	case <-time.After(20 * time.Second):
		t.Fatal("no batch was acknowledged")
	}
	if got := hubCursor(t, dir); got >= victim.first {
		t.Fatalf("the cursor is at %d, past the batch %d…%d its leader never recorded", got, victim.first, victim.last)
	}
	// The member is gone; the other one is elected and takes the duty over.
	if err := victim.m.node.Close(); err != nil {
		t.Fatal(err)
	}
	waitCluster(t, "the surviving member to forward the rest", func() bool {
		return hubCursor(t, dir) == hubHead(t, dir)
	})
	rep := c.verdict(t)
	if len(rep.Chains) != 1 {
		t.Fatalf("chains in the stream: %+v", rep.Chains)
	}
	v := rep.Chains[0]
	if !v.OK() || v.FirstID != 1 || v.LastID != hubHead(t, dir) || len(v.Gaps) != 0 {
		t.Fatalf("the stream across the leader's death: %+v; want ids 1…%d, whole", v, hubHead(t, dir))
	}
	if want := int(victim.last - victim.first + 1); v.Duplicates < want || len(v.Forks) != 0 {
		t.Fatalf("%d repeat(s), forks %v; the %d rows the dead leader never recorded must arrive again, unchanged",
			v.Duplicates, v.Forks, want)
	}
}

func auditRowsOf(t *testing.T, dir string, action auditaction.Action) []statedb.AuditEvent {
	t.Helper()
	db, err := statedb.Open(state.DBPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	rows, _, err := db.ListAuditEvents(statedb.AuditFilter{EventType: string(action), Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	return rows
}

func grepLines(s, sub string) string {
	var out []string
	for _, l := range strings.Split(s, "\n") {
		if strings.Contains(l, sub) {
			out = append(out, l)
		}
	}
	return strings.Join(out, "\n")
}
