package auditforward

import (
	"encoding/json"
	"fmt"
	"net/http"
	"runtime"
	"runtime/debug"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/auditaction"
	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/hubmetrics"
)

// Every chain, to a TLS syslog receiver demanding a client certificate and to
// an HTTPS collector demanding a token: each receives every row of both
// chains, rows written while the forwarder runs included, and what each
// received verifies end to end — every record re-hashes, every link holds,
// from id 1.
func TestForwardsEveryChainToTLSSyslogAndHTTPS(t *testing.T) {
	hubDir, cp := chainDir(t)
	projDir, proj := chainDir(t)
	appendRows(t, cp, 23)
	appendRows(t, proj, 17)

	server, client := newTLSMaterial(t), newClientMaterial(t)
	syslog := newSyslogReceiver(t, server, client.pool)
	collector := newHTTPSReceiver(t)

	h := newHarness(t, cp,
		Chain{Source: SourceControlPlane, Dir: hubDir, Path: cp},
		Chain{Source: SourceProject, Dir: projDir, Path: proj})
	h.creds["syslog-client-key"] = client.keyPEM
	h.creds["collector-token#TOKEN"] = []byte("s3cr3t-token")
	h.setConfig(config.AuditForwardConfig{
		Hostname: "hub-one",
		Sinks: []config.AuditForwardSink{
			{
				Name: "siem-syslog", Type: config.AuditSinkSyslog, Address: syslog.addr(),
				CAFile: server.certFile, ClientCert: client.certFile, ClientKeySecret: "syslog-client-key",
				BatchSize: 7,
			},
			{
				Name: "siem-https", Type: config.AuditSinkHTTPS, URL: collector.srv.URL + "/ingest",
				CAFile: collector.caFile(t), TokenSecret: "collector-token#TOKEN", BatchSize: 5,
			},
		},
	})
	h.start(Hooks{})

	// Both chains have every row the moment they were started with, and the
	// forwarder ships what is written after too.
	want := func() int { return int(maxID(t, cp) + maxID(t, proj)) }
	waitForLogged(t, h, "both sinks to receive the backlog", 20*time.Second, func() bool {
		return len(syslog.messages()) >= want() && collector.count() >= want()
	})
	appendRows(t, proj, 9)
	appendRows(t, cp, 4)
	waitForLogged(t, h, "both sinks to receive the rows written while running", 20*time.Second, func() bool {
		return len(syslog.messages()) >= want() && collector.count() >= want()
	})

	for name, stream := range map[string]string{"syslog": syslog.stream(), "https": collector.stream()} {
		rep := verify(t, stream)
		if !rep.OK() {
			t.Fatalf("%s: the received stream does not verify: %+v", name, rep)
		}
		hub := chainVerdict(t, rep, SourceControlPlane, hubDir)
		project := chainVerdict(t, rep, SourceProject, projDir)
		if hub.FirstID != 1 || hub.LastID != maxID(t, cp) || project.FirstID != 1 || project.LastID != maxID(t, proj) {
			t.Errorf("%s: received ids %d…%d and %d…%d, want 1…%d and 1…%d", name,
				hub.FirstID, hub.LastID, project.FirstID, project.LastID, maxID(t, cp), maxID(t, proj))
		}
		if len(hub.Hubs) != 1 || hub.Hubs[0] != "hub-one" {
			t.Errorf("%s: records name hub %v, want hub-one", name, hub.Hubs)
		}
	}

	// The syslog side is RFC 5424 in RFC 5425 framing, over the client
	// certificate the secret held.
	syslog.mu.Lock()
	bad, peers := append([]string(nil), syslog.bad...), len(syslog.peers)
	syslog.mu.Unlock()
	if len(bad) > 0 {
		t.Fatalf("the syslog receiver could not read what it was sent: %v", bad)
	}
	if peers == 0 {
		t.Error("the syslog sink connected without presenting its client certificate")
	}
	for _, m := range syslog.messages() {
		var body struct {
			EventType string `json:"event_type"`
		}
		if err := json.Unmarshal([]byte(m.body), &body); err != nil {
			t.Fatalf("syslog MSG is not the JSON record: %v\n%s", err, m.body)
		}
		if m.hostname != "hub-one" || m.app != "cloop" || m.msgid != body.EventType {
			t.Fatalf("syslog header = %+v, want HOSTNAME hub-one, APP-NAME cloop, MSGID %s", m, body.EventType)
		}
		if facility := m.pri / 8; facility != 16 {
			t.Fatalf("syslog facility %d, want local0 (16)", facility)
		}
		if _, err := time.Parse(time.RFC3339Nano, m.ts); err != nil || !strings.HasSuffix(m.ts, "Z") {
			t.Fatalf("syslog timestamp %q is not RFC 3339 UTC: %v", m.ts, err)
		}
	}

	// The HTTPS side presented the token from the secret store, batches
	// within the configured size.
	collector.mu.Lock()
	defer collector.mu.Unlock()
	for _, a := range collector.auth {
		if a != "Bearer s3cr3t-token" {
			t.Fatalf("Authorization = %q, want the bearer token from the secret", a)
		}
	}
	for _, b := range collector.batches {
		if b.records > 5 {
			t.Fatalf("a batch carried %d records, more than batch_size 5", b.records)
		}
	}
}

// A Splunk HTTP Event Collector receives each row as a HEC event, presented
// with its token, and a reply whose code is not 0 is not an acknowledgement:
// the batch goes again.
func TestSplunkHECSink(t *testing.T) {
	hubDir, cp := chainDir(t)
	appendRows(t, cp, 12)
	hec := newHTTPSReceiver(t)
	hec.hec = true
	// The first reply refuses the batch the way HEC does when its queue is
	// full, with a 200 whose body says so.
	hec.reply = func(n int) string {
		if n == 1 {
			return `{"text":"Server is busy","code":9}`
		}
		return `{"text":"Success","code":0}`
	}
	h := newHarness(t, cp, Chain{Source: SourceControlPlane, Dir: hubDir, Path: cp})
	h.creds["hec"] = []byte("0d4e-hec-token")
	h.setConfig(config.AuditForwardConfig{Sinks: []config.AuditForwardSink{{
		Name: "splunk", Type: config.AuditSinkHTTPS, Variant: config.AuditVariantSplunkHEC,
		URL: hec.srv.URL + "/services/collector/event", CAFile: hec.caFile(t), TokenSecret: "hec",
		SplunkIndex: "audit", SplunkSourceType: "cloop:audit",
	}}})
	h.start(Hooks{})

	// The chain holds the 12 rows and the audit.forward.configured row the
	// leader recorded when it started under this sink.
	waitForLogged(t, h, "the HEC to accept every row", 20*time.Second, func() bool { return hec.count() >= 13 })
	hec.mu.Lock()
	auth, bad, requests := append([]string(nil), hec.auth...), append([]string(nil), hec.hecBad...), hec.requests
	hec.mu.Unlock()
	if len(bad) > 0 {
		t.Fatalf("events not in HEC's shape: %v", bad[0])
	}
	if requests < 2 {
		t.Fatalf("%d request(s); the refused batch was not sent again", requests)
	}
	for _, a := range auth {
		if a != "Splunk 0d4e-hec-token" {
			t.Fatalf("Authorization = %q, want the HEC scheme with the stored token", a)
		}
	}
	rep := verify(t, hec.stream())
	if v := chainVerdict(t, rep, SourceControlPlane, hubDir); !v.OK() || v.LastID != maxID(t, cp) {
		t.Fatalf("the events do not hold the chain whole: %+v", v)
	}
	if !strings.Contains(hec.stream(), `"index":"audit"`) {
		t.Error("events do not carry the configured index")
	}
}

// A sink that was down catches up a backlog many batches deep, in batches
// never larger than configured, without the forwarder holding the backlog in
// memory: what it read is bounded by one batch however far behind it fell.
func TestSinkDownCatchesUpALargeBacklogInBoundedMemory(t *testing.T) {
	if testing.Short() {
		t.Skip("writes a 40 MB backlog")
	}
	hubDir, cp := chainDir(t)
	collector := newHTTPSReceiver(t)
	var up atomic.Bool
	collector.status = func(int) int {
		if up.Load() {
			return http.StatusOK
		}
		return http.StatusServiceUnavailable
	}
	// The receiver spools what it accepts to a file, so the heap measured
	// below is the forwarder's and not the receiver's.
	collector.spoolTo(t)
	h := newHarness(t, cp, Chain{Source: SourceControlPlane, Dir: hubDir, Path: cp})
	h.setConfig(config.AuditForwardConfig{Sinks: []config.AuditForwardSink{{
		Name: "down", Type: config.AuditSinkHTTPS, URL: collector.srv.URL, CAFile: collector.caFile(t),
		BatchSize: 200, MaxBatchBytes: 1 << 20,
	}}})
	h.start(Hooks{})

	const rows, size = 10000, 4000
	appendRowsSized(t, cp, rows, size)
	waitFor(t, "the sink to fail at least once", 10*time.Second, func() bool {
		collector.mu.Lock()
		defer collector.mu.Unlock()
		return collector.requests > 0
	})
	if c := cursorOf(t, cp, "down", cp); c.AckedID != 0 {
		t.Fatalf("the cursor moved to %d while the sink refused every batch", c.AckedID)
	}

	old := debug.SetGCPercent(20)
	defer debug.SetGCPercent(old)
	runtime.GC()
	var base runtime.MemStats
	runtime.ReadMemStats(&base)
	var (
		peak    atomic.Uint64
		stopped = make(chan struct{})
		wg      sync.WaitGroup
	)
	wg.Add(1)
	go func() {
		defer wg.Done()
		var ms runtime.MemStats
		for {
			select {
			case <-stopped:
				return
			case <-time.After(5 * time.Millisecond):
			}
			runtime.ReadMemStats(&ms)
			if ms.HeapInuse > peak.Load() {
				peak.Store(ms.HeapInuse)
			}
		}
	}()

	up.Store(true)
	// Polled through the receiver's count rather than the database, so the
	// test's own reads add nothing to the heap being measured.
	deadline := time.Now().Add(120 * time.Second)
	for collector.count() < rows+1 && time.Now().Before(deadline) {
		time.Sleep(100 * time.Millisecond)
	}
	close(stopped)
	wg.Wait()
	waitFor(t, "the cursor to reach the end of the backlog", 20*time.Second, func() bool {
		return cursorOf(t, cp, "down", cp).AckedID >= int64(rows)
	})

	backlog := uint64(rows * size)
	grew := peak.Load() - min(peak.Load(), base.HeapInuse)
	t.Logf("heap in use grew by %d KiB at most while catching up a %d KiB backlog", grew>>10, backlog>>10)
	if grew > backlog/2 {
		t.Errorf("the heap grew by %d bytes while catching up a %d-byte backlog: the backlog is being held in memory",
			grew, backlog)
	}
	collector.mu.Lock()
	for _, b := range collector.batches {
		if b.records > 200 || b.bytes > 1<<20+size*2 {
			t.Errorf("a batch carried %d records in %d bytes; the bound is 200 records, 1 MiB", b.records, b.bytes)
		}
	}
	collector.mu.Unlock()
	rep := verify(t, collector.stream())
	if v := chainVerdict(t, rep, SourceControlPlane, hubDir); !v.OK() || v.FirstID != 1 || v.LastID != maxID(t, cp) {
		t.Fatalf("the caught-up stream is not the chain: %+v", v)
	}
}

// A leader that dies after the sink acknowledged a batch and before it moved
// the cursor leaves the batch unrecorded; the next leader resends it from the
// cursor. Nothing is missing, the repeats carry the row_hash they had, and
// the receiver tells them apart from new rows by it.
func TestALeaderKilledMidBatchIsResumedFromTheCursor(t *testing.T) {
	hubDir, cp := chainDir(t)
	appendRows(t, cp, 40)
	collector := newHTTPSReceiver(t)
	cfg := config.AuditForwardConfig{Sinks: []config.AuditForwardSink{{
		Name: "siem", Type: config.AuditSinkHTTPS, URL: collector.srv.URL, CAFile: collector.caFile(t), BatchSize: 10,
	}}}

	// Leader A: acknowledged, then gone before the cursor write — the
	// worker exits where a SIGKILL would have stopped the process.
	a := newHarness(t, cp, Chain{Source: SourceControlPlane, Dir: hubDir, Path: cp})
	a.setConfig(cfg)
	acked := make(chan [2]int64, 1)
	var killed sync.Once
	_, stopA := a.start(Hooks{AfterAck: func(_ string, _ Chain, first, last int64) {
		killed.Do(func() {
			acked <- [2]int64{first, last}
			runtime.Goexit()
		})
	}})
	var batch [2]int64
	select {
	case batch = <-acked:
	case <-time.After(20 * time.Second):
		t.Fatal("leader A never had a batch acknowledged")
	}
	stopA()
	if c := cursorOf(t, cp, "siem", cp); c.AckedID >= batch[0] {
		t.Fatalf("the cursor is at %d although leader A died before recording the batch %d…%d", c.AckedID, batch[0], batch[1])
	}

	// Leader B takes over from the cursor in the database.
	b := newHarness(t, cp, Chain{Source: SourceControlPlane, Dir: hubDir, Path: cp})
	b.setConfig(cfg)
	b.start(Hooks{})
	waitFor(t, "leader B to deliver to the end of the chain", 20*time.Second, func() bool {
		return cursorOf(t, cp, "siem", cp).AckedID == maxID(t, cp)
	})

	rep := verify(t, collector.stream())
	v := chainVerdict(t, rep, SourceControlPlane, hubDir)
	if !v.OK() {
		t.Fatalf("the stream across the leader change does not verify: %+v", v)
	}
	if v.FirstID != 1 || v.LastID != maxID(t, cp) || len(v.Gaps) != 0 {
		t.Fatalf("received ids %d…%d with gaps %v; want 1…%d with none", v.FirstID, v.LastID, v.Gaps, maxID(t, cp))
	}
	if want := int(batch[1] - batch[0] + 1); v.Duplicates < want {
		t.Fatalf("%d repeated record(s); the %d rows A sent and never recorded should have been sent again", v.Duplicates, want)
	}
	if len(v.Forks) != 0 {
		t.Fatalf("repeats carried different row hashes (forks at %v): a resend must be the same rows", v.Forks)
	}
}

// Delivered and failed rows are counted per sink; the counter is the one the
// hub exports.
func TestForwardedRowsAreCounted(t *testing.T) {
	hubDir, cp := chainDir(t)
	appendRows(t, cp, 6)
	collector := newHTTPSReceiver(t)
	collector.status = func(n int) int {
		if n == 1 {
			return http.StatusBadGateway
		}
		return http.StatusOK
	}
	before := counterValue(t, "counted", hubmetrics.AuditForwardDelivered)
	failedBefore := counterValue(t, "counted", hubmetrics.AuditForwardFailed)
	h := newHarness(t, cp, Chain{Source: SourceControlPlane, Dir: hubDir, Path: cp})
	h.setConfig(config.AuditForwardConfig{Sinks: []config.AuditForwardSink{{
		Name: "counted", Type: config.AuditSinkHTTPS, URL: collector.srv.URL, CAFile: collector.caFile(t),
	}}})
	h.start(Hooks{})
	// Six rows, and the configured row the leader recorded.
	waitForLogged(t, h, "delivery", 20*time.Second, func() bool { return cursorOf(t, cp, "counted", cp).AckedID == 7 })
	if got := counterValue(t, "counted", hubmetrics.AuditForwardDelivered) - before; got != 7 {
		t.Errorf("delivered counter rose by %v, want 7", got)
	}
	if got := counterValue(t, "counted", hubmetrics.AuditForwardFailed) - failedBefore; got < 7 {
		t.Errorf("failed counter rose by %v, want the 7 rows of the refused batch", got)
	}
	if c := cursorOf(t, cp, "counted", cp); c.Delivered != 7 || c.AckedAt.IsZero() {
		t.Errorf("cursor = %+v, want 7 delivered with an acknowledgement time", c)
	}
}

// counterValue reads one sample of cloop_audit_forward_rows_total.
func counterValue(t testing.TB, sink, outcome string) float64 {
	t.Helper()
	want := `cloop_audit_forward_rows_total{sink="` + sink + `",outcome="` + outcome + `"} `
	for _, line := range strings.Split(hubmetrics.Default.Gather(), "\n") {
		if strings.HasPrefix(line, want) {
			var v float64
			if _, err := fmt.Sscan(strings.TrimPrefix(line, want), &v); err != nil {
				t.Fatalf("parse %q: %v", line, err)
			}
			return v
		}
	}
	return 0
}

// The configuration a leader runs under is recorded when it changes — added,
// changed, removed — naming the secrets a sink reads, never their values.
func TestAConfigurationChangeIsRecorded(t *testing.T) {
	hubDir, cp := chainDir(t)
	h := newHarness(t, cp, Chain{Source: SourceControlPlane, Dir: hubDir, Path: cp})
	h.creds["tok"] = []byte("the-token-value")
	sinkA := config.AuditForwardSink{Name: "a", Type: config.AuditSinkHTTPS, URL: "https://127.0.0.1:9/x", TokenSecret: "tok"}
	h.setConfig(config.AuditForwardConfig{Sinks: []config.AuditForwardSink{sinkA}})
	_, stop := h.start(Hooks{})
	waitFor(t, "the first configuration to be recorded", 10*time.Second, func() bool {
		return len(auditRows(t, cp, auditaction.ActionAuditForwardConfigured)) == 1
	})

	sinkA.BatchSize = 10
	sinkB := config.AuditForwardSink{Name: "b", Type: config.AuditSinkFile, Path: t.TempDir() + "/audit.jsonl"}
	h.setConfig(config.AuditForwardConfig{Sinks: []config.AuditForwardSink{sinkA, sinkB}})
	waitFor(t, "the change to be recorded", 10*time.Second, func() bool {
		return len(auditRows(t, cp, auditaction.ActionAuditForwardConfigured)) == 2
	})
	h.setConfig(config.AuditForwardConfig{})
	waitFor(t, "the removal to be recorded", 10*time.Second, func() bool {
		return len(auditRows(t, cp, auditaction.ActionAuditForwardConfigured)) == 3
	})
	stop()

	rows := auditRows(t, cp, auditaction.ActionAuditForwardConfigured)
	for i, want := range []string{`"added":["a"]`, `"added":["b"],"changed":["a"]`, `"removed":["a","b"]`} {
		if !strings.Contains(rows[i].Payload, want) {
			t.Errorf("row %d payload %s does not say %s", i, rows[i].Payload, want)
		}
	}
	for _, r := range rows {
		if strings.Contains(r.Payload, "the-token-value") {
			t.Fatalf("a configuration row carries a secret's value: %s", r.Payload)
		}
	}
	if !strings.Contains(rows[0].Payload, `"refs":["tok"]`) {
		t.Errorf("the row does not name the secret the sink reads: %s", rows[0].Payload)
	}
	// A restart under the same configuration records nothing.
	h.start(Hooks{})
	time.Sleep(200 * time.Millisecond)
	if n := len(auditRows(t, cp, auditaction.ActionAuditForwardConfigured)); n != 3 {
		t.Errorf("%d configuration rows after a restart under an unchanged configuration, want 3", n)
	}
}
