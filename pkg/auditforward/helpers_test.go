package auditforward

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/internal/statedbtest"
	"github.com/blechschmidt/cloop/pkg/auditaction"
	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
	"github.com/blechschmidt/cloop/pkg/tlsconf"
)

// chainDir is a directory holding a migrated .cloop/state.db.
func chainDir(t testing.TB) (dir, path string) {
	t.Helper()
	dir = t.TempDir()
	path = state.DBPath(dir)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	statedbtest.Template().Seed(t, path)
	abs, err := filepath.Abs(path)
	if err != nil {
		t.Fatal(err)
	}
	return dir, abs
}

// payloads the rows cycle through: compact JSON, JSON the encoder would
// rewrite (whitespace, a raw '<'), and text that is not JSON at all — every
// shape a receiver must be able to re-hash.
var payloads = []string{
	`{"task":1,"title":"ship it"}`,
	`{ "spaced" : true }`,
	`{"html":"<b>&</b>"}`,
	`not json at all`,
	``,
}

// appendRows appends n audit rows to the chain at path.
func appendRows(t testing.TB, path string, n int) {
	t.Helper()
	appendRowsSized(t, path, n, 0)
}

// appendRowsSized appends n rows, each with a payload of about size bytes
// when size is positive.
func appendRowsSized(t testing.TB, path string, n, size int) {
	t.Helper()
	db, err := statedb.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	batch := make([]*statedb.AuditEvent, 0, 256)
	flush := func() {
		if err := db.AppendAuditEvents(batch); err != nil {
			t.Fatal(err)
		}
		batch = batch[:0]
	}
	for i := 0; i < n; i++ {
		var ev statedb.AuditEvent
		ev.Actor = "tester"
		ev.EventType = string(auditaction.ActionTaskUpsert)
		ev.EntityType = "task"
		ev.EntityID = strconv.Itoa(i)
		ev.Payload = payloads[i%len(payloads)]
		if size > 0 {
			ev.Payload = fmt.Sprintf(`{"n":%d,"pad":%q}`, i, strings.Repeat("x", size))
		}
		batch = append(batch, &ev)
		if len(batch) == cap(batch) {
			flush()
		}
	}
	if len(batch) > 0 {
		flush()
	}
}

// maxID is the newest row of the chain at path.
func maxID(t testing.TB, path string) int64 {
	t.Helper()
	db, err := statedb.Open(path)
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

// tlsMaterial is a self-signed certificate for 127.0.0.1 and the files it
// lives in.
type tlsMaterial struct {
	certFile, keyFile string
	cert              tls.Certificate
	pool              *x509.CertPool
	keyPEM            []byte
}

func newTLSMaterial(t testing.TB) tlsMaterial {
	t.Helper()
	dir := t.TempDir()
	m := tlsMaterial{certFile: filepath.Join(dir, "cert.pem"), keyFile: filepath.Join(dir, "key.pem")}
	if _, err := tlsconf.GenerateSelfSigned(m.certFile, m.keyFile, tlsconf.SelfSignedOptions{Hosts: []string{"127.0.0.1", "localhost"}}); err != nil {
		t.Fatal(err)
	}
	cert, err := tls.LoadX509KeyPair(m.certFile, m.keyFile)
	if err != nil {
		t.Fatal(err)
	}
	m.cert = cert
	certPEM, _ := os.ReadFile(m.certFile)
	m.keyPEM, _ = os.ReadFile(m.keyFile)
	m.pool = x509.NewCertPool()
	m.pool.AppendCertsFromPEM(certPEM)
	return m
}

// newClientMaterial is a self-signed certificate for TLS client
// authentication, its key PEM-encoded as a secret would hold it.
func newClientMaterial(t testing.TB) tlsMaterial {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "cloop-hub"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	m := tlsMaterial{certFile: filepath.Join(dir, "client.pem")}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	m.keyPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(m.certFile, certPEM, 0o644); err != nil {
		t.Fatal(err)
	}
	if m.cert, err = tls.X509KeyPair(certPEM, m.keyPEM); err != nil {
		t.Fatal(err)
	}
	m.pool = x509.NewCertPool()
	m.pool.AppendCertsFromPEM(certPEM)
	return m
}

// ── syslog receiver ─────────────────────────────────────────────────────────

// syslogMsg is one received RFC 5424 message.
type syslogMsg struct {
	pri      int
	ts       string
	hostname string
	app      string
	msgid    string
	body     string
}

// rfc5424 matches the header the forwarder writes: PRI, VERSION 1,
// TIMESTAMP, HOSTNAME, APP-NAME, PROCID, MSGID, STRUCTURED-DATA "-", MSG.
var rfc5424 = regexp.MustCompile(`^<(\d{1,3})>1 (\S+) (\S+) (\S+) (\S+) (\S+) - (.*)$`)

// syslogReceiver is an RFC 5425 receiver: TLS, octet-counted framing.
type syslogReceiver struct {
	t    testing.TB
	ln   net.Listener
	mu   sync.Mutex
	msgs []syslogMsg
	// peers records the client certificates presented.
	peers []string
	bad   []string
}

func newSyslogReceiver(t testing.TB, server tlsMaterial, clientCAs *x509.CertPool) *syslogReceiver {
	t.Helper()
	cfg := &tls.Config{Certificates: []tls.Certificate{server.cert}, MinVersion: tls.VersionTLS12}
	if clientCAs != nil {
		cfg.ClientCAs = clientCAs
		cfg.ClientAuth = tls.RequireAndVerifyClientCert
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", cfg)
	if err != nil {
		t.Fatal(err)
	}
	r := &syslogReceiver{t: t, ln: ln}
	go r.serve()
	t.Cleanup(func() { _ = ln.Close() })
	return r
}

func (r *syslogReceiver) addr() string { return r.ln.Addr().String() }

func (r *syslogReceiver) serve() {
	for {
		c, err := r.ln.Accept()
		if err != nil {
			return
		}
		go r.handle(c)
	}
}

func (r *syslogReceiver) handle(c net.Conn) {
	defer c.Close()
	tc := c.(*tls.Conn)
	if err := tc.Handshake(); err != nil {
		return
	}
	if certs := tc.ConnectionState().PeerCertificates; len(certs) > 0 {
		r.mu.Lock()
		r.peers = append(r.peers, certs[0].Subject.String())
		r.mu.Unlock()
	}
	br := bufio.NewReader(c)
	for {
		// MSG-LEN SP SYSLOG-MSG (RFC 5425 §4.3).
		lenStr, err := br.ReadString(' ')
		if err != nil {
			return
		}
		n, err := strconv.Atoi(strings.TrimSuffix(lenStr, " "))
		if err != nil || n <= 0 {
			r.fail("bad frame length %q", lenStr)
			return
		}
		buf := make([]byte, n)
		if _, err := io.ReadFull(br, buf); err != nil {
			return
		}
		m := rfc5424.FindStringSubmatch(string(buf))
		if m == nil {
			r.fail("not an RFC 5424 message: %q", buf)
			continue
		}
		pri, _ := strconv.Atoi(m[1])
		r.mu.Lock()
		r.msgs = append(r.msgs, syslogMsg{pri: pri, ts: m[2], hostname: m[3], app: m[4], msgid: m[6], body: m[7]})
		r.mu.Unlock()
	}
}

func (r *syslogReceiver) fail(format string, args ...any) {
	r.mu.Lock()
	r.bad = append(r.bad, fmt.Sprintf(format, args...))
	r.mu.Unlock()
}

func (r *syslogReceiver) messages() []syslogMsg {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]syslogMsg(nil), r.msgs...)
}

// stream renders what was received as the lines VerifyStream reads.
func (r *syslogReceiver) stream() string {
	var b strings.Builder
	for _, m := range r.messages() {
		b.WriteString(m.body)
		b.WriteByte('\n')
	}
	return b.String()
}

// ── https receiver ──────────────────────────────────────────────────────────

// httpsReceiver is an NDJSON (or HEC) collector.
type httpsReceiver struct {
	srv *httptest.Server

	mu       sync.Mutex
	lines    []string
	requests int
	// batches records each acknowledged request's record count and size.
	batches []batchSeen
	auth    []string
	// status decides the reply to the n-th request (from 1); nil is 200.
	status func(n int) int
	// reject, when it returns true for a request body, answers 400 to it.
	reject func(body []byte) bool
	// reply overrides the body of a 200.
	reply func(n int) string
	// hec unwraps HEC envelopes and checks their shape.
	hec    bool
	hecBad []string
	// spool, when set, receives the lines instead of memory, so a test can
	// measure the forwarder's heap without the receiver's in it.
	spool    *os.File
	received int
}

type batchSeen struct {
	records int
	bytes   int
}

func newHTTPSReceiver(t testing.TB) *httpsReceiver {
	t.Helper()
	r := &httpsReceiver{}
	r.srv = httptest.NewTLSServer(http.HandlerFunc(r.serve))
	t.Cleanup(r.srv.Close)
	return r
}

// caFile writes the receiver's certificate where a sink's ca_file can name it.
func (r *httpsReceiver) caFile(t testing.TB) string {
	t.Helper()
	return caFileFor(t, r.srv)
}

// caFileFor writes a TLS test server's certificate to a file.
func caFileFor(t testing.TB, srv *httptest.Server) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "ca.pem")
	block := &pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func (r *httpsReceiver) serve(w http.ResponseWriter, req *http.Request) {
	body, _ := io.ReadAll(req.Body)
	r.mu.Lock()
	r.requests++
	n := r.requests
	r.auth = append(r.auth, req.Header.Get("Authorization"))
	status := http.StatusOK
	if r.status != nil {
		status = r.status(n)
	}
	if r.reject != nil && r.reject(body) {
		status = http.StatusBadRequest
	}
	reply := ""
	if r.reply != nil {
		reply = r.reply(n)
	}
	r.mu.Unlock()
	if status != http.StatusOK {
		http.Error(w, "unavailable", status)
		return
	}
	var lines []string
	for _, line := range bytes.Split(bytes.TrimSpace(body), []byte("\n")) {
		if len(line) == 0 {
			continue
		}
		if r.hec {
			var env struct {
				Time       json.Number     `json:"time"`
				Host       string          `json:"host"`
				Source     string          `json:"source"`
				SourceType string          `json:"sourcetype"`
				Index      string          `json:"index"`
				Event      json.RawMessage `json:"event"`
			}
			if err := json.Unmarshal(line, &env); err != nil || len(env.Event) == 0 || env.Time == "" || env.SourceType == "" {
				r.mu.Lock()
				r.hecBad = append(r.hecBad, string(line))
				r.mu.Unlock()
			}
		}
		lines = append(lines, string(line))
	}
	if reply != "" {
		_, _ = io.WriteString(w, reply)
		if strings.Contains(reply, `"code":0`) || !strings.Contains(reply, `"code"`) {
			r.accept(lines, len(body))
		}
		return
	}
	r.accept(lines, len(body))
	if r.hec {
		_, _ = io.WriteString(w, `{"text":"Success","code":0}`)
	}
}

func (r *httpsReceiver) accept(lines []string, size int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.spool != nil {
		for _, l := range lines {
			_, _ = r.spool.WriteString(l + "\n")
		}
	} else {
		r.lines = append(r.lines, lines...)
	}
	r.received += len(lines)
	r.batches = append(r.batches, batchSeen{records: len(lines), bytes: size})
}

func (r *httpsReceiver) stream() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.spool != nil {
		b, _ := os.ReadFile(r.spool.Name())
		return string(b)
	}
	return strings.Join(r.lines, "\n") + "\n"
}

func (r *httpsReceiver) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.received
}

// spoolTo makes the receiver write what it accepts to a file.
func (r *httpsReceiver) spoolTo(t testing.TB) {
	t.Helper()
	f, err := os.Create(filepath.Join(t.TempDir(), "received.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })
	r.mu.Lock()
	r.spool = f
	r.mu.Unlock()
}

// ── running a forwarder ─────────────────────────────────────────────────────

// fwdHarness runs one Forwarder over a control plane and a set of chains.
type fwdHarness struct {
	t  testing.TB
	cp string

	mu     sync.Mutex
	cfg    config.AuditForwardConfig
	chains []Chain

	creds map[string][]byte
	logs  *logSink
}

type logSink struct {
	mu    sync.Mutex
	lines []string
}

func (l *logSink) logf(format string, args ...any) {
	l.mu.Lock()
	l.lines = append(l.lines, fmt.Sprintf(format, args...))
	l.mu.Unlock()
}

func (l *logSink) text() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return strings.Join(l.lines, "\n")
}

func newHarness(t testing.TB, cp string, chains ...Chain) *fwdHarness {
	return &fwdHarness{t: t, cp: cp, chains: chains, creds: map[string][]byte{}, logs: &logSink{}}
}

func (h *fwdHarness) setConfig(cfg config.AuditForwardConfig) {
	h.mu.Lock()
	h.cfg = cfg
	h.mu.Unlock()
}

func (h *fwdHarness) setChains(chains ...Chain) {
	h.mu.Lock()
	h.chains = chains
	h.mu.Unlock()
}

func (h *fwdHarness) options(hooks Hooks) Options {
	return Options{
		ControlPlane: h.cp,
		Config: func() (config.AuditForwardConfig, error) {
			h.mu.Lock()
			defer h.mu.Unlock()
			return h.cfg, nil
		},
		ConfigSource: "test",
		Chains: func() []Chain {
			h.mu.Lock()
			defer h.mu.Unlock()
			return append([]Chain(nil), h.chains...)
		},
		Credentials: func(ref string) ([]byte, error) {
			h.mu.Lock()
			defer h.mu.Unlock()
			v, ok := h.creds[ref]
			if !ok {
				return nil, fmt.Errorf("no secret %q", ref)
			}
			return append([]byte(nil), v...), nil
		},
		Version:    "test",
		Poll:       20 * time.Millisecond,
		ConfigPoll: 50 * time.Millisecond,
		Logf:       h.logs.logf,
		Hooks:      hooks,
	}
}

// start runs a forwarder until the returned stop is called (or the test
// ends). stop waits for it.
func (h *fwdHarness) start(hooks Hooks) (fwd *Forwarder, stop func()) {
	h.t.Helper()
	fwd, err := New(h.options(hooks))
	if err != nil {
		h.t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		fwd.Run(ctx)
	}()
	var once sync.Once
	stop = func() {
		once.Do(func() {
			cancel()
			<-done
		})
	}
	h.t.Cleanup(stop)
	return fwd, stop
}

// waitFor polls cond until it holds or the deadline passes.
func waitFor(t testing.TB, what string, timeout time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out after %s waiting for %s", timeout, what)
}

// waitForLogged is waitFor, failing with what the forwarder said.
func waitForLogged(t testing.TB, h *fwdHarness, what string, timeout time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out after %s waiting for %s; the forwarder said:\n%s", timeout, what, h.logs.text())
}

// verify runs VerifyStream over a received stream.
func verify(t testing.TB, stream string) StreamReport {
	t.Helper()
	rep, err := VerifyStream(strings.NewReader(stream))
	if err != nil {
		t.Fatal(err)
	}
	return rep
}

// chainVerdict finds one chain's verdict.
func chainVerdict(t testing.TB, rep StreamReport, source, dir string) ChainVerdict {
	t.Helper()
	for _, c := range rep.Chains {
		if c.Source == source && c.Dir == dir {
			return c
		}
	}
	t.Fatalf("no %s chain for %s in the stream; chains: %+v", source, dir, rep.Chains)
	return ChainVerdict{}
}

// cursorOf reads one cursor from the control plane.
func cursorOf(t testing.TB, cp, sink, chain string) statedb.AuditForwardCursor {
	t.Helper()
	db, err := statedb.Open(cp)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	c, ok, err := db.AuditForwardCursorFor(sink, chain)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		return statedb.AuditForwardCursor{}
	}
	return c
}

// auditRows lists the rows of one action in the chain at path.
func auditRows(t testing.TB, path string, action auditaction.Action) []statedb.AuditEvent {
	t.Helper()
	db, err := statedb.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	rows, _, err := db.ListAuditEvents(statedb.AuditFilter{EventType: string(action), Limit: 1000})
	if err != nil {
		t.Fatal(err)
	}
	return rows
}
