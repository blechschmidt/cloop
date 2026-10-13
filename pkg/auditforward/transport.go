package auditforward

// transport.go: how a batch reaches a sink, and what counts as the sink
// having acknowledged it.
//
// Every outbound connection is made by guardedDialer, which checks the
// address the socket is about to connect to — after DNS, so a name that
// resolves somewhere it should not cannot slip past a check made on the name:
// a cloud metadata service (pkg/cloudmeta) is refused for every sink, and a
// plaintext sink may only ever connect to a loopback address, whatever its
// host name resolved to. The https client follows no redirect and uses no
// proxy from the environment: a 3xx is a failed send, not an instruction to
// carry the audit trail, and its token, somewhere else.

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/blechschmidt/cloop/pkg/cloudmeta"
	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/tlsconf"
)

// transport delivers a batch to one sink.
type transport interface {
	// send delivers msgs and returns once the sink has acknowledged every
	// one of them. An error means none of them may be counted as delivered.
	send(ctx context.Context, msgs []message) error
	close() error
}

// errTooLarge is a sink refusing a batch for its size (HTTP 413).
var errTooLarge = errors.New("the sink refused the batch as too large")

// rejectedError is a sink that took the request and refused its rows for
// their content — a 400 or 422, or a HEC reply naming the data. Sending the
// same rows again gets the same answer, so the chain they came from backs off
// on its own while the sink's other chains carry on.
type rejectedError struct{ msg string }

func (e *rejectedError) Error() string { return e.msg }

// hecContentCodes are the HEC reply codes that refuse the data rather than the
// request: no data, invalid data format, event field required or blank, and
// indexed fields that could not be handled.
var hecContentCodes = map[int]bool{5: true, 6: true, 12: true, 13: true, 15: true}

// ErrMetadataAddress is the refusal to connect to a cloud metadata service.
var ErrMetadataAddress = errors.New("auditforward: refusing to connect to a cloud metadata service")

// ErrPlaintextOffHost is the refusal to send plaintext anywhere but loopback.
var ErrPlaintextOffHost = errors.New("auditforward: refusing plaintext to a non-loopback address")

// guardedDialer returns a dialer whose every connection is checked at the
// address it connects to. plaintext restricts it to loopback addresses.
func guardedDialer(timeout time.Duration, plaintext bool) *net.Dialer {
	return &net.Dialer{
		Timeout:   timeout,
		KeepAlive: 30 * time.Second,
		Control: func(network, address string, _ syscall.RawConn) error {
			return checkDialAddress(address, plaintext)
		},
	}
}

// checkDialAddress is the address rule, on the "ip:port" a socket is about to
// connect to.
func checkDialAddress(address string, plaintext bool) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("auditforward: dial address %q: %w", address, err)
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		// Control is called with the resolved address; anything else is a
		// dial this package did not expect, and is refused rather than
		// trusted.
		return fmt.Errorf("auditforward: dial address %q is not an IP address", address)
	}
	if svc, ok := cloudmeta.LookupDialed(ip); ok {
		return fmt.Errorf("%w: %s is %s", ErrMetadataAddress, ip, svc.Describe())
	}
	// Loopback as the socket sees it: an IPv4-mapped spelling is the same
	// host, a NAT64 one is a gateway somewhere on the network, which the
	// plaintext would cross to reach it.
	if plaintext && !ip.Unmap().IsLoopback() {
		return fmt.Errorf("%w: %s", ErrPlaintextOffHost, ip)
	}
	return nil
}

// newTransport builds the transport for a sink, reading the credentials it
// names from the secret store.
func newTransport(cfg config.AuditForwardSink, creds Credentials, version string) (transport, error) {
	// The configuration was validated at load; this is the same rule again
	// where it is enforced, so no path that skipped validation can send in
	// plaintext off the host.
	if err := config.ValidateAuditForwardSink(cfg); err != nil {
		return nil, fmt.Errorf("sink refused: %w", err)
	}
	switch strings.ToLower(cfg.Type) {
	case config.AuditSinkFile:
		return &fileTransport{path: cfg.Path}, nil
	case config.AuditSinkSyslog:
		tlsCfg, err := sinkTLS(cfg, creds)
		if err != nil {
			return nil, err
		}
		return &syslogTransport{cfg: cfg, tls: tlsCfg}, nil
	case config.AuditSinkHTTPS:
		return newHTTPSTransport(cfg, creds, version)
	}
	return nil, fmt.Errorf("sink refused: type %q is not one of syslog, https, file", cfg.Type)
}

// sinkTLS builds the client TLS configuration a sink dials with, or nil for a
// plaintext sink.
func sinkTLS(cfg config.AuditForwardSink, creds Credentials) (*tls.Config, error) {
	if cfg.Plaintext() {
		return nil, nil
	}
	opts := tlsconf.ClientOptions{RootCAFile: cfg.CAFile, ServerName: cfg.ServerName}
	if cfg.ClientCert != "" {
		cert, err := clientCertificate(cfg, creds)
		if err != nil {
			return nil, err
		}
		opts.Certificates = []tls.Certificate{cert}
	}
	return tlsconf.ClientConfig(opts)
}

// clientCertificate pairs the sink's certificate file with the private key
// its secret holds.
func clientCertificate(cfg config.AuditForwardSink, creds Credentials) (tls.Certificate, error) {
	certPEM, err := os.ReadFile(cfg.ClientCert)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("read client_cert: %w", err)
	}
	if creds == nil {
		return tls.Certificate{}, fmt.Errorf("client_key_secret %q: this hub has no secret store", cfg.ClientKeySecret)
	}
	keyPEM, err := creds(cfg.ClientKeySecret)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("client_key_secret %q: %w", cfg.ClientKeySecret, err)
	}
	defer zero(keyPEM)
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("client_cert and the key in %q do not form a key pair: %w", cfg.ClientKeySecret, err)
	}
	return cert, nil
}

func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// ── syslog ──────────────────────────────────────────────────────────────────

// syslogTransport sends RFC 5424 messages over one long-lived connection, in
// RFC 5425 octet-counted framing ("MSG-LEN SP SYSLOG-MSG", RFC 5425 §4.3) —
// over TLS, or plain TCP to a loopback collector.
type syslogTransport struct {
	cfg  config.AuditForwardSink
	tls  *tls.Config
	conn net.Conn
	tcp  *net.TCPConn
}

func (t *syslogTransport) dial(ctx context.Context) error {
	timeout := t.cfg.EffectiveTimeout()
	d := guardedDialer(timeout, t.tls == nil)
	raw, err := d.DialContext(ctx, "tcp", t.cfg.Address)
	if err != nil {
		return fmt.Errorf("connect to %s: %w", t.cfg.Address, err)
	}
	tcp, _ := raw.(*net.TCPConn)
	if t.tls == nil {
		t.conn, t.tcp = raw, tcp
		return nil
	}
	cfg := t.tls.Clone()
	if cfg.ServerName == "" {
		host, _, _ := net.SplitHostPort(t.cfg.Address)
		cfg.ServerName = host
	}
	tc := tls.Client(raw, cfg)
	hctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	if err := tc.HandshakeContext(hctx); err != nil {
		_ = raw.Close()
		return fmt.Errorf("TLS handshake with %s: %w", t.cfg.Address, err)
	}
	t.conn, t.tcp = tc, tcp
	return nil
}

func (t *syslogTransport) send(ctx context.Context, msgs []message) error {
	if t.conn == nil {
		if err := t.dial(ctx); err != nil {
			return err
		}
	}
	deadline := time.Now().Add(t.cfg.EffectiveTimeout())
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	_ = t.conn.SetWriteDeadline(deadline)
	// A leader that stops leading abandons its send at once rather than at
	// the write deadline: closing the connection unblocks the write, and the
	// batch, unacknowledged, is its successor's to send.
	conn := t.conn
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	// One buffered writer per batch, so a batch goes out in as few TLS
	// records as fit rather than one per message.
	w := bufio.NewWriterSize(t.conn, 64<<10)
	for _, m := range msgs {
		if _, err := w.WriteString(strconv.Itoa(len(m.data))); err != nil {
			return t.fail(err)
		}
		if err := w.WriteByte(' '); err != nil {
			return t.fail(err)
		}
		if _, err := w.Write(m.data); err != nil {
			return t.fail(err)
		}
	}
	if err := w.Flush(); err != nil {
		return t.fail(err)
	}
	// RFC 5425 has no acknowledgement, so the receiver's TCP stack is asked
	// for one: every byte written must be acknowledged, on a connection the
	// receiver has not closed.
	if err := waitAcknowledged(ctx, t.tcp, deadline); err != nil {
		return t.fail(err)
	}
	return nil
}

// fail closes the connection so the next send starts a fresh one, and
// returns err.
func (t *syslogTransport) fail(err error) error {
	_ = t.close()
	return err
}

func (t *syslogTransport) close() error {
	if t.conn == nil {
		return nil
	}
	err := t.conn.Close()
	t.conn, t.tcp = nil, nil
	return err
}

// ── https ───────────────────────────────────────────────────────────────────

// httpsTransport POSTs each batch: NDJSON, or HEC events.
type httpsTransport struct {
	cfg    config.AuditForwardSink
	client *http.Client
	auth   string
	agent  string
	hec    bool
	// channel identifies this sender to a HEC whose token has indexer
	// acknowledgement on, which refuses a request without one; a code of 0
	// then means received, not yet indexed.
	channel string
}

func newHTTPSTransport(cfg config.AuditForwardSink, creds Credentials, version string) (*httpsTransport, error) {
	tlsCfg, err := sinkTLS(cfg, creds)
	if err != nil {
		return nil, err
	}
	timeout := cfg.EffectiveTimeout()
	d := guardedDialer(timeout, cfg.Plaintext())
	tr := &http.Transport{
		// Never a proxy from the environment: the dial check has to see the
		// address the rows go to, not a proxy's.
		Proxy:                 nil,
		DialContext:           d.DialContext,
		TLSClientConfig:       tlsCfg,
		ForceAttemptHTTP2:     true,
		TLSHandshakeTimeout:   timeout,
		ResponseHeaderTimeout: timeout,
		MaxIdleConnsPerHost:   2,
		IdleConnTimeout:       90 * time.Second,
	}
	t := &httpsTransport{
		cfg: cfg,
		client: &http.Client{
			Transport: tr,
			Timeout:   timeout,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		agent: "cloop-audit-forward/" + version,
		hec:   strings.EqualFold(cfg.Variant, config.AuditVariantSplunkHEC),
	}
	if t.hec {
		t.channel = newChannelID()
	}
	if cfg.TokenSecret != "" {
		if creds == nil {
			return nil, fmt.Errorf("token_secret %q: this hub has no secret store", cfg.TokenSecret)
		}
		tok, err := creds(cfg.TokenSecret)
		if err != nil {
			return nil, fmt.Errorf("token_secret %q: %w", cfg.TokenSecret, err)
		}
		t.auth = authorization(cfg.EffectiveAuthScheme(), strings.TrimSpace(string(tok)))
		zero(tok)
	}
	return t, nil
}

// authorization renders the Authorization header for a scheme.
func authorization(scheme, token string) string {
	switch scheme {
	case config.AuditAuthAPIKey:
		return "ApiKey " + token
	case config.AuditAuthBasic:
		return "Basic " + base64.StdEncoding.EncodeToString([]byte(token))
	case config.AuditAuthSplunk:
		return "Splunk " + token
	}
	return "Bearer " + token
}

func (t *httpsTransport) send(ctx context.Context, msgs []message) error {
	var body bytes.Buffer
	for _, m := range msgs {
		body.Write(m.data)
		body.WriteByte('\n')
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, t.cfg.URL, bytes.NewReader(body.Bytes()))
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	if t.hec {
		req.Header.Set("Content-Type", "application/json")
	} else {
		req.Header.Set("Content-Type", "application/x-ndjson")
	}
	req.Header.Set("User-Agent", t.agent)
	if t.auth != "" {
		req.Header.Set("Authorization", t.auth)
	}
	if t.channel != "" {
		req.Header.Set("X-Splunk-Request-Channel", t.channel)
	}
	endpoint := redactedURL(t.cfg.URL)
	resp, err := t.client.Do(req)
	if err != nil {
		// net/http's error repeats the whole URL, query string included,
		// which is where a collector that takes its key as a parameter
		// would have it; the sink is named without one.
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err
		}
		return fmt.Errorf("POST %s: %w", endpoint, err)
	}
	defer resp.Body.Close()
	reply, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	var hecReply struct {
		Code *int   `json:"code"`
		Text string `json:"text"`
	}
	if t.hec {
		_ = json.Unmarshal(bytes.TrimSpace(reply), &hecReply)
	}
	switch {
	case resp.StatusCode == http.StatusRequestEntityTooLarge:
		return fmt.Errorf("%w (HTTP 413 from %s)", errTooLarge, endpoint)
	case resp.StatusCode >= 300 && resp.StatusCode < 400:
		return fmt.Errorf("POST %s answered %s, a redirect, which is never followed: point the sink at the "+
			"final URL", endpoint, resp.Status)
	case resp.StatusCode == http.StatusBadRequest || resp.StatusCode == http.StatusUnprocessableEntity:
		if t.hec && hecReply.Code != nil && !hecContentCodes[*hecReply.Code] {
			// A 400 that names the request, not the data — an index the
			// token may not write — fails every chain alike.
			return fmt.Errorf("HEC at %s refused the request: code %d (%s)", endpoint, *hecReply.Code, hecReply.Text)
		}
		return &rejectedError{msg: fmt.Sprintf("POST %s refused the rows: %s: %s", endpoint, resp.Status, snippet(reply))}
	case resp.StatusCode < 200 || resp.StatusCode > 299:
		return fmt.Errorf("POST %s answered %s: %s", endpoint, resp.Status, snippet(reply))
	}
	// HEC answers {"text":"Success","code":0}; a JSON reply with another code
	// is a refusal, whatever the status line said.
	if t.hec && hecReply.Code != nil && *hecReply.Code != 0 {
		if hecContentCodes[*hecReply.Code] {
			return &rejectedError{msg: fmt.Sprintf("HEC at %s refused the rows: code %d (%s)", endpoint, *hecReply.Code, hecReply.Text)}
		}
		return fmt.Errorf("HEC at %s refused the batch: code %d (%s)", endpoint, *hecReply.Code, hecReply.Text)
	}
	return nil
}

// newChannelID is a random UUID (version 4), the shape HEC wants for a
// request channel.
func newChannelID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

func (t *httpsTransport) close() error {
	t.client.CloseIdleConnections()
	return nil
}

// redactedURL renders a sink URL for an error message.
func redactedURL(raw string) string {
	if i := strings.IndexAny(raw, "?#"); i >= 0 {
		return raw[:i]
	}
	return raw
}

// snippet renders the start of a refusal body for an error message.
func snippet(b []byte) string {
	s := strings.TrimSpace(string(b))
	if len(s) > 300 {
		s = s[:300] + "…"
	}
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, s)
}

// ── file ────────────────────────────────────────────────────────────────────

// fileTransport appends each batch to a file and fsyncs it: the copy an
// operator keeps on a volume the database does not share.
type fileTransport struct {
	path string
}

func (t *fileTransport) send(_ context.Context, msgs []message) error {
	if err := config.ValidateAuditForwardFile(t.path); err != nil {
		return err
	}
	if err := config.CheckOutsideCloopOnDisk(t.path); err != nil {
		return err
	}
	var buf bytes.Buffer
	for _, m := range msgs {
		buf.Write(m.data)
		buf.WriteByte('\n')
	}
	_, statErr := os.Stat(t.path)
	created := os.IsNotExist(statErr)
	// A directory that does not exist is an error rather than something to
	// create: a missing directory would otherwise turn "the copy goes to the
	// archive volume" into "the copy goes to the root disk".
	f, err := os.OpenFile(t.path, os.O_RDWR|os.O_APPEND|os.O_CREATE, 0o600)
	if err != nil {
		return fmt.Errorf("open %s: %w", t.path, err)
	}
	fi, err := f.Stat()
	if err != nil {
		f.Close() //nolint:errcheck
		return fmt.Errorf("stat %s: %w", t.path, err)
	}
	size := fi.Size()
	data := buf.Bytes()
	// A file that does not end in a newline holds the half of a line a
	// write cut short — a full disk, a crash. The next record starts on a
	// line of its own, or it would be read as part of that one.
	if size > 0 {
		last := make([]byte, 1)
		if _, err := f.ReadAt(last, size-1); err == nil && last[0] != '\n' {
			data = append([]byte{'\n'}, data...)
		}
	}
	// A batch that is not wholly written and fsynced is cut back off, so a
	// retry appends to the file as it was rather than after a fragment.
	fail := func(what string, err error) error {
		_ = f.Truncate(size)
		f.Close() //nolint:errcheck
		return fmt.Errorf("%s %s: %w", what, t.path, err)
	}
	if _, err := f.Write(data); err != nil {
		return fail("append to", err)
	}
	if err := f.Sync(); err != nil {
		return fail("fsync", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("close %s: %w", t.path, err)
	}
	if created {
		if d, err := os.Open(filepath.Dir(t.path)); err == nil {
			_ = d.Sync()
			d.Close() //nolint:errcheck
		}
	}
	return nil
}

func (t *fileTransport) close() error { return nil }
