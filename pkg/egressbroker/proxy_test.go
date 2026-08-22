package egressbroker

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/secretbroker"
)

// recordingAuditor collects events so a test can assert on the audit trail —
// which is half of what this package promises. A decision that is enforced
// but not recorded would pass every functional assertion below.
type recordingAuditor struct {
	mu     sync.Mutex
	events []secretbroker.Event
}

func (a *recordingAuditor) Audit(ev secretbroker.Event) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.events = append(a.events, ev)
}

func (a *recordingAuditor) all() []secretbroker.Event {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]secretbroker.Event(nil), a.events...)
}

// waitFor polls until cond holds or the limit elapses. Used instead of a
// fixed sleep for assertions on work done by the proxy's own goroutines.
func (a *recordingAuditor) waitFor(t *testing.T, limit time.Duration, cond func([]secretbroker.Event) bool) []secretbroker.Event {
	t.Helper()
	deadline := time.Now().Add(limit)
	for {
		evs := a.all()
		if cond(evs) {
			return evs
		}
		if time.Now().After(deadline) {
			t.Fatalf("condition not met within %s; %d events recorded:\n%s", limit, len(evs), renderEvents(evs))
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func renderEvents(evs []secretbroker.Event) string {
	var b strings.Builder
	for _, ev := range evs {
		b.WriteString("  " + ev.Fields() + "\n")
	}
	return b.String()
}

func findEvent(evs []secretbroker.Event, action secretbroker.Action, decision secretbroker.Decision) (secretbroker.Event, bool) {
	for _, ev := range evs {
		if ev.Action == action && ev.Decision == decision {
			return ev, true
		}
	}
	return secretbroker.Event{}, false
}

// ---------------------------------------------------------------------------
// fixtures
// ---------------------------------------------------------------------------

type fixture struct {
	broker  *Broker
	proxy   *Proxy
	audit   *recordingAuditor
	red     *Redemption
	dialLog *dialRecorder
}

// dialRecorder captures the address the proxy actually dialled, which is the
// only way to prove the resolve-once pin held.
type dialRecorder struct {
	mu    sync.Mutex
	addrs []string
	inner DialFunc
}

func (d *dialRecorder) dial(ctx context.Context, network, addr string) (net.Conn, error) {
	d.mu.Lock()
	d.addrs = append(d.addrs, addr)
	d.mu.Unlock()
	if d.inner != nil {
		return d.inner(ctx, network, addr)
	}
	return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, network, addr)
}

func (d *dialRecorder) seen() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]string(nil), d.addrs...)
}

// newFixture builds a broker, stores the grant, starts a proxy on loopback,
// and redeems a session against it.
func newFixture(t *testing.T, g Grant, opts Options) *fixture {
	t.Helper()

	audit := &recordingAuditor{}
	store := NewMemStore()
	b, err := New(store, WithAuditor(audit))
	if err != nil {
		t.Fatalf("new broker: %v", err)
	}

	sub, err := secretbroker.ParseSubject("project:/srv/app")
	if err != nil {
		t.Fatalf("subject: %v", err)
	}
	if _, err := b.Grant(context.Background(), GrantRequest{
		Subject:      sub,
		Hosts:        g.Hosts,
		CIDRs:        g.CIDRs,
		Ports:        g.Ports,
		Methods:      g.Methods,
		MaxBytesUp:   g.MaxBytesUp,
		MaxBytesDown: g.MaxBytesDown,
		SessionTTL:   g.SessionTTL,
		TTL:          time.Hour,
		Actor:        "test",
	}); err != nil {
		t.Fatalf("grant: %v", err)
	}

	rec := &dialRecorder{inner: opts.Dial}
	opts.Dial = rec.dial
	if opts.ListenAddr == "" {
		opts.ListenAddr = "127.0.0.1:0"
	}
	p, err := NewProxy(b, opts)
	if err != nil {
		t.Fatalf("new proxy: %v", err)
	}
	serveErr := make(chan error, 1)
	go func() { serveErr <- p.ListenAndServe() }()
	t.Cleanup(func() {
		_ = p.Close()
		select {
		case err := <-serveErr:
			if err != nil {
				t.Errorf("serve: %v", err)
			}
		case <-time.After(2 * time.Second):
			t.Error("proxy did not stop")
		}
	})

	deadline := time.Now().Add(2 * time.Second)
	for p.Addr() == "" && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if p.Addr() == "" {
		t.Fatal("proxy never bound")
	}

	red, err := b.Redeem(context.Background(), RedeemRequest{
		Requester: secretbroker.Requester{ExecutorID: "exec-1", ProjectID: "/srv/app"},
		TaskID:    "20163",
		Actor:     "test",
	})
	if err != nil {
		t.Fatalf("redeem: %v", err)
	}
	return &fixture{broker: b, proxy: p, audit: audit, red: red, dialLog: rec}
}

// client returns an HTTP client routed through the proxy with the session's
// credential, optionally reusing an origin's TLS configuration.
func (f *fixture) client(t *testing.T, base *http.Client) *http.Client {
	t.Helper()
	proxyURL, err := url.Parse(f.red.ProxyURL)
	if err != nil {
		t.Fatalf("parse proxy url: %v", err)
	}
	tr := &http.Transport{Proxy: http.ProxyURL(proxyURL), DisableKeepAlives: true}
	if base != nil {
		if bt, ok := base.Transport.(*http.Transport); ok && bt.TLSClientConfig != nil {
			tr.TLSClientConfig = bt.TLSClientConfig.Clone()
		}
	}
	c := &http.Client{Transport: tr, Timeout: 10 * time.Second}
	t.Cleanup(c.CloseIdleConnections)
	return c
}

// portOf extracts the port from an httptest server URL.
func portOf(t *testing.T, rawURL string) int {
	t.Helper()
	u, err := url.Parse(rawURL)
	if err != nil {
		t.Fatalf("parse %q: %v", rawURL, err)
	}
	p, err := strconv.Atoi(u.Port())
	if err != nil {
		t.Fatalf("port of %q: %v", rawURL, err)
	}
	return p
}

// loopbackGrant is the shape every round-trip test needs: the origin runs on
// 127.0.0.1, which the SSRF guard blocks by default, so the test opts in with
// an explicit CIDR — exercising the opt-in path rather than working around it.
func loopbackGrant(port int) Grant {
	return Grant{
		Hosts: []string{"127.0.0.1", "example.com"},
		CIDRs: []string{"127.0.0.0/8"},
		Ports: []int{port},
	}
}

// ---------------------------------------------------------------------------
// round trips
// ---------------------------------------------------------------------------

func TestPlainHTTPRoundTrip(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// The session credential must never reach the origin: forwarding it
		// would hand every visited site a working key to the proxy.
		if got := r.Header.Get("Proxy-Authorization"); got != "" {
			t.Errorf("origin received Proxy-Authorization %q", got)
		}
		fmt.Fprintf(w, "hello %s", r.URL.Path)
	}))
	defer origin.Close()

	f := newFixture(t, loopbackGrant(portOf(t, origin.URL)), Options{})
	resp, err := f.client(t, nil).Get(origin.URL + "/world")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK || string(body) != "hello /world" {
		t.Fatalf("got %d %q", resp.StatusCode, body)
	}

	evs := f.audit.waitFor(t, 2*time.Second, func(evs []secretbroker.Event) bool {
		_, ok := findEvent(evs, secretbroker.ActionEgressRequest, secretbroker.DecisionAllow)
		return ok
	})
	ev, _ := findEvent(evs, secretbroker.ActionEgressRequest, secretbroker.DecisionAllow)
	if ev.Host != "127.0.0.1" || ev.Port != portOf(t, origin.URL) {
		t.Errorf("audit row should name the destination, got host=%q port=%d", ev.Host, ev.Port)
	}
	if ev.TaskID != "20163" || ev.ExecutorID != "exec-1" {
		t.Errorf("audit row should carry the identity, got task=%q executor=%q", ev.TaskID, ev.ExecutorID)
	}
	if ev.BytesDown <= 0 {
		t.Errorf("audit row should carry the byte count, got %d", ev.BytesDown)
	}
	// No audit row may contain the session token.
	for _, e := range evs {
		if strings.Contains(e.Reason, f.red.Token) || strings.Contains(e.Constraints, f.red.Token) {
			t.Fatalf("audit event leaked the proxy token: %s", e.Fields())
		}
	}
}

func TestConnectTunnelRoundTrip(t *testing.T) {
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "tunnelled")
	}))
	defer origin.Close()

	f := newFixture(t, loopbackGrant(portOf(t, origin.URL)), Options{})
	resp, err := f.client(t, origin.Client()).Get(origin.URL)
	if err != nil {
		t.Fatalf("GET over CONNECT: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if string(body) != "tunnelled" {
		t.Fatalf("body = %q", body)
	}

	evs := f.audit.waitFor(t, 2*time.Second, func(evs []secretbroker.Event) bool {
		_, ok := findEvent(evs, secretbroker.ActionEgressConnect, secretbroker.DecisionAllow)
		return ok
	})
	ev, _ := findEvent(evs, secretbroker.ActionEgressConnect, secretbroker.DecisionAllow)
	if ev.Host != "127.0.0.1" {
		t.Errorf("connect row should name the host, got %q", ev.Host)
	}
	// The tunnel is CA-free: the client validated the origin's own
	// certificate, so nothing in the proxy re-signed it. If it had, the
	// httptest client's pool would have rejected the handshake above.
	if resp.TLS == nil {
		t.Error("expected a real TLS session end to end")
	}
}

// TestConnectTunnelByNameResolvesOnce drives the full stack through a
// hostname, so the resolve-once pin is exercised on a real socket rather than
// only in Resolve's unit test. example.com is used because httptest's
// certificate is issued for it, which keeps TLS validation genuine.
func TestConnectTunnelByNameResolvesOnce(t *testing.T) {
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "by-name")
	}))
	defer origin.Close()
	port := portOf(t, origin.URL)

	resolver := &fakeResolver{answers: [][]string{
		{"127.0.0.1"},   // approved and pinned
		{"10.99.99.99"}, // the rebind, never consulted
	}}
	f := newFixture(t, loopbackGrant(port), Options{Resolver: resolver})

	resp, err := f.client(t, origin.Client()).Get(fmt.Sprintf("https://example.com:%d/", port))
	if err != nil {
		t.Fatalf("GET by name: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "by-name" {
		t.Fatalf("body = %q", body)
	}

	if n := resolver.calls.Load(); n != 1 {
		t.Fatalf("resolved %d times, want exactly 1", n)
	}
	dialed := f.dialLog.seen()
	if len(dialed) != 1 || dialed[0] != fmt.Sprintf("127.0.0.1:%d", port) {
		t.Fatalf("dialled %v, want the pinned literal", dialed)
	}
}

// TestRebindingAnswerIsRefusedUpFront: when the *first* answer is inward, the
// connection never happens at all.
func TestRebindingAnswerIsRefusedUpFront(t *testing.T) {
	resolver := &fakeResolver{answers: [][]string{{"169.254.169.254"}}}
	f := newFixture(t, Grant{Hosts: []string{"*"}, Ports: []int{80}}, Options{Resolver: resolver})

	resp, err := f.client(t, nil).Get("http://metadata.example/latest/meta-data/")
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", resp.StatusCode)
	}
	if v := resp.Header.Get("X-Cloop-Egress-Verdict"); v != "destination_blocked" {
		t.Fatalf("verdict = %q, want destination_blocked", v)
	}
	if got := f.dialLog.seen(); len(got) != 0 {
		t.Fatalf("a blocked destination must never be dialled, got %v", got)
	}
}

// ---------------------------------------------------------------------------
// refusals
// ---------------------------------------------------------------------------

func TestUnauthenticatedRequestsAreRefused(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("origin must not be reached without a credential")
	}))
	defer origin.Close()

	f := newFixture(t, loopbackGrant(portOf(t, origin.URL)), Options{})

	cases := []struct {
		name string
		auth string
	}{
		{"missing", ""},
		{"wrong scheme", "Bearer " + f.red.Token},
		{"unknown session", FormatProxyCredential("sess_deadbeef", f.red.Token)},
		{"wrong token", FormatProxyCredential(f.red.Session.ID, "0000")},
		{"not base64", "Basic !!!!"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req, err := http.NewRequest(http.MethodGet, origin.URL, nil)
			if err != nil {
				t.Fatal(err)
			}
			req.URL.Scheme = "http"
			proxyURL, _ := url.Parse("http://" + f.proxy.Addr())
			tr := &http.Transport{
				Proxy:             http.ProxyURL(proxyURL),
				DisableKeepAlives: true,
				ProxyConnectHeader: http.Header{},
			}
			if tc.auth != "" {
				req.Header.Set("Proxy-Authorization", tc.auth)
			}
			resp, err := tr.RoundTrip(req)
			if err != nil {
				t.Fatalf("round trip: %v", err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusProxyAuthRequired {
				t.Fatalf("status = %d, want 407", resp.StatusCode)
			}
			if resp.Header.Get("Proxy-Authenticate") == "" {
				t.Error("a 407 must carry a challenge")
			}
		})
	}
}

func TestPolicyRefusals(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "reached")
	}))
	defer origin.Close()
	port := portOf(t, origin.URL)

	tests := []struct {
		name    string
		grant   Grant
		target  string
		verdict string
	}{
		{
			// No CIDRs, so the name check is the whole gate and fires before
			// any lookup or dial.
			name:    "host not allowed",
			grant:   Grant{Hosts: []string{"allowed.test"}, Ports: []int{port}},
			target:  origin.URL,
			verdict: "host_not_allowed",
		},
		{
			name:    "port not allowed",
			grant:   Grant{Hosts: []string{"127.0.0.1"}, CIDRs: []string{"127.0.0.0/8"}, Ports: []int{9}},
			target:  origin.URL,
			verdict: "port_not_allowed",
		},
		{
			name:    "method not allowed",
			grant:   Grant{Hosts: []string{"127.0.0.1"}, CIDRs: []string{"127.0.0.0/8"}, Ports: []int{port}, Methods: []string{"POST"}},
			target:  origin.URL,
			verdict: "method_not_allowed",
		},
		{
			// The SSRF guard on a real socket: the allowlist says everything,
			// and loopback is still refused because no CIDR opts in.
			name:    "loopback without a cidr opt-in",
			grant:   Grant{Hosts: []string{"*"}, Ports: []int{port}},
			target:  origin.URL,
			verdict: "destination_blocked",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t, tc.grant, Options{})
			resp, err := f.client(t, nil).Get(tc.target)
			if err != nil {
				t.Fatalf("request: %v", err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusForbidden {
				t.Fatalf("status = %d, want 403", resp.StatusCode)
			}
			if v := resp.Header.Get("X-Cloop-Egress-Verdict"); v != tc.verdict {
				t.Fatalf("verdict = %q, want %q", v, tc.verdict)
			}
			if got := f.dialLog.seen(); len(got) != 0 {
				t.Errorf("a refused request must not dial, got %v", got)
			}
			evs := f.audit.waitFor(t, 2*time.Second, func(evs []secretbroker.Event) bool {
				_, ok := findEvent(evs, secretbroker.ActionEgressRequest, secretbroker.DecisionDeny)
				return ok
			})
			ev, _ := findEvent(evs, secretbroker.ActionEgressRequest, secretbroker.DecisionDeny)
			if ev.Reason == "" {
				t.Error("a denial row must carry a reason")
			}
		})
	}
}

// ---------------------------------------------------------------------------
// quota and expiry
// ---------------------------------------------------------------------------

// TestQuotaCutoffMidStream: a download larger than the budget is torn down
// while it is in flight, and no more than the budget is delivered.
func TestQuotaCutoffMidStream(t *testing.T) {
	const bodySize = 1 << 20 // 1 MiB
	const budget = 64 << 10  // 64 KiB

	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", strconv.Itoa(bodySize))
		w.WriteHeader(http.StatusOK)
		chunk := make([]byte, 4096)
		for sent := 0; sent < bodySize; sent += len(chunk) {
			if _, err := w.Write(chunk); err != nil {
				return
			}
		}
	}))
	defer origin.Close()

	g := loopbackGrant(portOf(t, origin.URL))
	g.MaxBytesDown = budget
	f := newFixture(t, g, Options{})

	resp, err := f.client(t, nil).Get(origin.URL)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()

	n, readErr := io.Copy(io.Discard, resp.Body)
	if readErr == nil && n == bodySize {
		t.Fatal("the whole body was delivered; the quota did nothing")
	}
	if n > budget {
		t.Fatalf("delivered %d bytes, which is more than the %d budget", n, budget)
	}

	evs := f.audit.waitFor(t, 2*time.Second, func(evs []secretbroker.Event) bool {
		ev, ok := findEvent(evs, secretbroker.ActionEgressRequest, secretbroker.DecisionDeny)
		return ok && strings.Contains(ev.Reason, "quota")
	})
	ev, _ := findEvent(evs, secretbroker.ActionEgressRequest, secretbroker.DecisionDeny)
	if !strings.Contains(ev.Reason, "download budget") {
		t.Errorf("denial reason should name the budget, got %q", ev.Reason)
	}

	// The session is spent: a second request is refused before it starts.
	resp2, err := f.client(t, nil).Get(origin.URL)
	if err != nil {
		t.Fatalf("second GET: %v", err)
	}
	defer resp2.Body.Close()
	if v := resp2.Header.Get("X-Cloop-Egress-Verdict"); v != "quota_exceeded" {
		t.Fatalf("second request verdict = %q, want quota_exceeded", v)
	}
}

// TestSessionExpiresMidTunnel: an open CONNECT tunnel does not outlive its
// lease, including when it is idle.
func TestSessionExpiresMidTunnel(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go func() {
		for {
			c, aerr := ln.Accept()
			if aerr != nil {
				return
			}
			go func() { _, _ = io.Copy(c, c); _ = c.Close() }()
		}
	}()

	_, portStr, _ := net.SplitHostPort(ln.Addr().String())
	port, _ := strconv.Atoi(portStr)

	g := loopbackGrant(port)
	g.SessionTTL = 600 * time.Millisecond
	f := newFixture(t, g, Options{})

	conn, err := net.Dial("tcp", f.proxy.Addr())
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()

	target := fmt.Sprintf("127.0.0.1:%d", port)
	fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\nProxy-Authorization: %s\r\n\r\n",
		target, target, FormatProxyCredential(f.red.Session.ID, f.red.Token))

	br := bufio.NewReader(conn)
	statusLine, err := br.ReadString('\n')
	if err != nil {
		t.Fatalf("read CONNECT response: %v", err)
	}
	if !strings.Contains(statusLine, "200") {
		t.Fatalf("CONNECT response = %q", statusLine)
	}
	// Drain the blank line terminating the response headers.
	for {
		line, rerr := br.ReadString('\n')
		if rerr != nil {
			t.Fatalf("read headers: %v", rerr)
		}
		if strings.TrimSpace(line) == "" {
			break
		}
	}

	// The tunnel works while the session is live.
	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatalf("write: %v", err)
	}
	echo := make([]byte, 4)
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := io.ReadFull(br, echo); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if string(echo) != "ping" {
		t.Fatalf("echo = %q", echo)
	}

	// Then it dies at the TTL, with nothing else happening on it.
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := br.ReadByte(); err == nil {
		t.Fatal("tunnel outlived its session")
	}

	evs := f.audit.waitFor(t, 3*time.Second, func(evs []secretbroker.Event) bool {
		ev, ok := findEvent(evs, secretbroker.ActionEgressClose, secretbroker.DecisionDeny)
		return ok && strings.Contains(ev.Reason, "expired mid-tunnel")
	})
	ev, _ := findEvent(evs, secretbroker.ActionEgressClose, secretbroker.DecisionDeny)
	if ev.Host != "127.0.0.1" || ev.Port != port {
		t.Errorf("close row should name the destination, got %s:%d", ev.Host, ev.Port)
	}
	if ev.BytesUp != 4 || ev.BytesDown != 4 {
		t.Errorf("close row should carry the transfer totals, got up=%d down=%d", ev.BytesUp, ev.BytesDown)
	}
}

// ---------------------------------------------------------------------------
// lifecycle
// ---------------------------------------------------------------------------

func TestRevokeClosesLiveSessions(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "ok")
	}))
	defer origin.Close()

	f := newFixture(t, loopbackGrant(portOf(t, origin.URL)), Options{})
	if resp, err := f.client(t, nil).Get(origin.URL); err != nil {
		t.Fatalf("pre-revoke GET: %v", err)
	} else {
		resp.Body.Close()
	}

	if err := f.broker.Revoke(context.Background(), f.red.Session.GrantID, "test"); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if !f.red.Session.Closed() {
		t.Fatal("revocation must close the live session immediately")
	}

	resp, err := f.client(t, nil).Get(origin.URL)
	if err != nil {
		t.Fatalf("post-revoke GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusProxyAuthRequired {
		t.Fatalf("status after revoke = %d, want 407", resp.StatusCode)
	}
}

func TestMalformedConnectTargetIsRefused(t *testing.T) {
	f := newFixture(t, Grant{Hosts: []string{"*"}, Ports: []int{443}}, Options{})

	conn, err := net.Dial("tcp", f.proxy.Addr())
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()

	fmt.Fprintf(conn, "CONNECT example.com HTTP/1.1\r\nHost: example.com\r\nProxy-Authorization: %s\r\n\r\n",
		FormatProxyCredential(f.red.Session.ID, f.red.Token))

	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 for a portless CONNECT target", resp.StatusCode)
	}
	if v := resp.Header.Get("X-Cloop-Egress-Verdict"); v != "malformed_request" {
		t.Errorf("verdict = %q", v)
	}
}

// TestHTTPSAbsoluteURIIsRefused: an https:// absolute-URI on the plain-HTTP
// path would mean the proxy terminating TLS, which it never does.
func TestHTTPSAbsoluteURIIsRefused(t *testing.T) {
	f := newFixture(t, Grant{Hosts: []string{"*"}, Ports: []int{443}}, Options{})

	conn, err := net.Dial("tcp", f.proxy.Addr())
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()

	fmt.Fprintf(conn, "GET https://example.com/ HTTP/1.1\r\nHost: example.com\r\nProxy-Authorization: %s\r\n\r\n",
		FormatProxyCredential(f.red.Session.ID, f.red.Token))

	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
}

func TestSanitizeHeadersDropsHopByHop(t *testing.T) {
	in := http.Header{
		"Proxy-Authorization": {"Basic secret"},
		"Connection":          {"X-Custom, Keep-Alive"},
		"X-Custom":            {"dropped by Connection"},
		"X-Keep":              {"kept"},
		"Transfer-Encoding":   {"chunked"},
	}
	out := sanitizeHeaders(in)
	for _, k := range []string{"Proxy-Authorization", "Connection", "X-Custom", "Transfer-Encoding"} {
		if _, ok := out[http.CanonicalHeaderKey(k)]; ok {
			t.Errorf("%s should have been dropped", k)
		}
	}
	if out.Get("X-Keep") != "kept" {
		t.Error("end-to-end headers must survive")
	}
	// The input must not be mutated: it is the live request's header map.
	if in.Get("Proxy-Authorization") == "" {
		t.Error("sanitizeHeaders must not mutate its input")
	}
}

func TestSplitHostPort(t *testing.T) {
	tests := []struct {
		in       string
		defPort  int
		wantHost string
		wantPort int
		wantErr  bool
	}{
		{"example.com:8080", 80, "example.com", 8080, false},
		{"example.com", 80, "example.com", 80, false},
		{"EXAMPLE.com.", 80, "example.com", 80, false},
		{"[2001:db8::1]:443", 80, "2001:db8::1", 443, false},
		{"example.com:0", 80, "", 0, true},
		{"example.com:70000", 80, "", 0, true},
		{"", 80, "", 0, true},
	}
	for _, tc := range tests {
		host, port, err := splitHostPort(tc.in, tc.defPort)
		if (err != nil) != tc.wantErr {
			t.Errorf("splitHostPort(%q) error = %v, wantErr %v", tc.in, err, tc.wantErr)
			continue
		}
		if err == nil && (host != tc.wantHost || port != tc.wantPort) {
			t.Errorf("splitHostPort(%q) = %q,%d want %q,%d", tc.in, host, port, tc.wantHost, tc.wantPort)
		}
	}
}

// TestVerdictOfCoversEveryDenialSentinel keeps the header vocabulary and the
// error set from drifting apart: a new sentinel without a verdict would
// silently report itself as the generic "denied".
func TestVerdictOfCoversEveryDenialSentinel(t *testing.T) {
	for _, sentinel := range []error{
		ErrHostNotAllowed, ErrPortNotAllowed, ErrMethodNotAllowed,
		ErrDestinationBlocked, ErrQuotaExceeded, ErrSessionExpired,
		ErrUnauthenticated, ErrResolveFailed, ErrDialFailed, ErrInvalidRequest,
	} {
		wrapped := fmt.Errorf("context: %w", sentinel)
		if v := verdictOf(wrapped); v == "denied" || v == "allow" {
			t.Errorf("%v has no distinct verdict (got %q)", sentinel, v)
		}
	}
	if verdictOf(nil) != "allow" {
		t.Error("a nil error is an allow")
	}
	if verdictOf(errors.New("something else")) != "denied" {
		t.Error("an unclassified error should fall back to denied")
	}
}

// TestTLSHandshakeIsNotIntercepted proves the tunnel is CA-free: the client
// trusts only the origin's own test CA, so a proxy that re-signed would fail
// the handshake rather than silently succeed.
func TestTLSHandshakeIsNotIntercepted(t *testing.T) {
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "ok")
	}))
	defer origin.Close()

	f := newFixture(t, loopbackGrant(portOf(t, origin.URL)), Options{})
	client := f.client(t, origin.Client())

	tr := client.Transport.(*http.Transport)
	if tr.TLSClientConfig == nil || tr.TLSClientConfig.RootCAs == nil {
		t.Skip("httptest client exposes no pinned root pool on this Go version")
	}
	tr.TLSClientConfig.InsecureSkipVerify = false

	resp, err := client.Get(origin.URL)
	if err != nil {
		t.Fatalf("handshake through the tunnel failed, which means it was intercepted: %v", err)
	}
	defer resp.Body.Close()
	if resp.TLS == nil || resp.TLS.Version < tls.VersionTLS12 {
		t.Error("expected a genuine TLS session")
	}
}

// TestBlockedDestinationsUnreachableViaLiteralConnect walks the SSRF matrix
// through a live proxy rather than through BlockReason alone.
func TestBlockedDestinationsUnreachableViaLiteralConnect(t *testing.T) {
	f := newFixture(t, Grant{Hosts: []string{"*"}, Ports: []int{80, 443}}, Options{})

	for _, target := range []string{
		"127.0.0.1:443", "10.0.0.1:443", "192.168.1.1:443",
		"169.254.169.254:80", "[::1]:443", "[::ffff:127.0.0.1]:443",
		"0.0.0.0:80", "100.64.0.1:443",
	} {
		t.Run(target, func(t *testing.T) {
			conn, err := net.Dial("tcp", f.proxy.Addr())
			if err != nil {
				t.Fatalf("dial proxy: %v", err)
			}
			defer conn.Close()

			fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\nProxy-Authorization: %s\r\n\r\n",
				target, target, FormatProxyCredential(f.red.Session.ID, f.red.Token))

			resp, rerr := http.ReadResponse(bufio.NewReader(conn), nil)
			if rerr != nil {
				t.Fatalf("read response: %v", rerr)
			}
			defer resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				t.Fatalf("%s was tunnelled; it must be blocked", target)
			}
			if v := resp.Header.Get("X-Cloop-Egress-Verdict"); v != "destination_blocked" {
				t.Errorf("verdict for %s = %q, want destination_blocked", target, v)
			}
		})
	}
	if got := f.dialLog.seen(); len(got) != 0 {
		t.Errorf("no blocked destination may be dialled, got %v", got)
	}
}

// TestCloseDrainsInFlightHandlers pins the shutdown ordering that a real
// `cloop egress test` run exposed: the proxy killed the connection, the
// handler wrote its audit row afterwards, and by then the caller had closed
// the database. The decision was enforced but not recorded, which is the one
// outcome this package is supposed to make impossible.
func TestCloseDrainsInFlightHandlers(t *testing.T) {
	release := make(chan struct{})
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		<-release // hold the handler open until the test says otherwise
	}))
	defer origin.Close()
	defer close(release)

	f := newFixture(t, loopbackGrant(portOf(t, origin.URL)), Options{})

	started := make(chan struct{})
	go func() {
		close(started)
		resp, err := f.client(t, nil).Get(origin.URL)
		if err == nil {
			resp.Body.Close()
		}
	}()
	<-started

	// Wait until the proxy has actually dialled the origin, so there really
	// is a handler in flight when Close runs.
	deadline := time.Now().Add(3 * time.Second)
	for len(f.dialLog.seen()) == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if len(f.dialLog.seen()) == 0 {
		t.Skip("proxy never dialled; nothing in flight to drain")
	}

	before := len(f.audit.all())
	if err := f.proxy.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	// By the time Close returns, the handler must have finished reporting —
	// no polling, because the whole point is that the caller may now close
	// the audit sink.
	if after := len(f.audit.all()); after <= before {
		t.Fatalf("Close returned with %d audit rows, same as before; the handler's row was lost", after)
	}

	// A request arriving after Close is refused without becoming a denial.
	resp, err := f.client(t, nil).Get(origin.URL)
	if err == nil {
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusServiceUnavailable {
			t.Errorf("post-close status = %d, want 503", resp.StatusCode)
		}
	}
}

// echoListener starts a raw TCP echo server, for the tunnel tests that need
// a long-lived connection rather than an HTTP exchange.
func echoListener(t *testing.T) (net.Listener, int) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, aerr := ln.Accept()
			if aerr != nil {
				return
			}
			go func() { _, _ = io.Copy(c, c); _ = c.Close() }()
		}
	}()
	_, portStr, _ := net.SplitHostPort(ln.Addr().String())
	port, _ := strconv.Atoi(portStr)
	return ln, port
}

// openTunnel establishes a CONNECT tunnel through the proxy and returns the
// client side plus its buffered reader.
func openTunnel(t *testing.T, f *fixture, port int) (net.Conn, *bufio.Reader) {
	t.Helper()
	conn, err := net.Dial("tcp", f.proxy.Addr())
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	target := fmt.Sprintf("127.0.0.1:%d", port)
	fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\nProxy-Authorization: %s\r\n\r\n",
		target, target, FormatProxyCredential(f.red.Session.ID, f.red.Token))

	br := bufio.NewReader(conn)
	status, err := br.ReadString('\n')
	if err != nil || !strings.Contains(status, "200") {
		t.Fatalf("CONNECT failed: %q (%v)", status, err)
	}
	for {
		line, rerr := br.ReadString('\n')
		if rerr != nil {
			t.Fatalf("read headers: %v", rerr)
		}
		if strings.TrimSpace(line) == "" {
			break
		}
	}
	// Prove the tunnel carries traffic before the test does anything to it.
	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatalf("write: %v", err)
	}
	echo := make([]byte, 4)
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.ReadFull(br, echo); err != nil || string(echo) != "ping" {
		t.Fatalf("echo = %q (%v)", echo, err)
	}
	return conn, br
}

// TestRevokeSeversAnOpenTunnel is the claim the README and the CLI both make:
// revocation is immediate rather than bounded by the session TTL.
//
// Marking the session closed and dropping it from the registry only stops the
// *next* request. A tunnel that is already moving bytes — the exfiltration
// case revocation exists for — keeps moving them unless the socket itself is
// closed, which is why Session tracks its connections.
func TestRevokeSeversAnOpenTunnel(t *testing.T) {
	_, port := echoListener(t)

	g := loopbackGrant(port)
	g.SessionTTL = time.Hour // long, so only revocation can end this
	f := newFixture(t, g, Options{})

	conn, br := openTunnel(t, f, port)

	if err := f.broker.Revoke(context.Background(), f.red.Session.GrantID, "op"); err != nil {
		t.Fatalf("revoke: %v", err)
	}

	// The tunnel must die now, not in an hour.
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := br.ReadByte(); err == nil {
		t.Fatal("tunnel survived revocation; a brokered capability must be recallable")
	}
	if _, err := conn.Write([]byte("more")); err == nil {
		if _, err := br.ReadByte(); err == nil {
			t.Fatal("tunnel still carries traffic after revocation")
		}
	}

	evs := f.audit.waitFor(t, 3*time.Second, func(evs []secretbroker.Event) bool {
		_, ok := findEvent(evs, secretbroker.ActionEgressClose, secretbroker.DecisionDeny)
		return ok
	})
	ev, _ := findEvent(evs, secretbroker.ActionEgressClose, secretbroker.DecisionDeny)
	if !strings.Contains(ev.Reason, "mid-tunnel") {
		t.Errorf("the severed tunnel should be audited as such, got %q", ev.Reason)
	}
}

// TestCloseSeversOpenTunnelsPromptly: http.Server.Close does not touch a
// hijacked connection, so without the proxy's own registry a shutdown would
// leave every tunnel running *and* wedge the audit drain until it timed out.
func TestCloseSeversOpenTunnelsPromptly(t *testing.T) {
	_, port := echoListener(t)

	g := loopbackGrant(port)
	g.SessionTTL = time.Hour
	f := newFixture(t, g, Options{})

	conn, br := openTunnel(t, f, port)

	start := time.Now()
	if err := f.proxy.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	elapsed := time.Since(start)

	// The drain must complete, not time out: a wedged handler would take the
	// full drainTimeout and write its audit row after the caller had closed
	// the database.
	if elapsed >= drainTimeout {
		t.Fatalf("Close took %s (>= the %s drain timeout), so the tunnel handler never returned", elapsed, drainTimeout)
	}
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := br.ReadByte(); err == nil {
		t.Fatal("tunnel outlived the proxy that was supposed to be its only route out")
	}
	// Close returning means the handler finished reporting, so the row is
	// already there — no polling.
	if _, ok := findEvent(f.audit.all(), secretbroker.ActionEgressClose, secretbroker.DecisionAllow); !ok {
		if _, ok := findEvent(f.audit.all(), secretbroker.ActionEgressClose, secretbroker.DecisionDeny); !ok {
			t.Fatalf("no close row after shutdown:\n%s", renderEvents(f.audit.all()))
		}
	}
}

// TestSessionTTLBoundsAPlainHTTPStream: the plain-HTTP path has no socket to
// put a deadline on, so without an explicit session-bound context a workload
// could hold an endless response open from an allowed host indefinitely.
func TestSessionTTLBoundsAPlainHTTPStream(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		flusher, _ := w.(http.Flusher)
		// An endless trickle: bounded only by the client giving up.
		for i := 0; i < 600; i++ {
			if _, err := w.Write([]byte("x")); err != nil {
				return
			}
			if flusher != nil {
				flusher.Flush()
			}
			time.Sleep(20 * time.Millisecond)
		}
	}))
	defer origin.Close()

	g := loopbackGrant(portOf(t, origin.URL))
	g.SessionTTL = 700 * time.Millisecond
	f := newFixture(t, g, Options{})

	start := time.Now()
	resp, err := f.client(t, nil).Get(origin.URL)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	elapsed := time.Since(start)

	// Generous slack for scheduling, but far short of the origin's 12s.
	if elapsed > 4*time.Second {
		t.Fatalf("the stream ran %s, past the %s session TTL", elapsed, g.SessionTTL)
	}
}

// TestUnauthenticatedResponsesAreIndistinguishable: the constant-time compare
// in Authenticate is defeated if the response body says which half was wrong.
func TestUnauthenticatedResponsesAreIndistinguishable(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer origin.Close()
	f := newFixture(t, loopbackGrant(portOf(t, origin.URL)), Options{})

	probe := func(auth string) (int, string) {
		t.Helper()
		req, err := http.NewRequest(http.MethodGet, origin.URL, nil)
		if err != nil {
			t.Fatal(err)
		}
		if auth != "" {
			req.Header.Set("Proxy-Authorization", auth)
		}
		proxyURL, _ := url.Parse("http://" + f.proxy.Addr())
		tr := &http.Transport{Proxy: http.ProxyURL(proxyURL), DisableKeepAlives: true}
		resp, err := tr.RoundTrip(req)
		if err != nil {
			t.Fatalf("round trip: %v", err)
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(body)
	}

	// A live session ID with the wrong token, versus an ID that does not
	// exist at all. Telling these apart is a live-session oracle.
	wrongToken := FormatProxyCredential(f.red.Session.ID, strings.Repeat("0", TokenBytes*2))
	unknownID := FormatProxyCredential("sess_000000000000000000000000", strings.Repeat("0", TokenBytes*2))

	s1, b1 := probe(wrongToken)
	s2, b2 := probe(unknownID)
	s3, b3 := probe("")

	if s1 != s2 || s2 != s3 {
		t.Fatalf("statuses differ: %d / %d / %d", s1, s2, s3)
	}
	if b1 != b2 || b2 != b3 {
		t.Fatalf("bodies differ and leak which check failed:\n  wrong token: %q\n  unknown id:  %q\n  missing:     %q", b1, b2, b3)
	}
}

// TestOutOfRangeUpstreamStatusIsRefusedNotPanicked: http.ReadResponse accepts
// any three-digit status, WriteHeader panics below 100, and a panicking
// handler writes no audit row for a request it had already authorised and
// executed.
func TestOutOfRangeUpstreamStatusIsRefusedNotPanicked(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go func() {
		for {
			c, aerr := ln.Accept()
			if aerr != nil {
				return
			}
			go func() {
				_, _ = bufio.NewReader(c).ReadString('\n') // consume the request line
				_, _ = io.WriteString(c, "HTTP/1.1 099 nonsense\r\nContent-Length: 0\r\n\r\n")
				_ = c.Close()
			}()
		}
	}()
	_, portStr, _ := net.SplitHostPort(ln.Addr().String())
	port, _ := strconv.Atoi(portStr)

	f := newFixture(t, loopbackGrant(port), Options{})
	resp, err := f.client(t, nil).Get(fmt.Sprintf("http://127.0.0.1:%d/", port))
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502", resp.StatusCode)
	}

	// The point of the fix: the decision is still recorded.
	f.audit.waitFor(t, 2*time.Second, func(evs []secretbroker.Event) bool {
		ev, ok := findEvent(evs, secretbroker.ActionEgressRequest, secretbroker.DecisionDeny)
		return ok && strings.Contains(ev.Reason, "out-of-range status")
	})
}

// TestUploadQuotaDoesNotOvershoot: the request-body meter must refuse the
// over-quota bytes rather than hand them to io.Copy with an error attached,
// which delivers them to the origin first.
func TestUploadQuotaDoesNotOvershoot(t *testing.T) {
	const budget = 1024

	var received atomic.Int64
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n, _ := io.Copy(io.Discard, r.Body)
		received.Add(n)
		w.WriteHeader(http.StatusOK)
	}))
	defer origin.Close()

	g := loopbackGrant(portOf(t, origin.URL))
	g.MaxBytesUp = budget
	f := newFixture(t, g, Options{})

	body := strings.NewReader(strings.Repeat("A", 256<<10))
	resp, err := f.client(t, nil).Post(origin.URL, "application/octet-stream", body)
	if err == nil {
		defer resp.Body.Close()
		_, _ = io.Copy(io.Discard, resp.Body)
	}

	// Whatever the client saw, the origin must not have received more than
	// the budget allowed.
	if got := received.Load(); got > budget {
		t.Fatalf("origin received %d bytes, which exceeds the %d upload budget", got, budget)
	}
}

// TestNormalizeAddrUnwrapsEmbeddedIPv4 is a direct check on the helper the
// matrix depends on, so a failure points at the unwrapping rather than at
// eight table rows at once.
func TestNormalizeAddrUnwrapsEmbeddedIPv4(t *testing.T) {
	tests := map[string]string{
		"::ffff:127.0.0.1": "127.0.0.1",
		"64:ff9b::7f00:1":  "127.0.0.1",
		"::127.0.0.1":      "127.0.0.1",
		"2001:db8::1":      "2001:db8::1",
		"::1":              "::1",
		"::":               "::",
	}
	for in, want := range tests {
		if got := normalizeAddr(netip.MustParseAddr(in)).String(); got != want {
			t.Errorf("normalizeAddr(%s) = %s, want %s", in, got, want)
		}
	}
}
