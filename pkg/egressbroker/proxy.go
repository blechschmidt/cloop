package egressbroker

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/blechschmidt/cloop/pkg/secretbroker"
)

// proxy.go is the enforcement point: an authenticated HTTP forward proxy
// speaking CONNECT for TLS and absolute-URI requests for plain HTTP.
//
// Nothing here decides policy. Every verdict comes from the Grant snapshot on
// the authenticated Session, so the wire format and the security model can be
// reviewed independently — and the security model can be tested without a
// socket, which is why grant_test.go and netguard_test.go have no listener in
// them.

// DefaultListenAddr binds loopback only.
//
// This is the safe default and frequently the wrong one, which is worth being
// explicit about: a container on a bridge network cannot reach the host's
// loopback, so an operator running sandboxes will set an address the sandbox
// can route to (a podman gateway, a docker0 address) — and at that moment the
// proxy becomes reachable by anything else on that network too. The
// authentication is what holds there, not the bind address.
const DefaultListenAddr = "127.0.0.1:0"

const (
	// defaultDialTimeout bounds the connection to an authorised origin.
	defaultDialTimeout = 15 * time.Second
	// defaultReadHeaderTimeout bounds how long a client may take to finish
	// its request line and headers, which is the slow-loris budget.
	defaultReadHeaderTimeout = 20 * time.Second
	// tunnelBufferSize is the per-direction copy buffer for a CONNECT
	// tunnel. 32 KiB matches io.Copy's default and is large enough that the
	// quota pre-check does not dominate throughput.
	tunnelBufferSize = 32 * 1024
	// reapInterval is how often expired sessions are swept out of memory.
	reapInterval = 30 * time.Second
)

// Options configure a Proxy.
type Options struct {
	// ListenAddr is the bind address. Empty means DefaultListenAddr.
	ListenAddr string
	// Endpoint is the address sandboxes should use to reach this proxy. It
	// is what goes into HTTPS_PROXY and is frequently *not* ListenAddr: a
	// container reaches the host by a gateway address, not by the address
	// the host bound. Empty falls back to the listener's own address.
	Endpoint string
	// DialTimeout bounds the connection to an authorised origin.
	DialTimeout time.Duration
	// Resolver overrides DNS. Tests use it to simulate rebinding.
	Resolver Resolver
	// Dial overrides the outbound dialer. Tests use it to avoid the network;
	// production leaves it nil.
	Dial DialFunc
}

func (o Options) dialTimeout() time.Duration {
	if o.DialTimeout > 0 {
		return o.DialTimeout
	}
	return defaultDialTimeout
}

// Proxy is the forward proxy. Build it with NewProxy and run it with Serve or
// ListenAndServe.
type Proxy struct {
	broker *Broker
	opts   Options

	dial DialFunc
	srv  *http.Server

	mu       sync.Mutex
	listener net.Listener
	closed   bool
	done     chan struct{}
	// inflight counts handlers that are still running, so Close can wait for
	// them. See Close for why that matters.
	inflight sync.WaitGroup
	// tunnels holds every hijacked connection. http.Server.Close does not
	// touch these — a hijacked conn is deliberately untracked by the server
	// — so without this registry a CONNECT tunnel would outlive the proxy
	// that is supposed to be its only route out.
	tunnels connSet
}

// drainTimeout bounds how long Close waits for in-flight handlers.
const drainTimeout = 5 * time.Second

// enter admits a request and registers it as in-flight, or reports that the
// proxy is shutting down.
//
// The flag is checked under the same mutex Close sets it with, which is what
// makes the WaitGroup safe: no Add can begin after Wait has.
func (p *Proxy) enter() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return false
	}
	p.inflight.Add(1)
	return true
}

// NewProxy builds a proxy over a broker.
func NewProxy(b *Broker, opts Options) (*Proxy, error) {
	if b == nil {
		return nil, fmt.Errorf("egressbroker: nil broker")
	}
	p := &Proxy{broker: b, opts: opts, done: make(chan struct{})}

	p.dial = opts.Dial
	if p.dial == nil {
		d := &net.Dialer{Timeout: opts.dialTimeout()}
		p.dial = d.DialContext
	}
	p.srv = &http.Server{
		Handler:           p,
		ReadHeaderTimeout: defaultReadHeaderTimeout,
		// No ReadTimeout or WriteTimeout: a CONNECT tunnel is hijacked and a
		// large legitimate download is not slow-loris. The bounds that do
		// apply to a tunnel are the session TTL and the byte quota, both set
		// on the hijacked connection directly.
		ErrorLog: nil,
	}
	return p, nil
}

// Addr returns the bound address, or "" before Serve.
func (p *Proxy) Addr() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.listener == nil {
		return ""
	}
	return p.listener.Addr().String()
}

// ListenAndServe binds ListenAddr and serves until Close.
//
// It publishes the bound address to the broker before serving, so a
// configuration of ":0" still produces a usable HTTPS_PROXY value — which
// matters more than it sounds, because port 0 is the right choice for an
// ephemeral per-run proxy and the wrong one to have to know in advance.
func (p *Proxy) ListenAndServe() error {
	addr := strings.TrimSpace(p.opts.ListenAddr)
	if addr == "" {
		addr = DefaultListenAddr
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("egressbroker: listen on %s: %w", addr, err)
	}
	return p.Serve(ln)
}

// Serve serves on an existing listener and returns when it is closed.
func (p *Proxy) Serve(ln net.Listener) error {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		_ = ln.Close()
		return http.ErrServerClosed
	}
	p.listener = ln
	p.mu.Unlock()

	endpoint := strings.TrimSpace(p.opts.Endpoint)
	if endpoint == "" {
		endpoint = ln.Addr().String()
	}
	p.broker.SetEndpoint(endpoint)

	go p.reapLoop()

	err := p.srv.Serve(ln)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

// reapLoop sweeps expired sessions until the proxy closes.
func (p *Proxy) reapLoop() {
	t := time.NewTicker(reapInterval)
	defer t.Stop()
	for {
		select {
		case <-p.done:
			return
		case <-t.C:
			p.broker.ReapExpired()
		}
	}
}

// Close stops the proxy. It is idempotent and safe to call from a defer
// alongside an explicit call.
//
// Shutdown is deliberately not graceful in the http.Server.Shutdown sense: an
// open CONNECT tunnel has no request boundary to wait for, so Shutdown would
// block until the session TTL expired. Closing outright is also the correct
// security behaviour — when the control plane stops, so does every sandbox's
// route to the Internet.
//
// Making that true takes two steps, not one. http.Server.Close closes the
// connections the server still tracks, but a hijacked connection is
// deliberately not among them, so every live CONNECT tunnel survives it; they
// are closed explicitly from the registry. Skipping that step does not merely
// leak a tunnel — it also wedges the drain below, because the handler owning
// the tunnel never returns.
//
// The drain then waits for the handlers to *finish reporting*. Each one still
// has an audit row to write, and http.Server.Close does not wait for handler
// goroutines. Without it those rows land after the caller has closed the
// database, which is how a decision ends up enforced but unrecorded — the one
// outcome this package exists to make impossible. The wait is bounded, so a
// wedged handler delays shutdown rather than preventing it.
func (p *Proxy) Close() error {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return nil
	}
	p.closed = true
	close(p.done)
	p.mu.Unlock()

	err := p.srv.Close()
	p.tunnels.closeAll()

	drained := make(chan struct{})
	go func() {
		p.inflight.Wait()
		close(drained)
	}()
	select {
	case <-drained:
	case <-time.After(drainTimeout):
	}
	return err
}

// ---------------------------------------------------------------------------
// request handling
// ---------------------------------------------------------------------------

// ServeHTTP authenticates the caller and dispatches to the tunnel or
// plain-HTTP path.
func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !p.enter() {
		// Shutting down. 503 rather than a policy status: nothing was
		// decided, so nothing should read as a denial.
		w.Header().Set("X-Cloop-Egress-Verdict", "shutting_down")
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	defer p.inflight.Done()

	sess, err := p.authenticate(r)
	if err != nil {
		// 407 with a challenge, so a client that simply forgot the
		// credential retries with it instead of guessing at a 403.
		//
		// Deliberately not audited. There is no identity to attribute the
		// attempt to, and writing a row per unauthenticated request would
		// let anyone who can reach the listener append to a hash-chained,
		// deliberately-immutable log at will — turning the audit trail into
		// the softest target on the box. Authenticated denials are the ones
		// worth recording, and those all carry a session.
		w.Header().Set("Proxy-Authenticate", ProxyAuthScheme+` realm="cloop-egress"`)
		p.refuse(w, nil, r, http.StatusProxyAuthRequired, err)
		return
	}
	sess.requests.Add(1)

	if r.Method == http.MethodConnect {
		p.handleConnect(w, r, sess)
		return
	}
	p.handleHTTP(w, r, sess)
}

// authenticate resolves the Proxy-Authorization header to a live session.
func (p *Proxy) authenticate(r *http.Request) (*Session, error) {
	id, token, err := ParseProxyCredential(r.Header.Get("Proxy-Authorization"))
	if err != nil {
		return nil, err
	}
	return p.broker.Authenticate(id, token)
}

// handleConnect authorises and opens a TLS tunnel.
//
// The tunnel is CA-free: cloop does not terminate, inspect, or re-sign the
// TLS session, and no cloop certificate is installed in the sandbox. The
// workload validates the origin's certificate itself, exactly as it would
// without a proxy. That costs visibility into the request — see the package
// doc — and buys the property that compromising the control plane does not
// hand over every sandbox's traffic in plaintext.
func (p *Proxy) handleConnect(w http.ResponseWriter, r *http.Request, sess *Session) {
	target := r.RequestURI
	if target == "" {
		target = r.Host
	}
	host, port, err := ParseConnectTarget(target)
	if err != nil {
		p.refuse(w, sess, r, http.StatusBadRequest, err)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), p.opts.dialTimeout())
	defer cancel()

	dest, err := Resolve(ctx, p.opts.Resolver, sess.Grant, host, port)
	if err != nil {
		p.broker.auditRequest(sess, secretbroker.ActionEgressConnect, host, port, err, "")
		p.refuse(w, nil, r, statusFor(err), err)
		return
	}
	if err := sess.checkLive(p.broker.now()); err != nil {
		p.broker.auditRequest(sess, secretbroker.ActionEgressConnect, host, port, err, "")
		p.refuse(w, nil, r, statusFor(err), err)
		return
	}

	// Dial the *resolved literal*, never the name. This is the line that
	// defeats DNS rebinding: there is no second lookup between the policy
	// check and the connection, so there is nothing for a hostile
	// authoritative server to answer differently.
	upstream, err := p.dial(ctx, "tcp", dest.AddrPort())
	if err != nil {
		derr := fmt.Errorf("%w: %s: %v", ErrDialFailed, dest.AddrPort(), err)
		p.broker.auditRequest(sess, secretbroker.ActionEgressConnect, host, port, derr, "")
		p.refuse(w, nil, r, http.StatusBadGateway, derr)
		return
	}

	hj, ok := w.(http.Hijacker)
	if !ok {
		_ = upstream.Close()
		herr := fmt.Errorf("%w: connection does not support tunnelling", ErrInvalidRequest)
		p.broker.auditRequest(sess, secretbroker.ActionEgressConnect, host, port, herr, "")
		p.refuse(w, nil, r, http.StatusInternalServerError, herr)
		return
	}
	client, buf, err := hj.Hijack()
	if err != nil {
		_ = upstream.Close()
		p.broker.auditRequest(sess, secretbroker.ActionEgressConnect, host, port,
			fmt.Errorf("%w: hijack: %v", ErrInvalidRequest, err), "")
		return
	}

	// Register both ends before a byte moves, with the session (so revoking
	// the grant severs the tunnel) and with the proxy (so shutting the proxy
	// down does too). A registration that is refused means the session or the
	// proxy ended between the policy check and here, so the tunnel must not
	// open at all.
	if !p.registerTunnel(sess, client, upstream) {
		lerr := fmt.Errorf("%w: session ended before the tunnel opened", ErrSessionExpired)
		p.broker.auditRequest(sess, secretbroker.ActionEgressConnect, host, port, lerr, "")
		return
	}
	defer p.unregisterTunnel(sess, client, upstream)

	p.broker.auditRequest(sess, secretbroker.ActionEgressConnect, host, port, nil,
		"tunnel opened to "+dest.Addr.String())

	if _, err := buf.WriteString("HTTP/1.1 200 Connection established\r\n\r\n"); err != nil {
		_ = client.Close()
		_ = upstream.Close()
		return
	}
	if err := buf.Flush(); err != nil {
		_ = client.Close()
		_ = upstream.Close()
		return
	}

	// Bytes the client pipelined behind the CONNECT are already in the
	// hijacked reader's buffer. Forwarding them before the copy loop starts
	// is what makes a client that sends its TLS ClientHello immediately work
	// — and dropping them silently is a hang that looks like a network fault.
	if n := buf.Reader.Buffered(); n > 0 {
		pending, rerr := buf.Reader.Peek(n)
		if rerr == nil {
			if qerr := sess.addUp(int64(len(pending))); qerr != nil {
				p.closeTunnel(client, upstream, sess, host, port, qerr)
				return
			}
			if _, werr := upstream.Write(pending); werr != nil {
				p.closeTunnel(client, upstream, sess, host, port, werr)
				return
			}
			_, _ = buf.Reader.Discard(n)
		}
	}

	err = p.tunnel(client, upstream, sess)
	p.closeTunnel(client, upstream, sess, host, port, err)
}

// registerTunnel adds both ends of a tunnel to the session's and the proxy's
// registries, reporting whether both accepted. On a partial failure it undoes
// the half that succeeded and closes the sockets, so a refused tunnel never
// leaves a live connection behind.
func (p *Proxy) registerTunnel(sess *Session, client, upstream net.Conn) bool {
	if !sess.track(client) {
		_ = client.Close()
		_ = upstream.Close()
		return false
	}
	if !sess.track(upstream) {
		sess.untrack(client)
		_ = client.Close()
		_ = upstream.Close()
		return false
	}
	if !p.tunnels.add(client) || !p.tunnels.add(upstream) {
		sess.untrack(client)
		sess.untrack(upstream)
		_ = client.Close()
		_ = upstream.Close()
		return false
	}
	return true
}

func (p *Proxy) unregisterTunnel(sess *Session, client, upstream net.Conn) {
	sess.untrack(client)
	sess.untrack(upstream)
	p.tunnels.remove(client)
	p.tunnels.remove(upstream)
}

// closeTunnel tears both ends down and records the outcome once.
func (p *Proxy) closeTunnel(client, upstream net.Conn, sess *Session, host string, port int, err error) {
	_ = client.Close()
	_ = upstream.Close()

	if err != nil && !isBenignCopyErr(err) {
		p.broker.auditRequest(sess, secretbroker.ActionEgressClose, host, port, err, "")
		return
	}
	p.broker.auditRequest(sess, secretbroker.ActionEgressClose, host, port, nil, "tunnel closed")
}

// tunnel copies bytes both ways until one side closes, a quota is spent, or
// the session expires.
//
// The session deadline is set on both raw connections rather than watched by
// a timer. That is what makes expiry apply to an *idle* tunnel too: a
// long-lived connection with no traffic still dies at its TTL, instead of
// surviving indefinitely because nothing woke up to check.
func (p *Proxy) tunnel(client, upstream net.Conn, sess *Session) error {
	deadline := sess.ExpiresAt
	_ = client.SetDeadline(deadline)
	_ = upstream.SetDeadline(deadline)

	var (
		wg     sync.WaitGroup
		result atomic.Pointer[error]
	)
	record := func(err error) {
		if err == nil {
			return
		}
		result.CompareAndSwap(nil, &err)
	}

	copyDir := func(dst, src net.Conn, add func(int64) error) {
		defer wg.Done()
		_, err := copyMetered(dst, src, add)
		record(err)
		// Closing the far side's read direction unblocks the peer goroutine.
		// A full Close is used rather than CloseWrite because the connection
		// is being torn down either way and not every net.Conn in a test is a
		// *net.TCPConn.
		_ = dst.Close()
		_ = src.Close()
	}

	wg.Add(2)
	go copyDir(upstream, client, sess.addUp)
	go copyDir(client, upstream, sess.addDown)
	wg.Wait()

	if errp := result.Load(); errp != nil {
		return p.classifyTunnelErr(*errp, sess)
	}
	return nil
}

// classifyTunnelErr turns a raw copy error into the typed reason an operator
// needs. A read deadline that fires at exactly the session's expiry is not a
// network problem, and reporting it as one would send someone looking at
// their firewall.
func (p *Proxy) classifyTunnelErr(err error, sess *Session) error {
	if errors.Is(err, ErrQuotaExceeded) {
		return err
	}
	// A session that ended under the tunnel is the cause, whatever the socket
	// reported. When revocation severs the connections the copy sees a bare
	// net.ErrClosed, which isBenignCopyErr would otherwise record as a normal
	// hang-up — losing the fact that the control plane cut it.
	if sess.Closed() {
		if !p.broker.now().Before(sess.ExpiresAt) {
			return fmt.Errorf("%w: session %s expired mid-tunnel at %s",
				ErrSessionExpired, sess.ID, sess.ExpiresAt.UTC().Format(time.RFC3339))
		}
		return fmt.Errorf("%w: session %s was closed mid-tunnel", ErrSessionExpired, sess.ID)
	}
	var nerr net.Error
	if errors.As(err, &nerr) && nerr.Timeout() && !p.broker.now().Before(sess.ExpiresAt) {
		return fmt.Errorf("%w: session %s expired mid-tunnel at %s",
			ErrSessionExpired, sess.ID, sess.ExpiresAt.UTC().Format(time.RFC3339))
	}
	return err
}

// handleHTTP proxies a plain (non-TLS) request.
//
// Plain HTTP is the one path where the method is visible, so it is the one
// path where Grant.Methods can be enforced. It is also the path where a
// workload's traffic is readable by anything between here and the origin,
// which is the reason to prefer https and the reason the method filter is
// worth so little on its own.
func (p *Proxy) handleHTTP(w http.ResponseWriter, r *http.Request, sess *Session) {
	if r.URL == nil || !r.URL.IsAbs() {
		p.refuse(w, sess, r, http.StatusBadRequest,
			fmt.Errorf("%w: a forward proxy needs an absolute URI (got %q)", ErrInvalidRequest, r.RequestURI))
		return
	}
	if !strings.EqualFold(r.URL.Scheme, "http") {
		p.refuse(w, sess, r, http.StatusBadRequest,
			fmt.Errorf("%w: scheme %q must be tunnelled with CONNECT, not proxied", ErrInvalidRequest, r.URL.Scheme))
		return
	}

	host, port, err := splitHostPort(r.URL.Host, 80)
	if err != nil {
		p.refuse(w, sess, r, http.StatusBadRequest, err)
		return
	}
	if err := sess.Grant.CheckMethod(r.Method); err != nil {
		p.broker.auditRequest(sess, secretbroker.ActionEgressRequest, host, port, err, "")
		p.refuse(w, nil, r, http.StatusForbidden, err)
		return
	}

	// Bound the whole exchange by the session.
	//
	// The tunnel path gets this from a socket deadline; here there is no
	// socket to set one on, because the response body is streamed by an
	// http.Transport and the request context is the only handle on it.
	// Without this a workload could hold an endless chunked response open
	// from an allowed host long past its lease — an unbounded egress channel
	// that every other control in this package would report as compliant.
	ctx, cancel := sess.BindContext(r.Context())
	defer cancel()

	dest, err := Resolve(ctx, p.opts.Resolver, sess.Grant, host, port)
	if err != nil {
		p.broker.auditRequest(sess, secretbroker.ActionEgressRequest, host, port, err, "")
		p.refuse(w, nil, r, statusFor(err), err)
		return
	}
	if err := sess.checkLive(p.broker.now()); err != nil {
		p.broker.auditRequest(sess, secretbroker.ActionEgressRequest, host, port, err, "")
		p.refuse(w, nil, r, statusFor(err), err)
		return
	}

	outReq := r.Clone(ctx)
	outReq.RequestURI = ""
	outReq.Header = sanitizeHeaders(r.Header)
	if r.Body != nil {
		outReq.Body = &meteredReader{r: r.Body, add: sess.addUp}
	}

	// A fresh Transport per request, with keep-alives disabled.
	//
	// A shared pool would key connections by host and could hand a connection
	// pinned to one resolved address — under one session's policy — to a
	// later request from a different session for the same name. That is the
	// rebinding defence undone by a cache, so the pool does not exist. The
	// cost is a TCP (and DNS-free) setup per request, which for a policy
	// gate on a sandbox's egress is the right trade.
	tr := &http.Transport{
		DisableKeepAlives: true,
		Proxy:             nil,
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			// The address is ignored on purpose: it is whatever the
			// Transport derived from the URL, and honouring it would
			// reintroduce the second lookup.
			return p.dial(ctx, network, dest.AddrPort())
		},
	}
	defer tr.CloseIdleConnections()

	resp, err := tr.RoundTrip(outReq)
	if err != nil {
		if errors.Is(err, ErrQuotaExceeded) {
			p.broker.auditRequest(sess, secretbroker.ActionEgressRequest, host, port, err, "")
			p.refuse(w, nil, r, http.StatusForbidden, err)
			return
		}
		derr := fmt.Errorf("%w: %s: %v", ErrDialFailed, dest.AddrPort(), err)
		p.broker.auditRequest(sess, secretbroker.ActionEgressRequest, host, port, derr, "")
		p.refuse(w, nil, r, http.StatusBadGateway, derr)
		return
	}
	defer resp.Body.Close()

	// http.ReadResponse accepts any three-digit status, but WriteHeader
	// panics below 100. An origin the sandbox controls can therefore answer
	// "HTTP/1.1 099 x" and take the handler down — recovered per-connection
	// by http.Server, but the audit row for an authorised, dialled, executed
	// request would never be written. Refusing the response keeps the trail
	// complete.
	if resp.StatusCode < 100 || resp.StatusCode > 599 {
		serr := fmt.Errorf("%w: origin returned an out-of-range status %d",
			ErrInvalidRequest, resp.StatusCode)
		p.broker.auditRequest(sess, secretbroker.ActionEgressRequest, host, port, serr, "")
		p.refuse(w, nil, r, http.StatusBadGateway, serr)
		return
	}

	copyHeaders(w.Header(), sanitizeHeaders(resp.Header))
	w.WriteHeader(resp.StatusCode)
	_, copyErr := copyMetered(w, resp.Body, sess.addDown)

	if copyErr != nil && !isBenignCopyErr(copyErr) {
		// The status line is already on the wire, so the only honest way to
		// signal a mid-body cutoff is to abandon the response — which
		// surfaces to the client as a truncated body, exactly as it should.
		p.broker.auditRequest(sess, secretbroker.ActionEgressRequest, host, port, copyErr, "")
		return
	}
	p.broker.auditRequest(sess, secretbroker.ActionEgressRequest, host, port, nil,
		fmt.Sprintf("%s %d via %s", r.Method, resp.StatusCode, dest.Addr))
}

// refuse writes a proxy error response and, when sess is non-nil, records it.
//
// sess is nil at call sites that have already written their own audit row, so
// that a single refusal never produces two.
func (p *Proxy) refuse(w http.ResponseWriter, sess *Session, r *http.Request, status int, err error) {
	if sess != nil {
		host, port := "", 0
		if r != nil && r.URL != nil {
			host, port, _ = splitHostPort(r.URL.Host, 0)
		}
		p.broker.auditRequest(sess, secretbroker.ActionEgressRequest, host, port, err, "")
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("X-Cloop-Egress-Verdict", verdictOf(err))
	w.WriteHeader(status)

	// An authentication failure gets one fixed sentence, byte for byte.
	//
	// The detailed errors distinguish "unknown session" from "token
	// mismatch", which is exactly the distinction the constant-time compare
	// in Broker.Authenticate exists to hide; writing either into the response
	// would make the body — and its Content-Length — an oracle for whether a
	// session ID is live. The specific reason still reaches the operator,
	// because the caller logs it; it just does not reach the caller's
	// counterparty.
	if errors.Is(err, ErrUnauthenticated) {
		_, _ = io.WriteString(w, "proxy authentication required\n")
		return
	}
	// Everything else is redacted for the same reason it is redacted on the
	// way into the audit log: it is assembled from wrapped errors, and a
	// sandbox is the last place to hand one an unfiltered control-plane
	// error string.
	_, _ = io.WriteString(w, secretbroker.RedactString(err.Error())+"\n")
}

// statusFor maps a denial to the HTTP status a client should see.
//
// Everything the policy refuses is a 403: the request was understood, the
// credential was valid, and the answer is no. A 502 would suggest retrying.
func statusFor(err error) int {
	switch {
	case errors.Is(err, ErrSessionExpired):
		return http.StatusProxyAuthRequired
	case errors.Is(err, ErrResolveFailed):
		return http.StatusBadGateway
	case errors.Is(err, ErrInvalidRequest):
		return http.StatusBadRequest
	default:
		return http.StatusForbidden
	}
}

// verdictOf names the denial class for the X-Cloop-Egress-Verdict header, so
// a workload can branch on the reason without parsing prose.
func verdictOf(err error) string {
	switch {
	case err == nil:
		return "allow"
	case errors.Is(err, ErrHostNotAllowed):
		return "host_not_allowed"
	case errors.Is(err, ErrPortNotAllowed):
		return "port_not_allowed"
	case errors.Is(err, ErrMethodNotAllowed):
		return "method_not_allowed"
	case errors.Is(err, ErrDestinationBlocked):
		return "destination_blocked"
	case errors.Is(err, ErrQuotaExceeded):
		return "quota_exceeded"
	case errors.Is(err, ErrSessionExpired):
		return "session_expired"
	case errors.Is(err, ErrUnauthenticated):
		return "unauthenticated"
	case errors.Is(err, ErrResolveFailed):
		return "resolve_failed"
	case errors.Is(err, ErrDialFailed):
		return "dial_failed"
	case errors.Is(err, ErrInvalidRequest):
		return "malformed_request"
	default:
		return "denied"
	}
}

// ---------------------------------------------------------------------------
// metering
// ---------------------------------------------------------------------------

// meteredReader counts bytes read from a request body and fails the read once
// the quota is spent.
type meteredReader struct {
	r   io.ReadCloser
	add func(int64) error
}

// Read charges the bytes read and, when that exceeds the quota, reports zero
// bytes alongside the error.
//
// Returning (n, err) instead would deliver the over-quota bytes: io.Copy
// inside the Transport writes the n bytes it was handed before acting on the
// error, so an upload could exceed its budget by a whole read buffer. Dropping
// them costs nothing, because the request is being abandoned either way. The
// charge stands, since those bytes did cross the control plane — which is the
// same accounting copyMetered uses on the download side.
func (m *meteredReader) Read(p []byte) (int, error) {
	n, err := m.r.Read(p)
	if n > 0 {
		if qerr := m.add(int64(n)); qerr != nil {
			return 0, qerr
		}
	}
	return n, err
}

func (m *meteredReader) Close() error { return m.r.Close() }

// copyMetered copies src to dst, charging every byte to add and stopping the
// moment add refuses.
//
// The charge happens before the write, so an over-quota transfer is cut
// *before* the offending bytes are delivered rather than after. That is the
// difference between a quota and a report: a download that is allowed to
// finish and then flagged has already cost the bandwidth it was meant to
// bound.
func copyMetered(dst io.Writer, src io.Reader, add func(int64) error) (int64, error) {
	buf := make([]byte, tunnelBufferSize)
	var total int64
	for {
		n, rerr := src.Read(buf)
		if n > 0 {
			if qerr := add(int64(n)); qerr != nil {
				return total, qerr
			}
			written, werr := dst.Write(buf[:n])
			total += int64(written)
			if werr != nil {
				return total, werr
			}
			if written != n {
				return total, io.ErrShortWrite
			}
			if f, ok := dst.(http.Flusher); ok {
				f.Flush()
			}
		}
		if rerr != nil {
			if rerr == io.EOF {
				return total, nil
			}
			return total, rerr
		}
	}
}

// isBenignCopyErr reports whether a copy error is the ordinary end of a
// connection rather than a policy or transport failure worth a deny row.
func isBenignCopyErr(err error) bool {
	if err == nil || errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
		return true
	}
	if errors.Is(err, io.ErrUnexpectedEOF) {
		return true
	}
	// A peer that resets rather than closing is normal for TLS tunnels that
	// end at the application layer.
	return strings.Contains(err.Error(), "connection reset by peer") ||
		strings.Contains(err.Error(), "broken pipe")
}

// ---------------------------------------------------------------------------
// header handling
// ---------------------------------------------------------------------------

// hopByHopHeaders are stripped in both directions (RFC 9110 §7.6.1).
//
// Proxy-Authorization is on the list for a reason beyond spec compliance: it
// carries this session's credential, and forwarding it to the origin would
// hand every site a sandbox visits a working key to the control plane's
// egress proxy.
var hopByHopHeaders = []string{
	"Connection",
	"Keep-Alive",
	"Proxy-Authenticate",
	"Proxy-Authorization",
	"Proxy-Connection",
	"Te",
	"Trailer",
	"Transfer-Encoding",
	"Upgrade",
}

// sanitizeHeaders returns a copy with hop-by-hop headers removed, including
// the ones named dynamically by the Connection header.
func sanitizeHeaders(in http.Header) http.Header {
	out := make(http.Header, len(in))
	drop := make(map[string]bool, len(hopByHopHeaders)+4)
	for _, h := range hopByHopHeaders {
		drop[http.CanonicalHeaderKey(h)] = true
	}
	for _, v := range in.Values("Connection") {
		for _, token := range strings.Split(v, ",") {
			if t := strings.TrimSpace(token); t != "" {
				drop[http.CanonicalHeaderKey(t)] = true
			}
		}
	}
	for k, vals := range in {
		if drop[http.CanonicalHeaderKey(k)] {
			continue
		}
		out[k] = append([]string(nil), vals...)
	}
	return out
}

func copyHeaders(dst, src http.Header) {
	for k, vals := range src {
		for _, v := range vals {
			dst.Add(k, v)
		}
	}
}

// splitHostPort separates an authority into host and port, applying
// defaultPort when none is present. A defaultPort of 0 means "no default",
// used on the error paths where the port is only wanted for an audit field.
func splitHostPort(authority string, defaultPort int) (string, int, error) {
	a := strings.TrimSpace(authority)
	if a == "" {
		return "", 0, fmt.Errorf("%w: request has no host", ErrInvalidRequest)
	}
	host, portStr, err := net.SplitHostPort(a)
	if err != nil {
		// No port present: SplitHostPort fails, and the whole authority is
		// the host.
		host, portStr = a, ""
	}
	// Same validator the CONNECT parser uses. Sharing it is what guarantees
	// the two request shapes cannot disagree about what a host is — see
	// NormalizeDestinationHost.
	host, err = NormalizeDestinationHost(strings.Trim(host, "[]"))
	if err != nil {
		return "", 0, err
	}
	if portStr == "" {
		return host, defaultPort, nil
	}
	port, perr := strconv.Atoi(portStr)
	if perr != nil || port < 1 || port > 65535 {
		return "", 0, fmt.Errorf("%w: port %q is outside 1-65535", ErrInvalidRequest, portStr)
	}
	return host, port, nil
}
