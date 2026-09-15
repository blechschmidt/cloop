package kubeguard

// proxy.go is the monitor: the HTTPS server that sits between a sandbox and
// the API server, reads every request, and decides.
//
// The shape is a reverse proxy, but the interesting part is what it refuses
// to be. It is not a transparent one:
//
//   - the destination is never taken from the request. It comes from the
//     session, which came from a kubeconfig the hub holds. A sandbox cannot
//     redirect the proxy at another cluster by any header, path or Host.
//   - the credential is attached here and only here, after the decision.
//   - impersonation headers are stripped, not forwarded. Kubernetes lets a
//     sufficiently privileged credential act as another user, and a developer's
//     own kubeconfig frequently is one, so forwarding Impersonate-User would
//     hand the sandbox every identity in the cluster through a header.
//   - hop-by-hop headers are dropped, per RFC 7230, so a sandbox cannot use
//     Connection to smuggle a header past the upstream.
//   - a protocol upgrade is refused before it reaches the transport, so the
//     proxy never holds a stream it cannot read.
//
// A refusal is rendered as a Kubernetes Status object, which is what makes
// this usable: kubectl parses it and prints the message, so a developer sees
// "this session has read-only access to the cluster" rather than a raw 403.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor/kubernetes"
	"github.com/blechschmidt/cloop/pkg/hubmetrics"
)

// Server tunables.
const (
	// shutdownGrace bounds Close. A watch is a long-lived request, so the
	// grace period is short and the remainder are cut: a hub that would not
	// exit until every watch ended would not exit.
	shutdownGrace = 10 * time.Second

	// readHeaderTimeout is the slow-loris guard. There is no overall read or
	// write timeout, because a watch is a response that legitimately never
	// ends.
	readHeaderTimeout = 20 * time.Second

	// upstreamHeaderTimeout bounds how long the API server may take to send
	// response headers. It bounds headers only, not the body, so a watch
	// still streams indefinitely once it has started.
	upstreamHeaderTimeout = 60 * time.Second

	// userAgent identifies the monitor in the API server's own audit log, so
	// a cluster admin reading those can tell cloop-brokered traffic apart.
	userAgent = "cloop-kubeguard/1"
)

// hopByHopHeaders are dropped in both directions, per RFC 7230 section 6.1.
var hopByHopHeaders = []string{
	"Connection", "Keep-Alive", "Proxy-Authenticate", "Proxy-Authorization",
	"Proxy-Connection", "Te", "Trailer", "Transfer-Encoding", "Upgrade",
}

// impersonationHeaderPrefix and friends are stripped from every request.
const impersonationHeaderPrefix = "Impersonate-"

// Options configures a Proxy.
type Options struct {
	// Transport overrides the outbound transport. Tests use it; in
	// production it is nil and each session's own transport, built from its
	// kubeconfig's TLS material, is used instead.
	Transport http.RoundTripper
}

// Proxy serves the Kubernetes API to sandboxes, under policy.
type Proxy struct {
	reg  *Registry
	opts Options

	mu        sync.Mutex
	srv       *http.Server
	listener  net.Listener
	closed    bool
	transport map[string]http.RoundTripper
}

// New returns a proxy that authenticates against reg.
func New(reg *Registry, opts Options) (*Proxy, error) {
	if reg == nil {
		return nil, errors.New("kubeguard: nil registry")
	}
	return &Proxy{reg: reg, opts: opts, transport: make(map[string]http.RoundTripper)}, nil
}

// Registry returns the registry this proxy authenticates against.
func (p *Proxy) Registry() *Registry { return p.reg }

// Serve accepts connections on ln until Close.
func (p *Proxy) Serve(ln net.Listener) error {
	srv := &http.Server{
		Handler:           p,
		ReadHeaderTimeout: readHeaderTimeout,
	}
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		_ = ln.Close()
		return http.ErrServerClosed
	}
	p.srv, p.listener = srv, ln
	p.mu.Unlock()

	err := srv.Serve(ln)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

// Addr reports where the proxy is listening.
func (p *Proxy) Addr() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.listener == nil {
		return ""
	}
	return p.listener.Addr().String()
}

// Close stops serving and releases pooled upstream connections.
func (p *Proxy) Close() error {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return nil
	}
	p.closed = true
	srv := p.srv
	transports := p.transport
	p.transport = make(map[string]http.RoundTripper)
	p.mu.Unlock()

	for _, tr := range transports {
		if t, ok := tr.(*http.Transport); ok {
			t.CloseIdleConnections()
		}
	}
	if srv == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), shutdownGrace)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		return srv.Close()
	}
	return nil
}

// ServeHTTP is the whole decision path, in order.
func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	sess, err := p.authenticate(r)
	if err != nil {
		p.rejectUnauthenticated(w, r, err)
		return
	}

	req := Parse(r)

	if err := sess.Policy.Decide(req); err != nil {
		p.deny(w, sess, req, err)
		return
	}

	p.forward(w, r, sess, req)
}

// authenticate resolves the request's bearer token to a live session.
//
// Only the Authorization header is consulted. Kubernetes also accepts a token
// in a websocket subprotocol and, historically, in a query parameter; neither
// is honoured here, because a credential in a URL lands in every intermediary's
// access log and the websocket path is refused by policy anyway.
func (p *Proxy) authenticate(r *http.Request) (*Session, error) {
	raw := strings.TrimSpace(r.Header.Get("Authorization"))
	if raw == "" {
		return nil, ErrUnauthenticated
	}
	token, ok := cutBearer(raw)
	if !ok {
		return nil, ErrUnauthenticated
	}
	return p.reg.Authenticate(token)
}

// cutBearer extracts the token from an "Authorization: Bearer x" header. The
// scheme is matched case-insensitively, as RFC 7235 requires.
func cutBearer(header string) (string, bool) {
	const scheme = "bearer "
	if len(header) <= len(scheme) || !strings.EqualFold(header[:len(scheme)], scheme) {
		return "", false
	}
	tok := strings.TrimSpace(header[len(scheme):])
	if tok == "" {
		return "", false
	}
	return tok, true
}

// forward sends an allowed request upstream with the real credential.
func (p *Proxy) forward(w http.ResponseWriter, r *http.Request, sess *Session, req APIRequest) {
	rc := sess.Upstream()
	if rc == nil {
		p.fail(w, sess, req, http.StatusInternalServerError,
			"this session has no cluster credential", "session_without_upstream")
		return
	}

	target := strings.TrimSuffix(rc.Server, "/") + req.Path
	if q := r.URL.RawQuery; q != "" {
		target += "?" + q
	}

	// The cap is enforced twice, because the two cases fail differently.
	//
	// A declared Content-Length above the cap is refused here, before a byte
	// is read: the cheapest possible refusal, and the one that covers an
	// honest client.
	//
	// A chunked or mis-declared body is caught by cappedReader below, which
	// returns an error rather than truncating. Truncation was the earlier
	// behaviour and it was worse than either: the API server would receive a
	// half object and answer with its own parse error, so the sandbox would
	// be told its JSON was malformed when in fact its request was too large,
	// and DenyBodyTooLarge — a reason this package declares — would never
	// have been emitted at all.
	if r.ContentLength > sess.Policy.MaxBodyBytes {
		p.deny(w, sess, req, &Denial{
			Reason: DenyBodyTooLarge,
			Message: fmt.Sprintf("request body of %d bytes exceeds this session's limit of %d",
				r.ContentLength, sess.Policy.MaxBodyBytes),
		})
		return
	}
	var body io.Reader
	if r.Body != nil {
		body = &cappedReader{r: r.Body, n: &sess.bytesIn, limit: sess.Policy.MaxBodyBytes}
	}

	out, err := http.NewRequestWithContext(r.Context(), r.Method, target, body)
	if err != nil {
		p.fail(w, sess, req, http.StatusBadRequest,
			"the request could not be forwarded to the cluster", "malformed_request")
		return
	}
	copyRequestHeaders(out.Header, r.Header)
	out.Header.Set("User-Agent", userAgent)
	// Set last, after every copy, so nothing a sandbox sent can survive into
	// the credential slot.
	applyCredential(out.Header, rc)
	if r.ContentLength >= 0 {
		out.ContentLength = r.ContentLength
	}

	tr, err := p.transportFor(sess)
	if err != nil {
		p.fail(w, sess, req, http.StatusBadGateway,
			"the cluster credential is unusable: "+err.Error(), "unusable_credential")
		return
	}

	resp, err := tr.RoundTrip(out)
	if err != nil {
		// The cap tripped while the transport was streaming the body. This is
		// a policy refusal that happens to surface as a transport error, so it
		// is reported as one — the alternative is a 502 blaming the cluster
		// for a limit the hub imposed.
		if errors.Is(err, errBodyTooLarge) {
			p.deny(w, sess, req, &Denial{
				Reason: DenyBodyTooLarge,
				Message: fmt.Sprintf("request body exceeds this session's limit of %d bytes",
					sess.Policy.MaxBodyBytes),
			})
			return
		}
		if errors.Is(err, context.Canceled) || errors.Is(r.Context().Err(), context.Canceled) {
			// The sandbox hung up. Nothing to report and nowhere to report it.
			return
		}
		p.fail(w, sess, req, http.StatusBadGateway,
			"the cluster could not be reached: "+err.Error(), "upstream_unreachable")
		return
	}
	defer resp.Body.Close()

	sess.allowed.Add(1)
	hubmetrics.KubeGuardRequests.Inc(hubmetrics.ResultAllowed)
	if p.reg.SampleAllowed {
		e := sess.eventFor(EventRequestAllowed, req)
		e.Detail = fmt.Sprintf("upstream %d", resp.StatusCode)
		p.reg.emit(e)
	}

	copyResponseHeaders(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	streamBody(w, resp.Body, &sess.bytesOut)
}

// transportFor returns the outbound transport for a session, building it once.
//
// Per session rather than per proxy because the TLS material is per cluster:
// two sessions against two clusters must not share a connection pool whose
// client certificate belongs to one of them.
func (p *Proxy) transportFor(sess *Session) (http.RoundTripper, error) {
	if p.opts.Transport != nil {
		return p.opts.Transport, nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return nil, errors.New("proxy is shutting down")
	}
	if tr, ok := p.transport[sess.ID]; ok {
		return tr, nil
	}
	p.pruneTransportsLocked()
	tr, err := sess.Upstream().Transport(upstreamHeaderTimeout)
	if err != nil {
		return nil, err
	}
	p.transport[sess.ID] = tr
	return tr, nil
}

// transportPruneThreshold is how many cached transports accumulate before a
// new session triggers a sweep. Small, because each entry is a connection
// pool rather than a few bytes, and large enough that a hub running a normal
// number of concurrent sessions never sweeps at all.
const transportPruneThreshold = 64

// pruneTransportsLocked drops transports whose session the registry no longer
// holds. Caller must hold p.mu.
//
// Without it the map grows for the life of the process: sessions are reaped
// from the registry on their TTL, but nothing told the proxy, so every session
// a long-running hub ever minted kept an idle connection pool alive. The sweep
// is on insert rather than on a ticker so the proxy needs no goroutine of its
// own and no coupling to the reaper's schedule.
func (p *Proxy) pruneTransportsLocked() {
	if len(p.transport) < transportPruneThreshold {
		return
	}
	for id, tr := range p.transport {
		if sess, ok := p.reg.Session(id); ok && !sess.Closed() {
			continue
		}
		if t, ok := tr.(*http.Transport); ok {
			t.CloseIdleConnections()
		}
		delete(p.transport, id)
	}
}

// streamBody copies the upstream response, flushing as it goes.
//
// The flush is what makes `kubectl get pods -w` work: a watch is a response
// body that dribbles one JSON object per event and never ends, and a proxy
// that buffered it would turn a live stream into a hang.
func streamBody(w http.ResponseWriter, body io.Reader, counter *atomic.Int64) {
	flusher, _ := w.(http.Flusher)
	buf := make([]byte, 32*1024)
	for {
		n, err := body.Read(buf)
		if n > 0 {
			counter.Add(int64(n))
			if _, werr := w.Write(buf[:n]); werr != nil {
				return
			}
			if flusher != nil {
				flusher.Flush()
			}
		}
		if err != nil {
			return
		}
	}
}

// copyRequestHeaders copies the sandbox's headers, minus everything that must
// not cross the boundary.
func copyRequestHeaders(dst, src http.Header) {
	for k, vs := range src {
		if isHopByHop(k) || isImpersonation(k) || strings.EqualFold(k, "Authorization") {
			continue
		}
		for _, v := range vs {
			dst.Add(k, v)
		}
	}
}

// copyResponseHeaders copies the API server's headers back, minus hop-by-hop
// ones. WWW-Authenticate is dropped as well: it would invite a client to
// retry with a credential aimed at the cluster's own authenticator, which is
// not who is asking.
func copyResponseHeaders(dst, src http.Header) {
	for k, vs := range src {
		if isHopByHop(k) || strings.EqualFold(k, "WWW-Authenticate") {
			continue
		}
		for _, v := range vs {
			dst.Add(k, v)
		}
	}
}

func isHopByHop(k string) bool {
	for _, h := range hopByHopHeaders {
		if strings.EqualFold(k, h) {
			return true
		}
	}
	return false
}

// isImpersonation reports the Impersonate-User, Impersonate-Group,
// Impersonate-Uid and Impersonate-Extra-* family.
func isImpersonation(k string) bool {
	return len(k) >= len(impersonationHeaderPrefix) &&
		strings.EqualFold(k[:len(impersonationHeaderPrefix)], impersonationHeaderPrefix)
}

// applyCredential attaches the cluster credential.
//
// A client certificate needs nothing here: it is presented during the TLS
// handshake by the transport. A bearer token is a header, and it is set —
// never added — so it replaces rather than joins anything that survived.
//
// The else branch matters as much as the if: an anonymous upstream must leave
// with no Authorization header at all, not with whatever the sandbox sent.
func applyCredential(h http.Header, rc *kubernetes.RESTConfig) {
	if rc != nil && rc.BearerToken != "" {
		h.Set("Authorization", "Bearer "+rc.BearerToken)
		return
	}
	h.Del("Authorization")
}

// deny refuses a request that policy rejected.
func (p *Proxy) deny(w http.ResponseWriter, sess *Session, req APIRequest, err error) {
	reason, _ := DenyReasonOf(err)
	sess.denied.Add(1)
	hubmetrics.KubeGuardRequests.Inc(hubmetrics.ResultDenied)
	if reason != "" {
		hubmetrics.KubeGuardDenials.Inc(string(reason))
	}

	var d *Denial
	msg := err.Error()
	if errors.As(err, &d) && d != nil {
		msg = d.Message
	}

	e := sess.eventFor(EventRequestDenied, req)
	e.Reason = reason
	e.Detail = msg
	p.reg.emit(e)

	writeStatus(w, http.StatusForbidden, "Forbidden", msg, string(reason))
}

// fail reports a proxy-side problem: the request was allowed, and something
// else went wrong. Counted as neither allowed nor denied, because it is
// neither — conflating a broken upstream with a policy refusal would make the
// denial metric lie in exactly the situation an operator is paging on.
func (p *Proxy) fail(w http.ResponseWriter, sess *Session, req APIRequest, status int, msg, reason string) {
	e := sess.eventFor(EventRejected, req)
	e.Detail = msg
	p.reg.emit(e)
	writeStatus(w, status, http.StatusText(status), msg, reason)
}

// rejectUnauthenticated refuses a request with no usable session.
//
// The message names the three reasons a token stops working — wrong, expired,
// revoked — without saying which, because the caller has not proved it is
// entitled to know. An expired session is the exception: the caller did prove
// it held the token, so it is told to ask for a fresh lease rather than left
// to guess.
func (p *Proxy) rejectUnauthenticated(w http.ResponseWriter, r *http.Request, err error) {
	hubmetrics.KubeGuardRequests.Inc(hubmetrics.ResultDenied)
	hubmetrics.KubeGuardDenials.Inc("unauthenticated")

	msg := "no valid cloop Kubernetes session: the credential is missing, unknown, or has been revoked"
	switch {
	case errors.Is(err, ErrSessionExpired):
		msg = "this cloop Kubernetes session has expired; the hub issues a fresh one at the " +
			"start of each dispatch"
	case errors.Is(err, ErrSessionClosed):
		msg = "this cloop Kubernetes session was revoked"
	}

	p.reg.emit(Event{
		Kind: EventRejected, Verb: strings.ToLower(r.Method), Resource: cleanPath(r.URL.Path),
		Detail: msg,
	})
	writeStatus(w, http.StatusUnauthorized, "Unauthorized", msg, "unauthenticated")
}

// status is the metav1.Status wire shape.
//
// Hand-written rather than pulled from k8s.io/apimachinery: cloop does not
// depend on the Kubernetes Go modules anywhere, and this is nine stable
// fields that have not changed since v1. Taking the dependency to render a
// refusal would be a poor trade.
type status struct {
	Kind       string   `json:"kind"`
	APIVersion string   `json:"apiVersion"`
	Metadata   struct{} `json:"metadata"`
	Status     string   `json:"status"`
	Message    string   `json:"message"`
	Reason     string   `json:"reason"`
	Details    *struct {
		Causes []statusCause `json:"causes,omitempty"`
	} `json:"details,omitempty"`
	Code int `json:"code"`
}

type statusCause struct {
	Type    string `json:"reason"`
	Message string `json:"message"`
}

// writeStatus renders a refusal the way the API server does, so kubectl
// prints the message instead of the status code.
func writeStatus(w http.ResponseWriter, code int, reason, message, cause string) {
	s := status{
		Kind:       "Status",
		APIVersion: "v1",
		Status:     "Failure",
		Message:    message,
		Reason:     reason,
		Code:       code,
	}
	if cause != "" {
		s.Details = &struct {
			Causes []statusCause `json:"causes,omitempty"`
		}{Causes: []statusCause{{Type: cause, Message: message}}}
	}
	body, err := json.Marshal(s)
	if err != nil {
		body = []byte(`{"kind":"Status","apiVersion":"v1","status":"Failure","code":500}`)
		code = http.StatusInternalServerError
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	_, _ = w.Write(body)
}

// errBodyTooLarge is returned by cappedReader once the limit is passed. It
// travels out through http.Transport.RoundTrip, where forward recognises it.
var errBodyTooLarge = errors.New("kubeguard: request body exceeds the session limit")

// cappedReader tallies bytes read from a sandbox's request body and refuses
// to deliver more than limit of them.
type cappedReader struct {
	r     io.Reader
	n     *atomic.Int64
	limit int64
	read  int64
}

func (c *cappedReader) Read(b []byte) (int, error) {
	if c.read >= c.limit {
		return 0, errBodyTooLarge
	}
	if int64(len(b)) > c.limit-c.read {
		// Read no further than one byte past the limit, so the cap costs the
		// hub the cap and not the body.
		b = b[:c.limit-c.read+1]
	}
	n, err := c.r.Read(b)
	if n > 0 {
		c.read += int64(n)
		c.n.Add(int64(n))
	}
	if c.read > c.limit {
		return 0, errBodyTooLarge
	}
	return n, err
}
