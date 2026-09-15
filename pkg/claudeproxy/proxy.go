package claudeproxy

// proxy.go is the request path: authenticate, decide, attach the hub's
// credential, forward, meter.
//
// The ordering is the point. The upstream credential is attached in exactly
// one place, after the policy has returned nil, so there is no code path in
// which a refused request and a credentialled request differ only by a
// forgotten early return.

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"path"
	"strings"
	"sync"
	"time"
)

const (
	// upstreamHeaderTimeout bounds how long the upstream may take to send
	// response headers. The body is not bounded: a long agent turn streams
	// for minutes and the request context cancels it if the client leaves.
	upstreamHeaderTimeout = 120 * time.Second

	// dialTimeout bounds establishing the upstream connection.
	dialTimeout = 15 * time.Second

	// maxMeteredResponseBytes bounds the buffer used to read `usage` out of a
	// non-streaming response. Past it, metering is abandoned and the body is
	// still relayed: losing a token count is acceptable, truncating a
	// response is not.
	maxMeteredResponseBytes = 4 << 20

	// maxSSELineBytes bounds one server-sent-event line while scanning for
	// usage. A data line carrying a large text delta exceeds this and is
	// skipped for metering purposes, which is correct: usage lines are small.
	maxSSELineBytes = 1 << 20
)

// hopByHopHeaders are stripped in both directions per RFC 7230 §6.1.
var hopByHopHeaders = []string{
	"Connection", "Keep-Alive", "Proxy-Authenticate", "Proxy-Authorization",
	"Proxy-Connection", "Te", "Trailer", "Transfer-Encoding", "Upgrade",
}

// forwardedRequestHeaders is the allowlist of headers copied from the client
// to the upstream.
//
// An allowlist, not a denylist: the header set an SDK sends grows with the
// SDK, and a denylist that has not been updated is a denylist that forwards
// whatever was added. The cost is that a genuinely new header has to be added
// here, which is a code change with a reviewer — the right amount of friction
// for "what does the hub's credential get sent alongside".
var forwardedRequestHeaders = []string{
	"Content-Type",
	"Accept",
	"Anthropic-Version",
	"Anthropic-Beta",
}

// Options configures a Proxy.
type Options struct {
	// Upstream is the credential and endpoint to relay to.
	Upstream Upstream

	// PathPrefix is stripped from the incoming path before the API surface
	// is matched, e.g. "/api/ci/anthropic".
	PathPrefix string

	// Transport overrides the upstream HTTP transport. Tests point this at
	// an httptest server.
	Transport http.RoundTripper

	// Now overrides the clock.
	Now func() time.Time
}

// Proxy relays requests from CI sessions to the Anthropic API.
type Proxy struct {
	reg    *Registry
	up     Upstream
	prefix string
	client *http.Client
	now    func() time.Time
}

// New returns a Proxy serving sessions from reg.
func New(reg *Registry, opts Options) (*Proxy, error) {
	if reg == nil {
		return nil, errors.New("claudeproxy: nil registry")
	}
	if err := opts.Upstream.Validate(); err != nil {
		return nil, err
	}
	rt := opts.Transport
	if rt == nil {
		rt = &http.Transport{
			DialContext:           (&net.Dialer{Timeout: dialTimeout}).DialContext,
			ResponseHeaderTimeout: upstreamHeaderTimeout,
			ForceAttemptHTTP2:     true,
			MaxIdleConnsPerHost:   8,
		}
	}
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	return &Proxy{
		reg:    reg,
		up:     opts.Upstream,
		prefix: strings.TrimSuffix(opts.PathPrefix, "/"),
		// No client timeout: a streamed agent turn legitimately runs for
		// minutes, and the request context already cancels when the pipeline
		// gives up.
		client: &http.Client{Transport: rt},
		now:    now,
	}, nil
}

// Registry returns the registry this proxy serves.
func (p *Proxy) Registry() *Registry { return p.reg }

// ServeHTTP implements http.Handler.
func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	sess, err := p.authenticate(r)
	if err != nil {
		p.reg.emit(Event{
			Kind: EventRejected, Method: r.Method, Path: p.apiPath(r),
			Detail: "no usable session token", At: p.now(),
		})
		// The WWW-Authenticate header is what makes an SDK's error message
		// say "authentication" rather than "unexpected response".
		w.Header().Set("WWW-Authenticate", `Bearer realm="cloop-ci"`)
		writeAPIError(w, http.StatusUnauthorized, "authentication_error",
			"the CI session token was not accepted; federate again to obtain a fresh one")
		return
	}

	apiPath := p.apiPath(r)
	if d := AllowsPath(r.Method, apiPath); d != nil {
		p.denied(w, sess, r, apiPath, "", d)
		return
	}

	body, d := p.readBody(r, sess.Policy.BodyCap())
	if d != nil {
		p.denied(w, sess, r, apiPath, "", d)
		return
	}

	model := ""
	if apiPath == "/v1/messages" || apiPath == "/v1/messages/count_tokens" {
		rewritten, req, dd := sess.Policy.DecideMessages(body)
		if dd != nil {
			p.denied(w, sess, r, apiPath, req.Model, dd)
			return
		}
		body, model = rewritten, req.Model
	}

	// Budget is claimed only once every other check has passed, so a request
	// the policy was going to refuse does not consume a unit of a pipeline's
	// allowance.
	if !sess.claimRequest() {
		p.denied(w, sess, r, apiPath, model, &Denial{
			Reason: DenyBudget, Status: http.StatusTooManyRequests,
			Message: fmt.Sprintf("this session's budget of %d requests is spent", sess.Policy.MaxRequests),
		})
		return
	}
	sess.bytesUp.Add(int64(len(body)))

	if err := p.forward(w, r, sess, apiPath, model, body); err != nil {
		// The reservation is returned only when the upstream was never
		// reached. Once it has answered, the request was spent whatever the
		// status.
		sess.releaseRequest()
		p.reg.emit(Event{
			Kind: EventRelayDenied, SessionID: sess.ID, RuleID: sess.RuleID, RuleName: sess.RuleName,
			Project: sess.Project, Repository: sess.Repository, Ref: sess.Ref,
			Workflow: sess.Workflow, Actor: sess.Actor, RunID: sess.RunID,
			Method: r.Method, Path: apiPath, Model: model,
			Detail: "upstream unreachable: " + err.Error(), At: p.now(),
		})
		writeAPIError(w, http.StatusBadGateway, "api_error",
			"the cloop hub could not reach the Anthropic API")
	}
}

// authenticate resolves the session from either credential form.
//
// Both are accepted because both are in use: Claude Code sends
// ANTHROPIC_AUTH_TOKEN as a bearer, while the SDKs send ANTHROPIC_API_KEY in
// x-api-key. A pipeline should not have to know which one the harness it runs
// happens to use.
func (p *Proxy) authenticate(r *http.Request) (*Session, error) {
	if auth := r.Header.Get("Authorization"); auth != "" {
		if tok, ok := strings.CutPrefix(auth, "Bearer "); ok {
			return p.reg.Authenticate(strings.TrimSpace(tok))
		}
		return nil, ErrUnauthenticated
	}
	if key := r.Header.Get("X-Api-Key"); key != "" {
		return p.reg.Authenticate(strings.TrimSpace(key))
	}
	return nil, ErrUnauthenticated
}

// apiPath is the request path with the mount prefix removed, normalised.
//
// Normalising *here* rather than inside the allowlist check is the point. The
// two have to be the same string: a path that is checked after cleaning but
// forwarded before it is a path where "/v1/messages/../batches" satisfies a
// check about /v1/batches and then asks the upstream for something else. That
// is the classic shape of a proxy bypass, and the only reliable fix is for
// there to be one path value.
func (p *Proxy) apiPath(r *http.Request) string {
	raw := r.URL.Path
	if p.prefix != "" {
		if trimmed, ok := strings.CutPrefix(raw, p.prefix); ok {
			raw = trimmed
		}
	}
	if !strings.HasPrefix(raw, "/") {
		raw = "/" + raw
	}
	return path.Clean(raw)
}

// readBody reads and bounds the request body.
func (p *Proxy) readBody(r *http.Request, limit int64) ([]byte, *Denial) {
	if r.Body == nil {
		return nil, nil
	}
	// Content-Length is checked first so an oversize body is refused before
	// it is read, then the read is bounded anyway because Content-Length is
	// a claim by the client.
	if r.ContentLength > limit {
		return nil, &Denial{Reason: DenyBodyTooLarge, Status: http.StatusRequestEntityTooLarge,
			Message: fmt.Sprintf("request body is %d bytes, limit is %d", r.ContentLength, limit)}
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, limit+1))
	if err != nil {
		return nil, &Denial{Reason: DenyBodyMalformed, Status: http.StatusBadRequest,
			Message: "request body could not be read"}
	}
	if int64(len(body)) > limit {
		return nil, &Denial{Reason: DenyBodyTooLarge, Status: http.StatusRequestEntityTooLarge,
			Message: fmt.Sprintf("request body exceeds the %d byte limit", limit)}
	}
	return body, nil
}

// denied records a refusal and answers the client.
func (p *Proxy) denied(w http.ResponseWriter, sess *Session, r *http.Request,
	apiPath, model string, d *Denial) {

	sess.denied.Add(1)
	p.reg.emit(Event{
		Kind: EventRelayDenied, SessionID: sess.ID, RuleID: sess.RuleID, RuleName: sess.RuleName,
		Project: sess.Project, Repository: sess.Repository, Ref: sess.Ref,
		Workflow: sess.Workflow, Actor: sess.Actor, RunID: sess.RunID,
		Method: r.Method, Path: apiPath, Model: model,
		Reason: d.Reason, Status: d.Status, Detail: d.Message, At: p.now(),
	})
	status := d.Status
	if status == 0 {
		status = http.StatusForbidden
	}
	// The refusal is shaped like an Anthropic API error so an SDK surfaces
	// the message instead of "unexpected response body".
	kind := "permission_error"
	switch status {
	case http.StatusRequestEntityTooLarge, http.StatusBadRequest:
		kind = "invalid_request_error"
	case http.StatusTooManyRequests:
		kind = "rate_limit_error"
	case http.StatusNotFound, http.StatusMethodNotAllowed:
		kind = "not_found_error"
	}
	writeAPIError(w, status, kind, d.Message)
}

// forward relays the request with the hub's credential attached.
func (p *Proxy) forward(w http.ResponseWriter, r *http.Request, sess *Session,
	apiPath, model string, body []byte) error {

	target := p.up.Base() + apiPath
	if q := r.URL.RawQuery; q != "" {
		target += "?" + q
	}
	req, err := http.NewRequestWithContext(r.Context(), r.Method, target, bytes.NewReader(body))
	if err != nil {
		return err
	}
	for _, h := range forwardedRequestHeaders {
		if v := r.Header.Get(h); v != "" {
			req.Header.Set(h, v)
		}
	}
	if req.Header.Get("Content-Type") == "" && len(body) > 0 {
		req.Header.Set("Content-Type", "application/json")
	}
	if req.Header.Get("Anthropic-Version") == "" {
		// A missing version is a 400 from the API. Supplying one keeps a
		// minimal client working rather than failing in a way that looks
		// like the proxy is broken.
		req.Header.Set("Anthropic-Version", "2023-06-01")
	}
	// The hub identifies itself, replacing whatever the runner sent. The
	// session ID is included so an upstream rate-limit or abuse report can be
	// traced back to one pipeline without the hub having to keep a second log.
	req.Header.Set("User-Agent", "cloop-ci-proxy/1 (session "+sess.ID+")")

	// The one place the credential is attached.
	if k := strings.TrimSpace(p.up.APIKey); k != "" {
		req.Header.Set("X-Api-Key", k)
	} else {
		req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(p.up.AuthToken))
	}

	resp, err := p.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close() //nolint:errcheck // response body, read-only

	for k, vv := range resp.Header {
		if isHopByHop(k) || strings.EqualFold(k, "Www-Authenticate") {
			// WWW-Authenticate is dropped: it describes how to authenticate
			// to Anthropic, which is not something this pipeline can or
			// should act on.
			continue
		}
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)

	meter := newUsageMeter(resp.Header.Get("Content-Type"))
	n, copyErr := streamBody(w, resp.Body, meter)
	sess.bytesDown.Add(n)

	u := meter.result()
	sess.inTok.Add(u.input)
	sess.outTok.Add(u.output)
	sess.cacheRead.Add(u.cacheRead)
	sess.cacheWrite.Add(u.cacheWrite)

	detail := ""
	if copyErr != nil {
		detail = "client disconnected: " + copyErr.Error()
	}
	p.reg.emit(Event{
		Kind: EventRelayAllowed, SessionID: sess.ID, RuleID: sess.RuleID, RuleName: sess.RuleName,
		Project: sess.Project, Repository: sess.Repository, Ref: sess.Ref,
		Workflow: sess.Workflow, Actor: sess.Actor, RunID: sess.RunID,
		Method: r.Method, Path: apiPath, Model: model, Status: resp.StatusCode,
		InputTokens: u.input + u.cacheRead + u.cacheWrite, OutputTokens: u.output,
		Detail: detail, At: p.now(),
	})
	return nil
}

// streamBody copies the upstream response to the client, flushing as it goes
// so server-sent events arrive as they are produced rather than at the end.
func streamBody(w http.ResponseWriter, body io.Reader, meter *usageMeter) (int64, error) {
	flusher, _ := w.(http.Flusher)
	buf := make([]byte, 32<<10)
	var total int64
	for {
		n, err := body.Read(buf)
		if n > 0 {
			meter.observe(buf[:n])
			if _, werr := w.Write(buf[:n]); werr != nil {
				return total, werr
			}
			total += int64(n)
			if flusher != nil {
				flusher.Flush()
			}
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				return total, nil
			}
			return total, err
		}
	}
}

func isHopByHop(h string) bool {
	for _, x := range hopByHopHeaders {
		if strings.EqualFold(h, x) {
			return true
		}
	}
	return false
}

// writeAPIError answers in the Anthropic API's error shape.
func writeAPIError(w http.ResponseWriter, status int, kind, message string) {
	if w == nil {
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"type": "error",
		"error": map[string]any{
			"type":    kind,
			"message": message,
		},
	})
}

// ---------------------------------------------------------------------------
// Usage metering
// ---------------------------------------------------------------------------

// usageTotals is what one response reported spending.
type usageTotals struct {
	input      int64
	output     int64
	cacheRead  int64
	cacheWrite int64
}

// usageMeter extracts token counts from a response as it streams past.
//
// Both response shapes carry the same information in different places. A
// buffered response has a top-level `usage` object. A streamed one reports
// input tokens in message_start and a running output total in each
// message_delta, so the last value seen is the total rather than something to
// add up — getting that backwards would inflate every streamed call's
// reported spend by roughly the number of deltas.
type usageMeter struct {
	sse bool

	mu      sync.Mutex
	partial []byte
	buf     []byte
	gaveUp  bool
	totals  usageTotals
}

func newUsageMeter(contentType string) *usageMeter {
	return &usageMeter{sse: strings.Contains(strings.ToLower(contentType), "text/event-stream")}
}

func (m *usageMeter) observe(chunk []byte) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.gaveUp {
		return
	}
	if !m.sse {
		if len(m.buf)+len(chunk) > maxMeteredResponseBytes {
			// A response too large to hold is a response whose token count
			// is not worth holding it for. Relaying continues regardless.
			m.gaveUp = true
			m.buf = nil
			return
		}
		m.buf = append(m.buf, chunk...)
		return
	}
	m.partial = append(m.partial, chunk...)
	for {
		i := bytes.IndexByte(m.partial, '\n')
		if i < 0 {
			if len(m.partial) > maxSSELineBytes {
				// An enormous line is a text delta, never a usage line.
				m.partial = m.partial[:0]
			}
			return
		}
		line := m.partial[:i]
		m.partial = m.partial[i+1:]
		m.scanSSELine(line)
	}
}

// scanSSELine reads usage out of one `data:` line. Lines without "usage" in
// them are the overwhelming majority and are rejected by a substring test
// before any JSON decoding happens.
func (m *usageMeter) scanSSELine(line []byte) {
	data, ok := bytes.CutPrefix(bytes.TrimSpace(line), []byte("data:"))
	if !ok || !bytes.Contains(data, []byte(`"usage"`)) {
		return
	}
	var ev struct {
		Type    string     `json:"type"`
		Usage   *usageJSON `json:"usage"`
		Message *struct {
			Usage *usageJSON `json:"usage"`
		} `json:"message"`
	}
	if err := json.Unmarshal(bytes.TrimSpace(data), &ev); err != nil {
		return
	}
	if ev.Message != nil && ev.Message.Usage != nil {
		u := ev.Message.Usage
		m.totals.input = u.Input
		m.totals.cacheRead = u.CacheRead
		m.totals.cacheWrite = u.CacheWrite
		if u.Output > m.totals.output {
			m.totals.output = u.Output
		}
	}
	if ev.Usage != nil {
		if ev.Usage.Input > 0 {
			m.totals.input = ev.Usage.Input
		}
		if ev.Usage.CacheRead > 0 {
			m.totals.cacheRead = ev.Usage.CacheRead
		}
		if ev.Usage.CacheWrite > 0 {
			m.totals.cacheWrite = ev.Usage.CacheWrite
		}
		// Cumulative, not incremental: take the maximum rather than the sum.
		if ev.Usage.Output > m.totals.output {
			m.totals.output = ev.Usage.Output
		}
	}
}

type usageJSON struct {
	Input      int64 `json:"input_tokens"`
	Output     int64 `json:"output_tokens"`
	CacheRead  int64 `json:"cache_read_input_tokens"`
	CacheWrite int64 `json:"cache_creation_input_tokens"`
}

func (m *usageMeter) result() usageTotals {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.sse || m.gaveUp {
		return m.totals
	}
	var doc struct {
		Usage *usageJSON `json:"usage"`
	}
	if err := json.Unmarshal(m.buf, &doc); err == nil && doc.Usage != nil {
		m.totals = usageTotals{
			input:      doc.Usage.Input,
			output:     doc.Usage.Output,
			cacheRead:  doc.Usage.CacheRead,
			cacheWrite: doc.Usage.CacheWrite,
		}
	}
	return m.totals
}
