package atlassian

// client.go is how a connector talks to a site: one Client per call, holding
// the source's credential in the form it is sent, and the set of values that
// form must never be written as.
//
// Every connection is made by a dialer that checks the address it is about to
// connect to, after DNS (Policy). The transport uses no proxy from the
// environment — a proxy would be the address checked, not the site — and
// follows no redirect: a 3xx is a failed request, not an instruction to carry
// the credential somewhere else. A request is bounded in time, its answer in
// size, and a 429 or 503 is retried after the site's Retry-After, or after a
// bounded, jittered exponential backoff when it sends none.

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/blechschmidt/cloop/pkg/boundedread"
	"github.com/blechschmidt/cloop/pkg/knowledge"
	"github.com/blechschmidt/cloop/pkg/redact"
)

// Request bounds.
const (
	// DefaultRequestTimeout bounds one request: connecting, sending, and
	// reading the whole answer.
	DefaultRequestTimeout = 60 * time.Second
	// DefaultMaxRetries bounds the retries of one request.
	DefaultMaxRetries = 5
	// DefaultMaxResponseBytes bounds one answer.
	DefaultMaxResponseBytes int64 = 48 << 20
	// MaxRetryAfter is the longest Retry-After a request waits out; a site
	// asking for longer fails the call, and the next sync tries again.
	MaxRetryAfter = 2 * time.Minute
	// BackoffBase and BackoffMax bound the wait between retries when the
	// site names none.
	BackoffBase = time.Second
	BackoffMax  = 30 * time.Second
	// maxErrorBytes bounds what of a refusal's body is read for its message.
	maxErrorBytes = 16 << 10
	// maxRequestBytes bounds a request body a connector sends.
	maxRequestBytes = 64 << 10
)

// ErrTooLarge is an answer over the client's MaxResponseBytes.
var ErrTooLarge = errors.New("the answer is larger than the connector reads")

// Config is how a Client is made.
type Config struct {
	// Product is the connector's kind, "confluence" or "jira": it names the
	// client in its errors and its User-Agent.
	Product string
	// Base is the API root, without a trailing slash: what a request's path
	// is resolved below.
	Base *url.URL
	// Auth is AuthBasic or AuthBearer; Email is basic auth's account.
	Auth  string
	Email string
	// Policy is which addresses the client may connect to.
	Policy Policy
	// Transport replaces the client's guarded transport, address checks and
	// all: for a test that talks to an httptest TLS server.
	Transport http.RoundTripper
	// Sleep waits between retries; it returns early with ctx's error.
	// Defaults to a timer.
	Sleep func(ctx context.Context, d time.Duration) error
	// Now is the clock a Retry-After date is read against.
	Now func() time.Time
	// Timeout bounds one request; DefaultRequestTimeout by default.
	Timeout time.Duration
	// Retries bounds the retries of one request; none when zero or less.
	Retries int
	// MaxResponseBytes bounds one answer; DefaultMaxResponseBytes by
	// default.
	MaxResponseBytes int64
}

// Client makes one call's requests to one site.
type Client struct {
	product string
	base    *url.URL
	// auth is the Authorization header.
	auth string
	// scrub is every form the credential is sent in: no error leaves the
	// connector with one of them in it.
	scrub    *redact.Set
	http     *http.Client
	sleep    func(context.Context, time.Duration) error
	now      func() time.Time
	timeout  time.Duration
	retries  int
	maxBytes int64
	insecure bool
}

// NewClient builds the client for a call with cred, which it reads but keeps
// no copy of beyond the header it sends.
func NewClient(cfg Config, cred knowledge.Credential) (*Client, error) {
	token := strings.TrimSpace(string(cred.Value()))
	if token == "" {
		return nil, fmt.Errorf("a %s source signs in with a secret: name one holding the API token, "+
			"OAuth access token or personal access token in the source's secret reference", cfg.Product)
	}
	if strings.ContainsAny(token, "\r\n") {
		return nil, errors.New("the source's secret holds a line break, which a token never does")
	}
	if cfg.Base == nil {
		return nil, errors.New("a client needs a base URL")
	}
	cl := &Client{
		product: cfg.Product, base: cfg.Base, http: httpClient(cfg),
		sleep: cfg.Sleep, now: cfg.Now, timeout: cfg.Timeout, retries: max(cfg.Retries, 0),
		maxBytes: cfg.MaxResponseBytes, insecure: cfg.Policy.Insecure,
	}
	if cl.sleep == nil {
		cl.sleep = sleep
	}
	if cl.now == nil {
		cl.now = time.Now
	}
	if cl.timeout <= 0 {
		cl.timeout = DefaultRequestTimeout
	}
	if cl.maxBytes <= 0 {
		cl.maxBytes = DefaultMaxResponseBytes
	}
	var forms []string
	switch cfg.Auth {
	case AuthBasic:
		basic := base64.StdEncoding.EncodeToString([]byte(cfg.Email + ":" + token))
		cl.auth = "Basic " + basic
		forms = []string{token, basic, cfg.Email + ":" + token}
	case AuthBearer:
		cl.auth = "Bearer " + token
		forms = []string{token}
	default:
		return nil, fmt.Errorf("auth is %q or %q, not %q", AuthBasic, AuthBearer, cfg.Auth)
	}
	cl.scrub = redact.New(append(forms, cl.auth)...)
	return cl, nil
}

// sleep waits d, or until ctx ends.
func sleep(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// httpClient is the HTTP client for cfg: the guarded transport, or
// cfg.Transport in a test.
func httpClient(cfg Config) *http.Client {
	noRedirect := func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	if cfg.Transport != nil {
		return &http.Client{Transport: cfg.Transport, CheckRedirect: noRedirect}
	}
	policy := cfg.Policy
	dialer := &net.Dialer{
		Timeout:   15 * time.Second,
		KeepAlive: 30 * time.Second,
		Control: func(_, address string, _ syscall.RawConn) error {
			return CheckDialAddress(address, policy)
		},
	}
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = DefaultRequestTimeout
	}
	return &http.Client{
		CheckRedirect: noRedirect,
		Transport: &http.Transport{
			Proxy:                  nil,
			DialContext:            dialer.DialContext,
			TLSClientConfig:        &tls.Config{MinVersion: tls.VersionTLS12},
			TLSHandshakeTimeout:    15 * time.Second,
			ResponseHeaderTimeout:  timeout,
			MaxResponseHeaderBytes: 64 << 10,
			MaxIdleConns:           4,
			IdleConnTimeout:        30 * time.Second,
			ForceAttemptHTTP2:      true,
		},
	}
}

// Base is the API root the client resolves paths below.
func (cl *Client) Base() *url.URL { u := *cl.base; return &u }

// Insecure reports a client that may follow http links (Policy.Insecure).
func (cl *Client) Insecure() bool { return cl.insecure }

// Close releases the client's idle connections.
func (cl *Client) Close() { cl.http.CloseIdleConnections() }

// APIError is a site's refusal of a request.
type APIError struct {
	Status int
	Method string
	// Path is the request's path below the API root, without its query.
	Path string
	Msg  string
}

func (e *APIError) Error() string {
	method := e.Method
	if method == "" {
		method = http.MethodGet
	}
	text := fmt.Sprintf("%s %s: %d %s", method, e.Path, e.Status, http.StatusText(e.Status))
	switch e.Status {
	case http.StatusUnauthorized:
		text += " — the site refused the credential: check the source's secret (an API token with the " +
			"configured email for Cloud basic auth, an OAuth access token, or a Data Center personal access token)"
	case http.StatusForbidden:
		text += " — the account the source signs in as may not read this"
	}
	if e.Msg != "" {
		text += ": " + e.Msg
	}
	return text
}

// IsStatus reports whether err is a refusal with status code, scrubbed or
// not.
func IsStatus(err error, code int) bool {
	var ae *APIError
	if errors.As(err, &ae) {
		return ae.Status == code
	}
	var ce *cleanError
	return errors.As(err, &ce) && IsStatus(ce.cause, code)
}

// Clean returns err's text with the credential, in every form it is sent in,
// and anything else shaped like a credential, removed — as an error that
// still matches what err matches (a context's cancellation, a refusal's
// status), without unwrapping to the text it replaced.
func (cl *Client) Clean(err error) error {
	if err == nil {
		return nil
	}
	var ce *cleanError
	if errors.As(err, &ce) {
		return err
	}
	text := err.Error()
	if cl != nil {
		text = cl.scrub.String(text)
	}
	return &cleanError{msg: redact.Scrub(text), cause: err}
}

// cleanError is an error whose text was scrubbed of credentials.
type cleanError struct {
	msg   string
	cause error
}

func (e *cleanError) Error() string { return e.msg }

// Is reports whether the scrubbed error's cause matches target.
func (e *cleanError) Is(target error) bool { return errors.Is(e.cause, target) }

// resolve turns ref — a path below the API root, with its query — into a URL
// on the site.
func (cl *Client) resolve(ref string) (*url.URL, error) {
	path, query, _ := strings.Cut(ref, "?")
	if !strings.HasPrefix(path, "/") || strings.HasPrefix(path, "//") {
		return nil, fmt.Errorf("%q is not a path on the site", ref)
	}
	for _, seg := range strings.Split(path, "/") {
		if seg == "." || seg == ".." {
			return nil, fmt.Errorf("%q is not a path on the site", ref)
		}
	}
	u := *cl.base
	u.Path = cl.base.Path + path
	u.RawPath = ""
	u.RawQuery = query
	return &u, nil
}

// Get fetches ref and decodes the JSON answer into v, retrying a site that
// asks to be retried.
func (cl *Client) Get(ctx context.Context, ref string, v any) error {
	return cl.do(ctx, http.MethodGet, ref, nil, v)
}

// Post sends body, as JSON, to ref and decodes the JSON answer into v,
// retrying as Get does. It is for the reads an API offers as a POST — a
// search whose query would not fit a URL — never for a change.
func (cl *Client) Post(ctx context.Context, ref string, body, v any) error {
	b, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("POST %s: encode the request: %v", strings.SplitN(ref, "?", 2)[0], err)
	}
	if len(b) > maxRequestBytes {
		return fmt.Errorf("POST %s: the request is larger than %d KiB", strings.SplitN(ref, "?", 2)[0], maxRequestBytes>>10)
	}
	return cl.do(ctx, http.MethodPost, ref, b, v)
}

// do makes a request until it succeeds, fails for good, or runs out of
// retries.
func (cl *Client) do(ctx context.Context, method, ref string, body []byte, v any) error {
	u, err := cl.resolve(ref)
	if err != nil {
		return err
	}
	path, _, _ := strings.Cut(ref, "?")
	for attempt := 0; ; attempt++ {
		answer, wait, err := cl.attempt(ctx, method, u, path, body)
		if err == nil {
			if err := json.Unmarshal(answer, v); err != nil {
				return fmt.Errorf("%s %s: the answer is not the JSON the API returns: %v", method, path, err)
			}
			return nil
		}
		if wait < 0 || attempt >= cl.retries || ctx.Err() != nil {
			if ctx.Err() != nil {
				return fmt.Errorf("%s %s: %w", method, path, ctx.Err())
			}
			return err
		}
		if wait == 0 {
			wait = Backoff(attempt)
		}
		if err := cl.sleep(ctx, wait); err != nil {
			return fmt.Errorf("%s %s: %w", method, path, err)
		}
	}
}

// Backoff is the wait before retry attempt+1 when the site names none:
// exponential from BackoffBase, at most BackoffMax, its upper half jittered so
// that the hub's syncs do not retry in step.
func Backoff(attempt int) time.Duration {
	d := BackoffMax
	if attempt < 16 {
		d = min(BackoffBase<<attempt, BackoffMax)
	}
	return d/2 + time.Duration(rand.Int64N(int64(d/2)+1))
}

// attempt makes one request. It returns the body of a 2xx answer; or the
// error, with how long to wait before retrying: 0 for the backoff's choice,
// negative for an error retrying cannot fix.
func (cl *Client) attempt(ctx context.Context, method string, u *url.URL, path string, body []byte) ([]byte, time.Duration, error) {
	actx, cancel := context.WithTimeout(ctx, cl.timeout)
	defer cancel()
	var reqBody io.Reader
	if body != nil {
		reqBody = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(actx, method, u.String(), reqBody)
	if err != nil {
		return nil, -1, fmt.Errorf("%s %s: %v", method, path, err)
	}
	req.Header.Set("Authorization", cl.auth)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "cloop-knowledge-"+cl.product+"/1")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := cl.http.Do(req)
	if err != nil {
		if errors.Is(err, ErrBlockedAddress) {
			return nil, -1, fmt.Errorf("%s %s: %w", method, path, unwrapBlocked(err))
		}
		var cert *tls.CertificateVerificationError
		if errors.As(err, &cert) {
			return nil, -1, fmt.Errorf("%s %s: the site's certificate is not trusted: %v", method, path, cert.Err)
		}
		// A timeout, a reset, a refused connection: the network's, and worth
		// another try.
		return nil, 0, fmt.Errorf("%s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	switch {
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		answer, err := boundedread.ReadAll(resp.Body, "a "+cl.product+" answer", cl.maxBytes)
		if errors.Is(err, boundedread.ErrTooLarge) {
			return nil, -1, fmt.Errorf("%s %s: %w (%s)", method, path, ErrTooLarge, sizeText(cl.maxBytes))
		}
		if err != nil {
			return nil, 0, fmt.Errorf("%s %s: %v", method, path, err)
		}
		return answer, 0, nil
	case resp.StatusCode >= 300 && resp.StatusCode < 400:
		return nil, -1, fmt.Errorf("%s %s: the site answered %d, a redirect to %q; the connector follows none — "+
			"set base_url to where the site is", method, path, resp.StatusCode, redact.Scrub(resp.Header.Get("Location")))
	}
	refusal := &APIError{Status: resp.StatusCode, Method: method, Path: path, Msg: ErrorMessage(resp.Body)}
	switch resp.StatusCode {
	case http.StatusTooManyRequests, http.StatusServiceUnavailable:
		wait, ok := RetryAfter(resp.Header.Get("Retry-After"), cl.now())
		if !ok {
			return nil, 0, refusal
		}
		if wait > MaxRetryAfter {
			return nil, -1, fmt.Errorf("%w; the site asks to wait %s, longer than a sync waits — the next sync tries again",
				refusal, wait.Round(time.Second))
		}
		// At least a moment, so a "Retry-After: 0" is not a busy loop.
		return nil, max(wait, 100*time.Millisecond), refusal
	case http.StatusBadGateway, http.StatusGatewayTimeout:
		return nil, 0, refusal
	}
	return nil, -1, refusal
}

// sizeText is n bytes as a person reads it.
func sizeText(n int64) string {
	if n >= 1<<20 && n%(1<<20) == 0 {
		return strconv.FormatInt(n>>20, 10) + " MiB"
	}
	return strconv.FormatInt(n>>10, 10) + " KiB"
}

// unwrapBlocked returns the address refusal inside a transport error, without
// the URL the transport wraps it in.
func unwrapBlocked(err error) error {
	for e := err; e != nil; e = errors.Unwrap(e) {
		if strings.HasPrefix(e.Error(), ErrBlockedAddress.Error()) {
			return e
		}
	}
	return err
}

// RetryAfter reads a Retry-After header: seconds, or an HTTP date.
func RetryAfter(v string, now time.Time) (time.Duration, bool) {
	v = strings.TrimSpace(v)
	if v == "" {
		return 0, false
	}
	if n, err := strconv.ParseInt(v, 10, 64); err == nil {
		if n < 0 {
			return 0, false
		}
		if n > int64(24*time.Hour/time.Second) {
			n = int64(24 * time.Hour / time.Second)
		}
		return time.Duration(n) * time.Second, true
	}
	if t, err := http.ParseTime(v); err == nil {
		return max(t.Sub(now), 0), true
	}
	return 0, false
}

// ErrorMessage reads what a refusal says: the message of an Atlassian error
// body in any of its products' forms — Confluence's "message", v2 "errors"
// list and v1 "data.errors"; Jira's "errorMessages" and per-field "errors"
// object — or a line of its text.
func ErrorMessage(r io.Reader) string {
	b, _, err := boundedread.ReadTruncated(r, maxErrorBytes)
	if err != nil || len(b) == 0 {
		return ""
	}
	var body struct {
		Message       string          `json:"message"`
		ErrorMessages []string        `json:"errorMessages"`
		Errors        json.RawMessage `json:"errors"`
		Data          struct {
			Errors []struct {
				Message struct {
					Translation string `json:"translation"`
					Key         string `json:"key"`
				} `json:"message"`
			} `json:"errors"`
		} `json:"data"`
	}
	msg := ""
	if json.Unmarshal(b, &body) == nil {
		var parts []string
		if body.Message != "" {
			parts = append(parts, body.Message)
		}
		parts = append(parts, body.ErrorMessages...)
		parts = append(parts, fieldErrors(body.Errors)...)
		for _, e := range body.Data.Errors {
			if e.Message.Translation != "" {
				parts = append(parts, e.Message.Translation)
			}
		}
		msg = strings.Join(parts, "; ")
	} else if !strings.Contains(strings.ToLower(string(b[:min(len(b), 512)])), "<html") {
		msg = string(b)
	}
	msg = strings.Join(strings.Fields(strings.ToValidUTF8(msg, "")), " ")
	if len(msg) > 400 {
		msg = msg[:400] + "…"
	}
	return msg
}

// fieldErrors reads an "errors" member: Confluence v2's list of titled
// errors, or Jira's object of messages by field, in field order.
func fieldErrors(raw json.RawMessage) []string {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 {
		return nil
	}
	var parts []string
	switch raw[0] {
	case '[':
		var list []struct {
			Title   string `json:"title"`
			Detail  string `json:"detail"`
			Message string `json:"message"`
		}
		if json.Unmarshal(raw, &list) != nil {
			return nil
		}
		for _, e := range list {
			if s := strings.TrimSpace(e.Title + " " + e.Detail + " " + e.Message); s != "" {
				parts = append(parts, s)
			}
		}
	case '{':
		var byField map[string]json.RawMessage
		if json.Unmarshal(raw, &byField) != nil {
			return nil
		}
		fields := make([]string, 0, len(byField))
		for f := range byField {
			fields = append(fields, f)
		}
		sort.Strings(fields)
		for _, f := range fields {
			var text string
			if json.Unmarshal(byField[f], &text) == nil && strings.TrimSpace(text) != "" {
				parts = append(parts, f+": "+text)
			}
		}
	}
	return parts
}
