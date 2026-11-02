package confluence

// client.go is how the connector talks to a site: one client per call, holding
// the source's credential in the form it is sent, and the set of values that
// form must never be written as.
//
// Every connection is made by a dialer that checks the address it is about to
// connect to, after DNS (addressPolicy). The transport uses no proxy from the
// environment — a proxy would be the address checked, not the site — and
// follows no redirect: a 3xx is a failed request, not an instruction to carry
// the credential somewhere else. A request is bounded in time, its answer in
// size, and a 429 or 503 is retried after the site's Retry-After, or after a
// bounded, jittered exponential backoff when it sends none.

import (
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
	"net/netip"
	"net/url"
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
	// maxErrorBytes bounds what of a refusal's body is read for its message.
	maxErrorBytes = 16 << 10
	// maxRetryAfter is the longest Retry-After a request waits out; a site
	// asking for longer fails the call, and the next sync tries again.
	maxRetryAfter = 2 * time.Minute
	// backoffBase and backoffMax bound the wait between retries when the
	// site names none.
	backoffBase = time.Second
	backoffMax  = 30 * time.Second
	userAgent   = "cloop-knowledge-confluence/1"
)

// maxResponseBytes bounds one answer. A listing asks for few pages at once
// with their bodies, and asks for fewer when an answer is larger. A variable
// only so that a test can make an answer too large without sending 48 MiB.
var maxResponseBytes int64 = 48 << 20

// errTooLarge is an answer over maxResponseBytes.
var errTooLarge = errors.New("the answer is larger than the connector reads")

// apiError is a site's refusal of a request.
type apiError struct {
	Status int
	// Path is the request's path below the API root, without its query.
	Path string
	Msg  string
}

func (e *apiError) Error() string {
	text := fmt.Sprintf("GET %s: %d %s", e.Path, e.Status, http.StatusText(e.Status))
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

// isStatus reports whether err is a refusal with status code, scrubbed or not.
func isStatus(err error, code int) bool {
	var ae *apiError
	if errors.As(err, &ae) {
		return ae.Status == code
	}
	var ce *cleanError
	return errors.As(err, &ce) && isStatus(ce.cause, code)
}

// client makes one call's requests to one site.
type client struct {
	base *url.URL
	// auth is the Authorization header.
	auth string
	// scrub is every form the credential is sent in: no error leaves the
	// connector with one of them in it.
	scrub   *redact.Set
	http    *http.Client
	sleep   func(context.Context, time.Duration) error
	now     func() time.Time
	timeout time.Duration
	retries int
	// insecure admits an http base URL's links (Options.AllowInsecure).
	insecure bool
}

// newClient builds the client for a call with cred, which it reads but keeps
// no copy of beyond the header it sends.
func (c *Connector) newClient(s settings, cred knowledge.Credential) (*client, error) {
	token := strings.TrimSpace(string(cred.Value()))
	if token == "" {
		return nil, errors.New("a confluence source signs in with a secret: name one holding the API token, " +
			"OAuth access token or personal access token in the source's secret reference")
	}
	if strings.ContainsAny(token, "\r\n") {
		return nil, errors.New("the source's secret holds a line break, which a token never does")
	}
	cl := &client{
		base: s.base, http: c.httpClient(s.policy),
		sleep: c.opts.Sleep, now: c.opts.Now, timeout: c.opts.RequestTimeout, retries: c.opts.MaxRetries,
		insecure: c.opts.AllowInsecure,
	}
	var forms []string
	switch s.auth {
	case AuthBasic:
		basic := base64.StdEncoding.EncodeToString([]byte(s.email + ":" + token))
		cl.auth = "Basic " + basic
		forms = []string{token, basic, s.email + ":" + token}
	default:
		cl.auth = "Bearer " + token
		forms = []string{token}
	}
	cl.scrub = redact.New(append(forms, cl.auth)...)
	return cl, nil
}

// httpClient is the HTTP client for a source under policy: the connector's
// own guarded transport, or Options.Transport in a test.
func (c *Connector) httpClient(policy addressPolicy) *http.Client {
	noRedirect := func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	if c.opts.Transport != nil {
		return &http.Client{Transport: c.opts.Transport, CheckRedirect: noRedirect}
	}
	dialer := &net.Dialer{
		Timeout:   15 * time.Second,
		KeepAlive: 30 * time.Second,
		Control: func(_, address string, _ syscall.RawConn) error {
			return checkDialAddress(address, policy)
		},
	}
	return &http.Client{
		CheckRedirect: noRedirect,
		Transport: &http.Transport{
			Proxy:                  nil,
			DialContext:            dialer.DialContext,
			TLSClientConfig:        &tls.Config{MinVersion: tls.VersionTLS12},
			TLSHandshakeTimeout:    15 * time.Second,
			ResponseHeaderTimeout:  c.opts.RequestTimeout,
			MaxResponseHeaderBytes: 64 << 10,
			MaxIdleConns:           4,
			IdleConnTimeout:        30 * time.Second,
			ForceAttemptHTTP2:      true,
		},
	}
}

// checkDialAddress applies policy to the "ip:port" a socket is about to
// connect to.
func checkDialAddress(address string, policy addressPolicy) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("%w: dial address %q: %v", ErrBlockedAddress, address, err)
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		// The dialer resolves before it connects; anything else is a dial
		// this package did not expect, and is refused rather than trusted.
		return fmt.Errorf("%w: dial address %q is not an IP address", ErrBlockedAddress, address)
	}
	return policy.checkAddr(ip)
}

// close releases the client's idle connections.
func (cl *client) close() { cl.http.CloseIdleConnections() }

// clean returns err's text with the credential, in every form it is sent in,
// and anything else shaped like a credential, removed — as an error that
// still matches what err matches (a context's cancellation, a refusal's
// status), without unwrapping to the text it replaced.
func (cl *client) clean(err error) error {
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
func (cl *client) resolve(ref string) (*url.URL, error) {
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

// get fetches ref and decodes the JSON answer into v, retrying a site that
// asks to be retried.
func (cl *client) get(ctx context.Context, ref string, v any) error {
	u, err := cl.resolve(ref)
	if err != nil {
		return err
	}
	path, _, _ := strings.Cut(ref, "?")
	for attempt := 0; ; attempt++ {
		body, wait, err := cl.attempt(ctx, u, path)
		if err == nil {
			if err := json.Unmarshal(body, v); err != nil {
				return fmt.Errorf("GET %s: the answer is not the JSON the API returns: %v", path, err)
			}
			return nil
		}
		if wait < 0 || attempt >= cl.retries || ctx.Err() != nil {
			if ctx.Err() != nil {
				return fmt.Errorf("GET %s: %w", path, ctx.Err())
			}
			return err
		}
		if wait == 0 {
			wait = backoff(attempt)
		}
		if err := cl.sleep(ctx, wait); err != nil {
			return fmt.Errorf("GET %s: %w", path, err)
		}
	}
}

// backoff is the wait before retry attempt+1 when the site names none:
// exponential from backoffBase, at most backoffMax, its upper half jittered so
// that the hub's syncs do not retry in step.
func backoff(attempt int) time.Duration {
	d := backoffMax
	if attempt < 16 {
		d = min(backoffBase<<attempt, backoffMax)
	}
	return d/2 + time.Duration(rand.Int64N(int64(d/2)+1))
}

// attempt makes one request. It returns the body of a 2xx answer; or the
// error, with how long to wait before retrying: 0 for the backoff's choice,
// negative for an error retrying cannot fix.
func (cl *client) attempt(ctx context.Context, u *url.URL, path string) ([]byte, time.Duration, error) {
	actx, cancel := context.WithTimeout(ctx, cl.timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(actx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, -1, fmt.Errorf("GET %s: %v", path, err)
	}
	req.Header.Set("Authorization", cl.auth)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", userAgent)
	resp, err := cl.http.Do(req)
	if err != nil {
		if errors.Is(err, ErrBlockedAddress) {
			return nil, -1, fmt.Errorf("GET %s: %w", path, unwrapBlocked(err))
		}
		var cert *tls.CertificateVerificationError
		if errors.As(err, &cert) {
			return nil, -1, fmt.Errorf("GET %s: the site's certificate is not trusted: %v", path, cert.Err)
		}
		// A timeout, a reset, a refused connection: the network's, and worth
		// another try.
		return nil, 0, fmt.Errorf("GET %s: %v", path, err)
	}
	defer resp.Body.Close()
	switch {
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		body, err := boundedread.ReadAll(resp.Body, "a confluence answer", maxResponseBytes)
		if errors.Is(err, boundedread.ErrTooLarge) {
			return nil, -1, fmt.Errorf("GET %s: %w (%d MiB)", path, errTooLarge, maxResponseBytes>>20)
		}
		if err != nil {
			return nil, 0, fmt.Errorf("GET %s: %v", path, err)
		}
		return body, 0, nil
	case resp.StatusCode >= 300 && resp.StatusCode < 400:
		return nil, -1, fmt.Errorf("GET %s: the site answered %d, a redirect to %q; the connector follows none — "+
			"set base_url to where the site is", path, resp.StatusCode, redact.Scrub(resp.Header.Get("Location")))
	}
	refusal := &apiError{Status: resp.StatusCode, Path: path, Msg: errorMessage(resp.Body)}
	switch resp.StatusCode {
	case http.StatusTooManyRequests, http.StatusServiceUnavailable:
		wait, ok := retryAfter(resp.Header.Get("Retry-After"), cl.now())
		if !ok {
			return nil, 0, refusal
		}
		if wait > maxRetryAfter {
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

// retryAfter reads a Retry-After header: seconds, or an HTTP date.
func retryAfter(v string, now time.Time) (time.Duration, bool) {
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

// errorMessage reads what a refusal says: the message of Confluence's error
// body, in either API's form, or a line of its text.
func errorMessage(r io.Reader) string {
	b, _, err := boundedread.ReadTruncated(r, maxErrorBytes)
	if err != nil || len(b) == 0 {
		return ""
	}
	var body struct {
		Message string `json:"message"`
		Errors  []struct {
			Title  string `json:"title"`
			Detail string `json:"detail"`
		} `json:"errors"`
		Data struct {
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
		for _, e := range body.Errors {
			if s := strings.TrimSpace(e.Title + " " + e.Detail); s != "" {
				parts = append(parts, s)
			}
		}
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
