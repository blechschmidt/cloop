package hubclient

// The HTTP half: one client for a hub, which speaks the hub's three error
// dialects back as one error type, trusts an extra CA when told to, and never
// follows a redirect with the credential attached.

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/version"
)

// maxResponseBytes bounds how much of any hub answer is read. A project list
// or a task list is well under this; a hub that sends more is not one to
// buffer without limit.
const maxResponseBytes = 32 << 20

// requestTimeout bounds one API call. Streams (FollowLogs) are not calls and
// are bounded by their context instead.
const requestTimeout = 60 * time.Second

// longRequestTimeout bounds the calls the hub answers only after a workload of
// its own has finished: creating a project runs `cloop init` (bounded at five
// minutes on the hub), creating a feature checks out a worktree (four), and
// opening a pull request pushes a branch (ten). Each is a little longer than
// the hub's own bound, so the hub's answer — even a refusal — arrives rather
// than this client giving up first.
const longRequestTimeout = 11 * time.Minute

// Client talks to one hub.
type Client struct {
	// Base is the hub's base URL, as NormalizeURL renders it.
	Base string
	// Credential is presented as `Authorization: Bearer …`; empty for the
	// two device endpoints, which are reached before there is one.
	Credential string

	http      *http.Client
	tlsConfig *tls.Config
}

// New builds a client for a hub. caFile, when set, names a PEM bundle trusted
// in addition to the system's roots: a hub with an internal CA.
func New(base, caFile, credential string) (*Client, error) {
	norm, err := NormalizeURL(base)
	if err != nil {
		return nil, err
	}
	tr := http.DefaultTransport.(*http.Transport).Clone()
	var tlsCfg *tls.Config
	if strings.TrimSpace(caFile) != "" {
		pool, err := x509.SystemCertPool()
		if err != nil || pool == nil {
			pool = x509.NewCertPool()
		}
		pem, err := os.ReadFile(caFile)
		if err != nil {
			return nil, fmt.Errorf("hubclient: read --ca-file: %w", err)
		}
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("hubclient: %s holds no PEM certificate", caFile)
		}
		tlsCfg = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
		tr.TLSClientConfig = tlsCfg
	}
	return &Client{
		Base:       norm,
		Credential: credential,
		tlsConfig:  tlsCfg,
		http: &http.Client{
			Transport: tr,
			// A hub that redirects an API call is misconfigured or is not
			// the hub; following it would carry the bearer to wherever the
			// Location points.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}, nil
}

// HTTPClient returns the client's underlying HTTP client, for a WebSocket
// dial that must trust the same CA.
func (c *Client) HTTPClient() *http.Client { return c.http }

// UserAgent is what this build calls itself to a hub, and what the approval
// page shows as the requesting client.
func UserAgent() string {
	return fmt.Sprintf("cloop/%s (%s/%s)", version.Version, runtime.GOOS, runtime.GOARCH)
}

// APIError is a hub's refusal, whichever of its error shapes it came in.
type APIError struct {
	// Status is the HTTP status.
	Status int
	// Code is the machine-readable code when the hub sent one: an OAuth
	// error ("authorization_pending"), an apierror code ("FORBIDDEN"), or
	// the dashboard dialect's own ("executor_audience_denied").
	Code string
	// Message is the hub's prose.
	Message string
	// Remediation is the hub's "what to do about it", when it sent one apart
	// from the message.
	Remediation string
	// Details is the rest of what the hub said about the refusal: apierror's
	// "details" object — required_permission, role and scope for a missing
	// permission — or the dashboard dialect's other fields (executor_id,
	// alternatives, …). Values are as JSON decodes them.
	Details map[string]any
	// IntervalSeconds is the polling interval a device-flow error carried.
	IntervalSeconds int
}

func (e *APIError) Error() string {
	var b strings.Builder
	switch {
	case e.Message != "" && e.Code != "" && !strings.Contains(e.Message, e.Code):
		fmt.Fprintf(&b, "%s (HTTP %d, %s)", e.Message, e.Status, e.Code)
	case e.Message != "":
		fmt.Fprintf(&b, "%s (HTTP %d)", e.Message, e.Status)
	case e.Code != "":
		fmt.Fprintf(&b, "HTTP %d: %s", e.Status, e.Code)
	default:
		fmt.Fprintf(&b, "HTTP %d", e.Status)
	}
	if e.Remediation != "" && !strings.Contains(e.Message, e.Remediation) {
		b.WriteString(" — ")
		b.WriteString(e.Remediation)
	}
	return b.String()
}

// Detail returns one of the refusal's details rendered as text, "" when the
// hub sent none by that name.
func (e *APIError) Detail(key string) string {
	if e == nil || e.Details == nil {
		return ""
	}
	v, ok := e.Details[key]
	if !ok {
		return ""
	}
	return RenderValue(v)
}

// RenderValue renders a decoded JSON value as one line of text: a string as
// itself, a list joined with commas, an object as key=value pairs in key
// order. Never Go's map[…] syntax and never raw JSON, which is what a person
// reading an error in a terminal should not be handed.
func RenderValue(v any) string {
	switch x := v.(type) {
	case nil:
		return ""
	case string:
		return x
	case bool:
		if x {
			return "yes"
		}
		return "no"
	case float64:
		if x == float64(int64(x)) {
			return fmt.Sprintf("%d", int64(x))
		}
		return fmt.Sprintf("%g", x)
	case json.Number:
		return x.String()
	case []any:
		parts := make([]string, 0, len(x))
		for _, item := range x {
			if s := RenderValue(item); s != "" {
				parts = append(parts, s)
			}
		}
		return strings.Join(parts, ", ")
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		parts := make([]string, 0, len(keys))
		for _, k := range keys {
			if s := RenderValue(x[k]); s != "" {
				parts = append(parts, k+"="+s)
			}
		}
		return strings.Join(parts, ", ")
	}
	return fmt.Sprint(v)
}

// IsUnauthorized reports whether err is the hub refusing the credential.
func IsUnauthorized(err error) bool {
	var ae *APIError
	return errors.As(err, &ae) && ae.Status == http.StatusUnauthorized
}

// AsAPIError returns err's *APIError, if it is one.
func AsAPIError(err error) (*APIError, bool) {
	var ae *APIError
	if errors.As(err, &ae) {
		return ae, true
	}
	return nil, false
}

// flatErrorKeys are the dashboard dialect's fields parseError reads into
// APIError's own fields rather than into Details.
var flatErrorKeys = map[string]bool{
	"error": true, "error_description": true, "message": true, "interval": true,
	"code": true, "remediation": true, "ok": true,
}

// parseError reads the hub's error dialects: OAuth's {"error": code,
// "error_description": text}, the dashboard's {"error": text} — which may carry
// "code", "remediation" and fields of its own beside it — and apierror's
// {"error": {"code", "message", "details"}}.
func parseError(status int, body []byte) *APIError {
	e := &APIError{Status: status}
	var fields map[string]json.RawMessage
	if json.Unmarshal(body, &fields) != nil || fields == nil {
		e.Message = strings.TrimSpace(string(body))
		if len(e.Message) > 300 {
			e.Message = e.Message[:300]
		}
		return e
	}
	text := func(key string) string {
		var s string
		if raw, ok := fields[key]; ok {
			_ = json.Unmarshal(raw, &s)
		}
		return strings.TrimSpace(s)
	}
	var interval int
	if raw, ok := fields["interval"]; ok && json.Unmarshal(raw, &interval) == nil && interval > 0 {
		e.IntervalSeconds = interval
	}

	var s string
	if raw, ok := fields["error"]; ok && json.Unmarshal(raw, &s) == nil {
		if desc := text("error_description"); desc != "" {
			// OAuth: the "error" is the code.
			e.Code, e.Message = s, desc
			return e
		}
		e.Message = s
		e.Code = text("code")
		e.Remediation = text("remediation")
		for k, raw := range fields {
			if flatErrorKeys[k] {
				continue
			}
			var v any
			if json.Unmarshal(raw, &v) == nil && v != nil {
				if e.Details == nil {
					e.Details = map[string]any{}
				}
				e.Details[k] = v
			}
		}
		return e
	}
	var nested struct {
		Code        string         `json:"code"`
		Message     string         `json:"message"`
		Remediation string         `json:"remediation"`
		Details     map[string]any `json:"details"`
	}
	if raw, ok := fields["error"]; ok && json.Unmarshal(raw, &nested) == nil {
		e.Code, e.Message, e.Remediation = nested.Code, nested.Message, nested.Remediation
		if len(nested.Details) > 0 {
			e.Details = nested.Details
		}
	}
	if e.Message == "" {
		e.Message = text("message")
	}
	return e
}

// Do performs one JSON call. body, when non-nil, is sent as JSON; out, when
// non-nil, receives the decoded answer. A status of 400 or above is returned
// as an *APIError.
func (c *Client) Do(ctx context.Context, method, path string, query url.Values, body, out any) error {
	return c.do(ctx, requestTimeout, method, path, query, body, out)
}

// doLong is Do for a call the hub answers after a workload of its own.
func (c *Client) doLong(ctx context.Context, method, path string, query url.Values, body, out any) error {
	return c.do(ctx, longRequestTimeout, method, path, query, body, out)
}

func (c *Client) do(ctx context.Context, timeout time.Duration, method, path string, query url.Values, body, out any) error {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	u := c.Base + path
	if len(query) > 0 {
		u += "?" + query.Encode()
	}
	var rdr io.Reader
	if body != nil {
		blob, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("hubclient: encode request: %w", err)
		}
		rdr = bytes.NewReader(blob)
	}
	req, err := http.NewRequestWithContext(ctx, method, u, rdr)
	if err != nil {
		return fmt.Errorf("hubclient: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", UserAgent())
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.Credential != "" {
		req.Header.Set("Authorization", "Bearer "+c.Credential)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("reach %s: %w", c.Base, err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return fmt.Errorf("read the answer from %s: %w", c.Base, err)
	}
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		return &APIError{Status: resp.StatusCode,
			Message: "the hub answered with a redirect to " + resp.Header.Get("Location") +
				" — is this the hub's base URL? (an API call is never followed across a redirect)"}
	}
	if resp.StatusCode >= 400 {
		return parseError(resp.StatusCode, data)
	}
	if out == nil || len(bytes.TrimSpace(data)) == 0 {
		return nil
	}
	if err := json.Unmarshal(data, out); err != nil {
		return fmt.Errorf("decode the answer from %s%s: %w", c.Base, path, err)
	}
	return nil
}
