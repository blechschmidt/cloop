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
	// error ("authorization_pending"), or an apierror code ("FORBIDDEN").
	Code string
	// Message is the hub's prose.
	Message string
	// IntervalSeconds is the polling interval a device-flow error carried.
	IntervalSeconds int
}

func (e *APIError) Error() string {
	switch {
	case e.Message != "" && e.Code != "" && !strings.Contains(e.Message, e.Code):
		return fmt.Sprintf("%s (HTTP %d, %s)", e.Message, e.Status, e.Code)
	case e.Message != "":
		return fmt.Sprintf("%s (HTTP %d)", e.Message, e.Status)
	case e.Code != "":
		return fmt.Sprintf("HTTP %d: %s", e.Status, e.Code)
	}
	return fmt.Sprintf("HTTP %d", e.Status)
}

// IsUnauthorized reports whether err is the hub refusing the credential.
func IsUnauthorized(err error) bool {
	var ae *APIError
	return errors.As(err, &ae) && ae.Status == http.StatusUnauthorized
}

// parseError reads the hub's three error dialects: OAuth's {"error": code,
// "error_description": text}, the dashboard's {"error": text}, and apierror's
// {"error": {"code", "message"}}.
func parseError(status int, body []byte) *APIError {
	e := &APIError{Status: status}
	var flat struct {
		Error       json.RawMessage `json:"error"`
		Description string          `json:"error_description"`
		Message     string          `json:"message"`
		Interval    int             `json:"interval"`
	}
	if json.Unmarshal(body, &flat) != nil {
		e.Message = strings.TrimSpace(string(body))
		if len(e.Message) > 300 {
			e.Message = e.Message[:300]
		}
		return e
	}
	if flat.Interval > 0 {
		e.IntervalSeconds = flat.Interval
	}
	var s string
	if json.Unmarshal(flat.Error, &s) == nil {
		if flat.Description != "" {
			e.Code, e.Message = s, flat.Description
		} else {
			e.Message = s
		}
		return e
	}
	var nested struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	}
	if json.Unmarshal(flat.Error, &nested) == nil {
		e.Code, e.Message = nested.Code, nested.Message
	}
	if e.Message == "" {
		e.Message = flat.Message
	}
	return e
}

// Do performs one JSON call. body, when non-nil, is sent as JSON; out, when
// non-nil, receives the decoded answer. A status of 400 or above is returned
// as an *APIError.
func (c *Client) Do(ctx context.Context, method, path string, query url.Values, body, out any) error {
	ctx, cancel := context.WithTimeout(ctx, requestTimeout)
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
