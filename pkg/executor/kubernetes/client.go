package kubernetes

// client.go is a hand-rolled Kubernetes API client covering exactly the eight
// calls this driver makes: create a Pod, get a Pod, watch a Pod, follow its
// logs, delete it, list Pods by label for garbage collection, and create and
// delete the one Secret a workspace fetch's credential travels in.
//
// Not using client-go is a deliberate size decision. client-go plus its
// api/apimachinery dependencies add roughly 40 MB to a binary that operators
// copy onto edge devices, in exchange for typed structs and a discovery
// cache that an eight-call surface does not need. The REST API is stable, is
// versioned (`/api/v1`), and is plain JSON over HTTP; the cost of talking to
// it directly is the handful of structs in pod.go.
//
// The one thing worth being careful about is error reporting. A bare
// "unexpected status 403" sends an operator hunting through the wrong layer,
// so every non-2xx is decoded into the API's own Status object and wrapped
// into an APIError that carries the verb, the path, the reason and the
// server's message — plus, for the authorization failures that dominate a
// first-time setup, the RBAC rule that would fix it.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	// apiPrefix is the core v1 group all Pod operations live under.
	apiPrefix = "/api/v1"

	// maxErrorBodyBytes bounds how much of a failed response we read before
	// giving up on decoding it. An API server behind a misconfigured ingress
	// can return a megabyte of HTML.
	maxErrorBodyBytes = 64 << 10

	// dialTimeout and tlsTimeout bound connection setup so an unreachable
	// API server surfaces promptly instead of hanging a Start.
	dialTimeout = 10 * time.Second
	tlsTimeout  = 10 * time.Second
)

// client is a REST client bound to one RESTConfig.
//
// Two http.Clients are kept because the requirements are opposite: unary
// calls want a total request timeout, and watch/log-follow are long-lived
// streams for which any total timeout is a bug. Sharing one client with
// Timeout unset and relying on ctx alone would work, but it removes the
// backstop that stops a wedged API server from pinning a Start forever.
type client struct {
	rest   *RESTConfig
	unary  *http.Client
	stream *http.Client
	// userAgent identifies this control plane in API server audit logs.
	userAgent string
}

// newClient builds a client for rc. It performs no I/O.
func newClient(rc *RESTConfig, requestTimeout time.Duration) (*client, error) {
	if rc == nil {
		return nil, fmt.Errorf("kubernetes: nil REST config")
	}
	tlsCfg, err := rc.tlsConfig()
	if err != nil {
		return nil, err
	}
	transport := &http.Transport{
		TLSClientConfig:       tlsCfg,
		DialContext:           (&net.Dialer{Timeout: dialTimeout, KeepAlive: 30 * time.Second}).DialContext,
		TLSHandshakeTimeout:   tlsTimeout,
		ResponseHeaderTimeout: requestTimeout,
		MaxIdleConnsPerHost:   4,
		// Streaming endpoints send chunked bodies that must not be buffered.
		DisableCompression: true,
		ForceAttemptHTTP2:  true,
	}
	if rc.ProxyURL != "" {
		pu, perr := url.Parse(rc.ProxyURL)
		if perr != nil {
			return nil, fmt.Errorf("kubernetes: proxy-url %q: %w", rc.ProxyURL, perr)
		}
		transport.Proxy = http.ProxyURL(pu)
	}
	return &client{
		rest:      rc,
		unary:     &http.Client{Transport: transport, Timeout: requestTimeout},
		stream:    &http.Client{Transport: transport},
		userAgent: "cloop-executor/1 (kubernetes)",
	}, nil
}

// close releases pooled connections. Called when a handle is finished so a
// long-lived control plane does not hold a socket per completed run.
func (c *client) close() {
	for _, hc := range []*http.Client{c.unary, c.stream} {
		if tr, ok := hc.Transport.(*http.Transport); ok {
			tr.CloseIdleConnections()
		}
	}
}

// newRequest builds an authenticated request against the API server.
func (c *client) newRequest(ctx context.Context, method, path string, query url.Values, body []byte) (*http.Request, error) {
	full := c.rest.Server + path
	if len(query) > 0 {
		full += "?" + query.Encode()
	}
	var rdr io.Reader
	if body != nil {
		rdr = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, full, rdr)
	if err != nil {
		return nil, fmt.Errorf("kubernetes: build %s %s: %w", method, path, err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", c.userAgent)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.rest.BearerToken != "" {
		req.Header.Set("Authorization", "Bearer "+c.rest.BearerToken)
	}
	return req, nil
}

// doJSON performs a unary request, decoding a 2xx body into out (which may be
// nil) and every other status into an *APIError.
func (c *client) doJSON(ctx context.Context, method, path string, query url.Values, in, out any) error {
	var body []byte
	if in != nil {
		var err error
		if body, err = json.Marshal(in); err != nil {
			return fmt.Errorf("kubernetes: encode %s %s body: %w", method, path, err)
		}
	}
	req, err := c.newRequest(ctx, method, path, query, body)
	if err != nil {
		return err
	}
	resp, err := c.unary.Do(req)
	if err != nil {
		return c.transportError(method, path, err)
	}
	defer drainClose(resp.Body)

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return newAPIError(method, path, resp)
	}
	if out == nil {
		return nil
	}
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		return fmt.Errorf("kubernetes: decode %s %s response: %w", method, path, err)
	}
	return nil
}

// openStream performs a request whose body is consumed incrementally (watch,
// log follow). The caller owns the returned ReadCloser.
func (c *client) openStream(ctx context.Context, path string, query url.Values) (io.ReadCloser, error) {
	req, err := c.newRequest(ctx, http.MethodGet, path, query, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.stream.Do(req)
	if err != nil {
		return nil, c.transportError(http.MethodGet, path, err)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		// newAPIError has already consumed the (bounded) error body, so
		// closing is all that is left.
		apiErr := newAPIError(http.MethodGet, path, resp)
		_ = resp.Body.Close()
		return nil, apiErr
	}
	return resp.Body, nil
}

// transportError explains a failure that never reached the API server.
// ctx errors are returned bare so callers can errors.Is them; everything else
// gets the endpoint attached, because "connection refused" without a host is
// the least useful message in distributed systems.
func (c *client) transportError(method, path string, err error) error {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	// http.Client wraps ctx errors in *url.Error; unwrap before deciding.
	var urlErr *url.Error
	if errors.As(err, &urlErr) {
		if errors.Is(urlErr.Err, context.Canceled) || errors.Is(urlErr.Err, context.DeadlineExceeded) {
			return urlErr.Err
		}
	}
	return fmt.Errorf("kubernetes: %s %s%s: %w", method, c.rest.Server, path, err)
}

// APIError is a non-2xx response from the API server, decoded.
type APIError struct {
	// Code is the HTTP status.
	Code int
	// Reason is the API's machine-readable reason ("NotFound", "Forbidden").
	Reason string
	// Message is the API's human-readable message.
	Message string
	// Verb and Path locate the call that failed.
	Verb string
	Path string
}

func (e *APIError) Error() string {
	msg := e.Message
	if msg == "" {
		msg = http.StatusText(e.Code)
	}
	s := fmt.Sprintf("kubernetes: %s %s failed: %d %s", e.Verb, e.Path, e.Code, msg)
	if hint := e.hint(); hint != "" {
		s += " — " + hint
	}
	return s
}

// hint turns the failures that dominate a first-time setup into the thing to
// do about them. Authorization in particular: a 403 names the ServiceAccount
// and the verb, and what an operator needs is the Role rule, not a reminder
// that RBAC exists.
func (e *APIError) hint() string {
	switch {
	case e.Code == http.StatusUnauthorized:
		return "the brokered kubeconfig's credential was rejected. If it is a ServiceAccount token, " +
			"it may have expired; re-mint it and update the secret with `cloop secret mint --kind kubeconfig`"
	case e.Code == http.StatusForbidden && strings.Contains(e.Path, "/secrets"):
		return "the kubeconfig's identity may not manage Secrets in the target namespace, which a git " +
			"workspace needs: add `- apiGroups: [\"\"] resources: [\"secrets\"] verbs: [\"create\", \"delete\"]` " +
			"to its Role. create and delete only — the driver never reads a Secret back"
	case e.Code == http.StatusForbidden:
		return "the kubeconfig's identity lacks RBAC for this call. It needs a Role in the target " +
			"namespace granting pods: create, get, list, watch, delete; pods/log: get; and " +
			"secrets: create, delete"
	case e.Code == http.StatusNotFound && strings.Contains(e.Path, "/namespaces/"):
		return "check that executors.kubernetes.namespace names an existing namespace"
	case e.Code == http.StatusConflict:
		return "the object already exists; a previous run may not have been garbage-collected"
	case e.Code == http.StatusGone:
		return "the watch's resourceVersion is too old; the driver re-lists and resumes"
	case e.Code >= 500:
		return "the API server reported a server-side failure; this is usually transient"
	}
	return ""
}

// NotFound reports whether the object does not exist. Deleting an
// already-absent Pod is success, not failure, so callers check this.
func (e *APIError) NotFound() bool { return e != nil && e.Code == http.StatusNotFound }

// Expired reports whether a watch was rejected because its resourceVersion
// aged out of the API server's history window.
func (e *APIError) Expired() bool { return e != nil && e.Code == http.StatusGone }

// Retryable reports whether repeating the call could plausibly succeed.
// Authorization and validation failures are excluded: retrying them just
// turns one clear error into a slow one.
func (e *APIError) Retryable() bool {
	if e == nil {
		return false
	}
	return e.Code == http.StatusTooManyRequests || e.Code >= 500
}

// status is the API server's error envelope.
type status struct {
	Kind    string `json:"kind"`
	Status  string `json:"status"`
	Message string `json:"message"`
	Reason  string `json:"reason"`
	Code    int    `json:"code"`
}

// newAPIError decodes a non-2xx response. The body is read here (bounded) so
// callers only have to close it.
func newAPIError(verb, path string, resp *http.Response) *APIError {
	e := &APIError{Code: resp.StatusCode, Verb: verb, Path: path}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxErrorBodyBytes))
	if err != nil || len(raw) == 0 {
		return e
	}
	var st status
	if json.Unmarshal(raw, &st) == nil && st.Message != "" {
		e.Message = st.Message
		e.Reason = st.Reason
		return e
	}
	// Not a Status object — an ingress error page, a proxy, a plain string.
	// Keep the first line so the operator sees what actually answered.
	e.Message = firstLine(string(raw))
	return e
}

// asAPIError extracts an *APIError from a wrapped error chain.
func asAPIError(err error) (*APIError, bool) {
	var ae *APIError
	if errors.As(err, &ae) {
		return ae, true
	}
	return nil, false
}

// drainClose closes a response body after consuming a bounded remainder, so
// the connection can be returned to the pool instead of being torn down.
func drainClose(rc io.ReadCloser) {
	if rc == nil {
		return
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(rc, maxErrorBodyBytes))
	_ = rc.Close()
}

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	if len(s) > 300 {
		s = s[:300] + "…"
	}
	return s
}

// --- typed operations -------------------------------------------------

func podsPath(namespace string) string {
	return apiPrefix + "/namespaces/" + url.PathEscape(namespace) + "/pods"
}

func podPath(namespace, name string) string {
	return podsPath(namespace) + "/" + url.PathEscape(name)
}

// createPod POSTs p and returns the server's view of it, which is where the
// generateName-derived name and the UID come from.
func (c *client) createPod(ctx context.Context, namespace string, p *pod) (*pod, error) {
	var out pod
	if err := c.doJSON(ctx, http.MethodPost, podsPath(namespace), nil, p, &out); err != nil {
		return nil, err
	}
	if out.Metadata.Name == "" {
		return nil, fmt.Errorf("kubernetes: API server accepted the Pod but returned no name")
	}
	return &out, nil
}

// getPod fetches one Pod.
func (c *client) getPod(ctx context.Context, namespace, name string) (*pod, error) {
	var out pod
	if err := c.doJSON(ctx, http.MethodGet, podPath(namespace, name), nil, nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// listPods returns the Pods matching labelSelector, plus the list's
// resourceVersion so a watch can resume from it without a gap.
func (c *client) listPods(ctx context.Context, namespace, labelSelector string) (*podList, error) {
	q := url.Values{}
	if labelSelector != "" {
		q.Set("labelSelector", labelSelector)
	}
	var out podList
	if err := c.doJSON(ctx, http.MethodGet, podsPath(namespace), q, nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// deleteOptions is the body of a DELETE. gracePeriodSeconds is a pointer so
// zero ("kill now") is transmitted rather than omitted.
type deleteOptions struct {
	APIVersion         string `json:"apiVersion"`
	Kind               string `json:"kind"`
	GracePeriodSeconds *int64 `json:"gracePeriodSeconds,omitempty"`
	PropagationPolicy  string `json:"propagationPolicy,omitempty"`
}

// deletePod removes a Pod. An already-absent Pod is success: the caller asked
// for it to be gone and it is gone.
func (c *client) deletePod(ctx context.Context, namespace, name string, gracePeriod time.Duration) error {
	secs := int64(gracePeriod / time.Second)
	if secs < 0 {
		secs = 0
	}
	body := deleteOptions{
		APIVersion:         "v1",
		Kind:               "DeleteOptions",
		GracePeriodSeconds: &secs,
		PropagationPolicy:  "Background",
	}
	err := c.doJSON(ctx, http.MethodDelete, podPath(namespace, name), nil, body, nil)
	if ae, ok := asAPIError(err); ok && ae.NotFound() {
		return nil
	}
	return err
}

// --- secrets ----------------------------------------------------------
//
// The driver creates exactly one kind of Secret — a workspace credential for
// one run — and deletes it as soon as the init container that consumes it has
// finished. There is deliberately no getSecret and no listSecrets, and the
// shipped RBAC grants create and delete only: this driver never reads a Secret
// back, so the ability to do so would be authority nothing here needs.

// secret models the fields this driver sets. StringData rather than Data
// because the API server does the base64 for us, and a driver that encoded it
// itself would be one more place a credential passes through unnecessarily.
type secret struct {
	APIVersion string            `json:"apiVersion,omitempty"`
	Kind       string            `json:"kind,omitempty"`
	Metadata   objectMeta        `json:"metadata"`
	Type       string            `json:"type,omitempty"`
	StringData map[string]string `json:"stringData,omitempty"`
}

func secretsPath(namespace string) string {
	return apiPrefix + "/namespaces/" + url.PathEscape(namespace) + "/secrets"
}

func secretPath(namespace, name string) string {
	return secretsPath(namespace) + "/" + url.PathEscape(name)
}

// createSecret POSTs s and returns the server's view of it.
//
// The response is decoded for its name the way createPod is, and for nothing
// else: a Secret the API server echoes back carries the material in its data
// field, so anything this function did with the response beyond reading
// metadata would be handling a credential it has no reason to handle.
func (c *client) createSecret(ctx context.Context, namespace string, s *secret) (*secret, error) {
	var out secret
	if err := c.doJSON(ctx, http.MethodPost, secretsPath(namespace), nil, s, &out); err != nil {
		return nil, err
	}
	if out.Metadata.Name == "" {
		// A Secret is created with an explicit name, not a generateName, so an
		// empty one back means the response was not the object we asked for —
		// and the caller is about to reference that name from a Pod.
		return nil, fmt.Errorf("kubernetes: API server accepted the Secret but returned no name")
	}
	return &out, nil
}

// deleteSecret removes a Secret. As with deletePod, an already-absent object is
// success: the caller asked for the credential to be gone and it is gone.
func (c *client) deleteSecret(ctx context.Context, namespace, name string) error {
	body := deleteOptions{
		APIVersion: "v1",
		Kind:       "DeleteOptions",
		// No grace period: a Secret has no running process to wind down, and
		// the whole point of the call is that the material stops existing now.
		PropagationPolicy: "Background",
	}
	err := c.doJSON(ctx, http.MethodDelete, secretPath(namespace, name), nil, body, nil)
	if ae, ok := asAPIError(err); ok && ae.NotFound() {
		return nil
	}
	return err
}

// watchEvent is one frame of a watch stream.
type watchEvent struct {
	Type   string          `json:"type"`
	Object json.RawMessage `json:"object"`
}

// watchPod opens a watch scoped to a single Pod by name.
//
// resourceVersion resumes from a known point; passing "" starts from the
// object's current state. allowWatchBookmarks is off because this watch is
// short-lived and single-object, and bookmark frames would only add a case
// the decoder has to skip.
func (c *client) watchPod(ctx context.Context, namespace, name, resourceVersion string) (io.ReadCloser, error) {
	q := url.Values{}
	q.Set("watch", "true")
	q.Set("fieldSelector", "metadata.name="+name)
	if resourceVersion != "" {
		q.Set("resourceVersion", resourceVersion)
	}
	// Bound how long the API server holds the watch open. Without it a
	// silently-dropped connection (a load balancer idle timeout) leaves the
	// driver waiting for events that will never arrive; with it, the stream
	// ends and the caller re-establishes.
	q.Set("timeoutSeconds", "300")
	return c.openStream(ctx, podsPath(namespace), q)
}

// followLogs opens the Pod's log stream.
func (c *client) followLogs(ctx context.Context, namespace, name, container string, follow bool) (io.ReadCloser, error) {
	q := url.Values{}
	if container != "" {
		q.Set("container", container)
	}
	if follow {
		q.Set("follow", "true")
	}
	return c.openStream(ctx, podPath(namespace, name)+"/log", q)
}

// serverVersion hits /version, the cheapest call that proves the endpoint is
// a reachable API server and that TLS agrees. It is the health check because
// it needs no RBAC beyond being authenticated, so a healthy-but-unprivileged
// executor reports its actual problem (a 403 on pod create) rather than
// masking it as "unreachable".
func (c *client) serverVersion(ctx context.Context) (string, error) {
	var out struct {
		GitVersion string `json:"gitVersion"`
		Major      string `json:"major"`
		Minor      string `json:"minor"`
	}
	if err := c.doJSON(ctx, http.MethodGet, "/version", nil, nil, &out); err != nil {
		return "", err
	}
	if out.GitVersion != "" {
		return out.GitVersion, nil
	}
	if out.Major != "" || out.Minor != "" {
		return "v" + out.Major + "." + out.Minor, nil
	}
	return "unknown", nil
}
