package kubernetes

// apiclient.go exports this package's hand-rolled REST client to a second
// caller: the executor controller (pkg/kubecontroller, Task 20483), which runs
// in a cluster and scales an ExecutorPool's runner Pods.
//
// The controller needs verbs this driver never uses — list and watch of a
// custom resource, a status update, a Lease, an Event — and a client that adds
// them one typed method at a time would be a second client grown inside this
// one. So the export is the generic half: a JSON request against a path, a
// merge patch, and a stream. The controller owns its paths and its types; this
// file owns everything that is easy to get wrong and already right here — the
// TLS construction from a RESTConfig (shared with kubeguard through
// RESTConfig.Transport), the two http.Clients with opposite timeout needs, the
// bounded error-body decoding into *APIError, and ctx errors returned bare.
//
// Two differences from the driver's own client:
//
//   - Errors carry no driver hint. APIError.hint() speaks about a brokered
//     kubeconfig and executors.kubernetes.namespace, which would send the
//     controller's operator to the wrong file; the controller adds its own
//     remediation where it has one.
//   - The bearer token may come from a function rather than the RESTConfig, so
//     a controller that runs for months re-reads its projected ServiceAccount
//     token as the kubelet rotates it (see InClusterSource for why the file,
//     never a copy, is the truth).

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// APIClient is a generic JSON client for one Kubernetes API server.
type APIClient struct {
	c *client
}

// APIClientOptions configure NewAPIClient.
type APIClientOptions struct {
	// RequestTimeout bounds every unary call; zero means 30 seconds. Streams
	// are bounded by their context only.
	RequestTimeout time.Duration
	// UserAgent identifies the caller in the API server's audit log.
	UserAgent string
	// Token, when set, supplies the bearer token for each request instead of
	// the RESTConfig's BearerToken, so a rotated token is used as soon as the
	// function returns it. An error fails the request without sending it.
	Token func() (string, error)
}

// NewAPIClient builds a client for rc. It performs no I/O.
func NewAPIClient(rc *RESTConfig, opts APIClientOptions) (*APIClient, error) {
	timeout := opts.RequestTimeout
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	c, err := newClient(rc, timeout)
	if err != nil {
		return nil, err
	}
	if ua := strings.TrimSpace(opts.UserAgent); ua != "" {
		c.userAgent = ua
	}
	c.tokenFn = opts.Token
	return &APIClient{c: c}, nil
}

// Server is the API server's base URL.
func (a *APIClient) Server() string { return a.c.rest.Server }

// Close releases pooled connections.
func (a *APIClient) Close() { a.c.close() }

// Do sends a JSON request: in (nil for none) as the body, a 2xx response
// decoded into out (nil to discard it). A non-2xx answer is an *APIError.
func (a *APIClient) Do(ctx context.Context, method, path string, query url.Values, in, out any) error {
	return plainError(a.c.doJSON(ctx, method, path, query, in, out))
}

// Patch sends body as a patch of patchType ("application/merge-patch+json",
// say), decoding a 2xx response into out when out is not nil.
func (a *APIClient) Patch(ctx context.Context, path, patchType string, body []byte, out any) error {
	req, err := a.c.newRequest(ctx, http.MethodPatch, path, nil, body)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", patchType)
	resp, err := a.c.unary.Do(req)
	if err != nil {
		return a.c.transportError(http.MethodPatch, path, err)
	}
	defer drainClose(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return plainError(newAPIError(http.MethodPatch, path, resp))
	}
	if out == nil {
		return nil
	}
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		return fmt.Errorf("kubernetes: decode PATCH %s response: %w", path, err)
	}
	return nil
}

// Stream opens a GET whose body is read incrementally — a watch. The caller
// closes it.
func (a *APIClient) Stream(ctx context.Context, path string, query url.Values) (io.ReadCloser, error) {
	rc, err := a.c.openStream(ctx, path, query)
	return rc, plainError(err)
}

// plainError strips the driver's hints from an *APIError in err's chain.
func plainError(err error) error {
	if ae, ok := asAPIError(err); ok {
		ae.plain = true
	}
	return err
}

// IsNotFound reports whether err is the API server's 404.
func IsNotFound(err error) bool {
	ae, ok := asAPIError(err)
	return ok && ae.NotFound()
}

// IsConflict reports whether err is the API server's 409: an object that
// already exists, or an update against a stale resourceVersion.
func IsConflict(err error) bool {
	ae, ok := asAPIError(err)
	return ok && ae.Code == http.StatusConflict
}

// IsGone reports whether err is the API server's 410: a watch or list whose
// resourceVersion fell out of the server's history.
func IsGone(err error) bool {
	ae, ok := asAPIError(err)
	return ok && ae.Expired()
}

// IsForbidden reports whether err is the API server's 403.
func IsForbidden(err error) bool {
	ae, ok := asAPIError(err)
	return ok && ae.Code == http.StatusForbidden
}

// IsInvalid reports whether err is the API server's 422: an object its
// validation — or an admission webhook — refused.
func IsInvalid(err error) bool {
	ae, ok := asAPIError(err)
	return ok && ae.Code == http.StatusUnprocessableEntity
}
