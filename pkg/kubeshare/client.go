package kubeshare

// client.go is the handful of Kubernetes API calls a share makes, over the
// same RESTConfig and transport the executor's driver uses
// (pkg/executor/kubernetes), so "is this kubeconfig insecure" and "which CA
// does it trust" have one answer in the whole binary.
//
// It does not use client-go for the reason the driver gives: six calls do not
// justify forty megabytes on a binary operators copy onto edge devices.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor/kubernetes"
)

const (
	// requestTimeout bounds one API call.
	requestTimeout = 30 * time.Second
	// maxResponseBytes bounds what is read of an answer. The largest a share
	// reads is a list of its own RoleBindings.
	maxResponseBytes = 4 << 20
	userAgent        = "cloop-kubeshare/1"
)

// Client talks to one API server as one credential.
type Client struct {
	rc *kubernetes.RESTConfig
	hc *http.Client
}

// NewClient builds a client for rc. It performs no I/O.
func NewClient(rc *kubernetes.RESTConfig) (*Client, error) {
	if rc == nil {
		return nil, errors.New("kubeshare: no cluster to talk to")
	}
	tr, err := rc.Transport(requestTimeout)
	if err != nil {
		return nil, err
	}
	return &Client{rc: rc, hc: &http.Client{
		Transport: tr,
		Timeout:   requestTimeout,
		// An API server does not redirect an API call; following one would
		// carry the bearer token to wherever Location points.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}}, nil
}

// Close releases pooled connections.
func (c *Client) Close() {
	if c == nil || c.hc == nil {
		return
	}
	if tr, ok := c.hc.Transport.(*http.Transport); ok {
		tr.CloseIdleConnections()
	}
}

// Server is the API server the client talks to.
func (c *Client) Server() string { return c.rc.Server }

// APIError is a refusal from the API server, decoded from its Status object.
type APIError struct {
	Method  string
	Path    string
	Status  int
	Reason  string
	Message string
}

func (e *APIError) Error() string {
	msg := strings.TrimSpace(e.Message)
	if msg == "" {
		msg = http.StatusText(e.Status)
	}
	return fmt.Sprintf("%s %s: %s (HTTP %d)", e.Method, e.Path, msg, e.Status)
}

// statusOf returns err's HTTP status when it is an APIError.
func statusOf(err error) int {
	var ae *APIError
	if errors.As(err, &ae) {
		return ae.Status
	}
	return 0
}

// IsNotFound, IsConflict, IsForbidden and IsUnauthorized classify an APIError.
func IsNotFound(err error) bool     { return statusOf(err) == http.StatusNotFound }
func IsConflict(err error) bool     { return statusOf(err) == http.StatusConflict }
func IsForbidden(err error) bool    { return statusOf(err) == http.StatusForbidden }
func IsUnauthorized(err error) bool { return statusOf(err) == http.StatusUnauthorized }

// do performs one JSON call.
func (c *Client) do(ctx context.Context, method, path string, query url.Values, body, out any) error {
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("encode %s %s: %w", method, path, err)
		}
		rdr = bytes.NewReader(b)
	}
	target := strings.TrimRight(c.rc.Server, "/") + path
	if len(query) > 0 {
		target += "?" + query.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, method, target, rdr)
	if err != nil {
		return fmt.Errorf("%s %s: %w", method, path, err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", userAgent)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.rc.BearerToken != "" {
		req.Header.Set("Authorization", "Bearer "+c.rc.BearerToken)
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return fmt.Errorf("reach the API server at %s: %w", c.rc.Server, err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return fmt.Errorf("%s %s: read the answer: %w", method, path, err)
	}
	if resp.StatusCode >= 300 {
		ae := &APIError{Method: method, Path: path, Status: resp.StatusCode}
		var st struct {
			Reason  string `json:"reason"`
			Message string `json:"message"`
		}
		if json.Unmarshal(data, &st) == nil {
			ae.Reason, ae.Message = st.Reason, st.Message
		}
		return ae
	}
	if out == nil || len(bytes.TrimSpace(data)) == 0 {
		return nil
	}
	if err := json.Unmarshal(data, out); err != nil {
		return fmt.Errorf("%s %s: decode the answer: %w", method, path, err)
	}
	return nil
}

// Create creates one object.
func (c *Client) Create(ctx context.Context, m Manifest) error {
	return c.do(ctx, http.MethodPost, m.Collection, nil, m.Body, nil)
}

// ObjectMeta is the part of an object a share reads back.
type ObjectMeta struct {
	Name            string            `json:"name"`
	Namespace       string            `json:"namespace"`
	UID             string            `json:"uid"`
	ResourceVersion string            `json:"resourceVersion"`
	Labels          map[string]string `json:"labels"`
	Annotations     map[string]string `json:"annotations"`
}

// Get reads an object's metadata. An object that is not one a share could
// have created is refused before any request is built from its name.
func (c *Client) Get(ctx context.Context, o Object) (ObjectMeta, error) {
	if !o.Valid() {
		return ObjectMeta{}, fmt.Errorf("%s is not an object a share creates", o)
	}
	var out struct {
		Metadata ObjectMeta `json:"metadata"`
	}
	err := c.do(ctx, http.MethodGet, ObjectPath(o), nil, nil, &out)
	return out.Metadata, err
}

// Delete deletes one object. Gone already is success: revoke is idempotent.
//
// It deletes whatever the name holds. Only a share's own rollback, deleting
// what it created a moment ago, may use it; revoke deletes through
// DeleteExact, which names the object it read.
func (c *Client) Delete(ctx context.Context, o Object) error {
	if !o.Valid() {
		return fmt.Errorf("%s is not an object a share creates", o)
	}
	err := c.do(ctx, http.MethodDelete, ObjectPath(o), nil,
		map[string]any{"apiVersion": "v1", "kind": "DeleteOptions", "propagationPolicy": "Background"}, nil)
	if IsNotFound(err) {
		return nil
	}
	return err
}

// DeleteExact deletes o only if it is still the object read as meta: the API
// server checks the uid and resourceVersion preconditions and refuses (409) if
// either changed — so an object swapped, relabelled or re-annotated after it
// was checked is not the one deleted. Gone already is success.
func (c *Client) DeleteExact(ctx context.Context, o Object, meta ObjectMeta) error {
	if !o.Valid() {
		return fmt.Errorf("%s is not an object a share creates", o)
	}
	if meta.UID == "" || meta.ResourceVersion == "" {
		return fmt.Errorf("%s: the cluster reported no uid or resourceVersion to delete it by", o)
	}
	err := c.do(ctx, http.MethodDelete, ObjectPath(o), nil, map[string]any{
		"apiVersion": "v1", "kind": "DeleteOptions", "propagationPolicy": "Background",
		"preconditions": map[string]any{"uid": meta.UID, "resourceVersion": meta.ResourceVersion},
	}, nil)
	if IsNotFound(err) {
		return nil
	}
	return err
}

// Labelled is an object a labelled listing found, with its metadata as listed.
type Labelled struct {
	Object
	Meta ObjectMeta
}

// ListLabelled lists the objects of a kind in namespace (or cluster-wide for a
// ClusterRoleBinding) that carry the share's label, with their metadata.
func (c *Client) ListLabelled(ctx context.Context, kind, namespace, shareID string) ([]Labelled, error) {
	probe := Object{Kind: kind, Namespace: namespace}
	if (kind == "ClusterRoleBinding") != (namespace == "") || (namespace != "" && !ValidNamespace(namespace)) {
		return nil, fmt.Errorf("cannot list %s in namespace %q", kind, namespace)
	}
	if !shareIDPattern.MatchString(shareID) {
		return nil, fmt.Errorf("%q is not a share id", shareID)
	}
	var out struct {
		Items []struct {
			Metadata ObjectMeta `json:"metadata"`
		} `json:"items"`
	}
	q := url.Values{"labelSelector": {LabelShare + "=" + shareID}}
	if err := c.do(ctx, http.MethodGet, CollectionPath(probe), q, nil, &out); err != nil {
		return nil, err
	}
	objs := make([]Labelled, 0, len(out.Items))
	for _, it := range out.Items {
		ns := it.Metadata.Namespace
		if ns == "" {
			ns = namespace
		}
		objs = append(objs, Labelled{Object: Object{Kind: kind, Namespace: ns, Name: it.Metadata.Name}, Meta: it.Metadata})
	}
	return objs, nil
}

// Token is a minted ServiceAccount token.
type Token struct {
	Value     string
	ExpiresAt time.Time
}

// String redacts the token.
func (t Token) String() string {
	return fmt.Sprintf("ServiceAccount token [redacted], expires %s", t.ExpiresAt.UTC().Format(time.RFC3339))
}

// GoString mirrors String.
func (t Token) GoString() string { return t.String() }

// RequestToken mints a token for namespace/serviceAccount through the
// TokenRequest API, valid for ttl or whatever shorter time the cluster caps it
// at — managed API servers do cap it, which is the reason renewal exists.
func (c *Client) RequestToken(ctx context.Context, namespace, serviceAccount string, ttl time.Duration) (Token, error) {
	secs := int64(ttl / time.Second)
	if secs < int64(MinTTL/time.Second) {
		secs = int64(MinTTL / time.Second)
	}
	body := map[string]any{
		"apiVersion": "authentication.k8s.io/v1",
		"kind":       "TokenRequest",
		"spec":       map[string]any{"expirationSeconds": secs},
	}
	var out struct {
		Status struct {
			Token               string    `json:"token"`
			ExpirationTimestamp time.Time `json:"expirationTimestamp"`
		} `json:"status"`
	}
	path := "/api/v1/namespaces/" + namespace + "/serviceaccounts/" + serviceAccount + "/token"
	if err := c.do(ctx, http.MethodPost, path, nil, body, &out); err != nil {
		return Token{}, err
	}
	if strings.TrimSpace(out.Status.Token) == "" {
		return Token{}, fmt.Errorf("the API server answered the TokenRequest for %s/%s without a token",
			namespace, serviceAccount)
	}
	return Token{Value: strings.TrimSpace(out.Status.Token), ExpiresAt: out.Status.ExpirationTimestamp.UTC()}, nil
}

// WhoAmI asks the API server who this client's credential is
// (SelfSubjectReview). ok is false on a cluster too old to answer (before
// 1.27 without the beta enabled), which callers treat as "cannot tell", never
// as "nobody".
func (c *Client) WhoAmI(ctx context.Context) (username string, ok bool, err error) {
	for _, version := range []string{"v1", "v1beta1"} {
		var out struct {
			Status struct {
				UserInfo struct {
					Username string `json:"username"`
				} `json:"userInfo"`
			} `json:"status"`
		}
		path := "/apis/authentication.k8s.io/" + version + "/selfsubjectreviews"
		err := c.do(ctx, http.MethodPost, path, nil, map[string]any{
			"apiVersion": "authentication.k8s.io/" + version, "kind": "SelfSubjectReview",
		}, &out)
		switch {
		case err == nil:
			return out.Status.UserInfo.Username, true, nil
		case IsNotFound(err):
			continue
		default:
			return "", false, err
		}
	}
	return "", false, nil
}
