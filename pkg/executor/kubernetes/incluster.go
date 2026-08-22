package kubernetes

// incluster.go is the credential source for a hub that is itself a Pod.
//
// Everywhere else this driver insists on a brokered kubeconfig, and for good
// reason: a control plane that reaches for ambient cluster credentials is a
// control plane where every tenant shares one authority. In-cluster mode is
// the one case where that reasoning inverts, because the authority is not
// ambient — it is the Pod's own ServiceAccount, and what it may do is written
// down in a Role the operator installed next to the Deployment. The blast
// radius is bounded by RBAC in the cluster rather than by a grant in cloop's
// database, which is a stronger boundary, not a weaker one: it is enforced by
// the API server rather than by us.
//
// So this source exists to let `deploy/helm/cloop-hub` ship without asking an
// operator to mint a kubeconfig, seal it into cloop's secret store and grant
// it back to the executor that is already running inside the cluster the
// kubeconfig would point at. That loop is not more secure, only longer, and a
// long loop is one that gets shortcut with a cluster-admin kubeconfig.
//
// Two properties are worth stating because they are easy to get wrong:
//
//   - The token is re-read on every Acquire and every Renew, never cached.
//     Projected ServiceAccount tokens are bound to the Pod and rotate on a
//     schedule the kubelet chooses (hourly by default). A source that read
//     the file once at startup would work for an hour and then fail every
//     API call, which is exactly the failure mode that is hardest to
//     attribute. Renew() re-reading it is what makes the driver's existing
//     "rotated ServiceAccount token" path in adoptCredentials real.
//
//   - ExpiresAt is the token's own `exp`, decoded but NOT verified. Nothing
//     here trusts the claim: it is used solely to schedule the next re-read,
//     and the API server is the thing that decides whether the token is
//     actually good. A forged `exp` can make cloop re-read a file it already
//     has permission to read, which is not an attack. A missing or unparsable
//     `exp` falls back to a short fixed horizon rather than to "never".

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// DefaultServiceAccountDir is where the kubelet projects a Pod's
// ServiceAccount credentials.
const DefaultServiceAccountDir = "/var/run/secrets/kubernetes.io/serviceaccount"

const (
	saTokenFile     = "token"
	saCAFile        = "ca.crt"
	saNamespaceFile = "namespace"
)

// fallbackTokenTTL is the re-read horizon used when a token carries no usable
// `exp`. Short enough that a rotation is picked up promptly, long enough that
// the renew loop is not spinning on file reads.
const fallbackTokenTTL = 10 * time.Minute

// ErrNotInCluster is returned when in-cluster mode is requested from a
// process that is not running as a Pod. It is deliberately a hard failure:
// the alternative is silently falling back to some other credential, and
// "which identity is this executor actually using" must never be a question
// answered by whatever happened to be available.
var ErrNotInCluster = errors.New(
	"kubernetes: in-cluster mode requires a projected ServiceAccount, but this process is not running in a Pod")

// InClusterSource authenticates as the Pod's own ServiceAccount.
//
// It implements CredentialSource without touching the secret broker, so a hub
// deployed by the Helm chart needs no kubeconfig secret, no grant and no
// CLOOP_SECRET_KEY to run workloads in the cluster it lives in.
type InClusterSource struct {
	// Dir holds the projected ServiceAccount files. Empty means
	// DefaultServiceAccountDir; tests point it at a fixture.
	Dir string
	// Host and Port address the API server. Empty means the
	// KUBERNETES_SERVICE_HOST / KUBERNETES_SERVICE_PORT environment the
	// kubelet injects into every Pod.
	Host string
	Port string
	// Namespace overrides the projected namespace. The executor's configured
	// namespace still wins over both; this is the fallback that makes "run
	// Pods next to the hub" the zero-config behaviour.
	Namespace string

	now func() time.Time
}

// NewInClusterSource validates the ambient environment and returns a source.
//
// It fails rather than deferring, because the useful time to learn that a
// Deployment forgot automountServiceAccountToken is at startup, next to the
// executor registration that mentions it — not twenty minutes later inside a
// task whose output is a 401 from an API server nobody expected to be called.
func NewInClusterSource(namespaceOverride string) (*InClusterSource, error) {
	s := &InClusterSource{
		Dir:       DefaultServiceAccountDir,
		Namespace: strings.TrimSpace(namespaceOverride),
	}
	if err := s.check(); err != nil {
		return nil, err
	}
	return s, nil
}

// check reports whether the ambient environment can produce a credential.
func (s *InClusterSource) check() error {
	host, port := s.endpoint()
	if host == "" || port == "" {
		return fmt.Errorf("%w: KUBERNETES_SERVICE_HOST and KUBERNETES_SERVICE_PORT are not set", ErrNotInCluster)
	}
	tokenPath := s.path(saTokenFile)
	if _, err := os.Stat(tokenPath); err != nil {
		return fmt.Errorf("%w: %s is not readable (%v).\n"+
			"Set automountServiceAccountToken: true on the Pod, or bind a kubeconfig with "+
			"`cloop secret grant` and leave executors.kubernetes.in_cluster false",
			ErrNotInCluster, tokenPath, err)
	}
	return nil
}

// Describe implements CredentialSource.
func (s *InClusterSource) Describe() string {
	host, port := s.endpoint()
	ns := s.Namespace
	if ns == "" {
		ns = s.readNamespace()
	}
	return fmt.Sprintf("in-cluster ServiceAccount: server=https://%s namespace=%s",
		net.JoinHostPort(host, port), orNone(ns))
}

// Acquire implements CredentialSource. projectID is unused: an in-cluster
// identity is a property of the Pod, not of the tenant, and pretending
// otherwise would imply a per-project isolation this mode does not provide.
// Per-project isolation in a cluster comes from binding projects to different
// executors (and therefore different namespaces), not from this file.
func (s *InClusterSource) Acquire(ctx context.Context, projectID string) (*Credentials, error) {
	return s.load()
}

// Renew implements CredentialSource by re-reading the projected token, which
// is what picks up a kubelet rotation.
func (s *InClusterSource) Renew(ctx context.Context, leaseID string) (*Credentials, error) {
	return s.load()
}

// Release implements CredentialSource. There is no lease to give back: the
// credential is a file the kubelet owns, and its lifetime is the Pod's.
func (s *InClusterSource) Release(string) {}

// load reads the current projected credential.
func (s *InClusterSource) load() (*Credentials, error) {
	host, port := s.endpoint()
	if host == "" || port == "" {
		return nil, fmt.Errorf("%w: KUBERNETES_SERVICE_HOST and KUBERNETES_SERVICE_PORT are not set", ErrNotInCluster)
	}

	rawToken, err := os.ReadFile(s.path(saTokenFile))
	if err != nil {
		return nil, fmt.Errorf("kubernetes: read projected ServiceAccount token: %w", err)
	}
	token := strings.TrimSpace(string(rawToken))
	zero(rawToken)
	if token == "" {
		return nil, fmt.Errorf("kubernetes: the projected ServiceAccount token is empty")
	}

	// The cluster CA is projected alongside the token. Its absence is not
	// fatal — a cluster whose API server presents a publicly-trusted
	// certificate legitimately omits it — but it is the normal case, and
	// falling back to the system pool silently would turn a missing file into
	// an unverifiable connection.
	caPath := s.path(saCAFile)
	caData, err := os.ReadFile(caPath)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("kubernetes: read cluster CA %s: %w", caPath, err)
	}

	ns := s.Namespace
	if ns == "" {
		ns = s.readNamespace()
	}

	rest := &RESTConfig{
		Server:      "https://" + net.JoinHostPort(host, port),
		Namespace:   ns,
		Context:     "in-cluster",
		CAData:      caData,
		BearerToken: token,
	}

	return &Credentials{
		Rest:       rest,
		LeaseID:    "", // no broker lease exists to renew or release
		ExpiresAt:  s.tokenExpiry(token),
		SecretName: "serviceaccount",
		Summary:    "projected ServiceAccount token (in-cluster)",
		Namespace:  ns,
	}, nil
}

// tokenExpiry returns when the driver should next re-read the token file.
//
// It prefers the token's own `exp` so a short-lived projected token is
// re-read before it lapses, and falls back to a fixed horizon otherwise. The
// value is only ever used to schedule work; see the file header.
func (s *InClusterSource) tokenExpiry(token string) time.Time {
	now := time.Now
	if s.now != nil {
		now = s.now
	}
	if exp, ok := unverifiedJWTExpiry(token); ok && exp.After(now()) {
		return exp
	}
	return now().Add(fallbackTokenTTL)
}

// readNamespace returns the projected namespace, or "" when it is absent.
func (s *InClusterSource) readNamespace() string {
	b, err := os.ReadFile(s.path(saNamespaceFile))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

func (s *InClusterSource) path(name string) string {
	dir := s.Dir
	if strings.TrimSpace(dir) == "" {
		dir = DefaultServiceAccountDir
	}
	return filepath.Join(dir, name)
}

func (s *InClusterSource) endpoint() (host, port string) {
	host, port = strings.TrimSpace(s.Host), strings.TrimSpace(s.Port)
	if host == "" {
		host = strings.TrimSpace(os.Getenv("KUBERNETES_SERVICE_HOST"))
	}
	if port == "" {
		port = strings.TrimSpace(os.Getenv("KUBERNETES_SERVICE_PORT"))
	}
	return host, port
}

// unverifiedJWTExpiry decodes a JWT's `exp` claim WITHOUT verifying the
// signature. See the file header for why that is safe here and would not be
// anywhere else.
func unverifiedJWTExpiry(token string) (time.Time, bool) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return time.Time{}, false
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return time.Time{}, false
	}
	var claims struct {
		Exp int64 `json:"exp"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil || claims.Exp <= 0 {
		return time.Time{}, false
	}
	return time.Unix(claims.Exp, 0), true
}
