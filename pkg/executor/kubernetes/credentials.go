package kubernetes

// credentials.go binds this driver to pkg/secretbroker.
//
// The rule the whole file exists to enforce: the kubeconfig this executor
// authenticates with never becomes a file on the control-plane host. Every
// other consumer of a brokered secret calls Lease.Materialize, which writes
// the credential into a tmpfs directory for a child process to read. A
// Kubernetes executor has no child process on this host — it makes HTTPS
// calls from inside the control plane — so materialising would create a file
// for no reason, and a file that exists can be read, backed up, snapshotted
// and inherited by the next process to run as the same user.
//
// So the lease is consumed in memory: Material.Files[i].Content is parsed
// straight into a RESTConfig and the buffer is wiped. Nothing touches a
// filesystem, and the plaintext's lifetime is the handle's.
//
// The lease is also *held* for the handle's lifetime rather than dropped
// after Start, because the driver keeps needing the credential: to watch the
// Pod, to follow its logs, and — the one that matters — to delete it. A
// driver that released its lease at Start would be unable to clean up the
// workload it created.
//
// Renewal closes the loop the broker promises: Broker.Renew re-evaluates
// every grant from the store, so a kubeconfig grant revoked while a run is in
// flight stops renewing, and the driver kills the Pod rather than continuing
// on authority that was withdrawn.

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/secretbroker"
)

// ErrNoKubeconfigGrant is returned when the broker issued a lease that
// carries no kubeconfig this executor may use. It is a denial, not a
// misconfiguration to work around: without a kubeconfig there is no cluster
// to run in, and falling back to anything else would be host execution.
var ErrNoKubeconfigGrant = errors.New("kubernetes: no kubeconfig grant is available for this executor")

// Credentials is one acquired kubeconfig lease, already parsed.
type Credentials struct {
	// Rest is the parsed connection config. Holds the credential in memory.
	Rest *RESTConfig
	// LeaseID identifies the broker lease to renew and release.
	LeaseID string
	// ExpiresAt is when the lease stops being valid.
	ExpiresAt time.Time
	// SecretName and Summary are audit-safe descriptions of what was
	// delivered — never the credential itself.
	SecretName string
	Summary    string
	// Namespace is the namespace the grant pinned, when it pinned one. The
	// executor's configured namespace still wins; this is the fallback.
	Namespace string
}

// CredentialSource supplies kubeconfig leases.
//
// It is an interface so the driver can be tested against a fake API server
// without standing up a broker, an encrypted secret store and a grant — but
// the only production implementation is BrokerSource, and Options.Credentials
// has no default. An executor with no source configured refuses to start
// anything rather than reaching for a kubeconfig on disk.
type CredentialSource interface {
	// Acquire leases a kubeconfig for projectID.
	Acquire(ctx context.Context, projectID string) (*Credentials, error)
	// Renew re-evaluates the grants behind an existing lease. Returning an
	// error means the authority was withdrawn, and the caller terminates the
	// workload.
	Renew(ctx context.Context, leaseID string) (*Credentials, error)
	// Release drops a lease. Must be safe to call with an unknown ID.
	Release(leaseID string)
	// Describe is an audit-safe one-liner for diagnostics.
	Describe() string
}

// BrokerSource leases kubeconfigs from a secretbroker.Broker.
type BrokerSource struct {
	// Broker is the control plane's broker. Required.
	Broker *secretbroker.Broker
	// ExecutorID is the subject grants are matched against.
	ExecutorID string
	// SecretRef optionally pins which kubeconfig secret to use, by name or
	// ID. Empty accepts the first kubeconfig grant in the lease, which is the
	// common case (a project has one cluster).
	SecretRef string
	// Context selects a kubeconfig context. Empty uses current-context.
	Context string
	// Actor is recorded in the broker's audit trail.
	Actor string
}

// NewBrokerSource validates and returns a broker-backed source.
func NewBrokerSource(b *secretbroker.Broker, executorID, secretRef, kubeContext string) (*BrokerSource, error) {
	if b == nil {
		return nil, fmt.Errorf("kubernetes: nil secret broker")
	}
	if strings.TrimSpace(executorID) == "" {
		return nil, fmt.Errorf("kubernetes: broker source needs an executor ID to match grants against")
	}
	return &BrokerSource{
		Broker:     b,
		ExecutorID: executorID,
		SecretRef:  strings.TrimSpace(secretRef),
		Context:    strings.TrimSpace(kubeContext),
		Actor:      "executor:" + executorID,
	}, nil
}

// Describe implements CredentialSource.
func (s *BrokerSource) Describe() string {
	ref := s.SecretRef
	if ref == "" {
		ref = "(first kubeconfig grant)"
	}
	return fmt.Sprintf("secret broker: executor=%s secret=%s", s.ExecutorID, ref)
}

// Acquire implements CredentialSource.
func (s *BrokerSource) Acquire(ctx context.Context, projectID string) (*Credentials, error) {
	lease, err := s.Broker.LeaseFor(ctx, secretbroker.Requester{
		ExecutorID: s.ExecutorID,
		ProjectID:  projectID,
	}, s.Actor)
	if err != nil {
		return nil, fmt.Errorf("kubernetes: lease kubeconfig: %w", err)
	}
	creds, err := s.fromLease(lease)
	if err != nil {
		// A lease we cannot use is a lease we must not hold.
		s.Broker.Release(lease.ID)
		return nil, err
	}
	return creds, nil
}

// Renew implements CredentialSource.
func (s *BrokerSource) Renew(ctx context.Context, leaseID string) (*Credentials, error) {
	lease, err := s.Broker.Renew(ctx, leaseID)
	if err != nil {
		return nil, fmt.Errorf("kubernetes: renew kubeconfig lease: %w", err)
	}
	creds, err := s.fromLease(lease)
	if err != nil {
		s.Broker.Release(lease.ID)
		return nil, err
	}
	return creds, nil
}

// Release implements CredentialSource.
func (s *BrokerSource) Release(leaseID string) {
	if leaseID == "" {
		return
	}
	s.Broker.Release(leaseID)
}

// fromLease picks the kubeconfig material out of a lease and parses it.
func (s *BrokerSource) fromLease(lease *secretbroker.Lease) (*Credentials, error) {
	if lease == nil {
		return nil, ErrNoKubeconfigGrant
	}
	for _, mat := range lease.Materials {
		if mat.Kind != secretbroker.KindKubeconfig {
			continue
		}
		if s.SecretRef != "" && mat.SecretName != s.SecretRef && mat.SecretID != s.SecretRef {
			continue
		}
		raw := kubeconfigBytes(mat)
		if len(raw) == 0 {
			continue
		}
		rest, err := ParseKubeconfig(raw, s.Context)
		// The minimized kubeconfig is the plaintext credential. Wipe the
		// buffer now that a RESTConfig has been built from it, so the only
		// remaining copy is the one the driver actively needs.
		zero(raw)
		if err != nil {
			return nil, fmt.Errorf("kubernetes: kubeconfig from secret %q is unusable: %w", mat.SecretName, err)
		}
		return &Credentials{
			Rest:       rest,
			LeaseID:    lease.ID,
			ExpiresAt:  lease.ExpiresAt,
			SecretName: mat.SecretName,
			Summary:    mat.Summary,
			Namespace:  namespaceHint(mat, rest),
		}, nil
	}
	if s.SecretRef != "" {
		return nil, fmt.Errorf("%w: no grant delivers a kubeconfig named %q to executor %q — "+
			"check `cloop secret grants --subject executor:%s`",
			ErrNoKubeconfigGrant, s.SecretRef, s.ExecutorID, s.ExecutorID)
	}
	return nil, fmt.Errorf("%w: grant one with "+
		"`cloop secret grant <kubeconfig-secret> --to executor:%s --namespaces <ns>`",
		ErrNoKubeconfigGrant, s.ExecutorID)
}

// kubeconfigBytes finds the kubeconfig document inside a material. The broker
// names the file "kubeconfig" and points KUBECONFIG at it; both are accepted
// so a future change to either does not silently yield an empty credential.
func kubeconfigBytes(mat secretbroker.Material) []byte {
	for _, f := range mat.Files {
		if f.Name == "kubeconfig" || f.EnvVar == "KUBECONFIG" {
			return append([]byte(nil), f.Content...)
		}
	}
	return nil
}

// namespaceHint prefers the namespace the grant pinned over the one the
// kubeconfig context names, because the grant is the narrower authority.
func namespaceHint(mat secretbroker.Material, rest *RESTConfig) string {
	if ns := strings.TrimSpace(mat.Env["CLOOP_K8S_NAMESPACE"]); ns != "" {
		return ns
	}
	if rest != nil {
		return rest.Namespace
	}
	return ""
}

// zero overwrites a buffer holding plaintext.
func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
