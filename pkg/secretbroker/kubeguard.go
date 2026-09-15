package secretbroker

// kubeguard.go defines the seam an out-of-sandbox Kubernetes monitor plugs
// into (Task 20277). It is the kubeconfig counterpart of gitguard.go, and it
// exists for the same reason.
//
// # What this package can and cannot enforce on its own
//
// MinimizeKubeconfig is subtractive and therefore real: a context outside the
// grant's allowlist is gone from the delivered document, and the cluster and
// user it referenced go with it. A sandbox cannot reach a cluster whose
// credential it was never handed.
//
// Two of the three things a kubeconfig grant claims cannot be enforced that
// way at all:
//
//   - The namespace written into a delivered context is a *client-side
//     default*. `kubectl -n kube-system get secrets` ignores it. So the
//     namespace allowlist, unaided, describes an intent rather than a bound.
//   - Read-only has no representation in a kubeconfig. The document carries a
//     credential; the credential's authority is the cluster's RBAC, which
//     this hub does not administer. On a personal kubeconfig that authority
//     is frequently cluster-admin.
//
// A KubeGuard closes both by moving the decision out of the document and into
// a process the sandbox does not control: the hub keeps the credential, the
// sandbox gets a token that only works against the monitor, and every request
// is parsed and matched against the grant before it reaches the API server.
//
// # Why an interface rather than a direct dependency
//
// The same reason gitguard.go is one. pkg/kubeguard parses a kubeconfig with
// pkg/executor/kubernetes, which imports this package, so this package cannot
// import it back. The interface also keeps "which grant authorises this
// cluster" here and "and how does the sandbox reach it" in the hub, where an
// operator turns it on and off.

import (
	"context"
	"errors"
	"strings"
	"time"
)

// KubeGuardSessionEnvKey carries the monitor session's id into the delivered
// environment, so a lease's sessions can be found again at release time
// without this package having to learn what a monitor session is.
//
// The id is not a credential — the bearer token is inside the kubeconfig
// file, at 0600 — so carrying it in the environment costs nothing and buys
// revocation that lands before the TTL.
const KubeGuardSessionEnvKey = "CLOOP_KUBEGUARD_SESSION"

// KubeGuard interposes an out-of-sandbox monitor between a workload and a
// Kubernetes cluster.
type KubeGuard interface {
	// GuardKubeconfig takes custody of a kubeconfig and the constraints it
	// was granted under, and returns the document to deliver instead.
	//
	// Returning a zero result with a nil error means "declined": there is no
	// monitor on this hub, and the caller should deliver the minimised
	// kubeconfig as before. Returning an error means a monitor was required
	// and could not be provided, which must fail the lease rather than fall
	// back — a hub whose config promises enforcement and silently delivers
	// the raw credential is worse than one that never promised.
	GuardKubeconfig(ctx context.Context, req KubeGuardRequest) (KubeGuardResult, error)
}

// KubeGuardRequest is what the broker hands the monitor.
type KubeGuardRequest struct {
	// Kubeconfig is the minimised document, already reduced to the contexts
	// the grant allows. The monitor takes custody of it; it must not be
	// copied into the result, into a log, or into anything the sandbox reads.
	//
	// Minimised rather than raw on purpose: the two narrowings compose, so a
	// monitor that was somehow pointed at the wrong context still cannot
	// reach a cluster the grant excluded.
	Kubeconfig []byte
	// Verbs is the grant's effective verb allowlist, already resolved from
	// Constraints.KubeVerbs — so the monitor never has to re-derive that an
	// empty list means read-only.
	Verbs []string
	// Namespaces is the grant's namespace allowlist. The monitor enforces it
	// on every request, which is the thing the delivered document could not.
	Namespaces []string

	// Labels. None is secret; all are audit bookkeeping.
	SecretName string
	SecretID   string
	GrantID    string
	LeaseID    string
	ProjectID  string
	ExecutorID string
	Actor      string
	// Owner is the identity a personal kubeconfig belongs to, or "" for a
	// shared one. It rides along so the monitor's audit rows name the person
	// whose cluster credential is being spent.
	Owner string
}

// KubeGuardResult is the monitor's answer.
type KubeGuardResult struct {
	// Kubeconfig is the document to deliver into the sandbox. It points at
	// the monitor and carries a session token, and it contains no cluster
	// credential — that is the whole point, and kubeconfig_test.go in
	// pkg/kubeguard asserts it against a known plaintext.
	Kubeconfig []byte
	// SessionID identifies the monitor session, for audit joins and
	// revocation.
	SessionID string
	// ExpiresAt is when the monitor stops honouring the session.
	ExpiresAt time.Time
	// ReadOnly records whether the resulting session can only read. Surfaced
	// so the lease summary can say so without re-deriving the rule.
	ReadOnly bool
	// Summary is an audit-safe description of what the monitor will enforce
	// ("read-only, ns app|app-staging"). It carries no credential.
	Summary string
}

// Guarded reports whether the monitor actually took custody. A zero result is
// a decline.
func (r KubeGuardResult) Guarded() bool { return len(r.Kubeconfig) > 0 }

// UnavailableKubeGuard refuses every request, for a hub whose configuration
// asked for a monitor and has not got one.
//
// It refuses rather than being left nil because the two are read differently:
// nil means "this deployment does not intercept Kubernetes traffic", which is
// a valid configuration, while this means "it was supposed to and is not".
type UnavailableKubeGuard struct {
	// Reason is shown to the operator. It should name the configuration that
	// is not in effect, not merely say that something is missing.
	Reason string
}

// GuardKubeconfig implements KubeGuard by always failing.
func (g UnavailableKubeGuard) GuardKubeconfig(context.Context, KubeGuardRequest) (KubeGuardResult, error) {
	reason := strings.TrimSpace(g.Reason)
	if reason == "" {
		reason = "the Kubernetes access monitor is not running"
	}
	return KubeGuardResult{}, errors.New(reason)
}

// Interface check.
var _ KubeGuard = UnavailableKubeGuard{}
