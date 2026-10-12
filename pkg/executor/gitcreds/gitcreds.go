// Package gitcreds leases the credential a git workspace fetch needs.
//
// It sits between pkg/secretbroker, which knows about grants and constraints,
// and the executor drivers, which know about Pods and edge devices and must not
// know about either. The drivers see executor.WorkspaceCredentialSource — an
// interface with no broker types in it — so a driver can be tested with a fake
// source, and so pkg/executor stays a leaf package that a remote agent can
// depend on without pulling in the hub's secret store.
//
// # Why the lease is taken by the driver and not by the caller
//
// The obvious alternative is for the Web UI to lease the token and put it in
// the Spec. It cannot: a Spec is persisted by pkg/executorstore, marshalled
// across the remote-executor boundary, and echoed into audit rows. A credential
// placed there would be durable in three places by the time anything used it.
//
// So the Spec carries only the *name* of a grant, and the driver dispatching
// the workload leases the material at the last possible moment, holds it for
// the length of one fetch, and releases it. The credential's lifetime is a
// property of the code path rather than of anyone remembering to wipe it.
package gitcreds

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/forgehost"
	"github.com/blechschmidt/cloop/pkg/secretbroker"
)

// BrokerSource leases workspace credentials from a secret broker.
type BrokerSource struct {
	// Broker is the control plane's secret broker.
	Broker *secretbroker.Broker
	// ExecutorID is the subject grants are matched against.
	ExecutorID string
	// Actor is the audit-trail identity for the lease.
	Actor string
}

// New returns a source, or an error when it would be unusable.
func New(broker *secretbroker.Broker, executorID, actor string) (*BrokerSource, error) {
	if broker == nil {
		return nil, errors.New("gitcreds: nil broker")
	}
	if strings.TrimSpace(executorID) == "" {
		return nil, errors.New("gitcreds: executor id is empty")
	}
	if strings.TrimSpace(actor) == "" {
		actor = "system"
	}
	return &BrokerSource{Broker: broker, ExecutorID: executorID, Actor: actor}, nil
}

// ForWorkspace implements executor.WorkspaceCredentialSource.
//
// The returned release function is always non-nil, including on the error
// paths, so a caller can defer it unconditionally.
//
// Selection is by *authority*, not by name alone. A grant satisfies the
// workspace when it is a GitHub credential whose repository allowlist admits
// this repository on the forge host its credential is good against — and,
// when the spec named a grant, when it is that one. A grant that names the
// right secret but excludes the repository is reported as a distinct Reason,
// because "create a grant" and "widen the grant you have" are different fixes
// and an operator who is told the wrong one will go looking in the wrong
// place.
//
// A repository is (host, path) here (Task 20423). An allowlist names
// owner/name, so a grant for acme/* used to match
// https://attacker.example/acme/tool exactly as it matched github.com, and the
// token was handed to whatever host the project's origin named. Now a grant
// whose allowlist admits the path on another host is a refusal naming both
// hosts — never a credential, and never a silent pass.
func (s *BrokerSource) ForWorkspace(ctx context.Context, projectID string, w executor.Workspace) (executor.WorkspaceAccess, func(), error) {
	return s.forWorkspace(ctx, projectID, w, false)
}

// ForProxiedWorkspace is ForWorkspace for a caller that will hand the
// credential to cloop's git proxy rather than to the executor — the
// gitproxycreds decorator, which looks for this method.
//
// The difference is one fact told to the broker (Requester.GitHubProxied): a
// grant limited to certain branches keeps its push, because the proxy is what
// holds the push to the list. Leased through plain ForWorkspace the same grant
// is delivered without its push, since the credential is headed somewhere
// nothing can.
func (s *BrokerSource) ForProxiedWorkspace(ctx context.Context, projectID string, w executor.Workspace) (executor.WorkspaceAccess, func(), error) {
	return s.forWorkspace(ctx, projectID, w, true)
}

func (s *BrokerSource) forWorkspace(ctx context.Context, projectID string, w executor.Workspace, proxied bool) (executor.WorkspaceAccess, func(), error) {
	noop := func() {}
	if s == nil || s.Broker == nil {
		return executor.WorkspaceAccess{}, noop, errors.New("gitcreds: no broker configured")
	}
	if !w.RequiresCredential() {
		// An unauthenticated fetch. Legitimate for a public repository, and
		// not something to manufacture a lease for.
		return executor.WorkspaceAccess{}, noop, nil
	}

	// The executor the lease is for: this source's own, unless the dispatch
	// is for a virtual executor its device carries out, in which case the
	// grant chosen before dispatch was matched against the virtual one and
	// the lease has to be too (Task 20349).
	executorID := executor.RequestingExecutor(ctx, s.ExecutorID)

	repoPath, hasRepoPath := w.RepoPath()
	// The origin's host, once it is known, rides on every refusal: what
	// fixes one depends on whether that host is github.com (Task 20423).
	var originHost string
	denied := func(reason string) error {
		return &executor.WorkspaceGrantError{
			Repo:        w.Repo,
			RepoPath:    repoPath,
			Grant:       strings.TrimSpace(w.CredentialGrant),
			ExecutorID:  executorID,
			ProjectPath: projectID,
			Reason:      reason,
			Host:        originHost,
		}
	}
	if !hasRepoPath {
		// Repository allowlists are owner/name globs, so a URL that is not
		// owner/name cannot be matched against one. Saying so beats leasing a
		// credential that no constraint could have narrowed.
		return executor.WorkspaceAccess{}, noop, denied(fmt.Sprintf(
			"%s is not an owner/name repository URL, so no repository allowlist can authorise it", w.Repo))
	}
	host, herr := w.ForgeHost()
	if herr != nil {
		// No host a credential could be bound to, so none is leased.
		return executor.WorkspaceAccess{}, noop, denied(fmt.Sprintf(
			"%s names no forge host a credential could be presented to: %v", w.Repo, herr))
	}
	originHost = host

	// Leased as the project whose grants these are. For a feature (Task
	// 20367) that is its parent: the grant chosen before the dispatch was
	// matched against the parent, and the feature's own path holds none — so
	// leasing as the path the run was dispatched for found nothing, and a
	// feature whose branch rides on a private upstream clone was refused
	// with "no active GitHub grant named …" while that grant was in force.
	lease, err := s.Broker.LeaseFor(ctx, secretbroker.Requester{
		ExecutorID:    executorID,
		ProjectID:     executor.PolicyProjectPath(projectID),
		GitHubProxied: proxied,
		// Only a GitHub token is read out of this lease; a kubeconfig the
		// same subjects hold is discarded, never handed on (Task 20420).
		KubeInProcess: true,
	}, s.Actor)
	if err != nil {
		return executor.WorkspaceAccess{}, noop, fmt.Errorf("gitcreds: lease for %s: %w", projectID, err)
	}
	release := func() { s.Broker.Release(lease.ID) }

	want := strings.TrimSpace(w.CredentialGrant)
	var (
		sawSecret bool
		// The first grant whose allowlist admitted the path on another
		// host, and that host: reported when nothing admits both.
		otherHostGrant, otherHost string
	)
	for _, mat := range lease.Materials {
		token, ok := mat.GitHubToken()
		if !ok {
			continue
		}
		if want != "" && !matchesGrantRef(mat, want) {
			continue
		}
		sawSecret = true
		if !mat.Constraints.AllowsRepo(repoPath) {
			continue
		}
		if mat.CheckForgeHost(originHost) != nil {
			if otherHost == "" {
				otherHostGrant, otherHost = mat.SecretName, mat.GitHubHost()
			}
			continue
		}
		return executor.WorkspaceAccess{
			Credential: executor.GitCredential{
				Username:   secretbroker.GitHubUsername,
				Password:   token,
				LeaseID:    lease.ID,
				GrantID:    mat.GrantID,
				SecretName: mat.SecretName,
				ExpiresAt:  lease.ExpiresAt,
				// The host the token may be presented to, and the only one:
				// every consumer downstream checks it again (Task 20423).
				Host: mat.GitHubHost(),
				// Carried for the proxy that applies it. Only a grant that
				// can push has one to carry: the broker drops the list from a
				// grant whose push it withheld, and a read-only grant never
				// had one.
				Branches: mat.Constraints.BranchNames(),
				// A GitHub App token's hour, which RefreshWorkspaceCredential
				// renews for a proxy session that outlives it. Zero for a PAT.
				TokenExpiresAt: mat.GitHubTokenExpiresAt(),
			},
		}, release, nil
	}

	// Nothing usable. Release before returning: a lease held open for a
	// workload that will not start is a credential the broker believes is out
	// in the world.
	release()
	if otherHost != "" {
		// Ahead of every other reason: the grant exists and admits the
		// path, so "create a grant" and "widen the allowlist" would both
		// send the operator the wrong way.
		gerr := denied(executor.HostMismatchReason(otherHostGrant, originHost, otherHost)).(*executor.WorkspaceGrantError)
		gerr.GrantHost = otherHost
		return executor.WorkspaceAccess{}, noop, gerr
	}
	shown := repoPath
	if !forgehost.IsGitHub(originHost) {
		shown += " on " + originHost
	}
	if sawSecret {
		return executor.WorkspaceAccess{}, noop, denied(fmt.Sprintf(
			"grant %s does not include repository %s in its allowlist", want, shown))
	}
	if want != "" {
		return executor.WorkspaceAccess{}, noop, denied(fmt.Sprintf(
			"no active GitHub grant named %s is issued to this executor for this project", want))
	}
	return executor.WorkspaceAccess{}, noop, denied(fmt.Sprintf(
		"no active GitHub grant authorises %s", shown))
}

// RefreshWorkspaceCredential re-mints the GitHub App installation token cred
// carries, at the scope it was first minted at, for a git proxy session that
// presents it longer than GitHub's hour (Task 20375). held is the token the
// session presents now.
//
// It returns the renewed credential and the function that destroys the one it
// replaced, which the session calls once nothing presents that any more. A
// refusal that will not change — the grant revoked or expired, the lease
// released, GitHub refusing for good — wraps executor.ErrCredentialRefused; any
// other error is worth retrying.
func (s *BrokerSource) RefreshWorkspaceCredential(ctx context.Context, cred executor.GitCredential, held string) (executor.GitCredential, func(), error) {
	if s == nil || s.Broker == nil {
		return executor.GitCredential{}, nil, errors.New("gitcreds: no broker configured")
	}
	got, err := s.Broker.RefreshAppToken(ctx, cred.LeaseID, cred.GrantID, held)
	if err != nil {
		if errors.Is(err, secretbroker.ErrRefreshRefused) {
			return executor.GitCredential{}, nil, fmt.Errorf("%w: %w", executor.ErrCredentialRefused, err)
		}
		return executor.GitCredential{}, nil, err
	}
	out := cred
	out.Password = got.Token
	out.TokenExpiresAt = got.ExpiresAt
	return out, got.Retire, nil
}

// LeasesRecorded implements gitproxycreds.RecordedSource: the broker records
// the leases it issues, so another hub process can take one over (Task 20390).
func (s *BrokerSource) LeasesRecorded() bool {
	return s != nil && s.Broker != nil && s.Broker.LeaseHolder() != ""
}

// matchesGrantRef reports whether a material is the one the spec named. Both
// the secret name and the grant ID are accepted, because the UI shows names
// while the API returns IDs and an operator will reasonably paste either.
func matchesGrantRef(mat secretbroker.Material, ref string) bool {
	return strings.EqualFold(strings.TrimSpace(mat.SecretName), ref) ||
		strings.EqualFold(strings.TrimSpace(mat.GrantID), ref) ||
		strings.EqualFold(strings.TrimSpace(mat.SecretID), ref)
}

// Static assertion that the concrete type still satisfies the interface the
// drivers hold. Without it a signature change here would only surface at the
// two wiring sites, each of which is behind a build tag's worth of optional
// configuration.
var _ executor.WorkspaceCredentialSource = (*BrokerSource)(nil)
