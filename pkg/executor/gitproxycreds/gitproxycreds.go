// Package gitproxycreds interposes a git interception proxy between a sandbox
// and the forge.
//
// It decorates an executor.WorkspaceCredentialSource. The inner source leases
// the forge credential exactly as before; this one keeps that credential on the
// hub, mints a pkg/gitproxy session against it, and hands the sandbox a session
// token plus a rewritten repository URL. The sandbox's git then talks to the
// proxy, and the proxy decides — per ref, on the push's own command list —
// whether an update is inside the branch allowlist.
//
// # What changes for the sandbox
//
// Nothing it can observe except the URL. The credential is still delivered as
// an HTTP basic header scoped to the repository's origin by
// executor.GitCredentialEnv, still never written to disk and never placed in an
// argv. Because the proxy's URL preserves the "owner/name" path
// (gitproxy.Minted.RepoURL), executor.Workspace.RepoPath keeps returning the
// same value, so grant matching and every audit row that names a repository are
// unaffected.
//
// # Why the decorator, and not a flag on the inner source
//
// Interception is a property of the deployment, not of a grant: the same GitHub
// grant is correct whether or not a hub routes through a proxy. Wrapping keeps
// pkg/executor/gitcreds solely about "which grant authorises this repository"
// and leaves "and how does the sandbox reach it" here, where an operator turns
// it on and off.
//
// # What a leaked token is worth
//
// The session token is worth the policy below, for the remaining TTL, against
// one repository, through one proxy: push to refs/heads/cloop/**, create and
// update only, and fetch. It is worth nothing against github.com directly. The
// PAT it stands in for is worth every repository the token is scoped to, in
// every direction, from anywhere, until someone revokes it.
package gitproxycreds

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/gitproxy"
)

// Source is an executor.WorkspaceCredentialSource that routes through a proxy.
type Source struct {
	// Inner leases the real forge credential. Required.
	Inner executor.WorkspaceCredentialSource
	// Registry mints the sessions. Required, and must be the same registry the
	// running proxy authenticates against — sessions live in its memory, so a
	// registry in another process could not authenticate what this one mints.
	Registry *gitproxy.Registry
	// Policy is applied to every session. The zero value means
	// WriteBackPolicy plus fetch; see New.
	Policy gitproxy.Policy
	// TTL bounds a session. Zero means gitproxy.DefaultSessionTTL.
	TTL time.Duration
	// ExecutorID is the executor sessions are minted for, recorded on the
	// audit row so a proxy event can be joined to a dispatch.
	ExecutorID string
	// Actor is the audit identity recorded on the mint.
	Actor string
}

// New returns a source that routes w through reg, or an error when it would be
// unusable.
//
// The default policy is WriteBackPolicy with fetch added: create and update
// under refs/heads/cloop/**, no deletes, and the read half a provisioning fetch
// needs. Fetch is on because with a proxy interposed the *clone* also goes
// through it — that is the point, since it is what keeps the forge credential
// off the sandbox for both halves of the round trip.
func New(inner executor.WorkspaceCredentialSource, reg *gitproxy.Registry, policy gitproxy.Policy,
	ttl time.Duration, executorID, actor string) (*Source, error) {

	if inner == nil {
		return nil, errors.New("gitproxycreds: nil inner credential source")
	}
	if reg == nil {
		return nil, errors.New("gitproxycreds: nil session registry")
	}
	if policy.IsZero() {
		policy = gitproxy.WriteBackPolicy()
		policy.AllowFetch = true
	}
	policy.Normalize()
	if err := policy.Validate(); err != nil {
		return nil, fmt.Errorf("gitproxycreds: session policy: %w", err)
	}
	if ttl < 0 {
		return nil, fmt.Errorf("gitproxycreds: negative session ttl %s", ttl)
	}
	if ttl > gitproxy.MaxSessionTTL {
		// Refused rather than clamped, for the reason Mint refuses it: an
		// operator who configured a day and silently got twelve hours would
		// discover it as a push that failed halfway through a long run.
		return nil, fmt.Errorf("gitproxycreds: session ttl %s exceeds the maximum %s",
			ttl, gitproxy.MaxSessionTTL)
	}
	if strings.TrimSpace(actor) == "" {
		actor = "system"
	}
	return &Source{
		Inner: inner, Registry: reg, Policy: policy, TTL: ttl,
		ExecutorID: strings.TrimSpace(executorID), Actor: actor,
	}, nil
}

// ForWorkspace implements executor.WorkspaceCredentialSource.
//
// The release function is always non-nil and gives back the *inner* lease — the
// forge credential the hub holds — exactly as the undecorated source does. It
// does not close the session: the sandbox fetches at the start of a run and
// pushes at the end, so a session closed when the credential was delivered
// would refuse the write-back it exists to authorise. A session's life is its
// TTL, and Registry.Close is how an operator ends one early.
func (s *Source) ForWorkspace(ctx context.Context, projectID string, w executor.Workspace) (executor.WorkspaceAccess, func(), error) {
	noop := func() {}
	if s == nil || s.Inner == nil || s.Registry == nil {
		return executor.WorkspaceAccess{}, noop, errors.New("gitproxycreds: source is not configured")
	}

	access, release, err := s.Inner.ForWorkspace(ctx, projectID, w)
	if release == nil {
		release = noop
	}
	if err != nil {
		// Returned unchanged so a *executor.WorkspaceGrantError still reaches
		// the UI with its remediation intact. Wrapping here would keep
		// errors.As working and bury the fix behind a prefix about a proxy the
		// operator has no reason to think about.
		return executor.WorkspaceAccess{}, release, err
	}
	if access.Credential.Empty() {
		// An unauthenticated fetch of a public repository. There is no
		// credential to keep off the sandbox, so there is nothing for the proxy
		// to protect and a session would only add a hop that can fail. A push
		// write-back on such a workspace has no credential either way and is
		// refused by gitwriteback with a message that says so.
		return access, release, nil
	}

	m, err := s.Registry.Mint(gitproxy.MintRequest{
		Upstream: w.Repo,
		Credential: gitproxy.Credential{
			Username: access.Credential.Username,
			Password: access.Credential.Password,
			GrantID:  access.Credential.GrantID,
			LeaseID:  access.Credential.LeaseID,
		},
		Policy:    s.Policy,
		TTL:       s.TTL,
		ProjectID: projectID,
		// No TaskID. ForWorkspace is not told one, and filling the field with
		// the nearest available string — the grant name — would put
		// "task=github-pat" on every proxy event and quietly break any join
		// against the run and task records that field exists to support.
		ExecutorID: s.ExecutorID,
		Actor:      s.Actor,
	})
	if err != nil {
		// Fail the dispatch. Falling back to the direct credential would hand
		// the sandbox the PAT precisely when the boundary is broken, which is
		// the one moment it must not: a proxy that fails open is not a
		// boundary, it is a default.
		release()
		return executor.WorkspaceAccess{}, noop, fmt.Errorf(
			"gitproxycreds: mint a proxy session for %s: %w", w.Repo, err)
	}

	sessionCred := m.Credential()
	return executor.WorkspaceAccess{
		Credential: executor.GitCredential{
			Username: sessionCred.Username,
			Password: sessionCred.Password,
			// The lease and grant identifiers are carried through unchanged so
			// the provisioning audit rows still name the grant that authorised
			// the fetch. They are not secret and the proxy's own events use the
			// same values, which is what lets the two trails be joined.
			LeaseID:    access.Credential.LeaseID,
			GrantID:    access.Credential.GrantID,
			SecretName: access.Credential.SecretName,
			// The session's expiry, not the lease's. This is the deadline that
			// now actually bounds the sandbox: before interception the sandbox
			// held the PAT and its access ended never, whatever the lease said.
			ExpiresAt: m.Session.ExpiresAt,
		},
		Repo: m.RepoURL,
	}, release, nil
}

// Static assertion: a signature change on the interface must fail here rather
// than at the single wiring site, which is behind optional configuration.
var _ executor.WorkspaceCredentialSource = (*Source)(nil)
