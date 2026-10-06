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
// The inner lease — the forge credential the hub holds — lives as long as the
// session, and is released when the session ends: closed, reaped after its TTL,
// or closed with the hub. It used to be released when the driver was done
// delivering, which for a github_app grant destroyed the installation token at
// GitHub while the session went on presenting it upstream: every later git
// operation through the session met a dead token, and on Kubernetes, which
// delivers before the init container fetches, the fetch itself did (Task 20349).
//
// The release function handed to the driver is therefore about the *session*.
// It is always non-nil, and it closes the session only if nothing ever
// authenticated with it — the dispatch failed, or the fetch never reached the
// proxy — which releases the inner lease with it. A session the sandbox did use
// keeps its TTL: the sandbox fetches at the start of a run and pushes at the
// end, so a session closed when the credential was delivered would refuse the
// write-back it exists to authorise. Registry.Close is how an operator ends one
// early.
func (s *Source) ForWorkspace(ctx context.Context, projectID string, w executor.Workspace) (executor.WorkspaceAccess, func(), error) {
	noop := func() {}
	if s == nil || s.Inner == nil || s.Registry == nil {
		return executor.WorkspaceAccess{}, noop, errors.New("gitproxycreds: source is not configured")
	}

	// Leased as proxied when the inner source can be told so: this decorator
	// is about to keep the credential on the hub, which is what lets a grant
	// limited to certain branches keep its push (the broker withholds it from
	// a credential headed anywhere else). An inner source that cannot be told
	// is leased the ordinary way — the safe default, since it can only mean a
	// push withheld that did not need to be.
	var (
		access  executor.WorkspaceAccess
		release func()
		err     error
	)
	if held, ok := s.Inner.(HeldSource); ok {
		access, release, err = held.ForProxiedWorkspace(ctx, projectID, w)
	} else {
		access, release, err = s.Inner.ForWorkspace(ctx, projectID, w)
	}
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

	// The grant's own branch list narrows the hub's policy for this session
	// (Task 20340): the hub's allowlist stays the ceiling, and a push has to
	// match both. A grant with no list leaves the policy exactly as configured.
	pol := s.Policy
	pol.RestrictRefs = nil
	if len(access.Credential.Branches) > 0 {
		pol.RestrictRefs = append([]string(nil), access.Credential.Branches...)
	}

	var (
		refresh   gitproxy.RefreshFunc
		credUntil time.Time
	)
	if rs, ok := s.Inner.(RefreshingSource); ok && !access.Credential.TokenExpiresAt.IsZero() {
		// A credential the hub minted, such as a GitHub App installation
		// token: the session renews it through the source that leased it,
		// rather than presenting it past its hour (Task 20375).
		refresh = workspaceRefresher(rs, access.Credential)
		credUntil = access.Credential.TokenExpiresAt
	}

	m, err := s.Registry.Mint(gitproxy.MintRequest{
		// Recorded, when the lease it stands on is (Task 20390): the hub
		// process that adopts the run after this one stops takes that lease
		// over and restores the session, so a write-back push that presents
		// it after a restart is served rather than refused.
		Durable:  s.leasesRecorded() && strings.TrimSpace(access.Credential.LeaseID) != "",
		Upstream: w.Repo,
		Credential: gitproxy.Credential{
			Username: access.Credential.Username,
			Password: access.Credential.Password,
			GrantID:  access.Credential.GrantID,
			LeaseID:  access.Credential.LeaseID,
		},
		CredentialExpiresAt: credUntil,
		Refresh:             refresh,
		Policy:              pol,
		TTL:                 s.TTL,
		ProjectID:           projectID,
		// No TaskID. ForWorkspace is not told one, and filling the field with
		// the nearest available string — the grant name — would put
		// "task=github-pat" on every proxy event and quietly break any join
		// against the run and task records that field exists to support.
		// The executor the dispatch is for, which a virtual executor's
		// device is not: the proxy's rows should name the one the operator
		// bound the project to.
		ExecutorID: executor.RequestingExecutor(ctx, s.ExecutorID),
		Actor:      s.Actor,
		// The inner lease stands behind the session's upstream credential, so
		// it goes when the session does and not a moment before.
		OnEnd: release,
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
			// Passed on for anything downstream that reports it. The session
			// above is what enforces it.
			Branches: access.Credential.Branches,
			// Named so a driver that keeps the credential for a write-back
			// can say which session it holds (Task 20390). Not secret: it is
			// the session's username and in every proxy audit row.
			SessionID: m.Session.ID,
		},
		Repo: m.RepoURL,
	}, s.relinquish(m.Session), nil
}

// RecordedSource is implemented by an inner source whose leases are recorded
// durably, so a hub process other than the one that issued one can take it
// over (Task 20390). Only a session standing on such a lease is minted
// Durable: a record of one standing on a lease nobody can take over would be
// a record nothing could restore.
//
// Discovered by type assertion for the reason HeldSource is.
type RecordedSource interface {
	LeasesRecorded() bool
}

// leasesRecorded reports whether the inner source's leases are recorded.
func (s *Source) leasesRecorded() bool {
	rs, ok := s.Inner.(RecordedSource)
	return ok && rs.LeasesRecorded()
}

// relinquish returns the release a driver calls when it is done with what it
// was handed: it closes a session nothing ever authenticated with, and leaves a
// used one to its TTL. See ForWorkspace.
func (s *Source) relinquish(sess *gitproxy.Session) func() {
	return func() {
		if sess.Used() {
			return
		}
		s.Registry.Close(sess.ID, "workspace credential released unused")
	}
}

// RefreshingSource is implemented by an inner source whose credentials expire
// on a clock the hub knows and can be re-minted before they do —
// gitcreds.BrokerSource, for a GitHub App grant (Task 20375).
//
// Discovered by type assertion for the reason HeldSource is.
type RefreshingSource interface {
	// RefreshWorkspaceCredential renews cred, whose password the session
	// presents as held. It returns the renewed credential and the function
	// that ends the one it replaced; an error wrapping
	// executor.ErrCredentialRefused is final.
	RefreshWorkspaceCredential(ctx context.Context, cred executor.GitCredential, held string) (executor.GitCredential, func(), error)
}

// workspaceRefresher adapts a RefreshingSource to the session's refresher.
func workspaceRefresher(rs RefreshingSource, cred executor.GitCredential) gitproxy.RefreshFunc {
	return func(ctx context.Context, held string) (gitproxy.Refreshed, error) {
		got, retire, err := rs.RefreshWorkspaceCredential(ctx, cred, held)
		if err != nil {
			if errors.Is(err, executor.ErrCredentialRefused) {
				return gitproxy.Refreshed{}, fmt.Errorf("%w: %w", gitproxy.ErrCredentialRefused, err)
			}
			return gitproxy.Refreshed{}, err
		}
		return gitproxy.Refreshed{
			Credential: gitproxy.Credential{
				Username: got.Username,
				Password: got.Password,
				GrantID:  got.GrantID,
				LeaseID:  got.LeaseID,
			},
			ExpiresAt: got.TokenExpiresAt,
			Retire:    retire,
		}, nil
	}
}

// HeldSource is implemented by an inner source that can lease a credential
// knowing a git proxy, not the executor, will hold it. gitcreds.BrokerSource
// does; see its ForProxiedWorkspace for what that changes.
//
// Discovered by type assertion rather than added to
// executor.WorkspaceCredentialSource, because only this decorator has anything
// to say through it and every other implementation — the fakes in driver
// tests included — would otherwise have to grow a method that means nothing
// to them.
type HeldSource interface {
	ForProxiedWorkspace(ctx context.Context, projectID string, w executor.Workspace) (executor.WorkspaceAccess, func(), error)
}

// Static assertion: a signature change on the interface must fail here rather
// than at the single wiring site, which is behind optional configuration.
var _ executor.WorkspaceCredentialSource = (*Source)(nil)

// Refusing returns a source that refuses every workspace with
// executor.ErrWorkspaceUnavailable, saying why.
//
// It is what a process whose configuration asks for the git proxy puts in
// front of a driver when that process cannot route through one — the proxy
// failed to start in `cloop ui`, or the process is not `cloop ui` at all and so
// never runs one (Task 20349). Handing the undecorated source back instead
// would deliver the forge credential into every sandbox while the
// configuration says it cannot happen.
//
// It refuses rather than standing in for "no source" because the two read
// differently downstream: no source means "this hub has no broker", whose
// remedy is a grant, while this means "the proxy the operator configured is not
// in the path", whose remedy is the proxy.
func Refusing(reason string) executor.WorkspaceCredentialSource {
	return refusingSource{reason: strings.TrimSpace(reason)}
}

type refusingSource struct{ reason string }

func (r refusingSource) ForWorkspace(_ context.Context, _ string, _ executor.Workspace) (executor.WorkspaceAccess, func(), error) {
	return executor.WorkspaceAccess{}, func() {}, fmt.Errorf("%w: %s", executor.ErrWorkspaceUnavailable, r.reason)
}
