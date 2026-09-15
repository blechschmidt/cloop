package ui

// gitguard.go implements secretbroker.GitGuard on top of the running git
// proxy, so a user's personal GitHub token is narrowed by something outside
// the sandbox rather than by a script inside it.
//
// # What changes for the user
//
// A developer on a multi-user hub stores their own PAT (a personal secret, so
// only they can spend it — see pkg/secretbroker/ownership.go) and grants it to
// a project with an allowlist. Without a proxy, the token is written into the
// sandbox and the allowlist is enforced by a credential helper the workload
// can simply read around; the practical authority granted is everything the
// PAT can reach, which for a personal token is usually every repository its
// owner can see.
//
// With the proxy, the token stays on the hub. The sandbox gets a session
// credential that only works against this proxy, only for the allowlisted
// repositories, only for the refs the policy admits, and only until the TTL
// expires. That is the narrowing: the same broad token, bounded by the network
// path instead of by convention.
//
// # Where the two halves of the bound come from
//
// The operator's configured policy is the ceiling and the grant narrows within
// it. An operator who restricted pushes to refs/heads/cloop/** cannot be
// widened by any grant, and a grant that authorises no writes is read-only
// however permissive the hub's policy is. Composing them this way means
// neither party can be surprised by the other.

import (
	"context"
	"fmt"
	"strings"

	"github.com/blechschmidt/cloop/pkg/gitproxy"
	"github.com/blechschmidt/cloop/pkg/secretbroker"
)

// githubUpstreamBase is the forge a github_pat grant is proxied to.
//
// Fixed rather than configurable: a GitHub PAT authenticates to github.com,
// and a hub that pointed one somewhere else would be presenting a user's
// credential to a host they never authorised. GitHub Enterprise would be a
// different secret kind with its own base, not a setting on this one.
const githubUpstreamBase = "https://github.com"

// gitGuard adapts the proxy service to the broker's seam.
type gitGuard struct{ svc *gitProxyService }

// GuardGitHub mints a scoped proxy session for a PAT grant.
//
// A nil service declines rather than failing, which is how a hub with no proxy
// configured keeps delivering credentials the old way. The broker treats a
// declined guard and a configured-but-broken one differently on purpose: only
// the second is a security control that was asked for and is not there, and
// that one fails the lease.
func (g gitGuard) GuardGitHub(ctx context.Context, req secretbroker.GitGuardRequest) (secretbroker.GitGuardResult, error) {
	if g.svc == nil || g.svc.reg == nil {
		return secretbroker.GitGuardResult{}, nil
	}
	if err := ctx.Err(); err != nil {
		return secretbroker.GitGuardResult{}, err
	}
	if strings.TrimSpace(req.Token) == "" {
		return secretbroker.GitGuardResult{}, fmt.Errorf("no token to guard")
	}
	if len(req.Repos) == 0 {
		// Refused rather than defaulted. A session with no allowlist would
		// admit nothing and every clone would fail with a refusal that named
		// the wrong cause; the real fault is a grant that should not exist.
		return secretbroker.GitGuardResult{}, fmt.Errorf(
			"grant %s carries no repository allowlist", req.GrantID)
	}

	policy, readOnly := guardPolicy(g.svc.policy, req.Permissions)

	// The actor is the credential's owner when there is one. A personal PAT
	// spent on a project should name the person in the proxy's audit rows,
	// not the executor that happened to run the task.
	actor := strings.TrimSpace(req.Owner)
	if actor == "" {
		actor = strings.TrimSpace(req.Actor)
	}
	if actor == "" {
		actor = workspaceLeaseActor
	}

	m, err := g.svc.reg.Mint(gitproxy.MintRequest{
		Upstream:     githubUpstreamBase,
		RepoPatterns: req.Repos,
		Credential: gitproxy.Credential{
			Username: secretbroker.GitHubUsername,
			Password: req.Token,
			GrantID:  req.GrantID,
			LeaseID:  req.LeaseID,
		},
		Policy:     policy,
		TTL:        g.svc.ttl,
		ProjectID:  req.ProjectID,
		ExecutorID: req.ExecutorID,
		Actor:      actor,
	})
	if err != nil {
		return secretbroker.GitGuardResult{}, err
	}

	cred := m.Credential()
	mode := "read-write"
	if readOnly {
		mode = "read-only"
	}
	return secretbroker.GitGuardResult{
		BaseURL:   g.svc.baseURL,
		Username:  cred.Username,
		Password:  cred.Password,
		ExpiresAt: m.Session.ExpiresAt,
		SessionID: m.Session.ID,
		ReadOnly:  readOnly,
		Summary: fmt.Sprintf("%s via git proxy, repos %s, refs %s",
			mode, strings.Join(req.Repos, "|"), strings.Join(policy.AllowedRefs, "|")),
	}, nil
}

// guardPolicy narrows the hub's configured policy by the grant's permissions,
// and reports whether the result can write at all.
//
// It only ever narrows. Reading comes from the configured policy, which in
// every real deployment enables fetch (see config.GitProxyConfig.Policy), so
// this does not have to grant it — and must not, because forcing a dimension on
// would make "the operator's policy is the ceiling" false in that one place.
//
// Writing is the part that has to be earned.
// secretbroker.Constraints.AllowsPermission treats an unenumerated permission
// set as authorising nothing beyond read, and this honours that reading rather
// than inventing a second one.
//
// Delete is never granted regardless of the permission set. A write-back has
// no reason to remove a ref, and "contents:write" is far too coarse a thing to
// read as permission to destroy a branch in someone's personal repository.
func guardPolicy(base gitproxy.Policy, permissions []string) (gitproxy.Policy, bool) {
	c := secretbroker.Constraints{Permissions: permissions}
	mayWrite := c.AllowsPermission("contents:write")

	pol := base
	if pol.IsZero() {
		// No configured policy at all, so there is no ceiling to respect and a
		// default has to be chosen. WriteBackPolicy does not allow fetch — it
		// was written for a push-only write-back — and a PAT grant that could
		// not read would be useless, so this one case adds it.
		pol = gitproxy.WriteBackPolicy()
		pol.AllowFetch = true
	}
	// A fresh slice: Policy is copied by value but shares its allowlist's
	// backing array, so narrowing in place would write through into the
	// service's own configured policy and narrow it for every later session.
	pol.AllowedRefs = append([]string(nil), pol.AllowedRefs...)

	// Every remaining adjustment narrows. AllowFetch is deliberately *not* set
	// here: it is inherited from the configured policy, so this function cannot
	// return anything broader than the operator allowed in any dimension. In
	// practice config.GitProxyConfig.Policy() always enables fetch, so a grant
	// gets its read access from there rather than from an override here.
	pol.AllowDelete = false
	if !mayWrite {
		pol.AllowCreate = false
		pol.AllowUpdate = false
	}
	// Otherwise create/update stay as the operator configured them: the grant
	// authorises writing, and how far is the hub's policy to say.
	return pol, !pol.AllowCreate && !pol.AllowUpdate
}

// attachGitGuard points a broker at the running proxy, if there is one.
//
// Called wherever the UI opens a broker, because the broker is constructed per
// call and the proxy is a process singleton started earlier in boot. A nil
// return from activeGitProxy leaves the broker unguarded, which is the correct
// behaviour for a hub with no proxy configured — and for one whose proxy
// failed to start, the guard is still attached as unavailable so the lease
// fails rather than quietly handing the sandbox the raw token.
func attachGitGuard(b *secretbroker.Broker) *secretbroker.Broker {
	if b == nil {
		return b
	}
	svc := activeGitProxy()
	if svc == nil {
		if gitProxyRequired.Load() {
			// The operator asked for interception and there is none. Refusing
			// here is the same trade Wrap makes for workspaces: a GitHub PAT
			// lease fails loudly instead of delivering the unguarded token
			// into a sandbox while the config says it cannot happen.
			b.GitGuard = unavailableGitGuard()
		}
		return b
	}
	b.GitGuard = gitGuard{svc: svc}
	return b
}

// gitProxySessionEnvKey is the environment variable deliverGuardedGitHub puts
// the session id in. It is how a lease's proxy sessions are found again at
// close time without the broker having to learn what a proxy session is.
//
// The id is not a credential — the token is in a separate 0600 file — so
// carrying it in the environment costs nothing and buys the revocation below.
const gitProxySessionEnvKey = secretbroker.GitProxySessionEnvKey

// closeGuardedSessions revokes every git proxy session a lease's materials
// named. It is safe to call with a nil lease, on a hub with no proxy, and more
// than once: Registry.Close is idempotent.
func closeGuardedSessions(lease *secretbroker.Lease) {
	if lease == nil {
		return
	}
	svc := activeGitProxy()
	if svc == nil || svc.reg == nil {
		return
	}
	for _, m := range lease.Materials {
		id := strings.TrimSpace(m.Env[gitProxySessionEnvKey])
		if id == "" {
			continue
		}
		svc.reg.Close(id, "lease released")
	}
}

// Enforcement modes reported on a grant. See grantView.Enforcement.
const (
	enforcementProxy     = "proxy"
	enforcementUnguarded = "unguarded"
)

// grantEnforcement reports where a grant of this kind has its scope checked
// on this hub.
//
// Two kinds are answered, and they are the two whose grant says more than the
// delivered payload can enforce by itself:
//
//   - github_pat, whose repository allowlist is otherwise checked by a
//     credential helper running inside the sandbox;
//   - kubeconfig, whose namespace allowlist is otherwise a client-side
//     default that `kubectl -n` ignores, and whose verbs have no
//     representation in the document at all.
//
// The other kinds are narrowed by rewriting the payload before delivery — an
// App credential is exchanged for a token GitHub itself has already scoped, a
// registry secret loses the auth entries it may not use — so there is no gap
// between what the grant says and what the workload holds, and no question
// for this field to answer.
func grantEnforcement(kind secretbroker.Kind) string {
	// Required-but-absent reports as unguarded rather than as proxy in both
	// cases: the lease will fail, and a row claiming the stronger mode would
	// be the one thing worse than the weaker one — a promise the hub is not
	// keeping.
	switch kind {
	case secretbroker.KindGitHubPAT:
		if activeGitProxy() == nil {
			return enforcementUnguarded
		}
		return enforcementProxy
	case secretbroker.KindKubeconfig:
		if activeKubeGuard() == nil {
			return enforcementUnguarded
		}
		return enforcementProxy
	default:
		return ""
	}
}

// unavailableGitGuard is what a hub that asked for a proxy and has not got one
// attaches, so a GitHub lease fails instead of falling back to the raw token.
func unavailableGitGuard() secretbroker.GitGuard {
	return secretbroker.UnavailableGitGuard{Reason: "executors.git_proxy is enabled but the " +
		"proxy is not running, so a GitHub token cannot be delivered without handing it to " +
		"the sandbox directly"}
}

// Interface checks at the wiring layer, where a signature change should fail.
var (
	_ secretbroker.GitGuard = gitGuard{}
)
