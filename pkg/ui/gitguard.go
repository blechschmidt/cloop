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

	policy, readOnly := guardPolicy(g.svc.policy, req.Permissions, req.Branches)

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
	var pushRefs []string
	if readOnly {
		mode = "read-only"
	} else {
		// The session's own normalised copy, so what the workload is told is
		// exactly what the proxy will compare its push against.
		pushRefs = append([]string(nil), m.Session.Policy.AllowedRefs...)
	}
	return secretbroker.GitGuardResult{
		BaseURL:   g.svc.baseURL,
		Username:  cred.Username,
		Password:  cred.Password,
		ExpiresAt: m.Session.ExpiresAt,
		SessionID: m.Session.ID,
		ReadOnly:  readOnly,
		PushRefs:  pushRefs,
		Summary: fmt.Sprintf("%s via git proxy, repos %s, refs %s",
			mode, strings.Join(req.Repos, "|"), m.Session.Policy.RefSummary()),
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
//
// A grant's branch allowlist narrows where the remaining writes may land
// (Task 20340). It becomes the policy's RestrictRefs rather than its
// AllowedRefs, so the operator's allowlist stays the ceiling: a ref has to be
// admitted by both, and a grant that names main on a hub restricted to
// refs/heads/cloop/** gains nothing by it.
func guardPolicy(base gitproxy.Policy, permissions, branches []string) (gitproxy.Policy, bool) {
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
	readOnly := !pol.AllowCreate && !pol.AllowUpdate

	// Replaced, never appended to: the base is the hub's policy, which has no
	// restriction of its own, and a fresh slice for the aliasing reason above.
	// A read-only session gets none, because there is no push for it to
	// narrow — and ValidateFor refuses a branch list on a grant that cannot
	// push, so a read-only grant carrying one should not exist anyway.
	pol.RestrictRefs = nil
	if !readOnly && len(branches) > 0 {
		pol.RestrictRefs = secretbroker.Constraints{Branches: branches}.BranchRefPatterns()
		if len(pol.RestrictRefs) == 0 {
			// Every entry was blank. A list that named something but narrows
			// to nothing must not read as "no restriction"; Normalize turns
			// this into a pattern Validate refuses, failing the mint closed.
			pol.RestrictRefs = []string{""}
		}
	}
	return pol, readOnly
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

// What becomes of a grant's branch allowlist on this hub (Task 20340). See
// branchEnforcement.
const (
	// branchesByProxy: the git proxy holds the token and refuses a push to any
	// branch outside the list, outside the sandbox.
	branchesByProxy = "proxy"
	// branchesProxyDown: the config asks for a proxy that is not running, so
	// the grant's GitHub lease fails rather than deliver the token unguarded.
	branchesProxyDown = "unavailable"
	// branchesReadOnly: no proxy on this hub, so a github_app grant is minted
	// read-only — GitHub enforces that — and its push is withheld.
	branchesReadOnly = "read_only"
	// branchesNotDelivered: no proxy on this hub, and a github_pat cannot be
	// narrowed to read-only, so the grant is not delivered at all.
	branchesNotDelivered = "not_delivered"
)

// branchEnforcement reports what a grant's branch allowlist amounts to on this
// hub, or "" for a grant that has none.
//
// It exists because the list is the one GitHub constraint that nothing but the
// proxy can enforce, so the same grant means three different things on three
// hubs: an enforced boundary, a read-only credential, or no credential at all.
// A row that showed "branches: feature/*" identically in all three cases would
// be claiming the first while delivering one of the others. The rule mirrors
// the broker's (secretbroker.githubMaterial and githubAppMaterial) and the
// attachment attachGitGuard makes, and gitguard_test.go holds them together.
func branchEnforcement(kind secretbroker.Kind, c secretbroker.Constraints) string {
	if !c.RestrictsBranches() {
		return ""
	}
	switch {
	case activeGitProxy() != nil:
		return branchesByProxy
	case gitProxyRequired.Load():
		return branchesProxyDown
	case kind == secretbroker.KindGitHubApp:
		return branchesReadOnly
	case kind == secretbroker.KindGitHubPAT:
		return branchesNotDelivered
	}
	return ""
}

// gitProxyStatusView is what a panel that offers a branch allowlist needs to
// know before anyone types one: whether this hub can enforce it, and inside
// which ceiling.
type gitProxyStatusView struct {
	// Running: the proxy is up, so a branch allowlist is enforced.
	Running bool `json:"running"`
	// Required: the config asks for one. With Running false this is a hub
	// whose proxy failed to start, and GitHub leases fail closed.
	Required bool `json:"required"`
	// PushRefs is the hub's own allowlist for pushes, as full ref patterns. A
	// grant's branches only narrow within it. Empty when no proxy runs.
	PushRefs []string `json:"push_refs,omitempty"`
}

// gitProxyStatus reports the running proxy's state for the dashboard.
//
// The ceiling is the running proxy's, not the config file's: a panel that
// quoted the file would be describing a policy this process may not have
// loaded. No listen address, certificate path or session count — none of that
// helps someone choose a branch, and all of it is reconnaissance.
func gitProxyStatus() gitProxyStatusView {
	v := gitProxyStatusView{Required: gitProxyRequired.Load()}
	if svc := activeGitProxy(); svc != nil {
		v.Running = true
		pol := svc.policy
		if pol.IsZero() {
			// guardPolicy's own fallback, so the panel names the ceiling the
			// guard will actually apply.
			pol = gitproxy.WriteBackPolicy()
		}
		pol.Normalize()
		if pol.AllowCreate || pol.AllowUpdate {
			v.PushRefs = append([]string(nil), pol.AllowedRefs...)
		}
	}
	return v
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
