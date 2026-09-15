package secretbroker

// gitguard.go moves a GitHub PAT's enforcement point out of the sandbox.
//
// # The problem with the credential helper
//
// githubpat.go delivers a PAT by writing it into the lease directory and
// installing a shell credential helper that releases it only for repositories
// inside the grant's allowlist. That helper is honest about what it is: the
// best enforcement point available *given that the token is in the sandbox*.
//
// But the helper runs inside the sandbox, reads a token file inside the
// sandbox, and is one `cat` away from being irrelevant. A workload that wants
// the whole token has it. So for a `github_pat` the allowlist is advisory —
// documentation of intent, not a boundary — and a user who grants a broadly
// scoped personal token to a project is, in practice, handing that project
// every repository the token can reach.
//
// This matters most in exactly the case the feature is for. A PAT is personal:
// it usually carries the `repo` scope across everything its owner can see,
// including repositories that have nothing to do with the project, and
// including other people's. "Narrow it down" cannot mean "ask nicely".
//
// # The inversion
//
// A GitGuard hands the token to something outside the sandbox — pkg/gitproxy —
// and gets back a session credential that is worth nothing anywhere else. The
// sandbox's git is pointed at the proxy by URL rewriting, so it keeps working
// unchanged; the proxy holds the PAT, admits only the allowlisted
// repositories, and enforces the grant's permissions as a ref policy.
//
//	workload ──session token──▶ gitproxy ──PAT──▶ github.com
//	                               │
//	                     allowlist + ref policy, outside the sandbox
//
// The narrowing becomes a property of the network path. A broad PAT stops
// being broad at the first hop, and a leaked session token buys an attacker
// the allowlist for the rest of the TTL rather than the token's whole reach.
//
// # Why an interface
//
// pkg/secretbroker must not import pkg/gitproxy: the broker is the lower layer
// and brokers credentials for executors that have nothing to do with git. The
// guard is therefore a seam, implemented in pkg/ui where the proxy singleton
// already lives, and this package stays unaware that a proxy is what is on the
// other side of it.

import (
	"context"
	"errors"
	"strings"
	"time"
)

// ErrGuardUnavailable reports that a guard was configured but could not
// produce a session.
//
// It is a distinct sentinel because the choice it forces is not a detail. A
// guarded delivery that quietly fell back to writing the PAT into the sandbox
// would hand over the broad credential at precisely the moment the boundary
// meant to narrow it was broken — the one circumstance in which it must not.
// Callers fail the lease instead. See githubMaterial.
var ErrGuardUnavailable = errors.New("secretbroker: git guard unavailable")

// GitGuard interposes an out-of-sandbox proxy between a workload and GitHub.
//
// An implementation takes custody of the token and returns credentials for a
// proxy that holds it. It must not return a result that embeds the token.
type GitGuard interface {
	// GuardGitHub takes a GitHub token and the constraints it was granted
	// under, and returns the credentials a sandbox should use in its place.
	//
	// Returning a zero GitGuardResult with a nil error means "not guarding
	// this one" — the delivery falls back to the in-sandbox helper. That is
	// how a hub with the proxy switched off keeps working, and it is a
	// decision the implementation makes deliberately rather than one this
	// package infers from an error it cannot interpret.
	GuardGitHub(ctx context.Context, req GitGuardRequest) (GitGuardResult, error)
}

// GitGuardRequest is one token and the authority it was granted.
type GitGuardRequest struct {
	// Token is the credential the guard takes custody of. It must not be
	// copied into the result, into a log, or into anything the sandbox reads.
	Token string
	// Repos is the grant's owner/name glob allowlist. The guard enforces it.
	Repos []string
	// Permissions is the grant's permission set ("contents:read"). The guard
	// translates it into what the proxy will allow — most importantly whether
	// the sandbox may push at all.
	Permissions []string

	// Labels. None is secret; all are audit bookkeeping.
	SecretName string
	SecretID   string
	GrantID    string
	LeaseID    string
	ProjectID  string
	ExecutorID string
	Actor      string
	// Owner is the identity a personal secret belongs to, or "" for a shared
	// one. It rides along so the proxy's audit rows name the person whose
	// credential is being spent, which for a personal PAT is the whole point.
	Owner string
}

// GitGuardResult is the substitute credential a sandbox receives.
type GitGuardResult struct {
	// BaseURL is the proxy's https base, with no path. GitHub URLs are
	// rewritten to it.
	BaseURL string
	// Username and Password authenticate to the proxy and to nothing else.
	Username string
	Password string
	// ExpiresAt is when the proxy stops honouring them.
	ExpiresAt time.Time
	// SessionID identifies the proxy session, for audit joins and revocation.
	SessionID string
	// Summary is an audit-safe description of what the proxy will enforce
	// ("read-only, acme/*"). It carries no credential.
	Summary string
	// ReadOnly records whether the grant's permissions left the session
	// unable to push. Surfaced so the lease's own summary can say so without
	// re-deriving the rule the guard already applied.
	ReadOnly bool
}

// Guarded reports whether the result actually carries a substitute credential.
// The zero value means the guard declined, which is not an error.
func (r GitGuardResult) Guarded() bool {
	return r.BaseURL != "" && r.Password != ""
}

// GitProxySessionEnvKey is the environment variable a guarded delivery carries
// the proxy session id in.
//
// Exported because the hub reads it back to revoke the session when the lease
// is released, and a second copy of the literal in pkg/ui would be a string
// that could drift — leaving sessions alive with nothing pointing at them.
//
// The id is not secret: the token it names lives in a separate 0600 file, and
// the proxy's own audit events already carry the id in the clear.
const GitProxySessionEnvKey = "CLOOP_GIT_PROXY_SESSION"

// UnavailableGitGuard refuses every request, for a caller that must not
// deliver a GitHub token unguarded but has no proxy to guard it with.
//
// It exists because "the proxy is required and is not here" arises in two
// unrelated places — the hub whose proxy failed to start, and a short-lived
// CLI process that never had one (cloop hub doctor --smoke brokers a real
// lease and materialises it into a real sandbox). Both must fail closed, and a
// second hand-rolled copy of that decision is how one of them ends up not
// doing so.
type UnavailableGitGuard struct {
	// Reason is shown to the operator. It should name the configuration that
	// is not in effect, not merely say that something is missing.
	Reason string
}

// GuardGitHub implements GitGuard by always failing.
func (g UnavailableGitGuard) GuardGitHub(context.Context, GitGuardRequest) (GitGuardResult, error) {
	reason := strings.TrimSpace(g.Reason)
	if reason == "" {
		reason = "no git proxy is available to hold the token"
	}
	return GitGuardResult{}, errors.New(reason)
}
