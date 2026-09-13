// Package ui - claude_identity.go resolves which Claude Code account a request
// acts on, and hands the answer to both the auth endpoints and the run
// dispatcher.
//
// Motivation (Task 20241): before this, a hub had exactly one Claude login.
// Whoever logged in last owned it; every user's tasks ran on that person's
// subscription; and any user clicking "Log out" signed out the whole
// deployment. With OIDC enabled each signed-in user now gets their own
// credential, session history and usage figures, stored in a private
// configuration directory (see pkg/claudecodeauth/identity.go).
//
// Deployments without OIDC are untouched: one machine, one operator, one
// credential in the host's own ~/.claude, exactly as before.
package ui

import (
	"fmt"
	"net/http"

	"github.com/blechschmidt/cloop/pkg/claudecodeauth"
	"github.com/blechschmidt/cloop/pkg/executor"
)

// claudeScope names the Claude account a request acts on.
type claudeScope struct {
	// Owner is the identity's OwnerKey, or "" in single-user mode. It keys
	// in-flight login sessions.
	Owner string
	// ConfigDir is the CLAUDE_CONFIG_DIR to run the CLI under, or "" to use
	// the host default.
	ConfigDir string
}

// PerUser reports whether this scope isolates a specific user rather than
// falling back to the host's shared credential.
func (c claudeScope) PerUser() bool { return c.ConfigDir != "" }

// claudeScopeFor resolves the Claude account for a request.
//
// With OIDC off the zero scope is returned, meaning "the host credential" —
// the single-user behaviour cloop has always had.
//
// With OIDC on the caller's identity selects a private directory. If no
// identity can be resolved the call fails rather than falling back to the host
// credential: on a multi-tenant hub, "I could not tell who you are" must never
// resolve to "then use the shared account everyone can see", which would hand
// an unidentified caller the operator's subscription.
func (s *Server) claudeScopeFor(r *http.Request) (claudeScope, error) {
	if !s.oidcEnabled() {
		return claudeScope{}, nil
	}
	id := s.recipientIdentity(r)
	if id == nil {
		return claudeScope{}, fmt.Errorf("no identity on request: cannot resolve a Claude Code account")
	}
	owner := id.OwnerKey()
	if owner == "" {
		return claudeScope{}, fmt.Errorf("identity has no stable owner key: cannot resolve a Claude Code account")
	}
	dir, err := claudecodeauth.HomeFor(owner)
	if err != nil {
		return claudeScope{}, fmt.Errorf("prepare Claude Code home for %s: %w", id.DisplayName(), err)
	}
	return claudeScope{Owner: owner, ConfigDir: dir}, nil
}

// claudeEnvResolver resolves the caller's Claude account now and returns a
// function that answers "what environment pins a workload to it" later.
//
// The two-step shape exists because the answer depends on the executor, which
// is only known once the workload is being dispatched — sometimes after the
// HTTP handler has returned (the brainstorm path dispatches from a goroutine).
// Resolving eagerly and capturing only the result keeps the *http.Request from
// outliving its handler, which is not safe to rely on.
//
// Returns nil in single-user mode, so callers can pass the result straight
// through without branching.
func (s *Server) claudeEnvResolver(r *http.Request) func(executor.Executor) []string {
	if r == nil {
		return nil
	}
	scope, err := s.claudeScopeFor(r)
	if err != nil || !scope.PerUser() {
		return nil
	}
	return func(ex executor.Executor) []string {
		return claudeEnvFor(scope, ex)
	}
}

// claudeWorkloadEnv returns the environment assignments that pin a dispatched
// workload to the requesting user's Claude account. It is the immediate form
// of claudeEnvResolver, for callers that already hold the executor.
func (s *Server) claudeWorkloadEnv(r *http.Request, ex executor.Executor) []string {
	resolve := s.claudeEnvResolver(r)
	if resolve == nil {
		return nil
	}
	return resolve(ex)
}

// claudeEnvFor is the placement decision shared by both forms.
//
// Returns nil when there is nothing to pin — no per-user scope, or an executor
// that does not share this filesystem. In the latter case the directory path
// would be meaningless inside the sandbox, and the hub deliberately does not
// forward its own environment there anyway; such executors receive credentials
// through the secret broker instead.
func claudeEnvFor(scope claudeScope, ex executor.Executor) []string {
	if ex == nil || !scope.PerUser() {
		return nil
	}
	if executor.IsolatesFromHost(ex) {
		return nil
	}
	// ScopeHarnessEnv also clears CLAUDE_CODE_OAUTH_TOKEN, which is the half
	// that actually enforces the isolation: an ambient token outranks the
	// configuration directory, and cloop populates one from the host's
	// dotfiles. The assignments are appended to the child's environment, where
	// the last occurrence of a key wins.
	//
	// Harness-scoped rather than CLI-scoped on purpose: this environment
	// belongs to a whole `cloop run`, which may be using a different provider
	// entirely, so other providers' credentials must survive it.
	return claudecodeauth.ScopeHarnessEnv(nil, scope.ConfigDir)
}
