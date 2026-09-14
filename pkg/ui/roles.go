package ui

// Runtime role bindings on the hub side (Task 20248).
//
// Two things live here: opening the source the resolver reads from, and
// closing it. Everything about what a binding means is in pkg/authz, and
// everything about how one is stored is in pkg/rolestore — this file only
// connects them to a running server's lifetime.
//
// The enforcement half is in authz.go, where a deny binding is checked ahead
// of the RBAC bypass. It has to be: a hub running on oidc.admin_emails alone
// never reaches Resolve, and that is the deployment most likely to still have
// a long-lived administrator worth demoting.

import (
	"fmt"
	"sync"

	"github.com/blechschmidt/cloop/pkg/apitoken"
	"github.com/blechschmidt/cloop/pkg/authz"
	"github.com/blechschmidt/cloop/pkg/logger"
	"github.com/blechschmidt/cloop/pkg/oidcauth"
	"github.com/blechschmidt/cloop/pkg/rolestore"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

type roleStoreState struct {
	mu    sync.Mutex
	store *rolestore.Store
	db    *statedb.DB
}

// OpenRoleStore returns the runtime binding source backed by the hub's own
// control-plane database, opening it on first call.
//
// Unlike OpenSessionStore the error is a real failure and the caller should
// abort startup. The asymmetry is deliberate. A missing session store costs
// durability — people stay signed in, they just get signed out by a restart —
// whereas a missing binding source costs *containment*: every deny an operator
// has written silently stops applying, and the hub comes up handing authority
// back to accounts somebody deliberately took it from. Starting wide open is
// not a degraded mode of that, it is the failure it was meant to prevent.
//
// The database is the hub's, never a managed project's, for the sharpest
// version of the usual reason: a tenant able to write this table could grant
// itself admin across the fleet with one INSERT.
func (s *Server) OpenRoleStore() (*rolestore.Store, error) {
	s.roles.mu.Lock()
	defer s.roles.mu.Unlock()
	if s.roles.store != nil {
		return s.roles.store, nil
	}
	// No existence check, unlike OpenSessionStore. Open creates and migrates,
	// and on a first run that is the right answer rather than an error: an
	// empty binding table has no containment to lose. The hub has in any case
	// already opened this database to take its lease, so the file exists by
	// the time anything calls here.
	dbPath := state.DBPath(s.WorkDir)
	db, err := statedb.Open(dbPath)
	if err != nil {
		return nil, fmt.Errorf("open control-plane database: %w", err)
	}
	store, err := rolestore.New(db, rolestore.WithErrorHandler(func(err error) {
		// A refresh that failed leaves the previous answer in force, so this
		// is not an outage — but it does mean a demotion written since then
		// has not landed, which is the one thing an operator mid-incident
		// must not have to guess at.
		s.log().Warn(logger.EventAuthz, 0,
			"could not refresh runtime role bindings — still enforcing the last known set",
			map[string]interface{}{"error": err.Error()})
	}))
	if err != nil {
		_ = db.Close()
		return nil, err
	}
	s.roles.db, s.roles.store = db, store
	return store, nil
}

// connectionDenied reports the runtime deny binding that has withdrawn an open
// stream's authority since it was established, or nil.
//
// Authorization for a long-lived connection is decided once, at connect. That
// is fine for a policy that only changes on redeploy, and not fine for a
// runtime deny binding, whose entire purpose is to take authority away from an
// account that is using it right now. Without a periodic re-check a demoted
// administrator keeps a live stream of every task update, log line and state
// diff for as long as they leave the tab open — and containment that leaves
// the data flowing is not containment.
//
// Takes the two identity fields rather than a client struct because both
// transports need it and they have separate ones: hubClient for WebSockets and
// sseClient for the EventSource fallback. Fixing only the transport that
// happened to be read first would leave the gap open on the other, which is
// what a client picks when the WebSocket upgrade fails.
//
// Both identity shapes are checked. The session identity is the obvious one;
// the API token's owner matters for the same reason it does in grant.decide —
// a display-glasses link (Task 20194) is delegated authority, and delegated
// authority must not outlive the person it was delegated from. A token with no
// owner is a service account, which no claim names and no binding can match.
//
// Every connection on a hub with no runtime bindings is settled by the guard
// below before anything else is computed: projectNameForPath walks the project
// registry, and that is not a cost to put on a keepalive tick for a hub that
// has never had an incident.
func (s *Server) connectionDenied(user *oidcauth.Identity, token *apitoken.Token, workDir string) *authz.Binding {
	if !s.runtimeBindingsExist() {
		return nil
	}
	scope := authz.Scope{Project: s.projectNameForPath(workDir), ProjectPath: workDir}
	if user != nil {
		if b := s.Authz.DeniedBy(subjectFromIdentity(user), scope); b != nil {
			return b
		}
	}
	if token != nil && token.Owner != nil {
		if b := s.Authz.DeniedBy(subjectFromOwner(token.Owner), scope); b != nil {
			return b
		}
	}
	return nil
}

// logConnectionDenied records a stream torn down by a runtime deny.
func (s *Server) logConnectionDenied(transport string, b *authz.Binding) {
	s.log().Warn(logger.EventAuthz, 0,
		"closing a "+transport+" stream whose identity has been denied at runtime",
		map[string]interface{}{"binding": b.Value, "claim": string(b.Claim)})
}

// closeRoleStore releases the runtime binding database handle.
func (s *Server) closeRoleStore() {
	s.roles.mu.Lock()
	db := s.roles.db
	s.roles.db, s.roles.store = nil, nil
	s.roles.mu.Unlock()
	if db != nil {
		_ = db.Close()
	}
}
