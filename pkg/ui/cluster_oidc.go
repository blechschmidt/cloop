package ui

// cluster_oidc.go: single sign-on when several hub processes serve one control
// plane (Task 20354).
//
// Sessions were already durable (Task 20176), so any member can authenticate
// any session. Three things were not:
//
//   - A login in flight. Its nonce and PKCE verifier live in the memory of the
//     member that sent the browser to the identity provider, and the callback
//     comes back to whichever member the load balancer picks. The state
//     parameter now names the member that began the login, and the callback is
//     forwarded there.
//   - A revoked session. Each member caches sessions for sessionCacheTTL, so a
//     sign-out on one left the session honoured on the others until their copy
//     aged out. Invalidations now go over the bus, and since Task 20398 each
//     member that hears one also closes the streams the session opened there.
//   - A refresh. Two members redeeming one refresh token at once is, for a
//     provider that rotates refresh tokens, a sign-out. Redemptions of one
//     session now take a cluster-wide lock.

import (
	"context"
	"net/http"
	"time"

	"github.com/blechschmidt/cloop/pkg/oidcauth"
)

// ownerSessionRefresh is the ownership kind the refresh lock claims. Key: the
// session's stored id.
const ownerSessionRefresh = "session_refresh"

// refreshLockPoll is how often a member waiting for another's refresh looks
// again. A redemption is one HTTPS round trip; this is a small fraction of it.
const refreshLockPoll = 100 * time.Millisecond

// InstallOIDCHooks adds this hub's hooks to an authenticator config.
//
// On every hub, a session that changes — revoked, signed out, expired, its
// claims refreshed — re-checks the streams and terminals this hub holds open
// with it, and closes them if it ended (Task 20398). On a cluster member the
// same notice also goes on the bus, and logins and refreshes get the cluster
// hooks described at the top of this file.
func (s *Server) InstallOIDCHooks(cfg *oidcauth.Config) {
	if cfg == nil {
		return
	}
	cfg.OnCacheInvalidate = s.onSessionChanged
	n := s.clusterNode()
	if n == nil {
		return
	}
	cfg.StatePrefix = n.ID()
	cfg.RefreshLock = s.sessionRefreshLock
}

// sessionRefreshLock holds the cluster-wide right to redeem sessionID's
// refresh token until the returned release is called.
func (s *Server) sessionRefreshLock(ctx context.Context, sessionID string) (func(), error) {
	return s.clusterMutex(ctx, ownerSessionRefresh, sessionID)
}

// clusterMutex holds (kind, key) as a cluster-wide mutex until the returned
// release is called, waiting for another member that holds it. A holder that
// dies releases it by dying. Standalone, and on a lock that cannot be read, it
// returns at once: refusing would turn a database hiccup into an outage of
// whatever the lock guards, which is worse than the race it closes.
func (s *Server) clusterMutex(ctx context.Context, kind, key string) (func(), error) {
	n := s.clusterNode()
	if n == nil || key == "" {
		return func() {}, nil
	}
	for {
		_, ok, err := n.Claim(kind, key, nil)
		if err != nil {
			// A lock that cannot be read is not a reason to refuse the
			// refresh: that would turn a database hiccup into a sign-out
			// storm. Proceed as a single process would.
			return func() {}, nil
		}
		if ok {
			return func() { _, _ = n.Release(kind, key) }, nil
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(refreshLockPoll):
		}
	}
}

// evictSessionCache drops sessions another member changed.
func (s *Server) evictSessionCache(sessionHash string, all bool) {
	if s.OIDC == nil {
		return
	}
	if all {
		s.OIDC.EvictAllCachedSessions()
		return
	}
	s.OIDC.EvictCachedSession(sessionHash)
}

// routeOIDCCallback forwards a login callback to the member that began the
// login, and reports whether it did.
func (s *Server) routeOIDCCallback(w http.ResponseWriter, r *http.Request) bool {
	n := s.clusterNode()
	if n == nil {
		return false
	}
	owner := oidcauth.StateOwner(r.URL.Query().Get("state"))
	if owner == "" || owner == n.ID() {
		return false
	}
	m, ok := n.Member(owner)
	if !ok || !m.Alive {
		// The member that began this login is gone, and its nonce and
		// verifier with it. Answering here produces the ordinary "this
		// sign-in attempt has expired" page, which is the truth.
		return false
	}
	return s.forwardTo(w, r, m)
}
