package ui

// cluster_proxies.go: the git proxy, the Kubernetes monitor and the CI relay
// when several hub processes serve one control plane (Task 20354).
//
// Each keeps its sessions in the memory of the process that minted them, and
// deliberately: a session holds a live forge, cluster or model credential, and
// putting it in the database would be that credential at rest in a second
// place. What goes in the database instead is only *which process* holds each
// session, so a sandbox's request that reaches another process — through a
// load balancer in front of all of them — is forwarded to the one that can
// authenticate it. The session id rides in every credential, so the process
// that has never heard of it can look it up without learning the secret.

import (
	"net/http"
	"strings"

	"github.com/blechschmidt/cloop/pkg/claudeproxy"
	"github.com/blechschmidt/cloop/pkg/gitproxy"
	"github.com/blechschmidt/cloop/pkg/kubeguard"
)

// Ownership kinds for proxy sessions. Key: the session id.
const (
	ownerGitProxy  = "gitproxy"
	ownerKubeGuard = "kubeguard"
	ownerCISession = "cisession"
)

// Internal paths a forwarded proxy request is served under on its owner.
const (
	clusterAPIProxyGit  = clusterAPIPrefix + "proxy/git"
	clusterAPIProxyKube = clusterAPIPrefix + "proxy/kube"
)

// proxySessionEvent extracts (session id, minted, closed) from a proxy event.
type proxySessionEvent[E any] func(E) (id string, minted, closed bool)

// A restored session is claimed as a minted one is: it is served here from
// now on (Task 20383).
func gitProxySessionEvent(ev gitproxy.Event) (string, bool, bool) {
	served := ev.Kind == gitproxy.EventSessionMinted || ev.Kind == gitproxy.EventSessionRestored
	return ev.SessionID, served, ev.Kind == gitproxy.EventSessionClosed
}

func kubeGuardSessionEvent(ev kubeguard.Event) (string, bool, bool) {
	served := ev.Kind == kubeguard.EventSessionMinted || ev.Kind == kubeguard.EventSessionRestored
	return ev.SessionID, served, ev.Kind == kubeguard.EventSessionClosed
}

// A restored session is claimed as a minted one is, and a suspended one is
// released as a closed one is: the process that restores it claims it then
// (Task 20390).
func ciSessionEvent(ev claudeproxy.Event) (string, bool, bool) {
	served := ev.Kind == claudeproxy.EventSessionMinted || ev.Kind == claudeproxy.EventSessionRestored
	ended := ev.Kind == claudeproxy.EventSessionClosed || ev.Kind == claudeproxy.EventSessionSuspended
	return ev.SessionID, served, ended
}

// withProxySessionOwnership records each minted session as owned by this
// process and releases it when the session ends, then passes the event on.
func withProxySessionOwnership[E any](kind string, parse proxySessionEvent[E], inner func(E)) func(E) {
	return func(ev E) {
		if n := currentCluster(); n != nil {
			if id, minted, closed := parse(ev); id != "" {
				switch {
				case minted:
					_ = n.Assert(kind, id, nil)
				case closed:
					_, _ = n.Release(kind, id)
				}
			}
		}
		if inner != nil {
			inner(ev)
		}
	}
}

// releaseSuspendedSessions gives up this process's claim on sessions it
// suspended (Task 20383), so a member a request for one reaches does not
// forward it here: the process that restores a session claims it then.
// Release is conditional on this member holding the claim, so one a restoring
// process already took is left alone.
func releaseSuspendedSessions(kind string, ids []string) {
	n := currentCluster()
	if n == nil {
		return
	}
	for _, id := range ids {
		if _, err := n.Release(kind, id); err != nil {
			clusterLogf("release the claim on suspended %s session %s: %v", kind, id, err)
		}
	}
}

// clusterProxyFallback forwards a request naming a session this process does
// not hold to the live member that does, under internalPath on that member's
// hub listener — the proxy's own listener may not be reachable from other
// members at all (it defaults to loopback).
//
// When no live member claims the session, a request presenting a recorded
// session whose holder stopped waits for the process adopting its run to
// restore it (session_hold.go, Task 20383). False, and the request is refused
// here as unauthenticated, when neither happens.
func clusterProxyFallback(kind, internalPath string) func(http.ResponseWriter, *http.Request, string) bool {
	return func(w http.ResponseWriter, r *http.Request, sessionID string) bool {
		if forwardProxyRequest(w, r, kind, internalPath, sessionID) {
			return true
		}
		return proxySessionHold(w, r, kind, internalPath, sessionID)
	}
}

// forwardProxyRequest forwards r to the live member claiming the session, and
// reports whether there was one.
func forwardProxyRequest(w http.ResponseWriter, r *http.Request, kind, internalPath, sessionID string) bool {
	n := currentCluster()
	if n == nil {
		return false
	}
	o, found, err := n.Lookup(kind, sessionID)
	if err != nil || !found || o.Self || !o.Alive {
		return false
	}
	fwd := r.Clone(r.Context())
	fwd.URL.Path = internalPath + r.URL.Path
	fwd.URL.RawPath = ""
	if err := n.Forward(w, fwd, o.Member, remoteAddrIP(r)); err != nil {
		clusterLogf("forward %s session %s to member %s: %v", kind, sessionID, o.InstanceID, err)
	}
	return true
}

// ciRelayFallback forwards a CI relay call to the member that serves its
// session. The relay is served on the hub's own listener, so the path is
// forwarded unchanged. When no live member serves it, a recorded session
// whose holder stopped is restored here (Task 20390, ci_sessions.go); the
// relay then decides the request against this member's registry.
func (s *Server) ciRelayFallback(w http.ResponseWriter, r *http.Request, svc *ciService, sessionID string) bool {
	if _, forwarded := peerCallFrom(r); forwarded {
		return false
	}
	if n := s.clusterNode(); n != nil {
		if o, found, err := n.Lookup(ownerCISession, sessionID); err == nil && found && !o.Self && o.Alive {
			return s.forwardTo(w, r, o.Member)
		}
	}
	return s.restoreCISessionOnDemand(w, r, svc, sessionID)
}

// serveForwardedProxy answers a proxy request another member forwarded here:
// the prefix is stripped and the local proxy decides it as if the sandbox had
// reached it directly.
func (s *Server) serveForwardedProxy(w http.ResponseWriter, r *http.Request) bool {
	var (
		prefix  string
		handler http.Handler
	)
	switch {
	case strings.HasPrefix(r.URL.Path, clusterAPIProxyGit+"/"):
		prefix = clusterAPIProxyGit
		if svc := activeGitProxy(); svc != nil && svc.proxy != nil {
			handler = svc.proxy
		}
	case strings.HasPrefix(r.URL.Path, clusterAPIProxyKube+"/"):
		prefix = clusterAPIProxyKube
		if svc := activeKubeGuard(); svc != nil && svc.proxy != nil {
			handler = svc.proxy
		}
	default:
		return false
	}
	if handler == nil {
		jsonErr(w, "this hub member runs no such proxy", http.StatusNotFound)
		return true
	}
	local := r.Clone(r.Context())
	local.URL.Path = strings.TrimPrefix(r.URL.Path, prefix)
	local.URL.RawPath = ""
	handler.ServeHTTP(w, local)
	return true
}

// remoteAddrIP is the host part of r.RemoteAddr.
func remoteAddrIP(r *http.Request) string {
	host := r.RemoteAddr
	if i := strings.LastIndexByte(host, ':'); i > 0 {
		host = host[:i]
	}
	return strings.Trim(host, "[]")
}
