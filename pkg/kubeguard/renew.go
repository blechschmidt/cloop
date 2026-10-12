package kubeguard

// renew.go lets a live session spend a renewed credential (Task 20416).
//
// A session holds the cluster credential it was minted from for as long as it
// lives, and a run's session can outlive the token behind it: a Kubernetes
// share's ServiceAccount token is minted for a bounded time, often capped by
// the managed API server, and the hub renews it in the secret before it
// expires. Without this the session would keep presenting the old token until
// the cluster refused it — the mid-run expiry the renewal exists to prevent.
//
// What may change is the credential and nothing else. The server the session
// is pinned to, and the TLS material its connection pool was built with, are
// part of what the session is; a kubeconfig that changed those is not a
// renewal but a different grant, and is refused.

import (
	"bytes"
	"crypto/subtle"
	"errors"
	"fmt"
	"strings"

	"github.com/blechschmidt/cloop/pkg/executor/kubernetes"
)

// ErrNoSuchSession is UpdateUpstream naming a session this registry does not
// hold.
var ErrNoSuchSession = errors.New("kubeguard: no such session")

// UpdateUpstream re-reads the session's context from kubeconfig and, when only
// its credential changed, makes that the credential the session presents from
// the next request on. It reports whether the credential changed.
func (r *Registry) UpdateUpstream(id string, kubeconfig []byte) (bool, error) {
	r.mu.RLock()
	s := r.sessions[strings.TrimSpace(id)]
	r.mu.RUnlock()
	if s == nil {
		return false, ErrNoSuchSession
	}
	if s.Closed() {
		return false, ErrSessionClosed
	}
	rc, err := kubernetes.ParseKubeconfig(kubeconfig, s.ContextName)
	if err != nil {
		return false, fmt.Errorf("kubeguard: renew session %s: %w", s.ID, err)
	}
	cur := s.upstream.Load()
	if cur == nil {
		return false, fmt.Errorf("kubeguard: renew session %s: it has no credential to replace", s.ID)
	}
	if why := sameEndpoint(cur, rc); why != "" {
		return false, fmt.Errorf("kubeguard: renew session %s: refused, %s; a renewal replaces a credential "+
			"and nothing else", s.ID, why)
	}
	if sameCredential(cur, rc) {
		return false, nil
	}
	// Should another renewal have swapped it in between, whichever landed
	// last is a current credential either way.
	s.upstream.CompareAndSwap(cur, rc)
	return true, nil
}

// sameEndpoint reports how b differs from a in anything but the credential, or
// "" when it does not.
func sameEndpoint(a, b *kubernetes.RESTConfig) string {
	switch {
	case !strings.EqualFold(strings.TrimSuffix(a.Server, "/"), strings.TrimSuffix(b.Server, "/")):
		return fmt.Sprintf("the kubeconfig now names %s, not %s the session is pinned to", b.Server, a.Server)
	case !bytes.Equal(a.CAData, b.CAData), a.ServerName != b.ServerName, a.Insecure != b.Insecure:
		return "the cluster's TLS trust changed"
	case a.ProxyURL != b.ProxyURL:
		return "the cluster's proxy changed"
	case !bytes.Equal(a.ClientCertData, b.ClientCertData) || !bytes.Equal(a.ClientKeyData, b.ClientKeyData):
		// A client certificate is presented by the connection pool the proxy
		// built for the session, so swapping it here would not take effect.
		return "its client certificate changed"
	}
	return ""
}

// sameCredential compares two bearer credentials in constant time.
func sameCredential(a, b *kubernetes.RESTConfig) bool {
	return subtle.ConstantTimeCompare([]byte(a.BearerToken), []byte(b.BearerToken)) == 1
}
