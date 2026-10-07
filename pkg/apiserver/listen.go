package apiserver

// listen.go: where `cloop serve` binds (Task 20393).
//
// The rule is the dashboard's (pkg/exposure): without a credential the server
// listens on 127.0.0.1, and an address beyond loopback needs the
// acknowledgement. Its credential is the bearer token alone — there is no SSO
// here — so the words differ, and they are this file's.

import (
	"errors"
	"fmt"
	"net"

	"github.com/blechschmidt/cloop/pkg/exposure"
)

// listenPlan is where Run binds, or the refusal of an address a server
// without a token may not bind.
func (s *Server) listenPlan() (exposure.Plan, error) {
	plan, err := exposure.Decide(exposure.Request{
		Listen:                      s.ListenHost,
		Source:                      "--listen",
		Port:                        s.Port,
		StaticToken:                 s.Token != "",
		AllowUnauthenticatedNetwork: s.AllowUnauthenticatedNetwork,
	})
	var refused *exposure.RefusalError
	if errors.As(err, &refused) {
		return exposure.Plan{}, &refusal{text: fmt.Sprintf("refusing to listen on %s (--listen): cloop serve has "+
			"no token — no --token or CLOOP_API_TOKEN is set — so anyone who can reach that address could start "+
			"runs on this host and edit its plan.\n"+
			"  Set a token, or drop --listen to keep it on this machine: without a token it listens on %s.\n"+
			"  To serve it without a token anyway, set %s: true in .cloop/config.yaml.",
			refused.Plan, exposure.LoopbackHost, exposure.AckKey)}
	}
	return plan, err
}

// refusal is this server's wording of exposure's refusal. It unwraps to
// exposure.ErrOpenToNetwork, as the dashboard's does.
type refusal struct{ text string }

func (r *refusal) Error() string { return r.text }
func (r *refusal) Unwrap() error { return exposure.ErrOpenToNetwork }

// listenNotice is what a starting server prints about its exposure, or "".
// warning reports that it goes to stderr: no token, and beyond loopback.
func listenNotice(p exposure.Plan) (text string, warning bool) {
	switch {
	case p.Open() && p.BeyondLoopback():
		return fmt.Sprintf("WARNING: cloop serve has no token and listens on %s because %s is set: anyone who "+
			"can reach that address can start runs on this host. Set --token (or CLOOP_API_TOKEN), or listen on %s.",
			p, exposure.AckKey, exposure.LoopbackHost), true
	case p.Open() && !p.Explicit:
		return fmt.Sprintf("No token is configured, so the API server listens on %s only. Set --token (or "+
			"CLOOP_API_TOKEN) to serve it on every interface.", p), false
	}
	return "", false
}

// BoundAddr is the address Run's listener holds, or nil before it has bound
// and after a refused start.
func (s *Server) BoundAddr() net.Addr {
	s.shutdownMu.Lock()
	defer s.shutdownMu.Unlock()
	return s.boundAddr
}
