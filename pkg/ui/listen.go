package ui

// listen.go: where Run binds (Task 20393).
//
// `cloop ui` decides the address before it joins the control plane, so a
// refusal leaves no trace there; Run decides it again from what the Server
// actually holds. The two agree because both ask pkg/exposure, and the second
// asking is what keeps a Server constructed some other way — a test, an
// embedding program — from binding more widely than its authentication allows.

import (
	"net"
	"strings"

	"github.com/blechschmidt/cloop/pkg/exposure"
)

// listenPlan is where this server listens, or the refusal of an address a hub
// without sign-in may not bind.
func (s *Server) listenPlan() (exposure.Plan, error) {
	// The URL browsers reach this hub at, as config.UIConfig.PublicURL reads
	// it: the external URL, else the SSO callback.
	public, key := strings.TrimSpace(s.ExternalURL), "ui.external_url"
	if public == "" && s.oidcEnabled() {
		public, key = s.OIDC.RedirectURL(), "ui.oidc.redirect_url"
	}
	return exposure.Decide(exposure.Request{
		Listen:                      s.ListenHost,
		Port:                        s.Port,
		SSO:                         s.oidcEnabled(),
		StaticToken:                 s.Token != "",
		AllowUnauthenticatedNetwork: s.AllowUnauthenticatedNetwork,
		TLS:                         s.TLSEnabled(),
		ExternalURL:                 public,
		ExternalURLKey:              key,
	})
}

// BoundAddr is the address Run's listener holds, or nil before it has bound
// and after a refused start.
func (s *Server) BoundAddr() net.Addr {
	s.shutdownMu.Lock()
	defer s.shutdownMu.Unlock()
	return s.boundAddr
}
