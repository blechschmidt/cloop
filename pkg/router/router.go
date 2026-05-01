// Package router maps task roles to specific AI providers.
// This enables heterogeneous multi-agent execution where different task types
// (backend, frontend, security, etc.) are handled by the most suitable model.
package router

import (
	"fmt"
	"strings"

	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/provider"
)

// Router routes tasks to specific providers based on their role.
// When no route is configured for a role, the default provider is used.
type Router struct {
	// routes maps AgentRole (string) to a built provider.
	routes map[string]provider.Provider
	// default_ is used when no role-specific route matches.
	default_ provider.Provider
}

// New creates a Router with the given default provider.
func New(defaultProvider provider.Provider) *Router {
	return &Router{
		routes:   make(map[string]provider.Provider),
		default_: defaultProvider,
	}
}

// Register binds a role to a provider.
func (r *Router) Register(role pm.AgentRole, prov provider.Provider) {
	r.routes[strings.ToLower(string(role))] = prov
}

// For returns the provider for a given task role.
// Falls back to the default provider if no route is registered for that role.
func (r *Router) For(role pm.AgentRole) provider.Provider {
	if role == "" {
		return r.default_
	}
	if prov, ok := r.routes[strings.ToLower(string(role))]; ok {
		return prov
	}
	return r.default_
}

// Default returns the default provider.
func (r *Router) Default() provider.Provider {
	return r.default_
}

// Routes returns a copy of the role→provider name mapping for display.
func (r *Router) Routes() map[string]string {
	out := make(map[string]string, len(r.routes))
	for role, prov := range r.routes {
		out[role] = prov.Name()
	}
	return out
}

// Summary returns a human-readable description of the routing table.
func (r *Router) Summary() string {
	if len(r.routes) == 0 {
		return fmt.Sprintf("all roles → %s (no role-specific routing configured)", r.default_.Name())
	}
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("default → %s\n", r.default_.Name()))
	for role, prov := range r.routes {
		sb.WriteString(fmt.Sprintf("  %-12s → %s\n", role, prov.Name()))
	}
	return strings.TrimRight(sb.String(), "\n")
}
