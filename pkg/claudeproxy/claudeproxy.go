// Package claudeproxy relays a CI/CD pipeline's Anthropic API calls through
// the hub, so the pipeline can run an agent harness without ever holding the
// hub's Claude credential.
//
// # The shape of the bargain
//
// A pipeline that has federated its OIDC identity (see pkg/ciauth) receives a
// session token and a base URL. It exports them as ANTHROPIC_BASE_URL and
// ANTHROPIC_AUTH_TOKEN and runs Claude Code, or any Anthropic SDK, unchanged:
// both send their requests to the base URL and their credential in the
// Authorization header, and both are satisfied by a server that answers the
// Messages API. Nothing in the runner knows it is not talking to Anthropic.
//
// What it is actually talking to is a monitor. The session token is worth only
// what its policy says — these models, this many requests, this long — and it
// stops being worth anything the moment the hub closes the session. The real
// credential never leaves the hub process.
//
// This is the same construction pkg/gitproxy applies to a GitHub token and
// pkg/kubeguard applies to a kubeconfig: take custody of the credential, give
// out something narrower that points at a thing that reads every request, and
// make the audit trail a record of decisions rather than of deliveries.
//
// # What it deliberately does not do
//
// It does not inspect or rewrite prompts, and it does not cache responses. A
// proxy that reads the conversation is a proxy an operator must reason about
// as a data processor; this one moves bytes and decides whether it should.
// The exception is `max_tokens`, which is clamped because it is the one field
// that bounds spend, and the model name, which is checked because it is the
// one field that selects it.
package claudeproxy

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"
)

// TokenPrefix identifies a CI session token.
//
// The prefix is load-bearing, exactly as it is for pkg/apitoken: it is what
// lets a secret scanner recognise one of these in a log or a commit, and what
// lets the authentication path tell a session token apart from an Anthropic
// key a confused pipeline sent instead.
const TokenPrefix = "cloop_ci_"

// DefaultUpstream is the Anthropic API base. The proxy appends the path the
// client asked for, so this is the origin plus nothing.
const DefaultUpstream = "https://api.anthropic.com"

// Errors the hub distinguishes.
var (
	// ErrUnauthenticated covers every reason a presented token is not usable:
	// malformed, unknown, expired, closed. They are one error on purpose —
	// a caller probing for a valid session learns nothing from the
	// difference — while the audit trail records which it was.
	ErrUnauthenticated = errors.New("claudeproxy: session token not accepted")

	// ErrSessionNotFound is returned by management calls, not by
	// authentication.
	ErrSessionNotFound = errors.New("claudeproxy: no such session")

	// ErrBudgetExhausted means the session's request budget is spent.
	ErrBudgetExhausted = errors.New("claudeproxy: session request budget exhausted")

	// ErrNoUpstream means no Anthropic credential is configured, so there is
	// nothing to relay to.
	ErrNoUpstream = errors.New("claudeproxy: no upstream Anthropic credential is configured")
)

// Upstream is the credential the hub holds and the endpoint it relays to.
//
// Exactly one of APIKey or AuthToken must be set. The two are different
// things at the API: an API key is a workspace credential presented in
// x-api-key, an auth token is an OAuth bearer. Guessing from the shape of the
// string would be a guess about billing, so the caller says which it has.
type Upstream struct {
	// BaseURL is the API origin. Empty uses DefaultUpstream.
	BaseURL string

	// APIKey is sent as x-api-key.
	APIKey string

	// AuthToken is sent as Authorization: Bearer.
	AuthToken string
}

// Configured reports whether there is a credential to relay with.
func (u Upstream) Configured() bool {
	return strings.TrimSpace(u.APIKey) != "" || strings.TrimSpace(u.AuthToken) != ""
}

// Validate checks the upstream is usable.
func (u Upstream) Validate() error {
	if !u.Configured() {
		return ErrNoUpstream
	}
	if strings.TrimSpace(u.APIKey) != "" && strings.TrimSpace(u.AuthToken) != "" {
		return errors.New("claudeproxy: set exactly one of APIKey and AuthToken")
	}
	base := u.Base()
	parsed, err := url.Parse(base)
	if err != nil || parsed.Host == "" {
		return fmt.Errorf("claudeproxy: upstream %q is not a URL", base)
	}
	if parsed.Scheme != "https" && !isLoopback(parsed.Hostname()) {
		// A plaintext upstream would put the hub's credential on the wire.
		// Loopback is exempt so tests and local gateways work.
		return fmt.Errorf("claudeproxy: upstream %q must use https", base)
	}
	if strings.Trim(parsed.Path, "/") != "" {
		// The client chooses the path; a base with one would produce
		// /v1/v1/messages and a 404 that blames the client.
		return fmt.Errorf("claudeproxy: upstream %q must have no path", base)
	}
	return nil
}

// Base returns the upstream origin with no trailing slash.
func (u Upstream) Base() string {
	b := strings.TrimSpace(u.BaseURL)
	if b == "" {
		return DefaultUpstream
	}
	return strings.TrimSuffix(b, "/")
}

// Redacted describes the upstream without revealing the credential, for logs
// and for the dashboard.
func (u Upstream) Redacted() string {
	switch {
	case !u.Configured():
		return "none"
	case strings.TrimSpace(u.APIKey) != "":
		return u.Base() + " (api key)"
	default:
		return u.Base() + " (oauth token)"
	}
}

// Usage is what a session spent. Every field is cumulative for the session's
// lifetime.
type Usage struct {
	Requests     int64 `json:"requests"`
	Denied       int64 `json:"denied"`
	InputTokens  int64 `json:"input_tokens"`
	OutputTokens int64 `json:"output_tokens"`
	CacheRead    int64 `json:"cache_read_input_tokens,omitempty"`
	CacheWrite   int64 `json:"cache_creation_input_tokens,omitempty"`
	BytesUp      int64 `json:"bytes_up"`
	BytesDown    int64 `json:"bytes_down"`
}

// TotalTokens is the sum a spend report cares about.
func (u Usage) TotalTokens() int64 {
	return u.InputTokens + u.OutputTokens + u.CacheRead + u.CacheWrite
}

func isLoopback(host string) bool {
	return host == "localhost" || strings.HasPrefix(host, "127.") || host == "::1"
}

// clampDuration is a small shared helper for the TTL arithmetic the registry
// and the policy both do.
func clampDuration(d, min, max time.Duration) time.Duration {
	if d < min {
		return min
	}
	if d > max {
		return max
	}
	return d
}
