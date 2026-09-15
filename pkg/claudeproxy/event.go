package claudeproxy

import "time"

// Event is one thing the proxy decided, for the audit trail.
//
// Events carry identifiers, model names, reasons and counts. They never carry
// a prompt, a completion, a session token or the upstream credential: an audit
// log that contains the conversation is a second copy of the data the proxy
// was built to avoid reading.
type Event struct {
	Kind      EventKind `json:"kind"`
	SessionID string    `json:"session_id,omitempty"`

	// Which rule admitted this pipeline, and which pipeline it was.
	RuleID     string `json:"rule_id,omitempty"`
	RuleName   string `json:"rule_name,omitempty"`
	Project    string `json:"project,omitempty"`
	Subject    string `json:"subject,omitempty"`
	Repository string `json:"repository,omitempty"`
	Ref        string `json:"ref,omitempty"`
	Workflow   string `json:"workflow,omitempty"`
	Actor      string `json:"actor,omitempty"`
	RunID      string `json:"run_id,omitempty"`

	// Request shape, for allowed and denied relays.
	Method string `json:"method,omitempty"`
	Path   string `json:"path,omitempty"`
	Model  string `json:"model,omitempty"`
	Status int    `json:"status,omitempty"`

	// Reason is set on a refusal.
	Reason DenyReason `json:"reason,omitempty"`

	// Spend attributable to this event.
	InputTokens  int64 `json:"input_tokens,omitempty"`
	OutputTokens int64 `json:"output_tokens,omitempty"`

	Detail string    `json:"detail,omitempty"`
	At     time.Time `json:"at"`
}

// EventKind names what happened.
type EventKind string

const (
	// EventExchangeAccepted / EventExchangeRejected record the OIDC
	// federation step: a pipeline presented a token and either received a
	// session or did not. Both are emitted by the hub rather than by the
	// proxy, because that exchange happens before a session exists.
	EventExchangeAccepted EventKind = "ci.exchange.accepted"
	EventExchangeRejected EventKind = "ci.exchange.rejected"

	// EventSessionMinted / EventSessionClosed bracket a session's life.
	EventSessionMinted EventKind = "ci.session.minted"
	EventSessionClosed EventKind = "ci.session.closed"

	// EventRelayAllowed is one forwarded request. It carries the token counts
	// the upstream reported, which is what makes per-pipeline spend
	// answerable.
	EventRelayAllowed EventKind = "ci.relay.allowed"

	// EventRelayDenied is one request the policy refused. The upstream never
	// saw it and the hub's credential was never attached.
	EventRelayDenied EventKind = "ci.relay.denied"

	// EventRejected is a request that never reached a session: an
	// unparseable, unknown, expired or revoked token.
	EventRejected EventKind = "ci.rejected"
)
