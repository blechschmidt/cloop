package claudeproxy

// policy.go decides whether one relayed request is permitted.
//
// The checks are deliberately few. A proxy in front of a model API can be made
// to enforce almost anything, and almost all of it is enforcement an operator
// cannot verify by reading the rule. What is here is the set that answers
// concrete questions an operator does ask about a CI pipeline: which models
// may it use, how much may one call produce, how many calls may it make, and
// what parts of the API may it reach at all.

import (
	"encoding/json"
	"fmt"
	"path"
	"strings"
)

// DenyReason is a stable machine-readable refusal code. Audit consumers match
// on these; the human-readable message beside them is free to change.
type DenyReason string

const (
	DenyPathNotAllowed  DenyReason = "path_not_allowed"
	DenyMethodNotAllowd DenyReason = "method_not_allowed"
	DenyModelNotAllowed DenyReason = "model_not_allowed"
	DenyBodyTooLarge    DenyReason = "body_too_large"
	DenyBodyMalformed   DenyReason = "body_malformed"
	DenyBudget          DenyReason = "budget_exhausted"
	DenyExpired         DenyReason = "session_expired"
)

// Denial is a refusal with a reason and a message safe to return to the
// pipeline. The message names what is wrong with the request, never what the
// policy would have accepted instead: a caller mapping out an allowlist by
// probing it should learn nothing it did not already know.
type Denial struct {
	Reason  DenyReason
	Message string
	Status  int
}

func (d *Denial) Error() string { return string(d.Reason) + ": " + d.Message }

// Default body and output bounds.
const (
	// DefaultMaxBodyBytes bounds one request. Conversations with large
	// pasted files are legitimately big; 24 MiB is past anything the
	// Messages API will accept anyway, so this is a memory guard rather
	// than a policy.
	DefaultMaxBodyBytes int64 = 24 << 20

	// DefaultMaxOutputTokens clamps max_tokens when a policy sets none.
	// Generous enough for an agent turn, finite enough that a runaway loop
	// is bounded per call.
	DefaultMaxOutputTokens = 32000
)

// allowedPaths is the API surface a CI session may reach, relative to the
// proxy mount point.
//
// It is an allowlist because the Anthropic API is larger than the Messages
// API, and the rest of it is either billing-visible state that outlives the
// job (batches, files) or account administration. A pipeline that has been
// lent the ability to ask a model a question has not been lent the ability to
// enumerate the workspace that pays for it.
var allowedPaths = []struct {
	pattern string
	methods string
}{
	{"/v1/messages", "POST"},
	{"/v1/messages/count_tokens", "POST"},
	{"/v1/models", "GET"},
	{"/v1/models/*", "GET"},
}

// Policy is what one CI session may do.
type Policy struct {
	// Models is a glob allowlist of model IDs. Empty denies everything: the
	// caller resolves "unset" to the hub default before minting.
	Models []string

	// MaxOutputTokens clamps `max_tokens` on every request. Zero uses
	// DefaultMaxOutputTokens.
	MaxOutputTokens int

	// MaxRequests caps the session's lifetime request count. Zero means
	// unlimited, which the minting path does not produce.
	MaxRequests int

	// MaxBodyBytes bounds one request body. Zero uses DefaultMaxBodyBytes.
	MaxBodyBytes int64
}

// OutputCap returns the effective max_tokens ceiling.
func (p Policy) OutputCap() int {
	if p.MaxOutputTokens <= 0 {
		return DefaultMaxOutputTokens
	}
	return p.MaxOutputTokens
}

// BodyCap returns the effective request body limit.
func (p Policy) BodyCap() int64 {
	if p.MaxBodyBytes <= 0 {
		return DefaultMaxBodyBytes
	}
	return p.MaxBodyBytes
}

// AllowsModel reports whether a model ID is in the allowlist.
func (p Policy) AllowsModel(model string) bool {
	if model == "" {
		return false
	}
	for _, pat := range p.Models {
		if ok, err := path.Match(pat, model); err == nil && ok {
			return true
		}
	}
	return false
}

// AllowsPath reports whether method and path are in the API surface, and
// returns a denial explaining which of the two failed.
//
// Path and method are separated because they fail for different reasons and
// an operator reading the audit trail wants to know which: an unknown path is
// usually an SDK reaching for a feature the policy does not cover, while a
// wrong method on a known path is usually a client bug.
func AllowsPath(method, p string) *Denial {
	// Normalised here as well as in Proxy.apiPath. AllowsPath is exported and
	// a future caller may hand it a raw path; for the relay this is
	// idempotent, and a check that depends on its caller having remembered to
	// clean is a check that eventually will not have been.
	clean := path.Clean("/" + strings.TrimPrefix(p, "/"))
	var pathKnown bool
	for _, a := range allowedPaths {
		ok, err := path.Match(a.pattern, clean)
		if err != nil || !ok {
			continue
		}
		pathKnown = true
		if a.methods == method {
			return nil
		}
	}
	if pathKnown {
		return &Denial{Reason: DenyMethodNotAllowd, Status: 405,
			Message: fmt.Sprintf("%s is not permitted on %s", method, clean)}
	}
	return &Denial{Reason: DenyPathNotAllowed, Status: 404,
		Message: fmt.Sprintf("%s is not part of the API surface this session may reach", clean)}
}

// MessageRequest is the handful of fields the policy reads out of a Messages
// API request. Everything else is passed through untouched.
type MessageRequest struct {
	Model     string `json:"model"`
	MaxTokens *int   `json:"max_tokens,omitempty"`
	Stream    bool   `json:"stream,omitempty"`
}

// InspectBody decodes the policy-relevant fields of a request body.
//
// It decodes into a struct with three fields rather than into a map, so a body
// carrying a 10 MB conversation is not materialised twice just to read the
// model name.
func InspectBody(body []byte) (MessageRequest, error) {
	var m MessageRequest
	if err := json.Unmarshal(body, &m); err != nil {
		return m, err
	}
	return m, nil
}

// DecideMessages applies the policy to a Messages API request and returns the
// body to forward.
//
// The returned body differs from the input only when max_tokens had to be
// clamped. Rewriting rather than refusing is deliberate: a client that asked
// for more output than the policy allows is not misbehaving, it is using a
// default, and failing the request would make every stock SDK configuration
// unusable behind a policy that sets any cap at all.
func (p Policy) DecideMessages(body []byte) ([]byte, MessageRequest, *Denial) {
	req, err := InspectBody(body)
	if err != nil {
		return nil, req, &Denial{Reason: DenyBodyMalformed, Status: 400,
			Message: "request body is not valid JSON"}
	}
	if req.Model == "" {
		return nil, req, &Denial{Reason: DenyBodyMalformed, Status: 400,
			Message: "request body names no model"}
	}
	if !p.AllowsModel(req.Model) {
		return nil, req, &Denial{Reason: DenyModelNotAllowed, Status: 403,
			Message: fmt.Sprintf("model %q is not permitted for this pipeline", req.Model)}
	}
	cap := p.OutputCap()
	if req.MaxTokens == nil || *req.MaxTokens <= cap {
		return body, req, nil
	}
	clamped, err := clampMaxTokens(body, cap)
	if err != nil {
		return nil, req, &Denial{Reason: DenyBodyMalformed, Status: 400,
			Message: "request body could not be rewritten"}
	}
	v := cap
	req.MaxTokens = &v
	return clamped, req, nil
}

// clampMaxTokens rewrites just the max_tokens field.
//
// The body is decoded into a map and re-encoded, which reorders keys and
// drops nothing — JSON object order is not significant and the Messages API
// does not depend on it. The alternative, a textual splice, would have to
// parse JSON anyway to find the field safely.
func clampMaxTokens(body []byte, cap int) ([]byte, error) {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(body, &m); err != nil {
		return nil, err
	}
	raw, err := json.Marshal(cap)
	if err != nil {
		return nil, err
	}
	m["max_tokens"] = raw
	return json.Marshal(m)
}
