package hubclient

// The approvals inbox's calls (Task 20427): what waits on the caller — grant
// requests they may decide, API tokens they may approve — and the decisions
// themselves, made through the same routes the dashboard's dialogs use. The
// hub decides what the caller may see and do; nothing here filters.

import (
	"context"
	"net/http"
	"net/url"
)

// WaitingToken is an API token waiting for an administrator's approval:
// never its hash, never its secret.
type WaitingToken struct {
	ID        string   `json:"id"`
	Name      string   `json:"name"`
	Prefix    string   `json:"prefix"`
	Roles     []string `json:"roles"`
	CreatedBy string   `json:"created_by,omitempty"`
	CreatedAt string   `json:"created_at,omitempty"`
}

// ApprovalItem is one thing waiting on the caller.
type ApprovalItem struct {
	// Kind is grant_request or api_token.
	Kind string `json:"kind"`
	ID   string `json:"id"`
	// Deadline is when the item stops being decidable, RFC 3339; empty for a
	// token that never expires.
	Deadline          string        `json:"deadline,omitempty"`
	DeadlineInSeconds int64         `json:"deadline_in_seconds,omitempty"`
	Request           *GrantRequest `json:"request,omitempty"`
	Token             *WaitingToken `json:"token,omitempty"`
}

// Approvals is GET /api/approvals.
type Approvals struct {
	Items         []ApprovalItem `json:"items"`
	Count         int            `json:"count"`
	GrantRequests int            `json:"grant_requests"`
	APITokens     int            `json:"api_tokens"`
	NextDeadline  string         `json:"next_deadline,omitempty"`
	// Mine is the caller's own requests: pending, and those settled in the
	// last week.
	Mine  []GrantRequest `json:"mine"`
	Actor string         `json:"actor,omitempty"`
}

// Approvals lists what waits on the caller.
func (c *Client) Approvals(ctx context.Context) (*Approvals, error) {
	var out Approvals
	if err := c.Do(ctx, http.MethodGet, "/api/approvals", nil, nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// DecidedRequest is the answer to an approval or a denial.
type DecidedRequest struct {
	Request GrantRequest `json:"request"`
	// GrantID is the grant an approval minted, and Note what the hub says
	// about when it takes effect.
	GrantID string `json:"grant_id,omitempty"`
	Note    string `json:"note,omitempty"`
}

// ApproveGrantRequest mints the grant a request asked for. ttlMinutes, when
// positive, shortens it — it can only narrow.
func (c *Client) ApproveGrantRequest(ctx context.Context, id, note string, ttlMinutes int) (DecidedRequest, error) {
	return c.decideGrantRequest(ctx, id, "approve", note, ttlMinutes)
}

// DenyGrantRequest refuses a request; note, the reason, is required.
func (c *Client) DenyGrantRequest(ctx context.Context, id, note string) (DecidedRequest, error) {
	return c.decideGrantRequest(ctx, id, "deny", note, 0)
}

func (c *Client) decideGrantRequest(ctx context.Context, id, action, note string, ttlMinutes int) (DecidedRequest, error) {
	body := map[string]any{"note": note}
	if ttlMinutes > 0 {
		body["ttl_minutes"] = ttlMinutes
	}
	var out DecidedRequest
	err := c.Do(ctx, http.MethodPost, "/api/grant-requests/"+url.PathEscape(id)+"/"+action, nil, body, &out)
	return out, err
}

// ApproveToken approves an API token minted with no role policy in force.
func (c *Client) ApproveToken(ctx context.Context, id string) error {
	return c.Do(ctx, http.MethodPost, "/api/tokens/"+url.PathEscape(id)+"/approve", nil, map[string]any{}, nil)
}
