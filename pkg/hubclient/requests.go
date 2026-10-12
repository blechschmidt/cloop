package hubclient

// The Access Requests panel's calls (Task 20417): asking for a credential the
// caller cannot grant themselves, listing those asks, and taking one back.
// Asking confers nothing — an approver with secret.grant decides — so these
// sit at secret.request, an operator's permission.

import (
	"context"
	"net/http"
	"net/url"
	"time"
)

// GrantRequest is one request as the hub shows it to the caller.
type GrantRequest struct {
	ID             string    `json:"id"`
	RequestedBy    string    `json:"requested_by"`
	SecretID       string    `json:"secret_id"`
	SecretName     string    `json:"secret_name,omitempty"`
	Kind           string    `json:"kind,omitempty"`
	Subject        string    `json:"subject"`
	Constraints    string    `json:"constraints,omitempty"`
	Scope          string    `json:"scope,omitempty"`
	TTLMinutes     int       `json:"ttl_minutes"`
	Justification  string    `json:"justification"`
	State          string    `json:"state"`
	CreatedAt      time.Time `json:"created_at"`
	ExpiresAt      time.Time `json:"expires_at,omitempty"`
	DecidedBy      string    `json:"decided_by,omitempty"`
	DecidedAt      time.Time `json:"decided_at,omitempty"`
	DecisionNote   string    `json:"decision_note,omitempty"`
	GrantID        string    `json:"grant_id,omitempty"`
	GrantExpiresAt time.Time `json:"grant_expires_at,omitempty"`
	Mine           bool      `json:"mine"`
	Decidable      bool      `json:"decidable"`
	// Approvers says who may approve a pending request: the accounts and
	// groups the hub's policy gives secret.grant, other than the requester.
	// A hub older than Task 20417 does not say.
	Approvers []string `json:"approvers,omitempty"`
}

// GrantRequestList is GET /api/grant-requests.
type GrantRequestList struct {
	Requests     []GrantRequest `json:"requests"`
	PendingCount int            `json:"pending_count"`
	CanDecide    bool           `json:"can_decide"`
	Actor        string         `json:"actor"`
}

// GrantRequests lists requests: the caller's own, or — for a caller who may
// decide them — everyone's unless mine is set. state narrows to one state.
func (c *Client) GrantRequests(ctx context.Context, state string, mine bool) (*GrantRequestList, error) {
	q := url.Values{}
	if state != "" {
		q.Set("state", state)
	}
	if mine {
		q.Set("mine", "1")
	}
	var out GrantRequestList
	if err := c.Do(ctx, http.MethodGet, "/api/grant-requests", q, nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// FileGrantRequest is the POST /api/grant-requests body.
type FileGrantRequest struct {
	SecretRef     string   `json:"secret_ref"`
	Subject       string   `json:"subject"`
	Scope         string   `json:"scope,omitempty"`
	TTLMinutes    int      `json:"ttl_minutes"`
	WaitMinutes   int      `json:"wait_minutes,omitempty"`
	Justification string   `json:"justification"`
	Repos         []string `json:"repos,omitempty"`
	Permissions   []string `json:"permissions,omitempty"`
	Branches      []string `json:"branches,omitempty"`
	Namespaces    []string `json:"namespaces,omitempty"`
	Contexts      []string `json:"contexts,omitempty"`
	Hosts         []string `json:"hosts,omitempty"`
	Registries    []string `json:"registries,omitempty"`
	EnvKeys       []string `json:"env_keys,omitempty"`
	Writable      bool     `json:"writable,omitempty"`
}

// RequestGrant files a request.
func (c *Client) RequestGrant(ctx context.Context, req FileGrantRequest) (GrantRequest, error) {
	var out GrantRequest
	err := c.Do(ctx, http.MethodPost, "/api/grant-requests", nil, req, &out)
	return out, err
}

// WithdrawGrantRequest takes back one of the caller's pending requests.
func (c *Client) WithdrawGrantRequest(ctx context.Context, id string) (GrantRequest, error) {
	var out struct {
		Request GrantRequest `json:"request"`
	}
	err := c.Do(ctx, http.MethodPost, "/api/grant-requests/"+url.PathEscape(id)+"/withdraw", nil, map[string]any{}, &out)
	return out.Request, err
}

// CatalogEntry is a secret the caller may ask for: its id, name and kind,
// and nothing else.
type CatalogEntry struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Kind string `json:"kind"`
}

// SecretCatalog lists what the caller may file a request for.
func (c *Client) SecretCatalog(ctx context.Context) ([]CatalogEntry, error) {
	var out struct {
		Secrets []CatalogEntry `json:"secrets"`
	}
	if err := c.Do(ctx, http.MethodGet, "/api/secrets/catalog", nil, nil, &out); err != nil {
		return nil, err
	}
	return out.Secrets, nil
}
