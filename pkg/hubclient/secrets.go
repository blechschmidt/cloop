package hubclient

// The secret calls `cloop remote kube` makes (Task 20416). Each is one of the
// dashboard's own routes, made with the terminal's session, so a share is
// stored, listed and deleted exactly as the dashboard's Secrets panel would do
// it for the same person: personal to them on a hub with single sign-on.

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Secret is one secret as GET /api/secrets lists it. It carries no
// credential: the hub never returns one.
type Secret struct {
	ID           string            `json:"id"`
	Name         string            `json:"name"`
	Kind         string            `json:"kind"`
	Metadata     map[string]string `json:"metadata"`
	CreatedAt    time.Time         `json:"created_at"`
	CreatedBy    string            `json:"created_by"`
	Owner        string            `json:"owner"`
	Personal     bool              `json:"personal"`
	Mine         bool              `json:"mine"`
	Grants       int               `json:"grants"`
	ActiveGrants int               `json:"active_grants"`
}

// SecretsList is GET /api/secrets.
type SecretsList struct {
	Secrets []Secret `json:"secrets"`
	Broker  struct {
		SecretsAvailable bool   `json:"secrets_available"`
		Reason           string `json:"reason"`
		Remediation      string `json:"remediation"`
	} `json:"broker"`
	// KubeGuard is whether the hub delivers kubeconfigs through its
	// Kubernetes access monitor. A hub older than Task 20416 does not say,
	// which reads as no monitor.
	KubeGuard struct {
		Enabled bool `json:"enabled"`
		Running bool `json:"running"`
	} `json:"kube_guard"`
}

// Secrets lists the secrets this session may see.
func (c *Client) Secrets(ctx context.Context) (*SecretsList, error) {
	var out SecretsList
	if err := c.Do(ctx, http.MethodGet, "/api/secrets", nil, nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// FindSecret returns the secret named name among those this session may see.
func (l *SecretsList) FindSecret(name string) (Secret, bool) {
	for _, s := range l.Secrets {
		if s.Name == name {
			return s, true
		}
	}
	return Secret{}, false
}

// CreateSecretRequest is the POST /api/secrets body.
type CreateSecretRequest struct {
	Name     string            `json:"name"`
	Kind     string            `json:"kind"`
	Payload  string            `json:"payload"`
	Metadata map[string]string `json:"metadata,omitempty"`
	// Personal, when set, asks for a personal or a shared secret; unset lets
	// the hub decide, which is personal whenever the session has an identity.
	Personal *bool `json:"personal,omitempty"`
}

// CreateSecret stores a secret.
func (c *Client) CreateSecret(ctx context.Context, req CreateSecretRequest) (Secret, error) {
	var out Secret
	err := c.Do(ctx, http.MethodPost, "/api/secrets", nil, req, &out)
	return out, err
}

// DeleteSecret deletes a secret, revoking every grant of it.
func (c *Client) DeleteSecret(ctx context.Context, id string) error {
	return c.Do(ctx, http.MethodDelete, "/api/secrets/"+url.PathEscape(id), nil, nil, nil)
}

// RenewedShare is POST /api/secrets/{id}/renew's answer.
type RenewedShare struct {
	ID             string    `json:"id"`
	Name           string    `json:"name"`
	Renewal        string    `json:"renewal"`
	ServiceAccount string    `json:"service_account"`
	IssuedAt       time.Time `json:"issued_at"`
	ExpiresAt      time.Time `json:"expires_at"`
	Renewals       int       `json:"renewals"`
	Verified       bool      `json:"verified"`
	Sessions       int       `json:"sessions"`
}

// ErrRenewUnsupported is a hub that predates Kubernetes share renewal.
var ErrRenewUnsupported = errors.New("this hub predates Kubernetes share renewal (POST /api/secrets/{id}/renew); upgrade it")

// RenewSecret asks the hub to renew a Kubernetes share: itself, now, when
// token is empty, or with token, which the share's owner minted.
func (c *Client) RenewSecret(ctx context.Context, id, token string) (RenewedShare, error) {
	var out RenewedShare
	body := map[string]string{}
	if strings.TrimSpace(token) != "" {
		body["token"] = strings.TrimSpace(token)
	}
	err := c.Do(ctx, http.MethodPost, "/api/secrets/"+url.PathEscape(id)+"/renew", nil, body, &out)
	var ae *APIError
	if errors.As(err, &ae) && (ae.Status == http.StatusNotFound || ae.Status == http.StatusMethodNotAllowed) &&
		!strings.Contains(strings.ToLower(ae.Message), "secret") {
		return out, ErrRenewUnsupported
	}
	return out, err
}
