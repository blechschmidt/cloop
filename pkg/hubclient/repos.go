package hubclient

// The Repositories panel's calls (Task 20417): which GitHub repositories a
// project may reach, through which credential, and assigning or withdrawing
// them. The subject of every grant made here is the project in the path, never
// a value from the body — the hub's own rule, which is why a terminal can be
// handed these routes at all.

import (
	"context"
	"net/http"
	"net/url"
	"time"
)

// RepoApp is a stored GitHub App the caller may assign repositories from.
type RepoApp struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// RepoAssignment is one live grant of repositories to a project.
type RepoAssignment struct {
	GrantID           string    `json:"grant_id"`
	SecretID          string    `json:"secret_id"`
	SecretName        string    `json:"secret_name"`
	Kind              string    `json:"kind"`
	Repos             []string  `json:"repos"`
	Access            string    `json:"access"`
	Branches          []string  `json:"branches,omitempty"`
	BranchEnforcement string    `json:"branch_enforcement,omitempty"`
	Replaceable       bool      `json:"replaceable,omitempty"`
	ExpiresAt         time.Time `json:"expires_at"`
	CreatedAt         time.Time `json:"created_at"`
	CreatedBy         string    `json:"created_by,omitempty"`
}

// GitProxyStatus is whether the hub's git proxy guards GitHub credentials.
type GitProxyStatus struct {
	Running  bool     `json:"running"`
	Required bool     `json:"required"`
	PushRefs []string `json:"push_refs,omitempty"`
}

// ProjectRepositories is GET /api/projects/{idx}/repositories.
type ProjectRepositories struct {
	Project     string           `json:"project"`
	Apps        []RepoApp        `json:"apps"`
	Assignments []RepoAssignment `json:"assignments"`
	GitProxy    GitProxyStatus   `json:"git_proxy"`
}

// ProjectRepositories lists what a project can reach and what the caller
// may grant it from.
func (c *Client) ProjectRepositories(ctx context.Context, idx int) (*ProjectRepositories, error) {
	var out ProjectRepositories
	if err := c.Do(ctx, http.MethodGet, projectPath(idx, "repositories"), nil, nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// AvailableRepository is one repository a GitHub App installation reaches.
type AvailableRepository struct {
	ID       int64  `json:"id"`
	FullName string `json:"full_name"`
	Private  bool   `json:"private"`
}

// AvailableRepositories asks the hub which repositories the GitHub App stored
// as secret reaches — GitHub's own inventory of the installation.
func (c *Client) AvailableRepositories(ctx context.Context, idx int, secret string) ([]AvailableRepository, error) {
	var out struct {
		Repositories []AvailableRepository `json:"repositories"`
	}
	if err := c.Do(ctx, http.MethodGet, projectPath(idx, "repositories/available"),
		url.Values{"secret": {secret}}, nil, &out); err != nil {
		return nil, err
	}
	return out.Repositories, nil
}

// AssignRepositoriesRequest is the POST /api/projects/{idx}/repositories body.
type AssignRepositoriesRequest struct {
	Secret     string   `json:"secret"`
	Repos      []string `json:"repos"`
	Access     string   `json:"access,omitempty"`
	TTLMinutes int      `json:"ttl_minutes,omitempty"`
	Branches   []string `json:"branches,omitempty"`
	// Replaces names a grant of this project's the new one supersedes.
	Replaces string `json:"replaces,omitempty"`
}

// AssignRepositories grants repositories to a project through a stored
// GitHub credential.
func (c *Client) AssignRepositories(ctx context.Context, idx int, req AssignRepositoriesRequest) (RepoAssignment, error) {
	var out RepoAssignment
	err := c.Do(ctx, http.MethodPost, projectPath(idx, "repositories"), nil, req, &out)
	return out, err
}

// RevokedRepositories is the hub's answer to a withdrawal.
type RevokedRepositories struct {
	GrantID string `json:"grant_id"`
	State   string `json:"state,omitempty"`
	Leases  int    `json:"leases,omitempty"`
	Note    string `json:"note,omitempty"`
}

// RevokeRepositories withdraws one of a project's repository grants.
func (c *Client) RevokeRepositories(ctx context.Context, idx int, grantID string) (RevokedRepositories, error) {
	var out RevokedRepositories
	err := c.Do(ctx, http.MethodDelete, projectPath(idx, "repositories"), url.Values{"grant": {grantID}}, nil, &out)
	return out, err
}
