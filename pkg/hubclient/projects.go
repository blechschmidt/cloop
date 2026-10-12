package hubclient

// The calls `cloop remote init` and `cloop remote executors` make (Task
// 20417): creating a project, the executor fleet as the caller may use it, and
// the Claude credential a sandboxed run would authenticate with. Each is one of
// the dashboard's own routes — the New Project dialog, the Executors panel, the
// Claude credential card — so the hub authorises each exactly as it would the
// dashboard's control.

import (
	"context"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

// ProjectGrant is one credential a new project should hold from the moment
// it exists: a stored secret by name, narrowed as its kind requires.
type ProjectGrant struct {
	SecretRef   string   `json:"secret_ref"`
	Scope       string   `json:"scope,omitempty"`
	TTLMinutes  int      `json:"ttl_minutes,omitempty"`
	Repos       []string `json:"repos,omitempty"`
	Permissions []string `json:"permissions,omitempty"`
	Branches    []string `json:"branches,omitempty"`
	Namespaces  []string `json:"namespaces,omitempty"`
	Contexts    []string `json:"contexts,omitempty"`
	Hosts       []string `json:"hosts,omitempty"`
	Registries  []string `json:"registries,omitempty"`
	EnvKeys     []string `json:"env_keys,omitempty"`
	Writable    bool     `json:"writable,omitempty"`
}

// NewProjectRequest is the POST /api/projects/new body.
type NewProjectRequest struct {
	// Dir is the project's directory on the hub. Empty with Name set asks
	// the hub to place it under its projects root (ui.projects_root).
	Dir  string `json:"dir,omitempty"`
	Name string `json:"name,omitempty"`
	Goal string `json:"goal"`

	Provider string `json:"provider,omitempty"`
	Model    string `json:"model,omitempty"`
	Effort   string `json:"effort,omitempty"`

	// ExecutorID pins the project; Grants are opened with it. Both are
	// applied with the creation or not at all.
	ExecutorID string         `json:"executor_id,omitempty"`
	Grants     []ProjectGrant `json:"grants,omitempty"`
}

// NewProject is the hub's answer to a creation.
type NewProject struct {
	Dir string `json:"dir"`
	// Idx is the project's index in the caller's project list, -1 when the
	// hub could not find it there.
	Idx int `json:"project_idx"`
}

// CreateProject creates and initialises a project on the hub.
func (c *Client) CreateProject(ctx context.Context, req NewProjectRequest) (NewProject, error) {
	var out NewProject
	err := c.doLong(ctx, http.MethodPost, "/api/projects/new", nil, req, &out)
	return out, err
}

// Executor is one executor as GET /api/executors describes it to the caller.
type Executor struct {
	ID            string            `json:"id"`
	Name          string            `json:"name"`
	Kind          string            `json:"kind"`
	Status        string            `json:"status"`
	Registered    bool              `json:"registered"`
	Default       bool              `json:"default"`
	Isolation     string            `json:"isolation"`
	Health        string            `json:"health,omitempty"`
	Blocked       bool              `json:"blocked"`
	BlockedReason string            `json:"blocked_reason,omitempty"`
	SchedState    string            `json:"sched_state"`
	SchedReason   string            `json:"sched_reason,omitempty"`
	Schedulable   bool              `json:"schedulable"`
	Restricted    bool              `json:"restricted,omitempty"`
	Admitted      bool              `json:"admitted"`
	Labels        map[string]string `json:"labels,omitempty"`
	Virtual       *struct {
		Parent string `json:"parent"`
	} `json:"virtual,omitempty"`
}

// Usable reports whether a project bound to e could run there now, and if
// not, why not.
func (e Executor) Usable() (bool, string) {
	switch {
	case !e.Admitted:
		return false, "you are not on its access list"
	case e.Blocked:
		if e.BlockedReason != "" {
			return false, e.BlockedReason
		}
		return false, "blocked by the hub's policy"
	case !e.Registered:
		return false, "not registered on this hub"
	}
	return true, ""
}

// ExecutorList is GET /api/executors, as the caller sees it.
type ExecutorList struct {
	Executors []Executor `json:"executors"`
	DefaultID string     `json:"default_id"`
}

// Executors lists the fleet.
func (c *Client) Executors(ctx context.Context) (*ExecutorList, error) {
	var out ExecutorList
	if err := c.Do(ctx, http.MethodGet, "/api/executors", nil, nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// BindExecutor pins a project to an executor; an empty id unpins it.
func (c *Client) BindExecutor(ctx context.Context, idx int, executorID string) error {
	return c.Do(ctx, http.MethodPost, projectPath(idx, "executor"), nil,
		map[string]string{"executor_id": executorID}, nil)
}

// HarnessGrant is a grant the project's sandbox would authenticate with.
type HarnessGrant struct {
	GrantID    string     `json:"grant_id"`
	SecretID   string     `json:"secret_id"`
	SecretName string     `json:"secret_name"`
	Owner      string     `json:"owner,omitempty"`
	ExpiresAt  *time.Time `json:"expires_at"`
	Keys       []string   `json:"keys"`
}

// HarnessCandidate is a secret the caller could grant to fill the gap.
type HarnessCandidate struct {
	ID       string   `json:"id"`
	Name     string   `json:"name"`
	Owner    string   `json:"owner,omitempty"`
	Personal bool     `json:"personal"`
	Mine     bool     `json:"mine"`
	Keys     []string `json:"keys"`
	Complete bool     `json:"complete"`
	Granted  bool     `json:"granted"`
}

// HarnessCredential is GET /api/projects/{idx}/harness-credential: what the
// project's sandbox would sign in to Claude with.
type HarnessCredential struct {
	Applies     bool               `json:"applies"`
	State       string             `json:"state"`
	Provider    string             `json:"provider"`
	Needed      [][]string         `json:"needed"`
	SatisfiedBy *HarnessGrant      `json:"satisfied_by"`
	ExpiresAt   *time.Time         `json:"expires_at"`
	Reason      string             `json:"reason,omitempty"`
	Remedy      string             `json:"remedy,omitempty"`
	Candidates  []HarnessCandidate `json:"candidates"`
	CanPaste    bool               `json:"can_paste"`
	// BrokerUnavailable is why nothing can be granted on this hub at all.
	BrokerUnavailable string `json:"broker_unavailable,omitempty"`
	Granted           *struct {
		GrantID    string    `json:"grant_id"`
		SecretName string    `json:"secret_name"`
		EnvKeys    []string  `json:"env_keys"`
		ExpiresAt  time.Time `json:"expires_at"`
	} `json:"granted,omitempty"`
}

// HarnessCredential reads the project's Claude credential card.
func (c *Client) HarnessCredential(ctx context.Context, idx int) (*HarnessCredential, error) {
	var out HarnessCredential
	if err := c.Do(ctx, http.MethodGet, projectPath(idx, "harness-credential"), nil, nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// GrantHarnessCredential grants an env secret the caller holds as the
// project's Claude credential — the card's dialog, with a secret chosen.
func (c *Client) GrantHarnessCredential(ctx context.Context, idx int, secret string) (*HarnessCredential, error) {
	var out HarnessCredential
	if err := c.Do(ctx, http.MethodPost, projectPath(idx, "harness-credential"), nil,
		map[string]string{"secret": secret}, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// projectPath is /api/projects/{idx}/<rest>.
func projectPath(idx int, rest string) string {
	return "/api/projects/" + strconv.Itoa(idx) + "/" + rest
}

// DashboardURL is the link that opens a project in the hub's dashboard: the
// dashboard reads ?project=<path> once its project list has loaded. A query,
// not a fragment, because the hub's sign-in round trip keeps the path and
// query it was sent from and nothing else.
func (c *Client) DashboardURL(projectPath string) string {
	if projectPath == "" {
		return c.Base + "/"
	}
	return c.Base + "/?" + url.Values{"project": {projectPath}}.Encode()
}
