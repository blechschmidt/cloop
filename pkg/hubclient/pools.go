package hubclient

// Executor pools (Task 20486): the dashboard's pool calls, for `cloop executor
// pool`. Every route is an administrator's (executor.manage), and the writes
// ask a session for a recent sign-in, as the dashboard's buttons do.

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// PoolCapabilities is what a pool's runners advertise.
type PoolCapabilities struct {
	Harnesses         []string `json:"harnesses,omitempty"`
	ContainerRuntimes []string `json:"container_runtimes,omitempty"`
	Platform          string   `json:"platform,omitempty"`
	Arch              string   `json:"arch,omitempty"`
	MemoryMB          int      `json:"memory_mb,omitempty"`
	CPUs              int      `json:"cpus,omitempty"`
}

// PoolSnapshot is a pool's demand and runners.
type PoolSnapshot struct {
	Revoked    bool   `json:"revoked"`
	Cordoned   bool   `json:"cordoned,omitempty"`
	MaxRunners int    `json:"max_runners"`
	Demand     int    `json:"demand"`
	Waiting    int    `json:"waiting"`
	Busy       int    `json:"busy"`
	Idle       int    `json:"idle"`
	Pending    int    `json:"pending"`
	Runners    int    `json:"runners"`
	Spare      int    `json:"spare"`
	Wanted     int    `json:"wanted"`
	Revision   string `json:"revision"`
}

// PoolStorage is a controller's count of a pool's runner volumes.
type PoolStorage struct {
	Claims        int   `json:"claims"`
	Bound         int   `json:"bound"`
	Pending       int   `json:"pending"`
	InUse         int   `json:"in_use"`
	Full          int   `json:"full"`
	Retained      int   `json:"retained"`
	BytesUsed     int64 `json:"bytes_used"`
	BytesCapacity int64 `json:"bytes_capacity"`
}

// PoolProblem is something about a pool that needs a person.
type PoolProblem struct {
	Kind         string `json:"kind"`
	Severity     string `json:"severity"`
	Message      string `json:"message"`
	Remedy       string `json:"remedy,omitempty"`
	CredentialID string `json:"credential_id,omitempty"`
}

// PoolController is the controller a pool heard from last.
type PoolController struct {
	CredentialID string    `json:"credential_id"`
	Version      string    `json:"version,omitempty"`
	Protocol     int       `json:"protocol"`
	Behind       bool      `json:"behind"`
	LastContact  time.Time `json:"last_contact"`
}

// PoolHealth is what the hub knows of a pool's controllers and makes of it.
type PoolHealth struct {
	Problems        []PoolProblem   `json:"problems"`
	Waiting         int             `json:"waiting"`
	LastContact     time.Time       `json:"last_contact,omitzero"`
	Controller      *PoolController `json:"controller,omitempty"`
	Storage         *PoolStorage    `json:"storage,omitempty"`
	LiveCredentials int             `json:"live_credentials"`
}

// ExecutorPool is one pool as the hub's API shows it.
type ExecutorPool struct {
	ID           string            `json:"id"`
	Name         string            `json:"name"`
	Labels       map[string]string `json:"labels,omitempty"`
	Capabilities PoolCapabilities  `json:"capabilities"`
	MaxRunners   int               `json:"max_runners"`
	Owner        string            `json:"owner,omitempty"`
	WorkDirRoot  string            `json:"workdir_root,omitempty"`
	CreatedAt    time.Time         `json:"created_at"`
	CreatedBy    string            `json:"created_by,omitempty"`
	RevokedAt    time.Time         `json:"revoked_at,omitzero"`
	RevokedBy    string            `json:"revoked_by,omitempty"`
	CordonedAt   time.Time         `json:"cordoned_at,omitzero"`
	CordonedBy   string            `json:"cordoned_by,omitempty"`
	CordonReason string            `json:"cordon_reason,omitempty"`
	Binding      string            `json:"binding"`
	Cordoned     bool              `json:"cordoned"`
	Snapshot     *PoolSnapshot     `json:"snapshot,omitempty"`
	Health       *PoolHealth       `json:"health,omitempty"`
}

// Revoked reports whether the pool was revoked.
func (p ExecutorPool) Revoked() bool { return !p.RevokedAt.IsZero() && p.RevokedAt.Year() > 1 }

// State is "revoked", "cordoned" or "live".
func (p ExecutorPool) State() string {
	switch {
	case p.Revoked():
		return "revoked"
	case p.Cordoned:
		return "cordoned"
	}
	return "live"
}

// PoolList is GET /api/executor-pools.
type PoolList struct {
	Pools []ExecutorPool `json:"pools"`
	// HubProtocol is the pool-controller protocol the hub speaks; Chart and
	// ImageTag are what an upgrade of a controller behind it installs.
	HubProtocol int    `json:"hub_protocol"`
	Chart       string `json:"chart"`
	ImageTag    string `json:"image_tag"`
}

// PoolCredential is a controller credential, never its secret.
type PoolCredential struct {
	ID                 string    `json:"id"`
	PoolID             string    `json:"pool_id"`
	CreatedAt          time.Time `json:"created_at"`
	CreatedBy          string    `json:"created_by,omitempty"`
	LastUsedAt         time.Time `json:"last_used_at"`
	RevokedAt          time.Time `json:"revoked_at"`
	RevokedBy          string    `json:"revoked_by,omitempty"`
	ControllerVersion  string    `json:"controller_version,omitempty"`
	ControllerProtocol int       `json:"controller_protocol"`
}

// Revoked reports whether the credential was revoked.
func (c PoolCredential) Revoked() bool { return !c.RevokedAt.IsZero() && c.RevokedAt.Year() > 1 }

// Used reports whether a controller ever presented the credential.
func (c PoolCredential) Used() bool { return !c.LastUsedAt.IsZero() && c.LastUsedAt.Year() > 1 }

// AudienceEntry is one principal on a pool's access list.
type AudienceEntry struct {
	Kind    string    `json:"kind"`
	Value   string    `json:"value"`
	AddedAt time.Time `json:"added_at"`
	AddedBy string    `json:"added_by,omitempty"`
}

// PoolRunner is one runner of a pool.
type PoolRunner struct {
	EnrollmentID string    `json:"enrollment_id"`
	Name         string    `json:"name"`
	ExecutorID   string    `json:"executor_id,omitempty"`
	State        string    `json:"state"`
	Member       string    `json:"member,omitempty"`
	QueueID      string    `json:"queue_id,omitempty"`
	MintedAt     time.Time `json:"minted_at"`
	EnrolledAt   time.Time `json:"enrolled_at"`
	RetiredAt    time.Time `json:"retired_at"`
	RetireReason string    `json:"retire_reason,omitempty"`
	CredentialID string    `json:"credential_id,omitempty"`
}

// Live reports whether the runner is pending, idle or busy.
func (r PoolRunner) Live() bool {
	return r.State == "pending" || r.State == "idle" || r.State == "busy"
}

// PoolQueueEntry is one run waiting for, or handed to, a runner.
type PoolQueueEntry struct {
	ID          string    `json:"id"`
	ProjectPath string    `json:"project_path"`
	Starter     string    `json:"starter,omitempty"`
	State       string    `json:"state"`
	Reason      string    `json:"reason,omitempty"`
	ExecutorID  string    `json:"executor_id,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
}

// PoolControllerReport is a controller's last health report.
type PoolControllerReport struct {
	CredentialID string       `json:"credential_id"`
	Healthy      bool         `json:"healthy"`
	Reason       string       `json:"reason,omitempty"`
	Message      string       `json:"message,omitempty"`
	ReportedAt   time.Time    `json:"reported_at"`
	Storage      *PoolStorage `json:"storage,omitempty"`
}

// PoolDetail is GET /api/executor-pools/{id}.
type PoolDetail struct {
	ExecutorPool
	Credentials       []PoolCredential       `json:"credentials"`
	Audience          []AudienceEntry        `json:"audience"`
	Runners           []PoolRunner           `json:"runners"`
	Queue             []PoolQueueEntry       `json:"queue"`
	ControllerReports []PoolControllerReport `json:"controller_reports"`
}

// PoolAudienceEntry names one principal for a pool's access list.
type PoolAudienceEntry struct {
	Kind  string `json:"kind"`
	Value string `json:"value"`
}

// PoolPersistence is the runner volumes' defaults for the install.
type PoolPersistence struct {
	Enabled       bool   `json:"enabled"`
	StorageClass  string `json:"storage_class,omitempty"`
	Size          string `json:"size,omitempty"`
	ReclaimPolicy string `json:"reclaim_policy,omitempty"`
}

// PoolInstallOptions shapes the controller's install commands.
type PoolInstallOptions struct {
	Namespace   string           `json:"namespace,omitempty"`
	Release     string           `json:"release,omitempty"`
	MinRunners  int              `json:"min_runners,omitempty"`
	Persistence *PoolPersistence `json:"persistence,omitempty"`
}

// CreatePoolRequest is POST /api/executor-pools.
type CreatePoolRequest struct {
	Name         string              `json:"name"`
	Labels       map[string]string   `json:"labels,omitempty"`
	Capabilities PoolCapabilities    `json:"capabilities"`
	MaxRunners   int                 `json:"max_runners"`
	Owner        string              `json:"owner,omitempty"`
	WorkDirRoot  string              `json:"workdir_root,omitempty"`
	Audience     []PoolAudienceEntry `json:"audience,omitempty"`
	Credential   bool                `json:"credential,omitempty"`
	Kubernetes   *PoolInstallOptions `json:"kubernetes,omitempty"`
}

// PoolInstall is the install block the hub answers a create with.
type PoolInstall struct {
	Command          string   `json:"command,omitempty"`
	Unavailable      string   `json:"unavailable,omitempty"`
	Chart            string   `json:"chart"`
	Release          string   `json:"release"`
	Namespace        string   `json:"namespace"`
	CredentialSecret string   `json:"credential_secret"`
	HubURL           string   `json:"hub_url"`
	Pin              string   `json:"pin,omitempty"`
	ImageTag         string   `json:"image_tag"`
	Notes            []string `json:"notes,omitempty"`
}

// CreatedPool is the hub's answer to a create: the only time the credential
// is shown.
type CreatedPool struct {
	Pool       ExecutorPool    `json:"pool"`
	Audience   []AudienceEntry `json:"audience,omitempty"`
	Credential *PoolCredential `json:"credential,omitempty"`
	Token      string          `json:"token,omitempty"`
	Install    *PoolInstall    `json:"install,omitempty"`
	Notice     string          `json:"notice,omitempty"`
}

// MintedPoolCredential is a newly minted controller credential.
type MintedPoolCredential struct {
	Credential PoolCredential `json:"credential"`
	Token      string         `json:"token"`
	Pin        string         `json:"pin,omitempty"`
	Notice     string         `json:"notice"`
}

// RevokedPool is what revoking a pool took back.
type RevokedPool struct {
	PoolID        string   `json:"pool_id"`
	Credentials   int      `json:"credentials"`
	Tokens        int      `json:"tokens"`
	Runners       []string `json:"runners"`
	CancelledRuns int      `json:"cancelled_runs"`
}

// RevokedPoolCredential is what revoking one controller credential took back.
type RevokedPoolCredential struct {
	PoolID       string   `json:"pool_id"`
	CredentialID string   `json:"credential_id"`
	Tokens       int      `json:"tokens"`
	Runners      []string `json:"runners"`
}

func poolPath(id, rest string) string {
	return "/api/executor-pools/" + url.PathEscape(id) + rest
}

// ExecutorPools lists every pool with its demand and health.
func (c *Client) ExecutorPools(ctx context.Context) (*PoolList, error) {
	var out PoolList
	if err := c.Do(ctx, http.MethodGet, "/api/executor-pools", nil, nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// ExecutorPool reads one pool with its runners, queue and credentials.
func (c *Client) ExecutorPool(ctx context.Context, id string) (*PoolDetail, error) {
	var out PoolDetail
	if err := c.Do(ctx, http.MethodGet, poolPath(id, ""), nil, nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// ResolveExecutorPool finds a pool by its ID or its name; a revoked pool only
// by its ID, since its name may be taken again.
func (c *Client) ResolveExecutorPool(ctx context.Context, ref string) (ExecutorPool, error) {
	ref = strings.TrimSpace(ref)
	list, err := c.ExecutorPools(ctx)
	if err != nil {
		return ExecutorPool{}, err
	}
	for _, p := range list.Pools {
		if p.ID == ref {
			return p, nil
		}
	}
	var found []ExecutorPool
	for _, p := range list.Pools {
		if strings.EqualFold(p.Name, ref) && !p.Revoked() {
			found = append(found, p)
		}
	}
	switch len(found) {
	case 1:
		return found[0], nil
	case 0:
		return ExecutorPool{}, fmt.Errorf("no executor pool on %s is called or has the id %q: `cloop executor pool list` "+
			"shows them", c.Base, ref)
	}
	return ExecutorPool{}, fmt.Errorf("more than one executor pool is called %q; name it by its id", ref)
}

// CreateExecutorPool creates a pool, and with req.Credential its first
// controller credential and install commands.
func (c *Client) CreateExecutorPool(ctx context.Context, req CreatePoolRequest) (*CreatedPool, error) {
	var out CreatedPool
	if err := c.Do(ctx, http.MethodPost, "/api/executor-pools", nil, req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// PoolSpec is a pool's definition as PUT /api/executor-pools/{id} takes it:
// every field, since the hub replaces the definition whole.
type PoolSpec struct {
	Name         string            `json:"name"`
	Labels       map[string]string `json:"labels,omitempty"`
	Capabilities PoolCapabilities  `json:"capabilities"`
	MaxRunners   int               `json:"max_runners"`
	Owner        string            `json:"owner,omitempty"`
	WorkDirRoot  string            `json:"workdir_root,omitempty"`
}

// Spec is the pool's definition, to change and PUT back.
func (p ExecutorPool) Spec() PoolSpec {
	return PoolSpec{Name: p.Name, Labels: p.Labels, Capabilities: p.Capabilities, MaxRunners: p.MaxRunners,
		Owner: p.Owner, WorkDirRoot: p.WorkDirRoot}
}

// UpdateExecutorPool replaces a live pool's definition.
func (c *Client) UpdateExecutorPool(ctx context.Context, id string, spec PoolSpec) (ExecutorPool, error) {
	var out struct {
		Pool ExecutorPool `json:"pool"`
	}
	if err := c.Do(ctx, http.MethodPut, poolPath(id, ""), nil, spec, &out); err != nil {
		return ExecutorPool{}, err
	}
	return out.Pool, nil
}

// RevokeExecutorPool revokes a pool and everything it holds.
func (c *Client) RevokeExecutorPool(ctx context.Context, id string) (*RevokedPool, error) {
	var out RevokedPool
	if err := c.Do(ctx, http.MethodPost, poolPath(id, "/revoke"), nil, map[string]any{}, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// CordonExecutorPool holds a pool (cordon true) or releases it, and reports
// whether its state changed.
func (c *Client) CordonExecutorPool(ctx context.Context, id string, cordon bool, reason string) (ExecutorPool, bool, error) {
	var out struct {
		Changed bool         `json:"changed"`
		Pool    ExecutorPool `json:"pool"`
	}
	path, body := poolPath(id, "/uncordon"), map[string]any{}
	if cordon {
		path = poolPath(id, "/cordon")
		if strings.TrimSpace(reason) != "" {
			body["reason"] = reason
		}
	}
	if err := c.Do(ctx, http.MethodPost, path, nil, body, &out); err != nil {
		return ExecutorPool{}, false, err
	}
	return out.Pool, out.Changed, nil
}

// MintPoolCredential mints a controller credential for a pool: the only time
// its secret is shown.
func (c *Client) MintPoolCredential(ctx context.Context, id string) (*MintedPoolCredential, error) {
	var out MintedPoolCredential
	if err := c.Do(ctx, http.MethodPost, poolPath(id, "/credentials"), nil, map[string]any{}, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// RevokePoolCredential revokes one controller credential, and the runners and
// tokens it minted.
func (c *Client) RevokePoolCredential(ctx context.Context, id, credentialID string) (*RevokedPoolCredential, error) {
	var out RevokedPoolCredential
	if err := c.Do(ctx, http.MethodDelete, poolPath(id, "/credentials/"+url.PathEscape(credentialID)), nil, nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}
