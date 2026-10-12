package hubclient

// The Features panel's calls (Task 20417): a project's parallel features —
// git worktrees of it with their own task lists and run settings — listed,
// started, and proposed as pull requests. Addressed through the parent
// project, so each is authorised against it.

import (
	"context"
	"net/http"
	"net/url"
	"time"
)

// FeaturePR is a feature's pull request as the hub last saw it.
type FeaturePR struct {
	Number    int       `json:"number"`
	URL       string    `json:"url"`
	State     string    `json:"state"`
	Repo      string    `json:"repo,omitempty"`
	Head      string    `json:"head,omitempty"`
	Base      string    `json:"base,omitempty"`
	Draft     bool      `json:"draft,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}

// Feature is one feature of a project.
type Feature struct {
	// Idx is the feature's own index in the caller's project list: what its
	// run, tasks and options are addressed by (`cloop remote run <idx>`).
	Idx         int    `json:"project_idx"`
	Path        string `json:"path"`
	Name        string `json:"name"`
	Status      string `json:"status"`
	Running     bool   `json:"running"`
	TotalTasks  int    `json:"total_tasks"`
	DoneTasks   int    `json:"done_tasks"`
	FailedTasks int    `json:"failed_tasks"`
	Feature     *struct {
		Slug       string     `json:"slug"`
		Title      string     `json:"title"`
		Branch     string     `json:"branch"`
		Base       string     `json:"base"`
		CreatedAt  time.Time  `json:"created_at"`
		CreatedBy  string     `json:"created_by,omitempty"`
		AutoPR     bool       `json:"auto_pr,omitempty"`
		AutoEvolve bool       `json:"auto_evolve,omitempty"`
		Innovate   bool       `json:"innovate,omitempty"`
		PR         *FeaturePR `json:"pr,omitempty"`
	} `json:"feature,omitempty"`
}

// FeatureList is GET /api/projects/{idx}/features.
type FeatureList struct {
	Project  string    `json:"project"`
	Path     string    `json:"path"`
	Features []Feature `json:"features"`
	Max      int       `json:"max"`
}

// Features lists a project's features.
func (c *Client) Features(ctx context.Context, idx int) (*FeatureList, error) {
	var out FeatureList
	if err := c.Do(ctx, http.MethodGet, projectPath(idx, "features"), nil, nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// StartFeatureRequest is the POST /api/projects/{idx}/features body.
type StartFeatureRequest struct {
	Name        string   `json:"name"`
	Description string   `json:"description,omitempty"`
	Base        string   `json:"base,omitempty"`
	Tasks       []string `json:"tasks,omitempty"`
	AutoEvolve  bool     `json:"auto_evolve,omitempty"`
	Innovate    bool     `json:"innovate,omitempty"`
	Parallel    bool     `json:"parallel,omitempty"`
	MaxParallel int      `json:"max_parallel,omitempty"`
	AutoPR      bool     `json:"auto_pr,omitempty"`
}

// StartedFeature is the hub's answer to a new feature.
type StartedFeature struct {
	Slug   string `json:"slug"`
	Branch string `json:"branch"`
	Base   string `json:"base"`
	Path   string `json:"path"`
	Idx    int    `json:"project_idx"`
}

// StartFeature creates a feature of a project: a branch, its worktree, and a
// task list of its own.
func (c *Client) StartFeature(ctx context.Context, idx int, req StartFeatureRequest) (StartedFeature, error) {
	var out StartedFeature
	err := c.doLong(ctx, http.MethodPost, projectPath(idx, "features"), nil, req, &out)
	return out, err
}

// FeaturePRRequest is the POST /api/projects/{idx}/features/{slug}/pr body.
type FeaturePRRequest struct {
	Title string `json:"title,omitempty"`
	Body  string `json:"body,omitempty"`
	Draft bool   `json:"draft,omitempty"`
}

// FeaturePRResult is what opening a feature's pull request did.
type FeaturePRResult struct {
	PR          *FeaturePR `json:"pr"`
	Existing    bool       `json:"existing"`
	Pushed      bool       `json:"pushed"`
	Ahead       int        `json:"ahead"`
	Dirty       []string   `json:"dirty,omitempty"`
	TokenSource string     `json:"token_source"`
}

// OpenFeaturePR pushes a feature's branch and opens its pull request into
// the feature's base, or returns the one already open.
func (c *Client) OpenFeaturePR(ctx context.Context, idx int, slug string, req FeaturePRRequest) (*FeaturePRResult, error) {
	var out struct {
		Result *FeaturePRResult `json:"result"`
	}
	if err := c.doLong(ctx, http.MethodPost, projectPath(idx, "features/"+url.PathEscape(slug)+"/pr"), nil, req, &out); err != nil {
		return nil, err
	}
	if out.Result == nil {
		out.Result = &FeaturePRResult{}
	}
	return out.Result, nil
}
