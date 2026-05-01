// Package github provides a lightweight GitHub REST API client for cloop.
// It supports issue sync, PR listing, and comment creation without
// requiring external dependencies beyond the standard library.
package github

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os/exec"
	"strings"
	"time"
)

// Issue represents a GitHub issue.
type Issue struct {
	Number    int       `json:"number"`
	Title     string    `json:"title"`
	Body      string    `json:"body"`
	State     string    `json:"state"`
	HTMLURL   string    `json:"html_url"`
	Labels    []Label   `json:"labels"`
	Assignees []User    `json:"assignees"`
	Milestone *GHMilestone `json:"milestone"`
	UpdatedAt time.Time `json:"updated_at"`
	// PullRequest is non-nil when this is actually a PR (issues endpoint returns both).
	PullRequest *struct{} `json:"pull_request,omitempty"`
}

// IsPR returns true if this issue is actually a pull request.
func (i *Issue) IsPR() bool { return i.PullRequest != nil }

// LabelNames returns a comma-separated list of label names.
func (i *Issue) LabelNames() string {
	names := make([]string, len(i.Labels))
	for j, l := range i.Labels {
		names[j] = l.Name
	}
	return strings.Join(names, ", ")
}

// Label represents a GitHub label.
type Label struct {
	Name  string `json:"name"`
	Color string `json:"color"`
}

// User represents a GitHub user.
type User struct {
	Login string `json:"login"`
}

// GHMilestone represents a GitHub milestone attached to an issue.
type GHMilestone struct {
	Title string `json:"title"`
}

// PR represents a GitHub pull request.
type PR struct {
	Number    int    `json:"number"`
	Title     string `json:"title"`
	State     string `json:"state"`
	Draft     bool   `json:"draft"`
	HTMLURL   string `json:"html_url"`
	User      User   `json:"user"`
	Head      struct {
		Ref string `json:"ref"`
		SHA string `json:"sha"`
	} `json:"head"`
	Base struct {
		Ref string `json:"ref"`
	} `json:"base"`
	UpdatedAt time.Time `json:"updated_at"`
	Body      string    `json:"body"`
}

// CheckRun represents a CI check result.
type CheckRun struct {
	Name       string `json:"name"`
	Status     string `json:"status"`
	Conclusion string `json:"conclusion"`
	HTMLURL    string `json:"html_url"`
}

// CheckRunsResponse is the GitHub API response for check runs.
type CheckRunsResponse struct {
	CheckRuns []CheckRun `json:"check_runs"`
}

// Client is a minimal GitHub REST API client.
type Client struct {
	Token   string
	Repo    string // owner/repo
	BaseURL string // default: https://api.github.com
}

// New creates a new GitHub client. Token may be empty for public repos (read-only).
func New(token, repo string) *Client {
	return &Client{Token: token, Repo: repo, BaseURL: "https://api.github.com"}
}

// do makes an authenticated request to the GitHub API.
func (c *Client) do(method, path string, body interface{}) ([]byte, int, error) {
	var reqBody io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, 0, err
		}
		reqBody = bytes.NewReader(b)
	}

	u := c.BaseURL + "/repos/" + c.Repo + path
	req, err := http.NewRequest(method, u, reqBody)
	if err != nil {
		return nil, 0, err
	}
	if c.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.Token)
	}
	req.Header.Set("Accept", "application/vnd.github.v3+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(resp.Body)
	return data, resp.StatusCode, err
}

// ListIssues fetches issues from the repository.
// state: "open", "closed", or "all"
// labels: filter by label names (empty = no filter)
func (c *Client) ListIssues(state string, labels []string) ([]Issue, error) {
	params := url.Values{}
	params.Set("state", state)
	params.Set("per_page", "100")
	if len(labels) > 0 {
		params.Set("labels", strings.Join(labels, ","))
	}

	data, status, err := c.do("GET", "/issues?"+params.Encode(), nil)
	if err != nil {
		return nil, err
	}
	if status != 200 {
		return nil, fmt.Errorf("GitHub API error %d: %s", status, string(data))
	}

	var issues []Issue
	if err := json.Unmarshal(data, &issues); err != nil {
		return nil, fmt.Errorf("parsing issues: %w", err)
	}

	// Filter out pull requests (they appear in the issues endpoint too)
	result := issues[:0]
	for _, i := range issues {
		if !i.IsPR() {
			result = append(result, i)
		}
	}
	return result, nil
}

// GetIssue fetches a single issue by number.
func (c *Client) GetIssue(number int) (*Issue, error) {
	data, status, err := c.do("GET", fmt.Sprintf("/issues/%d", number), nil)
	if err != nil {
		return nil, err
	}
	if status != 200 {
		return nil, fmt.Errorf("GitHub API error %d: %s", status, string(data))
	}
	var issue Issue
	if err := json.Unmarshal(data, &issue); err != nil {
		return nil, fmt.Errorf("parsing issue: %w", err)
	}
	return &issue, nil
}

// CreateIssue creates a new issue and returns it.
func (c *Client) CreateIssue(title, body string, labels []string) (*Issue, error) {
	payload := map[string]interface{}{
		"title":  title,
		"body":   body,
		"labels": labels,
	}
	data, status, err := c.do("POST", "/issues", payload)
	if err != nil {
		return nil, err
	}
	if status != 201 {
		return nil, fmt.Errorf("GitHub API error %d: %s", status, string(data))
	}
	var issue Issue
	if err := json.Unmarshal(data, &issue); err != nil {
		return nil, fmt.Errorf("parsing created issue: %w", err)
	}
	return &issue, nil
}

// UpdateIssue updates an existing issue (title, body, state).
func (c *Client) UpdateIssue(number int, updates map[string]interface{}) error {
	data, status, err := c.do("PATCH", fmt.Sprintf("/issues/%d", number), updates)
	if err != nil {
		return err
	}
	if status != 200 {
		return fmt.Errorf("GitHub API error %d: %s", status, string(data))
	}
	return nil
}

// CloseIssue closes an issue by number.
func (c *Client) CloseIssue(number int) error {
	return c.UpdateIssue(number, map[string]interface{}{"state": "closed"})
}

// AddComment adds a comment to an issue or PR.
func (c *Client) AddComment(number int, body string) error {
	payload := map[string]string{"body": body}
	data, status, err := c.do("POST", fmt.Sprintf("/issues/%d/comments", number), payload)
	if err != nil {
		return err
	}
	if status != 201 {
		return fmt.Errorf("GitHub API error %d: %s", status, string(data))
	}
	return nil
}

// ListPRs lists pull requests.
// state: "open", "closed", "all"
func (c *Client) ListPRs(state string) ([]PR, error) {
	params := url.Values{}
	params.Set("state", state)
	params.Set("per_page", "100")

	data, status, err := c.do("GET", "/pulls?"+params.Encode(), nil)
	if err != nil {
		return nil, err
	}
	if status != 200 {
		return nil, fmt.Errorf("GitHub API error %d: %s", status, string(data))
	}
	var prs []PR
	if err := json.Unmarshal(data, &prs); err != nil {
		return nil, fmt.Errorf("parsing PRs: %w", err)
	}
	return prs, nil
}

// ListCheckRuns returns CI check runs for a commit SHA.
func (c *Client) ListCheckRuns(sha string) ([]CheckRun, error) {
	data, status, err := c.do("GET", fmt.Sprintf("/commits/%s/check-runs?per_page=100", sha), nil)
	if err != nil {
		return nil, err
	}
	if status != 200 {
		return nil, fmt.Errorf("GitHub API error %d: %s", status, string(data))
	}
	var resp CheckRunsResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("parsing check runs: %w", err)
	}
	return resp.CheckRuns, nil
}

// DetectRepo tries to discover the owner/repo from the git remote in the current directory.
// It returns "owner/repo" or an error if not detectable.
func DetectRepo() (string, error) {
	out, err := exec.Command("git", "remote", "get-url", "origin").Output()
	if err != nil {
		return "", fmt.Errorf("no git remote 'origin' found")
	}
	remote := strings.TrimSpace(string(out))
	return ParseRepoFromRemote(remote)
}

// ParseRepoFromRemote extracts "owner/repo" from a GitHub remote URL.
// Handles HTTPS (https://github.com/owner/repo.git) and SSH (git@github.com:owner/repo.git).
func ParseRepoFromRemote(remote string) (string, error) {
	// SSH: git@github.com:owner/repo.git
	if strings.Contains(remote, "git@github.com:") {
		path := strings.TrimPrefix(remote, "git@github.com:")
		path = strings.TrimSuffix(path, ".git")
		parts := strings.Split(path, "/")
		if len(parts) == 2 && parts[0] != "" && parts[1] != "" {
			return path, nil
		}
	}
	// HTTPS: https://github.com/owner/repo.git or https://github.com/owner/repo
	if strings.Contains(remote, "github.com") {
		u, err := url.Parse(remote)
		if err == nil {
			path := strings.TrimPrefix(u.Path, "/")
			path = strings.TrimSuffix(path, ".git")
			parts := strings.Split(path, "/")
			if len(parts) == 2 && parts[0] != "" && parts[1] != "" {
				return path, nil
			}
		}
	}
	return "", fmt.Errorf("cannot parse GitHub repo from remote: %q", remote)
}

// CheckRunSummary returns a one-line summary of check run results.
func CheckRunSummary(runs []CheckRun) string {
	if len(runs) == 0 {
		return "no checks"
	}
	pass, fail, pending := 0, 0, 0
	for _, r := range runs {
		switch r.Conclusion {
		case "success":
			pass++
		case "failure", "timed_out", "cancelled":
			fail++
		default:
			pending++
		}
	}
	parts := []string{}
	if pass > 0 {
		parts = append(parts, fmt.Sprintf("%d passed", pass))
	}
	if fail > 0 {
		parts = append(parts, fmt.Sprintf("%d failed", fail))
	}
	if pending > 0 {
		parts = append(parts, fmt.Sprintf("%d pending", pending))
	}
	return strings.Join(parts, ", ")
}
