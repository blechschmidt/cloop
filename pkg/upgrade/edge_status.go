package upgrade

// edge_status.go answers the hub's question about its own build (Task 20376):
// is there an edge build of the commit this hub runs, and if not, why not?
//
// "Not published" has several causes and each has a different remedy, so the
// Upgrade dialog must not flatten them into one sentence:
//
//   - the deploy built a commit that was never pushed — push it;
//   - CI has not run on it, or is still running — wait;
//   - CI failed, or the edge workflow did — fix main;
//   - the build was published and has since been pruned — the hub is old.
//
// Telling them apart costs GitHub API requests, which an unauthenticated
// client gets sixty of an hour. So the cheap check comes first and the rest
// only on a miss: the manifest is a plain download, not an API call, and a
// published build is answered by it alone. The commit lookup is one request
// and its answer never changes, so callers cache it for good; the workflow
// runs are one more request, made only to explain an absence.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// ErrCommitNotFound reports that GitHub has no commit by that name in the
// pinned repository — for the hub's own build, that the deploy built a local
// commit nobody pushed.
var ErrCommitNotFound = errors.New("upgrade: no such commit on GitHub")

// githubAPI is the API base. A variable so this package's tests can point it
// at a stand-in; nothing else sets it.
var githubAPI = githubAPIBase

// apiGet issues one GitHub API GET.
func apiGet(ctx context.Context, path, accept string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, githubAPI+path, nil)
	if err != nil {
		return nil, err
	}
	if accept == "" {
		accept = "application/vnd.github+json"
	}
	req.Header.Set("Accept", accept)
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	return httpClient.Do(req)
}

// ResolveCommit expands a commit prefix to the full id through the GitHub
// API, or returns ErrCommitNotFound.
func ResolveCommit(ctx context.Context, rev string) (string, error) {
	rev = strings.ToLower(strings.TrimSpace(rev))
	if !isHexCommit(rev, 7) {
		return "", fmt.Errorf("%w: %q is not a commit id", ErrEdgeTarget, rev)
	}
	// The sha media type answers with the bare id: forty bytes instead of a
	// commit object with its whole diff.
	resp, err := apiGet(ctx, fmt.Sprintf("/repos/%s/%s/commits/%s", repoOwner, repoName, rev),
		"application/vnd.github.sha")
	if err != nil {
		return "", fmt.Errorf("asking GitHub for commit %s: %w", rev, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	switch resp.StatusCode {
	case http.StatusOK:
		full := strings.ToLower(strings.TrimSpace(string(body)))
		if !IsFullCommit(full) || !strings.HasPrefix(full, rev) {
			return "", fmt.Errorf("GitHub answered commit %s with %q", rev, full)
		}
		return full, nil
	case http.StatusNotFound, http.StatusUnprocessableEntity:
		// 422 is "No commit found for SHA"; 404 a ref that does not exist.
		return "", fmt.Errorf("%w: %s/%s has no commit %s", ErrCommitNotFound, repoOwner, repoName, rev)
	}
	return "", fmt.Errorf("asking GitHub for commit %s: HTTP %d", rev, resp.StatusCode)
}

// EdgeStatus classifies what is known about one commit's edge build.
type EdgeStatus string

const (
	// EdgePublished: the manifest is there.
	EdgePublished EdgeStatus = "published"
	// EdgeNoCommit: the build names no commit — a release, or bare "dev".
	EdgeNoCommit EdgeStatus = "no_commit"
	// EdgeDirty: the build was made from a tree with uncommitted changes.
	EdgeDirty EdgeStatus = "dirty"
	// EdgeUnpushed: GitHub has no such commit.
	EdgeUnpushed EdgeStatus = "unpushed"
	// EdgeNoCI: no CI run on main exists for the commit.
	EdgeNoCI EdgeStatus = "no_ci"
	// EdgeCIRunning: CI is queued or running on it.
	EdgeCIRunning EdgeStatus = "ci_running"
	// EdgeCIFailed: CI finished on it without succeeding.
	EdgeCIFailed EdgeStatus = "ci_failed"
	// EdgePublishing: CI passed and the edge workflow has not finished.
	EdgePublishing EdgeStatus = "publishing"
	// EdgePublishFailed: the edge workflow failed for it.
	EdgePublishFailed EdgeStatus = "publish_failed"
	// EdgePruned: it was published and has been pruned since.
	EdgePruned EdgeStatus = "pruned"
	// EdgeUnknown: GitHub could not be asked.
	EdgeUnknown EdgeStatus = "unknown"
)

// EdgeBuild is what is known about the edge build of one build version.
type EdgeBuild struct {
	// Version is the build that was asked about, e.g. "dev+g8b418e2".
	Version string
	// Short is the commit prefix Version names; Commit the full id, once
	// GitHub has resolved it.
	Short, Commit string
	Status        EdgeStatus
	// Manifest is the published build's manifest when Status is
	// EdgePublished. Read, not verified: see FetchEdgeManifest.
	Manifest EdgeManifest
	// RunURL is the workflow run the reason refers to, when there is one.
	RunURL string
	// Err is the failure behind EdgeUnknown.
	Err error
}

// Published reports whether the build can be offered.
func (b EdgeBuild) Published() bool { return b.Status == EdgePublished }

// Target is the upgrade target naming the build: "edge:<full commit>". Empty
// unless the commit is known.
func (b EdgeBuild) Target() string {
	if b.Commit == "" {
		return ""
	}
	return EdgeTarget(b.Commit)
}

// Label names the build for a person: the short commit.
func (b EdgeBuild) Label() string {
	switch {
	case b.Short != "":
		return b.Short
	case len(b.Commit) >= 7:
		return b.Commit[:7]
	}
	return b.Version
}

// Reason says, in one sentence an operator can act on, why the build is not
// offered — or that it is.
func (b EdgeBuild) Reason() string {
	short := b.Label()
	run := ""
	if b.RunURL != "" {
		run = " (" + b.RunURL + ")"
	}
	switch b.Status {
	case EdgePublished:
		return fmt.Sprintf("CI built and signed commit %s from main, and it speaks protocol v%d.",
			short, b.Manifest.Protocol)
	case EdgeNoCommit:
		return fmt.Sprintf("this build (%s) names no commit, so no edge build can match it.", b.Version)
	case EdgeDirty:
		return fmt.Sprintf("this build (%s) was made from a tree with uncommitted changes, which no CI build "+
			"matches.", b.Version)
	case EdgeUnpushed:
		return fmt.Sprintf("the deploy built commit %s, which is not on GitHub: it was never pushed, so CI "+
			"cannot have built it. Push it to main.", short)
	case EdgeNoCI:
		return fmt.Sprintf("no CI run on main exists for commit %s: it is not on main, or it was pushed "+
			"together with newer commits (CI runs for the newest commit of a push only).", short)
	case EdgeCIRunning:
		return fmt.Sprintf("CI has not published commit %s yet: CI is still running on it%s, and its edge "+
			"build is published when it passes.", short, run)
	case EdgeCIFailed:
		return fmt.Sprintf("CI failed on commit %s%s, so no edge build was published for it.", short, run)
	case EdgePublishing:
		return fmt.Sprintf("CI passed on commit %s and has not published it yet: the edge workflow is "+
			"building and signing it%s.", short, run)
	case EdgePublishFailed:
		return fmt.Sprintf("CI passed on commit %s, but the edge workflow that publishes it failed%s.", short, run)
	case EdgePruned:
		return fmt.Sprintf("commit %s's edge build was published and has since been pruned: the edge release "+
			"keeps the newest %d commits' builds.", short, EdgeRetainedCommits)
	}
	if b.Err != nil {
		return fmt.Sprintf("whether CI has published commit %s could not be checked: %v.", short, b.Err)
	}
	return fmt.Sprintf("whether CI has published commit %s could not be checked.", short)
}

// ResolveEdgeBuild finds out whether an edge build of version exists, and if
// not, why. commit is the full id when the caller already knows it ("" to
// resolve it from version). It never returns an error: an unanswerable
// question is EdgeUnknown, with Err set.
func ResolveEdgeBuild(ctx context.Context, version, commit string) EdgeBuild {
	return resolveEdgeBuild(ctx, edgeDownloadBase(), version, commit)
}

func resolveEdgeBuild(ctx context.Context, base, version, commit string) EdgeBuild {
	b := EdgeBuild{Version: strings.TrimSpace(version), Commit: strings.ToLower(strings.TrimSpace(commit))}
	if strings.HasSuffix(b.Version, ".dirty") {
		b.Status = EdgeDirty
		return b
	}
	short, ok := VersionCommit(b.Version)
	if !ok && b.Commit == "" {
		b.Status = EdgeNoCommit
		return b
	}
	b.Short = short
	if b.Commit == "" {
		full, err := ResolveCommit(ctx, short)
		switch {
		case errors.Is(err, ErrCommitNotFound):
			b.Status = EdgeUnpushed
			return b
		case err != nil:
			b.Status, b.Err = EdgeUnknown, err
			return b
		}
		b.Commit = full
	}
	if b.Short == "" && len(b.Commit) >= 7 {
		b.Short = b.Commit[:7]
	}

	m, err := fetchEdgeManifestFrom(ctx, base, b.Commit)
	switch {
	case err == nil:
		b.Status, b.Manifest = EdgePublished, m
		return b
	case !errors.Is(err, ErrEdgeNotPublished):
		// A manifest that is there but wrong is not "not published yet"; it
		// is a build nobody should be offered.
		b.Status, b.Err = EdgeUnknown, err
		return b
	}

	ci, edge, err := workflowRuns(ctx, b.Commit)
	if err != nil {
		b.Status, b.Err = EdgeUnknown, err
		return b
	}
	switch {
	case ci == nil:
		b.Status = EdgeNoCI
	case ci.Status != "completed":
		b.Status, b.RunURL = EdgeCIRunning, ci.HTMLURL
	case ci.Conclusion != "success":
		b.Status, b.RunURL = EdgeCIFailed, ci.HTMLURL
	case edge == nil || edge.Status != "completed":
		b.Status = EdgePublishing
		if edge != nil {
			b.RunURL = edge.HTMLURL
		}
	case edge.Conclusion != "success":
		b.Status, b.RunURL = EdgePublishFailed, edge.HTMLURL
	default:
		b.Status, b.RunURL = EdgePruned, edge.HTMLURL
	}
	return b
}

// workflowRun is the subset of a GitHub Actions run this file reads.
type workflowRun struct {
	Path         string `json:"path"`
	Event        string `json:"event"`
	HeadBranch   string `json:"head_branch"`
	Status       string `json:"status"`
	Conclusion   string `json:"conclusion"`
	HTMLURL      string `json:"html_url"`
	RunNumber    int    `json:"run_number"`
	DisplayTitle string `json:"display_title"`
}

// workflowRuns returns the newest CI run on main for commit — a push to main —
// and the newest edge workflow run that built it. Either is nil when there is
// none.
//
// They are found differently. A CI run is filed under the commit it tested. An
// edge run is a workflow_run run, which GitHub files under main's head when it
// starts — a later commit, if main moved meanwhile — so it is found by its
// title, which edge.yml sets to "Edge build of <commit>" (its run-name).
func workflowRuns(ctx context.Context, commit string) (ci, edge *workflowRun, err error) {
	q := url.Values{"head_sha": {commit}, "per_page": {"50"}}
	runs, err := listRuns(ctx, fmt.Sprintf("/repos/%s/%s/actions/runs?%s", repoOwner, repoName, q.Encode()), commit)
	if err != nil {
		return nil, nil, err
	}
	// Newest first, as the API lists them; a re-run keeps its run number and
	// is listed once.
	for i := range runs {
		r := &runs[i]
		if strings.Contains(r.Path, "workflows/ci.yml") && r.Event == "push" && r.HeadBranch == "main" {
			ci = r
			break
		}
	}
	if ci == nil || ci.Status != "completed" || ci.Conclusion != "success" {
		return ci, nil, nil // the edge run is only worth a request once CI passed
	}
	runs, err = listRuns(ctx, fmt.Sprintf("/repos/%s/%s/actions/workflows/edge.yml/runs?per_page=50",
		repoOwner, repoName), commit)
	if err != nil {
		return ci, nil, err
	}
	for i := range runs {
		if strings.Contains(runs[i].DisplayTitle, commit) {
			edge = &runs[i]
			break
		}
	}
	return ci, edge, nil
}

// listRuns fetches one page of workflow runs.
func listRuns(ctx context.Context, path, commit string) ([]workflowRun, error) {
	resp, err := apiGet(ctx, path, "")
	if err != nil {
		return nil, fmt.Errorf("asking GitHub for the workflow runs of %s: %w", commit, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("asking GitHub for the workflow runs of %s: HTTP %d", commit, resp.StatusCode)
	}
	var page struct {
		Runs []workflowRun `json:"workflow_runs"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(&page); err != nil {
		return nil, fmt.Errorf("decoding the workflow runs of %s: %w", commit, err)
	}
	return page.Runs, nil
}
