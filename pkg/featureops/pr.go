package featureops

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/feature"
	gh "github.com/blechschmidt/cloop/pkg/github"
	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/state"
)

// ErrNothingToPropose is returned when a feature's branch has no commits its
// base does not already have. GitHub refuses such a pull request too, but
// with a message about "no commits between" two refs the user never named.
var ErrNothingToPropose = errors.New("the feature has no commits that its base branch does not already have — there is nothing to propose yet")

// ErrNoToken is returned when no credential for the forge's API was found.
var ErrNoToken = errors.New("no GitHub token was found to open the pull request with")

// EnvToken names the variable a caller — the hub, dispatching this for a
// project it can mint a token for — uses to hand this process a token for
// the forge's API. It is read before the ambient GITHUB_TOKEN so that a
// deliberate hand-over is never shadowed by whatever the environment holds.
const EnvToken = "CLOOP_GITHUB_TOKEN"

// EnvAPIURL overrides the forge API endpoint (GitHub Enterprise, tests).
const EnvAPIURL = "CLOOP_GITHUB_API_URL"

// PROptions describes a pull request to open for a feature.
type PROptions struct {
	FeatureDir string
	// Title and Body override the generated ones.
	Title string
	Body  string
	// Base overrides the feature's recorded base branch.
	Base  string
	Draft bool
	// Remote is the git remote to push to and to derive the repository from.
	// Empty means origin.
	Remote string
	// NoPush skips the push, for a branch that is already published.
	NoPush bool
	// Token is an explicit API token; empty resolves one (see ResolveToken).
	Token string
	// Repo overrides the owner/name derived from the remote.
	Repo string
	// APIURL overrides the forge API base URL.
	APIURL string
	// Now is the clock; nil uses time.Now.
	Now func() time.Time
}

// PRResult reports what OpenPR did.
type PRResult struct {
	PR *feature.PR `json:"pr"`
	// Existing reports that the pull request was already open and was
	// returned rather than created.
	Existing bool `json:"existing"`
	Pushed   bool `json:"pushed"`
	// Ahead is how many commits the pull request carries.
	Ahead int `json:"ahead"`
	// Dirty lists uncommitted changes, which the pull request does not
	// contain. Reported rather than refused: the committed work is still
	// worth proposing, and the caller says so to the user.
	Dirty []string `json:"dirty,omitempty"`
	// TokenSource names where the API token came from, never the token.
	TokenSource string `json:"token_source"`
}

// Remote is a parsed git remote on a forge.
type Remote struct {
	// Host is the forge's host name, e.g. github.com.
	Host string
	// Repo is owner/name.
	Repo string
	// HTTPS reports that the remote is reached over https, which is when a
	// token can authenticate the push itself.
	HTTPS bool
}

// ParseRemote extracts the forge host and owner/name from a git remote URL:
// https://host/owner/name(.git), ssh://[user@]host[:port]/owner/name(.git)
// and the scp-like [user@]host:owner/name(.git).
func ParseRemote(raw string) (Remote, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return Remote{}, errors.New("the remote URL is empty")
	}
	var host, path string
	var https bool
	switch {
	case strings.Contains(raw, "://"):
		u, err := url.Parse(raw)
		if err != nil {
			return Remote{}, fmt.Errorf("cannot parse remote %q", redactRemote(raw))
		}
		switch u.Scheme {
		case "https", "http":
			https = u.Scheme == "https"
		case "ssh", "git+ssh", "ssh+git":
		default:
			return Remote{}, fmt.Errorf("remote %q is a %s URL, not a forge repository", redactRemote(raw), u.Scheme)
		}
		host = u.Hostname()
		path = u.Path
	default:
		// scp-like: [user@]host:path — but not a Windows drive or a local
		// path, neither of which has a colon before its first slash. The
		// user part is whatever precedes the host, so the @ that ends it is
		// looked for only before the colon.
		colon := strings.Index(raw, ":")
		slash := strings.Index(raw, "/")
		if colon < 0 || (slash >= 0 && slash < colon) {
			return Remote{}, fmt.Errorf("remote %q is a local path, not a forge repository", redactRemote(raw))
		}
		host = raw[:colon]
		if at := strings.LastIndex(host, "@"); at >= 0 {
			host = host[at+1:]
		}
		path = raw[colon+1:]
	}
	path = strings.TrimSuffix(strings.Trim(path, "/"), ".git")
	parts := strings.Split(path, "/")
	if host == "" || len(parts) != 2 || !forgeNameRe.MatchString(parts[0]) || !forgeNameRe.MatchString(parts[1]) {
		return Remote{}, fmt.Errorf("cannot find owner/name in remote %q", redactRemote(raw))
	}
	return Remote{Host: strings.ToLower(host), Repo: parts[0] + "/" + parts[1], HTTPS: https}, nil
}

// forgeNameRe is what an owner or repository name on GitHub may contain.
// Anything else in that position means the remote was not parsed as intended.
var forgeNameRe = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)

// redactRemote drops the user part of a remote URL for an error message. A
// remote can carry a credential there (https://user:token@host/…), and these
// messages reach the dashboard and, for an automatic pull request, the
// feature's event journal.
func redactRemote(raw string) string {
	if strings.Contains(raw, "://") {
		if u, err := url.Parse(raw); err == nil && u.User != nil {
			u.User = nil
			return u.String()
		}
		scheme, rest, _ := strings.Cut(raw, "://")
		if at := strings.LastIndex(rest, "@"); at >= 0 {
			return scheme + "://…@" + rest[at+1:]
		}
		return raw
	}
	if at := strings.LastIndex(raw, "@"); at >= 0 {
		return "…@" + raw[at+1:]
	}
	return raw
}

// tokenMayReach reports whether an ambient GitHub token — one from the
// environment, a config file or the hub — may be sent to host. It is the
// guard against handing a GitHub credential to whatever server a project's
// origin happens to name: a GitLab remote, a self-hosted forge, a typo.
// github.com is always a GitHub host; anything else only when the operator
// named it explicitly as the API endpoint (GitHub Enterprise).
//
// Credentials that git's own helpers or the gh CLI return for a host are
// scoped to that host already, and do not need this check.
func tokenMayReach(host, apiOverride string) bool {
	switch strings.ToLower(host) {
	case "github.com", "www.github.com", "api.github.com":
		return true
	}
	if host == "" || apiOverride == "" {
		return false
	}
	u, err := url.Parse(apiOverride)
	return err == nil && strings.EqualFold(u.Hostname(), host)
}

// APIBaseURL returns the REST endpoint for a forge host: api.github.com for
// github.com, and the GitHub Enterprise convention otherwise.
func APIBaseURL(host string) string {
	if host == "" || host == "github.com" || host == "www.github.com" {
		return "https://api.github.com"
	}
	return "https://" + host + "/api/v3"
}

// ResolveToken finds a token for the forge's API, and names where it came
// from. The order runs from most to least specific to this project:
//
//  1. explicit — the --token flag;
//  2. GITHUB_TOKEN and GH_TOKEN — what a grant or a CI job exports;
//  3. github.token in the feature's config;
//  4. git's own credential helpers for this repository — the host's
//     credential store, or the scoped helper a secret grant installs;
//  5. the gh CLI's login for the host;
//  6. CLOOP_GITHUB_TOKEN — the hub's own token, handed over as a last resort,
//     so that a project's credentials are always preferred to the operator's.
//
// Sources 2, 3 and 6 are only consulted for a host a GitHub token may be sent
// to (see tokenMayReach). Only the source is ever reported; the token itself
// stays in this process.
func ResolveToken(ctx context.Context, dir string, remote Remote, explicit, apiOverride string) (token, source string) {
	if t := strings.TrimSpace(explicit); t != "" {
		return t, "flag"
	}
	ambient := tokenMayReach(remote.Host, apiOverride)
	if ambient {
		for _, env := range []string{"GITHUB_TOKEN", "GH_TOKEN"} {
			if t := strings.TrimSpace(os.Getenv(env)); t != "" {
				return t, env
			}
		}
		if cfg, err := config.Load(dir); err == nil && cfg != nil {
			if t := strings.TrimSpace(cfg.GitHub.Token); t != "" {
				return t, "config github.token"
			}
		}
	}
	if t := credentialFill(ctx, dir, remote); t != "" {
		return t, "git credential helper"
	}
	if t := ghAuthToken(ctx, remote.Host); t != "" {
		return t, "gh auth token"
	}
	if ambient {
		if t := strings.TrimSpace(os.Getenv(EnvToken)); t != "" {
			return t, EnvToken
		}
	}
	return "", ""
}

// credentialFill asks git's configured credential helpers for this
// repository's password. It never prompts: GIT_TERMINAL_PROMPT=0, and every
// askpass hook git consults is blanked for the call.
func credentialFill(ctx context.Context, dir string, remote Remote) string {
	if remote.Host == "" {
		return ""
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "git",
		"-c", "core.askPass=", "-c", "credential.interactive=never",
		"credential", "fill")
	cmd.Dir = dir
	cmd.Env = gitEnv("GIT_ASKPASS=", "SSH_ASKPASS=")
	cmd.Stdin = strings.NewReader("protocol=https\nhost=" + remote.Host + "\npath=" + remote.Repo + ".git\n\n")
	out, err := cmd.Output()
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(out), "\n") {
		if v, ok := strings.CutPrefix(line, "password="); ok {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

// ghAuthToken asks the gh CLI for its token, when gh is installed.
func ghAuthToken(ctx context.Context, host string) string {
	bin, err := exec.LookPath("gh")
	if err != nil {
		return ""
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	args := []string{"auth", "token"}
	if host != "" {
		args = append(args, "--hostname", host)
	}
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Env = append(os.Environ(), "GH_PROMPT_DISABLED=1")
	out, err := cmd.Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

// OpenPR publishes a feature: it pushes the feature's branch and opens a pull
// request from it into the feature's base branch, recording the result in the
// feature's record.
//
// It is idempotent. Asked again for a feature whose pull request is still
// open, it pushes whatever was committed since — which updates that pull
// request — and returns it rather than failing on GitHub's "already exists".
func OpenPR(ctx context.Context, opts PROptions) (*PRResult, error) {
	now := time.Now
	if opts.Now != nil {
		now = opts.Now
	}
	dir := opts.FeatureDir
	meta, err := feature.LoadMeta(dir)
	if err != nil {
		return nil, fmt.Errorf("%s is not a feature: %w", dir, err)
	}
	base := strings.TrimSpace(opts.Base)
	if base == "" {
		base = meta.Base
	}
	if err := validBranchName(ctx, dir, base); err != nil {
		return nil, fmt.Errorf("base: %w", err)
	}
	remoteName := strings.TrimSpace(opts.Remote)
	if remoteName == "" {
		remoteName = "origin"
	}
	if strings.HasPrefix(remoteName, "-") {
		return nil, fmt.Errorf("remote name %q may not start with a dash", remoteName)
	}

	// The worktree must still be on the feature's branch: a pull request is
	// opened from the branch, and a harness that checked out something else
	// would otherwise have its commits silently left out.
	head, err := runGit(ctx, dir, "symbolic-ref", "--quiet", "--short", "HEAD")
	if err != nil || head != meta.Branch {
		return nil, fmt.Errorf("the feature's worktree is not on its branch %s (HEAD is %q) — check it out again before opening a pull request", meta.Branch, head)
	}

	baseRef, err := resolveBase(ctx, dir, base)
	if err != nil {
		return nil, err
	}
	ahead, err := aheadCount(ctx, dir, baseRef, "refs/heads/"+meta.Branch)
	if err != nil {
		return nil, fmt.Errorf("compare %s with %s: %w", meta.Branch, base, err)
	}
	if ahead == 0 {
		return nil, ErrNothingToPropose
	}
	headSHA, err := runGit(ctx, dir, "rev-parse", "refs/heads/"+meta.Branch)
	if err != nil {
		return nil, err
	}
	res := &PRResult{Ahead: ahead}
	if dirty, derr := dirtyFiles(ctx, dir); derr == nil {
		res.Dirty = dirty
	}

	remote, perr := remoteOf(ctx, dir, remoteName)
	if errors.Is(perr, errNoRemote) {
		return nil, perr
	}
	if opts.Repo != "" {
		// An explicit repository stands in for a remote that does not name
		// one — a local mirror, a test fixture — so the parse error is moot.
		remote.Repo = opts.Repo
		perr = nil
	}
	if perr != nil {
		return nil, fmt.Errorf("cannot open a pull request: %w", perr)
	}

	override := strings.TrimSpace(opts.APIURL)
	if override == "" {
		override = strings.TrimSpace(os.Getenv(EnvAPIURL))
	}
	token, source := ResolveToken(ctx, dir, remote, opts.Token, override)
	res.TokenSource = source

	if !opts.NoPush {
		if err := push(ctx, dir, remoteName, meta.Branch, remote, token, source); err != nil {
			return nil, err
		}
		res.Pushed = true
	}
	if token == "" {
		return res, fmt.Errorf("%w: the branch was pushed, but opening the pull request needs a token with pull-request access — "+
			"grant the project a GitHub repository with write access, set github.token in the project's config, "+
			"or export GITHUB_TOKEN", ErrNoToken)
	}

	api := override
	if api == "" {
		api = APIBaseURL(remote.Host)
	}
	client := gh.New(token, remote.Repo)
	client.BaseURL = strings.TrimRight(api, "/")

	record := func(p *gh.PR, existing bool) *PRResult {
		rec := &feature.PR{
			Number:    p.Number,
			URL:       p.HTMLURL,
			State:     prState(p),
			Repo:      remote.Repo,
			Head:      meta.Branch,
			Base:      base,
			HeadSHA:   headSHA,
			Draft:     p.Draft,
			CreatedAt: now().UTC(),
		}
		if existing && meta.PR != nil && meta.PR.Number == p.Number && !meta.PR.CreatedAt.IsZero() {
			rec.CreatedAt = meta.PR.CreatedAt
		}
		res.PR = rec
		res.Existing = existing
		return res
	}

	// A pull request this feature already opened, and that is still open, is
	// the answer — the push above has already updated it. So is one that was
	// merged with the branch where it is now: nothing has been committed
	// since, and a second pull request would propose the same work again.
	if meta.PR != nil && meta.PR.Number > 0 && meta.PR.Repo == remote.Repo {
		if p, gerr := client.GetPR(meta.PR.Number); gerr == nil {
			if p.State == "open" || (prState(p) == "merged" && meta.PR.HeadSHA == headSHA) {
				return saveRecord(dir, meta, record(p, true))
			}
		}
	}

	title := strings.TrimSpace(opts.Title)
	if title == "" {
		title = feature.PRTitle(meta)
	}
	body := opts.Body
	if strings.TrimSpace(body) == "" {
		body = feature.PRBody(meta, featureTasks(dir))
	}
	created, err := client.CreatePR(meta.Branch, base, title, body, opts.Draft)
	if err != nil {
		var apiErr *gh.APIError
		if errors.As(err, &apiErr) && apiErr.Unprocessable() {
			// Most often: one already exists for this head, opened by hand or
			// by an earlier call whose record was lost.
			if p, ferr := client.FindPRByHead(meta.Branch, "open"); ferr == nil && p != nil {
				return saveRecord(dir, meta, record(p, true))
			}
		}
		if errors.As(err, &apiErr) && (apiErr.Status == 401 || apiErr.Status == 403 || apiErr.Status == 404) {
			return res, fmt.Errorf("GitHub refused to open the pull request with the token from %s (%d) — "+
				"it needs pull-request write access to %s: %w", source, apiErr.Status, remote.Repo, err)
		}
		return res, fmt.Errorf("open the pull request: %w", err)
	}
	return saveRecord(dir, meta, record(created, false))
}

// RefreshPR re-reads a feature's pull request from the forge and records its
// current state — open, closed or merged — so the dashboard can say so.
func RefreshPR(ctx context.Context, dir string, token, apiURL string) (*feature.PR, error) {
	meta, err := feature.LoadMeta(dir)
	if err != nil {
		return nil, err
	}
	if meta.PR == nil || meta.PR.Number == 0 {
		return nil, errors.New("the feature has no pull request yet")
	}
	remote := Remote{Repo: meta.PR.Repo}
	if r, perr := remoteOf(ctx, dir, "origin"); perr == nil {
		remote.Host = r.Host
		if remote.Repo == "" {
			remote.Repo = r.Repo
		}
	}
	override := strings.TrimSpace(apiURL)
	if override == "" {
		override = strings.TrimSpace(os.Getenv(EnvAPIURL))
	}
	tok, _ := ResolveToken(ctx, dir, remote, token, override)
	api := override
	if api == "" {
		api = APIBaseURL(remote.Host)
	}
	client := gh.New(tok, remote.Repo)
	client.BaseURL = strings.TrimRight(api, "/")
	p, err := client.GetPR(meta.PR.Number)
	if err != nil {
		return nil, err
	}
	meta.PR.State = prState(p)
	meta.PR.URL = p.HTMLURL
	meta.PR.Draft = p.Draft
	if p.Head.SHA != "" {
		meta.PR.HeadSHA = p.Head.SHA
	}
	if err := feature.SaveMeta(dir, meta); err != nil {
		return nil, err
	}
	return meta.PR, nil
}

// errNoRemote reports that the repository has no remote of the given name.
var errNoRemote = errors.New("no such remote")

// remoteOf identifies the forge repository behind a git remote.
//
// The URL as configured is tried first, then as git expands it. The order
// matters in both directions: a url.<base>.insteadOf rewrite can point a
// GitHub remote at a mirror or a local path that names no repository — the
// configured URL is still the forge's identity — while a shorthand such as
// "gh:owner/name" only becomes a URL once expanded.
func remoteOf(ctx context.Context, dir, name string) (Remote, error) {
	raw, err := runGit(ctx, dir, "config", "--get", "remote."+name+".url")
	if err != nil || strings.TrimSpace(raw) == "" {
		return Remote{}, fmt.Errorf("%w: the repository has no remote %q to publish the feature to", errNoRemote, name)
	}
	r, perr := ParseRemote(raw)
	if perr == nil {
		return r, nil
	}
	if expanded, err := runGit(ctx, dir, "remote", "get-url", name); err == nil && expanded != raw {
		if r, err := ParseRemote(expanded); err == nil {
			return r, nil
		}
	}
	return Remote{}, perr
}

// prState maps GitHub's state onto the three the dashboard distinguishes.
func prState(p *gh.PR) string {
	if p.Merged || p.MergedAt != nil {
		return "merged"
	}
	if p.State == "" {
		return "open"
	}
	return p.State
}

// saveRecord stores the pull request on the feature's record.
func saveRecord(dir string, meta *feature.Meta, res *PRResult) (*PRResult, error) {
	meta.PR = res.PR
	if err := feature.SaveMeta(dir, meta); err != nil {
		return res, fmt.Errorf("the pull request is open at %s, but recording it failed: %w", res.PR.URL, err)
	}
	return res, nil
}

// featureTasks loads the feature's plan for the pull request body. A feature
// whose state cannot be read still gets a pull request, just without the
// task list.
func featureTasks(dir string) []*pm.Task {
	st, err := state.LoadLite(dir)
	if err != nil || st.Plan == nil {
		return nil
	}
	return st.Plan.Tasks
}

// push publishes the feature's branch under its own name.
//
// Credentials are git's business first: an ssh remote uses the host's keys,
// and an https remote whatever credential helper is configured — the host's
// store, or the scoped helper a secret grant installs. That is the project's
// own authority, branch restrictions and all, and it is tried alone first.
//
// Only if that push fails is the API token offered for the push as well —
// when it is one git could not have used by itself (a flag, the environment, a
// config file, the hub's) and the remote is https. It travels as an HTTP header
// passed in the environment, never on the command line, where any user on the
// host could read it from the process table.
func push(ctx context.Context, dir, remoteName, branch string, remote Remote, token, source string) error {
	ctx, cancel := context.WithTimeout(ctx, pushTimeout)
	defer cancel()
	ref := "refs/heads/" + branch
	args := []string{"push", "--porcelain", remoteName, ref + ":" + ref}
	_, err := runGitEnv(ctx, dir, nil, args...)
	if err == nil {
		return nil
	}
	if !remote.HTTPS || token == "" || source == "git credential helper" {
		return fmt.Errorf("push %s to %s: %w", branch, remoteName, err)
	}
	basic := base64.StdEncoding.EncodeToString([]byte("x-access-token:" + token))
	env := appendGitConfigEnv(os.Getenv("GIT_CONFIG_COUNT"),
		"http.https://"+remote.Host+"/.extraheader", "AUTHORIZATION: basic "+basic)
	if _, err2 := runGitEnv(ctx, dir, env, args...); err2 != nil {
		return fmt.Errorf("push %s to %s: %w; and again with the token from %s: %v", branch, remoteName, err, source, err2)
	}
	return nil
}

// appendGitConfigEnv adds one key/value to git's GIT_CONFIG_COUNT protocol
// without disturbing entries the environment already carries.
//
// The count is a single variable for the whole environment, and a sandbox's
// workspace delivery uses it too (pkg/executor's gitConfigEnv). Writing
// GIT_CONFIG_COUNT=1 would silently truncate those entries to the one added
// here — and, since exec keeps the last duplicate, overwrite their first key —
// so the new pair is numbered after the existing ones.
func appendGitConfigEnv(existingCount, key, value string) []string {
	n, err := strconv.Atoi(strings.TrimSpace(existingCount))
	if err != nil || n < 0 {
		n = 0
	}
	idx := strconv.Itoa(n)
	return []string{
		"GIT_CONFIG_COUNT=" + strconv.Itoa(n+1),
		"GIT_CONFIG_KEY_" + idx + "=" + key,
		"GIT_CONFIG_VALUE_" + idx + "=" + value,
	}
}
