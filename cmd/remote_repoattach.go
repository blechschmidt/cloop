package cmd

// Choosing the credential a project's repositories are reached through (Task
// 20417), for `cloop remote init` and `cloop remote repos add`.
//
// The order is the one the task names: the developer's own GitHub App
// installation first, then the organisation's App where they may grant it,
// then a GitHub token of their own — but only where the hub's git proxy guards
// it, since otherwise the token itself would sit in the sandbox, whole. Each
// App is asked which repositories it actually reaches (GitHub's inventory, via
// the hub), so a repository is never granted through an App that cannot see it.
//
// What the developer may not grant themselves becomes a request instead: an
// approver with secret.grant mints the grant, and the request id and who can
// approve it are reported. Whether they may is the hub's decision — a grant the
// hub refuses for want of secret.grant is turned into a request; nothing here
// predicts a permission and acts on the prediction.

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/gitremote"
	"github.com/blechschmidt/cloop/pkg/hubclient"
)

// repoAttachOptions says how repositories are to be attached.
type repoAttachOptions struct {
	// Secret names the credential to use; empty chooses one.
	Secret string
	// Access is read or write.
	Access string
	// Branches limits where a write grant may push.
	Branches []string
	// TTL is the grant's lifetime; zero takes the hub's default.
	TTL time.Duration
	// Justification is the reason a request gives, when one has to be filed.
	Justification string
}

// repoAttachResult is what attaching did.
type repoAttachResult struct {
	Assigned  []hubclient.RepoAssignment `json:"assigned,omitempty"`
	Requested []hubclient.GrantRequest   `json:"requested,omitempty"`
	// Already lists repositories the project could reach before.
	Already []string `json:"already,omitempty"`
	// Unreached lists repositories no credential the caller may use or ask
	// for reaches.
	Unreached []string `json:"unreached,omitempty"`
	Notes     []string `json:"notes,omitempty"`
}

// repoAccessPermissions mirrors the hub's two access words (githubapp_api.go):
// read is contents:read; write adds what pushing a branch and opening a pull
// request take, and nothing more.
func repoAccessPermissions(access string) ([]string, error) {
	switch strings.ToLower(strings.TrimSpace(access)) {
	case "", "read":
		return []string{"contents:read"}, nil
	case "write":
		return []string{"contents:write", "pull_requests:write"}, nil
	}
	return nil, fmt.Errorf("--access %q: want read or write", access)
}

// repoCovered reports whether an allowlist entry reaches repo: an exact name
// (case-insensitive, as GitHub's are), owner/*, or *.
func repoCovered(pattern, repo string) bool {
	pattern, repo = strings.ToLower(strings.TrimSpace(pattern)), strings.ToLower(repo)
	switch {
	case pattern == "*" || pattern == repo:
		return true
	case strings.HasSuffix(pattern, "/*"):
		return strings.HasPrefix(repo, strings.TrimSuffix(pattern, "*"))
	}
	return false
}

// credentialChoice is one credential and the repositories it will be asked to
// reach.
type credentialChoice struct {
	ref   string // what the hub is sent: the secret's id
	name  string // what a person is shown
	repos []string
	// refusal is the hub's refusal to grant it, when it is to be requested
	// for that reason.
	refusal error
}

// attachRepositories grants repos to the project p, choosing the credential as
// the package comment describes.
func attachRepositories(ctx context.Context, c *hubclient.Client, p hubclient.Project, repos []gitremote.Repo,
	opt repoAttachOptions) (*repoAttachResult, error) {
	res := &repoAttachResult{}
	perms, err := repoAccessPermissions(opt.Access)
	if err != nil {
		return res, err
	}
	write := strings.EqualFold(strings.TrimSpace(opt.Access), "write")
	if len(opt.Branches) > 0 && !write {
		return res, fmt.Errorf("--branch limits where pushes may go, so it needs --access write")
	}
	panel, err := c.ProjectRepositories(ctx, p.Idx)
	if err != nil {
		return res, remoteErr(c, err)
	}

	// What the project reaches already, at the access asked for, is left
	// alone: a second grant for the same repository is one more thing to
	// revoke and changes nothing.
	var remaining []string
	for _, r := range repos {
		name := r.FullName()
		if via := reachedThrough(panel.Assignments, name, write); via != "" {
			res.Already = append(res.Already, name)
			res.Notes = append(res.Notes, fmt.Sprintf("%s is already reachable through %s", name, via))
			continue
		}
		remaining = append(remaining, name)
	}
	if len(remaining) == 0 {
		return res, nil
	}

	var plan []credentialChoice
	var toRequest []credentialChoice
	if ref := strings.TrimSpace(opt.Secret); ref != "" {
		plan = []credentialChoice{{ref: ref, name: ref, repos: remaining}}
	} else {
		plan, toRequest, remaining = chooseCredentials(ctx, c, p, panel, remaining, res)
		res.Unreached = append(res.Unreached, remaining...)
	}

	ttlMinutes := int(opt.TTL / time.Minute)
	for _, choice := range plan {
		a, err := c.AssignRepositories(ctx, p.Idx, hubclient.AssignRepositoriesRequest{
			Secret: choice.ref, Repos: choice.repos, Access: strings.ToLower(strings.TrimSpace(opt.Access)),
			Branches: opt.Branches, TTLMinutes: ttlMinutes,
		})
		if err == nil {
			res.Assigned = append(res.Assigned, a)
			if a.Kind == "github_pat" && !panel.GitProxy.Running {
				res.Notes = append(res.Notes, fmt.Sprintf("%s is a token, and this hub runs no git proxy: the sandbox "+
					"receives the token itself, with everything it can reach", a.SecretName))
			}
			continue
		}
		// Refused because granting this credential takes secret.grant: ask
		// an approver for it instead, which is what the hub would let this
		// caller do.
		if ae, ok := hubclient.AsAPIError(err); ok && ae.Status == 403 && needsGrantPermission(ae) {
			choice.refusal = err
			toRequest = append(toRequest, choice)
			continue
		}
		return res, fmt.Errorf("attach %s through %s: %w", strings.Join(choice.repos, ", "), choice.name, remoteErr(c, err))
	}
	for _, choice := range toRequest {
		if strings.TrimSpace(opt.Justification) == "" {
			return res, fmt.Errorf("%s needs an approver to grant %s, and a request needs a reason: pass --justification",
				choice.name, strings.Join(choice.repos, ", "))
		}
		req, err := c.RequestGrant(ctx, hubclient.FileGrantRequest{
			SecretRef: choice.ref, Subject: "project:" + p.Path, TTLMinutes: ttlMinutes,
			Justification: opt.Justification, Repos: choice.repos, Permissions: perms, Branches: opt.Branches,
		})
		if err != nil {
			// A caller who may not even ask is told what the grant itself
			// was refused for — the dashboard's answer to the same click —
			// rather than about the request they never chose to make.
			if ae, ok := hubclient.AsAPIError(err); ok && ae.Status == 403 && choice.refusal != nil {
				return res, fmt.Errorf("attach %s through %s: %w", strings.Join(choice.repos, ", "), choice.name,
					remoteErr(c, choice.refusal))
			}
			return res, fmt.Errorf("request %s for %s: %w", choice.name, strings.Join(choice.repos, ", "), remoteErr(c, err))
		}
		res.Requested = append(res.Requested, req)
	}
	return res, nil
}

// needsGrantPermission reports whether a refusal is for want of secret.grant —
// the one refusal a request answers.
func needsGrantPermission(ae *hubclient.APIError) bool {
	if p := ae.Detail("required_permission"); p != "" {
		return p == "secret.grant"
	}
	return strings.Contains(ae.Message, "secret.grant")
}

// reachedThrough names the grant through which the project already reaches
// repo at the access wanted, or "".
func reachedThrough(assignments []hubclient.RepoAssignment, repo string, write bool) string {
	for _, a := range assignments {
		if write && a.Access != "write" {
			continue
		}
		for _, pattern := range a.Repos {
			if repoCovered(pattern, repo) {
				return fmt.Sprintf("%s (grant %s, %s)", a.SecretName, a.GrantID, a.Access)
			}
		}
	}
	return ""
}

// chooseCredentials picks, for each repository, the credential that reaches
// it: returns what to grant, what to ask for, and what nothing reaches.
func chooseCredentials(ctx context.Context, c *hubclient.Client, p hubclient.Project, panel *hubclient.ProjectRepositories,
	repos []string, res *repoAttachResult) (plan, request []credentialChoice, unreached []string) {
	// What the caller owns, for the order and for their tokens. A caller who
	// may not list secrets owns none to offer.
	var owned map[string]hubclient.Secret
	var pats []hubclient.Secret
	if list, err := c.Secrets(ctx); err == nil {
		owned = map[string]hubclient.Secret{}
		for _, s := range list.Secrets {
			if s.Mine && s.Personal {
				owned[s.ID] = s
				if s.Kind == "github_pat" {
					pats = append(pats, s)
				}
			}
		}
	}
	apps := append([]hubclient.RepoApp(nil), panel.Apps...)
	sort.SliceStable(apps, func(i, j int) bool {
		_, mi := owned[apps[i].ID]
		_, mj := owned[apps[j].ID]
		if mi != mj {
			return mi
		}
		return apps[i].Name < apps[j].Name
	})

	remaining := append([]string(nil), repos...)
	assign := func(ref, name string, covers func(string) bool) {
		var mine, rest []string
		for _, r := range remaining {
			if covers(r) {
				mine = append(mine, r)
			} else {
				rest = append(rest, r)
			}
		}
		if len(mine) > 0 {
			plan = append(plan, credentialChoice{ref: ref, name: name, repos: mine})
		}
		remaining = rest
	}

	// GitHub Apps, asked which repositories they reach.
	var unchecked []hubclient.RepoApp
	for _, app := range apps {
		if len(remaining) == 0 {
			break
		}
		avail, err := c.AvailableRepositories(ctx, p.Idx, app.ID)
		if err != nil {
			unchecked = append(unchecked, app)
			res.Notes = append(res.Notes, fmt.Sprintf("could not ask which repositories the GitHub App %s reaches: %s",
				app.Name, firstLine(remoteErr(c, err).Error())))
			continue
		}
		reach := map[string]bool{}
		for _, r := range avail {
			reach[strings.ToLower(r.FullName)] = true
		}
		assign(app.ID, "the GitHub App "+app.Name, func(r string) bool { return reach[strings.ToLower(r)] })
	}

	// A token of the caller's own, guarded by the git proxy.
	if len(remaining) > 0 && len(pats) > 0 {
		sort.Slice(pats, func(i, j int) bool { return pats[i].Name < pats[j].Name })
		if panel.GitProxy.Running {
			pat := pats[0]
			assign(pat.ID, "your token "+pat.Name, func(string) bool { return true })
		} else {
			res.Notes = append(res.Notes, fmt.Sprintf("your GitHub token %s was not used: this hub runs no git proxy, "+
				"so the token itself would be handed to the sandbox — name it with --secret (or --repo-secret) "+
				"to use it anyway", pats[0].Name))
		}
	}

	// An App that could not be asked, when it is the only one: granted, with
	// a note, rather than leaving the repositories unreached.
	if len(remaining) > 0 && len(unchecked) == 1 && len(apps) == 1 {
		app := unchecked[0]
		res.Notes = append(res.Notes, fmt.Sprintf("granted through the GitHub App %s without confirming it reaches %s",
			app.Name, strings.Join(remaining, ", ")))
		assign(app.ID, "the GitHub App "+app.Name, func(string) bool { return true })
	}

	// The organisation's App the caller may not grant: ask an approver for it.
	if len(remaining) > 0 {
		if catalog, err := c.SecretCatalog(ctx); err == nil {
			offered := map[string]bool{}
			for _, a := range panel.Apps {
				offered[a.ID] = true
			}
			var askable []hubclient.CatalogEntry
			for _, e := range catalog {
				if e.Kind == "github_app" && !offered[e.ID] {
					askable = append(askable, e)
				}
			}
			switch len(askable) {
			case 0:
			case 1:
				request = append(request, credentialChoice{ref: askable[0].ID, name: "the GitHub App " + askable[0].Name, repos: remaining})
				remaining = nil
			default:
				names := make([]string, 0, len(askable))
				for _, e := range askable {
					names = append(names, e.Name)
				}
				res.Notes = append(res.Notes, fmt.Sprintf("%d GitHub Apps on this hub need an approver (%s); "+
					"name the one that reaches %s with --secret (or --repo-secret) to request it",
					len(askable), strings.Join(names, ", "), strings.Join(remaining, ", ")))
			}
		}
	}
	return plan, request, remaining
}

// firstLine is the first line of s.
func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}
