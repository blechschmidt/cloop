package cmd

// `cloop remote repos` (Task 20417): the GitHub repositories a project may
// reach, from a terminal. These are the Repositories panel's own calls —
// GET, POST and DELETE /api/projects/{idx}/repositories, and
// /repositories/available — so a grant made here is issued to the project in
// the path and nothing else, and is authorised on that project exactly as the
// panel's Grant button is.

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/blechschmidt/cloop/pkg/gitremote"
	"github.com/blechschmidt/cloop/pkg/hubclient"
)

var (
	reposSecret        string
	reposAccess        string
	reposBranches      []string
	reposTTL           time.Duration
	reposJustification string
)

var remoteReposCmd = &cobra.Command{
	Use:   "repos",
	Short: "List, attach and withdraw a project's GitHub repositories",
	Long: `The GitHub repositories a project may reach, and through which credential.

A project's code is the repositories granted to it: its runs clone them through
the hub's git proxy where the hub runs one. Attaching uses a GitHub App
installation the hub holds — yours first, then the organisation's where you may
grant it — or a GitHub token of your own that the git proxy guards. A credential
you may not grant yourself is requested from an approver instead.`,
}

var remoteReposListCmd = &cobra.Command{
	Use:   "list <project>",
	Short: "List the repositories a project can reach",
	Args:  cobra.ExactArgs(1),
	RunE:  runRemoteReposList,
}

var remoteReposAddCmd = &cobra.Command{
	Use:   "add <project> <owner/name>...",
	Short: "Grant a project access to GitHub repositories",
	Long: `Grant a project access to one or more GitHub repositories.

    cloop remote repos add api acme/api acme/api-docs
    cloop remote repos add api acme/api --access write --branch 'cloop/*'
    cloop remote repos add api acme/api --secret acme-github-app

Access is read-only unless --access write, which also allows opening pull
requests; --branch limits where pushes may go, and the hub's git proxy enforces it.
Without --secret the credential is chosen for you: a GitHub App the hub holds that
reaches the repository — yours first — then a token of yours the git proxy guards.
One you may not grant yourself is requested from an approver, with --justification
as the reason.`,
	Args: cobra.MinimumNArgs(2),
	RunE: runRemoteReposAdd,
}

var remoteReposRemoveCmd = &cobra.Command{
	Use:   "remove <project> <owner/name|grant-id>...",
	Short: "Withdraw a project's access to repositories",
	Long: `Withdraw a project's access to repositories, by repository or by grant id
(` + "`cloop remote repos list`" + ` shows both). Withdrawing one repository of a grant that
covers several replaces the grant with one without it; the rest keep working.
A grant that reaches other projects too is not this project's to withdraw.`,
	Args: cobra.MinimumNArgs(2),
	RunE: runRemoteReposRemove,
}

func runRemoteReposList(cmd *cobra.Command, args []string) error {
	c, err := remoteClient()
	if err != nil {
		return err
	}
	ctx := remoteContext(cmd)
	p, err := c.ResolveProject(ctx, args[0])
	if err != nil {
		return remoteErr(c, err)
	}
	panel, err := c.ProjectRepositories(ctx, p.Idx)
	if err != nil {
		return remoteErr(c, err)
	}
	out := cmd.OutOrStdout()
	if remoteJSON {
		return json.NewEncoder(out).Encode(panel)
	}
	if len(panel.Assignments) == 0 {
		fmt.Fprintf(out, "%s can reach no GitHub repository.\n", p.Name)
	} else {
		printAssignments(out, panel.Assignments)
	}
	if len(panel.Apps) > 0 {
		names := make([]string, 0, len(panel.Apps))
		for _, a := range panel.Apps {
			names = append(names, a.Name)
		}
		fmt.Fprintf(out, "\nGitHub Apps you may grant from: %s\n", strings.Join(names, ", "))
	}
	switch {
	case panel.GitProxy.Running:
		fmt.Fprintln(out, "The hub's git proxy guards these credentials: a sandbox never holds the token, and branch limits are enforced.")
	case panel.GitProxy.Required:
		fmt.Fprintln(out, "The hub's git proxy is configured but not running, so GitHub credentials are not delivered at all.")
	default:
		fmt.Fprintln(out, "This hub runs no git proxy: a sandbox receives the GitHub token it is granted.")
	}
	return nil
}

func printAssignments(out io.Writer, as []hubclient.RepoAssignment) {
	w := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "GRANT\tTHROUGH\tREPOSITORIES\tACCESS\tEXPIRES")
	for _, a := range as {
		access := a.Access
		if len(a.Branches) > 0 {
			access += " (" + strings.Join(a.Branches, ", ") + ")"
		}
		if a.BranchEnforcement != "" && a.BranchEnforcement != "enforced" {
			access += " [" + a.BranchEnforcement + "]"
		}
		via := a.SecretName
		if !a.Replaceable {
			via += " (shared grant)"
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n", a.GrantID, via, strings.Join(a.Repos, ", "), access, expiryText(a.ExpiresAt))
	}
	_ = w.Flush()
}

// expiryText renders a grant's expiry for a table.
func expiryText(t time.Time) string {
	if t.IsZero() {
		return "never"
	}
	return t.Local().Format("2006-01-02 15:04")
}

func runRemoteReposAdd(cmd *cobra.Command, args []string) error {
	repos, err := parseRepoArgs(args[1:])
	if err != nil {
		return err
	}
	c, err := remoteClient()
	if err != nil {
		return err
	}
	ctx := remoteContext(cmd)
	p, err := c.ResolveProject(ctx, args[0])
	if err != nil {
		return remoteErr(c, err)
	}
	res, err := attachRepositories(ctx, c, p, repos, repoAttachOptions{
		Secret: reposSecret, Access: reposAccess, Branches: reposBranches, TTL: reposTTL,
		Justification: reposJustification,
	})
	out := cmd.OutOrStdout()
	if remoteJSON {
		if jerr := json.NewEncoder(out).Encode(res); jerr != nil {
			return jerr
		}
	} else {
		printAttachResult(out, res)
	}
	if err != nil {
		return err
	}
	if len(res.Unreached) > 0 {
		return fmt.Errorf("no credential you may use or ask for reaches %s: connect a GitHub App that is installed on it, "+
			"or store a GitHub token of your own (Secrets panel, or `cloop secret` on the hub), then run this again",
			strings.Join(res.Unreached, ", "))
	}
	return nil
}

// printAttachResult reports what attaching repositories did.
func printAttachResult(out io.Writer, res *repoAttachResult) {
	for _, a := range res.Assigned {
		fmt.Fprintf(out, "Granted %s (%s) through %s — grant %s, until %s.\n",
			strings.Join(a.Repos, ", "), a.Access, a.SecretName, a.GrantID, expiryText(a.ExpiresAt))
	}
	for _, r := range res.Requested {
		printRequestFiled(out, r)
	}
	for _, n := range res.Notes {
		fmt.Fprintf(out, "note: %s\n", n)
	}
}

// printRequestFiled says a request was filed, its id, and who can approve it.
func printRequestFiled(out io.Writer, r hubclient.GrantRequest) {
	what := r.SecretName
	if r.Constraints != "" {
		what += " (" + r.Constraints + ")"
	}
	fmt.Fprintf(out, "Requested %s for %s — request %s, waiting for an approver", what, r.Subject, r.ID)
	if !r.ExpiresAt.IsZero() {
		fmt.Fprintf(out, " until %s", r.ExpiresAt.Local().Format("2006-01-02 15:04"))
	}
	fmt.Fprintln(out, ".")
	if len(r.Approvers) > 0 {
		fmt.Fprintf(out, "  Who can approve it: %s.\n", strings.Join(r.Approvers, "; "))
	} else {
		fmt.Fprintln(out, "  Who can approve it: a maintainer or administrator of the hub other than you.")
	}
	fmt.Fprintf(out, "  Take it back with: cloop remote grants withdraw %s\n", r.ID)
}

func runRemoteReposRemove(cmd *cobra.Command, args []string) error {
	c, err := remoteClient()
	if err != nil {
		return err
	}
	ctx := remoteContext(cmd)
	p, err := c.ResolveProject(ctx, args[0])
	if err != nil {
		return remoteErr(c, err)
	}
	panel, err := c.ProjectRepositories(ctx, p.Idx)
	if err != nil {
		return remoteErr(c, err)
	}
	type removal struct {
		GrantID  string                    `json:"grant_id"`
		Repos    []string                  `json:"repos"`
		Replaced *hubclient.RepoAssignment `json:"replaced_by,omitempty"`
		Note     string                    `json:"note,omitempty"`
	}
	var done []removal
	out := cmd.OutOrStdout()
	report := func() error {
		if remoteJSON {
			return json.NewEncoder(out).Encode(map[string]any{"project": p.Name, "removed": done})
		}
		for _, d := range done {
			if d.Replaced != nil {
				fmt.Fprintf(out, "Withdrew %s: grant %s replaced by %s, which keeps %s.\n", strings.Join(d.Repos, ", "),
					d.GrantID, d.Replaced.GrantID, strings.Join(d.Replaced.Repos, ", "))
			} else {
				fmt.Fprintf(out, "Withdrew grant %s (%s).\n", d.GrantID, strings.Join(d.Repos, ", "))
			}
			if d.Note != "" {
				fmt.Fprintf(out, "  %s\n", d.Note)
			}
		}
		return nil
	}

	for _, arg := range args[1:] {
		arg = strings.TrimSpace(arg)
		if a, ok := assignmentByGrant(panel.Assignments, arg); ok {
			res, err := c.RevokeRepositories(ctx, p.Idx, a.GrantID)
			if err != nil {
				_ = report()
				return remoteErr(c, err)
			}
			done = append(done, removal{GrantID: a.GrantID, Repos: a.Repos, Note: res.Note})
			continue
		}
		repo, err := gitremote.ParseRepo(arg)
		if err != nil {
			_ = report()
			return fmt.Errorf("%q is neither a grant of %s nor a repository: %w", arg, p.Name, err)
		}
		name := repo.FullName()
		matched := false
		for i, a := range panel.Assignments {
			if !containsFold(a.Repos, name) {
				continue
			}
			matched = true
			if !a.Replaceable {
				_ = report()
				return fmt.Errorf("%s is reached through grant %s, which is not %s's own: it reaches other projects too, "+
					"so withdraw it from the Secrets panel", name, a.GrantID, p.Name)
			}
			keep := withoutFold(a.Repos, name)
			if len(keep) == 0 {
				res, err := c.RevokeRepositories(ctx, p.Idx, a.GrantID)
				if err != nil {
					_ = report()
					return remoteErr(c, err)
				}
				done = append(done, removal{GrantID: a.GrantID, Repos: a.Repos, Note: res.Note})
				continue
			}
			replacement, err := c.AssignRepositories(ctx, p.Idx, hubclient.AssignRepositoriesRequest{
				Secret: a.SecretID, Repos: keep, Access: a.Access, Branches: a.Branches, Replaces: a.GrantID,
			})
			if err != nil {
				_ = report()
				return remoteErr(c, err)
			}
			done = append(done, removal{GrantID: a.GrantID, Repos: []string{name}, Replaced: &replacement})
			panel.Assignments[i] = replacement
		}
		if !matched {
			if via := reachedThrough(panel.Assignments, name, false); via != "" {
				_ = report()
				return fmt.Errorf("%s is reached through a wildcard grant, %s; withdraw that grant by its id instead", name, via)
			}
			_ = report()
			return fmt.Errorf("%s cannot reach %s, so there is nothing to withdraw", p.Name, name)
		}
	}
	return report()
}

func assignmentByGrant(as []hubclient.RepoAssignment, id string) (hubclient.RepoAssignment, bool) {
	for _, a := range as {
		if a.GrantID == id {
			return a, true
		}
	}
	return hubclient.RepoAssignment{}, false
}

func containsFold(list []string, s string) bool {
	for _, v := range list {
		if strings.EqualFold(v, s) {
			return true
		}
	}
	return false
}

func withoutFold(list []string, s string) []string {
	out := make([]string, 0, len(list))
	for _, v := range list {
		if !strings.EqualFold(v, s) {
			out = append(out, v)
		}
	}
	return out
}

// parseRepoArgs reads owner/name arguments, refusing any that do not name a
// GitHub repository.
func parseRepoArgs(args []string) ([]gitremote.Repo, error) {
	var repos []gitremote.Repo
	seen := map[string]bool{}
	for _, a := range args {
		for _, part := range strings.Split(a, ",") {
			if strings.TrimSpace(part) == "" {
				continue
			}
			r, err := gitremote.ParseRepo(part)
			if err != nil {
				return nil, fmt.Errorf("%w — name a GitHub repository as owner/name", err)
			}
			if key := strings.ToLower(r.FullName()); !seen[key] {
				seen[key] = true
				repos = append(repos, r)
			}
		}
	}
	if len(repos) == 0 {
		return nil, fmt.Errorf("name at least one repository as owner/name")
	}
	return repos, nil
}

func init() {
	remoteReposListCmd.Flags().BoolVar(&remoteJSON, "json", false, "Print JSON")
	remoteReposAddCmd.Flags().StringVar(&reposSecret, "secret", "",
		"The stored GitHub App or token to grant through (default: chosen for you)")
	remoteReposAddCmd.Flags().StringVar(&reposAccess, "access", "read", "read, or write (push and open pull requests)")
	remoteReposAddCmd.Flags().StringSliceVar(&reposBranches, "branch", nil,
		"Limit pushes to these branches (with --access write); repeatable, globs like cloop/* allowed")
	remoteReposAddCmd.Flags().DurationVar(&reposTTL, "ttl", 0, "How long the grant lasts (default: the hub's, 24h)")
	remoteReposAddCmd.Flags().StringVar(&reposJustification, "justification", "",
		"Why, when a credential has to be requested from an approver")
	remoteReposAddCmd.Flags().BoolVar(&remoteJSON, "json", false, "Print what was granted and requested as JSON")
	remoteReposRemoveCmd.Flags().BoolVar(&remoteJSON, "json", false, "Print what was withdrawn as JSON")
	remoteReposCmd.AddCommand(remoteReposListCmd, remoteReposAddCmd, remoteReposRemoveCmd)
	remoteCmd.AddCommand(remoteReposCmd)
}
