package cmd

// `cloop remote grants` (Task 20417): asking for a credential you cannot grant
// yourself, from a terminal — the Access Requests panel's own calls. Filing,
// listing and withdrawing take secret.request (an operator's permission); an
// approver with secret.grant decides, never the person who asked.

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/blechschmidt/cloop/pkg/hubclient"
)

var (
	grantsProject       string
	grantsSubject       string
	grantsJustification string
	grantsTTL           time.Duration
	grantsWait          time.Duration
	grantsRepos         []string
	grantsAccess        string
	grantsBranches      []string
	grantsPermissions   []string
	grantsNamespaces    []string
	grantsContexts      []string
	grantsHosts         []string
	grantsRegistries    []string
	grantsEnvKeys       []string
	grantsWritable      bool

	grantsState string
	grantsMine  bool
)

var remoteGrantsCmd = &cobra.Command{
	Use:   "grants",
	Short: "Request a credential you cannot grant yourself, and follow the request",
	Long: `Ask an approver for a credential you may not grant yourself — the organisation's
GitHub App for a repository, a cluster, a registry — narrowed to what you need,
with the reason. An approver with secret.grant (a maintainer or an administrator,
never you) mints the grant or refuses it. ` + "`list`" + ` shows your requests and who can
approve the pending ones; ` + "`withdraw`" + ` takes one back.`,
}

var remoteGrantsRequestCmd = &cobra.Command{
	Use:   "request <secret>",
	Short: "Ask an approver to grant a stored credential to a project",
	Long: `Ask an approver to grant the stored credential <secret> to a project.

    cloop remote grants request acme-github-app --project api --repo acme/api \
        --access write --justification "Ship the /healthz endpoint (API-412)"
    cloop remote grants request staging-cluster --project api --namespace payments \
        --justification "Integration tests against staging"

The request carries the narrowing the credential's kind needs: --repo for a GitHub
credential, --namespace or --context for a cluster, --host for egress, --registry
for a registry, --env-key for an env secret. ` + "`cloop remote grants list`" + ` follows it.`,
	Args: cobra.ExactArgs(1),
	RunE: runRemoteGrantsRequest,
}

var remoteGrantsListCmd = &cobra.Command{
	Use:   "list",
	Short: "List your grant requests",
	Long: `List grant requests: your own, or — if you may approve them — everyone's unless
--mine. Pending requests show who can approve them.`,
	Args: cobra.NoArgs,
	RunE: runRemoteGrantsList,
}

var remoteGrantsWithdrawCmd = &cobra.Command{
	Use:   "withdraw <request-id>",
	Short: "Take back a pending request of yours",
	Args:  cobra.ExactArgs(1),
	RunE:  runRemoteGrantsWithdraw,
}

func runRemoteGrantsRequest(cmd *cobra.Command, args []string) error {
	secret := strings.TrimSpace(args[0])
	if secret == "" {
		return errors.New("name the stored credential to request (see the Access Requests panel, or ask an approver)")
	}
	if strings.TrimSpace(grantsJustification) == "" {
		return errors.New("a request needs a reason an approver can weigh: pass --justification \"…\"")
	}
	if (grantsProject == "") == (grantsSubject == "") {
		return errors.New("say who the grant is for: --project <project>, or --subject executor:<id>")
	}
	c, err := remoteClient()
	if err != nil {
		return err
	}
	ctx := remoteContext(cmd)
	subject := strings.TrimSpace(grantsSubject)
	if grantsProject != "" {
		p, err := c.ResolveProject(ctx, grantsProject)
		if err != nil {
			return remoteErr(c, err)
		}
		subject = "project:" + p.Path
	}
	perms := append([]string(nil), grantsPermissions...)
	if len(grantsRepos) > 0 && len(perms) == 0 {
		if perms, err = repoAccessPermissions(grantsAccess); err != nil {
			return err
		}
	}
	repos := grantsRepos
	if len(repos) > 0 {
		parsed, err := parseRepoArgs(repos)
		if err != nil {
			return err
		}
		repos = make([]string, 0, len(parsed))
		for _, r := range parsed {
			repos = append(repos, r.FullName())
		}
	}
	req, err := c.RequestGrant(ctx, hubclient.FileGrantRequest{
		SecretRef: secret, Subject: subject, Justification: grantsJustification,
		TTLMinutes: int(grantsTTL / time.Minute), WaitMinutes: int(grantsWait / time.Minute),
		Repos: repos, Permissions: perms, Branches: grantsBranches, Namespaces: grantsNamespaces,
		Contexts: grantsContexts, Hosts: grantsHosts, Registries: grantsRegistries, EnvKeys: grantsEnvKeys,
		Writable: grantsWritable,
	})
	if err != nil {
		return remoteErr(c, err)
	}
	out := cmd.OutOrStdout()
	if remoteJSON {
		return json.NewEncoder(out).Encode(req)
	}
	printRequestFiled(out, req)
	return nil
}

func runRemoteGrantsList(cmd *cobra.Command, _ []string) error {
	c, err := remoteClient()
	if err != nil {
		return err
	}
	list, err := c.GrantRequests(remoteContext(cmd), strings.ToLower(strings.TrimSpace(grantsState)), grantsMine)
	if err != nil {
		return remoteErr(c, err)
	}
	out := cmd.OutOrStdout()
	if remoteJSON {
		return json.NewEncoder(out).Encode(list)
	}
	if len(list.Requests) == 0 {
		fmt.Fprintln(out, "No grant requests.")
		return nil
	}
	w := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "ID\tSTATE\tSECRET\tFOR\tASKED BY\tWANTS")
	for _, r := range list.Requests {
		wants := r.Constraints
		if r.TTLMinutes > 0 {
			if wants != "" {
				wants += "; "
			}
			wants += "for " + (time.Duration(r.TTLMinutes) * time.Minute).String()
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n", r.ID, r.State, orDash(r.SecretName), r.Subject,
			orDash(r.RequestedBy), orDash(wants))
	}
	_ = w.Flush()
	for _, r := range list.Requests {
		switch {
		case r.State == "pending" && r.Mine && len(r.Approvers) > 0:
			fmt.Fprintf(out, "%s can be approved by: %s\n", r.ID, strings.Join(r.Approvers, "; "))
		case r.State == "approved" && r.GrantID != "":
			fmt.Fprintf(out, "%s was approved by %s: grant %s\n", r.ID, orDash(r.DecidedBy), r.GrantID)
		case r.State == "denied":
			fmt.Fprintf(out, "%s was denied by %s: %s\n", r.ID, orDash(r.DecidedBy), orDash(r.DecisionNote))
		case r.State == "expired" && r.Mine:
			// Nobody decided it (Task 20427): the answer the requester is
			// owed is that asking again is the way forward.
			fmt.Fprintf(out, "%s lapsed undecided; file it again with a current reason\n", r.ID)
		case r.State == "withdrawn" && r.Mine && !strings.EqualFold(strings.TrimSpace(r.DecidedBy), strings.TrimSpace(r.RequestedBy)):
			fmt.Fprintf(out, "%s was withdrawn by %s: %s\n", r.ID, orDash(termText(r.DecidedBy)), orDash(termText(r.DecisionNote)))
		}
	}
	return nil
}

func runRemoteGrantsWithdraw(cmd *cobra.Command, args []string) error {
	c, err := remoteClient()
	if err != nil {
		return err
	}
	req, err := c.WithdrawGrantRequest(remoteContext(cmd), strings.TrimSpace(args[0]))
	if err != nil {
		return remoteErr(c, err)
	}
	out := cmd.OutOrStdout()
	if remoteJSON {
		return json.NewEncoder(out).Encode(req)
	}
	fmt.Fprintf(out, "Withdrew request %s (%s for %s).\n", req.ID, orDash(req.SecretName), req.Subject)
	return nil
}

func init() {
	f := remoteGrantsRequestCmd.Flags()
	f.StringVar(&grantsProject, "project", "", "The project the grant is for: its name, index or path")
	f.StringVar(&grantsSubject, "subject", "", "Who the grant is for, in the hub's form (executor:<id>), instead of --project")
	f.StringVar(&grantsJustification, "justification", "", "Why you need it — what an approver weighs (required)")
	f.DurationVar(&grantsTTL, "ttl", 0, "How long the grant should last once approved (default: the hub's, 24h)")
	f.DurationVar(&grantsWait, "wait", 0, "How long the request waits for a decision (default: the hub's)")
	f.StringSliceVar(&grantsRepos, "repo", nil, "GitHub repositories, as owner/name (GitHub credentials)")
	f.StringVar(&grantsAccess, "access", "read", "read or write, for --repo: write may push and open pull requests")
	f.StringSliceVar(&grantsBranches, "branch", nil, "Limit pushes to these branches (with --access write)")
	f.StringSliceVar(&grantsPermissions, "permission", nil, "Explicit permissions instead of --access (contents:write, …)")
	f.StringSliceVar(&grantsNamespaces, "namespace", nil, "Kubernetes namespaces (kubeconfig credentials)")
	f.StringSliceVar(&grantsContexts, "context", nil, "Kubernetes contexts (kubeconfig credentials)")
	f.StringSliceVar(&grantsHosts, "host", nil, "Hosts (egress credentials)")
	f.StringSliceVar(&grantsRegistries, "registry", nil, "Registries (registry credentials)")
	f.StringSliceVar(&grantsEnvKeys, "env-key", nil, "Keys of an env secret to deliver")
	f.BoolVar(&grantsWritable, "writable", false, "Write access, for a local repository or a host device")
	f.BoolVar(&remoteJSON, "json", false, "Print the filed request as JSON")
	remoteGrantsListCmd.Flags().StringVar(&grantsState, "state", "",
		"Only requests in this state (pending, approved, denied, withdrawn, expired)")
	remoteGrantsListCmd.Flags().BoolVar(&grantsMine, "mine", false, "Only your own requests")
	remoteGrantsListCmd.Flags().BoolVar(&remoteJSON, "json", false, "Print JSON")
	remoteGrantsWithdrawCmd.Flags().BoolVar(&remoteJSON, "json", false, "Print the withdrawn request as JSON")
	remoteGrantsCmd.AddCommand(remoteGrantsRequestCmd, remoteGrantsListCmd, remoteGrantsWithdrawCmd)
	remoteCmd.AddCommand(remoteGrantsCmd)
}
