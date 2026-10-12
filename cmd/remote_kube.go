package cmd

// `cloop remote kube` (Task 20416): share a Kubernetes cluster with a hub from
// the developer's own terminal, through a least-privilege ServiceAccount.
//
// The hub refuses a kubeconfig whose user signs in through an exec credential
// plugin — kubelogin on AKS, `aws eks get-token` on EKS, the GKE plugin —
// because running it there would execute a program named in an uploaded file
// on the control-plane host. These commands run the plugin here instead, on the
// machine and as the person kubectl already runs it for, and leave the hub
// holding only a static kubeconfig for a ServiceAccount with exactly the access
// chosen. See pkg/kubeshare for what is created and why, and pkg/kubeexec for
// the plugin protocol.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"sort"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/blechschmidt/cloop/pkg/executor/kubernetes"
	"github.com/blechschmidt/cloop/pkg/hubclient"
	"github.com/blechschmidt/cloop/pkg/kubeexec"
	"github.com/blechschmidt/cloop/pkg/kubeshare"
)

var (
	kubeContext     string
	kubeKubeconfig  string
	kubeNamespaces  []string
	kubeAccess      string
	kubeTTL         time.Duration
	kubeSANamespace string
	kubeClusterWide bool
	kubeRenewal     string
	kubeServer      string
	kubeShared      bool
	kubeDryRun      bool
	kubeJSON        bool
	kubeLocal       bool
	kubeForce       bool
)

var remoteKubeCmd = &cobra.Command{
	Use:   "kube",
	Short: "Share a Kubernetes cluster with the hub through a least-privilege ServiceAccount",
	Long: `Share a Kubernetes cluster with the hub without handing it your own credential.

` + "`share`" + ` runs on your machine against your own kubeconfig — exec credential plugins
included: kubelogin (AKS), aws eks get-token (EKS), gke-gcloud-auth-plugin (GKE). It
creates a labelled ServiceAccount, binds it to the cluster's view role (or edit, for
write access) in the namespaces you name, mints a bounded token for it, and stores a
static kubeconfig for that token on the hub as your personal secret.

When the hub runs its Kubernetes access monitor, the share renews itself: the
ServiceAccount may create a token for itself and for nothing else, the hub uses that to
mint the next token before the current one expires, and the monitor refuses it to every
sandbox. Without the monitor the token would sit in the sandbox, so no such permission
is installed and you renew with ` + "`cloop remote kube renew`" + `.

` + "`list`" + ` shows your shares and when each token expires; ` + "`revoke`" + ` deletes the
ServiceAccount, its bindings and the hub's secret.`,
}

var remoteKubeShareCmd = &cobra.Command{
	Use:   "share <name>",
	Short: "Create a ServiceAccount with only the access you choose and store its token on the hub",
	Long: `Share a cluster with the hub as secret <name>.

    cloop remote kube share aks-dev --context aks-dev --namespaces payments,payments-staging
    cloop remote kube share aks-ci --context aks-dev --namespaces payments --access write \
        --sa-namespace cloop-shares --ttl 12h

Read access (the default) binds the cluster's ` + "`view`" + ` role in each namespace; the
ServiceAccount lives in the first one unless --sa-namespace says otherwise. Write
access binds ` + "`edit`" + `, which may create Pods and Secrets — so the ServiceAccount must
live in a namespace it cannot write (--sa-namespace), or a workload could mint its
credential there. Nothing is bound cluster-wide unless --cluster-wide asks, and then
read access only.

The token lives --ttl (10m to 7d, default 24h), or less if the cluster caps it.
--renewal auto (the default) lets the hub renew it when the hub runs the Kubernetes
access monitor; --renewal manual never installs the self-renewal permission.

Store it, then grant it to a project from the dashboard's Secrets panel — or, on the hub,
` + "`cloop secret grant <name> --to project:<path> --namespaces <ns>`" + `.`,
	Args: cobra.ExactArgs(1),
	RunE: runRemoteKubeShare,
}

var remoteKubeListCmd = &cobra.Command{
	Use:   "list",
	Short: "List your Kubernetes shares, when each token expires and who renews it",
	Args:  cobra.NoArgs,
	RunE:  runRemoteKubeList,
}

var remoteKubeRenewCmd = &cobra.Command{
	Use:   "renew <name>",
	Short: "Mint a share's next token now",
	Long: `Mint a share's next token.

A share the hub renews is renewed by the hub, now. A share renewed by hand — or one
whose token lapsed before the hub could renew it — is renewed from here: your own
credentials (the exec plugin, if your kubeconfig uses one) mint a new token for the
share's ServiceAccount, and the hub stores it once the cluster has confirmed it is that
ServiceAccount's. --local forces the second way.`,
	Args: cobra.ExactArgs(1),
	RunE: runRemoteKubeRenew,
}

var remoteKubeRevokeCmd = &cobra.Command{
	Use:   "revoke <name>",
	Short: "Delete a share's ServiceAccount, its bindings and the hub's secret",
	Long: `Revoke a share: delete its ServiceAccount first — which invalidates every token ever
minted for it, the hub's and any copy — then its RoleBindings, its self-renewal Role,
and finally the secret on the hub, which revokes every grant of it and closes the
monitor sessions standing on it.

If the cluster cannot be reached, or an object cannot be deleted, the hub's secret is
kept so the revoke can be run again; --force deletes it anyway and prints the kubectl
command that removes what is left.`,
	Args: cobra.ExactArgs(1),
	RunE: runRemoteKubeRevoke,
}

// kubeSignalContext is the command's context, cancelled by Ctrl-C so a plugin
// or an API call stops — and a half-made share is rolled back.
func kubeSignalContext(cmd *cobra.Command) (context.Context, context.CancelFunc) {
	return signal.NotifyContext(remoteContext(cmd), os.Interrupt, syscall.SIGTERM)
}

// kubeconfigPaths are --kubeconfig, else what kubectl reads.
func kubeconfigPaths() []string {
	if p := strings.TrimSpace(kubeKubeconfig); p != "" {
		return []string{p}
	}
	return kubeexec.DefaultPaths()
}

// connectCluster resolves a context of the developer's kubeconfig and signs in
// with it, running its exec plugin here when it has one.
func connectCluster(ctx context.Context, contextName string, out io.Writer) (*kubeexec.Context, *kubernetes.RESTConfig, error) {
	kc, err := kubeexec.Load(kubeconfigPaths())
	if err != nil {
		return nil, nil, err
	}
	kctx, err := kc.Context(contextName)
	if err != nil {
		return nil, nil, err
	}
	if p := kctx.Plugin(); p != nil {
		fmt.Fprintf(out, "Signing in to %s with %s…\n", kctx.Server, kubeshare.DescribePlugin(p.Command, p.Args))
	}
	rc, cred, err := kctx.RESTConfig(ctx, kubeexec.Options{
		Terminal: term.IsTerminal(int(os.Stdin.Fd())),
		Stderr:   os.Stderr,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("sign in to context %s: %w", kctx.Name, err)
	}
	if cred != nil && !cred.ExpiresAt.IsZero() {
		fmt.Fprintf(out, "Signed in; the plugin's credential is valid until %s.\n",
			cred.ExpiresAt.Local().Format("2006-01-02 15:04 MST"))
	}
	return kctx, rc, nil
}

// whoAmI names the identity a cluster sees, for the summary. Best effort.
func whoAmI(ctx context.Context, c *kubeshare.Client) string {
	if who, ok, err := c.WhoAmI(ctx); err == nil && ok {
		return who
	}
	return ""
}

func runRemoteKubeShare(cmd *cobra.Command, args []string) error {
	out := cmd.OutOrStdout()
	name := strings.TrimSpace(args[0])
	ctx, stop := kubeSignalContext(cmd)
	defer stop()

	c, err := remoteClient()
	if err != nil {
		return err
	}
	list, err := c.Secrets(ctx)
	if err != nil {
		return remoteErr(c, err)
	}
	if !list.Broker.SecretsAvailable {
		return fmt.Errorf("%s cannot store secrets: %s. %s", c.Base, list.Broker.Reason, list.Broker.Remediation)
	}
	if _, taken := list.FindSecret(name); taken {
		return fmt.Errorf("the hub already holds a secret named %q; choose another name, or revoke it first "+
			"(cloop remote kube revoke %s)", name, quoteArg(name))
	}
	renewal, err := chooseRenewal(kubeRenewal, list.KubeGuard.Enabled, c.Base)
	if err != nil {
		return err
	}
	access, err := kubeshare.ParseAccess(kubeAccess)
	if err != nil {
		return err
	}

	// The owner annotation every object carries is the hub's own key for
	// this caller — the one it records as the share's owner — so a revoke can
	// tell the share's objects from anyone else's (Task 20420). A hub that
	// predates it answers with the email or subject, as before.
	owner := ""
	if me, err := c.Me(ctx); err == nil {
		owner, _ = me["identity"].(string)
		if owner == "" {
			owner, _ = me["email"].(string)
		}
		if owner == "" {
			owner, _ = me["sub"].(string)
		}
	}

	// The kubeconfig is read first so --dry-run can name the cluster; nothing
	// signs in, and no plugin runs, until the plan is known to be valid.
	kc, err := kubeexec.Load(kubeconfigPaths())
	if err != nil {
		return err
	}
	kctx, err := kc.Context(kubeContext)
	if err != nil {
		return err
	}
	server := strings.TrimRight(strings.TrimSpace(kubeServer), "/")
	if server == "" {
		server = kctx.Server
	} else if !strings.HasPrefix(server, "https://") {
		return fmt.Errorf("--server %s: the hub refuses an API server that is not https://", server)
	}
	plan, err := kubeshare.NewPlan(kubeshare.Request{
		Name: name, Namespaces: splitNamespaces(kubeNamespaces), ServiceAccountNamespace: kubeSANamespace,
		Access: access, ClusterWide: kubeClusterWide, TTL: kubeTTL, Renewal: renewal,
		Hub: c.Base, Owner: owner, Context: kctx.Name, Server: server,
	}, time.Now())
	if err != nil {
		return err
	}

	fmt.Fprintf(out, "Sharing context %s (%s) with %s as %q:\n", kctx.Name, server, c.Base, name)
	for _, line := range plan.Describe() {
		fmt.Fprintf(out, "  %s\n", line)
	}
	if kctx.InsecureSkipTLSVerify {
		fmt.Fprintf(out, "  Note            the context skips TLS verification (insecure-skip-tls-verify), and so "+
			"will the hub when it talks to %s\n", server)
	}
	if kubeDryRun {
		fmt.Fprintln(out, "\n--dry-run: nothing was created. These objects would be:")
		for _, m := range plan.Manifests() {
			fmt.Fprintf(out, "  %s\n", m.Object)
		}
		return nil
	}

	_, rc, err := connectCluster(ctx, kctx.Name, out)
	if err != nil {
		return err
	}
	kube, err := kubeshare.NewClient(rc)
	if err != nil {
		return err
	}
	defer kube.Close()
	if who := whoAmI(ctx, kube); who != "" {
		fmt.Fprintf(out, "The cluster knows you as %s.\n", who)
	}

	created, err := kubeshare.Apply(ctx, kube, plan)
	if err != nil {
		return err
	}
	// From here a failure undoes what was made.
	undo := func(cause error) error {
		res := kubeshare.Remove(context.Background(), kube, plan.Share())
		if !res.Clean() {
			return fmt.Errorf("%w; and the objects already created could not all be removed (%s): %s",
				cause, describeFailures(res.Failed), kubeshare.DeleteCommand(plan.ID, plan.ServiceAccountNamespace))
		}
		return fmt.Errorf("%w (the %d objects created were removed again)", cause, len(created))
	}

	tok, claims, err := kubeshare.Mint(ctx, kube, plan)
	if err != nil {
		return undo(err)
	}
	if claims.Lifetime() < plan.TTL-time.Minute {
		fmt.Fprintf(out, "The cluster capped the token at %s (asked for %s).\n",
			kubeshare.ShortDuration(claims.Lifetime().Round(time.Minute)), kubeshare.ShortDuration(plan.TTL))
	}
	namespace := ""
	if len(plan.Namespaces) > 0 {
		namespace = plan.Namespaces[0]
	} else {
		namespace = kctx.Namespace
	}
	doc, err := kubeshare.RenderKubeconfig(kubeshare.KubeconfigParams{
		Name: name, Server: server, CAData: kctx.CAData, TLSServerName: kctx.TLSServerName,
		Insecure: kctx.InsecureSkipTLSVerify, ProxyURL: kctx.ProxyURL, Namespace: namespace, Token: tok.Value,
	})
	if err != nil {
		return undo(err)
	}
	meta := plan.Share().Metadata()
	// The hub derives these from the token itself; sent too, so a hub that
	// predates shares still shows when the token expires.
	kubeshare.RecordToken(meta, claims)
	req := hubclient.CreateSecretRequest{Name: name, Kind: "kubeconfig", Payload: string(doc), Metadata: meta}
	if kubeShared {
		personal := false
		req.Personal = &personal
	}
	sec, err := c.CreateSecret(ctx, req)
	if err != nil {
		return undo(fmt.Errorf("store the share on %s: %w", c.Base, remoteErr(c, err)))
	}

	kind := "a shared secret"
	if sec.Personal {
		kind = "your personal secret"
	}
	fmt.Fprintf(out, "\nShared. %s holds the token as %s %q (%s).\n", c.Base, kind, sec.Name, sec.ID)
	fmt.Fprintf(out, "  Token expires   %s\n", kubeshare.Expiry(claims.ExpiresAt, time.Now()))
	if plan.Renewal == kubeshare.RenewalHub {
		fmt.Fprintf(out, "  Renewal         by the hub, at half the token's life; `cloop remote kube list` shows it\n")
	} else {
		fmt.Fprintf(out, "  Renewal         yours: `cloop remote kube renew %s` before it expires\n", quoteArg(name))
	}
	fmt.Fprintf(out, "\nNext, grant it to a project: the dashboard's Secrets panel, or on the hub\n"+
		"  cloop secret grant %s --to project:<path> --namespaces %s\n", quoteArg(name), grantNamespaces(plan))
	return nil
}

// chooseRenewal resolves --renewal against what the hub can do.
func chooseRenewal(flag string, monitored bool, hub string) (kubeshare.Renewal, error) {
	switch strings.ToLower(strings.TrimSpace(flag)) {
	case "", "auto":
		if monitored {
			return kubeshare.RenewalHub, nil
		}
		return kubeshare.RenewalManual, nil
	case "hub":
		if !monitored {
			return "", fmt.Errorf("--renewal hub: %s does not run the Kubernetes access monitor, and without it "+
				"the self-renewal permission would sit in the sandbox with the token. Use --renewal manual", hub)
		}
		return kubeshare.RenewalHub, nil
	case "manual":
		return kubeshare.RenewalManual, nil
	}
	return "", fmt.Errorf("--renewal %q: want auto, hub or manual", flag)
}

func splitNamespaces(in []string) []string {
	var out []string
	for _, v := range in {
		for _, ns := range strings.Split(v, ",") {
			if ns = strings.TrimSpace(ns); ns != "" {
				out = append(out, ns)
			}
		}
	}
	return out
}

func grantNamespaces(p *kubeshare.Plan) string {
	if p.ClusterWide {
		return "<namespace>"
	}
	return strings.Join(p.Namespaces, ",")
}

func describeFailures(failed map[kubeshare.Object]error) string {
	parts := make([]string, 0, len(failed))
	for o, err := range failed {
		parts = append(parts, o.String()+": "+err.Error())
	}
	sort.Strings(parts)
	return strings.Join(parts, "; ")
}

// shareView is one share as `list --json` prints it.
type shareView struct {
	Name           string    `json:"name"`
	ID             string    `json:"secret_id"`
	ShareID        string    `json:"share_id"`
	Server         string    `json:"server"`
	ServiceAccount string    `json:"service_account"`
	Namespaces     []string  `json:"namespaces,omitempty"`
	ClusterWide    bool      `json:"cluster_wide,omitempty"`
	Access         string    `json:"access"`
	Renewal        string    `json:"renewal"`
	ExpiresAt      time.Time `json:"expires_at"`
	RenewedAt      string    `json:"renewed_at,omitempty"`
	Renewals       int       `json:"renewals"`
	RenewError     string    `json:"renew_error,omitempty"`
	Lapsed         bool      `json:"lapsed,omitempty"`
	// Stopped: the hub will not renew the share while its owner is denied
	// on it (Task 20420); RenewError says why.
	Stopped      bool `json:"stopped,omitempty"`
	Personal     bool `json:"personal"`
	ActiveGrants int  `json:"active_grants"`
}

func listShares(list *hubclient.SecretsList) []shareView {
	var out []shareView
	for _, s := range list.Secrets {
		sh, ok := kubeshare.FromMetadata(s.Metadata)
		if s.Kind != "kubeconfig" || !ok {
			continue
		}
		v := shareView{
			Name: s.Name, ID: s.ID, ShareID: sh.ID, Server: sh.Server,
			ServiceAccount: sh.Namespace + "/" + sh.ServiceAccount, Namespaces: sh.Namespaces,
			ClusterWide: sh.ClusterWide, Access: string(sh.Access), Renewal: string(sh.Renewal),
			ExpiresAt: sh.ExpiresAt, Renewals: sh.Renewals,
			RenewError: sh.RenewError, Lapsed: sh.Lapsed, Stopped: sh.Stopped, Personal: s.Personal,
			ActiveGrants: s.ActiveGrants,
		}
		if !sh.RenewedAt.IsZero() {
			v.RenewedAt = sh.RenewedAt.Format(time.RFC3339)
		}
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func runRemoteKubeList(cmd *cobra.Command, _ []string) error {
	out := cmd.OutOrStdout()
	c, err := remoteClient()
	if err != nil {
		return err
	}
	ctx := remoteContext(cmd)
	list, err := c.Secrets(ctx)
	if err != nil {
		return remoteErr(c, err)
	}
	shares := listShares(list)
	if kubeJSON {
		if shares == nil {
			shares = []shareView{}
		}
		return json.NewEncoder(out).Encode(map[string]any{
			"hub": c.Base, "kube_guard": list.KubeGuard, "shares": shares,
		})
	}
	monitor := "does not run the Kubernetes access monitor: shares are renewed by hand"
	switch {
	case list.KubeGuard.Running:
		monitor = "runs the Kubernetes access monitor: it renews the shares made for it"
	case list.KubeGuard.Enabled:
		monitor = "is configured for the Kubernetes access monitor, which is not running: kubeconfig grants are refused until it is"
	}
	fmt.Fprintf(out, "%s %s.\n", c.Base, monitor)
	if len(shares) == 0 {
		fmt.Fprintln(out, "You have no Kubernetes shares here. Make one with `cloop remote kube share`.")
		return nil
	}
	now := time.Now()
	w := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "NAME\tSERVICE ACCOUNT\tNAMESPACES\tACCESS\tEXPIRES\tRENEWAL\tGRANTS")
	for _, s := range shares {
		ns := strings.Join(s.Namespaces, ",")
		if s.ClusterWide {
			ns = "(all)"
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%d\n", truncateField(s.Name, 28), s.ServiceAccount,
			truncateField(ns, 32), s.Access, kubeshare.Expiry(s.ExpiresAt, now), renewalStatus(s, now), s.ActiveGrants)
	}
	if err := w.Flush(); err != nil {
		return err
	}
	for _, s := range shares {
		switch {
		case s.Stopped:
			fmt.Fprintf(out, "\n%s: the hub does not renew it: %s\n", s.Name, s.RenewError)
		case s.RenewError != "":
			fmt.Fprintf(out, "\n%s: the last renewal failed: %s\n", s.Name, s.RenewError)
		}
	}
	return nil
}

// renewalStatus says who keeps a share's token current, and whether it is.
func renewalStatus(s shareView, now time.Time) string {
	expired := !s.ExpiresAt.IsZero() && !now.Before(s.ExpiresAt)
	switch {
	case s.Stopped:
		return "stopped by the hub (see below)"
	case s.Lapsed || (expired && s.Renewal == string(kubeshare.RenewalHub)):
		return "lapsed: run `cloop remote kube renew " + quoteArg(s.Name) + "`"
	case expired:
		return "expired: run `cloop remote kube renew " + quoteArg(s.Name) + "`"
	case s.Renewal == string(kubeshare.RenewalHub) && s.RenewError != "":
		return "hub, failing (see below)"
	case s.Renewal == string(kubeshare.RenewalHub) && s.RenewedAt != "":
		at, _ := time.Parse(time.RFC3339, s.RenewedAt)
		return fmt.Sprintf("hub, renewed %s ago", kubeshareAgo(now.Sub(at)))
	case s.Renewal == string(kubeshare.RenewalHub):
		return "hub"
	}
	return "manual"
}

func kubeshareAgo(d time.Duration) string {
	switch {
	case d < time.Minute:
		return d.Round(time.Second).String()
	case d < time.Hour:
		return fmt.Sprintf("%dm", int(d/time.Minute))
	}
	return fmt.Sprintf("%dh%dm", int(d/time.Hour), int(d%time.Hour/time.Minute))
}

// errNoSuchShare is a share name the hub holds no secret for.
var errNoSuchShare = errors.New("no such share")

// findShare resolves a share by name on the hub.
func findShare(ctx context.Context, c *hubclient.Client, name string) (hubclient.Secret, kubeshare.Share, error) {
	list, err := c.Secrets(ctx)
	if err != nil {
		return hubclient.Secret{}, kubeshare.Share{}, remoteErr(c, err)
	}
	sec, ok := list.FindSecret(name)
	if !ok {
		return hubclient.Secret{}, kubeshare.Share{}, fmt.Errorf("%w: %s holds no secret named %q that you can "+
			"see (cloop remote kube list)", errNoSuchShare, c.Base, name)
	}
	sh, isShare := kubeshare.FromMetadata(sec.Metadata)
	if sec.Kind != "kubeconfig" || !isShare {
		return hubclient.Secret{}, kubeshare.Share{}, fmt.Errorf("%q is not a Kubernetes share made with "+
			"`cloop remote kube share`", name)
	}
	// A personal secret's owner is the hub's own record of who stored it,
	// whatever its metadata says: that is whose objects revoke and renew may
	// touch (Task 20420).
	if sec.Personal && strings.TrimSpace(sec.Owner) != "" {
		sh.Owner = sec.Owner
	}
	return sec, sh, nil
}

func runRemoteKubeRenew(cmd *cobra.Command, args []string) error {
	out := cmd.OutOrStdout()
	ctx, stop := kubeSignalContext(cmd)
	defer stop()
	c, err := remoteClient()
	if err != nil {
		return err
	}
	sec, sh, err := findShare(ctx, c, args[0])
	if err != nil {
		return err
	}
	now := time.Now()

	if sh.Renewal == kubeshare.RenewalHub && !kubeLocal && !sh.Lapsed && !sh.Expired(now) {
		r, err := c.RenewSecret(ctx, sec.ID)
		if err == nil {
			fmt.Fprintf(out, "The hub renewed %s: the token now expires %s.\n", sec.Name, kubeshare.Expiry(r.ExpiresAt, time.Now()))
			if r.Sessions > 0 {
				fmt.Fprintf(out, "%d live monitor session(s) took up the new token.\n", r.Sessions)
			}
			return nil
		}
		fmt.Fprintf(out, "The hub could not renew %s (%v); minting one with your own credentials instead.\n",
			sec.Name, remoteErr(c, err))
	}

	// Minting runs with your own credentials, for a ServiceAccount the share's
	// metadata names, and the token goes to the hub. So the hub is asked
	// first whether you may renew this share at all, the context must reach
	// the share's cluster through the CA the share trusts, and the
	// ServiceAccount must be one the share created (Task 20420).
	if err := c.AuthorizeSecret(ctx, sec.ID, "renew"); err != nil {
		return fmt.Errorf("%s does not let you renew %s, so no token was minted: %w", c.Base, sec.Name, remoteErr(c, err))
	}
	contextName := strings.TrimSpace(kubeContext)
	if contextName == "" {
		contextName = sh.Context
	}
	kctx, rc, err := connectCluster(ctx, contextName, out)
	if err != nil {
		return err
	}
	if err := sh.SameCluster(kctx.Server, kctx.CAData); err != nil {
		return fmt.Errorf("context %s: %w; no token was minted", kctx.Name, err)
	}
	kube, err := kubeshare.NewClient(rc)
	if err != nil {
		return err
	}
	defer kube.Close()
	if err := kubeshare.VerifyServiceAccount(ctx, kube, sh); err != nil {
		if kubeshare.IsNotFound(errors.Unwrap(err)) || kubeshare.IsNotFound(err) {
			return fmt.Errorf("the cluster has no ServiceAccount %s/%s any more: the share was revoked there; "+
				"run `cloop remote kube revoke %s --force` to remove it from the hub too", sh.Namespace,
				sh.ServiceAccount, quoteArg(sec.Name))
		}
		return fmt.Errorf("%w; no token was minted", err)
	}
	ttl := kubeTTL
	if !cmd.Flags().Changed("ttl") {
		if ttl = sh.Lifetime(); ttl < kubeshare.MinTTL || ttl > kubeshare.MaxTTL {
			ttl = kubeshare.DefaultTTL
		}
	}
	if ttl < kubeshare.MinTTL || ttl > kubeshare.MaxTTL {
		return fmt.Errorf("--ttl %s: between %s and %s", ttl, kubeshare.MinTTL, kubeshare.ShortDuration(kubeshare.MaxTTL))
	}
	tok, err := kube.RequestToken(ctx, sh.Namespace, sh.ServiceAccount, ttl)
	if err != nil {
		if kubeshare.IsNotFound(err) {
			return fmt.Errorf("the cluster has no ServiceAccount %s/%s any more: the share was revoked there; "+
				"run `cloop remote kube revoke %s --force` to remove it from the hub too", sh.Namespace,
				sh.ServiceAccount, quoteArg(sec.Name))
		}
		return fmt.Errorf("mint a token for %s/%s: %w", sh.Namespace, sh.ServiceAccount, err)
	}
	r, err := c.AdoptToken(ctx, sec.ID, hubclient.MintedToken{Token: tok.Value, Server: kctx.Server,
		CASHA256: kubeshare.CAFingerprint(kctx.CAData)})
	if err != nil {
		return remoteErr(c, err)
	}
	fmt.Fprintf(out, "Renewed %s: the token now expires %s.\n", sec.Name, kubeshare.Expiry(r.ExpiresAt, time.Now()))
	if !r.Verified {
		fmt.Fprintln(out, "(The cluster does not answer SelfSubjectReview, so the hub checked the token's claims only.)")
	}
	if r.Sessions > 0 {
		fmt.Fprintf(out, "%d live monitor session(s) took up the new token.\n", r.Sessions)
	} else if sh.Renewal == kubeshare.RenewalManual {
		fmt.Fprintln(out, "A run already holding the old kubeconfig keeps it until that token expires; the next dispatch gets this one.")
	}
	return nil
}

func runRemoteKubeRevoke(cmd *cobra.Command, args []string) error {
	out := cmd.OutOrStdout()
	ctx, stop := kubeSignalContext(cmd)
	defer stop()
	c, err := remoteClient()
	if err != nil {
		return err
	}
	sec, sh, err := findShare(ctx, c, args[0])
	if errors.Is(err, errNoSuchShare) {
		// Deleted on the hub already — from the dashboard, or with its owner's
		// offboarding. The hub's copy of the token is gone, but the cluster's
		// objects are not, and only their labels say which they are.
		//
		// The advice lists before it deletes, with the owner of each object:
		// a label is anybody's to set, so deleting by it could take objects
		// somebody else labelled (Task 20420).
		return fmt.Errorf("%w.\nIf the secret was deleted on the hub, its ServiceAccount and bindings may still be "+
			"in the cluster. Find them, and who made each, with\n  kubectl get serviceaccounts,rolebindings,roles -A -l %s=cloop -o "+
			"custom-columns=KIND:.kind,NAMESPACE:.metadata.namespace,NAME:.metadata.name,"+
			"SHARE:.metadata.labels.cloop\\.dev/kube-share,FOR:.metadata.annotations.cloop\\.dev/share-name,"+
			"OWNER:.metadata.annotations.cloop\\.dev/owner\nand delete the ones whose OWNER is you, by name:\n  "+
			"kubectl delete -n <NAMESPACE> <KIND>/<NAME>", err, kubeshare.LabelManagedBy)
	}
	if err != nil {
		return err
	}

	// The hub first. Revoke deletes cluster objects with your own credentials
	// and only then asks the hub to delete the secret; a revoke the hub would
	// refuse must not have reached the cluster by then (Task 20420).
	hubOnly := false
	if err := c.AuthorizeSecret(ctx, sec.ID, "delete"); err != nil {
		if !kubeForce || !errors.Is(err, hubclient.ErrAuthorizeUnsupported) {
			return fmt.Errorf("%s does not let you revoke %s, so nothing in the cluster was touched: %w",
				c.Base, sec.Name, remoteErr(c, err))
		}
		hubOnly = true
	}

	contextName := strings.TrimSpace(kubeContext)
	if contextName == "" {
		contextName = sh.Context
	}
	// What to remove by hand when the cluster was not touched. Not a delete
	// by label: anybody who may label objects could give one of theirs this
	// share's id, so the advice lists the candidates with their owner, to be
	// checked against the share's before anything is deleted (Task 20420).
	leftover := func() string {
		cmds := []string{kubeshare.FindCommand(sh.ID, sh.Namespace)}
		for _, ns := range sh.Namespaces {
			if ns != sh.Namespace {
				cmds = append(cmds, kubeshare.FindCommand(sh.ID, ns))
			}
		}
		if sh.ClusterWide {
			cmds = append(cmds, kubeshare.FindCommand(sh.ID, ""))
		}
		owner := sh.Owner
		if owner == "" {
			owner = "(none recorded)"
		}
		return strings.Join(cmds, "\n  ") + "\nand delete those whose OWNER is " + owner
	}

	var cerr error
	var kctx *kubeexec.Context
	var rc *kubernetes.RESTConfig
	if hubOnly {
		cerr = hubclient.ErrAuthorizeUnsupported
	} else if kctx, rc, cerr = connectCluster(ctx, contextName, out); cerr == nil {
		// Your credentials act only on the share's own cluster, reached
		// through the CA the share trusts.
		if err := sh.SameCluster(kctx.Server, kctx.CAData); err != nil {
			cerr = fmt.Errorf("context %s: %w", kctx.Name, err)
		}
	}
	if cerr == nil {
		kube, err := kubeshare.NewClient(rc)
		if err != nil {
			return err
		}
		defer kube.Close()
		res := kubeshare.Remove(ctx, kube, sh)
		left, lerr := kubeshare.Remaining(ctx, kube, sh)
		for _, o := range res.Removed {
			fmt.Fprintf(out, "Deleted %s\n", o)
		}
		for _, o := range res.Gone {
			fmt.Fprintf(out, "Already gone: %s\n", o)
		}
		refused := make([]string, 0, len(res.Refused))
		for o, why := range res.Refused {
			refused = append(refused, fmt.Sprintf("%s: %s", o, why))
		}
		sort.Strings(refused)
		for _, line := range refused {
			fmt.Fprintf(out, "Not deleted, not this share's: %s\n", line)
		}
		switch {
		case res.Clean() && len(left) == 0 && lerr == nil:
		case kubeForce:
			// Only objects verified as the share's are worth naming; one
			// refused as somebody else's stays where it is.
			var stuck []kubeshare.Object
			for o := range res.Failed {
				if _, refused := res.Refused[o]; !refused && o.Valid() {
					stuck = append(stuck, o)
				}
			}
			stuck = append(stuck, left...)
			advice := "nothing of the share's own is left to remove by hand"
			if len(stuck) > 0 {
				advice = "remove what is left of the share's own with:\n  " + kubeshare.DeleteCommandFor(stuck)
			}
			fmt.Fprintf(out, "Some of the share's objects could not be removed (%s). --force: deleting the hub's "+
				"secret anyway; %s\n", describeFailures(res.Failed), advice)
		default:
			if lerr != nil {
				res.Failed[kubeshare.Object{Kind: "check"}] = lerr
			}
			for _, o := range left {
				res.Failed[o] = errors.New("still present")
			}
			return fmt.Errorf("not every object of %s could be removed, so the hub's secret is kept and the "+
				"revoke can be run again (%s). --force deletes the secret anyway", sec.Name, describeFailures(res.Failed))
		}
	} else if !kubeForce {
		return fmt.Errorf("%w — the hub's secret is kept so the revoke can be run again; --force deletes it "+
			"without touching the cluster", cerr)
	} else {
		fmt.Fprintf(out, "The cluster was not touched (%v). --force: deleting the hub's secret only. "+
			"Find the share's objects with:\n  %s\n", cerr, leftover())
	}

	if err := c.DeleteSecret(ctx, sec.ID); err != nil {
		return remoteErr(c, err)
	}
	grants := ""
	if sec.ActiveGrants > 0 {
		grants = fmt.Sprintf(", revoking its %d active grant(s)", sec.ActiveGrants)
	}
	fmt.Fprintf(out, "Deleted secret %s from %s%s.\n", sec.Name, c.Base, grants)
	return nil
}

func init() {
	share := remoteKubeShareCmd.Flags()
	share.StringVar(&kubeContext, "context", "", "The kubeconfig context to share (default: the current context)")
	share.StringSliceVar(&kubeNamespaces, "namespaces", nil, "The namespaces to share, comma-separated")
	share.StringVar(&kubeAccess, "access", "read", "read (the view role) or write (the edit role)")
	share.DurationVar(&kubeTTL, "ttl", kubeshare.DefaultTTL, "How long the token lives: 10m to 7d (168h)")
	share.StringVar(&kubeSANamespace, "sa-namespace", "",
		"Where the ServiceAccount lives (default: the first shared namespace; required for write access)")
	share.BoolVar(&kubeClusterWide, "cluster-wide", false, "Bind the view role cluster-wide instead of per namespace")
	share.StringVar(&kubeRenewal, "renewal", "auto",
		"Who renews the token: auto (the hub, when it runs the Kubernetes access monitor), hub, or manual")
	share.StringVar(&kubeServer, "server", "",
		"The API server URL the hub should use, when it reaches the cluster at another address than you do")
	share.BoolVar(&kubeShared, "shared", false,
		"Store an organisation-wide secret instead of a personal one (needs secret.grant)")
	share.BoolVar(&kubeDryRun, "dry-run", false, "Print what would be created, and create nothing")
	remoteKubeListCmd.Flags().BoolVar(&kubeJSON, "json", false, "Print JSON")
	renew := remoteKubeRenewCmd.Flags()
	renew.StringVar(&kubeContext, "context", "", "The kubeconfig context to mint with (default: the one the share was made from)")
	renew.DurationVar(&kubeTTL, "ttl", kubeshare.DefaultTTL, "How long the new token lives (default: as long as the last one)")
	renew.BoolVar(&kubeLocal, "local", false, "Mint the token with your own credentials even when the hub renews the share")
	revoke := remoteKubeRevokeCmd.Flags()
	revoke.StringVar(&kubeContext, "context", "", "The kubeconfig context to delete with (default: the one the share was made from)")
	revoke.BoolVar(&kubeForce, "force", false, "Delete the hub's secret even if the cluster's objects could not be")
	for _, c := range []*cobra.Command{remoteKubeShareCmd, remoteKubeRenewCmd, remoteKubeRevokeCmd} {
		c.Flags().StringVar(&kubeKubeconfig, "kubeconfig", "", "The kubeconfig file to read (default: $KUBECONFIG, else ~/.kube/config)")
	}

	remoteKubeCmd.AddCommand(remoteKubeShareCmd, remoteKubeListCmd, remoteKubeRenewCmd, remoteKubeRevokeCmd)
	remoteCmd.AddCommand(remoteKubeCmd)
}
