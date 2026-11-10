package cmd

// `cloop executor pool` (Task 20486): executor pools on a hub, from a terminal
// — the dashboard's pool calls (/api/executor-pools), made with this terminal's
// session (`cloop login`) or an API token, so each is authorised exactly as the
// Executors panel's buttons are: executor.manage, and on a hub with single
// sign-on a recent sign-in for every change.
//
//	cloop executor pool create <name> --max-runners N   pool, access list and credential in one step,
//	                                                     with the commands that install its controller
//	cloop executor pool list | show <pool>              demand, runners, volumes, controllers, problems
//	cloop executor pool cordon | uncordon <pool>        hold the pool, or release it
//	cloop executor pool revoke <pool>                   revoke it and everything it holds
//	cloop executor pool rotate-credential <pool>        a new controller credential; --finish revokes the old
//
// A controller credential is shown once, by the command that minted it.

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/blechschmidt/cloop/pkg/hubclient"
	"github.com/blechschmidt/cloop/pkg/kubecontroller"
)

var (
	poolHub   string
	poolToken string
	poolJSON  bool

	poolMaxRunners    int
	poolLabels        []string
	poolAudience      []string
	poolOwner         string
	poolHarnesses     []string
	poolWorkDirRoot   string
	poolNamespace     string
	poolRelease       string
	poolMinRunners    int
	poolPersistence   bool
	poolStorageClass  string
	poolStorageSize   string
	poolReclaimPolicy string
	poolReason        string
	poolYes           bool
	poolFinish        bool
	poolForce         bool
)

var executorPoolCmd = &cobra.Command{
	Use:   "pool",
	Short: "Executor pools on a hub: create, watch, cordon, revoke, rotate credentials",
	Long: `Executor pools on a cloop hub: sets of ephemeral runners that the executor controller
starts on a Kubernetes cluster as a pool's queued runs need them.

Every command is one of the dashboard's own calls, made as the identity this terminal
signed in as with ` + "`cloop login`" + ` (or --token), and needs executor.manage. On a hub with
single sign-on, changes also need a recent sign-in: run ` + "`cloop login`" + ` again when asked.

A pool is named by its name or its id, as ` + "`cloop executor pool list`" + ` shows them.`,
}

var executorPoolCreateCmd = &cobra.Command{
	Use:   "create <name>",
	Short: "Create a pool, its access list and a controller credential, and print the install commands",
	Long: `Create an executor pool on the hub, admit --audience principals to its access list, and
mint its first controller credential, in one step. The credential is printed once, inside
the commands that install the executor controller on a cluster with it: paste them where
kubectl and helm reach the cluster.

Bind a project to the pool as pool:<id> (` + "`cloop remote init --executor pool:<id>`" + `, or the
project's executor picker in the dashboard), then watch it scale with
` + "`cloop executor pool show <name>`" + `.`,
	Example: `  cloop executor pool create gpu --max-runners 4 --label gpu=true \
    --audience group:ml-team --persistence --size 50Gi`,
	Args: cobra.ExactArgs(1),
	RunE: runExecutorPoolCreate,
}

var executorPoolListCmd = &cobra.Command{
	Use:   "list",
	Short: "List the hub's executor pools with their demand, runners and controllers",
	Args:  cobra.NoArgs,
	RunE:  runExecutorPoolList,
}

var executorPoolShowCmd = &cobra.Command{
	Use:   "show <pool>",
	Short: "Show a pool: its runners, queue, volumes, controllers and what needs attention",
	Args:  cobra.ExactArgs(1),
	RunE:  runExecutorPoolShow,
}

var executorPoolUpdateCmd = &cobra.Command{
	Use:   "update <pool>",
	Short: "Change how many runners a pool may have at once",
	Long: `Change a pool's max_runners on the hub, keeping the rest of its definition. The controller
starts no more runners than the lower of this and its ExecutorPool's spec.maxRunners, so
raising it also needs the cluster side: the command prints the helm upgrade that does it
for a controller installed with the defaults (--namespace and --release name another).`,
	Args: cobra.ExactArgs(1),
	RunE: runExecutorPoolUpdate,
}

var executorPoolRevokeCmd = &cobra.Command{
	Use:   "revoke <pool>",
	Short: "Revoke a pool: its credentials, runners and queued runs go with it",
	Long: `Revoke an executor pool. In one transaction the hub revokes its controller credentials and
unredeemed runner tokens, retires its runners — ending their connections and the leases of
the runs they hold — and cancels the runs waiting for it. A revoked pool cannot be restored.`,
	Args: cobra.ExactArgs(1),
	RunE: runExecutorPoolRevoke,
}

var executorPoolCordonCmd = &cobra.Command{
	Use:   "cordon <pool>",
	Short: "Hold a pool: no run is handed to its runners and no runner is started; busy ones finish",
	Args:  cobra.ExactArgs(1),
	RunE:  func(cmd *cobra.Command, args []string) error { return runExecutorPoolCordon(cmd, args[0], true) },
}

var executorPoolUncordonCmd = &cobra.Command{
	Use:   "uncordon <pool>",
	Short: "Release a cordoned pool",
	Args:  cobra.ExactArgs(1),
	RunE:  func(cmd *cobra.Command, args []string) error { return runExecutorPoolCordon(cmd, args[0], false) },
}

var executorPoolRotateCmd = &cobra.Command{
	Use:   "rotate-credential <pool>",
	Short: "Mint a new controller credential, then --finish to revoke the old ones",
	Long: `Rotate a pool's controller credential in two steps, so no run loses its runner:

  1. cloop executor pool rotate-credential <pool>
     mints a new credential and prints, once, the command that puts it in the controller's
     Secret. The controller reads the Secret again within five minutes. The old credential
     keeps working meanwhile.
  2. cloop executor pool rotate-credential <pool> --finish
     revokes every older credential once the new one has been used. Revoking a credential
     retires the runners it started, so --finish waits for those to finish their runs
     unless you pass --force.

--namespace and --release name the controller's install when it is not the default
(cloop-<pool> and <pool>).`,
	Args: cobra.ExactArgs(1),
	RunE: runExecutorPoolRotate,
}

func poolClient() (*hubclient.Client, error) { return hubClientFor(poolHub, poolToken) }

// writeJSON prints v as indented JSON.
func writeJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

// parsePoolAudience reads --audience kind:value flags.
func parsePoolAudience(in []string) ([]hubclient.PoolAudienceEntry, error) {
	var out []hubclient.PoolAudienceEntry
	for _, raw := range in {
		kind, value, ok := strings.Cut(strings.TrimSpace(raw), ":")
		kind = strings.ToLower(strings.TrimSpace(kind))
		value = strings.TrimSpace(value)
		if !ok || value == "" || (kind != "user" && kind != "group" && kind != "role") {
			return nil, fmt.Errorf("invalid --audience %q: expected user:<email or subject>, group:<name> or role:<role>", raw)
		}
		out = append(out, hubclient.PoolAudienceEntry{Kind: kind, Value: value})
	}
	return out, nil
}

func runExecutorPoolCreate(cmd *cobra.Command, args []string) error {
	labels, err := parseLabelPairs(poolLabels)
	if err != nil {
		return err
	}
	audience, err := parsePoolAudience(poolAudience)
	if err != nil {
		return err
	}
	if poolMaxRunners < 1 {
		return errors.New("--max-runners is required: the most runners the pool may have at once")
	}
	req := hubclient.CreatePoolRequest{Name: strings.TrimSpace(args[0]), Labels: labels, MaxRunners: poolMaxRunners,
		Owner: poolOwner, WorkDirRoot: poolWorkDirRoot, Audience: audience, Credential: true,
		Capabilities: hubclient.PoolCapabilities{Harnesses: poolHarnesses},
		Kubernetes:   &hubclient.PoolInstallOptions{Namespace: poolNamespace, Release: poolRelease, MinRunners: poolMinRunners}}
	if poolPersistence {
		req.Kubernetes.Persistence = &hubclient.PoolPersistence{Enabled: true, StorageClass: poolStorageClass,
			Size: poolStorageSize, ReclaimPolicy: poolReclaimPolicy}
	} else if poolStorageClass != "" || poolStorageSize != "" || poolReclaimPolicy != "" {
		return errors.New("--storage-class, --size and --reclaim-policy shape runner volumes: add --persistence")
	}
	c, err := poolClient()
	if err != nil {
		return err
	}
	created, err := c.CreateExecutorPool(remoteContext(cmd), req)
	if err != nil {
		return remoteErr(c, err)
	}
	out := cmd.OutOrStdout()
	if poolJSON {
		return writeJSON(out, created)
	}
	p := created.Pool
	fmt.Fprintf(out, "Created executor pool %s (%s) on %s: at most %d runners.\n", p.Name, p.ID, c.Base, p.MaxRunners)
	if len(created.Audience) > 0 {
		names := make([]string, 0, len(created.Audience))
		for _, a := range created.Audience {
			names = append(names, a.Kind+":"+a.Value)
		}
		fmt.Fprintf(out, "Only these may run work on its runners: %s.\n", strings.Join(names, ", "))
	} else {
		fmt.Fprintln(out, "It has no access list: any project bound to it may run there.")
	}
	if created.Credential != nil {
		fmt.Fprintf(out, "\nController credential %s, shown once — it cannot be recovered:\n  %s\n",
			created.Credential.ID, created.Token)
	}
	if in := created.Install; in != nil {
		if in.Command != "" {
			fmt.Fprintf(out, "\nInstall the executor controller with it, where kubectl and helm reach the cluster:\n\n%s",
				indent(in.Command, "  "))
		} else if in.Unavailable != "" {
			fmt.Fprintf(out, "\n%s\n", in.Unavailable)
		}
		for _, n := range in.Notes {
			fmt.Fprintf(out, "\nNote: %s\n", n)
		}
	}
	fmt.Fprintf(out, "\nBind a project to it as %s, and watch it scale: cloop executor pool show %s\n",
		p.Binding, quoteArg(p.Name))
	return nil
}

// indent prefixes every non-empty line of s.
func indent(s, prefix string) string {
	var b strings.Builder
	for _, line := range strings.SplitAfter(s, "\n") {
		if strings.TrimSpace(line) != "" {
			b.WriteString(prefix)
		}
		b.WriteString(line)
	}
	return b.String()
}

func runExecutorPoolList(cmd *cobra.Command, _ []string) error {
	c, err := poolClient()
	if err != nil {
		return err
	}
	list, err := c.ExecutorPools(remoteContext(cmd))
	if err != nil {
		return remoteErr(c, err)
	}
	out := cmd.OutOrStdout()
	if poolJSON {
		return writeJSON(out, list)
	}
	if len(list.Pools) == 0 {
		fmt.Fprintf(out, "%s has no executor pools. Create one with: cloop executor pool create <name> --max-runners N\n", c.Base)
		return nil
	}
	w := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "NAME\tID\tSTATE\tWAITING\tBUSY\tIDLE\tSTARTING\tMAX\tVOLUMES\tCONTROLLER\tLAST CONTACT\tPROBLEMS")
	now := time.Now()
	for _, p := range list.Pools {
		var snap hubclient.PoolSnapshot
		if p.Snapshot != nil {
			snap = *p.Snapshot
		}
		h := p.Health
		if h == nil {
			h = &hubclient.PoolHealth{}
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%d\t%d\t%d\t%d\t%d\t%s\t%s\t%s\t%d\n", truncateField(p.Name, 32), p.ID, p.State(),
			snap.Waiting, snap.Busy, snap.Idle, snap.Pending, p.MaxRunners, volumesCell(h.Storage),
			controllerCell(h.Controller), contactCell(h.LastContact, now), len(h.Problems))
	}
	if err := w.Flush(); err != nil {
		return err
	}
	for _, p := range list.Pools {
		if p.Health == nil {
			continue
		}
		for _, pr := range p.Health.Problems {
			fmt.Fprintf(out, "\n%s %s", strings.ToUpper(pr.Severity), pr.Message)
		}
	}
	if anyProblems(list.Pools) {
		fmt.Fprintln(out)
	}
	return nil
}

func anyProblems(pools []hubclient.ExecutorPool) bool {
	for _, p := range pools {
		if p.Health != nil && len(p.Health.Problems) > 0 {
			return true
		}
	}
	return false
}

func volumesCell(s *hubclient.PoolStorage) string {
	if s == nil {
		return "-"
	}
	cell := fmt.Sprintf("%d/%d bound", s.Bound, s.Claims)
	if s.Pending > 0 {
		cell += fmt.Sprintf(", %d pending", s.Pending)
	}
	return cell
}

func controllerCell(c *hubclient.PoolController) string {
	if c == nil {
		return "none yet"
	}
	v := c.Version
	if v == "" {
		v = "unnamed"
	}
	cell := fmt.Sprintf("%s (p%d)", v, c.Protocol)
	if c.Behind {
		cell += " behind"
	}
	return cell
}

func contactCell(t time.Time, now time.Time) string {
	if t.IsZero() || t.Year() <= 1 {
		return "never"
	}
	return ago(now.Sub(t))
}

// ago renders an age the way a person reads one.
func ago(d time.Duration) string {
	switch {
	case d < 0:
		return "just now"
	case d < 90*time.Second:
		return fmt.Sprintf("%ds ago", int(d.Seconds()))
	case d < 90*time.Minute:
		return fmt.Sprintf("%dm ago", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%dh ago", int(d.Hours()))
	}
	return fmt.Sprintf("%dd ago", int(d.Hours()/24))
}

func humanSize(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}

func runExecutorPoolShow(cmd *cobra.Command, args []string) error {
	c, err := poolClient()
	if err != nil {
		return err
	}
	ctx := remoteContext(cmd)
	ref, err := c.ResolveExecutorPool(ctx, args[0])
	if err != nil {
		return remoteErr(c, err)
	}
	d, err := c.ExecutorPool(ctx, ref.ID)
	if err != nil {
		return remoteErr(c, err)
	}
	out := cmd.OutOrStdout()
	if poolJSON {
		return writeJSON(out, d)
	}
	now := time.Now()
	fmt.Fprintf(out, "Executor pool %s (%s): %s\n", d.Name, d.ID, d.State())
	if d.Cordoned {
		why := ""
		if d.CordonReason != "" {
			why = ": " + d.CordonReason
		}
		fmt.Fprintf(out, "  cordoned by %s %s%s\n", orDash(d.CordonedBy), ago(now.Sub(d.CordonedAt)), why)
	}
	fmt.Fprintf(out, "  binding:      %s\n", d.Binding)
	fmt.Fprintf(out, "  max runners:  %d\n", d.MaxRunners)
	if len(d.Labels) > 0 {
		keys := make([]string, 0, len(d.Labels))
		for k := range d.Labels {
			keys = append(keys, k+"="+d.Labels[k])
		}
		sort.Strings(keys)
		fmt.Fprintf(out, "  labels:       %s\n", strings.Join(keys, ", "))
	}
	if d.Owner != "" {
		fmt.Fprintf(out, "  owner:        %s\n", d.Owner)
	}
	if len(d.Audience) > 0 {
		names := make([]string, 0, len(d.Audience))
		for _, a := range d.Audience {
			names = append(names, a.Kind+":"+a.Value)
		}
		fmt.Fprintf(out, "  access list:  %s\n", strings.Join(names, ", "))
	} else {
		fmt.Fprintln(out, "  access list:  none (any project bound to it)")
	}
	if s := d.Snapshot; s != nil {
		fmt.Fprintf(out, "  runners:      %d busy, %d idle, %d starting (%d of %d)\n", s.Busy, s.Idle, s.Pending, s.Runners,
			d.MaxRunners)
		fmt.Fprintf(out, "  waiting:      %d run(s); the controller is asked for %d more runner(s)\n", s.Waiting, s.Wanted)
	}
	if h := d.Health; h != nil {
		if h.Storage != nil {
			s := h.Storage
			fmt.Fprintf(out, "  volumes:      %d claims, %d bound, %d pending, %d in use, %d full; %s of %s used\n",
				s.Claims, s.Bound, s.Pending, s.InUse, s.Full, humanSize(s.BytesUsed), humanSize(s.BytesCapacity))
		}
		fmt.Fprintf(out, "  controller:   %s, last contact %s\n", controllerCell(h.Controller), contactCell(h.LastContact, now))
		for _, pr := range h.Problems {
			fmt.Fprintf(out, "\n%s %s\n", strings.ToUpper(pr.Severity), pr.Message)
			if pr.Remedy != "" {
				fmt.Fprintf(out, "  to fix: %s\n", pr.Remedy)
			}
			if pr.Kind == "controller_behind" {
				list, err := c.ExecutorPools(ctx)
				if err == nil {
					plan := kubecontroller.InstallPlan{PoolName: d.Name, Chart: list.Chart, ImageTag: list.ImageTag}.Normalize()
					fmt.Fprintf(out, "  for a controller installed with the defaults:\n%s", indent(plan.UpgradeCommand(), "    "))
				}
			}
		}
	}
	if len(d.Runners) > 0 {
		fmt.Fprintln(out, "\nRunners:")
		w := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "  NAME\tSTATE\tEXECUTOR\tMINTED\tCREDENTIAL\tRETIRED")
		for _, r := range d.Runners {
			retired := "-"
			if r.State == "retired" {
				retired = r.RetireReason
			}
			fmt.Fprintf(w, "  %s\t%s\t%s\t%s\t%s\t%s\n", r.Name, r.State, orDash(r.ExecutorID), ago(now.Sub(r.MintedAt)),
				orDash(r.CredentialID), truncateField(retired, 60))
		}
		_ = w.Flush()
	}
	if len(d.Queue) > 0 {
		fmt.Fprintln(out, "\nQueue:")
		w := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "  PROJECT\tSTATE\tQUEUED\tEXECUTOR\tREASON")
		for _, q := range d.Queue {
			fmt.Fprintf(w, "  %s\t%s\t%s\t%s\t%s\n", q.ProjectPath, q.State, ago(now.Sub(q.CreatedAt)), orDash(q.ExecutorID),
				truncateField(q.Reason, 80))
		}
		_ = w.Flush()
	}
	if len(d.Credentials) > 0 {
		fmt.Fprintln(out, "\nController credentials:")
		w := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "  ID\tCREATED\tLAST USED\tCONTROLLER\tREVOKED")
		for _, cr := range d.Credentials {
			used := "never"
			if cr.Used() {
				used = ago(now.Sub(cr.LastUsedAt))
			}
			revoked := "-"
			if cr.Revoked() {
				revoked = ago(now.Sub(cr.RevokedAt))
			}
			ctl := "-"
			if cr.ControllerVersion != "" || cr.ControllerProtocol > 0 {
				ctl = fmt.Sprintf("%s (p%d)", orDash(cr.ControllerVersion), cr.ControllerProtocol)
			}
			fmt.Fprintf(w, "  %s\t%s\t%s\t%s\t%s\n", cr.ID, ago(now.Sub(cr.CreatedAt)), used, ctl, revoked)
		}
		_ = w.Flush()
	}
	return nil
}

// confirm asks a yes/no question on a terminal; without one it refuses
// unless --yes was given.
func confirm(cmd *cobra.Command, question string) error {
	if poolYes {
		return nil
	}
	if !interactive() {
		return errors.New("refusing without --yes: this is not a terminal to ask on")
	}
	fmt.Fprintf(cmd.ErrOrStderr(), "%s [y/N] ", question)
	answer, _ := bufio.NewReader(cmd.InOrStdin()).ReadString('\n')
	switch strings.ToLower(strings.TrimSpace(answer)) {
	case "y", "yes":
		return nil
	}
	return errors.New("not confirmed; nothing was changed")
}

func runExecutorPoolRevoke(cmd *cobra.Command, args []string) error {
	c, err := poolClient()
	if err != nil {
		return err
	}
	ctx := remoteContext(cmd)
	p, err := c.ResolveExecutorPool(ctx, args[0])
	if err != nil {
		return remoteErr(c, err)
	}
	busy := 0
	if p.Snapshot != nil {
		busy = p.Snapshot.Busy
	}
	q := fmt.Sprintf("Revoke executor pool %s? Its controller credentials, runners and queued runs go with it", p.Name)
	if busy > 0 {
		q += fmt.Sprintf(", and %d run(s) in progress lose their runner", busy)
	}
	if err := confirm(cmd, q+"."); err != nil {
		return err
	}
	rev, err := c.RevokeExecutorPool(ctx, p.ID)
	if err != nil {
		return remoteErr(c, err)
	}
	out := cmd.OutOrStdout()
	if poolJSON {
		return writeJSON(out, rev)
	}
	fmt.Fprintf(out, "Revoked executor pool %s: %d controller credential(s), %d unredeemed runner token(s), %d runner(s) "+
		"retired, %d queued run(s) cancelled.\n", p.Name, rev.Credentials, rev.Tokens, len(rev.Runners), rev.CancelledRuns)
	fmt.Fprintln(out, "Delete its controller's release from the cluster too: helm uninstall <release> -n <namespace>")
	return nil
}

func runExecutorPoolUpdate(cmd *cobra.Command, args []string) error {
	if poolMaxRunners < 1 {
		return errors.New("--max-runners is required: the most runners the pool may have at once")
	}
	c, err := poolClient()
	if err != nil {
		return err
	}
	ctx := remoteContext(cmd)
	p, err := c.ResolveExecutorPool(ctx, args[0])
	if err != nil {
		return remoteErr(c, err)
	}
	spec := p.Spec()
	before := spec.MaxRunners
	spec.MaxRunners = poolMaxRunners
	next, err := c.UpdateExecutorPool(ctx, p.ID, spec)
	if err != nil {
		return remoteErr(c, err)
	}
	out := cmd.OutOrStdout()
	if poolJSON {
		return writeJSON(out, next)
	}
	fmt.Fprintf(out, "Executor pool %s may now have %d runners at once (it was %d).\n", next.Name, next.MaxRunners, before)
	list, err := c.ExecutorPools(ctx)
	if err == nil {
		plan := kubecontroller.InstallPlan{PoolName: next.Name, Chart: list.Chart, Namespace: poolNamespace,
			Release: poolRelease}.Normalize()
		fmt.Fprintf(out, "The controller starts no more than its ExecutorPool's spec.maxRunners allows. To match it:\n  "+
			"helm upgrade %s %s -n %s --reuse-values --set pool.maxRunners=%d\n", plan.Release, plan.Chart,
			plan.Namespace, next.MaxRunners)
	}
	return nil
}

func runExecutorPoolCordon(cmd *cobra.Command, ref string, cordon bool) error {
	c, err := poolClient()
	if err != nil {
		return err
	}
	ctx := remoteContext(cmd)
	p, err := c.ResolveExecutorPool(ctx, ref)
	if err != nil {
		return remoteErr(c, err)
	}
	next, changed, err := c.CordonExecutorPool(ctx, p.ID, cordon, poolReason)
	if err != nil {
		return remoteErr(c, err)
	}
	out := cmd.OutOrStdout()
	if poolJSON {
		return writeJSON(out, map[string]any{"changed": changed, "pool": next})
	}
	switch {
	case cordon && changed:
		fmt.Fprintf(out, "Cordoned executor pool %s: no run is handed to its runners and no runner is started; "+
			"busy runners finish their runs. Release it with: cloop executor pool uncordon %s\n", next.Name, quoteArg(next.Name))
	case cordon:
		fmt.Fprintf(out, "Executor pool %s was already cordoned.\n", next.Name)
	case changed:
		fmt.Fprintf(out, "Uncordoned executor pool %s: its waiting runs are handed out again.\n", next.Name)
	default:
		fmt.Fprintf(out, "Executor pool %s was not cordoned.\n", next.Name)
	}
	return nil
}

func runExecutorPoolRotate(cmd *cobra.Command, args []string) error {
	c, err := poolClient()
	if err != nil {
		return err
	}
	ctx := remoteContext(cmd)
	p, err := c.ResolveExecutorPool(ctx, args[0])
	if err != nil {
		return remoteErr(c, err)
	}
	d, err := c.ExecutorPool(ctx, p.ID)
	if err != nil {
		return remoteErr(c, err)
	}
	if poolFinish {
		return finishPoolRotation(cmd, c, d)
	}
	minted, err := c.MintPoolCredential(ctx, d.ID)
	if err != nil {
		return remoteErr(c, err)
	}
	out := cmd.OutOrStdout()
	plan := kubecontroller.InstallPlan{PoolName: d.Name, Namespace: poolNamespace, Release: poolRelease}.Normalize()
	if poolJSON {
		return writeJSON(out, map[string]any{"credential": minted.Credential, "token": minted.Token,
			"command": plan.RotationScript(minted.Token), "notice": minted.Notice})
	}
	fmt.Fprintf(out, "New controller credential %s for executor pool %s, shown once — it cannot be recovered:\n  %s\n",
		minted.Credential.ID, d.Name, minted.Token)
	fmt.Fprintf(out, "\nPut it in the controller's Secret (namespace %s, release %s; --namespace and --release name "+
		"another install):\n\n%s", plan.Namespace, plan.Release, indent(plan.RotationScript(minted.Token), "  "))
	var old []string
	for _, cr := range d.Credentials {
		if !cr.Revoked() {
			old = append(old, cr.ID)
		}
	}
	fmt.Fprintln(out, "\nThe controller reads the Secret again within five minutes.")
	if len(old) > 0 {
		fmt.Fprintf(out, "The previous credential(s) %s keep working until you run:\n  cloop executor pool rotate-credential %s --finish\n",
			strings.Join(old, ", "), quoteArg(d.Name))
	}
	return nil
}

// finishPoolRotation revokes every live credential but the newest, once the
// newest has been used — and, unless forced, once no runner an older one
// started is busy.
func finishPoolRotation(cmd *cobra.Command, c *hubclient.Client, d *hubclient.PoolDetail) error {
	var live []hubclient.PoolCredential
	for _, cr := range d.Credentials {
		if !cr.Revoked() {
			live = append(live, cr)
		}
	}
	if len(live) == 0 {
		return fmt.Errorf("executor pool %s has no live controller credential: mint one with `cloop executor pool "+
			"rotate-credential %s`", d.Name, quoteArg(d.Name))
	}
	sort.SliceStable(live, func(i, j int) bool { return live[i].CreatedAt.After(live[j].CreatedAt) })
	newest, older := live[0], live[1:]
	out := cmd.OutOrStdout()
	if len(older) == 0 {
		fmt.Fprintf(out, "Executor pool %s has one live controller credential, %s: nothing to finish.\n", d.Name, newest.ID)
		return nil
	}
	// The controller has moved to the newest credential when that one was used
	// after every older one was: it holds one credential at a time, and an
	// older one it stopped presenting stops being used. A credential used once
	// by somebody testing it is not that.
	switched := newest.Used()
	for _, cr := range older {
		if cr.Used() && !newest.LastUsedAt.After(cr.LastUsedAt) {
			switched = false
		}
	}
	if !switched && !poolForce {
		return fmt.Errorf("the controller has not moved to the newest credential %s yet (an older one was used as "+
			"recently or more): put it in the controller's Secret and wait until `cloop executor pool show %s` shows "+
			"it used last, or pass --force to revoke the older ones anyway (the controller is then refused until it "+
			"reads the new one)", newest.ID, quoteArg(d.Name))
	}
	if err := checkRetiring(d, older); err != nil && !poolForce {
		return err
	}
	ctx := remoteContext(cmd)
	revoked := 0
	for _, cr := range older {
		// Read again just before each revocation: a runner the credential
		// started may have been handed a run since.
		if !poolForce {
			fresh, err := c.ExecutorPool(ctx, d.ID)
			if err != nil {
				return remoteErr(c, err)
			}
			if err := checkRetiring(fresh, []hubclient.PoolCredential{cr}); err != nil {
				return err
			}
		}
		rev, err := c.RevokePoolCredential(ctx, d.ID, cr.ID)
		if err != nil {
			return remoteErr(c, err)
		}
		revoked++
		if !poolJSON {
			fmt.Fprintf(out, "Revoked credential %s: %d runner token(s), %d runner(s) retired.\n", cr.ID, rev.Tokens,
				len(rev.Runners))
		}
	}
	if poolJSON {
		return writeJSON(out, map[string]any{"pool_id": d.ID, "kept": newest.ID, "revoked": revoked})
	}
	fmt.Fprintf(out, "Executor pool %s's controller now holds the only live credential, %s.\n", d.Name, newest.ID)
	return nil
}

// checkRetiring refuses to revoke credentials whose runners are busy: a
// revocation retires what the credential started, mid-run. A busy runner the
// hub names no credential for — a hub older than this command — may be any
// credential's, so it refuses too.
func checkRetiring(d *hubclient.PoolDetail, creds []hubclient.PoolCredential) error {
	retiring := map[string]bool{}
	for _, cr := range creds {
		retiring[cr.ID] = true
	}
	busy, unknown := 0, 0
	for _, r := range d.Runners {
		switch {
		case r.State != "busy":
		case r.CredentialID == "":
			unknown++
		case retiring[r.CredentialID]:
			busy++
		}
	}
	switch {
	case busy > 0:
		return fmt.Errorf("%d busy runner(s) were started with a credential this would revoke, which retires them "+
			"mid-run: run --finish again when they are done, or pass --force", busy)
	case unknown > 0:
		return fmt.Errorf("%d busy runner(s) were started with a credential the hub does not name, so revoking may "+
			"retire them mid-run: run --finish again when they are done, or pass --force", unknown)
	}
	return nil
}

func init() {
	pf := executorPoolCmd.PersistentFlags()
	// No backticks in a flag's usage: pflag would read the quoted words as the
	// flag's value name.
	pf.StringVar(&poolHub, "hub", "", "Hub URL (default: the default hub from cloop login, or CLOOP_HUB_URL)")
	pf.StringVar(&poolToken, "token", "",
		"API token to use instead of the stored session (CLOOP_API_TOKEN: for CLOOP_HUB_URL's hub, or one with no stored session)")
	pf.BoolVar(&poolJSON, "json", false, "Print JSON")

	f := executorPoolCreateCmd.Flags()
	f.IntVar(&poolMaxRunners, "max-runners", 0, "The most runners the pool may have at once (required, 1-1000)")
	f.StringSliceVar(&poolLabels, "label", nil,
		"label as key=value (repeatable): what the runners enroll with, and grants to label:key=value reach")
	f.StringSliceVar(&poolAudience, "audience", nil,
		"who may run work on its runners, as user:<email>, group:<name> or role:<role> (repeatable; none is everyone)")
	f.StringVar(&poolOwner, "owner", "", "the pool's owner (an email): its runners run only projects the owner may read")
	f.StringSliceVar(&poolHarnesses, "harness", nil, "a harness the runner image has, such as claude (repeatable)")
	f.StringVar(&poolWorkDirRoot, "workdir-root", "", "the root the runners confine workloads to")
	f.StringVar(&poolNamespace, "namespace", "", "the controller's namespace (default cloop-<name>)")
	f.StringVar(&poolRelease, "release", "", "the controller's Helm release (default <name>)")
	f.IntVar(&poolMinRunners, "min-runners", 0, "runners kept started beyond the demand")
	f.BoolVar(&poolPersistence, "persistence", false,
		"give runners volumes that keep a project's workspace and caches for its next run")
	f.StringVar(&poolStorageClass, "storage-class", "", "the volumes' StorageClass (default the cluster's)")
	f.StringVar(&poolStorageSize, "size", "", "each volume's size (default "+kubecontroller.DefaultPersistenceSize+")")
	f.StringVar(&poolReclaimPolicy, "reclaim-policy", "", "Delete (default) or Retain volumes the pool no longer needs")

	uf := executorPoolUpdateCmd.Flags()
	uf.IntVar(&poolMaxRunners, "max-runners", 0, "The most runners the pool may have at once (required, 1-1000)")
	uf.StringVar(&poolNamespace, "namespace", "", "the controller's namespace, for the helm command (default cloop-<pool>)")
	uf.StringVar(&poolRelease, "release", "", "the controller's Helm release, for the helm command (default <pool>)")
	executorPoolRevokeCmd.Flags().BoolVarP(&poolYes, "yes", "y", false, "do not ask for confirmation")
	executorPoolCordonCmd.Flags().StringVar(&poolReason, "reason", "", "why, for the people whose runs wait")
	rf := executorPoolRotateCmd.Flags()
	rf.BoolVar(&poolFinish, "finish", false, "revoke every older credential once the newest has been used")
	rf.BoolVar(&poolForce, "force", false, "with --finish: revoke even if the newest is unused or old runners are busy")
	rf.StringVar(&poolNamespace, "namespace", "", "the controller's namespace (default cloop-<pool>)")
	rf.StringVar(&poolRelease, "release", "", "the controller's Helm release (default <pool>)")

	executorPoolCmd.AddCommand(executorPoolCreateCmd, executorPoolListCmd, executorPoolShowCmd, executorPoolUpdateCmd,
		executorPoolRevokeCmd,
		executorPoolCordonCmd, executorPoolUncordonCmd, executorPoolRotateCmd)
	executorCmd.AddCommand(executorPoolCmd)
}
