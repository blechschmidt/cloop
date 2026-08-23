// Scoped secret grants (Task 20159).
//
// The legacy `cloop secret set/get/list/delete/export` subcommands in
// secret.go still manage the flat .cloop/secrets.enc store. These add the
// broker on top: kinded secrets, subject-scoped grants with enforced
// constraints, and TTLs.
//
// The two coexist deliberately during the transition. `cloop secret migrate`
// imports the flat store into the broker as unscoped env secrets, and until
// an operator runs it — and tightens the resulting grants — nothing about
// the old behaviour changes.

package cmd

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/secretbroker"
	"github.com/blechschmidt/cloop/pkg/secretstore"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var (
	grantToFlag         string
	grantReposFlag      []string
	grantPermsFlag      []string
	grantNamespacesFlag []string
	grantContextsFlag   []string
	grantHostsFlag      []string
	grantRegistriesFlag []string
	grantEnvKeysFlag    []string
	grantWritableFlag   bool
	grantTTLFlag        string
	grantScopeFlag      string

	grantsSubjectFlag string
	grantsSecretFlag  string
	grantsAllFlag     bool

	mintKindFlag  string
	mintFileFlag  string
	mintValueFlag string
)

// openBroker builds a broker over the current project's state database,
// wired to the hash-chained audit log.
//
// The returned close function must be called. It closes the database, not
// the broker: leases hold no persistent resources, by design.
func openBroker() (*secretbroker.Broker, func(), error) {
	workDir, err := os.Getwd()
	if err != nil {
		return nil, nil, fmt.Errorf("secret: resolve working directory: %w", err)
	}
	db, err := statedb.Open(state.DBPath(workDir))
	if err != nil {
		return nil, nil, fmt.Errorf("secret: open state database: %w", err)
	}
	store, err := secretstore.New(db)
	if err != nil {
		_ = db.Close()
		return nil, nil, err
	}
	broker, err := secretbroker.New(store, secretbroker.WithAuditor(secretstore.NewAuditor(db)))
	if err != nil {
		_ = db.Close()
		return nil, nil, err
	}
	return broker, func() { _ = db.Close() }, nil
}

// currentActor identifies who ran the command, for the audit trail. cloop
// has no CLI-side identity yet, so the OS user is the best available answer
// and is better than a constant "cli".
func currentActor() string {
	if u := os.Getenv("USER"); u != "" {
		return "cli:" + u
	}
	if u := os.Getenv("USERNAME"); u != "" {
		return "cli:" + u
	}
	return "cli"
}

var secretMintCmd = &cobra.Command{
	Use:   "mint <name>",
	Short: "Store a kinded secret in the broker",
	Long: `Seal a credential into the broker with a kind that determines how it is
constrained and delivered.

Kinds: github_pat, github_app, kubeconfig, registry, env, egress_proxy,
local_repo

The payload comes from --value, from --file, or from stdin. Prefer --file or
stdin: a --value argument is visible in the process table and in shell history.
A local_repo is the exception: its payload is a path, not a credential, so
--value is the natural way to give it.

  cloop secret mint deploy-pat --kind github_pat --file token.txt
  cloop secret mint prod-kube  --kind kubeconfig --file ~/.kube/config
  cloop secret mint dev-src    --kind local_repo --value /home/dev/src
  cat token | cloop secret mint ci-pat --kind github_pat`,
	Args:         cobra.ExactArgs(1),
	SilenceUsage: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		kind, err := secretbroker.ParseKind(mintKindFlag)
		if err != nil {
			return err
		}
		payload, err := readMintPayload(cmd)
		if err != nil {
			return err
		}

		broker, closeFn, err := openBroker()
		if err != nil {
			return err
		}
		defer closeFn()

		s, err := broker.Mint(cmd.Context(), secretbroker.MintRequest{
			Name:    args[0],
			Kind:    kind,
			Payload: payload,
			Actor:   currentActor(),
		})
		if err != nil {
			return err
		}
		color.Green("✓ minted %s (%s) as %s", s.Name, s.Kind, s.ID)
		color.New(color.Faint).Println("  no grant yet — nothing can use it until you run 'cloop secret grant'")
		return nil
	},
}

// readMintPayload collects the credential from the least-exposed source
// available, preferring a file or stdin over an argv value.
func readMintPayload(cmd *cobra.Command) ([]byte, error) {
	switch {
	case mintFileFlag != "":
		data, err := os.ReadFile(mintFileFlag)
		if err != nil {
			return nil, fmt.Errorf("secret: read payload file: %w", err)
		}
		return data, nil
	case mintValueFlag != "":
		return []byte(mintValueFlag), nil
	default:
		info, err := os.Stdin.Stat()
		if err != nil || info.Mode()&os.ModeCharDevice != 0 {
			return nil, fmt.Errorf("secret: no payload — pass --file, --value, or pipe the credential on stdin")
		}
		data, err := readAllStdin()
		if err != nil {
			return nil, err
		}
		if len(strings.TrimSpace(string(data))) == 0 {
			return nil, fmt.Errorf("secret: stdin payload is empty")
		}
		return data, nil
	}
}

var secretGrantCmd = &cobra.Command{
	Use:   "grant <secret>",
	Short: "Grant a subject scoped, expiring access to a secret",
	Long: `Authorise a project, an executor, or a labelled fleet to use a secret,
under constraints that are enforced at delivery.

  cloop secret grant deploy-pat --to project:/srv/app --repos 'org/*' --ttl 24h
  cloop secret grant prod-kube  --to executor:edge-01 --namespaces team-a --ttl 8h
  cloop secret grant proxy      --to label:region=eu --hosts '*.internal.example.com'
  cloop secret grant dev-src    --to project:/srv/app --repos api,shared-'*'

Constraints are required, not optional: a github grant needs --repos, a
kubeconfig grant needs --namespaces and/or --contexts, an egress_proxy grant
needs --hosts, a registry grant needs --registries, and a local_repo grant
needs --repos. Pass '*' explicitly if you really mean "everything" — there is
no implicit wildcard.

A local_repo grant is read-only unless --writable is given. Its --repos
patterns match repository *directory names* under the granted root, not
owner/repo as they do for github.`,
	Args:         cobra.ExactArgs(1),
	SilenceUsage: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		if strings.TrimSpace(grantToFlag) == "" {
			return fmt.Errorf("secret: --to is required (e.g. --to project:/srv/app)")
		}
		subject, err := secretbroker.ParseSubject(grantToFlag)
		if err != nil {
			return err
		}
		ttl, err := parseGrantTTL(grantTTLFlag)
		if err != nil {
			return err
		}

		broker, closeFn, err := openBroker()
		if err != nil {
			return err
		}
		defer closeFn()

		g, err := broker.Grant(cmd.Context(), secretbroker.GrantRequest{
			SecretRef: args[0],
			Subject:   subject,
			Scope:     grantScopeFlag,
			TTL:       ttl,
			Constraints: secretbroker.Constraints{
				Repos:       grantReposFlag,
				Permissions: grantPermsFlag,
				Namespaces:  grantNamespacesFlag,
				Contexts:    grantContextsFlag,
				Hosts:       grantHostsFlag,
				Registries:  grantRegistriesFlag,
				EnvKeys:     grantEnvKeysFlag,
				Writable:    grantWritableFlag,
			},
			Actor: currentActor(),
		})
		if err != nil {
			return err
		}

		color.Green("✓ granted %s to %s", args[0], g.Subject.String())
		fmt.Printf("  grant:       %s\n", g.ID)
		fmt.Printf("  constraints: %s\n", g.Constraints.Summary())
		if g.ExpiresAt.IsZero() {
			color.New(color.FgYellow).Println("  expires:     never")
		} else {
			fmt.Printf("  expires:     %s (in %s)\n",
				g.ExpiresAt.Format(time.RFC3339), time.Until(g.ExpiresAt).Round(time.Minute))
		}
		return nil
	},
}

// parseGrantTTL accepts a Go duration. An empty value means the broker's
// default; "never" is spelled out because an unexpiring grant should look
// deliberate in a shell history.
func parseGrantTTL(s string) (time.Duration, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, fmt.Errorf("secret: invalid --ttl %q: %w (try 24h, 90m, 7d as 168h)", s, err)
	}
	if d <= 0 {
		return 0, fmt.Errorf("secret: --ttl must be positive, got %s", s)
	}
	return d, nil
}

var secretGrantsCmd = &cobra.Command{
	Use:   "grants",
	Short: "List secret grants",
	Long: `Show grants and their constraints.

By default only active grants are listed. --all includes expired and revoked
ones, which is what you want when answering "who had access to this".`,
	SilenceUsage: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		broker, closeFn, err := openBroker()
		if err != nil {
			return err
		}
		defer closeFn()

		filter := secretbroker.GrantFilter{
			SecretRef:  grantsSecretFlag,
			ActiveOnly: !grantsAllFlag,
		}
		if strings.TrimSpace(grantsSubjectFlag) != "" {
			subject, perr := secretbroker.ParseSubject(grantsSubjectFlag)
			if perr != nil {
				return perr
			}
			filter.Subject = subject.String()
		}

		grants, err := broker.ListGrants(filter)
		if err != nil {
			return err
		}
		if len(grants) == 0 {
			color.New(color.Faint).Println("No grants. Use 'cloop secret grant <secret> --to ...' to create one.")
			return nil
		}

		secrets, err := broker.ListSecrets()
		if err != nil {
			return err
		}
		names := make(map[string]string, len(secrets))
		kinds := make(map[string]string, len(secrets))
		for _, s := range secrets {
			names[s.ID] = s.Name
			kinds[s.ID] = string(s.Kind)
		}

		bold := color.New(color.Bold)
		fmt.Printf("%-32s %-18s %-13s %-24s %-10s %s\n",
			bold.Sprint("GRANT"), bold.Sprint("SECRET"), bold.Sprint("KIND"),
			bold.Sprint("SUBJECT"), bold.Sprint("EXPIRES"), bold.Sprint("CONSTRAINTS"))
		fmt.Println(strings.Repeat("─", 124))

		now := time.Now()
		for _, g := range grants {
			name := names[g.SecretID]
			if name == "" {
				name = "(deleted)"
			}
			fmt.Printf("%-32s %-18s %-13s %-24s %-10s %s\n",
				g.ID, truncateCol(name, 18), truncateCol(kinds[g.SecretID], 13),
				truncateCol(g.Subject.String(), 24), grantExpiryLabel(g, now),
				g.Constraints.Summary())
		}
		fmt.Printf("\n%d grant(s)\n", len(grants))
		return nil
	},
}

// grantExpiryLabel renders a grant's lifetime state compactly, colouring
// the states an operator needs to notice.
func grantExpiryLabel(g secretbroker.Grant, now time.Time) string {
	switch {
	case !g.RevokedAt.IsZero():
		return color.New(color.FgRed).Sprint("revoked")
	case g.ExpiresAt.IsZero():
		return color.New(color.FgYellow).Sprint("never")
	case !now.Before(g.ExpiresAt):
		return color.New(color.FgRed).Sprint("expired")
	default:
		return time.Until(g.ExpiresAt).Round(time.Minute).String()
	}
}

func truncateCol(s string, width int) string {
	if len(s) <= width {
		return s
	}
	if width <= 1 {
		return s[:width]
	}
	return s[:width-1] + "…"
}

var secretRevokeCmd = &cobra.Command{
	Use:   "revoke <grant-id>",
	Short: "Revoke a grant",
	Long: `Withdraw a grant. It stops being honoured on the next lease or renewal.

Credentials already materialised inside a running workload survive until that
workload's lease expires — which is what the short lease TTL bounds. To cut
access immediately, revoke and then stop the run.`,
	Args:         cobra.ExactArgs(1),
	SilenceUsage: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		broker, closeFn, err := openBroker()
		if err != nil {
			return err
		}
		defer closeFn()

		if err := broker.Revoke(cmd.Context(), args[0], currentActor()); err != nil {
			return err
		}
		color.Green("✓ revoked grant %s", args[0])
		color.New(color.Faint).Println("  takes effect on the next lease; running workloads keep their current lease until it expires")
		return nil
	},
}

var secretMigrateCmd = &cobra.Command{
	Use:   "migrate",
	Short: "Import .cloop/secrets.enc entries into the broker",
	Long: `Copy every entry from the legacy flat secret store into the broker as an
unscoped 'env' secret with a matching wildcard grant.

The import preserves existing reach exactly — the entries were already
delivered to every workload, and narrowing them here would break running
projects at a moment nobody chose. Tighten them afterwards, one grant at a
time, with 'cloop secret revoke' and a new 'cloop secret grant'.

Safe to re-run: entries already present are skipped.`,
	SilenceUsage: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		workDir, err := os.Getwd()
		if err != nil {
			return err
		}
		broker, closeFn, err := openBroker()
		if err != nil {
			return err
		}
		defer closeFn()

		res, err := secretbroker.ImportLegacySecrets(cmd.Context(), broker, workDir, currentActor())
		if err != nil {
			return err
		}
		if len(res.Imported) == 0 && len(res.Skipped) == 0 {
			color.New(color.Faint).Println("Nothing to import — no legacy secrets found in .cloop/secrets.enc")
			return nil
		}
		if len(res.Imported) > 0 {
			color.Green("✓ imported %d secret(s): %s", len(res.Imported), strings.Join(res.Imported, ", "))
			color.New(color.FgYellow).Println("  these are unscoped (subject 'any', no expiry) — review with 'cloop secret grants'")
		}
		if len(res.Skipped) > 0 {
			color.New(color.Faint).Printf("  skipped %d already-imported: %s\n", len(res.Skipped), strings.Join(res.Skipped, ", "))
		}
		return nil
	},
}

var secretLeaseCmd = &cobra.Command{
	Use:   "lease",
	Short: "Show what an executor would receive for a project",
	Long: `Dry-run a lease: report which grants match a subject and what would be
delivered, without materialising any credential.

This is the "why is my token not arriving" command. It prints allowlists and
denial reasons, never payloads.

  cloop secret lease --executor edge-01 --project /srv/app`,
	SilenceUsage: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		executorID, _ := cmd.Flags().GetString("executor")
		projectID, _ := cmd.Flags().GetString("project")
		if strings.TrimSpace(projectID) == "" {
			projectID, _ = os.Getwd()
		}

		broker, closeFn, err := openBroker()
		if err != nil {
			return err
		}
		defer closeFn()

		lease, err := broker.Lease(cmd.Context(), executorID, projectID)
		if err != nil {
			return err
		}
		// The lease is never materialised, so nothing to wipe; drop the
		// server-side record so this dry run cannot be renewed.
		defer broker.Release(lease.ID)

		if lease.Empty() {
			color.New(color.Faint).Printf("No grants match executor=%q project=%q\n", executorID, projectID)
			return nil
		}
		color.Green("%d material(s), lease expires %s", len(lease.Materials), lease.ExpiresAt.Format(time.RFC3339))
		for _, m := range lease.Materials {
			fmt.Printf("\n  %s (%s)\n", m.SecretName, m.Kind)
			fmt.Printf("    grant:       %s\n", m.GrantID)
			fmt.Printf("    constraints: %s\n", m.Constraints.Summary())
			fmt.Printf("    delivers:    %s\n", m.Summary)
			if names := materialEnvNames(m); names != "" {
				fmt.Printf("    env:         %s\n", names)
			}
			if files := materialFileNames(m); files != "" {
				fmt.Printf("    files:       %s\n", files)
			}
		}
		return nil
	},
}

// materialEnvNames lists the variable *names* a material would set. Values
// are credentials and are never printed.
func materialEnvNames(m secretbroker.Material) string {
	names := make([]string, 0, len(m.Env))
	for k := range m.Env {
		names = append(names, k)
	}
	return strings.Join(sortedStrings(names), ", ")
}

func materialFileNames(m secretbroker.Material) string {
	names := make([]string, 0, len(m.Files))
	for _, f := range m.Files {
		names = append(names, f.Name)
	}
	return strings.Join(sortedStrings(names), ", ")
}

func init() {
	secretMintCmd.Flags().StringVar(&mintKindFlag, "kind", "env",
		"secret kind: github_pat, github_app, kubeconfig, registry, env, egress_proxy")
	secretMintCmd.Flags().StringVar(&mintFileFlag, "file", "", "read the payload from a file")
	secretMintCmd.Flags().StringVar(&mintValueFlag, "value", "",
		"payload as a literal (visible in the process table — prefer --file or stdin)")

	secretGrantCmd.Flags().StringVar(&grantToFlag, "to", "",
		"subject: project:<path>, executor:<id>, label:<k=v,...>, or any")
	secretGrantCmd.Flags().StringSliceVar(&grantReposFlag, "repos", nil,
		"repository allowlist: owner/repo globs for github, directory-name globs for local_repo")
	secretGrantCmd.Flags().BoolVar(&grantWritableFlag, "writable", false,
		"make a local_repo grant read-write (default read-only)")
	secretGrantCmd.Flags().StringSliceVar(&grantPermsFlag, "permissions", nil,
		"github permission set (e.g. contents:read,pull_requests:write)")
	secretGrantCmd.Flags().StringSliceVar(&grantNamespacesFlag, "namespaces", nil,
		"kubernetes namespace allowlist")
	secretGrantCmd.Flags().StringSliceVar(&grantContextsFlag, "contexts", nil,
		"kubeconfig context allowlist")
	secretGrantCmd.Flags().StringSliceVar(&grantHostsFlag, "hosts", nil,
		"egress host allowlist ('*.example.com' matches subdomains only)")
	secretGrantCmd.Flags().StringSliceVar(&grantRegistriesFlag, "registries", nil,
		"container registry allowlist")
	secretGrantCmd.Flags().StringSliceVar(&grantEnvKeysFlag, "env-keys", nil,
		"restrict an env secret to these keys")
	secretGrantCmd.Flags().StringVar(&grantTTLFlag, "ttl", "24h", "grant lifetime (e.g. 24h, 90m)")
	secretGrantCmd.Flags().StringVar(&grantScopeFlag, "scope", "", "operator-facing label for grouping (no authorisation effect)")

	secretGrantsCmd.Flags().StringVar(&grantsSubjectFlag, "subject", "", "only grants for this subject")
	secretGrantsCmd.Flags().StringVar(&grantsSecretFlag, "secret", "", "only grants for this secret (id or name)")
	secretGrantsCmd.Flags().BoolVar(&grantsAllFlag, "all", false, "include expired and revoked grants")

	secretLeaseCmd.Flags().String("executor", "", "executor id to simulate")
	secretLeaseCmd.Flags().String("project", "", "project path (default: working directory)")

	secretCmd.AddCommand(secretMintCmd)
	secretCmd.AddCommand(secretGrantCmd)
	secretCmd.AddCommand(secretGrantsCmd)
	secretCmd.AddCommand(secretRevokeCmd)
	secretCmd.AddCommand(secretMigrateCmd)
	secretCmd.AddCommand(secretLeaseCmd)
}

// sortedStrings returns a sorted copy.
func sortedStrings(in []string) []string {
	out := append([]string(nil), in...)
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j] < out[j-1]; j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}

// readAllStdin reads the whole of stdin. Split out so readMintPayload stays
// readable and so a test can exercise the size guard.
func readAllStdin() ([]byte, error) {
	const maxPayload = 1 << 20 // 1 MiB: a kubeconfig is the largest realistic payload
	buf := make([]byte, 0, 4096)
	tmp := make([]byte, 4096)
	for {
		n, err := os.Stdin.Read(tmp)
		buf = append(buf, tmp[:n]...)
		if len(buf) > maxPayload {
			return nil, fmt.Errorf("secret: payload exceeds %d bytes", maxPayload)
		}
		if err != nil {
			break
		}
	}
	return buf, nil
}
