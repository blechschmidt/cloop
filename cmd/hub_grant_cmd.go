package cmd

// `cloop hub grant` — the browserless half of self-service access requests
// (Task 20271).
//
// The request path exists because credentials were only ever brokered in one
// direction: `cloop secret grant` is gated on holding the authority already, so
// a developer who needed a repository or a cluster had to ask out of band and
// wait for somebody to hand-mint one. These four subcommands give the ask, and
// the answer, a shell-reachable form:
//
//	cloop hub grant request   file one
//	cloop hub grant list      the queue
//	cloop hub grant approve   mint the grant it asked for
//	cloop hub grant deny      refuse, with a reason
//
// (Withdrawing is `deny` by the requester's own hand in the UI; from a shell,
// a requester withdraws with `--withdraw` on `deny`, which routes to the
// broker's WithdrawRequest and refuses if they are not the requester.)
//
// # The lease rule
//
// No hub lease is taken, and per the argument in hub_admin.go that is a
// decision rather than an omission. The three groups there turn on how a
// running hub reads the table: quota overrides are cached in the enforcer's
// memory for the process lifetime and so need the fence, while role bindings and
// sessions are re-read and so must keep working while the hub is up.
//
// Access requests are in the second group, and more strongly than either: the
// hub holds no cache of them at all. Every HTTP handler in pkg/ui/requests_api.go
// opens the control-plane database, reads, and closes it again (openBrokers), so
// a request filed here is visible to the panel on its next read, and an approval
// made here is visible immediately. Refusing to run while a hub is up would
// break the only case that matters — asking for access on a working system.
//
// # Identity, and why the two-person rule still holds here
//
// operatorActor() names the real OS user from the passwd database, not $USER.
// That is what makes `cloop hub grant approve` refusable: the broker compares
// the decider against the requester, and an identity the caller could set would
// turn the two-person rule into a formality. It also means a request filed in
// the browser (whose actor is an OIDC subject) cannot be approved from a shell
// by the same human unless their OS user happens to match — which is the
// conservative direction, and the right one.

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"github.com/blechschmidt/cloop/pkg/secretbroker"
	"github.com/blechschmidt/cloop/pkg/secretstore"
)

var (
	hubGrantToFlag         string
	hubGrantReposFlag      []string
	hubGrantDevicesFlag    []string
	hubGrantPermsFlag      []string
	hubGrantNamespacesFlag []string
	hubGrantContextsFlag   []string
	hubGrantHostsFlag      []string
	hubGrantRegistriesFlag []string
	hubGrantEnvKeysFlag    []string
	hubGrantWritableFlag   bool
	hubGrantTTLFlag        string
	hubGrantWaitFlag       string
	hubGrantScopeFlag      string
	hubGrantWhyFlag        string

	hubGrantStateFlag     string
	hubGrantMineFlag      bool
	hubGrantUsesFlag      bool
	hubGrantFleetWideFlag bool
	hubGrantWithdrawFlag  bool
)

// openHubBroker builds a broker over the hub's own control-plane database.
//
// Separate from cmd/secret_grant.go's openBroker, which resolves the *current
// project's* database. Grants and requests live in the control plane for the
// reason pkg/ui/secrets_api.go gives: a tenant must not be able to grant itself
// credentials by writing to a database it owns. Reusing openBroker here would
// quietly file requests into whatever project the operator happened to be
// standing in, where the hub would never see them.
func openHubBroker(workdir string) (*secretbroker.Broker, func(), error) {
	db, closer, err := openHubDB(workdir)
	if err != nil {
		return nil, nil, err
	}
	store, serr := secretstore.New(db)
	if serr != nil {
		closer()
		return nil, nil, serr
	}
	broker, berr := secretbroker.New(store, secretbroker.WithAuditor(secretstore.NewAuditor(db)))
	if berr != nil {
		closer()
		return nil, nil, berr
	}
	return broker, closer, nil
}

var hubGrantCmd = &cobra.Command{
	Use:   "grant",
	Short: "Ask for a credential, and decide the asks of others",
	Long: `File and decide access requests without a browser.

A request is not a credential. It is a row naming a stored secret, the project
or executor it should reach, how long for, and why — and until somebody else
approves it, nothing exists that an executor can use. That second person is the
point: approving your own request is refused, so the scope gets read by someone
who was not in a hurry to get unblocked.

  cloop hub grant request prod-kube --to project:/srv/app \
        --contexts prod --namespaces app --ttl 8h \
        --why "debugging the failed rollout in INC-2291"

  cloop hub grant list --state pending
  cloop hub grant approve req_1a2b3c4d --ttl 2h --reason "scoped to one ns, ok"
  cloop hub grant deny    req_1a2b3c4d --reason "use the staging cluster"

Run these from the hub's own directory, or pass --workdir: requests live in the
control plane's database, not in a project's.`,
}

var hubGrantRequestCmd = &cobra.Command{
	Use:   "request <secret>",
	Short: "Ask for a grant against an existing secret",
	Long: `File a request for access to a credential the hub already holds.

The secret must already exist — a request asks for access to something an
operator stored, never for a credential to be created, because creating one
means supplying the material and a requester by definition does not have it.
` + "`cloop hub grant list --state approved`" + ` or the Secrets panel will show you
what there is to ask for.

Constraints are the same flags ` + "`cloop secret grant`" + ` takes, and they are
validated now, against the secret's kind, rather than when somebody comes to
approve it. An ask that could never be approved fails in front of the person who
can fix it.

--ttl is how long the credential should live once granted. --wait is how long the
request itself waits for a decision before it lapses (default 72h); a request
that sits pending forever is the one approved six weeks later by somebody who no
longer remembers what it was for.

A justification is required. That is not bureaucracy: it is the only thing the
approver has to decide against.`,
	Args:         cobra.ExactArgs(1),
	SilenceUsage: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		workdir, _ := cmd.Flags().GetString("workdir")
		asJSON, _ := cmd.Flags().GetBool("json")

		subject, err := secretbroker.ParseSubject(hubGrantToFlag)
		if err != nil {
			return err
		}
		ttl, err := parseOptionalDuration(hubGrantTTLFlag, "--ttl")
		if err != nil {
			return err
		}
		wait, err := parseOptionalDuration(hubGrantWaitFlag, "--wait")
		if err != nil {
			return err
		}
		if strings.TrimSpace(hubGrantWhyFlag) == "" {
			return fmt.Errorf("--why is required: an approver has nothing else to decide against")
		}

		warnIfNotAHub(workdir)
		broker, closer, err := openHubBroker(workdir)
		if err != nil {
			return err
		}
		defer closer()

		req, err := broker.RequestAccess(context.Background(), secretbroker.AccessRequestInput{
			SecretRef:     args[0],
			Subject:       subject,
			Scope:         hubGrantScopeFlag,
			TTL:           ttl,
			RequestTTL:    wait,
			Justification: hubGrantWhyFlag,
			Actor:         operatorActor(),
			Constraints: secretbroker.Constraints{
				Repos:       hubGrantReposFlag,
				Devices:     hubGrantDevicesFlag,
				Permissions: hubGrantPermsFlag,
				Namespaces:  hubGrantNamespacesFlag,
				Contexts:    hubGrantContextsFlag,
				Hosts:       hubGrantHostsFlag,
				Registries:  hubGrantRegistriesFlag,
				EnvKeys:     hubGrantEnvKeysFlag,
				Writable:    hubGrantWritableFlag,
			},
		})
		if err != nil {
			return err
		}
		if asJSON {
			return json.NewEncoder(os.Stdout).Encode(req)
		}
		color.New(color.FgGreen).Printf("✓ filed %s\n", req.ID)
		fmt.Printf("  secret      %s (%s)\n", req.SecretName, req.Kind)
		fmt.Printf("  subject     %s\n", req.Subject.String())
		if s := req.Constraints.Summary(); s != "" {
			fmt.Printf("  constraints %s\n", s)
		}
		fmt.Printf("  grant ttl   %s\n", req.TTL)
		fmt.Printf("  decide by   %s\n", req.ExpiresAt.Local().Format(time.RFC3339))
		color.New(color.Faint).Println(
			"\nNothing is granted yet. Somebody holding secret.grant — and not you — has to approve it.")
		return nil
	},
}

var hubGrantListCmd = &cobra.Command{
	Use:   "list",
	Short: "Show access requests and what became of them",
	Long: `List access requests.

--state narrows to pending, approved, denied, withdrawn or expired. --mine
narrows to your own. --uses additionally reports, for each approved request,
which leases actually redeemed the grant — the question an approver has a week
later, and the one broker_grants cannot answer: a grant nothing ever used and a
grant feeding a workload around the clock look identical from the grant table.

A task id appears where the dispatch was task-scoped. A lease issued for a whole
project run shows the project instead; that is not a missing value, it is what
happened — the hub leases credentials per run, not per task.`,
	Args:         cobra.NoArgs,
	SilenceUsage: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		workdir, _ := cmd.Flags().GetString("workdir")
		asJSON, _ := cmd.Flags().GetBool("json")

		filter := secretbroker.RequestFilter{}
		if s := strings.TrimSpace(hubGrantStateFlag); s != "" {
			st := secretbroker.RequestState(strings.ToLower(s))
			if !st.Valid() {
				return fmt.Errorf("unknown --state %q (want pending, approved, denied, withdrawn or expired)", s)
			}
			filter.State = st
		}
		if hubGrantMineFlag {
			filter.RequestedBy = operatorActor()
		}

		broker, closer, err := openHubBroker(workdir)
		if err != nil {
			return err
		}
		defer closer()

		requests, err := broker.ListRequests(filter)
		if err != nil {
			return err
		}
		if asJSON {
			out := make([]map[string]any, 0, len(requests))
			for _, req := range requests {
				row := map[string]any{"request": req}
				if hubGrantUsesFlag && req.State == secretbroker.RequestApproved {
					uses, uerr := broker.RequestUses(req.ID)
					if uerr == nil {
						row["uses"] = uses
					}
				}
				out = append(out, row)
			}
			return json.NewEncoder(os.Stdout).Encode(out)
		}

		if len(requests) == 0 {
			color.New(color.Faint).Println("no access requests")
			return nil
		}
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "ID\tSTATE\tREQUESTER\tSECRET\tSUBJECT\tTTL\tDEADLINE\tWHY")
		for _, req := range requests {
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
				req.ID, req.State, req.RequestedBy,
				req.SecretName+" ("+string(req.Kind)+")",
				req.Subject.String(), req.TTL,
				requestDeadlineCell(req), flattenCell(req.Justification, 48))
		}
		_ = w.Flush()

		if !hubGrantUsesFlag {
			return nil
		}
		for _, req := range requests {
			if req.State != secretbroker.RequestApproved {
				continue
			}
			uses, uerr := broker.RequestUses(req.ID)
			if uerr != nil {
				fmt.Fprintf(os.Stderr, "  %s: read uses: %v\n", req.ID, uerr)
				continue
			}
			color.New(color.Bold).Printf("\n%s → grant %s\n", req.ID, req.GrantID)
			if len(uses) == 0 {
				color.New(color.Faint).Println("  never leased — nothing has used this grant")
				continue
			}
			uw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(uw, "  LEASE\tEXECUTOR\tCONSUMED BY\tFIRST\tLAST")
			for _, u := range uses {
				fmt.Fprintf(uw, "  %s\t%s\t%s\t%s\t%s\n",
					u.LeaseID, defaultCell(u.ExecutorID),
					useConsumerCell(u),
					u.FirstSeen.Local().Format(time.RFC3339),
					u.LastSeen.Local().Format(time.RFC3339))
			}
			_ = uw.Flush()
		}
		return nil
	},
}

var hubGrantApproveCmd = &cobra.Command{
	Use:   "approve <request-id>",
	Short: "Mint the grant a request asked for",
	Long: `Approve a request, creating the grant it described.

The grant is minted through the same code path ` + "`cloop secret grant`" + ` uses, with
the request's own subject and constraints. There is deliberately no way to
approve something *other* than what was asked for: an approver who wants a
narrower scope denies and says so, or mints directly with ` + "`cloop secret grant`" + `,
which is a different act and gets a different audit row.

What you can narrow here is the lifetime. --ttl shortens the grant; a value
longer than the request asked for is ignored rather than honoured.

--fleet-wide is required to approve a request aimed at every project, every
executor, or a label selector. Such a grant reaches every tenant on the hub for
as long as it lasts, and it should not be possible to create one by approving
somebody else's ask without reading it.

You cannot approve your own request. That is the point of the request path.`,
	Args:         cobra.ExactArgs(1),
	SilenceUsage: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		workdir, _ := cmd.Flags().GetString("workdir")
		asJSON, _ := cmd.Flags().GetBool("json")
		reason, _ := cmd.Flags().GetString("reason")

		ttl, err := parseOptionalDuration(hubGrantTTLFlag, "--ttl")
		if err != nil {
			return err
		}

		warnIfNotAHub(workdir)
		broker, closer, err := openHubBroker(workdir)
		if err != nil {
			return err
		}
		defer closer()

		req, grant, err := broker.ApproveRequest(context.Background(), secretbroker.DecideInput{
			RequestID: args[0],
			Actor:     operatorActor(),
			Note:      reason,
			TTL:       ttl,
			// A shell on the hub host is already the strongest authority there
			// is — this operator could edit the database directly — so the
			// ceiling is the panel's own maximum rather than a role's. The
			// wildcard gate is still opt-in, because the value of that check is
			// not that it is unbypassable but that it makes a fleet-wide grant a
			// thing you typed on purpose.
			Delegation: secretbroker.Delegation{
				MaxTTL:               secretbroker.MaxDelegationTTL,
				AllowWildcardSubject: hubGrantFleetWideFlag,
			},
		})
		if err != nil {
			return err
		}
		if asJSON {
			return json.NewEncoder(os.Stdout).Encode(map[string]any{
				"request": req, "grant": grant,
			})
		}
		color.New(color.FgGreen).Printf("✓ approved %s → grant %s\n", req.ID, grant.ID)
		fmt.Printf("  subject     %s\n", grant.Subject.String())
		if s := grant.Constraints.Summary(); s != "" {
			fmt.Printf("  constraints %s\n", s)
		}
		fmt.Printf("  expires     %s\n", grant.ExpiresAt.Local().Format(time.RFC3339))
		if grant.ExpiresAt.Sub(req.DecidedAt) < req.TTL {
			color.New(color.Faint).Printf("  (narrowed from the %s that was requested)\n", req.TTL)
		}
		color.New(color.Faint).Println(
			"\nAn executor picks this up at its next lease, within one lease period.")
		return nil
	},
}

var hubGrantDenyCmd = &cobra.Command{
	Use:   "deny <request-id>",
	Short: "Refuse a request, on the record",
	Long: `Deny a request.

--reason is required and is shown to the requester. A refusal with no reason is
one they can only respond to by asking again, which produces the queue this
feature exists to drain.

--withdraw takes back your *own* request instead of refusing somebody else's.
The two are separate verbs because they are separate acts: an approver who wants
a request gone says no to it, on the record. Letting them withdraw would be a way
to make an inconvenient ask disappear without ever appearing as a refusal.`,
	Args:         cobra.ExactArgs(1),
	SilenceUsage: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		workdir, _ := cmd.Flags().GetString("workdir")
		asJSON, _ := cmd.Flags().GetBool("json")
		reason, _ := cmd.Flags().GetString("reason")

		warnIfNotAHub(workdir)
		broker, closer, err := openHubBroker(workdir)
		if err != nil {
			return err
		}
		defer closer()

		var req secretbroker.AccessRequest
		if hubGrantWithdrawFlag {
			req, err = broker.WithdrawRequest(context.Background(), args[0], operatorActor())
		} else {
			if _, rerr := requireReason(reason); rerr != nil {
				return rerr
			}
			req, err = broker.DenyRequest(context.Background(), secretbroker.DecideInput{
				RequestID: args[0],
				Actor:     operatorActor(),
				Note:      reason,
			})
		}
		if err != nil {
			return err
		}
		if asJSON {
			return json.NewEncoder(os.Stdout).Encode(req)
		}
		color.New(color.FgYellow).Printf("✓ %s is now %s\n", req.ID, req.State)
		if req.DecisionNote != "" {
			fmt.Printf("  reason %s\n", req.DecisionNote)
		}
		return nil
	},
}

// ---------------------------------------------------------------------------
// rendering helpers
// ---------------------------------------------------------------------------

// requestDeadlineCell renders when a pending request lapses, or when a decided
// one was decided. One column rather than two because only one of them is ever
// interesting for a given row, and a table with two mostly-empty date columns is
// harder to read than one that says what it means.
func requestDeadlineCell(req secretbroker.AccessRequest) string {
	if req.State == secretbroker.RequestPending {
		if req.ExpiresAt.IsZero() {
			return "-"
		}
		if remaining := time.Until(req.ExpiresAt); remaining > 0 {
			return remaining.Truncate(time.Minute).String() + " left"
		}
		return "lapsed"
	}
	if req.DecidedAt.IsZero() {
		return "-"
	}
	return req.DecidedAt.Local().Format("2006-01-02 15:04")
}

// useConsumerCell names what held a lease.
//
// A task id when the dispatch was task-scoped, the project otherwise — and the
// distinction is stated rather than papered over, because "task 41" and "the
// whole run" are different answers to an approver asking what their approval
// did, and printing a bare 0 would look like a bug.
func useConsumerCell(u secretbroker.RequestUse) string {
	if u.TaskID != 0 {
		return fmt.Sprintf("task #%d", u.TaskID)
	}
	if u.ProjectID != "" {
		return u.ProjectID + " (project run)"
	}
	return "-"
}

// flattenCell collapses a multi-line justification onto one table row.
// Separate from hub_telemetry_cmd.go's truncateCell because that one preserves
// whatever whitespace it is given, and a justification is free text that
// routinely contains newlines.
func flattenCell(s string, max int) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) <= max {
		return s
	}
	return s[:max-1] + "…"
}

func defaultCell(s string) string {
	if strings.TrimSpace(s) == "" {
		return "-"
	}
	return s
}

// parseOptionalDuration parses a flag that may legitimately be empty, so an
// unset duration reaches the broker as zero and picks up its default rather
// than being rejected here.
func parseOptionalDuration(raw, flag string) (time.Duration, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return 0, nil
	}
	d, err := time.ParseDuration(raw)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", flag, err)
	}
	if d <= 0 {
		return 0, fmt.Errorf("%s must be positive", flag)
	}
	return d, nil
}

func init() {
	for _, c := range []*cobra.Command{
		hubGrantRequestCmd, hubGrantListCmd, hubGrantApproveCmd, hubGrantDenyCmd,
	} {
		c.Flags().String("workdir", "", "hub directory holding .cloop/state.db (default: current directory)")
		c.Flags().Bool("json", false, "emit JSON")
	}
	hubGrantApproveCmd.Flags().String("reason", "", "note recorded with the approval")
	hubGrantDenyCmd.Flags().String("reason", "", "why the request is refused (required)")

	rf := hubGrantRequestCmd.Flags()
	rf.StringVar(&hubGrantToFlag, "to", "", "subject: project:<path>, executor:<id>, or label:k=v")
	rf.StringVar(&hubGrantWhyFlag, "why", "", "justification (required)")
	rf.StringVar(&hubGrantTTLFlag, "ttl", "", "how long the granted credential should live (default 24h)")
	rf.StringVar(&hubGrantWaitFlag, "wait", "", "how long to wait for a decision (default 72h)")
	rf.StringVar(&hubGrantScopeFlag, "scope", "", "operator-facing label for grouping; carries no authority")
	rf.StringSliceVar(&hubGrantReposFlag, "repos", nil, "github: allowed repositories")
	rf.StringSliceVar(&hubGrantPermsFlag, "permissions", nil, "github: allowed permissions")
	rf.StringSliceVar(&hubGrantNamespacesFlag, "namespaces", nil, "kubeconfig: allowed namespaces")
	rf.StringSliceVar(&hubGrantContextsFlag, "contexts", nil, "kubeconfig: allowed contexts")
	rf.StringSliceVar(&hubGrantHostsFlag, "hosts", nil, "egress_proxy: allowed hosts")
	rf.StringSliceVar(&hubGrantRegistriesFlag, "registries", nil, "registry: allowed registries")
	rf.StringSliceVar(&hubGrantEnvKeysFlag, "env-keys", nil, "env: allowed variable names")
	rf.StringSliceVar(&hubGrantDevicesFlag, "devices", nil, "host_device: allowed device names")
	rf.BoolVar(&hubGrantWritableFlag, "writable", false, "local_repo: mount read-write")
	_ = hubGrantRequestCmd.MarkFlagRequired("to")
	_ = hubGrantRequestCmd.MarkFlagRequired("why")

	lf := hubGrantListCmd.Flags()
	lf.StringVar(&hubGrantStateFlag, "state", "", "pending | approved | denied | withdrawn | expired")
	lf.BoolVar(&hubGrantMineFlag, "mine", false, "only your own requests")
	lf.BoolVar(&hubGrantUsesFlag, "uses", false, "also report which leases redeemed each approved grant")

	hubGrantApproveCmd.Flags().StringVar(&hubGrantTTLFlag, "ttl", "",
		"shorten the granted lifetime; a longer value than requested is ignored")
	hubGrantApproveCmd.Flags().BoolVar(&hubGrantFleetWideFlag, "fleet-wide", false,
		"required to approve a request aimed at every project, executor, or a label selector")
	hubGrantDenyCmd.Flags().BoolVar(&hubGrantWithdrawFlag, "withdraw", false,
		"take back your own request instead of refusing somebody else's")

	hubGrantCmd.AddCommand(hubGrantRequestCmd)
	hubGrantCmd.AddCommand(hubGrantListCmd)
	hubGrantCmd.AddCommand(hubGrantApproveCmd)
	hubGrantCmd.AddCommand(hubGrantDenyCmd)
	hubCmd.AddCommand(hubGrantCmd)
}
