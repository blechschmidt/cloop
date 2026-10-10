package cmd

// `cloop hub user offboard` — severing every credential surface an identity
// holds, in one operation (Task 20261).
//
// The runbook used to answer "this person left, are they out?" with a sequence:
// write a deny binding, then revoke sessions, then revoke tokens, then go
// looking for leases and running tasks by hand. A sequence is exactly the wrong
// shape for the question. It has no dry run, so the operator discovers the
// blast radius by causing it; it has no atomicity, so a failure halfway leaves
// a state nobody described; and it is long enough that the last step is the one
// that gets skipped under pressure — which is how a departed user's personal
// access token keeps working for another ninety days.
//
// This command is the whole sequence, planned first and applied once.
//
// Like the rest of `cloop hub`, it operates on the database directly and takes
// no lease, so it keeps working when the HTTP listener does not — which is
// often the situation that produces the need for it.

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"github.com/blechschmidt/cloop/pkg/multiui"
	"github.com/blechschmidt/cloop/pkg/offboard"
	"github.com/blechschmidt/cloop/pkg/ui"
)

var hubUserCmd = &cobra.Command{
	Use:   "user",
	Short: "Offboard a person from the hub",
	Long: `Act on a hub identity as a whole, rather than on one of its credentials.

  cloop hub user offboard alice@example.com --dry-run
  cloop hub user offboard alice@example.com --reason "left the company, ticket HR-882"

Use ` + "`cloop hub session`" + `, ` + "`cloop hub token`" + ` and ` + "`cloop hub role`" + ` when you mean to act on
one credential. Use this when you mean to act on the person.`,
}

var hubUserOffboardCmd = &cobra.Command{
	Use:   "offboard <email|sub>",
	Short: "Sever every credential surface an identity holds",
	Long: `End everything one identity can still do on this hub.

Seven surfaces outlive an account disabled at the identity provider, and all
seven are severed here:

  sessions   every signed-in dashboard session
  tokens     every API token whose owner binding is this person
  glasses    every Meta Ray-Ban Display link they hold
  deny       a runtime deny binding, so a *new* sign-in gets nothing either
  leases     secret leases held by their running tasks, released at the broker
  tasks      those tasks, stopped
  members    every project shared with them by name, removed

Four more are what they keep here rather than hold open, and are destroyed:

  secrets    their personal secrets — GitHub PATs, kubeconfigs — deleted
             through the broker: sealed material overwritten, audited
  grants     every grant over those secrets, revoked, including grants to
             projects other people own, which lose the credential
  requests   self-service grant requests they left pending, withdrawn
  claude     their Claude Code login on every hub member: a login in flight
             cancelled, each home logged out and its directory removed

and one is reported but never touched:

  projects   the projects they own, listed so an operator can reassign them

--keep-credentials is a legal hold: access is severed exactly as without it —
grants revoked, requests withdrawn, logins cancelled — but the personal secrets
and the Claude homes are kept as they are, and the report and the audit trail
say what was kept.

Projects are not deleted, on purpose. A departing user's projects usually hold
the team's work, and a command that quietly removed them would be a data-loss
tool wearing a security label.

The identity is resolved before anything is written. Give an email or an IdP
subject; both are expanded to every identifier that turns out to address the
same person, because the surfaces are keyed inconsistently — a session carries
an email, a token's owner may carry only a subject, and matching literally on
what you typed would leave that token live.

Sessions, tokens, glasses links, memberships and the deny binding are written
in ONE transaction: either the person is out of all five or nothing changed. Leases,
the stored credentials, tasks and Claude logins cannot join that transaction —
they are broker memory, other databases and other hub members' filesystems — so
they are applied after it, in that order, and any failure is reported rather
than rolled back over a severing that already succeeded.

Claude Code homes live under each hub process's own config directory, not in
the database. This command removes the copy under its own, and asks every
running hub member, over the bus, to remove theirs; a member that does not
answer is named as a failure, because a copy nobody reached may still hold a
live refresh token.

Run --dry-run first. It prints the same set the write would act on, because it
is the set the write acts on.

The revoked sessions, tokens and glasses links are announced to running hubs,
which stop honouring them and close the dashboard streams and sandbox terminals
they opened within about a second. A hub that reads no announcements
(ui.cluster.exclusive) stops honouring a revoked session within ` + sessionRevocationWindow.String() + ` (its
session cache) and closes what it opened at the next ` + streamRecheckWindow.String() + ` re-check.

Examples:

  # See the blast radius, change nothing
  cloop hub user offboard alice@example.com --dry-run

  # Do it
  cloop hub user offboard alice@example.com --reason "left the company, HR-882"

  # Someone whose IdP supplies no email claim
  cloop hub user offboard 'sub:8f14e45fce' --reason "contract ended, HR-901"

  # Under a legal hold: sever access, keep their stored credentials
  cloop hub user offboard alice@example.com --keep-credentials --reason "left, legal hold LH-17"`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		workdir, _ := cmd.Flags().GetString("workdir")
		dryRun, _ := cmd.Flags().GetBool("dry-run")
		asJSON, _ := cmd.Flags().GetBool("json")
		rawReason, _ := cmd.Flags().GetString("reason")
		keep, _ := cmd.Flags().GetBool("keep-credentials")

		identity := strings.TrimSpace(args[0])
		if identity == "" {
			return fmt.Errorf("an email address or IdP subject is required")
		}

		// A dry run changes nothing, so demanding a reason for one would only
		// train operators to type a placeholder they then reuse for the real
		// run. The write still requires one.
		reason := strings.TrimSpace(rawReason)
		if !dryRun {
			var err error
			if reason, err = requireReason(rawReason); err != nil {
				return err
			}
		}

		warnIfNotAHub(workdir)
		warnIfNoIdentityProvider(workdir)
		db, closer, err := openHubDB(workdir)
		if err != nil {
			return err
		}
		defer closer()

		// The registry is the only record of who owns a project. A hub whose
		// registry cannot be read still offboards every credential; it just
		// cannot say which projects need reassigning, and the plan's warnings
		// say so rather than implying there were none.
		var projects offboard.Projects
		if entries, err := multiui.Load(); err == nil {
			projects = offboard.RegistryProjects(entries)
		}

		// No lease broker here on purpose: leases are process memory in the
		// hub that issued them, bounded by their own TTL and released by that
		// hub; the report says they were not checked rather than implying
		// they were clean.
		//
		// The secret store is another matter (Task 20400). Destroying a
		// departed person's personal secrets removes rows and reads none, so
		// it is opened without a key: an offboarding that refused to run
		// because a shell lacked CLOOP_SECRET_KEY would fail in exactly the
		// emergency it exists for.
		secrets, serr := offboard.StoreSecrets(db)
		if serr != nil {
			secrets = nil
			fmt.Fprintf(os.Stderr, "warning: the secret store could not be opened, so personal secrets, "+
				"their grants and pending requests are not part of this run: %v\n", serr)
		}
		// Claude Code homes: this process's own tree, and every running
		// member's, asked over the bus. An operator's shell logs a home out
		// whatever the host-execution policy, which governs what a hub runs
		// on a request's behalf; the members apply their own.
		claude := ui.ClaudeHomesOnMembers(db, cliOrigin(), offboard.LocalClaude{OperatorShell: true})

		rep, err := offboard.Run(offboard.Options{
			DB:              db,
			Identity:        identity,
			Reason:          reason,
			Actor:           operatorActor(),
			Via:             "cli",
			DryRun:          dryRun,
			Projects:        projects,
			Tasks:           offboard.LocalTasks(),
			Secrets:         secrets,
			Claude:          claude,
			KeepCredentials: keep,
		})
		if err != nil {
			return err
		}
		// Memberships went in the credential transaction (Task 20366); tell
		// running hubs, so they apply it — and close this person's open
		// dashboards on those projects — now rather than at their next refresh.
		for _, m := range rep.MembershipsRevoked {
			if err := ui.AnnounceMembershipChange(db, cliOrigin(), m.Path); err != nil {
				fmt.Fprintf(os.Stderr, "warning: could not notify running hubs of the removed memberships: %v\n", err)
				break
			}
		}
		// So did the sessions, tokens and glasses links: tell running hubs
		// to drop them and close every stream and terminal they opened
		// (Task 20398), as `cloop hub session revoke` does.
		announced := true
		if err := ui.AnnounceSessionsEnded(db, cliOrigin(), rep.SessionsRevoked, false); err != nil {
			announced = false
			fmt.Fprintf(os.Stderr, "warning: could not notify running hubs of the ended sessions: %v\n", err)
		}
		if err := ui.AnnounceTokensRevoked(db, cliOrigin(),
			append(append([]string(nil), rep.TokensRevoked...), rep.GlassesRevoked...)); err != nil {
			announced = false
			fmt.Fprintf(os.Stderr, "warning: could not notify running hubs of the revoked tokens: %v\n", err)
		}

		// The grants were revoked in this process, which holds no lease and
		// reaches no workload: tell the running hubs, which take each back
		// from the workloads holding it (Task 20403).
		var grantRep *ui.GrantRevocationReport
		var grantErr error
		if !dryRun && len(rep.GrantsRevoked) > 0 {
			anns := make([]ui.GrantRevocationAnnouncement, 0, len(rep.GrantsRevoked))
			for _, g := range rep.GrantsRevoked {
				anns = append(anns, ui.GrantRevocationAnnouncement{GrantID: g.ID, Actor: operatorActor()})
			}
			gr, err := ui.AnnounceGrantsRevoked(db, cliOrigin(), anns, offboardGrantWait)
			grantRep, grantErr = &gr, err
		}

		if asJSON {
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			if err := enc.Encode(rep); err != nil {
				return err
			}
		} else {
			printOffboardReport(rep, announced)
			if grantRep != nil {
				fmt.Println("\nRevoked grants, taken back from running workloads:")
				printGrantRevocationReport(*grantRep, grantErr, offboardGrantWait)
			}
		}

		// A partial run is an error even though most of it worked: the operator
		// asked whether this person is out, and the honest answer is "not
		// entirely". Exiting 0 here would let a CI offboarding job go green over
		// a still-running task.
		if !rep.OK() {
			return fmt.Errorf("%d surface(s) could not be severed — see the failures above",
				len(rep.Failures))
		}
		return nil
	},
}

// printOffboardReport renders the plan, and for a real run what came of it.
// announced says whether running hubs were told of the revocations.
// offboardGrantWait bounds how long `hub user offboard` waits for running hubs
// to say what they took back of the grants it revoked.
const offboardGrantWait = 60 * time.Second

func printOffboardReport(rep offboard.Report, announced bool) {
	bold := color.New(color.Bold)
	faint := color.New(color.Faint)

	if rep.DryRun {
		bold.Printf("\nDry run — nothing was changed.\n")
	}
	bold.Printf("\nIdentity: %s\n", rep.Target.Label())
	if len(rep.Target.Emails) > 0 {
		faint.Printf("  emails:   %s\n", strings.Join(rep.Target.Emails, ", "))
	}
	if len(rep.Target.Subjects) > 0 {
		faint.Printf("  subjects: %s\n", strings.Join(rep.Target.Subjects, ", "))
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "\nSURFACE\tPLANNED\tRESULT")
	row := func(name string, planned int, result string) {
		fmt.Fprintf(w, "%s\t%d\t%s\n", name, planned, result)
	}
	done := func(n int) string {
		if rep.DryRun {
			return "-"
		}
		return fmt.Sprintf("%d severed", n)
	}
	row("sessions", len(rep.Sessions), done(len(rep.SessionsRevoked)))
	row("api tokens", len(rep.Tokens), done(len(rep.TokensRevoked)))
	row("glasses links", len(rep.Glasses), done(len(rep.GlassesRevoked)))
	row("deny bindings", len(rep.Denies), done(len(rep.DeniesWritten)))
	row("secret leases", len(rep.Leases), done(len(rep.LeasesReleased)))
	row("running tasks", len(rep.Tasks), done(len(rep.TasksStopped)))
	row("project memberships", len(rep.Memberships), done(len(rep.MembershipsRevoked)))
	// The stored footprint says what happened to it in its own verbs: a
	// secret is destroyed or kept, not "severed".
	doneAs := func(n int, verb string) string {
		if rep.DryRun {
			return "-"
		}
		return fmt.Sprintf("%d %s", n, verb)
	}
	creds := rep.Credentials
	row("personal grants", len(creds.Grants), doneAs(len(rep.GrantsRevoked), "revoked"))
	switch {
	case creds.Keep && rep.DryRun:
		row("personal secrets", len(creds.Secrets), "kept (legal hold)")
	case creds.Keep:
		row("personal secrets", len(creds.Secrets), fmt.Sprintf("%d kept (legal hold)", len(rep.SecretsKept)))
	default:
		row("personal secrets", len(creds.Secrets), doneAs(len(rep.SecretsDeleted), "destroyed"))
	}
	row("grant requests", len(creds.Requests), doneAs(len(rep.RequestsWithdrawn), "withdrawn"))
	claudeResult := doneAs(claudeRemoved(rep), "removed")
	if creds.Keep {
		claudeResult = "kept (legal hold)"
	}
	row("claude logins", creds.ClaudeCopies(), claudeResult)
	fmt.Fprintf(w, "projects\t%d\t%s\n", len(rep.Projects), "reported only (never deleted)")
	_ = w.Flush()

	detail := func(title string, lines []string) {
		if len(lines) == 0 {
			return
		}
		fmt.Printf("\n%s\n", title)
		for _, l := range lines {
			fmt.Printf("  %s\n", l)
		}
	}

	var sessions []string
	for _, s := range rep.Sessions {
		sessions = append(sessions, fmt.Sprintf("%s  %s", truncateField(s.ID, 16), s.Email))
	}
	detail("Sessions:", sessions)

	var tokens []string
	for _, t := range append(append([]offboard.TokenRef(nil), rep.Tokens...), rep.Glasses...) {
		kind := t.Kind
		if kind == "" {
			kind = "pat"
		}
		tokens = append(tokens, fmt.Sprintf("%s  %-8s %s", truncateField(t.ID, 16), kind, t.Name))
	}
	detail("Tokens:", tokens)

	var memberships []string
	for _, m := range rep.Memberships {
		memberships = append(memberships, fmt.Sprintf("%s  %-10s as %s", m.Path, m.Role, m.Identity))
	}
	detail("Project memberships (removed, not reported):", memberships)

	var tasks []string
	for _, t := range rep.Tasks {
		tasks = append(tasks, fmt.Sprintf("%s #%d  %s", t.ProjectName, t.ID, t.Title))
	}
	detail("Running tasks:", tasks)

	var secrets []string
	for _, sec := range creds.Secrets {
		secrets = append(secrets, fmt.Sprintf("%-24s %-12s created %s", sec.Name, sec.Kind,
			sec.CreatedAt.UTC().Format("2006-01-02")))
	}
	if creds.Keep {
		detail("Personal secrets (KEPT under the legal hold):", secrets)
	} else {
		detail("Personal secrets (destroyed):", secrets)
	}

	var grants []string
	for _, g := range creds.Grants {
		grants = append(grants, fmt.Sprintf("%s  %s -> %s", truncateField(g.ID, 16), g.SecretName, g.Subject))
	}
	detail("Grants over them (revoked — a project listed here loses the credential):", grants)

	var requests []string
	for _, rq := range creds.Requests {
		requests = append(requests, fmt.Sprintf("%s  %s for %s", truncateField(rq.ID, 16), rq.SecretName, rq.Subject))
	}
	detail("Pending grant requests (withdrawn):", requests)

	var homes []string
	for _, h := range creds.Claude {
		where := "this process"
		if h.Member != "" {
			where = "member " + h.Member
		}
		var found []string
		if h.Credential {
			found = append(found, "credential")
		} else if h.Exists {
			found = append(found, "no credential")
		}
		if h.Login {
			found = append(found, "login in flight")
		}
		homes = append(homes, fmt.Sprintf("%s: %s [%s]", where, h.Dir, strings.Join(found, ", ")))
	}
	for _, u := range creds.ClaudeUnreached {
		homes = append(homes, fmt.Sprintf("member %s: NOT REACHED — %s", u.Member, u.Detail))
	}
	if creds.Keep {
		detail("Claude Code logins (logins in flight cancelled, homes KEPT under the legal hold):", homes)
	} else {
		detail("Claude Code logins (cancelled, logged out and removed):", homes)
	}
	var outcomes []string
	for _, r := range rep.ClaudeResults {
		if r.Logout != "" {
			outcomes = append(outcomes, fmt.Sprintf("%s: logout %s", r.Dir, r.Logout))
		}
	}
	detail("Claude logout notes:", outcomes)

	if len(rep.Projects) > 0 {
		fmt.Printf("\n")
		color.New(color.FgYellow).Printf("Projects owned by this identity — REASSIGN THESE:\n")
		for _, p := range rep.Projects {
			fmt.Printf("  %s\t%s\n", p.Name, p.Path)
		}
	}

	if len(rep.Warnings) > 0 {
		fmt.Printf("\n")
		color.New(color.FgYellow).Printf("Warnings:\n")
		for _, warn := range rep.Warnings {
			fmt.Printf("  %s\n", warn)
		}
	}

	if len(rep.Failures) > 0 {
		fmt.Printf("\n")
		color.New(color.FgRed).Printf("Failures:\n")
		for _, f := range rep.Failures {
			fmt.Printf("  [%s] %s\n", f.Surface, f.Detail)
		}
	}

	if rep.DryRun {
		faint.Printf("\nRe-run without --dry-run and with --reason to apply.\n")
		return
	}
	if rep.OK() {
		color.New(color.FgGreen).Printf("\nOffboarded %s.\n", rep.Target.Label())
	}
	printSessionRevocationBound(announced)
}

// claudeRemoved counts the Claude homes the run removed.
func claudeRemoved(rep offboard.Report) int {
	n := 0
	for _, r := range rep.ClaudeResults {
		if r.Removed {
			n++
		}
	}
	return n
}

func init() {
	c := hubUserOffboardCmd
	c.Flags().String("workdir", "", "hub directory holding .cloop/state.db (default: current directory)")
	c.Flags().Bool("dry-run", false, "print the blast radius and change nothing")
	c.Flags().Bool("json", false, "emit JSON for scripting")
	c.Flags().String("reason", "", "why (required unless --dry-run; recorded in the audit trail)")
	c.Flags().Bool("keep-credentials", false,
		"legal hold: sever access as usual but keep the person's personal secrets and Claude homes")

	hubUserCmd.AddCommand(hubUserOffboardCmd)
	hubCmd.AddCommand(hubUserCmd)
}
