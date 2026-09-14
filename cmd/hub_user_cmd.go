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

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"github.com/blechschmidt/cloop/pkg/multiui"
	"github.com/blechschmidt/cloop/pkg/offboard"
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

Six surfaces outlive an account disabled at the identity provider, and all six
are severed here:

  sessions   every signed-in dashboard session
  tokens     every API token whose owner binding is this person
  glasses    every Meta Ray-Ban Display link they hold
  deny       a runtime deny binding, so a *new* sign-in gets nothing either
  leases     secret leases held by their running tasks, released at the broker
  tasks      those tasks, stopped

and a seventh is reported but never touched:

  projects   the projects they own, listed so an operator can reassign them

Projects are not deleted, on purpose. A departing user's projects usually hold
the team's work, and a command that quietly removed them would be a data-loss
tool wearing a security label.

The identity is resolved before anything is written. Give an email or an IdP
subject; both are expanded to every identifier that turns out to address the
same person, because the surfaces are keyed inconsistently — a session carries
an email, a token's owner may carry only a subject, and matching literally on
what you typed would leave that token live.

Sessions, tokens, glasses links and the deny binding are written in ONE
transaction: either the person is out of all four or nothing changed. Leases
and tasks cannot join that transaction — they are broker memory and other
databases — so they are applied after it, and any failure is reported rather
than rolled back over a severing that already succeeded.

Run --dry-run first. It prints the same set the write would act on, because it
is the set the write acts on.

A revoked session stops working within ` + sessionRevocationWindow.String() + ` on a running hub, which is
how long it may still be served from that process's session cache.

Examples:

  # See the blast radius, change nothing
  cloop hub user offboard alice@example.com --dry-run

  # Do it
  cloop hub user offboard alice@example.com --reason "left the company, HR-882"

  # Someone whose IdP supplies no email claim
  cloop hub user offboard 'sub:8f14e45fce' --reason "contract ended, HR-901"`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		workdir, _ := cmd.Flags().GetString("workdir")
		dryRun, _ := cmd.Flags().GetBool("dry-run")
		asJSON, _ := cmd.Flags().GetBool("json")
		rawReason, _ := cmd.Flags().GetString("reason")

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

		// No broker here on purpose. Building one needs CLOOP_SECRET_KEY, and
		// an offboarding that refused to run because a shell lacked the sealing
		// key would fail in exactly the emergency it exists for. Leases are
		// bounded by their own TTL and are released by the hub; the report says
		// they were not checked rather than implying they were clean.
		rep, err := offboard.Run(offboard.Options{
			DB:       db,
			Identity: identity,
			Reason:   reason,
			Actor:    operatorActor(),
			Via:      "cli",
			DryRun:   dryRun,
			Projects: projects,
			Tasks:    offboard.LocalTasks(),
		})
		if err != nil {
			return err
		}

		if asJSON {
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			if err := enc.Encode(rep); err != nil {
				return err
			}
		} else {
			printOffboardReport(rep)
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
func printOffboardReport(rep offboard.Report) {
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

	var tasks []string
	for _, t := range rep.Tasks {
		tasks = append(tasks, fmt.Sprintf("%s #%d  %s", t.ProjectName, t.ID, t.Title))
	}
	detail("Running tasks:", tasks)

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
	faint.Printf("A running hub may keep honouring revoked sessions for up to %s "+
		"(its session cache).\n", sessionRevocationWindow)
}

func init() {
	c := hubUserOffboardCmd
	c.Flags().String("workdir", "", "hub directory holding .cloop/state.db (default: current directory)")
	c.Flags().Bool("dry-run", false, "print the blast radius and change nothing")
	c.Flags().Bool("json", false, "emit JSON for scripting")
	c.Flags().String("reason", "", "why (required unless --dry-run; recorded in the audit trail)")

	hubUserCmd.AddCommand(hubUserOffboardCmd)
	hubCmd.AddCommand(hubUserCmd)
}
