package cmd

// `cloop hub session` — terminating dashboard sessions from a shell
// (Task 20248).
//
// The counterpart to GET/DELETE /api/sessions. It exists for the case those
// cannot serve: the listener is wedged, the hub is down, or the operator is
// on the host over SSH with no browser and a stolen cookie to contain. It
// reads and writes pkg/sessionstore directly for that reason, and takes no
// lease — see the lease rule in hub_admin.go.
//
// Revocation is not instantaneous and this file does not pretend otherwise. A
// running hub serves sessions from a 30-second cache (pkg/oidcauth), so a row
// deleted here stops being honoured within that window, which is the same
// bound the hub already accepts between replicas. Commands say so rather than
// printing an unqualified success.

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"github.com/blechschmidt/cloop/pkg/oidcauth"
	"github.com/blechschmidt/cloop/pkg/sessionstore"
)

// sessionRevocationWindow is how long a running hub may keep honouring a
// session this command deleted. It mirrors pkg/oidcauth's session cache TTL;
// it is stated to the operator rather than assumed, because "I revoked it and
// they were still in" is otherwise indistinguishable from a failure.
const sessionRevocationWindow = 30 * time.Second

var hubSessionCmd = &cobra.Command{
	Use:   "session",
	Short: "List and revoke dashboard sessions without a browser",
	Long: `Inspect and terminate signed-in dashboard sessions.

Operates on the hub's session table directly rather than through the REST API,
so it keeps working when the HTTP listener does not — which is the situation
that tends to produce the need for it.

  cloop hub session list                       who is signed in
  cloop hub session list --identity alice@x.io  ...for one person
  cloop hub session revoke <id> --reason "..."  end one session
  cloop hub session revoke --identity alice@x.io --reason "..."
  cloop hub session revoke --all --reason "..." end every session

A revoked session stops working within ` + sessionRevocationWindow.String() + ` on a running hub, which is how
long it may still be served from that process's session cache. Revoking does
not invalidate API tokens: a compromised account usually holds both, and
` + "`cloop hub token revoke`" + ` is the other half.`,
}

var hubSessionListCmd = &cobra.Command{
	Use:   "list",
	Short: "List signed-in dashboard sessions",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		workdir, _ := cmd.Flags().GetString("workdir")
		identity, _ := cmd.Flags().GetString("identity")
		asJSON, _ := cmd.Flags().GetBool("json")

		db, closer, err := openHubDB(workdir)
		if err != nil {
			return err
		}
		defer closer()
		store, err := sessionstore.New(db)
		if err != nil {
			return err
		}
		records, err := store.List()
		if err != nil {
			return fmt.Errorf("list sessions: %w", err)
		}
		records = filterSessions(records, identity)
		sort.Slice(records, func(i, j int) bool {
			return records[i].LastSeen.After(records[j].LastSeen)
		})

		if asJSON {
			return json.NewEncoder(os.Stdout).Encode(sessionsToJSON(records))
		}
		if len(records) == 0 {
			if identity != "" {
				fmt.Printf("No sessions for %q.\n", identity)
			} else {
				fmt.Println("No active sessions.")
			}
			return nil
		}
		now := time.Now()
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "ID\tIDENTITY\tIP\tIDLE\tEXPIRES\tIDP CHECKED")
		for _, rec := range records {
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n",
				truncateField(rec.ID, 16),
				truncateField(sessionIdentityLabel(rec), 32),
				truncateField(orDash(rec.IP), 20),
				durationLabel(now.Sub(rec.LastSeen)),
				expiryLabel(rec.ExpiresAt),
				lastUsedLabel(rec.RefreshCheckedAt))
		}
		return w.Flush()
	},
}

var hubSessionRevokeCmd = &cobra.Command{
	Use:   "revoke [id]",
	Short: "End one session, every session for an identity, or all of them",
	Long: `End dashboard sessions.

Exactly one selector is required: a session id, --identity, or --all. There is
no default, because the three differ by two orders of magnitude in blast radius
and the safe one is not obviously the one an operator meant.

Examples:

  # A single stolen cookie, identified from the Sessions panel or from ` + "`list`" + `
  cloop hub session revoke 9f3c... --reason "reported stolen laptop, INC-4412"

  # Everything one account holds
  cloop hub session revoke --identity alice@example.com --reason "credential compromise INC-4412"

  # Every session on the hub — an IdP compromise, or a hub being handed over
  cloop hub session revoke --all --reason "rotating IdP client secret"`,
	Args: cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		workdir, _ := cmd.Flags().GetString("workdir")
		identity, _ := cmd.Flags().GetString("identity")
		all, _ := cmd.Flags().GetBool("all")
		rawReason, _ := cmd.Flags().GetString("reason")

		var id string
		if len(args) == 1 {
			id = strings.TrimSpace(args[0])
		}
		selectors := 0
		for _, set := range []bool{id != "", identity != "", all} {
			if set {
				selectors++
			}
		}
		if selectors != 1 {
			return fmt.Errorf(
				"give exactly one of: a session id, --identity <who>, or --all")
		}
		reason, err := requireReason(rawReason)
		if err != nil {
			return err
		}

		db, closer, err := openHubDB(workdir)
		if err != nil {
			return err
		}
		defer closer()
		store, err := sessionstore.New(db)
		if err != nil {
			return err
		}

		// Resolve the selection before writing anything, so the audit record
		// names what was actually ended rather than what was asked for, and so
		// a mistyped identity is an error instead of a silent success.
		var targets []oidcauth.SessionRecord
		if id != "" {
			rec, err := store.Get(id)
			if err != nil {
				return fmt.Errorf("session %q: %w", id, err)
			}
			targets = []oidcauth.SessionRecord{rec}
		} else {
			records, err := store.List()
			if err != nil {
				return fmt.Errorf("list sessions: %w", err)
			}
			if all {
				targets = records
			} else {
				targets = filterSessions(records, identity)
			}
		}
		if len(targets) == 0 {
			return fmt.Errorf("no sessions match — nothing to revoke")
		}

		// Delete, then audit — the opposite order from the single-row
		// mutations elsewhere in this package, and the batch is why.
		//
		// Audit-first is right when the whole command is one write: a trail
		// failure aborts before anything changed. In a loop it stops being
		// right, because the abort lands mid-batch: a row audited as revoked
		// whose delete then fails leaves the trail asserting containment that
		// did not happen, and a reviewer who believes it stops looking. An
		// unrecorded revocation is the lesser error — the session really is
		// gone, and the operator is told which one lost its record.
		//
		// SQLITE_BUSY from a live hub is the realistic trigger, and it is in
		// scope precisely because this command deliberately takes no lease.
		revoked := make([]oidcauth.SessionRecord, 0, len(targets))
		for _, rec := range targets {
			existed, err := store.Delete(rec.ID)
			if err != nil {
				return fmt.Errorf("revoke session %s (%d of %d already revoked): %w",
					rec.ID, len(revoked), len(targets), err)
			}
			if !existed {
				// Gone between the listing and now — the janitor swept it, or
				// the hub's own panel ended it. Not this operator's action, so
				// it is not recorded as one.
				continue
			}
			revoked = append(revoked, rec)
			if err := auditHubAdmin(db, "session.revoked", "session", rec.ID, reason, map[string]any{
				"subject":   rec.Identity.Sub,
				"email":     rec.Identity.Email,
				"ip":        rec.IP,
				"issued_at": rec.IssuedAt.UTC().Format(time.RFC3339),
				"selector":  revokeSelectorLabel(id, identity, all),
				"selected":  len(targets),
			}); err != nil {
				return fmt.Errorf("session %s was revoked but could not be recorded "+
					"in the audit trail: %w", rec.ID, err)
			}
		}
		if len(revoked) == 0 {
			return fmt.Errorf("every matching session had already ended — nothing to revoke")
		}

		color.New(color.FgGreen).Printf("Revoked %d session(s).\n", len(revoked))
		for _, rec := range revoked {
			fmt.Printf("  %s  %s\n", truncateField(rec.ID, 16), sessionIdentityLabel(rec))
		}
		color.New(color.Faint).Printf(
			"\nA running hub may still honour these for up to %s (its session cache).\n"+
				"API tokens are a separate credential — see `cloop hub token list`.\n",
			sessionRevocationWindow)
		return nil
	},
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

// filterSessions narrows records to one identity, matched against email or
// subject.
//
// Email is compared case-insensitively because identity providers are
// inconsistent about the case they release, and an operator typing an address
// from a ticket should not have to guess. Subject is compared exactly:
// subjects are opaque and two that differ only in case are two people.
func filterSessions(records []oidcauth.SessionRecord, identity string) []oidcauth.SessionRecord {
	identity = strings.TrimSpace(identity)
	if identity == "" {
		return records
	}
	out := make([]oidcauth.SessionRecord, 0, len(records))
	for _, rec := range records {
		if strings.EqualFold(rec.Identity.Email, identity) || rec.Identity.Sub == identity {
			out = append(out, rec)
		}
	}
	return out
}

func sessionIdentityLabel(rec oidcauth.SessionRecord) string {
	if rec.Identity.Email != "" {
		return rec.Identity.Email
	}
	if rec.Identity.Sub != "" {
		return "sub:" + rec.Identity.Sub
	}
	return "(unknown)"
}

func revokeSelectorLabel(id, identity string, all bool) string {
	switch {
	case all:
		return "all"
	case identity != "":
		return "identity:" + identity
	default:
		return "id:" + id
	}
}

func sessionsToJSON(records []oidcauth.SessionRecord) []map[string]any {
	out := make([]map[string]any, 0, len(records))
	for _, rec := range records {
		out = append(out, map[string]any{
			"id":             rec.ID,
			"subject":        rec.Identity.Sub,
			"email":          rec.Identity.Email,
			"display_name":   rec.Identity.Name,
			"ip":             rec.IP,
			"user_agent":     rec.UserAgent,
			"issued_at":      rec.IssuedAt.UTC(),
			"last_seen":      rec.LastSeen.UTC(),
			"expires_at":     rec.ExpiresAt.UTC(),
			"idp_checked_at": rec.RefreshCheckedAt.UTC(),
		})
	}
	return out
}

// durationLabel renders an age compactly. Sessions are listed during incidents
// where "is this one active right now" is the question, so seconds matter near
// zero and nothing beyond days does.
func durationLabel(d time.Duration) string {
	switch {
	case d < 0:
		return "0s"
	case d < time.Minute:
		return fmt.Sprintf("%ds", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%dm", int(d.Minutes()))
	case d < 24*time.Hour:
		return fmt.Sprintf("%dh", int(d.Hours()))
	}
	return fmt.Sprintf("%dd", int(d.Hours()/24))
}

// registerHubSessionFlags declares the flags each session subcommand reads.
// See registerHubRoleFlags for why this is not inline in init().
func registerHubSessionFlags(c *cobra.Command, kind string) {
	c.Flags().String("workdir", "", "hub directory holding .cloop/state.db (default: current directory)")
	c.Flags().String("identity", "", "select by email address or IdP subject")
	if kind == "list" {
		c.Flags().Bool("json", false, "emit JSON for scripting")
		return
	}
	c.Flags().Bool("all", false, "revoke every session on the hub")
	c.Flags().String("reason", "", "why (required; recorded in the audit trail)")
}

func init() {
	registerHubSessionFlags(hubSessionListCmd, "list")
	registerHubSessionFlags(hubSessionRevokeCmd, "revoke")

	hubSessionCmd.AddCommand(hubSessionListCmd)
	hubSessionCmd.AddCommand(hubSessionRevokeCmd)
	hubCmd.AddCommand(hubSessionCmd)
}
