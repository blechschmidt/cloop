package cmd

// `cloop hub scim` — SCIM 2.0 provisioning from the shell (Task 20415): the
// credential an identity provider presents to /scim/v2, and what the
// provisioned directory holds.
//
// The shell counterpart to Settings → Provisioning (SCIM). It writes the
// control-plane database directly, like the rest of `cloop hub`, and needs no
// lease: a running hub reads credentials from the database on every request,
// so a credential minted, rotated or revoked here holds at the next one.

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/provision"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

var hubSCIMCmd = &cobra.Command{
	Use:   "scim",
	Short: "SCIM 2.0 provisioning: the identity provider's credential and directory",
	Long: `The identity provider — Microsoft Entra ID, Okta — provisions this hub over
SCIM 2.0 at <hub>/scim/v2. Deactivating an account there suspends it here
without an administrator: in one transaction its sessions, API tokens and
glasses links end and a deny binding refuses it, then its leases are released
and its running tasks stopped. Deleting it runs the full offboarding.

The provider authenticates with a dedicated credential, cloop_scim_…, minted
here or under Settings → Provisioning (SCIM). It is accepted on /scim/v2 and
nowhere else, and every change it makes is audited as scim:<name>.

  cloop hub scim credential create entra
  cloop hub scim credential rotate entra --grace 1h --reason "yearly rotation"
  cloop hub scim credential revoke entra --reason "moving to the new tenant"
  cloop hub scim status

Configuration is ui.oidc.scim: match_claim, offboard_after_days and
rate_limit_per_minute. See docs/guides/scim-provisioning.md.`,
}

var hubSCIMCredentialCmd = &cobra.Command{
	Use:   "credential",
	Short: "Mint, rotate, revoke and list SCIM credentials",
}

// scimAdmin is who is administering from this shell.
func scimAdmin(reason string) provision.AdminContext {
	actor := operatorActor()
	return provision.AdminContext{Actor: actor, Reason: strings.TrimSpace(reason), Via: "cli", OSUser: actor}
}

func printSCIMToken(c statedb.SCIMCredentialRow, plaintext, verb string) {
	fmt.Printf("%s SCIM credential %s (%s)\n\n", verb, color.New(color.Bold).Sprint(c.Name), c.ID)
	fmt.Println("  " + plaintext)
	fmt.Println()
	fmt.Println(color.YellowString("This is the only time it is shown.") +
		" Paste it into the identity provider as the secret token,")
	fmt.Println("with the tenant URL https://<this hub>/scim/v2. The hub keeps only an HMAC of it.")
}

var hubSCIMCredentialCreateCmd = &cobra.Command{
	Use:   "create <name>",
	Short: "Mint a SCIM credential for an identity provider",
	Long: `Mint a credential an identity provider presents to /scim/v2. The name
becomes the audit actor of every change the provider makes, scim:<name>, so
name it after the provider or tenant ("entra", "okta-prod").

The secret is printed once. It is accepted on the SCIM routes only: not as an
API token, not on the dashboard.`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		workdir, _ := cmd.Flags().GetString("workdir")
		reason, _ := cmd.Flags().GetString("reason")
		asJSON, _ := cmd.Flags().GetBool("json")
		warnIfNotAHub(workdir)
		db, closer, err := openHubDB(workdir)
		if err != nil {
			return err
		}
		defer closer()
		minted, err := provision.MintCredential(db, args[0], scimAdmin(reason), time.Now())
		if err != nil {
			return err
		}
		if asJSON {
			return writeSCIMJSON(map[string]any{"credential": scimCredentialJSON(minted.Row), "token": minted.Plaintext})
		}
		printSCIMToken(minted.Row, minted.Plaintext, "Minted")
		return nil
	},
}

var hubSCIMCredentialRotateCmd = &cobra.Command{
	Use:   "rotate <name|id>",
	Short: "Replace a SCIM credential's secret",
	Long: `Replace a credential's secret, keeping its name and id. With --grace the
secret it replaces is still accepted for that long — enough to paste the new
one into the identity provider without a failed provisioning cycle. Without it
the old secret stops working now. The longest grace is 7 days.`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		workdir, _ := cmd.Flags().GetString("workdir")
		raw, _ := cmd.Flags().GetString("reason")
		grace, _ := cmd.Flags().GetDuration("grace")
		asJSON, _ := cmd.Flags().GetBool("json")
		reason, err := requireReason(raw)
		if err != nil {
			return err
		}
		warnIfNotAHub(workdir)
		db, closer, err := openHubDB(workdir)
		if err != nil {
			return err
		}
		defer closer()
		minted, err := provision.RotateCredential(db, args[0], grace, scimAdmin(reason), time.Now())
		if err != nil {
			return err
		}
		if asJSON {
			return writeSCIMJSON(map[string]any{"credential": scimCredentialJSON(minted.Row), "token": minted.Plaintext})
		}
		printSCIMToken(minted.Row, minted.Plaintext, "Rotated")
		if grace > 0 {
			fmt.Printf("The previous secret is accepted until %s.\n", minted.Row.PreviousExpiresAt.Local().Format(time.RFC1123))
		} else {
			fmt.Println("The previous secret no longer works.")
		}
		return nil
	},
}

var hubSCIMCredentialRevokeCmd = &cobra.Command{
	Use:   "revoke <name|id>",
	Short: "Revoke a SCIM credential",
	Long: `Revoke a credential: both its secrets stop working at the next request.
The identity provider's provisioning fails until it is given a new one.`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		workdir, _ := cmd.Flags().GetString("workdir")
		raw, _ := cmd.Flags().GetString("reason")
		asJSON, _ := cmd.Flags().GetBool("json")
		reason, err := requireReason(raw)
		if err != nil {
			return err
		}
		warnIfNotAHub(workdir)
		db, closer, err := openHubDB(workdir)
		if err != nil {
			return err
		}
		defer closer()
		c, revoked, err := provision.RevokeCredential(db, args[0], scimAdmin(reason), time.Now())
		if err != nil {
			return err
		}
		if asJSON {
			return writeSCIMJSON(map[string]any{"credential": scimCredentialJSON(c), "revoked": revoked})
		}
		if revoked {
			fmt.Printf("Revoked SCIM credential %s (%s).\n", c.Name, c.ID)
		} else {
			fmt.Printf("SCIM credential %s (%s) was already revoked.\n", c.Name, c.ID)
		}
		return nil
	},
}

var hubSCIMCredentialListCmd = &cobra.Command{
	Use:   "list",
	Short: "List SCIM credentials, revoked ones included",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		workdir, _ := cmd.Flags().GetString("workdir")
		asJSON, _ := cmd.Flags().GetBool("json")
		db, closer, err := openHubDB(workdir)
		if err != nil {
			return err
		}
		defer closer()
		creds, err := db.ListSCIMCredentials()
		if err != nil {
			return err
		}
		if asJSON {
			out := make([]map[string]any, 0, len(creds))
			for _, c := range creds {
				out = append(out, scimCredentialJSON(c))
			}
			return writeSCIMJSON(map[string]any{"credentials": out})
		}
		if len(creds) == 0 {
			fmt.Println("No SCIM credentials. Mint one with `cloop hub scim credential create <name>`.")
			return nil
		}
		tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "NAME\tID\tCREATED\tROTATED\tLAST USED\tSTATE")
		for _, c := range creds {
			state := "live"
			if c.Revoked() {
				state = "revoked " + scimTime(c.RevokedAt)
			} else if c.PreviousHash != "" && time.Now().Before(c.PreviousExpiresAt) {
				state = "live, previous secret until " + scimTime(c.PreviousExpiresAt)
			}
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n", c.Name, c.ID, scimTime(c.CreatedAt),
				scimTime(c.RotatedAt), scimTime(c.LastUsedAt), state)
		}
		return tw.Flush()
	},
}

var hubSCIMStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "What the identity provider has provisioned, and what is waiting",
	Long: `Summarise the provisioned directory: users, how many are active and
suspended, groups, users the match claim cannot place or places twice, and
the users ui.oidc.scim.offboard_after_days will offboard at the next sweep.`,
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		workdir, _ := cmd.Flags().GetString("workdir")
		asJSON, _ := cmd.Flags().GetBool("json")
		db, closer, err := openHubDB(workdir)
		if err != nil {
			return err
		}
		defer closer()
		var scimCfg config.SCIMConfig
		if oidc := configuredBindings(workdir); oidc != nil {
			scimCfg = oidc.SCIM
		}
		claim, err := provision.ParseMatchClaim(scimCfg.MatchClaim)
		if err != nil {
			return err
		}
		dir, err := provision.NewDirectory(db, claim)
		if err != nil {
			return err
		}
		stats := dir.Stats()
		days := scimCfg.EffectiveOffboardAfterDays()
		var pending []statedb.SCIMUserRow
		if days > 0 {
			if pending, err = db.PendingSCIMOffboards(time.Now().Add(-time.Duration(days) * 24 * time.Hour)); err != nil {
				return err
			}
		}
		creds, err := db.ListSCIMCredentials()
		if err != nil {
			return err
		}
		live := 0
		for _, c := range creds {
			if !c.Revoked() {
				live++
			}
		}
		if asJSON {
			names := make([]string, 0, len(pending))
			for _, p := range pending {
				names = append(names, p.UserName)
			}
			return writeSCIMJSON(map[string]any{
				"match_claim": claim, "offboard_after_days": days,
				"rate_limit_per_minute": scimCfg.EffectiveRateLimitPerMinute(),
				"directory":             stats, "pending_offboards": names, "live_credentials": live,
			})
		}
		fmt.Printf("Match claim:      %s\n", claim)
		fmt.Printf("Credentials:      %d live\n", live)
		fmt.Printf("Users:            %d (%d active, %d suspended)\n", stats.Users, stats.Active, stats.Inactive)
		fmt.Printf("Groups:           %d (%d memberships)\n", stats.Groups, stats.Memberships)
		if stats.Unmatchable > 0 {
			fmt.Printf(color.YellowString("Unmatchable:      %d user(s) carry no %s, so no hub identity is theirs\n"),
				stats.Unmatchable, claim)
		}
		if stats.Ambiguous > 0 {
			fmt.Printf(color.YellowString("Ambiguous:        %d user(s) share a %s with another; none of their "+
				"groups are granted\n"), stats.Ambiguous, claim)
		}
		if days > 0 {
			fmt.Printf("Offboard after:   %d day(s) suspended — %d due at the next sweep\n", days, len(pending))
			for _, p := range pending {
				fmt.Printf("  %s  suspended %s\n", p.UserName, scimTime(p.DeactivatedAt))
			}
		} else {
			fmt.Println("Offboard after:   never (ui.oidc.scim.offboard_after_days is 0) — only a DELETE offboards")
		}
		return nil
	},
}

func scimCredentialJSON(c statedb.SCIMCredentialRow) map[string]any {
	out := map[string]any{
		"id": c.ID, "name": c.Name, "prefix": provision.CredentialPrefix + c.ID,
		"created_at": c.CreatedAt, "created_by": c.CreatedBy, "revoked": c.Revoked(),
	}
	if !c.RotatedAt.IsZero() {
		out["rotated_at"] = c.RotatedAt
	}
	if !c.RevokedAt.IsZero() {
		out["revoked_at"], out["revoked_by"] = c.RevokedAt, c.RevokedBy
	}
	if !c.LastUsedAt.IsZero() {
		out["last_used_at"] = c.LastUsedAt
	}
	if c.PreviousHash != "" && time.Now().Before(c.PreviousExpiresAt) {
		out["previous_valid_until"] = c.PreviousExpiresAt
	}
	return out
}

func scimTime(t time.Time) string {
	if t.IsZero() {
		return "-"
	}
	return t.Local().Format("2006-01-02 15:04")
}

func writeSCIMJSON(v any) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

// ── legal holds ─────────────────────────────────────────────────────────────

var hubUserHoldCmd = &cobra.Command{
	Use:   "hold",
	Short: "Place, release and list legal holds",
	Long: `A legal hold keeps an identity's stored credentials — personal secrets and
Claude Code homes — through every offboarding of it, whoever starts it: an
operator's ` + "`cloop hub user offboard`" + `, the identity provider deleting the
account over SCIM, or ui.oidc.scim.offboard_after_days running out. Access is
severed exactly as without a hold.

  cloop hub user hold place alice@example.com --reason "LH-17, contract dispute"
  cloop hub user hold list
  cloop hub user hold release alice@example.com --reason "LH-17 closed"`,
}

var hubUserHoldPlaceCmd = &cobra.Command{
	Use:   "place <email|sub:subject>",
	Short: "Place a legal hold on an identity",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		workdir, _ := cmd.Flags().GetString("workdir")
		raw, _ := cmd.Flags().GetString("reason")
		reason, err := requireReason(raw)
		if err != nil {
			return err
		}
		warnIfNotAHub(workdir)
		db, closer, err := openHubDB(workdir)
		if err != nil {
			return err
		}
		defer closer()
		h, err := provision.PlaceHold(db, args[0], reason, scimAdmin(""), time.Now())
		if err != nil {
			return err
		}
		fmt.Printf("Legal hold on %s: %s\n", h.Identity, h.Reason)
		fmt.Println("Every offboarding of this identity keeps its personal secrets and Claude Code homes until the hold is released.")
		return nil
	},
}

var hubUserHoldReleaseCmd = &cobra.Command{
	Use:   "release <email|sub:subject>",
	Short: "Release a legal hold",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		workdir, _ := cmd.Flags().GetString("workdir")
		raw, _ := cmd.Flags().GetString("reason")
		reason, err := requireReason(raw)
		if err != nil {
			return err
		}
		warnIfNotAHub(workdir)
		db, closer, err := openHubDB(workdir)
		if err != nil {
			return err
		}
		defer closer()
		prev, released, err := provision.ReleaseHold(db, args[0], scimAdmin(reason), time.Now())
		if err != nil {
			return err
		}
		if !released {
			return fmt.Errorf("no legal hold is placed on %s", args[0])
		}
		fmt.Printf("Released the legal hold on %s (placed %s by %s: %s).\n", prev.Identity,
			scimTime(prev.PlacedAt), prev.PlacedBy, prev.Reason)
		fmt.Println("An offboarding already run under it kept what it stored; run `cloop hub user offboard` again to destroy it.")
		return nil
	},
}

var hubUserHoldListCmd = &cobra.Command{
	Use:   "list",
	Short: "List legal holds",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		workdir, _ := cmd.Flags().GetString("workdir")
		asJSON, _ := cmd.Flags().GetBool("json")
		db, closer, err := openHubDB(workdir)
		if err != nil {
			return err
		}
		defer closer()
		holds, err := db.ListLegalHolds()
		if err != nil {
			return err
		}
		if asJSON {
			out := make([]map[string]any, 0, len(holds))
			for _, h := range holds {
				out = append(out, map[string]any{"identity": h.Identity, "reason": h.Reason,
					"placed_at": h.PlacedAt, "placed_by": h.PlacedBy})
			}
			return writeSCIMJSON(map[string]any{"holds": out})
		}
		if len(holds) == 0 {
			fmt.Println("No legal holds.")
			return nil
		}
		tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "IDENTITY\tPLACED\tBY\tREASON")
		for _, h := range holds {
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", h.Identity, scimTime(h.PlacedAt), h.PlacedBy, h.Reason)
		}
		return tw.Flush()
	},
}

func init() {
	for _, c := range []*cobra.Command{hubSCIMCredentialCreateCmd, hubSCIMCredentialRotateCmd,
		hubSCIMCredentialRevokeCmd, hubSCIMCredentialListCmd, hubSCIMStatusCmd,
		hubUserHoldPlaceCmd, hubUserHoldReleaseCmd, hubUserHoldListCmd} {
		c.Flags().String("workdir", "", "the hub's directory (default: the current one)")
		c.Flags().Bool("json", false, "print JSON")
	}
	for _, c := range []*cobra.Command{hubSCIMCredentialCreateCmd, hubSCIMCredentialRotateCmd,
		hubSCIMCredentialRevokeCmd, hubUserHoldPlaceCmd, hubUserHoldReleaseCmd} {
		c.Flags().String("reason", "", "why, for the audit trail")
	}
	hubSCIMCredentialRotateCmd.Flags().Duration("grace", 0,
		"keep accepting the replaced secret this long (at most 168h)")

	hubSCIMCredentialCmd.AddCommand(hubSCIMCredentialCreateCmd, hubSCIMCredentialRotateCmd,
		hubSCIMCredentialRevokeCmd, hubSCIMCredentialListCmd)
	hubSCIMCmd.AddCommand(hubSCIMCredentialCmd, hubSCIMStatusCmd)
	hubCmd.AddCommand(hubSCIMCmd)
	hubUserHoldCmd.AddCommand(hubUserHoldPlaceCmd, hubUserHoldReleaseCmd, hubUserHoldListCmd)
	hubUserCmd.AddCommand(hubUserHoldCmd)
}
