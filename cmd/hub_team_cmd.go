package cmd

// `cloop hub team` — the teams projects are shared with (Task 20478), for an
// administrator on the hub host.
//
// The dashboard's Settings → Teams is the everyday surface and takes
// user.manage. This command is the operator's: it writes the hub's
// control-plane database directly, like the rest of `cloop hub`, so it works
// when the listener does not — and whoever can run it can already write that
// database, so it checks no role. Every change commits together with its audit
// row (team.*, via "cli", with the operator's --reason) and is then announced
// on the hub cluster's bus, so running hub processes apply it — and close the
// open dashboards of anybody who lost a project through it — within a poll.

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"github.com/blechschmidt/cloop/pkg/auditaction"
	"github.com/blechschmidt/cloop/pkg/hubteam"
	"github.com/blechschmidt/cloop/pkg/projectmember"
	"github.com/blechschmidt/cloop/pkg/statedb"
	"github.com/blechschmidt/cloop/pkg/ui"
)

var hubTeamCmd = &cobra.Command{
	Use:   "team",
	Short: "Keep the teams projects are shared with",
	Long: `A team is a named group of people a project can be shared with, at a role, from
the project's Members card or with "cloop project members add <project> team:<slug>".
Its members are the people added to it by name, plus — when it follows one — everyone
whose ID token carries an identity-provider group (--idp-group), and everyone the
identity provider provisioned into a SCIM group (--scim-group). "everyone" is the
built-in team of every signed-in identity and needs no definition.

  cloop hub team list
  cloop hub team show payments
  cloop hub team create payments --name "Payments" --idp-group payments-devs --reason "..."
  cloop hub team add payments bob@example.com --reason "..."
  cloop hub team remove payments bob@example.com --reason "..."
  cloop hub team delete payments --reason "..."

Deleting a team also removes every project share that names it. Run it from the
hub's directory, or pass --workdir.`,
}

func openTeamStore(cmd *cobra.Command) (*hubteam.Store, *statedb.DB, func(), error) {
	workdir, _ := cmd.Flags().GetString("workdir")
	db, closer, err := openHubDB(workdir)
	if err != nil {
		return nil, nil, nil, err
	}
	store, err := hubteam.New(db.AsControlPlane())
	if err != nil {
		closer()
		return nil, nil, nil, err
	}
	return store, db, closer, nil
}

// teamShares maps each team to the projects shared with it.
func teamShares(db *statedb.DB) (map[string][]projectmember.Member, error) {
	store, err := projectmember.New(db)
	if err != nil {
		return nil, err
	}
	out := map[string][]projectmember.Member{}
	for _, m := range store.All() {
		if slug, ok := hubteam.SlugOfShareKey(m.IdentityKey); ok {
			out[slug] = append(out[slug], m)
		}
	}
	return out, nil
}

var hubTeamListCmd = &cobra.Command{
	Use:   "list",
	Short: "List the hub's teams",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		asJSON, _ := cmd.Flags().GetBool("json")
		store, db, closer, err := openTeamStore(cmd)
		if err != nil {
			return err
		}
		defer closer()
		shares, err := teamShares(db)
		if err != nil {
			return err
		}
		teams := append([]hubteam.Team{hubteam.BuiltinTeam()}, store.All()...)
		if asJSON {
			type row struct {
				hubteam.Team
				Projects []projectmember.Member `json:"projects"`
			}
			out := make([]row, 0, len(teams))
			for _, t := range teams {
				out = append(out, row{Team: t, Projects: nonNilMembers(shares[t.Slug])})
			}
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			return enc.Encode(map[string]any{"teams": out})
		}
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "SLUG\tNAME\tBY NAME\tFOLLOWS\tPROJECTS")
		for _, t := range teams {
			follows := teamFollows(t)
			byName := fmt.Sprint(len(t.Members))
			if t.Builtin() {
				byName, follows = "-", "every signed-in identity"
			}
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%d\n", t.Slug, truncateField(t.Label(), 30), byName, follows, len(shares[t.Slug]))
		}
		return w.Flush()
	},
}

func teamFollows(t hubteam.Team) string {
	var parts []string
	if t.IdPGroup != "" {
		parts = append(parts, "group "+t.IdPGroup)
	}
	if t.SCIMGroup != "" {
		parts = append(parts, "scim "+t.SCIMGroup)
	}
	if len(parts) == 0 {
		return "-"
	}
	return strings.Join(parts, ", ")
}

var hubTeamShowCmd = &cobra.Command{
	Use:   "show <slug>",
	Short: "Show a team: who is on it by name, what it follows, and its projects",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		asJSON, _ := cmd.Flags().GetBool("json")
		store, db, closer, err := openTeamStore(cmd)
		if err != nil {
			return err
		}
		defer closer()
		t, ok := store.Get(args[0])
		if !ok {
			return fmt.Errorf("there is no team %s on this hub", hubteam.NormalizeSlug(args[0]))
		}
		shares, err := teamShares(db)
		if err != nil {
			return err
		}
		projects := shares[t.Slug]
		sort.Slice(projects, func(i, j int) bool { return projects[i].ProjectPath < projects[j].ProjectPath })
		if asJSON {
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			return enc.Encode(map[string]any{"team": t, "projects": nonNilMembers(projects)})
		}
		fmt.Printf("%s (%s)\n", t.Label(), t.Slug)
		if t.Description != "" {
			fmt.Printf("  %s\n", t.Description)
		}
		if t.Builtin() {
			fmt.Println("  members: every signed-in identity")
		} else {
			fmt.Printf("  follows: %s\n", teamFollows(t))
			fmt.Printf("  by name (%d):\n", len(t.Members))
			for _, m := range t.Members {
				fmt.Printf("    %s  added %s by %s\n", m.IdentityKey, m.AddedAt.Local().Format("2006-01-02 15:04"), m.AddedBy)
			}
		}
		fmt.Printf("  shared with %d project(s):\n", len(projects))
		for _, p := range projects {
			fmt.Printf("    %s  as %s\n", p.ProjectPath, p.Role)
		}
		return nil
	},
}

var hubTeamCreateCmd = &cobra.Command{
	Use:   "create <slug>",
	Short: "Create a team",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		reason, err := requireReason(mustString(cmd, "reason"))
		if err != nil {
			return err
		}
		warnIfNoSingleSignOn(mustString(cmd, "workdir"))
		store, db, closer, err := openTeamStore(cmd)
		if err != nil {
			return err
		}
		defer closer()
		t, err := store.Create(hubteam.Team{
			Slug: args[0], Name: mustString(cmd, "name"), Description: mustString(cmd, "description"),
			IdPGroup: mustString(cmd, "idp-group"), SCIMGroup: mustString(cmd, "scim-group"), CreatedBy: operatorActor(),
		}, cliTeamAudit(auditaction.ActionTeamCreate, reason))
		if err != nil {
			return plainTeamError(err)
		}
		color.New(color.FgGreen).Printf("Created team %s (%s).\n", t.Slug, t.Label())
		announceTeams(db, t.Slug)
		return nil
	},
}

var hubTeamUpdateCmd = &cobra.Command{
	Use:   "update <slug>",
	Short: "Rename a team, or change the groups it follows",
	Long: `Change a team's name, description or the groups it follows. A flag left out keeps
its value; an empty one (--idp-group "") clears a link. Relinking changes who is on
the team, and so who reaches every project shared with it.`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		reason, err := requireReason(mustString(cmd, "reason"))
		if err != nil {
			return err
		}
		store, db, closer, err := openTeamStore(cmd)
		if err != nil {
			return err
		}
		defer closer()
		t, ok := store.Get(args[0])
		if !ok || t.Builtin() {
			return fmt.Errorf("there is no team %s on this hub to change", hubteam.NormalizeSlug(args[0]))
		}
		for flag, field := range map[string]*string{"name": &t.Name, "description": &t.Description,
			"idp-group": &t.IdPGroup, "scim-group": &t.SCIMGroup} {
			if cmd.Flags().Changed(flag) {
				*field = mustString(cmd, flag)
			}
		}
		t.UpdatedBy = operatorActor()
		stored, _, err := store.Update(t, cliTeamAudit(auditaction.ActionTeamUpdate, reason))
		if err != nil {
			return plainTeamError(err)
		}
		color.New(color.FgGreen).Printf("Updated team %s: follows %s.\n", stored.Slug, teamFollows(stored))
		announceTeams(db, stored.Slug)
		return nil
	},
}

var hubTeamDeleteCmd = &cobra.Command{
	Use:   "delete <slug>",
	Short: "Delete a team and every project share naming it",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		reason, err := requireReason(mustString(cmd, "reason"))
		if err != nil {
			return err
		}
		store, db, closer, err := openTeamStore(cmd)
		if err != nil {
			return err
		}
		defer closer()
		t, shares, err := store.Delete(args[0], cliTeamAudit(auditaction.ActionTeamDelete, reason))
		if err != nil {
			return plainTeamError(err)
		}
		color.New(color.FgGreen).Printf("Deleted team %s; unshared %d project(s).\n", t.Slug, len(shares))
		for _, sh := range shares {
			fmt.Printf("  %s (was %s)\n", sh.ProjectPath, sh.Role)
			if err := ui.AnnounceMembershipChange(db, cliOrigin(), sh.ProjectPath); err != nil {
				fmt.Fprintf(os.Stderr, "warning: could not notify running hubs of the removed share: %v\n", err)
			}
		}
		announceTeams(db, t.Slug)
		return nil
	},
}

var hubTeamAddCmd = &cobra.Command{
	Use:   "add <slug> <identity>",
	Short: "Add a person to a team by name",
	Args:  cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		reason, err := requireReason(mustString(cmd, "reason"))
		if err != nil {
			return err
		}
		store, db, closer, err := openTeamStore(cmd)
		if err != nil {
			return err
		}
		defer closer()
		m, existed, err := store.AddMember(args[0], args[1], operatorActor(), cliTeamAudit(auditaction.ActionTeamMemberAdd, reason))
		if err != nil {
			return plainTeamError(err)
		}
		slug := hubteam.NormalizeSlug(args[0])
		if existed {
			fmt.Printf("%s is already on %s.\n", m.IdentityKey, slug)
			return nil
		}
		color.New(color.FgGreen).Printf("Added %s to %s.\n", m.IdentityKey, slug)
		announceTeams(db, slug)
		return nil
	},
}

var hubTeamRemoveCmd = &cobra.Command{
	Use:   "remove <slug> <identity>",
	Short: "Take a person off a team",
	Args:  cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		reason, err := requireReason(mustString(cmd, "reason"))
		if err != nil {
			return err
		}
		store, db, closer, err := openTeamStore(cmd)
		if err != nil {
			return err
		}
		defer closer()
		removed, err := store.RemoveMember(args[0], args[1], cliTeamAudit(auditaction.ActionTeamMemberRemove, reason))
		if err != nil {
			return plainTeamError(err)
		}
		slug := hubteam.NormalizeSlug(args[0])
		if removed == nil {
			return fmt.Errorf("%s is not on %s by name", projectmember.NormalizeKey(args[1]), slug)
		}
		color.New(color.FgGreen).Printf("Removed %s from %s.\n", removed.IdentityKey, slug)
		if t, ok := store.Get(slug); ok && (t.IdPGroup != "" || t.SCIMGroup != "") {
			fmt.Printf("They stay on it while the team follows %s and they are in that group.\n", teamFollows(t))
		}
		announceTeams(db, slug)
		return nil
	},
}

// cliTeamAudit builds the audit rows a CLI team change commits with.
func cliTeamAudit(action auditaction.Action, reason string) hubteam.Audit {
	actor := operatorActor()
	return ui.TeamAuditRows(actor, "cli", action, map[string]any{"reason": reason, "os_user": actor})
}

// announceTeams tells running hub processes to apply a team change now. A
// failure only delays it to their next refresh, so it is a warning.
func announceTeams(db *statedb.DB, slug string) {
	if err := ui.AnnounceTeamsChange(db, cliOrigin(), slug); err != nil {
		fmt.Fprintf(os.Stderr, "warning: could not notify running hubs (%v); they apply the change within %s\n",
			err, hubteam.DefaultTTL)
		return
	}
	color.New(color.Faint).Println("Running hub processes apply this at once, and close the open dashboards of anybody who lost a project through it.")
}

// plainTeamError words a refused team change for whoever typed the command.
func plainTeamError(err error) error {
	switch {
	case errors.Is(err, statedb.ErrTeamExists):
		return errors.New("a team with that slug already exists")
	case errors.Is(err, statedb.ErrTeamNotFound):
		return errors.New("there is no such team on this hub")
	}
	msg := err.Error()
	for _, prefix := range []string{"team: ", "statedb: "} {
		msg = strings.ReplaceAll(msg, prefix, "")
	}
	return errors.New(msg)
}

// registerHubTeamFlags declares the flags of one team subcommand; tests
// register them on a fresh command.
func registerHubTeamFlags(c *cobra.Command, kind string) {
	c.Flags().String("workdir", "", "hub directory holding .cloop/state.db (default: current directory)")
	switch kind {
	case "list", "show":
		c.Flags().Bool("json", false, "emit JSON for scripting")
	case "create", "update":
		c.Flags().String("name", "", "how the team is shown (default: its slug)")
		c.Flags().String("description", "", "what the team is for")
		c.Flags().String("idp-group", "", "everyone whose ID token carries this group claim value is on the team")
		c.Flags().String("scim-group", "", "everyone provisioned into this SCIM group is on the team")
		c.Flags().String("reason", "", "why (required; recorded in the audit trail)")
	default:
		c.Flags().String("reason", "", "why (required; recorded in the audit trail)")
	}
}

func init() {
	for c, kind := range map[*cobra.Command]string{
		hubTeamListCmd: "list", hubTeamShowCmd: "show", hubTeamCreateCmd: "create", hubTeamUpdateCmd: "update",
		hubTeamDeleteCmd: "delete", hubTeamAddCmd: "add", hubTeamRemoveCmd: "remove",
	} {
		registerHubTeamFlags(c, kind)
	}
	hubTeamCmd.AddCommand(hubTeamListCmd, hubTeamShowCmd, hubTeamCreateCmd, hubTeamUpdateCmd,
		hubTeamDeleteCmd, hubTeamAddCmd, hubTeamRemoveCmd)
	hubCmd.AddCommand(hubTeamCmd)
}
