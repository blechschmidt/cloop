package cmd

// `cloop project members` — who besides its owner may reach a project on a hub
// with single sign-on (Task 20366), for administration without a browser.
//
// The dashboard's Members card is the everyday surface, and it enforces the
// rules a browser session needs: the granter must hold project.share on the
// project and may not grant above their own role. This command is the
// operator's: it writes the hub's control-plane database directly, like the
// rest of `cloop hub`, so it works when the listener does not — and whoever can
// run it can already write that database, so it checks no role.
//
// Each change commits together with its audit row (project.member.*, via
// "cli"), and is then announced on the hub cluster's bus, so every running hub
// process applies it — and closes a removed member's open dashboard streams —
// within a poll interval rather than at its next refresh.

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"github.com/blechschmidt/cloop/pkg/auditaction"
	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/feature"
	"github.com/blechschmidt/cloop/pkg/multiui"
	"github.com/blechschmidt/cloop/pkg/projectmember"
	"github.com/blechschmidt/cloop/pkg/statedb"
	"github.com/blechschmidt/cloop/pkg/ui"
)

var projectCmd = &cobra.Command{
	Use:   "project",
	Short: "Administer projects on a hub: who may reach them",
	Long: `Administer the projects a hub serves.

  cloop project members list [<project>]
  cloop project members add <project> <identity> --role operator --reason "..."
  cloop project members remove <project> <identity> --reason "..."

Run it from the hub's directory, or pass --workdir.`,
}

var projectMembersCmd = &cobra.Command{
	Use:   "members",
	Short: "List, add and remove the identities a project is shared with",
	Long: `A project on a hub with single sign-on is visible to its owner and the hub's
admins. A member is one more identity admitted to it, at a role:

  viewer      read the project
  operator    also start and stop runs and change tasks
  maintainer  also reshape the project and change its members
  admin       everything

A membership only adds access. The hub unions its role with whatever the
identity already holds, so sharing a project at viewer never demotes an
operator. On a hub without role mappings (admin_emails alone) a member's role
is their whole authority on the project, while its owner and the hub's admins
keep full access.

<project> is a registered project's name or its directory. A feature is shared
with its project and has no members of its own. <identity> is the member's
email, or "sub:<subject>" when the identity provider releases no email.`,
}

var projectMembersListCmd = &cobra.Command{
	Use:   "list [<project>]",
	Short: "List a project's members, or every membership on the hub",
	Args:  cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		workdir, _ := cmd.Flags().GetString("workdir")
		asJSON, _ := cmd.Flags().GetBool("json")
		db, closer, err := openHubDB(workdir)
		if err != nil {
			return err
		}
		defer closer()
		store, err := projectmember.New(db)
		if err != nil {
			return err
		}
		members := store.All()
		owner := ""
		if len(args) == 1 {
			p, err := resolveHubProject(workdir, args[0], false)
			if err != nil {
				return err
			}
			members, owner = store.MembersOf(p.Path), p.Owner
		}
		if asJSON {
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			out := map[string]any{"members": nonNilMembers(members)}
			if len(args) == 1 {
				out["owner"] = owner
			}
			return enc.Encode(out)
		}
		if owner != "" {
			fmt.Printf("owner: %s\n", owner)
		}
		if len(members) == 0 {
			fmt.Println("No memberships.")
			return nil
		}
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "PROJECT\tIDENTITY\tROLE\tGRANTED\tBY\tREASON")
		for _, m := range members {
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n", m.ProjectPath, m.IdentityKey, m.Role,
				m.GrantedAt.Local().Format("2006-01-02 15:04"), m.GrantedBy, truncateField(m.Reason, 40))
		}
		return w.Flush()
	},
}

var projectMembersAddCmd = &cobra.Command{
	Use:   "add <project> <identity>",
	Short: "Admit an identity to a project at a role, or change its role",
	Args:  cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		workdir, _ := cmd.Flags().GetString("workdir")
		roleFlag, _ := cmd.Flags().GetString("role")
		reason, err := requireReason(mustString(cmd, "reason"))
		if err != nil {
			return err
		}
		role, err := projectmember.ParseGrantableRole(roleFlag)
		if err != nil {
			return plainMemberError(err)
		}
		key, err := projectmember.ParseKey(args[1])
		if err != nil {
			return plainMemberError(err)
		}
		warnIfNotAHub(workdir)
		warnIfNoSingleSignOn(workdir)
		p, err := resolveHubProject(workdir, args[0], true)
		if err != nil {
			return err
		}
		if p.Owner == "" {
			fmt.Fprintln(os.Stderr, "note: this project has no owner, so on a hub without role mappings every\n"+
				"      signed-in user already reaches it and this membership adds nothing there.")
		} else if strings.EqualFold(p.Owner, key) {
			fmt.Fprintln(os.Stderr, "note: that identity owns this project.")
		}

		db, closer, err := openHubDB(workdir)
		if err != nil {
			return err
		}
		defer closer()
		store, err := projectmember.New(db.AsControlPlane())
		if err != nil {
			return err
		}
		stored, prev, err := store.Grant(projectmember.Member{
			ProjectPath: p.Path, IdentityKey: key, Role: role, Reason: reason, GrantedBy: operatorActor(),
		}, cliMemberAudit(p, reason, ""))
		if err != nil {
			return err
		}
		if prev == nil {
			color.New(color.FgGreen).Printf("Added %s to %s as %s.\n", stored.IdentityKey, p.Name, stored.Role)
		} else {
			color.New(color.FgGreen).Printf("Changed %s on %s from %s to %s.\n", stored.IdentityKey, p.Name, prev.Role, stored.Role)
		}
		announceMembershipChange(db, p.Path)
		return nil
	},
}

var projectMembersRemoveCmd = &cobra.Command{
	Use:   "remove <project> <identity>",
	Short: "Remove an identity from a project",
	Args:  cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		workdir, _ := cmd.Flags().GetString("workdir")
		reason, err := requireReason(mustString(cmd, "reason"))
		if err != nil {
			return err
		}
		key := projectmember.NormalizeKey(args[1])
		if key == "" {
			return fmt.Errorf("an identity is required")
		}
		// An unregistered path is accepted here: removing a stale grant must
		// work after its project is gone.
		p, err := resolveHubProject(workdir, args[0], false)
		if err != nil {
			return err
		}
		db, closer, err := openHubDB(workdir)
		if err != nil {
			return err
		}
		defer closer()
		store, err := projectmember.New(db.AsControlPlane())
		if err != nil {
			return err
		}
		removed, err := store.Revoke(p.Path, key, cliMemberAudit(p, reason, auditaction.ActionProjectMemberRevoke))
		if err != nil {
			return err
		}
		if removed == nil {
			return fmt.Errorf("%s is not a member of %s", key, p.Path)
		}
		color.New(color.FgGreen).Printf("Removed %s (%s) from %s.\n", removed.IdentityKey, removed.Role, p.Name)
		announceMembershipChange(db, p.Path)
		return nil
	},
}

// hubProject is a project as the CLI resolved it.
type hubProject struct {
	Name, Path, Owner string
}

// resolveHubProject finds a project by registry name or by directory. With
// registered, a directory the hub does not serve is refused: a membership of a
// path nobody registered would wait there and admit its member to whatever is
// registered at that path later.
func resolveHubProject(workdir, arg string, registered bool) (hubProject, error) {
	arg = strings.TrimSpace(arg)
	if arg == "" {
		return hubProject{}, fmt.Errorf("a project name or directory is required")
	}
	hub := workdir
	if hub == "" {
		if wd, err := os.Getwd(); err == nil {
			hub = wd
		}
	}
	hubAbs, _ := filepath.Abs(hub)
	entries, _ := multiui.Load()
	candidates := []hubProject{{Name: filepath.Base(hubAbs), Path: hubAbs}}
	for _, e := range entries {
		abs, err := filepath.Abs(e.Path)
		if err != nil {
			continue
		}
		name := e.Name
		if name == "" {
			name = filepath.Base(abs)
		}
		candidates = append(candidates, hubProject{Name: name, Path: abs, Owner: e.Owner})
	}

	var path string
	if st, err := os.Stat(arg); err == nil && st.IsDir() {
		path = projectmember.NormalizePath(arg)
	}
	var match []hubProject
	for _, c := range candidates {
		if (path != "" && c.Path == path) || (path == "" && strings.EqualFold(c.Name, arg)) {
			match = append(match, c)
		}
	}
	if path != "" {
		if parent, slug, ok := feature.ParentOf(path); ok {
			return hubProject{}, fmt.Errorf("%s is feature %q of %s, which is shared with its project — "+
				"give the project instead", path, slug, parent)
		}
	}
	switch {
	case len(match) == 1:
		return match[0], nil
	case len(match) > 1 && path == "":
		return hubProject{}, fmt.Errorf("%d projects are named %q — give its directory instead", len(match), arg)
	case len(match) > 1:
		return match[0], nil
	}
	if path == "" {
		if !registered {
			// A name that is not registered may still be a path whose
			// directory is gone; remove takes it literally.
			return hubProject{Name: arg, Path: projectmember.NormalizePath(arg)}, nil
		}
		return hubProject{}, fmt.Errorf("no project named %q is registered on this hub", arg)
	}
	if registered {
		return hubProject{}, fmt.Errorf("%s is not a project this hub serves — register it first", path)
	}
	return hubProject{Name: filepath.Base(path), Path: path}, nil
}

// cliMemberAudit builds the audit row a CLI change commits with.
func cliMemberAudit(p hubProject, reason string, force auditaction.Action) projectmember.Audit {
	actor := operatorActor()
	return func(prev, next *projectmember.Member) ([]*statedb.AuditEvent, error) {
		action, m := force, next
		payload := map[string]any{"project": p.Name, "project_path": p.Path, "via": "cli",
			"reason": reason, "os_user": actor}
		switch {
		case next == nil && prev != nil:
			m = prev
			if action == "" {
				action = auditaction.ActionProjectMemberRevoke
			}
		case prev == nil:
			action = auditaction.ActionProjectMemberGrant
		default:
			action = auditaction.ActionProjectMemberChange
			payload["previous_role"] = string(prev.Role)
		}
		if m == nil {
			return nil, nil
		}
		payload["identity"] = m.IdentityKey
		payload["role"] = string(m.Role)
		blob, err := json.Marshal(payload)
		if err != nil {
			return nil, err
		}
		return []*statedb.AuditEvent{{
			Timestamp:  time.Now().UTC(),
			Actor:      actor,
			EventType:  string(action),
			EntityType: "project_member",
			EntityID:   m.ProjectPath + "|" + m.IdentityKey,
			Payload:    string(blob),
		}}, nil
	}
}

// announceMembershipChange tells running hub processes to apply the change
// now. A failure only delays it to their next refresh, so it is a warning.
func announceMembershipChange(db *statedb.DB, path string) {
	origin := fmt.Sprintf("cli-%d", os.Getpid())
	if err := ui.AnnounceMembershipChange(db, origin, path); err != nil {
		fmt.Fprintf(os.Stderr, "warning: could not notify running hubs (%v); they apply the change within %s\n",
			err, projectmember.DefaultTTL)
		return
	}
	color.New(color.Faint).Println("Running hub processes apply this at once, and close a removed member's open dashboards.")
}

// warnIfNoSingleSignOn reports that memberships name signed-in identities, so
// a hub without single sign-on — in config.yaml or in any hub's overlay —
// has nobody for them to match.
func warnIfNoSingleSignOn(workdir string) {
	if workdir == "" {
		wd, err := os.Getwd()
		if err != nil {
			return
		}
		workdir = wd
	}
	if cfg, err := config.Load(workdir); err == nil && cfg.UI.OIDC.Enabled {
		return
	}
	ports, _ := config.UIInstancePorts(workdir)
	for _, port := range ports {
		if cfg, _, err := config.LoadUIInstance(workdir, port); err == nil && cfg.UI.OIDC.Enabled {
			return
		}
	}
	fmt.Fprintln(os.Stderr,
		"warning: no hub in this directory has single sign-on configured (ui.oidc.enabled),\n"+
			"         so there is no signed-in identity this membership can match yet.")
}

func nonNilMembers(m []projectmember.Member) []projectmember.Member {
	if m == nil {
		return []projectmember.Member{}
	}
	return m
}

// plainMemberError drops the package prefix from a validation error, which is
// addressed to whoever typed the arguments.
func plainMemberError(err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%s", strings.TrimPrefix(err.Error(), "projectmember: "))
}

func mustString(cmd *cobra.Command, name string) string {
	v, _ := cmd.Flags().GetString(name)
	return v
}

// registerProjectMemberFlags declares the flags of one members subcommand
// ("list", "add" or "remove"); tests register them on a fresh command.
func registerProjectMemberFlags(c *cobra.Command, kind string) {
	c.Flags().String("workdir", "", "hub directory holding .cloop/state.db (default: current directory)")
	switch kind {
	case "list":
		c.Flags().Bool("json", false, "emit JSON for scripting")
	case "add":
		c.Flags().String("role", "viewer", "viewer, operator, maintainer or admin")
		c.Flags().String("reason", "", "why (required; stored with the membership and in the audit trail)")
	case "remove":
		c.Flags().String("reason", "", "why (required; recorded in the audit trail)")
	}
}

func init() {
	registerProjectMemberFlags(projectMembersListCmd, "list")
	registerProjectMemberFlags(projectMembersAddCmd, "add")
	registerProjectMemberFlags(projectMembersRemoveCmd, "remove")

	projectMembersCmd.AddCommand(projectMembersListCmd, projectMembersAddCmd, projectMembersRemoveCmd)
	projectCmd.AddCommand(projectMembersCmd)
	rootCmd.AddCommand(projectCmd)
}
