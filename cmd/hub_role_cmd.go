package cmd

// `cloop hub role` — granting and, more to the point, withdrawing authority
// without a redeploy (Task 20248).
//
// This is the one command in the incident-response set with no REST
// counterpart, because until now there was nothing to expose: role bindings
// came only from oidc.role_mappings and oidc.admin_emails, which pkg/authz
// turns into bindings at startup. Demoting a compromised administrator meant
// editing config and redeploying — minutes at best, and needing whoever holds
// the deployment pipeline rather than whoever is watching the account being
// used.
//
// Writes go to the role_bindings table, which the hub reads through a
// TTL-cached source on every authorization decision. So a demotion lands on a
// live hub within rolestore.DefaultTTL and no lease is taken; see the lease
// rule in hub_admin.go.
//
// # Precedence
//
// Deny wins, and the database overrides config. A deny binding beats every
// other binding at every specificity, including the global admin binding that
// oidc.admin_emails produces — which is exactly what makes `role revoke` an
// emergency demotion rather than a suggestion. authz.Resolve states the rule
// in full and TestRuntimeDenyOverridesAdminEmails pins it.

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"github.com/blechschmidt/cloop/pkg/auditaction"
	"github.com/blechschmidt/cloop/pkg/authz"
	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/rolestore"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

var hubRoleCmd = &cobra.Command{
	Use:   "role",
	Short: "Grant or withdraw a role at runtime, without editing config",
	Long: `Edit the runtime role bindings that layer over ui.oidc in .cloop/config.yaml.

Configured bindings are policy: reviewed, diffed, deployed. These are the
exception — written in one command during an incident, and taken back the same
way.

  cloop hub role list                              what is in force
  cloop hub role grant  email alice@x.io --role viewer --reason "..."
  cloop hub role revoke email alice@x.io --reason "..."   deny, immediately
  cloop hub role delete rb_1a2b3c4d5e6f --reason "..."    undo either

Precedence is fixed and deliberately blunt: a deny beats every other binding,
including an oidc.admin_emails entry, and any runtime binding beats the
configured ones. Narrow a binding with --project or --executor when you mean to
withdraw authority somewhere rather than everywhere.

Note that ` + "`revoke`" + ` *writes* a deny rather than deleting a grant, so it works
against authority this table never issued — which is the case that matters.
Use ` + "`delete`" + ` to remove a binding row.`,
}

var hubRoleListCmd = &cobra.Command{
	Use:   "list",
	Short: "Show runtime role bindings, and the configured ones they layer over",
	Long: `List the bindings in force.

Runtime bindings come from the hub's database and are shown with their ids.
Configured bindings come from ui.oidc in .cloop/config.yaml and are shown for
context: they are what a runtime binding is overriding, and an operator asking
"why is this person still an admin" needs to see both.

--identity narrows to the bindings naming one email address or subject, and
reports whether that identity currently holds a deny. Group and role bindings
are not matched: which groups an identity carries comes from the token the
identity provider issues, which a shell command cannot see.`,
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		workdir, _ := cmd.Flags().GetString("workdir")
		identity, _ := cmd.Flags().GetString("identity")
		asJSON, _ := cmd.Flags().GetBool("json")

		db, closer, err := openHubDB(workdir)
		if err != nil {
			return err
		}
		defer closer()
		rows, err := db.ListRoleBindings()
		if err != nil {
			return err
		}
		rows = filterRoleBindings(rows, identity)

		configured := configuredBindings(workdir)
		if asJSON {
			return json.NewEncoder(os.Stdout).Encode(map[string]any{
				"runtime":    roleRowsToJSON(rows),
				"configured": configuredBindingsToJSON(configured, identity),
			})
		}

		bold := color.New(color.Bold)
		dim := color.New(color.Faint)

		bold.Println("Runtime bindings (this database)")
		if len(rows) == 0 {
			dim.Println("  none")
		} else {
			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "  ID\tEFFECT\tCLAIM\tVALUE\tROLE\tSCOPE\tBY\tREASON")
			for _, r := range rows {
				role := r.Role
				if strings.EqualFold(r.Effect, statedb.RoleEffectDeny) {
					role = "-"
				}
				fmt.Fprintf(w, "  %s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
					r.ID, r.Effect, r.Claim, truncateField(r.Value, 30), role,
					roleScopeLabel(r.Project, r.Executor),
					truncateField(orDash(r.CreatedBy), 20),
					truncateField(orDash(r.Reason), 40))
			}
			if err := w.Flush(); err != nil {
				return err
			}
		}

		fmt.Println()
		bold.Println("Configured bindings (.cloop/config.yaml)")
		shown := configuredBindingsToJSON(configured, identity)
		if len(shown) == 0 {
			dim.Println("  none")
		} else {
			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "  SOURCE\tCLAIM\tVALUE\tROLE\tSCOPE")
			for _, b := range shown {
				fmt.Fprintf(w, "  %s\t%s\t%s\t%s\t%s\n",
					b["source"], b["claim"], truncateField(fmt.Sprint(b["value"]), 30),
					b["role"], b["scope"])
			}
			if err := w.Flush(); err != nil {
				return err
			}
		}

		if identity != "" {
			fmt.Println()
			if denied := denyFor(rows, identity); denied != nil {
				color.New(color.FgRed).Printf(
					"%s is DENIED by %s%s — every request resolves to no permissions.\n",
					identity, denied.ID, roleScopeSuffix(denied.Project, denied.Executor))
			} else {
				dim.Printf("%s holds no runtime deny binding.\n", identity)
			}
		}
		return nil
	},
}

var hubRoleGrantCmd = &cobra.Command{
	Use:   "grant <claim> <value>",
	Short: "Grant a role at runtime, overriding the configured bindings",
	Long: `Write a runtime binding that grants a role.

<claim> is one of: ` + claimKindNames() + `. <value> is the claim value — an email
address, an IdP subject, a group name, or a role name as the provider releases
it. Leading "/" on a group path is optional; Keycloak's "/cloop-admins" and
"cloop-admins" are the same binding.

A runtime grant beats every configured binding for the identities it matches,
so it is also how you *narrow* somebody without editing config: granting viewer
overrides a role_mapping that gave them maintainer. It does not beat a deny.

Writing the same claim, value and scope twice replaces the binding rather than
adding a second one, so repeating a command under pressure is safe.

Examples:

  # Someone needs maintainer on one project for the duration of an incident
  cloop hub role grant email bob@example.com --role maintainer --project payments --reason "INC-4414 bridge"

  # Hold a whole group down to read-only during a change freeze
  cloop hub role grant group contractors --role viewer --reason "change freeze until 2026-10-01"`,
	Args: cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		role, _ := cmd.Flags().GetString("role")
		if strings.TrimSpace(role) == "" {
			return fmt.Errorf("--role is required (one of: %s)", roleNamesForHelp())
		}
		return writeRoleBinding(cmd, args[0], args[1], role, false)
	},
}

var hubRoleRevokeCmd = &cobra.Command{
	Use:   "revoke <claim> <value>",
	Short: "Deny an identity outright — the emergency demotion",
	Long: `Write a runtime deny binding.

This is the lever for a compromised or misbehaving account. A deny beats every
other binding that applies, at every specificity, including the global admin
binding produced by oidc.admin_emails — so it demotes an administrator whose
address is in a config file this command never touches, and it does so without
a redeploy.

It writes a row rather than removing one, which is what lets it work against
authority granted somewhere else. To undo it, ` + "`cloop hub role delete <id>`" + `.

Scope it when you mean to. With neither --project nor --executor the deny is
global and the identity can do nothing anywhere. With --project it withdraws
authority on that project alone and leaves the rest intact.

A deny stops a session from *acting*; it does not end it. During a compromise
run ` + "`cloop hub session revoke --identity`" + ` and ` + "`cloop hub token revoke`" + ` too —
docs/operations/runbook.md has the full sequence.

Examples:

  cloop hub role revoke email alice@example.com --reason "credential compromise INC-4412"
  cloop hub role revoke sub 8f14e45fce --reason "offboarded, IdP entry not yet removed"
  cloop hub role revoke email contractor@example.com --project payments --reason "scope reduction"`,
	Args: cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		return writeRoleBinding(cmd, args[0], args[1], string(authz.RoleNone), true)
	},
}

var hubRoleDeleteCmd = &cobra.Command{
	Use:   "delete <id>",
	Short: "Remove a runtime binding, reverting to the configured policy",
	Long: `Delete a runtime binding row by id, as shown by ` + "`cloop hub role list`" + `.

Deleting a deny restores whatever remains in force for that identity. Usually
that is the configured policy — for an oidc.admin_emails entry, admin again —
but not always: if a runtime *grant* for the same scope is also stored, that
grant takes over instead, because a runtime binding shuts the configured layer
out. ` + "`cloop hub role list --identity <who>`" + ` shows both before you decide.

This is the only way back from a deny, on purpose: reinstating authority should
name the binding being removed rather than being a side effect of a command
that looks like it grants something small.`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		workdir, _ := cmd.Flags().GetString("workdir")
		rawReason, _ := cmd.Flags().GetString("reason")

		reason, err := requireReason(rawReason)
		if err != nil {
			return err
		}
		warnIfNotAHub(workdir)
		db, closer, err := openHubDB(workdir)
		if err != nil {
			return err
		}
		defer closer()

		id := strings.TrimSpace(args[0])
		row, err := db.GetRoleBinding(id)
		if err != nil {
			if errors.Is(err, statedb.ErrRoleBindingNotFound) {
				return fmt.Errorf("no runtime binding %q — see `cloop hub role list`", id)
			}
			return err
		}
		if err := auditHubAdmin(db, auditaction.ActionRoleBindingDeleted, "role_binding", row.ID, reason,
			roleBindingPayload(row)); err != nil {
			return err
		}
		if _, err := db.DeleteRoleBinding(row.ID); err != nil {
			return err
		}

		color.New(color.FgGreen).Printf("Deleted runtime binding %s (%s %s=%s).\n",
			row.ID, row.Effect, row.Claim, row.Value)
		if strings.EqualFold(row.Effect, statedb.RoleEffectDeny) {
			// Which authority comes back depends on whether a runtime grant
			// for the same scope survives the deletion, because a runtime
			// binding shuts the configured layer out entirely. Saying
			// "configured policy" unconditionally would be wrong exactly when
			// somebody is checking what they just reinstated.
			if grant, ok := lookupCounterpartBinding(db, row); ok {
				color.New(color.FgYellow).Printf(
					"%s is no longer denied and now resolves to %s from runtime binding %s.\n",
					row.Value, grant.Role, grant.ID)
			} else {
				color.New(color.FgYellow).Printf(
					"%s is no longer denied and resolves from the configured policy again.\n", row.Value)
			}
		}
		printRolePropagationNote()
		return nil
	},
}

// ---------------------------------------------------------------------------
// shared write path
// ---------------------------------------------------------------------------

// writeRoleBinding is the common body of grant and revoke: they differ only in
// the effect and in what is printed, and sharing the path is what keeps a deny
// from being validated or stored any differently from a grant.
func writeRoleBinding(cmd *cobra.Command, claim, value, role string, deny bool) error {
	workdir, _ := cmd.Flags().GetString("workdir")
	project, _ := cmd.Flags().GetString("project")
	executor, _ := cmd.Flags().GetString("executor")
	rawReason, _ := cmd.Flags().GetString("reason")

	reason, err := requireReason(rawReason)
	if err != nil {
		return err
	}
	// Normalize through pkg/authz, which is the one definition of what a
	// binding is and when two are the same. A claim kind or role this build
	// does not know is rejected here rather than stored as a row that matches
	// nothing — the worst outcome for a deny, since it reports success and
	// withdraws nothing.
	binding, err := authz.NormalizeBinding(authz.Binding{
		Claim:    authz.ClaimKind(claim),
		Value:    value,
		Role:     authz.Role(role),
		Project:  project,
		Executor: executor,
		Deny:     deny,
	})
	if err != nil {
		return fmt.Errorf("invalid binding: %w", err)
	}
	row, err := rolestore.RowFor(binding, reason, operatorActor(), time.Now().UTC())
	if err != nil {
		return err
	}

	warnIfNotAHub(workdir)
	warnIfNoIdentityProvider(workdir)
	db, closer, err := openHubDB(workdir)
	if err != nil {
		return err
	}
	defer closer()

	eventType := auditaction.ActionRoleBindingGranted
	if deny {
		eventType = auditaction.ActionRoleBindingDenied
	}
	// Audit first, mutate second: an unrecorded change to who may act is an
	// authority change with nothing to review, and re-running the command is
	// cheap. The id is derived from the tuple, so it is known before the write.
	row.ID = statedb.RoleBindingID(row.Effect, row.Claim, row.Value, row.Project, row.Executor)
	if err := auditHubAdmin(db, eventType, "role_binding", row.ID, reason,
		roleBindingPayload(row)); err != nil {
		return err
	}
	stored, err := db.PutRoleBinding(row)
	if err != nil {
		return err
	}

	// The row's identity includes its effect, so a grant and a deny for the
	// same claim, value and scope are two rows that coexist. That is correct —
	// the deny still wins — but it makes each command's confirmation only half
	// the story, and the missing half is the one that decides the outcome. So
	// the counterpart is looked up and named. Its id is derivable, so this is
	// one indexed read, and a failure to find it is simply "there isn't one".
	counterpart, hasCounterpart := lookupCounterpartBinding(db, stored)

	if deny {
		color.New(color.FgRed, color.Bold).Printf("DENIED %s=%s%s\n",
			stored.Claim, stored.Value, roleScopeSuffix(stored.Project, stored.Executor))
		fmt.Printf("  binding  %s\n", stored.ID)
		color.New(color.Faint).Println(
			"  This outranks every other binding, including oidc.admin_emails.\n" +
				"  Undo with `cloop hub role delete " + stored.ID + "`.")
		if hasCounterpart {
			color.New(color.Faint).Printf(
				"  A runtime grant of %s for the same scope (%s) is still stored and is\n"+
					"  now inert. Removing this deny reinstates it, not the configured policy.\n",
				counterpart.Role, counterpart.ID)
		}
		color.New(color.FgYellow).Println(
			"\nA deny stops them acting; it does not end their sessions or revoke their\n" +
				"tokens. For a compromise, also run:\n" +
				"  cloop hub session revoke --identity " + stored.Value + " --reason \"...\"\n" +
				"  cloop hub token list   # then revoke anything they hold")
	} else {
		color.New(color.FgGreen).Printf("Granted %s to %s=%s%s\n",
			stored.Role, stored.Claim, stored.Value,
			roleScopeSuffix(stored.Project, stored.Executor))
		fmt.Printf("  binding  %s\n", stored.ID)
		if hasCounterpart {
			// The case that would otherwise send an operator away believing
			// they had restored somebody: grant is the natural inverse to
			// reach for, and against a live deny it does nothing at all.
			color.New(color.FgYellow).Printf(
				"\nThis grant is INERT: a deny binding (%s) covers the same scope and\n"+
					"outranks it. To restore access, remove the deny:\n"+
					"  cloop hub role delete %s --reason \"...\"\n",
				counterpart.ID, counterpart.ID)
		}
	}
	printRolePropagationNote()
	return nil
}

// warnIfNoIdentityProvider reports that a binding cannot bite on a hub with no
// SSO configured.
//
// Bindings resolve against claims from a validated ID token, so with
// ui.oidc.enabled false there are no identities for one to name — the hub does
// not even open the binding table. That is correct behaviour and a misleading
// success message: `revoke` otherwise prints a red DENIED and "a running hub
// picks this up within 10s" for a row nothing will ever read. The same class of
// silent no-op warnIfNotAHub covers, from the other direction.
func warnIfNoIdentityProvider(workdir string) {
	cfg := configuredBindings(workdir)
	if cfg == nil || cfg.Enabled {
		return
	}
	fmt.Fprintln(os.Stderr,
		"warning: this hub has no identity provider configured (ui.oidc.enabled is false),\n"+
			"         so every request is already granted everything and role bindings are\n"+
			"         inert. This row will take effect if SSO is turned on later.")
}

// lookupCounterpartBinding returns the stored binding with the opposite effect
// on the same claim, value and scope.
func lookupCounterpartBinding(db *statedb.DB, row statedb.RoleBindingRow) (statedb.RoleBindingRow, bool) {
	other := statedb.RoleEffectDeny
	if strings.EqualFold(row.Effect, statedb.RoleEffectDeny) {
		other = statedb.RoleEffectAllow
	}
	found, err := db.GetRoleBinding(
		statedb.RoleBindingID(other, row.Claim, row.Value, row.Project, row.Executor))
	if err != nil {
		return statedb.RoleBindingRow{}, false
	}
	return found, true
}

func printRolePropagationNote() {
	color.New(color.Faint).Printf(
		"\nA running hub picks this up within %s. No restart needed.\n", rolestore.DefaultTTL)
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

// filterRoleBindings narrows rows to those naming one identity.
//
// Only email and sub bindings are considered. A group binding may well govern
// the identity, but whether it does depends on the claims their provider
// releases, and guessing would mean showing bindings that do not apply — or
// worse, reporting "no deny" when a group deny is in force. The help text says
// so rather than the filter pretending otherwise.
func filterRoleBindings(rows []statedb.RoleBindingRow, identity string) []statedb.RoleBindingRow {
	identity = strings.TrimSpace(identity)
	if identity == "" {
		return rows
	}
	out := make([]statedb.RoleBindingRow, 0, len(rows))
	for _, r := range rows {
		switch authz.ClaimKind(r.Claim) {
		case authz.ClaimEmail:
			if strings.EqualFold(r.Value, identity) {
				out = append(out, r)
			}
		case authz.ClaimSub:
			if r.Value == identity {
				out = append(out, r)
			}
		}
	}
	return out
}

// denyFor returns the global deny covering identity, if any.
//
// Global only: a project-scoped deny withdraws authority there and nowhere
// else, so reporting it as "DENIED" without qualification would overstate what
// happened and could stop an operator escalating when they still need to.
func denyFor(rows []statedb.RoleBindingRow, identity string) *statedb.RoleBindingRow {
	for i := range rows {
		r := rows[i]
		if !strings.EqualFold(r.Effect, statedb.RoleEffectDeny) {
			continue
		}
		if r.Project != "" || r.Executor != "" {
			continue
		}
		return &rows[i]
	}
	return nil
}

// configuredBindings reads ui.oidc from config for display.
//
// Best-effort: an unreadable config file means the configured half of the
// listing is empty, which is a worse answer than the truth but a much better
// one than refusing to show the runtime bindings at all — those are the ones
// somebody is mid-incident about.
func configuredBindings(workdir string) *config.OIDCConfig {
	if workdir == "" {
		wd, err := os.Getwd()
		if err != nil {
			return nil
		}
		workdir = wd
	}
	cfg, err := config.Load(workdir)
	if err != nil || cfg == nil {
		return nil
	}
	return &cfg.UI.OIDC
}

func configuredBindingsToJSON(cfg *config.OIDCConfig, identity string) []map[string]any {
	if cfg == nil {
		return nil
	}
	out := make([]map[string]any, 0, len(cfg.RoleMappings)+len(cfg.AdminEmails))
	for _, email := range cfg.AdminEmails {
		email = strings.TrimSpace(email)
		if email == "" {
			continue
		}
		if identity != "" && !strings.EqualFold(email, identity) {
			continue
		}
		out = append(out, map[string]any{
			"source": "admin_emails",
			"claim":  string(authz.ClaimEmail),
			"value":  email,
			"role":   string(authz.RoleAdmin),
			"scope":  roleScopeLabel("", ""),
		})
	}
	for _, m := range cfg.RoleMappings {
		if identity != "" && !matchesConfiguredIdentity(m, identity) {
			continue
		}
		out = append(out, map[string]any{
			"source": "role_mappings",
			"claim":  m.Claim,
			"value":  m.Value,
			"role":   m.Role,
			"scope":  roleScopeLabel(m.Project, m.Executor),
		})
	}
	return out
}

// matchesConfiguredIdentity mirrors filterRoleBindings: email and sub only,
// for the same reason.
func matchesConfiguredIdentity(m config.RoleMapping, identity string) bool {
	switch authz.ClaimKind(strings.ToLower(strings.TrimSpace(m.Claim))) {
	case authz.ClaimEmail:
		return strings.EqualFold(strings.TrimSpace(m.Value), identity)
	case authz.ClaimSub:
		return strings.TrimSpace(m.Value) == identity
	}
	return false
}

func roleRowsToJSON(rows []statedb.RoleBindingRow) []map[string]any {
	out := make([]map[string]any, 0, len(rows))
	for _, r := range rows {
		out = append(out, roleBindingPayload(r))
	}
	return out
}

func roleBindingPayload(r statedb.RoleBindingRow) map[string]any {
	return map[string]any{
		"id":             r.ID,
		"effect":         r.Effect,
		"claim":          r.Claim,
		"value":          r.Value,
		"role":           r.Role,
		"project":        r.Project,
		"executor":       r.Executor,
		"binding_reason": r.Reason,
		"created_at":     r.CreatedAt.UTC().Format(time.RFC3339),
		"created_by":     r.CreatedBy,
	}
}

func roleScopeLabel(project, executor string) string {
	var parts []string
	if project != "" {
		parts = append(parts, "project="+project)
	}
	if executor != "" {
		parts = append(parts, "executor="+executor)
	}
	if len(parts) == 0 {
		return "(global)"
	}
	return strings.Join(parts, " ")
}

func roleScopeSuffix(project, executor string) string {
	if project == "" && executor == "" {
		return " (everywhere)"
	}
	return " on " + roleScopeLabel(project, executor)
}

func claimKindNames() string {
	names := make([]string, len(authz.AllClaimKinds))
	for i, c := range authz.AllClaimKinds {
		names[i] = string(c)
	}
	return strings.Join(names, ", ")
}

func roleNamesForHelp() string {
	names := make([]string, 0, len(authz.AllRoles))
	for _, r := range authz.AllRoles {
		names = append(names, string(r))
	}
	return strings.Join(names, ", ")
}

// registerHubRoleFlags declares the flags each role subcommand reads.
//
// Separate from init() so tests can build a fresh command around the same RunE
// rather than reusing the package-level one, whose flag values cobra keeps
// between invocations — the same reason registerHubBootstrapFlags exists.
func registerHubRoleFlags(c *cobra.Command, kind string) {
	c.Flags().String("workdir", "", "hub directory holding .cloop/state.db (default: current directory)")
	switch kind {
	case "list":
		c.Flags().String("identity", "", "narrow to bindings naming this email address or IdP subject")
		c.Flags().Bool("json", false, "emit JSON for scripting")
		return
	case "grant":
		c.Flags().String("role", "", "role to grant: "+roleNamesForHelp())
		fallthrough
	case "revoke":
		c.Flags().String("project", "", "narrow the binding to one project (registry name or path)")
		c.Flags().String("executor", "", "narrow the binding to one executor ID")
	}
	c.Flags().String("reason", "", "why (required; recorded in the audit trail)")
}

func init() {
	registerHubRoleFlags(hubRoleListCmd, "list")
	registerHubRoleFlags(hubRoleGrantCmd, "grant")
	registerHubRoleFlags(hubRoleRevokeCmd, "revoke")
	registerHubRoleFlags(hubRoleDeleteCmd, "delete")

	hubRoleCmd.AddCommand(hubRoleListCmd)
	hubRoleCmd.AddCommand(hubRoleGrantCmd)
	hubRoleCmd.AddCommand(hubRoleRevokeCmd)
	hubRoleCmd.AddCommand(hubRoleDeleteCmd)
	hubCmd.AddCommand(hubRoleCmd)
}
