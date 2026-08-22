package hubdoctor

// Authorization checks: who can do what, and is there anybody who can fix it?
//
// The finding this file exists for is "no group maps to admin". A hub with
// deny-by-default RBAC and no admin binding is not broken in any way the
// software can notice — every request is authorized correctly, every denial is
// correct — and it is unusable, because the panels that manage executors,
// secrets, tokens and the audit trail require an admin and nobody is one. The
// operator's own sign-in succeeds and shows them an empty dashboard. There is
// no error to search for.
//
// The rest of the checks here are the cases where a policy is *stricter or
// looser than it reads*: a default_role of admin (everyone in the directory is
// an administrator the moment SSO is switched on), a binding on a claim the IdP
// does not emit, a mapping that duplicates another with a weaker role.

import (
	"fmt"
	"sort"
	"strings"

	"github.com/blechschmidt/cloop/pkg/authz"
	"github.com/blechschmidt/cloop/pkg/config"
)

func checkRBAC(cfg *config.Config, add addFn) {
	oc := cfg.UI.OIDC
	if !oc.Enabled {
		// Without OIDC there is one identity — the token holder — and role
		// mappings never run. Saying so is more useful than silence, because
		// a config with role_mappings and oidc.enabled=false looks governed
		// and is not.
		if len(oc.RoleMappings) > 0 || len(oc.AdminEmails) > 0 {
			add(Finding{
				Check: "rbac.policy", Title: "Role mappings", Severity: SeverityWarn,
				Message: fmt.Sprintf("%d role mapping(s) and %d admin email(s) are configured but "+
					"ui.oidc.enabled is false, so none of them are consulted",
					len(oc.RoleMappings), len(oc.AdminEmails)),
				Remediation: "Set ui.oidc.enabled: true, or remove the mappings to avoid implying they apply",
			})
		}
		return
	}

	bindings := bindingsFrom(oc.RoleMappings)
	resolver, err := authz.New(authz.Config{
		DefaultRole: authz.Role(oc.DefaultRole),
		Bindings:    bindings,
		AdminEmails: oc.AdminEmails,
	})
	if err != nil {
		// The hub refuses to start on this, so it is a hard failure and the
		// error text already names the offending value.
		add(Finding{
			Check: "rbac.policy", Title: "Role mappings", Severity: SeverityFail,
			Message:     "the policy is invalid and `cloop ui` will refuse to start: " + err.Error(),
			Remediation: "Fix the named value in ui.oidc.role_mappings; valid roles are " + rolesList(),
		})
		return
	}
	add(Finding{
		Check: "rbac.policy", Title: "Role mappings", Severity: SeverityPass,
		Message: fmt.Sprintf("%d mapping(s) parse, default role %q", len(bindings), effectiveDefault(oc.DefaultRole)),
	})

	checkDefaultRole(oc, add)
	checkAdminReachable(oc, bindings, add)
	checkMappingHygiene(oc, bindings, add)
	_ = resolver
}

// checkDefaultRole reports the blast radius of authenticating at all.
//
// default_role is the role every user in the directory receives before any
// binding is consulted. Set to anything above "none" it means "everyone my IdP
// knows about", which for a corporate IdP is the whole company; set to admin it
// means the whole company can revoke secrets and read the audit trail.
func checkDefaultRole(oc config.OIDCConfig, add addFn) {
	role := effectiveDefault(oc.DefaultRole)
	switch authz.Role(role) {
	case authz.RoleNone:
		add(Finding{
			Check: "rbac.default_role", Title: "Default role", Severity: SeverityPass,
			Message: `deny-by-default: a user matching no mapping gets "none"`,
		})
	case authz.RoleAdmin:
		add(Finding{
			Check: "rbac.default_role", Title: "Default role", Severity: SeverityFail,
			Message: "ui.oidc.default_role is admin: every identity the issuer will authenticate " +
				"becomes an administrator of this hub",
			Remediation: `Set ui.oidc.default_role: none and grant admin through an explicit role_mapping`,
		})
	default:
		add(Finding{
			Check: "rbac.default_role", Title: "Default role", Severity: SeverityWarn,
			Message: fmt.Sprintf("ui.oidc.default_role is %q, so every identity the issuer authenticates "+
				"gets that role without matching any mapping", role),
			Remediation: `Set ui.oidc.default_role: none unless every user of the issuer should have it`,
		})
	}
}

// checkAdminReachable is the "no group maps to admin" check.
func checkAdminReachable(oc config.OIDCConfig, bindings []authz.Binding, add addFn) {
	var routes []string
	for _, e := range oc.AdminEmails {
		if strings.TrimSpace(e) != "" {
			routes = append(routes, "admin_emails: "+e)
		}
	}
	for _, b := range bindings {
		if b.Role != authz.RoleAdmin {
			continue
		}
		// A project- or executor-scoped admin binding is admin *of that
		// thing*, not of the hub: it does not grant user management, token
		// administration or the audit trail. Counting it as an admin route
		// would produce a green line on a hub nobody can administer.
		if strings.TrimSpace(b.Project) != "" || strings.TrimSpace(b.Executor) != "" {
			continue
		}
		routes = append(routes, fmt.Sprintf("%s=%s", b.Claim, b.Value))
	}

	if len(routes) == 0 {
		add(Finding{
			Check: "rbac.admin", Title: "Administrator access", Severity: SeverityFail,
			Message: "no claim maps to the admin role and ui.oidc.admin_emails is empty: nobody can " +
				"manage executors, secrets, tokens or read the audit trail, and every request is " +
				"denied correctly",
			Remediation: "Add a global mapping, e.g. " +
				`- {claim: group, value: platform-admins, role: admin}` +
				" — or list an address in ui.oidc.admin_emails",
		})
		return
	}
	add(Finding{
		Check: "rbac.admin", Title: "Administrator access", Severity: SeverityPass,
		Message: fmt.Sprintf("%d route(s) grant hub admin", len(routes)),
		Details: map[string]any{"granted_by": strings.Join(routes, ", ")},
	})
}

// checkMappingHygiene catches mappings that parse but cannot do what they look
// like they do.
func checkMappingHygiene(oc config.OIDCConfig, bindings []authz.Binding, add addFn) {
	// A group binding needs the groups claim in the request, and cloop only
	// asks for what ui.oidc.scopes lists. A group mapping with no groups
	// scope matches nothing, forever, silently.
	usesGroups := false
	for _, b := range bindings {
		if b.Claim == authz.ClaimGroup {
			usesGroups = true
			break
		}
	}
	if usesGroups && !hasScope(oc.Scopes, "groups") {
		add(Finding{
			Check: "rbac.scopes", Title: "Group claim scope", Severity: SeverityFail,
			Message: "role mappings bind on the group claim, but ui.oidc.scopes does not request " +
				`"groups", so no ID token will carry one and those mappings can never match`,
			Remediation: `Add "groups" to ui.oidc.scopes (many IdPs also need the claim enabled on the client)`,
		})
	}

	// Two bindings on the same claim+value: the stronger wins, so the weaker
	// is dead policy that reads as if it constrains something.
	seen := map[string][]authz.Role{}
	for _, b := range bindings {
		k := fmt.Sprintf("%s=%s|%s|%s", b.Claim, strings.ToLower(b.Value), b.Project, b.Executor)
		seen[k] = append(seen[k], b.Role)
	}
	var dupes []string
	for k, roles := range seen {
		if len(roles) > 1 {
			dupes = append(dupes, k)
		}
	}
	if len(dupes) > 0 {
		sort.Strings(dupes)
		add(Finding{
			Check: "rbac.duplicates", Title: "Duplicate mappings", Severity: SeverityWarn,
			Message: fmt.Sprintf("%d claim value(s) are bound more than once at the same scope; "+
				"the strongest role wins and the others are dead policy", len(dupes)),
			Remediation: "Remove the redundant entries from ui.oidc.role_mappings",
			Details:     map[string]any{"duplicated": strings.Join(dupes, ", ")},
		})
	}
}

func hasScope(scopes []string, want string) bool {
	for _, s := range scopes {
		if strings.EqualFold(strings.TrimSpace(s), want) {
			return true
		}
	}
	return false
}

// bindingsFrom mirrors cmd's roleMappingsToBindings. It is duplicated rather
// than exported from cmd because pkg may not import cmd, and the conversion is
// four field copies whose validation lives in authz.New either way.
func bindingsFrom(mappings []config.RoleMapping) []authz.Binding {
	if len(mappings) == 0 {
		return nil
	}
	out := make([]authz.Binding, 0, len(mappings))
	for _, m := range mappings {
		out = append(out, authz.Binding{
			Claim:    authz.ClaimKind(m.Claim),
			Value:    m.Value,
			Role:     authz.Role(m.Role),
			Project:  m.Project,
			Executor: m.Executor,
		})
	}
	return out
}

// effectiveDefault applies the same empty→none rule authz.New does.
func effectiveDefault(role string) string {
	if strings.TrimSpace(role) == "" {
		return string(authz.RoleNone)
	}
	return role
}

func rolesList() string {
	names := make([]string, 0, len(authz.AllRoles))
	for _, r := range authz.AllRoles {
		names = append(names, string(r))
	}
	return strings.Join(names, ", ")
}
