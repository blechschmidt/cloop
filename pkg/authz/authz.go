// Package authz implements claim-based role-based access control for the
// cloop hub.
//
// The model is deliberately small enough to audit by reading it:
//
//	Permission  a single capability ("run.start", "executor.manage", …)
//	Role        a named bundle of permissions (viewer < operator <
//	            maintainer < admin)
//	Binding     "identities carrying this claim value hold this role",
//	            optionally narrowed to one project or one executor
//	Subject     the claims cloop extracted from a validated ID token
//	Decision    the resolved role + permission set for one (subject, scope)
//
// Resolution is deny-by-default: a subject that matches no binding falls
// back to Config.DefaultRole, which is RoleNone (deny everything) unless an
// operator explicitly configures otherwise.
//
// # Precedence
//
// A binding applies to a request only if its scope is satisfied: a binding
// with Project set applies only to requests against that project, and a
// binding with Executor set only to requests against that executor. Applying
// bindings are then ranked by specificity:
//
//	tier 3  project + executor both pinned
//	tier 2  executor pinned
//	tier 1  project pinned
//	tier 0  global (neither pinned)
//
// The highest tier with any match wins outright, and within that tier the
// strongest role wins. A more specific binding therefore *overrides* a
// broader one rather than merging with it — which is what makes scoping
// useful in both directions: an operator can grant a global viewer
// maintainer rights on one project, and can equally hold a global maintainer
// down to viewer on a sensitive project.
//
// Config.AdminEmails (the pre-RBAC admin list) participates as an ordinary
// global admin binding, so it keeps working untouched and a project-scoped
// binding can still narrow it.
//
// This package has no dependencies beyond the standard library and knows
// nothing about HTTP or OIDC wire formats; pkg/oidcauth extracts claims into
// a Subject and pkg/ui enforces the Decision.
package authz

import (
	"fmt"
	"sort"
	"strings"
)

// Permission is a single capability a caller may hold. Values are stable
// wire strings: they appear in config files, in /api/me payloads the
// frontend gates on, and in audit records. Never rename one; add a new
// constant instead.
type Permission string

const (
	// PermProjectRead is the right to see a project at all: its state,
	// tasks, steps, analytics, and event history. A caller without it is
	// told the project does not exist (404), never that it is forbidden.
	PermProjectRead Permission = "project.read"

	// PermProjectWrite is the right to change a project's identity and
	// lifecycle: goal, instructions, initialization, reset, deletion.
	PermProjectWrite Permission = "project.write"

	// PermRunStart is the right to start execution — the permission that
	// actually spends tokens and money.
	PermRunStart Permission = "run.start"

	// PermRunStop is the right to halt a running plan. Deliberately
	// separate from PermRunStart: stopping a runaway plan is a safety
	// action and is granted to operators who may not be able to start one.
	PermRunStop Permission = "run.stop"

	// PermTaskMutate is the right to add, edit, reorder, retag, or delete
	// tasks, and to apply AI-proposed plan changes.
	PermTaskMutate Permission = "task.mutate"

	// PermExecutorRead is the right to list the executor fleet and see the
	// host-execution policy.
	PermExecutorRead Permission = "executor.read"

	// PermExecutorManage is the right to enroll, revoke, cordon, drain, or
	// bind executors. Enrolling a device grants it the right to run project
	// workloads, so this is an administrator-grade permission.
	PermExecutorManage Permission = "executor.manage"

	// PermSecretGrant is the right to lease a credential (GitHub PAT,
	// kubeconfig, egress allowance) to an executor.
	PermSecretGrant Permission = "secret.grant"

	// PermSecretRevoke is the right to revoke an outstanding credential
	// lease before its TTL expires.
	PermSecretRevoke Permission = "secret.revoke"

	// PermConfigWrite is the right to change provider/model selection,
	// budgets, rate limits, timeouts, and the persistent run options.
	PermConfigWrite Permission = "config.write"

	// PermAuditRead is the right to read the tamper-evident audit trail and
	// to verify its hash chain.
	//
	// Deliberately not granted to maintainer. The trail records who leased
	// which credential to which executor, who was denied what, and every
	// privileged grant across the fleet — including the actions of people
	// more privileged than the reader. Handing it to the same role that
	// brokers credentials would also let an operator watch their own
	// oversight. It is granted to admin alone, which is what makes "a plain
	// member cannot read the trail" a property of the role ladder rather
	// than of any one route's wiring.
	PermAuditRead Permission = "audit.read"

	// PermUserManage is the right to administer access itself: role
	// bindings, sessions, and the identity integration.
	PermUserManage Permission = "user.manage"

	// PermPublic is not a permission. It is the explicit marker a route
	// declares when it must stay reachable before authorization can even be
	// evaluated — the login machinery, the SPA shell, static assets, and
	// /api/me. It exists so that "this route is unguarded" is a visible,
	// greppable decision in the route table rather than an omission.
	PermPublic Permission = "public"
)

// AllPermissions lists every real permission (PermPublic excluded) in a
// stable order. Used for config validation and for the permission set the
// frontend receives.
var AllPermissions = []Permission{
	PermProjectRead,
	PermProjectWrite,
	PermRunStart,
	PermRunStop,
	PermTaskMutate,
	PermExecutorRead,
	PermExecutorManage,
	PermSecretGrant,
	PermSecretRevoke,
	PermConfigWrite,
	PermAuditRead,
	PermUserManage,
}

// Valid reports whether p is a known permission. PermPublic is not a
// permission and reports false.
func (p Permission) Valid() bool {
	for _, known := range AllPermissions {
		if p == known {
			return true
		}
	}
	return false
}

// Role is a named bundle of permissions.
type Role string

const (
	// RoleNone holds no permissions. It is the default default: an
	// identity that matches no binding can do nothing until an operator
	// says otherwise.
	RoleNone Role = "none"

	// RoleViewer may read projects and see the executor fleet.
	RoleViewer Role = "viewer"

	// RoleOperator may additionally drive execution: start and stop runs
	// and mutate the task plan. This is the day-to-day engineer role.
	RoleOperator Role = "operator"

	// RoleMaintainer may additionally reshape a project and broker
	// credentials to executors: project write, config write, secret
	// grant/revoke.
	RoleMaintainer Role = "maintainer"

	// RoleAdmin holds every permission, including managing the executor
	// fleet and access control itself.
	RoleAdmin Role = "admin"
)

// AllRoles lists roles from weakest to strongest.
var AllRoles = []Role{RoleNone, RoleViewer, RoleOperator, RoleMaintainer, RoleAdmin}

// rank orders roles for "strongest wins" comparisons within a specificity
// tier. Unknown roles rank below RoleNone so they can never win a tie.
func (r Role) rank() int {
	switch r {
	case RoleNone:
		return 0
	case RoleViewer:
		return 1
	case RoleOperator:
		return 2
	case RoleMaintainer:
		return 3
	case RoleAdmin:
		return 4
	}
	return -1
}

// Valid reports whether r is a known role.
func (r Role) Valid() bool { return r.rank() >= 0 }

// rolePermissions is the single source of truth for what each role may do.
// Roles are cumulative by construction — each tier embeds the one below —
// so the table reads as a ladder and cannot drift out of order.
var rolePermissions = map[Role][]Permission{
	RoleNone:   {},
	RoleViewer: {PermProjectRead, PermExecutorRead},
	RoleOperator: {
		PermProjectRead, PermExecutorRead,
		PermRunStart, PermRunStop, PermTaskMutate,
	},
	RoleMaintainer: {
		PermProjectRead, PermExecutorRead,
		PermRunStart, PermRunStop, PermTaskMutate,
		PermProjectWrite, PermConfigWrite, PermSecretGrant, PermSecretRevoke,
	},
	RoleAdmin: AllPermissions,
}

// Permissions returns the permission set granted by r, as a fresh sorted
// slice. An unknown role grants nothing.
func (r Role) Permissions() []Permission {
	perms := rolePermissions[r]
	out := make([]Permission, len(perms))
	copy(out, perms)
	sortPermissions(out)
	return out
}

func sortPermissions(p []Permission) {
	sort.Slice(p, func(i, j int) bool { return p[i] < p[j] })
}

// ClaimKind selects which part of an identity a binding matches against.
type ClaimKind string

const (
	// ClaimGroup matches a value from the ID token's group claim
	// (`groups`, Keycloak's `realm_access.roles` group paths, etc.).
	ClaimGroup ClaimKind = "group"

	// ClaimRole matches a value from the ID token's role claim.
	ClaimRole ClaimKind = "role"

	// ClaimEmail matches the email claim, case-insensitively.
	ClaimEmail ClaimKind = "email"

	// ClaimSub matches the issuer subject exactly (case-sensitively — it
	// is an opaque identifier, not a human-readable name). Useful when the
	// IdP does not release email.
	ClaimSub ClaimKind = "sub"
)

// AllClaimKinds lists the claim kinds a binding may use.
var AllClaimKinds = []ClaimKind{ClaimGroup, ClaimRole, ClaimEmail, ClaimSub}

// Valid reports whether c is a known claim kind.
func (c ClaimKind) Valid() bool {
	for _, k := range AllClaimKinds {
		if c == k {
			return true
		}
	}
	return false
}

// Binding maps one claim value to one role, optionally narrowed to a single
// project and/or a single executor. See the package comment for precedence.
type Binding struct {
	// Claim selects what Value is compared against.
	Claim ClaimKind

	// Value is the claim value to match. Group and role values are
	// compared case-insensitively after trimming whitespace and any
	// leading "/" (Keycloak emits group paths as "/cloop-admins").
	Value string

	// Role is granted to identities matching Claim/Value within scope.
	Role Role

	// Project narrows the binding to one project, matched
	// case-insensitively against either the project's registry name or its
	// filesystem path. Empty means "every project".
	Project string

	// Executor narrows the binding to one executor ID. Empty means "every
	// executor".
	Executor string
}

// tier is the binding's specificity: higher wins outright over lower.
func (b Binding) tier() int {
	t := 0
	if b.Project != "" {
		t |= 1
	}
	if b.Executor != "" {
		t |= 2
	}
	return t
}

// Scope identifies the resource a permission check is about. The zero value
// is the global scope: it satisfies only unscoped bindings, which is the
// correct conservative reading for fleet-wide actions.
type Scope struct {
	// Project is the project's registry name, if it has one.
	Project string

	// ProjectPath is the project's filesystem path. A binding's Project
	// matches either Project or ProjectPath so operators may write
	// whichever is stable for their deployment.
	ProjectPath string

	// Executor is the executor ID for executor-scoped actions.
	Executor string
}

// GlobalScope is the scope for actions that are not about one project or
// one executor.
var GlobalScope = Scope{}

// IsGlobal reports whether s names no specific resource.
func (s Scope) IsGlobal() bool {
	return s.Project == "" && s.ProjectPath == "" && s.Executor == ""
}

// String renders the scope for audit records and error details.
func (s Scope) String() string {
	switch {
	case s.Executor != "" && s.projectLabel() != "":
		return "executor=" + s.Executor + ",project=" + s.projectLabel()
	case s.Executor != "":
		return "executor=" + s.Executor
	case s.projectLabel() != "":
		return "project=" + s.projectLabel()
	}
	return "global"
}

func (s Scope) projectLabel() string {
	if s.Project != "" {
		return s.Project
	}
	return s.ProjectPath
}

// Subject is the set of claims cloop extracted from a validated ID token.
// A nil *Subject means "no authenticated identity", which resolves to a
// deny.
type Subject struct {
	// Sub is the issuer subject: stable, opaque, always present.
	Sub string

	// Email is the email claim, if released. May be empty.
	Email string

	// Groups holds the values of the group claim, already flattened from
	// whatever shape the IdP used.
	Groups []string

	// Roles holds the values of the role claim, likewise flattened.
	Roles []string
}

// Label returns the most human-meaningful identifier for audit records:
// email when available, else the subject.
func (s *Subject) Label() string {
	if s == nil {
		return "anonymous"
	}
	if s.Email != "" {
		return strings.ToLower(s.Email)
	}
	if s.Sub != "" {
		return "sub:" + s.Sub
	}
	return "anonymous"
}

// Source records why a Decision came out the way it did. It is written to
// the audit log so a denial can be explained without re-running resolution.
type Source string

const (
	// SourceAuthzDisabled means RBAC is not in force (OIDC is off): the
	// single-tenant local behavior of granting everything.
	SourceAuthzDisabled Source = "authz_disabled"

	// SourceStaticToken means the caller presented the deployment's own
	// bearer token, which is an operator credential by definition.
	SourceStaticToken Source = "static_token"

	// SourceBinding means a configured role mapping matched.
	SourceBinding Source = "binding"

	// SourceAdminEmail means the legacy oidc.admin_emails list matched.
	SourceAdminEmail Source = "admin_email"

	// SourceDefaultRole means no binding matched and oidc.default_role
	// applied.
	SourceDefaultRole Source = "default_role"

	// SourceUnauthenticated means there was no identity to resolve.
	SourceUnauthenticated Source = "unauthenticated"
)

// Decision is the resolved authority of one subject over one scope.
// The zero value denies everything, which is the safe failure mode if a
// caller ever forgets to populate it.
type Decision struct {
	// Role is the effective role, RoleNone when nothing granted.
	Role Role

	// Source explains where Role came from.
	Source Source

	// Scope is the scope the decision was resolved for.
	Scope Scope

	// Binding is a copy of the winning binding, nil when Source is not
	// SourceBinding.
	Binding *Binding

	// SubjectLabel identifies the acting subject for audit records.
	SubjectLabel string

	// perms is the resolved permission set. nil means "deny everything";
	// allowAll short-circuits it for the disabled/token paths so future
	// permissions are automatically included.
	perms    map[Permission]struct{}
	allowAll bool
}

// Allows reports whether the decision grants p. PermPublic is always
// allowed: it marks a route as needing no authorization at all.
func (d Decision) Allows(p Permission) bool {
	if p == PermPublic {
		return true
	}
	if d.allowAll {
		return true
	}
	if d.perms == nil {
		return false
	}
	_, ok := d.perms[p]
	return ok
}

// Permissions returns the granted permissions as a stable sorted slice.
// For an allow-all decision this is every known permission, so the frontend
// receives a concrete list either way.
func (d Decision) Permissions() []Permission {
	if d.allowAll {
		out := make([]Permission, len(AllPermissions))
		copy(out, AllPermissions)
		sortPermissions(out)
		return out
	}
	out := make([]Permission, 0, len(d.perms))
	for p := range d.perms {
		out = append(out, p)
	}
	sortPermissions(out)
	return out
}

// AllowAll builds a decision granting every permission, used for the two
// paths that intentionally bypass RBAC: OIDC disabled (single-tenant local
// use) and static-token automation. src records which.
func AllowAll(src Source, subjectLabel string) Decision {
	return Decision{
		Role:         RoleAdmin,
		Source:       src,
		SubjectLabel: subjectLabel,
		allowAll:     true,
	}
}

// Deny builds a decision granting nothing.
func Deny(src Source, subjectLabel string, scope Scope) Decision {
	return Decision{
		Role:         RoleNone,
		Source:       src,
		Scope:        scope,
		SubjectLabel: subjectLabel,
	}
}

// Config is the operator-supplied policy, mapped from oidc.role_mappings
// and oidc.default_role in .cloop/config.yaml.
type Config struct {
	// DefaultRole applies to authenticated identities that match no
	// binding. The zero value means RoleNone: deny by default.
	DefaultRole Role

	// Bindings are the configured claim→role mappings.
	Bindings []Binding

	// AdminEmails is the pre-RBAC admin list (oidc.admin_emails). Each
	// entry becomes a global admin binding.
	AdminEmails []string
}

// Resolver evaluates Config against subjects and scopes. It is immutable
// after New and safe for concurrent use.
type Resolver struct {
	defaultRole Role
	bindings    []Binding
	configured  bool
}

// Configured reports whether an operator actually supplied an RBAC policy —
// at least one role mapping, or an explicit default_role.
//
// This distinction exists so that turning on OIDC does not silently turn on
// deny-by-default. A deployment that enabled SSO before RBAC existed has no
// role_mappings; if the empty policy were enforced, upgrading would lock
// every user out of their own dashboard. Callers therefore treat an
// unconfigured resolver as "RBAC not in force" and keep the pre-RBAC
// behavior. Writing a single role_mapping (or setting default_role
// explicitly, including to "none") opts the deployment in, and from that
// point deny-by-default applies to everything the policy does not grant.
//
// admin_emails alone does not count: it predates RBAC and only ever meant
// "sees every project".
func (r *Resolver) Configured() bool {
	return r != nil && r.configured
}

// New validates cfg and returns a Resolver.
//
// Validation is strict and fails closed: a typo in a role name or claim kind
// is an error at startup rather than a binding that silently never matches.
// Error messages name the offending entry by index so a misconfigured YAML
// file is diagnosable without reading this code.
func New(cfg Config) (*Resolver, error) {
	def := cfg.DefaultRole
	if def == "" {
		def = RoleNone
	}
	if !def.Valid() {
		return nil, fmt.Errorf("authz: default_role %q is not a known role (valid: %s)", cfg.DefaultRole, roleNames())
	}

	bindings := make([]Binding, 0, len(cfg.Bindings)+len(cfg.AdminEmails))
	for i, b := range cfg.Bindings {
		nb, err := normalizeBinding(b)
		if err != nil {
			return nil, fmt.Errorf("authz: role_mappings[%d]: %w", i, err)
		}
		bindings = append(bindings, nb)
	}
	// The legacy admin list becomes ordinary global admin bindings so there
	// is exactly one resolution path to reason about.
	for _, email := range cfg.AdminEmails {
		email = strings.TrimSpace(email)
		if email == "" {
			continue
		}
		bindings = append(bindings, Binding{
			Claim: ClaimEmail,
			Value: strings.ToLower(email),
			Role:  RoleAdmin,
		})
	}

	return &Resolver{
		defaultRole: def,
		bindings:    bindings,
		configured:  len(cfg.Bindings) > 0 || cfg.DefaultRole != "",
	}, nil
}

func roleNames() string {
	names := make([]string, len(AllRoles))
	for i, r := range AllRoles {
		names[i] = string(r)
	}
	return strings.Join(names, ", ")
}

func claimNames() string {
	names := make([]string, len(AllClaimKinds))
	for i, c := range AllClaimKinds {
		names[i] = string(c)
	}
	return strings.Join(names, ", ")
}

func normalizeBinding(b Binding) (Binding, error) {
	b.Claim = ClaimKind(strings.ToLower(strings.TrimSpace(string(b.Claim))))
	if b.Claim == "" {
		return b, fmt.Errorf("claim is required (valid: %s)", claimNames())
	}
	if !b.Claim.Valid() {
		return b, fmt.Errorf("claim %q is not a known claim kind (valid: %s)", b.Claim, claimNames())
	}
	b.Value = normalizeClaimValue(b.Value)
	if b.Value == "" {
		return b, fmt.Errorf("value is required — a binding with an empty value would match nothing")
	}
	b.Role = Role(strings.ToLower(strings.TrimSpace(string(b.Role))))
	if b.Role == "" {
		return b, fmt.Errorf("role is required (valid: %s)", roleNames())
	}
	if !b.Role.Valid() {
		return b, fmt.Errorf("role %q is not a known role (valid: %s)", b.Role, roleNames())
	}
	b.Project = strings.TrimSpace(b.Project)
	b.Executor = strings.TrimSpace(b.Executor)
	return b, nil
}

// normalizeClaimValue trims whitespace and a single leading "/" so that
// Keycloak's group-path form ("/cloop-admins") and the bare form
// ("cloop-admins") are interchangeable in config and in tokens.
func normalizeClaimValue(v string) string {
	return strings.TrimPrefix(strings.TrimSpace(v), "/")
}

// Resolve computes the effective role and permission set for subject within
// scope. A nil subject denies everything.
func (r *Resolver) Resolve(subject *Subject, scope Scope) Decision {
	if r == nil {
		return Deny(SourceUnauthenticated, "", scope)
	}
	if subject == nil {
		return Deny(SourceUnauthenticated, "", scope)
	}

	bestTier := -1
	bestRole := RoleNone
	var best *Binding

	for i := range r.bindings {
		b := r.bindings[i]
		if !b.appliesTo(scope) || !b.matches(subject) {
			continue
		}
		t := b.tier()
		// A higher tier wins outright, even if it grants a weaker role:
		// that is what makes a project-scoped downgrade possible.
		if t > bestTier || (t == bestTier && b.Role.rank() > bestRole.rank()) {
			bestTier, bestRole, best = t, b.Role, &r.bindings[i]
		}
	}

	if best == nil {
		return Decision{
			Role:         r.defaultRole,
			Source:       SourceDefaultRole,
			Scope:        scope,
			SubjectLabel: subject.Label(),
			perms:        permSet(r.defaultRole),
		}
	}

	src := SourceBinding
	// Surface legacy admin_emails entries distinctly in audit records: an
	// operator debugging "why is this person an admin?" should not have to
	// guess whether it came from role_mappings.
	if best.Claim == ClaimEmail && best.Role == RoleAdmin && best.tier() == 0 {
		src = SourceAdminEmail
	}
	bound := *best
	return Decision{
		Role:         bestRole,
		Source:       src,
		Scope:        scope,
		Binding:      &bound,
		SubjectLabel: subject.Label(),
		perms:        permSet(bestRole),
	}
}

func permSet(role Role) map[Permission]struct{} {
	perms := rolePermissions[role]
	if len(perms) == 0 {
		return nil
	}
	set := make(map[Permission]struct{}, len(perms))
	for _, p := range perms {
		set[p] = struct{}{}
	}
	return set
}

// appliesTo reports whether the binding's scope narrowing is satisfied by
// the requested scope. A binding pinned to a project or executor never
// applies to a broader request: holding maintainer on one project must not
// confer maintainer on a fleet-wide action.
func (b Binding) appliesTo(scope Scope) bool {
	if b.Project != "" && !projectMatches(b.Project, scope) {
		return false
	}
	if b.Executor != "" && !strings.EqualFold(b.Executor, scope.Executor) {
		return false
	}
	return true
}

func projectMatches(want string, scope Scope) bool {
	if scope.Project != "" && strings.EqualFold(want, scope.Project) {
		return true
	}
	if scope.ProjectPath != "" && strings.EqualFold(want, scope.ProjectPath) {
		return true
	}
	return false
}

// matches reports whether the binding's claim/value identifies subject.
func (b Binding) matches(s *Subject) bool {
	switch b.Claim {
	case ClaimEmail:
		return s.Email != "" && strings.EqualFold(b.Value, strings.TrimSpace(s.Email))
	case ClaimSub:
		// Subjects are opaque identifiers, so compare exactly.
		return s.Sub != "" && b.Value == strings.TrimSpace(s.Sub)
	case ClaimGroup:
		return containsFold(s.Groups, b.Value)
	case ClaimRole:
		return containsFold(s.Roles, b.Value)
	}
	return false
}

func containsFold(values []string, want string) bool {
	for _, v := range values {
		if strings.EqualFold(normalizeClaimValue(v), want) {
			return true
		}
	}
	return false
}
