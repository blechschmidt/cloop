package authz

import (
	"strings"
	"testing"
)

// mustResolver builds a Resolver or fails the test. Used where the config is
// known-good and the test is about resolution, not validation.
func mustResolver(t *testing.T, cfg Config) *Resolver {
	t.Helper()
	r, err := New(cfg)
	if err != nil {
		t.Fatalf("New(%+v) returned error: %v", cfg, err)
	}
	return r
}

// TestRoleLadderIsCumulative locks in the central promise of the role model:
// each tier holds every permission of the tier below plus more. If a future
// edit removes a permission from a higher role while leaving it on a lower
// one, the ladder stops being a ladder and operators' mental model breaks.
func TestRoleLadderIsCumulative(t *testing.T) {
	t.Parallel()

	ladder := []Role{RoleNone, RoleViewer, RoleOperator, RoleMaintainer, RoleAdmin}
	for i := 1; i < len(ladder); i++ {
		lower, higher := ladder[i-1], ladder[i]
		lowerPerms := lower.Permissions()
		higherSet := map[Permission]bool{}
		for _, p := range higher.Permissions() {
			higherSet[p] = true
		}
		for _, p := range lowerPerms {
			if !higherSet[p] {
				t.Errorf("role ladder broken: %s holds %q but %s does not", lower, p, higher)
			}
		}
		if len(higher.Permissions()) <= len(lowerPerms) && higher != RoleAdmin {
			t.Errorf("role %s should hold strictly more than %s", higher, lower)
		}
	}
}

// TestAdminHoldsEveryPermission ensures a new permission cannot be added
// without admin picking it up — otherwise adding a permission silently
// creates an action nobody can perform.
func TestAdminHoldsEveryPermission(t *testing.T) {
	t.Parallel()

	admin := RoleAdmin.Permissions()
	have := map[Permission]bool{}
	for _, p := range admin {
		have[p] = true
	}
	for _, p := range AllPermissions {
		if !have[p] {
			t.Errorf("admin is missing permission %q — add it to rolePermissions[RoleAdmin]", p)
		}
	}
}

// TestResolvePermissionsAcrossClaimShapes is the table the task calls for:
// every claim kind, matched and unmatched, against the role each grants.
func TestResolvePermissionsAcrossClaimShapes(t *testing.T) {
	t.Parallel()

	cfg := Config{
		Bindings: []Binding{
			{Claim: ClaimGroup, Value: "cloop-admins", Role: RoleAdmin},
			{Claim: ClaimGroup, Value: "engineering", Role: RoleOperator},
			{Claim: ClaimRole, Value: "cloop-maintainer", Role: RoleMaintainer},
			{Claim: ClaimEmail, Value: "viewer@example.com", Role: RoleViewer},
			{Claim: ClaimSub, Value: "opaque-sub-123", Role: RoleOperator},
		},
	}
	r := mustResolver(t, cfg)

	cases := []struct {
		name     string
		subject  *Subject
		wantRole Role
		allows   []Permission
		denies   []Permission
	}{
		{
			name:     "group match grants admin",
			subject:  &Subject{Sub: "u1", Email: "a@example.com", Groups: []string{"cloop-admins"}},
			wantRole: RoleAdmin,
			allows:   []Permission{PermExecutorManage, PermUserManage, PermRunStart},
		},
		{
			name:     "group match is case-insensitive",
			subject:  &Subject{Sub: "u2", Groups: []string{"CLOOP-Admins"}},
			wantRole: RoleAdmin,
			allows:   []Permission{PermUserManage},
		},
		{
			name:     "keycloak group path form matches bare config value",
			subject:  &Subject{Sub: "u3", Groups: []string{"/engineering"}},
			wantRole: RoleOperator,
			allows:   []Permission{PermRunStart, PermRunStop, PermTaskMutate, PermProjectRead},
			denies:   []Permission{PermConfigWrite, PermExecutorManage, PermProjectWrite},
		},
		{
			name:     "role claim is matched separately from group claim",
			subject:  &Subject{Sub: "u4", Roles: []string{"cloop-maintainer"}},
			wantRole: RoleMaintainer,
			allows:   []Permission{PermConfigWrite, PermSecretGrant, PermSecretRevoke, PermProjectWrite},
			denies:   []Permission{PermExecutorManage, PermUserManage},
		},
		{
			name:     "a group value does not match a role binding",
			subject:  &Subject{Sub: "u5", Groups: []string{"cloop-maintainer"}},
			wantRole: RoleNone,
			denies:   []Permission{PermProjectRead},
		},
		{
			name:     "email match is case-insensitive",
			subject:  &Subject{Sub: "u6", Email: "Viewer@Example.COM"},
			wantRole: RoleViewer,
			allows:   []Permission{PermProjectRead, PermExecutorRead},
			denies:   []Permission{PermRunStart, PermTaskMutate},
		},
		{
			name:     "sub match grants operator",
			subject:  &Subject{Sub: "opaque-sub-123"},
			wantRole: RoleOperator,
			allows:   []Permission{PermRunStart},
		},
		{
			name:     "sub match is case-sensitive: subs are opaque",
			subject:  &Subject{Sub: "OPAQUE-SUB-123"},
			wantRole: RoleNone,
			denies:   []Permission{PermProjectRead},
		},
		{
			name:     "no matching claim falls back to deny-by-default",
			subject:  &Subject{Sub: "stranger", Email: "nobody@example.com", Groups: []string{"sales"}},
			wantRole: RoleNone,
			denies:   AllPermissions,
		},
		{
			name:     "strongest role wins when several bindings match at the same tier",
			subject:  &Subject{Sub: "u7", Groups: []string{"engineering", "cloop-admins"}},
			wantRole: RoleAdmin,
			allows:   []Permission{PermUserManage},
		},
		{
			name:     "empty email claim never matches an email binding",
			subject:  &Subject{Sub: "u8", Email: ""},
			wantRole: RoleNone,
			denies:   []Permission{PermProjectRead},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := r.Resolve(tc.subject, GlobalScope)
			if d.Role != tc.wantRole {
				t.Errorf("role = %q, want %q", d.Role, tc.wantRole)
			}
			for _, p := range tc.allows {
				if !d.Allows(p) {
					t.Errorf("expected %q to be allowed for role %q", p, d.Role)
				}
			}
			for _, p := range tc.denies {
				if d.Allows(p) {
					t.Errorf("expected %q to be DENIED for role %q", p, d.Role)
				}
			}
		})
	}
}

// TestResolveNilSubjectDenies is the fail-closed check: an unauthenticated
// caller must never resolve to anything.
func TestResolveNilSubjectDenies(t *testing.T) {
	t.Parallel()

	r := mustResolver(t, Config{
		DefaultRole: RoleAdmin, // even the most permissive default
		Bindings:    []Binding{{Claim: ClaimGroup, Value: "everyone", Role: RoleAdmin}},
	})
	d := r.Resolve(nil, GlobalScope)
	if d.Role != RoleNone {
		t.Errorf("nil subject resolved to role %q, want none", d.Role)
	}
	if d.Source != SourceUnauthenticated {
		t.Errorf("source = %q, want %q", d.Source, SourceUnauthenticated)
	}
	for _, p := range AllPermissions {
		if d.Allows(p) {
			t.Errorf("nil subject was granted %q", p)
		}
	}
}

// TestResolveNilResolverDenies guards the zero-value path: a Server that
// never got a resolver must not accidentally grant.
func TestResolveNilResolverDenies(t *testing.T) {
	t.Parallel()

	var r *Resolver
	d := r.Resolve(&Subject{Sub: "u1", Groups: []string{"admins"}}, GlobalScope)
	if d.Allows(PermProjectRead) {
		t.Error("nil resolver granted project.read")
	}
	if r.Configured() {
		t.Error("nil resolver reported Configured() == true")
	}
}

// TestScopedBindingPrecedence covers the rule that makes scoping useful in
// both directions: a more specific binding overrides a broader one, whether
// it grants more or less.
func TestScopedBindingPrecedence(t *testing.T) {
	t.Parallel()

	const (
		payments = "payments"
		payPath  = "/srv/projects/payments"
		infra    = "infra"
	)

	r := mustResolver(t, Config{
		Bindings: []Binding{
			// Global baseline.
			{Claim: ClaimGroup, Value: "engineering", Role: RoleOperator},
			// Upgrade on one project (by name).
			{Claim: ClaimGroup, Value: "engineering", Role: RoleMaintainer, Project: payments},
			// Deliberate downgrade on a sensitive project.
			{Claim: ClaimGroup, Value: "engineering", Role: RoleViewer, Project: infra},
			// Global admin, held down to viewer on one project.
			{Claim: ClaimEmail, Value: "root@example.com", Role: RoleAdmin},
			{Claim: ClaimEmail, Value: "root@example.com", Role: RoleViewer, Project: infra},
			// Executor-pinned binding.
			{Claim: ClaimGroup, Value: "fleet-ops", Role: RoleAdmin, Executor: "edge-1"},
			// Binding by filesystem path rather than registry name.
			{Claim: ClaimGroup, Value: "contractors", Role: RoleViewer, Project: payPath},
		},
	})

	eng := &Subject{Sub: "e1", Groups: []string{"engineering"}}
	root := &Subject{Sub: "r1", Email: "root@example.com"}
	fleet := &Subject{Sub: "f1", Groups: []string{"fleet-ops"}}
	contractor := &Subject{Sub: "c1", Groups: []string{"contractors"}}

	cases := []struct {
		name     string
		subject  *Subject
		scope    Scope
		wantRole Role
	}{
		{
			name:     "global binding applies to the global scope",
			subject:  eng, scope: GlobalScope, wantRole: RoleOperator,
		},
		{
			name:     "project binding upgrades within its project",
			subject:  eng,
			scope:    Scope{Project: payments, ProjectPath: payPath},
			wantRole: RoleMaintainer,
		},
		{
			name:     "project binding downgrades within its project",
			subject:  eng,
			scope:    Scope{Project: infra, ProjectPath: "/srv/projects/infra"},
			wantRole: RoleViewer,
		},
		{
			name:     "unpinned project falls back to the global binding",
			subject:  eng,
			scope:    Scope{Project: "marketing", ProjectPath: "/srv/projects/marketing"},
			wantRole: RoleOperator,
		},
		{
			name:     "a project-scoped downgrade beats a global admin grant",
			subject:  root,
			scope:    Scope{Project: infra},
			wantRole: RoleViewer,
		},
		{
			name:     "the global admin grant still applies elsewhere",
			subject:  root,
			scope:    Scope{Project: payments},
			wantRole: RoleAdmin,
		},
		{
			name:     "executor binding applies to its executor",
			subject:  fleet,
			scope:    Scope{Executor: "edge-1"},
			wantRole: RoleAdmin,
		},
		{
			name:     "executor binding does not leak to another executor",
			subject:  fleet,
			scope:    Scope{Executor: "edge-2"},
			wantRole: RoleNone,
		},
		{
			name:     "executor binding does not leak to the global scope",
			subject:  fleet,
			scope:    GlobalScope,
			wantRole: RoleNone,
		},
		{
			name:     "project binding does not confer authority globally",
			subject:  contractor,
			scope:    GlobalScope,
			wantRole: RoleNone,
		},
		{
			name:     "a project may be bound by filesystem path",
			subject:  contractor,
			scope:    Scope{Project: payments, ProjectPath: payPath},
			wantRole: RoleViewer,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := r.Resolve(tc.subject, tc.scope)
			if d.Role != tc.wantRole {
				t.Errorf("Resolve(%s, %s) role = %q, want %q",
					tc.subject.Label(), tc.scope, d.Role, tc.wantRole)
			}
		})
	}
}

// TestExecutorTierBeatsProjectTier pins the ordering between the two
// single-axis tiers when both could apply.
func TestExecutorTierBeatsProjectTier(t *testing.T) {
	t.Parallel()

	r := mustResolver(t, Config{
		Bindings: []Binding{
			{Claim: ClaimGroup, Value: "ops", Role: RoleAdmin, Project: "p1"},
			{Claim: ClaimGroup, Value: "ops", Role: RoleViewer, Executor: "e1"},
			// Both axes pinned — the most specific binding of all.
			{Claim: ClaimGroup, Value: "ops", Role: RoleOperator, Project: "p1", Executor: "e1"},
		},
	})
	ops := &Subject{Sub: "o1", Groups: []string{"ops"}}

	if got := r.Resolve(ops, Scope{Project: "p1"}).Role; got != RoleAdmin {
		t.Errorf("project-only scope: role = %q, want admin", got)
	}
	if got := r.Resolve(ops, Scope{Executor: "e1"}).Role; got != RoleViewer {
		t.Errorf("executor-only scope: role = %q, want viewer", got)
	}
	if got := r.Resolve(ops, Scope{Project: "p1", Executor: "e1"}).Role; got != RoleOperator {
		t.Errorf("both-pinned scope: role = %q, want operator (most specific binding)", got)
	}
}

// TestDefaultRoleApplies checks the fallback and that it is reported
// honestly in the decision's Source.
func TestDefaultRoleApplies(t *testing.T) {
	t.Parallel()

	t.Run("explicit viewer default", func(t *testing.T) {
		r := mustResolver(t, Config{DefaultRole: RoleViewer})
		d := r.Resolve(&Subject{Sub: "u1"}, GlobalScope)
		if d.Role != RoleViewer {
			t.Errorf("role = %q, want viewer", d.Role)
		}
		if d.Source != SourceDefaultRole {
			t.Errorf("source = %q, want default_role", d.Source)
		}
		if !d.Allows(PermProjectRead) || d.Allows(PermRunStart) {
			t.Error("viewer default should allow project.read and deny run.start")
		}
	})

	t.Run("empty default means deny", func(t *testing.T) {
		r := mustResolver(t, Config{Bindings: []Binding{
			{Claim: ClaimGroup, Value: "x", Role: RoleAdmin},
		}})
		d := r.Resolve(&Subject{Sub: "u1"}, GlobalScope)
		if d.Role != RoleNone {
			t.Errorf("role = %q, want none", d.Role)
		}
		for _, p := range AllPermissions {
			if d.Allows(p) {
				t.Errorf("deny-by-default granted %q", p)
			}
		}
	})
}

// TestAdminEmailsBecomeGlobalAdminBindings verifies the pre-RBAC admin list
// keeps working and is reported distinctly in audit records.
func TestAdminEmailsBecomeGlobalAdminBindings(t *testing.T) {
	t.Parallel()

	r := mustResolver(t, Config{AdminEmails: []string{"  Boss@Example.com  ", ""}})
	d := r.Resolve(&Subject{Sub: "b1", Email: "boss@example.com"}, GlobalScope)
	if d.Role != RoleAdmin {
		t.Fatalf("role = %q, want admin", d.Role)
	}
	if d.Source != SourceAdminEmail {
		t.Errorf("source = %q, want admin_email so operators can tell where it came from", d.Source)
	}
	if !d.Allows(PermExecutorManage) {
		t.Error("admin_emails entry should hold executor.manage")
	}

	// admin_emails alone must NOT count as an RBAC policy, or enabling
	// OIDC would flip a deployment into deny-by-default.
	if r.Configured() {
		t.Error("admin_emails alone must not report Configured() == true")
	}

	// A project-scoped binding can still narrow a legacy admin.
	r2 := mustResolver(t, Config{
		AdminEmails: []string{"boss@example.com"},
		Bindings:    []Binding{{Claim: ClaimEmail, Value: "boss@example.com", Role: RoleViewer, Project: "secret"}},
	})
	if got := r2.Resolve(&Subject{Sub: "b1", Email: "boss@example.com"}, Scope{Project: "secret"}).Role; got != RoleViewer {
		t.Errorf("scoped downgrade of an admin_emails user: role = %q, want viewer", got)
	}
}

// TestConfiguredReportsPolicyPresence documents exactly what opts a
// deployment into deny-by-default.
func TestConfiguredReportsPolicyPresence(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		cfg  Config
		want bool
	}{
		{"empty config", Config{}, false},
		{"admin emails only", Config{AdminEmails: []string{"a@b.c"}}, false},
		{"one binding", Config{Bindings: []Binding{{Claim: ClaimGroup, Value: "g", Role: RoleViewer}}}, true},
		{"explicit default role", Config{DefaultRole: RoleViewer}, true},
		{"explicit none default is still a policy", Config{DefaultRole: RoleNone}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := mustResolver(t, tc.cfg).Configured(); got != tc.want {
				t.Errorf("Configured() = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestNewValidatesConfig checks that misconfiguration fails at startup with
// a message naming the offending entry, rather than producing a binding that
// silently never matches.
func TestNewValidatesConfig(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name        string
		cfg         Config
		wantErrPart string
	}{
		{
			name:        "unknown default role",
			cfg:         Config{DefaultRole: Role("superuser")},
			wantErrPart: "default_role",
		},
		{
			name:        "unknown claim kind",
			cfg:         Config{Bindings: []Binding{{Claim: ClaimKind("department"), Value: "x", Role: RoleViewer}}},
			wantErrPart: "role_mappings[0]",
		},
		{
			name:        "unknown role",
			cfg:         Config{Bindings: []Binding{{Claim: ClaimGroup, Value: "x", Role: Role("superuser")}}},
			wantErrPart: "not a known role",
		},
		{
			name:        "empty value",
			cfg:         Config{Bindings: []Binding{{Claim: ClaimGroup, Value: "   ", Role: RoleViewer}}},
			wantErrPart: "value is required",
		},
		{
			name:        "missing claim",
			cfg:         Config{Bindings: []Binding{{Value: "x", Role: RoleViewer}}},
			wantErrPart: "claim is required",
		},
		{
			name:        "missing role",
			cfg:         Config{Bindings: []Binding{{Claim: ClaimGroup, Value: "x"}}},
			wantErrPart: "role is required",
		},
		{
			name: "index of the offending entry is reported",
			cfg: Config{Bindings: []Binding{
				{Claim: ClaimGroup, Value: "ok", Role: RoleViewer},
				{Claim: ClaimGroup, Value: "bad", Role: Role("nope")},
			}},
			wantErrPart: "role_mappings[1]",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := New(tc.cfg)
			if err == nil {
				t.Fatalf("New(%+v) succeeded, want an error", tc.cfg)
			}
			if !strings.Contains(err.Error(), tc.wantErrPart) {
				t.Errorf("error %q does not mention %q", err, tc.wantErrPart)
			}
		})
	}
}

// TestNewNormalizesInput checks the case/whitespace tolerances that make
// hand-written YAML forgiving without making matching ambiguous.
func TestNewNormalizesInput(t *testing.T) {
	t.Parallel()

	r := mustResolver(t, Config{
		DefaultRole: RoleNone,
		Bindings: []Binding{
			{Claim: ClaimKind("  GROUP  "), Value: "  /Cloop-Admins  ", Role: Role(" Admin ")},
		},
	})
	d := r.Resolve(&Subject{Sub: "u1", Groups: []string{"cloop-admins"}}, GlobalScope)
	if d.Role != RoleAdmin {
		t.Errorf("normalized binding did not match: role = %q, want admin", d.Role)
	}
}

// TestAllowAllAndDeny cover the two constructors pkg/ui uses for the paths
// that bypass RBAC entirely.
func TestAllowAllAndDeny(t *testing.T) {
	t.Parallel()

	allow := AllowAll(SourceAuthzDisabled, "local")
	for _, p := range AllPermissions {
		if !allow.Allows(p) {
			t.Errorf("AllowAll denied %q", p)
		}
	}
	if got := len(allow.Permissions()); got != len(AllPermissions) {
		t.Errorf("AllowAll().Permissions() has %d entries, want %d", got, len(AllPermissions))
	}

	deny := Deny(SourceUnauthenticated, "", GlobalScope)
	for _, p := range AllPermissions {
		if deny.Allows(p) {
			t.Errorf("Deny granted %q", p)
		}
	}
	if got := len(deny.Permissions()); got != 0 {
		t.Errorf("Deny().Permissions() has %d entries, want 0", got)
	}

	// The zero Decision must deny — a caller that forgets to populate one
	// should fail closed.
	var zero Decision
	for _, p := range AllPermissions {
		if zero.Allows(p) {
			t.Errorf("zero Decision granted %q", p)
		}
	}
	// PermPublic is the one thing any decision allows: it marks a route as
	// needing no authorization.
	if !zero.Allows(PermPublic) {
		t.Error("PermPublic should be allowed even by the zero Decision")
	}
}

// TestPermissionsIsSortedAndCopied guards against a caller mutating the
// shared role table through a returned slice.
func TestPermissionsIsSortedAndCopied(t *testing.T) {
	t.Parallel()

	first := RoleMaintainer.Permissions()
	for i := 1; i < len(first); i++ {
		if first[i-1] > first[i] {
			t.Fatalf("Permissions() is not sorted: %q before %q", first[i-1], first[i])
		}
	}
	first[0] = Permission("mutated")
	second := RoleMaintainer.Permissions()
	for _, p := range second {
		if p == Permission("mutated") {
			t.Fatal("Permissions() returned a slice aliasing the shared role table")
		}
	}
}

// TestScopeString exercises the audit-record rendering of every scope shape.
func TestScopeString(t *testing.T) {
	t.Parallel()

	cases := []struct {
		scope Scope
		want  string
	}{
		{GlobalScope, "global"},
		{Scope{Project: "p"}, "project=p"},
		{Scope{ProjectPath: "/srv/p"}, "project=/srv/p"},
		{Scope{Project: "p", ProjectPath: "/srv/p"}, "project=p"},
		{Scope{Executor: "e1"}, "executor=e1"},
		{Scope{Project: "p", Executor: "e1"}, "executor=e1,project=p"},
	}
	for _, tc := range cases {
		if got := tc.scope.String(); got != tc.want {
			t.Errorf("Scope%+v.String() = %q, want %q", tc.scope, got, tc.want)
		}
	}
	if !GlobalScope.IsGlobal() {
		t.Error("GlobalScope.IsGlobal() = false")
	}
	if (Scope{ProjectPath: "/srv/p"}).IsGlobal() {
		t.Error("a project-path scope must not report IsGlobal()")
	}
}

// TestSubjectLabel checks the identifier that lands in audit records.
func TestSubjectLabel(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		subject *Subject
		want    string
	}{
		{"nil", nil, "anonymous"},
		{"email preferred", &Subject{Sub: "s1", Email: "A@B.com"}, "a@b.com"},
		{"sub fallback", &Subject{Sub: "s1"}, "sub:s1"},
		{"empty", &Subject{}, "anonymous"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.subject.Label(); got != tc.want {
				t.Errorf("Label() = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestDecisionCarriesMatchedBinding checks the audit trail can name which
// rule granted access, and that the returned binding is a copy.
func TestDecisionCarriesMatchedBinding(t *testing.T) {
	t.Parallel()

	r := mustResolver(t, Config{Bindings: []Binding{
		{Claim: ClaimGroup, Value: "eng", Role: RoleOperator},
	}})
	d := r.Resolve(&Subject{Sub: "u1", Groups: []string{"eng"}}, GlobalScope)
	if d.Binding == nil {
		t.Fatal("decision from a matched binding must carry it for the audit record")
	}
	if d.Binding.Value != "eng" || d.Binding.Role != RoleOperator {
		t.Errorf("binding = %+v, want claim eng → operator", d.Binding)
	}
	d.Binding.Role = RoleAdmin // must not affect the resolver
	if got := r.Resolve(&Subject{Sub: "u2", Groups: []string{"eng"}}, GlobalScope).Role; got != RoleOperator {
		t.Errorf("mutating a returned binding changed resolution: role = %q", got)
	}
}

// TestPermissionAndRoleWireStability locks the string values that appear in
// config files, /api/me payloads, and audit records. Renaming one silently
// breaks every deployment's config and the frontend's permission gating, so
// a rename must be a deliberate, visible edit here.
func TestPermissionAndRoleWireStability(t *testing.T) {
	t.Parallel()

	wantPerms := []string{
		"project.read", "project.write", "run.start", "run.stop",
		"task.mutate", "executor.read", "executor.manage",
		"secret.grant", "secret.revoke", "config.write", "audit.read",
		"user.manage", "token.admin",
	}
	if len(AllPermissions) != len(wantPerms) {
		t.Fatalf("AllPermissions has %d entries, want %d — add the new one to this test",
			len(AllPermissions), len(wantPerms))
	}
	for i, want := range wantPerms {
		if string(AllPermissions[i]) != want {
			t.Errorf("AllPermissions[%d] = %q, want %q", i, AllPermissions[i], want)
		}
	}
	if string(PermPublic) != "public" {
		t.Errorf("PermPublic = %q, want %q", PermPublic, "public")
	}

	wantRoles := []string{"none", "viewer", "operator", "maintainer", "admin"}
	if len(AllRoles) != len(wantRoles) {
		t.Fatalf("AllRoles has %d entries, want %d", len(AllRoles), len(wantRoles))
	}
	for i, want := range wantRoles {
		if string(AllRoles[i]) != want {
			t.Errorf("AllRoles[%d] = %q, want %q", i, AllRoles[i], want)
		}
	}
}
