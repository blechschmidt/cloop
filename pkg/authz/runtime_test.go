package authz

// Pins the precedence rule between the runtime and configured binding layers
// (Task 20248): deny wins, and the database overrides config.
//
// The rule is worth pinning because both halves are load-bearing for exactly
// one scenario and inert otherwise. oidc.admin_emails becomes a global admin
// binding, so demoting a compromised administrator has to beat a tier-0 admin;
// rank a deny against it and the deny loses, consult config after a runtime
// match and the admin binding comes back. Either regression leaves an
// emergency lever that reports success and changes nothing, which is worse
// than not having one — nobody would go looking for the config edit.

import (
	"reflect"
	"testing"
)

// staticRuntime is an authz.RuntimeSource over a fixed slice.
type staticRuntime struct {
	bindings []Binding
	calls    int
}

func (s *staticRuntime) RuntimeBindings() []Binding {
	s.calls++
	return s.bindings
}

func adminEmailResolver(t *testing.T, runtime RuntimeSource, extra ...Binding) *Resolver {
	t.Helper()
	r, err := New(Config{
		AdminEmails: []string{"alice@example.com"},
		Bindings:    extra,
		Runtime:     runtime,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return r
}

// TestRuntimeDenyOverridesAdminEmails is the emergency demotion path, and the
// single most important assertion in this file: an operator must be able to
// take admin away from somebody whose address is in a config file the command
// never touches.
func TestRuntimeDenyOverridesAdminEmails(t *testing.T) {
	alice := &Subject{Sub: "sub-alice", Email: "alice@example.com"}

	// Before: the config list makes her a global admin.
	before := adminEmailResolver(t, nil).Resolve(alice, Scope{})
	if before.Role != RoleAdmin {
		t.Fatalf("precondition: admin_emails resolved %s, want admin", before.Role)
	}
	if !before.Allows(PermUserManage) {
		t.Fatal("precondition: admin must hold user.manage")
	}

	// After: one runtime deny.
	runtime := &staticRuntime{bindings: []Binding{
		{Claim: ClaimEmail, Value: "alice@example.com", Deny: true},
	}}
	after := adminEmailResolver(t, runtime).Resolve(alice, Scope{})
	if after.Role != RoleNone {
		t.Errorf("after a runtime deny the role is %s, want none — the deny lost to "+
			"the tier-0 admin binding admin_emails produces", after.Role)
	}
	for _, perm := range AllPermissions {
		if after.Allows(perm) {
			t.Errorf("a denied subject still holds %s", perm)
		}
	}
	if after.Source != SourceRuntimeDeny {
		t.Errorf("Source = %q, want %q — an auditor reading the trail must be able to "+
			"tell a deliberate demotion from nobody having granted anything",
			after.Source, SourceRuntimeDeny)
	}
	if after.Binding == nil || after.Binding.Value != "alice@example.com" {
		t.Error("the decision does not carry the binding that caused it, so no operator " +
			"can find out which one to delete")
	}

	// And nobody else is touched.
	bob := &Subject{Sub: "sub-bob", Email: "bob@example.com"}
	if d := adminEmailResolver(t, runtime).Resolve(bob, Scope{}); d.Role != RoleNone ||
		d.Source != SourceDefaultRole {
		// bob matches nothing either way; what matters is *why*.
		if d.Source == SourceRuntimeDeny {
			t.Error("a deny naming alice also denied bob")
		}
	}
}

// TestRuntimeDenyBeatsEveryAllow: a deny does not compete on specificity. A
// runtime allow at a higher tier, or a stronger role, must not outvote it.
func TestRuntimeDenyBeatsEveryAllow(t *testing.T) {
	alice := &Subject{Sub: "sub-alice", Email: "alice@example.com", Groups: []string{"admins"}}
	scope := Scope{Project: "payments", Executor: "edge-1"}

	runtime := &staticRuntime{bindings: []Binding{
		// Deliberately ordered and tiered so that any ranking scheme other
		// than "deny wins outright" picks one of the allows.
		{Claim: ClaimGroup, Value: "admins", Role: RoleAdmin, Project: "payments", Executor: "edge-1"},
		{Claim: ClaimEmail, Value: "alice@example.com", Role: RoleMaintainer, Project: "payments"},
		{Claim: ClaimEmail, Value: "alice@example.com", Deny: true},
	}}
	d := adminEmailResolver(t, runtime).Resolve(alice, scope)
	if d.Role != RoleNone {
		t.Errorf("a global deny lost to a tier-3 allow: role = %s, want none", d.Role)
	}
}

// TestRuntimeAllowOverridesConfiguredBinding is the second half of the rule.
// A runtime binding shuts the configured layer out entirely — including a
// configured binding that is *more specific* — so that narrowing somebody
// without a redeploy actually narrows them.
func TestRuntimeAllowOverridesConfiguredBinding(t *testing.T) {
	alice := &Subject{Sub: "sub-alice", Email: "alice@example.com", Groups: []string{"engineers"}}
	scope := Scope{Project: "payments"}

	configured := []Binding{
		{Claim: ClaimGroup, Value: "engineers", Role: RoleMaintainer, Project: "payments"},
	}
	// Without the runtime layer the project-scoped config binding wins.
	if d := adminEmailResolver(t, nil, configured...).Resolve(alice, scope); d.Role != RoleMaintainer {
		t.Fatalf("precondition: configured binding resolved %s, want maintainer", d.Role)
	}

	runtime := &staticRuntime{bindings: []Binding{
		{Claim: ClaimEmail, Value: "alice@example.com", Role: RoleViewer},
	}}
	d := adminEmailResolver(t, runtime, configured...).Resolve(alice, scope)
	if d.Role != RoleViewer {
		t.Errorf("role = %s, want viewer — a global runtime binding must shut out the "+
			"configured layer, including a more specific binding in it", d.Role)
	}
	if d.Source != SourceRuntimeBinding {
		t.Errorf("Source = %q, want %q", d.Source, SourceRuntimeBinding)
	}
	if d.Allows(PermTaskMutate) {
		t.Error("the narrowed subject kept task.mutate, so the narrowing did not apply")
	}
}

// TestRuntimeBindingsRankAmongThemselves: within the runtime layer the
// ordinary tier-then-strength rule still applies, so a project-scoped runtime
// grant can narrow a global runtime grant just like it can in config.
func TestRuntimeBindingsRankAmongThemselves(t *testing.T) {
	alice := &Subject{Email: "alice@example.com"}
	runtime := &staticRuntime{bindings: []Binding{
		{Claim: ClaimEmail, Value: "alice@example.com", Role: RoleAdmin},
		{Claim: ClaimEmail, Value: "alice@example.com", Role: RoleViewer, Project: "payments"},
	}}
	r := adminEmailResolver(t, runtime)

	if d := r.Resolve(alice, Scope{Project: "billing"}); d.Role != RoleAdmin {
		t.Errorf("on an unpinned project, role = %s, want admin", d.Role)
	}
	if d := r.Resolve(alice, Scope{Project: "payments"}); d.Role != RoleViewer {
		t.Errorf("on the pinned project, role = %s, want viewer", d.Role)
	}
}

// TestScopedDenyIsScoped: `role revoke --project X` must withdraw authority on
// X and nowhere else. Without this the only usable deny would be the global
// one, and an operator reducing somebody's blast radius would take them off
// the hub entirely.
func TestScopedDenyIsScoped(t *testing.T) {
	alice := &Subject{Email: "alice@example.com"}
	runtime := &staticRuntime{bindings: []Binding{
		{Claim: ClaimEmail, Value: "alice@example.com", Deny: true, Project: "payments"},
	}}
	r := adminEmailResolver(t, runtime)

	if d := r.Resolve(alice, Scope{Project: "payments"}); d.Role != RoleNone {
		t.Errorf("on the denied project, role = %s, want none", d.Role)
	}
	if d := r.Resolve(alice, Scope{Project: "billing"}); d.Role != RoleAdmin {
		t.Errorf("on another project, role = %s, want admin — a project-scoped deny "+
			"withdrew authority everywhere", d.Role)
	}
	// A global request is not "some project", so a project-pinned deny must
	// not apply to it either; that is appliesTo's existing contract and the
	// deny path must not have its own reading of it.
	if d := r.Resolve(alice, Scope{}); d.Role != RoleAdmin {
		t.Errorf("globally, role = %s, want admin", d.Role)
	}
}

// TestDeniedByWorksWithoutConfiguredPolicy is why DeniedBy exists at all. A
// hub running on admin_emails alone never reaches Resolve — the request path
// takes an allow-all bypass — so the demotion has to be answerable without a
// configured policy, on exactly the older deployments most likely to have a
// long-lived admin list.
func TestDeniedByWorksWithoutConfiguredPolicy(t *testing.T) {
	runtime := &staticRuntime{bindings: []Binding{
		{Claim: ClaimEmail, Value: "alice@example.com", Deny: true},
	}}
	r, err := New(Config{Runtime: runtime})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if r.Configured() {
		t.Fatal("runtime bindings must not switch deny-by-default on — that turns a " +
			"targeted demotion into a lockout of everyone who matches no binding")
	}

	alice := &Subject{Email: "alice@example.com"}
	if b := r.DeniedBy(alice, Scope{}); b == nil {
		t.Error("DeniedBy found nothing on an unconfigured hub, so the emergency " +
			"demotion is missing on every pre-RBAC deployment")
	}
	if b := r.DeniedBy(&Subject{Email: "bob@example.com"}, Scope{}); b != nil {
		t.Errorf("DeniedBy denied bob with a binding naming alice: %+v", b)
	}
	if b := r.DeniedBy(nil, Scope{}); b != nil {
		t.Error("DeniedBy(nil) returned a binding")
	}
}

// TestDeniedByCopiesTheBinding: callers park the result in a Decision that
// outlives the source's slice, which the TTL cache replaces wholesale on every
// refresh. Handing out an interior pointer would let a later refresh mutate a
// decision already made.
func TestDeniedByCopiesTheBinding(t *testing.T) {
	runtime := &staticRuntime{bindings: []Binding{
		{Claim: ClaimEmail, Value: "alice@example.com", Deny: true},
	}}
	r := adminEmailResolver(t, runtime)
	got := r.DeniedBy(&Subject{Email: "alice@example.com"}, Scope{})
	if got == nil {
		t.Fatal("no deny found")
	}
	if got == &runtime.bindings[0] {
		t.Error("DeniedBy returned a pointer into the source's slice")
	}
	got.Value = "mutated"
	if runtime.bindings[0].Value != "alice@example.com" {
		t.Error("mutating the returned binding changed the source")
	}
}

// TestResolveReadsRuntimeSourceOnce: two reads in one decision could disagree
// if a write lands between them, producing a resolution matching neither the
// table before nor after.
func TestResolveReadsRuntimeSourceOnce(t *testing.T) {
	runtime := &staticRuntime{bindings: []Binding{
		{Claim: ClaimEmail, Value: "bob@example.com", Role: RoleViewer},
	}}
	adminEmailResolver(t, runtime).Resolve(&Subject{Email: "alice@example.com"}, Scope{})
	if runtime.calls != 1 {
		t.Errorf("Resolve read the runtime source %d times, want 1", runtime.calls)
	}
}

// TestNoRuntimeSourceIsUnchanged: every existing deployment has none, so the
// layer must be provably inert when absent.
func TestNoRuntimeSourceIsUnchanged(t *testing.T) {
	alice := &Subject{Email: "alice@example.com"}
	withNil := adminEmailResolver(t, nil).Resolve(alice, Scope{})
	withEmpty := adminEmailResolver(t, &staticRuntime{}).Resolve(alice, Scope{})

	if withNil.Role != RoleAdmin || withEmpty.Role != RoleAdmin {
		t.Errorf("roles = %s / %s, want admin for both", withNil.Role, withEmpty.Role)
	}
	if withNil.Source != withEmpty.Source || withNil.Source != SourceAdminEmail {
		t.Errorf("sources = %q / %q, want %q for both",
			withNil.Source, withEmpty.Source, SourceAdminEmail)
	}
	if r := adminEmailResolver(t, nil); r.RuntimeBindings() != nil {
		t.Error("RuntimeBindings() on a hub with no source returned non-nil")
	}
}

// TestNormalizeBindingCanonicalizes covers the identity rule storage depends
// on: the derived row id is computed from these values, so a difference here
// is a duplicate row, and a difference between this and matches() is a binding
// that reports success and matches nothing.
func TestNormalizeBindingCanonicalizes(t *testing.T) {
	cases := []struct {
		name string
		in   Binding
		want Binding
	}{
		{
			name: "email case is folded",
			in:   Binding{Claim: ClaimEmail, Value: "  Alice@Example.COM ", Role: RoleAdmin},
			want: Binding{Claim: ClaimEmail, Value: "alice@example.com", Role: RoleAdmin},
		},
		{
			name: "keycloak group paths lose the leading slash",
			in:   Binding{Claim: ClaimGroup, Value: "/Cloop-Admins", Role: RoleViewer},
			want: Binding{Claim: ClaimGroup, Value: "cloop-admins", Role: RoleViewer},
		},
		{
			name: "opaque subjects keep their case",
			in:   Binding{Claim: ClaimSub, Value: "AbC123", Role: RoleViewer},
			want: Binding{Claim: ClaimSub, Value: "AbC123", Role: RoleViewer},
		},
		{
			// Group paths lose a leading "/" because Keycloak emits them that
			// way. Subjects are compared exactly, so the same edit would turn
			// a binding an operator typed from an IdP console into one that
			// matches nobody.
			name: "opaque subjects keep a leading slash",
			in:   Binding{Claim: ClaimSub, Value: "/opaque-id", Role: RoleViewer},
			want: Binding{Claim: ClaimSub, Value: "/opaque-id", Role: RoleViewer},
		},
		{
			name: "a deny needs no role",
			in:   Binding{Claim: ClaimEmail, Value: "alice@example.com", Deny: true},
			want: Binding{Claim: ClaimEmail, Value: "alice@example.com", Role: RoleNone, Deny: true},
		},
		{
			name: "claim kind case is folded",
			in:   Binding{Claim: "EMAIL", Value: "a@b.c", Role: RoleViewer},
			want: Binding{Claim: ClaimEmail, Value: "a@b.c", Role: RoleViewer},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := NormalizeBinding(tc.in)
			if err != nil {
				t.Fatalf("NormalizeBinding: %v", err)
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("NormalizeBinding(%+v) = %+v, want %+v", tc.in, got, tc.want)
			}
		})
	}
}

// TestNormalizeBindingRejectsNonsense: a binding that cannot match is at its
// worst when it is a deny, because the command reports success and withdraws
// nothing.
func TestNormalizeBindingRejectsNonsense(t *testing.T) {
	cases := map[string]Binding{
		"unknown claim kind":       {Claim: "department", Value: "eng", Role: RoleViewer},
		"unknown role":             {Claim: ClaimEmail, Value: "a@b.c", Role: "superadmin"},
		"empty value":              {Claim: ClaimEmail, Value: "   ", Role: RoleViewer},
		"empty value on deny":      {Claim: ClaimEmail, Value: "", Deny: true},
		"missing role on an allow": {Claim: ClaimEmail, Value: "a@b.c"},
		// No scope the hub constructs carries both narrowings — projectScope
		// sets no Executor and executorScope deliberately sets no Project — so
		// this binding matches nothing. A deny that matches nothing is the
		// exact failure this validation exists to prevent: the CLI prints a
		// confident DENIED and the operator stops looking.
		"project and executor at once": {
			Claim: ClaimEmail, Value: "a@b.c", Deny: true,
			Project: "payments", Executor: "edge-1",
		},
		"sub value that is only a slash": {Claim: ClaimSub, Value: " / ", Deny: true},
	}
	for name, b := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := NormalizeBinding(b); err == nil {
				t.Errorf("NormalizeBinding(%+v) accepted an unusable binding", b)
			}
		})
	}
}

// TestRuntimeDenyOnGroupAndSubClaims: the demotion must work against whatever
// claim the provider actually releases. An organisation whose tokens carry no
// email has only sub and groups to name a person by.
func TestRuntimeDenyOnGroupAndSubClaims(t *testing.T) {
	for _, tc := range []struct {
		name    string
		binding Binding
		subject *Subject
	}{
		{"by subject", Binding{Claim: ClaimSub, Value: "sub-alice", Deny: true},
			&Subject{Sub: "sub-alice", Email: "alice@example.com"}},
		{"by group", Binding{Claim: ClaimGroup, Value: "contractors", Deny: true},
			&Subject{Sub: "s", Email: "alice@example.com", Groups: []string{"/contractors"}}},
		{"by idp role", Binding{Claim: ClaimRole, Value: "temp", Deny: true},
			&Subject{Sub: "s", Email: "alice@example.com", Roles: []string{"Temp"}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			nb, err := NormalizeBinding(tc.binding)
			if err != nil {
				t.Fatalf("NormalizeBinding: %v", err)
			}
			r := adminEmailResolver(t, &staticRuntime{bindings: []Binding{nb}})
			if d := r.Resolve(tc.subject, Scope{}); d.Role != RoleNone {
				t.Errorf("role = %s, want none", d.Role)
			}
		})
	}
}
