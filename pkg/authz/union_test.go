package authz

import "testing"

// unionInputs is every shape a decision takes on the hub: nothing, each rung
// of the ladder from a binding, a membership, and the two allow-all bypasses.
func unionInputs(scope Scope) []Decision {
	return []Decision{
		Deny(SourceDefaultRole, "nobody", scope),
		FromRoles([]Role{RoleViewer}, SourceBinding, "viewer", scope),
		FromRoles([]Role{RoleOperator}, SourceBinding, "operator", scope),
		FromRoles([]Role{RoleMaintainer}, SourceProjectMember, "maintainer", scope),
		FromRoles([]Role{RoleAdmin}, SourceBinding, "admin", scope),
		AllowAll(SourceAuthzDisabled, "local"),
	}
}

// TestUnionNeverDemotes is the property memberships rest on (Task 20366):
// admitting somebody to a project must never take away anything they held, and
// must never grant anything neither side granted.
func TestUnionNeverDemotes(t *testing.T) {
	scope := Scope{Project: "p", ProjectPath: "/srv/p"}
	for _, a := range unionInputs(scope) {
		for _, b := range unionInputs(scope) {
			got := Union(a, b)
			for _, p := range AllPermissions {
				if (a.Allows(p) || b.Allows(p)) && !got.Allows(p) {
					t.Errorf("Union(%s/%s, %s/%s) drops %q", a.Role, a.Source, b.Role, b.Source, p)
				}
				if got.Allows(p) && !a.Allows(p) && !b.Allows(p) {
					t.Errorf("Union(%s, %s) grants %q, which neither side grants", a.Role, b.Role, p)
				}
			}
			if !got.Role.AtLeast(a.Role) || !got.Role.AtLeast(b.Role) {
				t.Errorf("Union(%s, %s).Role = %s, below one of its inputs", a.Role, b.Role, got.Role)
			}
		}
	}
}

// TestUnionNamesTheDecidingGrant: the audit trail must say which grant let the
// caller in. When the membership is what raised the answer, that is the
// membership; when the caller's own binding already sufficed, it is the
// binding — and the scope is always the one that was asked about.
func TestUnionNamesTheDecidingGrant(t *testing.T) {
	scope := Scope{Project: "p", ProjectPath: "/srv/p"}
	binding := &Binding{Claim: ClaimGroup, Value: "eng", Role: RoleViewer}
	viewer := FromRoles([]Role{RoleViewer}, SourceBinding, "bob@example.com", scope)
	viewer.Binding = binding
	member := FromRoles([]Role{RoleOperator}, SourceProjectMember, "bob@example.com", Scope{ProjectPath: "/srv/p"})

	got := Union(viewer, member)
	if got.Role != RoleOperator || got.Source != SourceProjectMember || got.Binding != nil {
		t.Errorf("membership raised the answer but the decision reads role=%s source=%s binding=%v",
			got.Role, got.Source, got.Binding)
	}
	if got.Scope != scope {
		t.Errorf("Union replaced the scope asked about: %+v", got.Scope)
	}
	if !got.Allows(PermRunStart) || got.Allows(PermProjectWrite) {
		t.Errorf("an operator membership over a viewer binding decides %v", got.Permissions())
	}

	admin := FromRoles([]Role{RoleAdmin}, SourceBinding, "bob@example.com", scope)
	if got := Union(admin, member); got.Source != SourceBinding || got.Role != RoleAdmin {
		t.Errorf("an admin who is also a member is decided by %s/%s, want the binding", got.Source, got.Role)
	}
	none := Union(Deny(SourceDefaultRole, "x", scope), Deny(SourceProjectMember, "x", scope))
	if none.Role != RoleNone || len(none.Permissions()) != 0 {
		t.Errorf("a union of two denials grants %s %v", none.Role, none.Permissions())
	}
}

// TestAtLeastFollowsTheLadder pins the comparison the membership ceiling uses.
func TestAtLeastFollowsTheLadder(t *testing.T) {
	for i, r := range AllRoles {
		for j, o := range AllRoles {
			if got, want := r.AtLeast(o), i >= j; got != want {
				t.Errorf("%s.AtLeast(%s) = %v, want %v", r, o, got, want)
			}
		}
	}
	if Role("owner").AtLeast(RoleNone) || RoleAdmin.AtLeast(Role("superuser")) {
		t.Error("an unknown role compared as a position on the ladder")
	}
}

// TestProjectShareIsMaintainerAndUp: sharing a project is a maintainer's
// decision, and nothing below it may make it.
func TestProjectShareIsMaintainerAndUp(t *testing.T) {
	for _, r := range AllRoles {
		want := r.AtLeast(RoleMaintainer)
		if got := FromRoles([]Role{r}, SourceBinding, "x", GlobalScope).Allows(PermProjectShare); got != want {
			t.Errorf("%s holds project.share = %v, want %v", r, got, want)
		}
	}
}
