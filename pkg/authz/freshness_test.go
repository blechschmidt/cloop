package authz

import "testing"

// TestRequiresFreshClaimsCoversTheNamedPermissions pins the six permissions
// Task 20273 was written about.
//
// They are asserted by name even though the implementation derives the set from
// the role ladder, because the derivation is the mechanism and these are the
// requirement. If somebody later grants one of them to the operator tier, the
// derived set silently stops covering it — and this test is what turns that
// into a failing build rather than a quiet loss of the control.
func TestRequiresFreshClaimsCoversTheNamedPermissions(t *testing.T) {
	for _, p := range []Permission{
		PermSecretGrant,
		PermSecretRevoke,
		PermUserManage,
		PermTokenAdmin,
		PermSessionAdmin,
		PermExecutorManage,
		PermConfigWrite,
	} {
		if !RequiresFreshClaims(p) {
			t.Errorf("RequiresFreshClaims(%q) = false — this permission may be "+
				"exercised on claims the IdP has not confirmed", p)
		}
	}
}

// TestRequiresFreshClaimsSparesTheOperatorTier is the other half: everything an
// operator holds is ordinary work, exercised constantly, and putting a
// synchronous IdP round trip in front of it would put the provider's
// availability on the path of running a plan.
func TestRequiresFreshClaimsSparesTheOperatorTier(t *testing.T) {
	for _, p := range rolePermissions[RoleOperator] {
		if RequiresFreshClaims(p) {
			t.Errorf("RequiresFreshClaims(%q) = true, but an operator holds it — "+
				"ordinary work must not depend on reaching the identity provider", p)
		}
	}
	// Reads specifically, since "read paths stay on the background cadence" is
	// the load-bearing claim of the whole design.
	for _, p := range []Permission{PermProjectRead, PermExecutorRead, PermViewPrefs} {
		if RequiresFreshClaims(p) {
			t.Errorf("RequiresFreshClaims(%q) = true: a read must never contact the IdP", p)
		}
	}
	if RequiresFreshClaims(PermPublic) {
		t.Error("PermPublic marks an unguarded route; gating it would make the " +
			"login page depend on the IdP being reachable twice over")
	}
	if RequiresFreshClaims("") {
		t.Error("the empty permission must not require anything")
	}
}

// TestFreshClaimPermissionsPartitionsTheLadder checks the set is exactly the
// complement of the operator tier over AllPermissions — no permission is
// missing from both sides, which is what would happen if AllPermissions and
// rolePermissions ever drifted.
func TestFreshClaimPermissionsPartitionsTheLadder(t *testing.T) {
	fresh := map[Permission]bool{}
	for _, p := range FreshClaimPermissions() {
		fresh[p] = true
	}
	for _, p := range AllPermissions {
		if p == PermPublic {
			continue
		}
		_, operator := operatorPermissions[p]
		if operator == fresh[p] {
			t.Errorf("permission %q is %v for the operator tier and %v for fresh claims; "+
				"every permission must be in exactly one of the two", p, operator, fresh[p])
		}
	}
	// A permission an operator holds that AllPermissions does not list would
	// make FreshClaimPermissions silently incomplete.
	all := map[Permission]bool{}
	for _, p := range AllPermissions {
		all[p] = true
	}
	for p := range operatorPermissions {
		if !all[p] {
			t.Errorf("operator holds %q, which AllPermissions does not list", p)
		}
	}
}
