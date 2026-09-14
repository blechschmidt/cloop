package authz

// Which permissions may not be exercised on stale claims (Task 20273).
//
// pkg/oidcauth can bound how old a session's group and role claims are, and it
// cannot decide *when* that bound should be enforced — that is an authorization
// question, and this is the package that answers those. The split is the same
// one Config.EffectiveRole already uses in the other direction.
//
// # Why this is derived and not a list
//
// The obvious implementation is a set literal naming secret.grant, user.manage,
// token.admin, session.admin, executor.manage and config.write. It would be
// wrong within one release. Every new permission added above the operator tier
// would default to *not* requiring fresh claims, silently, and the omission
// would be invisible until an incident — the failure mode where a security
// control quietly stops covering the thing it was written for.
//
// Deriving it from the ladder inverts that. A new permission is covered unless
// somebody deliberately grants it to an operator, which is a visible decision in
// rolePermissions with its own review. The rule is one sentence an operator can
// hold: anything an operator cannot do needs claims the IdP has confirmed
// recently.
//
// # Why the operator tier is the line
//
// It is where authority stops being about *this* project's work and starts
// being about the hub. An operator starts and stops runs and edits tasks — real
// power, bounded by a project, and exercised constantly, so putting a
// synchronous IdP round trip in front of it would put the provider's
// availability on the path of ordinary work. A maintainer brokers credentials
// and rewrites project configuration; an admin rewrites who everybody is. Those
// are rare, deliberate, and exactly the actions somebody performs in the
// minutes after being removed from a group.
//
// Reads are on the allowed side by construction, because viewer and operator
// hold them — which is what keeps the authenticated hot path free of any of
// this. See pkg/oidcauth/bench_test.go.

// RequiresFreshClaims reports whether exercising p demands a claim set the
// identity provider has confirmed within the deployment's max_claim_age.
//
// True for every permission an operator does not hold. PermPublic is false: it
// marks a route with no authorization at all, and a login page that contacted
// the IdP before rendering would be a denial of service with extra steps.
func RequiresFreshClaims(p Permission) bool {
	if p == PermPublic || p == "" {
		return false
	}
	_, heldByOperator := operatorPermissions[p]
	return !heldByOperator
}

// operatorPermissions is the operator tier as a set, built once from the same
// rolePermissions table the resolver uses.
//
// Built from that table rather than restated so the two cannot drift: a
// permission moved into or out of the operator tier changes what needs fresh
// claims in the same edit, which is the only way this stays true without
// anybody remembering it does.
var operatorPermissions = func() map[Permission]struct{} {
	set := make(map[Permission]struct{}, len(rolePermissions[RoleOperator]))
	for _, p := range rolePermissions[RoleOperator] {
		set[p] = struct{}{}
	}
	return set
}()

// FreshClaimPermissions returns every permission that requires fresh claims,
// in the order AllPermissions declares them.
//
// For documentation and for the `cloop hub doctor` line that tells an operator
// what the bound actually covers on their build — a list they would otherwise
// have to reconstruct by hand from two tables.
func FreshClaimPermissions() []Permission {
	out := make([]Permission, 0, len(AllPermissions))
	for _, p := range AllPermissions {
		if RequiresFreshClaims(p) {
			out = append(out, p)
		}
	}
	return out
}
