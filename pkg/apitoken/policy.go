package apitoken

// The anti-escalation rule.
//
// Holding token.admin is what lets a caller mint at all. It is deliberately
// *not* what decides which token they may mint — otherwise the permission
// would be a universal privilege ladder: one admin-granted capability that
// manufactures any authority the hub can express, including for a caller whose
// own role was narrowed on purpose.
//
// So minting is modelled as delegation, not creation. A token may carry
// authority its minter already holds and nothing else. That makes the rule
// stable under future changes to the role ladder — it compares permission
// sets, not role names — and it composes: a PAT that holds token.admin can
// mint further tokens, and each generation is bounded by the last, so no chain
// of delegations ever ends up stronger than the human at the start of it.

import (
	"fmt"
	"strings"

	"github.com/blechschmidt/cloop/pkg/authz"
)

// Delegator is the authority a new token is being minted from.
type Delegator struct {
	// Decision is the minter's own resolved authority, evaluated at the
	// global scope. Global rather than per-project because a token is a
	// fleet-level object: it is not created "inside" a project, and
	// resolving against one would let a caller who is maintainer on a single
	// project mint a hub-wide maintainer credential.
	Decision authz.Decision

	// ProjectScope is non-empty when the minter is itself a project-scoped
	// token. A scoped minter may only issue tokens at least as narrow.
	ProjectScope []string

	// Unrestricted marks a caller whose authority is not expressible as a
	// permission set — the OIDC-disabled local operator, and the static
	// bearer token. Both already act as the deployment itself, so bounding
	// them against their own (allow-all) decision would be theatre. Recorded
	// as a distinct flag rather than inferred, so the bypass is visible at
	// every call site instead of hiding inside an allow-all Decision.
	Unrestricted bool
}

// CheckDelegation reports whether the delegator may mint a token carrying
// roles and projectScope.
//
// Both inputs are the *normalized* forms (NormalizeRoles / NormalizeProjectScope);
// callers run those first so a validation error is reported as a bad request
// rather than as a permission denial.
//
// The error text names the specific permission or project that was refused.
// That is safe to return: it describes the caller's own authority, which they
// can already read from /api/me, and withholding it produces the worst kind of
// security UX — a 403 with no way to discover what would have worked.
func CheckDelegation(d Delegator, roles []string, projectScope []string) error {
	if err := checkRoleDelegation(d, roles); err != nil {
		return err
	}
	return checkScopeDelegation(d, projectScope)
}

func checkRoleDelegation(d Delegator, roles []string) error {
	if d.Unrestricted {
		return nil
	}
	for _, name := range roles {
		role, ok := authz.ParseRole(name)
		if !ok {
			return fmt.Errorf("%q is not a known role", name)
		}
		for _, perm := range role.Permissions() {
			if !d.Decision.Allows(perm) {
				return fmt.Errorf(
					"cannot mint a token with role %q: it grants %q, which your own role (%s) does not hold",
					role, perm, orNone(d.Decision.Role))
			}
		}
	}
	return nil
}

// checkScopeDelegation enforces that a scoped minter cannot widen its reach.
//
// A minter with no scope may issue any scope. A minter *with* a scope must
// issue a non-empty one — an empty scope means "every project", which is
// exactly the widening this prevents — and every project it names must be one
// the minter can already address.
func checkScopeDelegation(d Delegator, projectScope []string) error {
	if len(d.ProjectScope) == 0 {
		return nil
	}
	if len(projectScope) == 0 {
		return fmt.Errorf(
			"cannot mint an unscoped token: your own token is limited to %s, so the token you create must name projects from that set",
			strings.Join(d.ProjectScope, ", "))
	}
	allowed := &Token{ProjectScope: d.ProjectScope}
	for _, want := range projectScope {
		// Compare against both identifier forms, since a scope entry may be
		// a registry name or a filesystem path and the minter's list may use
		// the other one for the same project.
		if !allowed.AllowsProject(want, want) {
			return fmt.Errorf(
				"cannot mint a token scoped to %q: your own token is limited to %s",
				want, strings.Join(d.ProjectScope, ", "))
		}
	}
	return nil
}

func orNone(r authz.Role) authz.Role {
	if r == "" {
		return authz.RoleNone
	}
	return r
}
