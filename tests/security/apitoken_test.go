package security

// Guarantee 7: an API token cannot exceed the authority it was granted
// (Task 20175).
//
// A PAT is the only credential in cloop that can *create another credential*.
// That makes it the one place where a containment failure compounds: a token
// that could mint a stronger token would let any holder of the weakest useful
// role walk up to admin in two calls, and the audit trail would show nothing
// but two ordinary creations.
//
// So there are three distinct things to assert, and they fail in different
// ways:
//
//  1. A token's *permission set* is exactly what its roles bundle — not the
//     allow-all decision that a hub with RBAC inactive hands to everyone else.
//     Broken, this looks like a working token that happens to be able to do
//     more than the operator intended, which nothing surfaces.
//  2. A token cannot *mint* roles its holder does not have. Broken, this is
//     silent privilege escalation.
//  3. A token cannot mint outside its own project scope. Broken, a credential
//     issued for one tenant becomes a credential for all of them.
//
// The first is checked against every role in the ladder rather than a
// representative sample, because the interesting failures are at the edges —
// the strongest role that should still be refused something, and the weakest
// that should still be allowed something.

import (
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/apitoken"
	"github.com/blechschmidt/cloop/pkg/authz"
)

// TestTokenPermissionsAreExactlyItsRoles asserts property 1 across the whole
// ladder: for every role, a token carrying it must hold precisely that role's
// permissions — no more (escalation) and no fewer (a credential that silently
// stops working).
func TestTokenPermissionsAreExactlyItsRoles(t *testing.T) {
	now := time.Now()

	for _, role := range authz.AllRoles {
		if role == authz.RoleNone {
			continue
		}
		t.Run(string(role), func(t *testing.T) {
			tok := &apitoken.Token{Name: "t", Roles: []string{string(role)}}
			d := tok.Decision(authz.GlobalScope, now)

			granted := map[authz.Permission]bool{}
			for _, p := range role.Permissions() {
				granted[p] = true
			}
			for _, p := range authz.AllPermissions {
				got := d.Allows(p)
				if got != granted[p] {
					verb := "was denied"
					if got {
						verb = "was granted"
					}
					t.Errorf("a %q token %s %q; role %q grants %v",
						role, verb, p, role, role.Permissions())
				}
			}
		})
	}
}

// TestTokenNeverInheritsAllowAll is the specific regression that makes the
// whole feature safe on single-tenant hubs.
//
// With OIDC off, cloop grants every request everything — that is the
// deliberate local-use behaviour. A token's decision must not be computed that
// way, or the narrowest credential cloop can issue would become the broadest
// one on exactly the deployments most likely to hand a token to CI.
func TestTokenNeverInheritsAllowAll(t *testing.T) {
	now := time.Now()
	viewer := &apitoken.Token{Name: "ci", Roles: []string{"viewer"}}
	d := viewer.Decision(authz.GlobalScope, now)

	// The allow-all decision answers true for everything, including
	// permissions it was never asked about. A role-derived one does not.
	for _, p := range []authz.Permission{
		authz.PermRunStart, authz.PermTaskMutate, authz.PermProjectWrite,
		authz.PermConfigWrite, authz.PermSecretGrant, authz.PermSecretRevoke,
		authz.PermExecutorManage, authz.PermAuditRead, authz.PermUserManage,
		authz.PermTokenAdmin,
	} {
		if d.Allows(p) {
			t.Errorf("a viewer token holds %q — it inherited an allow-all decision", p)
		}
	}
	if d.Source != authz.SourceAPIToken {
		t.Errorf("Source = %q, want %q — a token must not be recorded as a bypass",
			d.Source, authz.SourceAPIToken)
	}
	if d.Role == authz.RoleAdmin {
		t.Error("a viewer token resolved to the admin role")
	}
}

// TestTokenCannotMintBeyondItsOwnRoles asserts property 2 exhaustively: for
// every (minter role, requested role) pair in the ladder, delegation is
// permitted exactly when the requested role's permissions are a subset of the
// minter's.
//
// Expressed as a subset check rather than a rank comparison on purpose. Rank
// is a property of today's ladder; the subset relation is what the rule
// actually means, so this test keeps holding if a future role is added off the
// ladder — and it would catch a role added *to* the ladder in the wrong place.
func TestTokenCannotMintBeyondItsOwnRoles(t *testing.T) {
	for _, minter := range authz.AllRoles {
		if minter == authz.RoleNone {
			continue
		}
		delegator := apitoken.Delegator{
			Decision: authz.FromRoles([]authz.Role{minter},
				authz.SourceAPIToken, "minter", authz.GlobalScope),
		}
		held := map[authz.Permission]bool{}
		for _, p := range minter.Permissions() {
			held[p] = true
		}

		for _, requested := range authz.AllRoles {
			if requested == authz.RoleNone {
				continue
			}
			// Allowed exactly when every permission the requested role grants
			// is one the minter already holds.
			wantAllowed := true
			for _, p := range requested.Permissions() {
				if !held[p] {
					wantAllowed = false
					break
				}
			}

			t.Run(string(minter)+"→"+string(requested), func(t *testing.T) {
				err := apitoken.CheckDelegation(delegator, []string{string(requested)}, nil)
				if wantAllowed && err != nil {
					t.Fatalf("a %q token could not mint a %q token, but %q's permissions "+
						"are a subset of its own: %v", minter, requested, requested, err)
				}
				if !wantAllowed && err == nil {
					t.Fatalf("PRIVILEGE ESCALATION: a %q token minted a %q token. "+
						"%q grants permissions %q does not hold.",
						minter, requested, requested, minter)
				}
			})
		}
	}
}

// TestTokenCannotSmuggleARoleInAMultiRoleRequest closes the obvious bypass of
// the rule above: asking for a permitted role and a forbidden one together.
// The check must apply to every entry, not just the first.
func TestTokenCannotSmuggleARoleInAMultiRoleRequest(t *testing.T) {
	operator := apitoken.Delegator{
		Decision: authz.FromRoles([]authz.Role{authz.RoleOperator},
			authz.SourceAPIToken, "op", authz.GlobalScope),
	}

	for _, roles := range [][]string{
		{"viewer", "admin"},
		{"admin", "viewer"},
		{"viewer", "operator", "maintainer"},
		{"operator", "operator", "admin"},
	} {
		t.Run(strings.Join(roles, "+"), func(t *testing.T) {
			if err := apitoken.CheckDelegation(operator, roles, nil); err == nil {
				t.Fatalf("PRIVILEGE ESCALATION: an operator token minted %v", roles)
			}
		})
	}
}

// TestTokenCannotWidenItsProjectScope asserts property 3. The minter is an
// *admin* token deliberately: role strength must not buy scope, or "scoped to
// one project" would be advisory for anyone strong enough to ignore it.
func TestTokenCannotWidenItsProjectScope(t *testing.T) {
	scoped := apitoken.Delegator{
		Decision: authz.FromRoles([]authz.Role{authz.RoleAdmin},
			authz.SourceAPIToken, "scoped-admin", authz.GlobalScope),
		ProjectScope: []string{"payments"},
	}

	refused := [][]string{
		nil,                        // every project
		{},                         // every project, spelled differently
		{"billing"},                // a different project
		{"payments", "billing"},    // its own plus one more
		{"PAYMENTS", "..", "/etc"}, // case tricks and path escapes
	}
	for _, scope := range refused {
		t.Run("refuse "+strings.Join(scope, ",")+"|", func(t *testing.T) {
			if err := apitoken.CheckDelegation(scoped, []string{"viewer"}, scope); err == nil {
				t.Fatalf("SCOPE ESCALATION: a token scoped to [payments] minted one scoped to %v", scope)
			}
		})
	}

	// Its own scope, and case-insensitive matches of it, are fine — an
	// operator writing "Payments" must not be silently refused.
	for _, scope := range [][]string{{"payments"}, {"PAYMENTS"}, {" payments "}} {
		t.Run("allow "+strings.Join(scope, ","), func(t *testing.T) {
			normalized, err := apitoken.NormalizeProjectScope(scope)
			if err != nil {
				t.Fatalf("NormalizeProjectScope: %v", err)
			}
			if err := apitoken.CheckDelegation(scoped, []string{"viewer"}, normalized); err != nil {
				t.Fatalf("minting inside its own scope was refused: %v", err)
			}
		})
	}
}

// TestScopedTokenIsDeniedOutOfScopeProjectsRegardlessOfRole is the runtime
// half of property 3: not what a token may *mint*, but what it may *reach*.
func TestScopedTokenIsDeniedOutOfScopeProjectsRegardlessOfRole(t *testing.T) {
	now := time.Now()
	for _, role := range authz.AllRoles {
		if role == authz.RoleNone {
			continue
		}
		t.Run(string(role), func(t *testing.T) {
			tok := &apitoken.Token{
				Roles:        []string{string(role)},
				ProjectScope: []string{"payments"},
			}
			out := tok.Decision(authz.Scope{Project: "billing", ProjectPath: "/srv/billing"}, now)
			if got := out.Permissions(); len(got) != 0 {
				t.Fatalf("a %q token scoped to [payments] holds %v on project billing", role, got)
			}
			// And the in-scope project still works, so the deny above is
			// caused by the scope and not by the token being inert.
			in := tok.Decision(authz.Scope{Project: "payments", ProjectPath: "/srv/payments"}, now)
			if !in.Allows(authz.PermProjectRead) {
				t.Fatalf("a %q token cannot read its own in-scope project", role)
			}
		})
	}
}

// TestRevokedOrExpiredTokenHoldsNothing pins the lifecycle half: a withdrawn
// credential must resolve to an empty permission set, not merely be refused at
// the authentication layer. Defence in depth — if a future code path ever
// reaches Decision without going through Verify, it must still deny.
func TestRevokedOrExpiredTokenHoldsNothing(t *testing.T) {
	now := time.Now()
	cases := map[string]*apitoken.Token{
		"revoked": {Roles: []string{"admin"}, RevokedAt: now.Add(-time.Second)},
		"expired": {Roles: []string{"admin"}, ExpiresAt: now.Add(-time.Second)},
		"expires exactly now": {
			Roles:     []string{"admin"},
			ExpiresAt: now,
		},
		"unknown role only": {Roles: []string{"root"}},
		"no roles":          {Roles: nil},
	}
	for name, tok := range cases {
		t.Run(name, func(t *testing.T) {
			if got := tok.Decision(authz.GlobalScope, now).Permissions(); len(got) != 0 {
				t.Fatalf("a %s token holds %v, want nothing", name, got)
			}
		})
	}
}

// TestTokenAdminIsAdminOnly guards the route-level half of the rule. Every
// containment property above assumes the mint endpoint is unreachable below
// admin; if `token.admin` were ever added to a lower tier, the delegation
// checks would still hold but the blast radius of a compromised maintainer
// account would change materially.
func TestTokenAdminIsAdminOnly(t *testing.T) {
	for _, role := range authz.AllRoles {
		holds := false
		for _, p := range role.Permissions() {
			if p == authz.PermTokenAdmin {
				holds = true
				break
			}
		}
		if role == authz.RoleAdmin && !holds {
			t.Error("admin does not hold token.admin — nobody can mint a token")
		}
		if role != authz.RoleAdmin && holds {
			t.Errorf("role %q holds token.admin; minting an identity is an admin-grade action", role)
		}
	}
}
