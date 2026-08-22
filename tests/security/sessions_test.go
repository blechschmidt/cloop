package security

// Guarantee 8: enumerating and ending other people's sessions is an
// oversight-grade action (Task 20176).
//
// A session is the credential nearly every human request on a hosted hub
// arrives with, and it is the only one issued automatically, renewed
// implicitly, and held by a browser the operator does not control. Four
// properties matter, and they are checked in three places because each belongs
// where it can be asserted against the real thing rather than a reconstruction:
//
//	the cookie is not recoverable from the store
//	    pkg/oidcauth: TestOnlyTheHashIsStored — replays the stored identifier
//	    as a cookie and requires it to fail, so the property survives a change
//	    of hashing scheme.
//	    pkg/sessionstore: TestRefreshTokenIsEncryptedAtRest — greps the raw
//	    database file for the plaintext refresh token.
//
//	both clocks are enforced on the read path, not only by the janitor
//	    pkg/oidcauth: TestIdleTimeoutEndsSession, TestAbsoluteExpiryEndsSession
//	    — advance a synthetic clock, run no sweep, require the next request to
//	    be refused. A regression here produces no error anywhere and is
//	    invisible until an incident.
//
//	revocation takes effect on the next request
//	    pkg/ui: TestRevokedSessionIsRefusedOnNextRequest — over real HTTP,
//	    against a warmed cache, since a revocation that only works on a cold
//	    cache is not a revocation.
//
//	the IdP's refusal ends the session, its outage does not
//	    pkg/oidcauth: TestRefreshRejectionTerminatesSession,
//	    TestRefreshOutageKeepsSession.
//
// What is left for this file is the one property that is a fact about the role
// ladder rather than about any running server, and that would otherwise be
// asserted nowhere: that `session.admin` does not drift down a tier. Every
// check above assumes the session routes are unreachable below admin; if the
// permission were added to a lower role the individual behaviours would still
// hold while the blast radius of a compromised maintainer account changed
// materially — an operator who could only run tasks would gain the ability to
// enumerate who is signed in, from where, and to sign any of them out.

import (
	"testing"

	"github.com/blechschmidt/cloop/pkg/authz"
)

// TestSessionAdminIsAdminOnly pins the permission to the top of the ladder in
// both directions: admin must hold it (or nobody can terminate a session at
// all, and the kill switch is decorative), and nobody below may.
func TestSessionAdminIsAdminOnly(t *testing.T) {
	for _, role := range authz.AllRoles {
		holds := false
		for _, p := range role.Permissions() {
			if p == authz.PermSessionAdmin {
				holds = true
				break
			}
		}
		if role == authz.RoleAdmin && !holds {
			t.Error("admin does not hold session.admin — nobody can terminate a session")
		}
		if role != authz.RoleAdmin && holds {
			t.Errorf("role %q holds session.admin; enumerating and ending other people's "+
				"sessions is an oversight-grade action", role)
		}
	}
}

// TestSessionAdminIsDistinctFromUserManage guards the split itself.
//
// The two were deliberately separated: terminating a session is containment
// and changes nobody's standing rights, so the on-call operator who needs it at
// 3am should not also need the ability to rewrite role bindings. Collapsing
// them back into one permission — the tempting simplification — would silently
// undo that, which is why the distinction is asserted rather than assumed.
func TestSessionAdminIsDistinctFromUserManage(t *testing.T) {
	if authz.PermSessionAdmin == authz.PermUserManage {
		t.Fatal("session.admin and user.manage have collapsed into one permission; " +
			"ending a session must not require authority over role bindings")
	}
	seen := map[authz.Permission]bool{}
	for _, p := range authz.AllPermissions {
		if seen[p] {
			t.Errorf("permission %q appears twice in AllPermissions", p)
		}
		seen[p] = true
	}
	if !seen[authz.PermSessionAdmin] {
		t.Error("session.admin is missing from AllPermissions — config validation and " +
			"the /api/me payload enumerate that list, so an absent permission is " +
			"one the frontend can never gate on")
	}
}
