package ui

import (
	"net/http"

	"github.com/blechschmidt/cloop/pkg/apierror"
	"github.com/blechschmidt/cloop/pkg/authz"
	"github.com/blechschmidt/cloop/pkg/secretbroker"
)

// Personal secrets in the hub's HTTP layer (Task 20275).
//
// The broker owns the ownership rule — who may see, spend and delete a secret
// that belongs to one person. This file owns the two things the broker
// deliberately does not know:
//
//   - which identity the request is acting as, and
//   - whether that identity additionally holds the organisation-level
//     authority (secret.grant / secret.revoke) over the shared secrets that
//     were the only kind before this feature.
//
// The split matters because the secrets routes now admit operators, who hold
// secret.own and nothing else. Before, the route permission was the whole
// answer: everything past the gate was a maintainer, so every handler could
// show every row. Now the gate is a floor, and each handler narrows below it.
// Getting that wrong in the widening direction would hand an operator the
// inventory of the organisation's credentials, so the narrowing is written
// once, here, and pinned by TestSecretsRoutesNarrowOperatorsToTheirOwn.

// secretViewer builds the broker viewer for this request.
//
// Identity is the same OwnerKey the rest of the hub's per-user features key on
// — a lowercased email, or "sub:<subject>" when the IdP releases no email — so
// that a user's personal secrets, their Claude Code login and their project
// memberships all agree about who they are.
//
// It is empty on a single-user hub with no OIDC, and that is correct rather
// than a gap: with one dashboard and one person there is nobody to be personal
// *from*, every secret is already theirs, and the shared model is the right
// one. The mint path refuses to create a personal secret without an identity
// rather than silently minting a shared one (see secretbroker.ErrOwnerRequired).
func (s *Server) secretViewer(r *http.Request) secretbroker.Viewer {
	return secretbroker.Viewer{
		Identity: secretbroker.NormalizeOwner(s.recipientIdentity(r).OwnerKey()),
		Admin:    s.holdsPersonalSecretAdmin(r),
	}
}

// holdsPersonalSecretAdmin reports whether the caller may see and destroy other
// people's personal secrets.
//
// Gated on PermUserManage — admin-only — rather than on secret.grant, and the
// choice is deliberate. secret.grant sits at maintainer and is authority over
// the organisation's credentials; it should not silently become authority over
// every developer's private ones, or "maintainer" would quietly mean "may read
// the inventory of everyone's personal GitHub tokens". PermUserManage is the
// permission that already means administering people — provisioning them,
// binding their roles, and offboarding them — which is the one job that
// genuinely requires reaching a departed colleague's credentials.
//
// It confers visibility and deletion only. No permission in the ladder lets one
// identity *spend* another's personal secret; that is enforced in the broker by
// Secret.SpendableBy, which ignores this flag entirely.
func (s *Server) holdsPersonalSecretAdmin(r *http.Request) bool {
	return s.permissionsFor(r, authz.GlobalScope).Allows(authz.PermUserManage)
}

// holdsSharedSecretRead reports whether the caller may see the organisation's
// shared secrets and the grants over them.
//
// This is the narrowing that the lowered route floor makes necessary. The
// reasoning GET /api/secrets was gated on secret.grant for has not changed —
// which credentials exist, who holds them and what each may reach is
// reconnaissance — so an operator admitted by secret.own sees their own rows
// and no others.
func (s *Server) holdsSharedSecretRead(r *http.Request) bool {
	return s.permissionsFor(r, authz.GlobalScope).Allows(authz.PermSecretGrant)
}

// holdsSharedSecretWrite reports whether the caller may create or hand out the
// organisation's shared secrets: minting an unowned secret, and granting one.
func (s *Server) holdsSharedSecretWrite(r *http.Request) bool {
	return s.permissionsFor(r, authz.GlobalScope).Allows(authz.PermSecretGrant)
}

// holdsSharedSecretDelete reports whether the caller may destroy a shared
// secret or revoke a grant over one. Separate from the write check because the
// role ladder separates them: an operator can be given secret.revoke to pull a
// leaked credential without secret.grant to issue one.
func (s *Server) holdsSharedSecretDelete(r *http.Request) bool {
	return s.permissionsFor(r, authz.GlobalScope).Allows(authz.PermSecretRevoke)
}

// visibleSecrets filters secrets down to what this caller may see: their own
// personal ones always, everyone's personal ones if they administer users, and
// the shared ones only with the organisation-level read permission.
//
// The broker has already applied the ownership half through ListSecretsFor;
// this applies the half the broker deliberately does not know about.
func (s *Server) visibleSecrets(r *http.Request, in []secretbroker.Secret) []secretbroker.Secret {
	if s.holdsSharedSecretRead(r) {
		return in
	}
	out := in[:0:0]
	for _, sec := range in {
		if sec.Personal() {
			out = append(out, sec)
		}
	}
	return out
}

// visibleGrants is visibleSecrets for grant rows, which carry the owner
// denormalised for exactly this purpose.
func (s *Server) visibleGrants(r *http.Request, in []secretbroker.Grant) []secretbroker.Grant {
	if s.holdsSharedSecretRead(r) {
		return in
	}
	out := in[:0:0]
	for _, g := range in {
		if g.Personal() {
			out = append(out, g)
		}
	}
	return out
}

// denySharedSecret writes the 403 for an operator reaching past their own
// secrets into the organisation's, with the permission they lack named so the
// message is actionable rather than merely negative.
func denySharedSecret(w http.ResponseWriter, perm authz.Permission, what string) {
	apierror.WriteError(w, apierror.New(apierror.CodeForbidden,
		"this is a shared secret: "+what+" requires "+string(perm)+
			". Personal secrets you own are yours to manage."))
}
