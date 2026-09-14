package ui

// The synchronous half of bounded authorization staleness (Task 20273).
//
// pkg/oidcauth owns the policy — how old claims may be, how to re-assert them,
// how to collapse a burst into one IdP round trip. pkg/authz owns which
// permissions demand it. This file is the join: it sits inside require(), runs
// for permissions above operator and nothing else, and turns a refusal into an
// HTTP response an administrator can act on.
//
// # What it must not become
//
// A per-request call to the identity provider. Three guards keep it off the hot
// path, and all three matter:
//
//	the permission     RequiresFreshClaims is false for every read, so a
//	                   dashboard poll never reaches this file at all
//	the freshness      EnsureFreshClaims returns immediately when the stored
//	                   claims are inside the bound, which they are for all but
//	                   the first privileged call in each max_claim_age window
//	the credential     an API token carries its own authority and its own
//	                   lifecycle (Task 20175); it has no session and no IdP
//	                   claims to refresh, so it is left alone
//
// # Why the decision is recomputed rather than reused
//
// The grant attached to a request was resolved from the claims the session held
// when the request arrived. If revalidation narrows them, that grant is a
// decision about who the caller used to be. Re-deriving from the refreshed
// identity is the entire point: a demotion has to reach the call it is racing,
// not the one after it.

import (
	"errors"
	"net/http"

	"github.com/blechschmidt/cloop/pkg/apierror"
	"github.com/blechschmidt/cloop/pkg/authz"
	"github.com/blechschmidt/cloop/pkg/logger"
	"github.com/blechschmidt/cloop/pkg/oidcauth"
)

// freshClaimGrant re-asserts the caller's claims when perm demands it.
//
// Returns the grant the decision should be made with — the request's own when
// nothing changed or nothing applied, a re-derived one when the provider
// narrowed the claims — or an error when current authority could not be
// established. The error case has already been logged; the caller renders it.
func (s *Server) freshClaimGrant(r *http.Request, perm authz.Permission) (*grant, error) {
	if !authz.RequiresFreshClaims(perm) || !s.oidcEnabled() {
		return nil, nil
	}
	if s.OIDC.MaxClaimAge() <= 0 {
		// The deployment opted out. Nothing to enforce, and nothing to spend.
		return nil, nil
	}
	g := s.grantFor(r)
	if g == nil || g.token != nil || g.subject == nil {
		// A PAT, a static deployment token, or an unauthenticated caller.
		// None of them holds IdP claims, so there is nothing here to refresh;
		// a PAT's staleness is bounded by its own expiry and by the owner
		// intersection in grant.decide.
		return nil, nil
	}
	rec, ok := s.OIDC.SessionFromRequest(r)
	if !ok {
		return nil, nil
	}

	fresh, err := s.OIDC.EnsureFreshClaims(r.Context(), rec.ID)
	if err != nil {
		return nil, err
	}
	if sameClaims(rec.Identity, fresh.Identity) {
		return g, nil
	}
	// Narrowed (or widened) at the provider. A new grant rather than a mutated
	// one: the old grant memoizes decisions per scope, and those were computed
	// under claims that no longer hold.
	return &grant{server: s, subject: subjectFromIdentity(&fresh.Identity)}, nil
}

// sameClaims reports whether two identities carry the same groups and roles.
//
// Order-sensitive on purpose. Both sides come from the same provider through
// the same decoder, so a reordering is not something a real IdP does between
// two responses — and treating an unexpected reordering as "changed" costs one
// grant rebuild, while treating a real change as "same" costs a privileged
// operation authorised on withdrawn claims.
func sameClaims(a, b oidcauth.Identity) bool {
	return equalStrings(a.Groups, b.Groups) && equalStrings(a.Roles, b.Roles)
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// writeClaimFreshnessError renders a refusal for a privileged action the hub
// could not establish current authority for.
//
// 403 rather than 503, deliberately. The action was refused, and it will keep
// being refused until something changes — a 503 invites a retry loop against an
// IdP that is already the problem. The body names the cause and the remedy
// because the alternative is an administrator reading "Forbidden" and going to
// edit role bindings that were never wrong.
func (s *Server) writeClaimFreshnessError(w http.ResponseWriter, r *http.Request, perm authz.Permission, err error) {
	if errors.Is(err, oidcauth.ErrSessionNotFound) {
		// The provider withdrew the grant during the check. The session is
		// already gone; say so rather than describing it as a permission
		// problem, which would send the user to the wrong place.
		apierror.WriteError(w, apierror.New(apierror.CodeUnauthorized,
			"your session has ended: the identity provider no longer recognises it. Sign in again."))
		return
	}

	details := map[string]any{"required_permission": string(perm)}
	var cf *oidcauth.ClaimFreshnessError
	if errors.As(err, &cf) {
		details["reason"] = cf.Reason
		details["claim_age_seconds"] = int64(cf.Age.Seconds())
		details["max_claim_age_seconds"] = int64(cf.Limit.Seconds())
	}

	// Logged at warn: on a healthy hub this never fires, and when it does the
	// operator is usually being told about it by a user rather than watching.
	s.log().Warn(logger.EventAuthz, 0,
		"refused a privileged action: the identity provider could not confirm the session's claims",
		map[string]interface{}{
			"permission": string(perm),
			"error":      err.Error(),
			"path":       r.URL.Path,
		})

	apierror.WriteError(w, apierror.New(apierror.CodeForbidden, err.Error()).WithDetails(details))
}
