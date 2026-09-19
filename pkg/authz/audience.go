// audience.go is the gate half of this package.
//
// Everything else here is additive: a Binding grants a role, and resolving an
// identity means unioning every grant that matches it. That shape cannot
// express "this executor is available to these two groups and nobody else",
// because the permission being restricted — executor.manage, or simply the
// right to run work somewhere — is one the caller already holds fleet-wide.
// Adding grants cannot take it away, and narrowing a grant to one executor
// (Binding.Executor) restricts *that grant*, not the resource: every identity
// whose unscoped binding already covers the executor keeps reaching it.
//
// So an audience is a separate predicate, and it composes with the role ladder
// by intersection rather than union — see pkg/ui/executoraudience.go, which is
// the only enforcement point that matters. This file owns just the question
// "does this identity appear in this list", because the answer has to agree
// exactly with Binding.matches: an admin who writes a group path their IdP
// shows them expects it to work in both places, and two normalisers would
// eventually disagree about a leading slash or a letter case and produce a
// gate that admits someone the role model denies, or the reverse.
package authz

import "strings"

// AudienceMember is one entry in an executor's allowlist.
//
// Kind is deliberately the same ClaimKind the binding model uses rather than a
// private enum, so that the set of things an admin can name here can never
// drift from the set a role binding can name.
type AudienceMember struct {
	// Kind is ClaimGroup, ClaimRole, ClaimEmail or ClaimSub. The storage layer
	// and the UI speak of "user" and "group"; a "user" arrives here as either
	// ClaimEmail or ClaimSub depending on what the admin typed, which is
	// resolved by AudienceMemberFor.
	Kind ClaimKind `json:"kind"`
	// Value is the claim value to match, in whichever spelling the admin used.
	Value string `json:"value"`
}

// AudienceMemberFor turns the two-way UI vocabulary ("user" or "group", plus a
// typed value) into the claim this package matches on.
//
// A "user" is ambiguous at the point an admin types it: an IdP subject is an
// opaque identifier and an email is not, and which one they pasted is knowable
// only by looking. Guessing on the presence of "@" is the whole rule, and it is
// safe in both directions — an email compared as a subject fails closed, and a
// subject compared as an email fails closed too, because the comparison that
// would wrongly succeed is one where the two strings are equal anyway.
//
// An unrecognised kind yields the zero AudienceMember, which Admits never
// matches. That is the direction a gate must fail in: a row this binary cannot
// interpret restricts more than intended rather than less.
func AudienceMemberFor(kind, value string) AudienceMember {
	value = strings.TrimSpace(value)
	if value == "" {
		return AudienceMember{}
	}
	switch strings.ToLower(strings.TrimSpace(kind)) {
	case "group":
		return AudienceMember{Kind: ClaimGroup, Value: normalizeClaimValue(value)}
	case "role":
		return AudienceMember{Kind: ClaimRole, Value: normalizeClaimValue(value)}
	case "user":
		if strings.Contains(value, "@") {
			return AudienceMember{Kind: ClaimEmail, Value: value}
		}
		return AudienceMember{Kind: ClaimSub, Value: value}
	}
	return AudienceMember{}
}

// Admits reports whether s appears in the audience.
//
// An *empty* audience admits everyone. That is the opt-in property the whole
// feature rests on: an executor nobody has restricted behaves exactly as it did
// before audiences existed, so enabling this code path is a no-op for every
// existing deployment, and the first entry an admin adds is the act that turns
// the gate on. Callers that need to distinguish "unrestricted" from "restricted
// to a list that happens to admit this caller" ask len(members) instead — the
// two are different sentences in an audit trail even though they permit the
// same request.
//
// A nil subject is denied unless the audience is empty. A hub running without
// OIDC has no subjects at all, and there the audience is empty on every
// executor because there is no identity an admin could have named.
func Admits(members []AudienceMember, s *Subject) bool {
	if len(members) == 0 {
		return true
	}
	if s == nil {
		return false
	}
	for _, m := range members {
		// An empty value never matches, checked here rather than left to the
		// matcher below. Group and role claims compare through containsFold,
		// which has no emptiness guard — so a member with a blank value would
		// be admitted by any identity whose provider emits an empty string in
		// its group list, turning "restricted to one group" into "open to
		// anyone whose IdP is sloppy". The email and sub arms already guard
		// this; the set arms cannot without changing what a Binding means, and
		// a gate is the wrong place to discover that difference.
		if strings.TrimSpace(m.Value) == "" {
			continue
		}
		// Reuses the binding matcher rather than re-deriving it. The Binding
		// built here is never stored and carries no role: it exists so that the
		// comparison is literally the same code path, which is the only durable
		// way to keep this gate and the role model agreeing about what a claim
		// value means.
		if (Binding{Claim: m.Kind, Value: m.Value}).matches(s) {
			return true
		}
	}
	return false
}
