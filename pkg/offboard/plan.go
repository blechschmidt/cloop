// Identity resolution and blast-radius planning.
//
// Everything here runs before a single row is written, and --dry-run stops
// after it. That split is deliberate: the operator sees exactly the set the
// write will act on, because it *is* the set the write acts on.

package offboard

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/blechschmidt/cloop/pkg/apitoken"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// BuildPlan resolves the identity and collects every surface it holds.
func BuildPlan(o Options) (Plan, error) {
	if o.DB == nil {
		return Plan{}, fmt.Errorf("offboard: nil database")
	}
	input := strings.TrimSpace(o.Identity)
	if input == "" {
		return Plan{}, fmt.Errorf("offboard: identity is required")
	}

	sessions, err := o.DB.ListSessions()
	if err != nil {
		return Plan{}, fmt.Errorf("list sessions: %w", err)
	}
	store, err := apitoken.NewSQLStore(o.DB)
	if err != nil {
		return Plan{}, err
	}
	tokens, err := store.List()
	if err != nil {
		return Plan{}, fmt.Errorf("list api tokens: %w", err)
	}

	target, warnings := resolve(input, sessions, tokens)
	plan := Plan{Target: target, Warnings: warnings}

	// Sessions. The live authenticator when there is one — it is the authority
	// in both store modes, and on a hub with no durable store the table read
	// above is empty however many people are signed in.
	if o.Sessions != nil {
		live, err := o.Sessions.List()
		if err != nil {
			return Plan{}, fmt.Errorf("list live sessions: %w", err)
		}
		for _, s := range live {
			if target.matchesIdentity(s.Subject, s.Email) {
				plan.Sessions = append(plan.Sessions, s)
			}
		}
	} else {
		for _, row := range sessions {
			if !target.matchesSession(row) {
				continue
			}
			plan.Sessions = append(plan.Sessions, SessionRef{
				ID:        row.ID,
				Subject:   row.Subject,
				Email:     row.Email,
				IP:        row.IP,
				IssuedAt:  row.IssuedAt,
				ExpiresAt: row.ExpiresAt,
			})
		}
	}

	// Tokens and glasses links. Only live ones: a token already revoked or
	// expired is not a surface, and listing it would inflate the blast radius
	// an operator is being asked to approve.
	now := o.now()
	for _, tok := range tokens {
		if !tok.RevokedAt.IsZero() {
			continue
		}
		if !tok.ExpiresAt.IsZero() && !now.Before(tok.ExpiresAt) {
			continue
		}
		if !target.matchesOwner(tok.Owner) {
			continue
		}
		ref := TokenRef{
			ID:        tok.ID,
			Name:      tok.Name,
			Prefix:    tok.Prefix,
			Kind:      tok.Kind,
			Owner:     tok.Owner.Key(),
			Roles:     tok.Roles,
			ExpiresAt: tok.ExpiresAt,
		}
		if tok.Kind == apitoken.KindGlasses {
			plan.Glasses = append(plan.Glasses, ref)
		} else {
			plan.Tokens = append(plan.Tokens, ref)
		}
	}

	// Deny bindings.
	denies, denyWarnings := plannedDenies(target)
	plan.Denies = denies
	plan.Warnings = append(plan.Warnings, denyWarnings...)

	// Projects — reported, never deleted.
	ownerKeys := target.OwnerKeys()
	if o.Projects != nil {
		owned, err := o.Projects.Owned(ownerKeys)
		if err != nil {
			plan.Warnings = append(plan.Warnings,
				fmt.Sprintf("could not enumerate owned projects: %v", err))
		} else {
			plan.Projects = owned
		}
	} else {
		plan.Warnings = append(plan.Warnings,
			"project ownership was not checked: no project registry available to this run")
	}

	// Running tasks in those projects.
	if o.Tasks != nil {
		for _, p := range plan.Projects {
			running, err := o.Tasks.Running(p.Path)
			if err != nil {
				plan.Warnings = append(plan.Warnings,
					fmt.Sprintf("could not read running tasks for %s: %v", p.Path, err))
				continue
			}
			for _, t := range running {
				t.ProjectName = p.Name
				plan.Tasks = append(plan.Tasks, t)
			}
		}
	} else if len(plan.Projects) > 0 {
		plan.Warnings = append(plan.Warnings,
			"running tasks were not checked: no execution surface available to this run")
	}

	// Leases held on behalf of those projects.
	if o.Leases != nil {
		owned := map[string]struct{}{}
		for _, p := range plan.Projects {
			owned[p.Path] = struct{}{}
		}
		for _, l := range o.Leases.LiveLeases() {
			if _, ok := owned[l.ProjectID]; ok {
				plan.Leases = append(plan.Leases, l)
			}
		}
	} else {
		plan.Warnings = append(plan.Warnings,
			"secret leases were not checked: no broker available to this run")
	}

	return plan, nil
}

// ---------------------------------------------------------------------------
// Resolution
// ---------------------------------------------------------------------------

// resolve expands what the operator typed into every identifier that addresses
// the same person.
//
// It is a fixpoint rather than a single pass because the identifiers chain: an
// email matches a session, that session supplies a subject, and the subject
// matches a token whose owner carries no email at all. One pass would stop at
// the session and leave the token live — a departed user's PAT still working,
// which is the exact failure this package exists to prevent.
//
// The loop is bounded by the number of distinct identifiers in the two tables,
// and terminates because each iteration either adds one or stops.
func resolve(input string, sessions []statedb.SessionRow, tokens []apitoken.Token) (Target, []string) {
	t := Target{Input: input}
	emails := map[string]struct{}{}
	subjects := map[string]struct{}{}

	// Seed from the literal input. "sub:x" is accepted because that is how an
	// owner key spells a subject, and an operator copying one out of the
	// dashboard should not have to strip the prefix.
	seed := strings.TrimSpace(input)
	seedSub := strings.TrimPrefix(seed, "sub:")

	matchesLiteral := func(sub, email string) bool {
		if email != "" && strings.EqualFold(email, seed) {
			return true
		}
		if sub != "" && (sub == seed || sub == seedSub) {
			return true
		}
		return false
	}

	for {
		grew := false
		note := func(sub, email string) {
			if email != "" {
				k := strings.ToLower(email)
				if _, ok := emails[k]; !ok {
					emails[k] = struct{}{}
					grew = true
				}
			}
			if sub != "" {
				if _, ok := subjects[sub]; !ok {
					subjects[sub] = struct{}{}
					grew = true
				}
			}
		}
		known := func(sub, email string) bool {
			if email != "" {
				if _, ok := emails[strings.ToLower(email)]; ok {
					return true
				}
			}
			if sub != "" {
				if _, ok := subjects[sub]; ok {
					return true
				}
			}
			return matchesLiteral(sub, email)
		}

		for _, row := range sessions {
			if known(row.Subject, row.Email) {
				note(row.Subject, row.Email)
			}
		}
		for _, tok := range tokens {
			if tok.Owner == nil {
				continue
			}
			if known(tok.Owner.Sub, tok.Owner.Email) {
				note(tok.Owner.Sub, tok.Owner.Email)
			}
		}
		if !grew {
			break
		}
	}

	t.Emails = sortedKeys(emails)
	t.Subjects = sortedKeys(subjects)

	// Nothing on this hub matched. The identity may still be one the operator
	// wants denied pre-emptively — a name from an HR feed that never signed in
	// here — so fall back to reading the input the way the `hub role` commands
	// do: an address is an email, anything else is a subject.
	if len(t.Emails) == 0 && len(t.Subjects) == 0 {
		if strings.Contains(seed, "@") {
			t.Emails = []string{strings.ToLower(seed)}
		} else {
			t.Subjects = []string{seedSub}
		}
	}

	if len(t.Emails) > 0 {
		t.Key = t.Emails[0]
	} else {
		t.Key = "sub:" + t.Subjects[0]
	}

	return t, unreadableOwnerWarnings(tokens)
}

// unreadableOwnerWarnings reports tokens whose owner binding did not decode.
//
// These cannot be matched, and — critically — cannot be proven *not* to belong
// to the departing user. Silently skipping them would let an offboarding report
// success over a credential that may well be theirs. Naming them puts the
// decision in front of the operator, who can revoke by id.
func unreadableOwnerWarnings(tokens []apitoken.Token) []string {
	var ids []string
	for _, tok := range tokens {
		if !tok.OwnerUnreadable || !tok.RevokedAt.IsZero() {
			continue
		}
		ids = append(ids, tok.ID)
	}
	if len(ids) == 0 {
		return nil
	}
	sort.Strings(ids)
	return []string{fmt.Sprintf(
		"%d live token(s) have an unreadable owner binding and cannot be matched to "+
			"any identity: %s — review them by hand (`cloop hub token revoke <id>`); "+
			"they may belong to this user",
		len(ids), strings.Join(ids, ", "))}
}

// matchesIdentity reports whether a (subject, email) pair is this person.
func (t Target) matchesIdentity(sub, email string) bool {
	for _, s := range t.Subjects {
		if sub != "" && sub == s {
			return true
		}
	}
	for _, e := range t.Emails {
		if email != "" && strings.EqualFold(email, e) {
			return true
		}
	}
	return false
}

// matchesSession reports whether a session row belongs to this identity.
func (t Target) matchesSession(row statedb.SessionRow) bool {
	if t.matchesIdentity(row.Subject, row.Email) {
		return true
	}
	// owner_key is denormalised onto the row, so a session whose subject and
	// email columns are somehow empty is still reachable.
	if row.OwnerKey != "" {
		for _, k := range t.OwnerKeys() {
			if strings.EqualFold(row.OwnerKey, k) {
				return true
			}
		}
	}
	return false
}

// matchesOwner reports whether a token's owner binding is this identity.
//
// An unbound token (nil owner) never matches: it belongs to the hub rather than
// to a person, and revoking every unbound token because somebody left would
// break service accounts that have nothing to do with them. Those are surfaced
// as a warning instead when their binding is unreadable.
func (t Target) matchesOwner(o *apitoken.Owner) bool {
	if o == nil {
		return false
	}
	for _, s := range t.Subjects {
		if o.Sub != "" && o.Sub == s {
			return true
		}
	}
	for _, e := range t.Emails {
		if o.Email != "" && strings.EqualFold(o.Email, e) {
			return true
		}
	}
	if key := o.Key(); key != "" {
		for _, k := range t.OwnerKeys() {
			if strings.EqualFold(key, k) {
				return true
			}
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func sortedKeys(m map[string]struct{}) []string {
	if len(m) == 0 {
		return nil
	}
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func marshalPayload(payload map[string]any) (string, error) {
	b, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("encode audit payload: %w", err)
	}
	return string(b), nil
}
