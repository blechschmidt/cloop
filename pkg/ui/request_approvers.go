package ui

// Who can approve an access request (Task 20417).
//
// A developer whose `cloop remote init` files a request for a credential they
// cannot grant themselves has one question next: whom to ask. The dashboard
// answered it with "a maintainer has to approve it", which names a role and
// leaves the requester to find out who holds it. The hub knows: approving is
// POST /api/grant-requests/{id}/approve, gated on secret.grant across the whole
// hub, and the policy says which accounts and groups hold that.
//
// What is reported is the policy, not a membership list. A group binding is
// reported as the group — the hub does not know a group's members until they
// sign in, and listing who happened to have signed in would be both wrong and
// reconnaissance. The requester is left out: the broker refuses self-approval,
// so naming them would send them to ask themselves.
//
// It is shown to whoever files or lists requests, which takes secret.request:
// people who run the hub's projects, asking whom on their own team to ask.

import (
	"sort"
	"strconv"
	"strings"

	"github.com/blechschmidt/cloop/pkg/authz"
	"github.com/blechschmidt/cloop/pkg/secretbroker"
)

// maxApprovers bounds the list. A hub whose policy names more accounts than
// this has a group for them, and the rest are summarised.
const maxApprovers = 12

// approverCache computes the two lists a response can need once: who may
// approve a request for one named project or executor, and who may approve
// one aimed at an open-ended set, which takes an administrator.
type approverCache struct {
	s         *Server
	requester string
	named     []string
	wildcard  []string
	done      bool
}

func (s *Server) newApproverCache(requester string) *approverCache {
	return &approverCache{s: s, requester: strings.TrimSpace(requester)}
}

// forSubject is the approvers of a request for subject.
func (c *approverCache) forSubject(subject secretbroker.Subject) []string {
	if !c.done {
		c.named = c.s.requestApprovers(c.requester, false)
		c.wildcard = c.s.requestApprovers(c.requester, true)
		c.done = true
	}
	// A label selector is open-ended for approval purposes, as the broker
	// treats it (isWildcardSubject): the set it selects grows after the
	// approval, whenever a device carrying the label is enrolled. The same
	// predicate decides what the approvals inbox offers (approvals_api.go).
	if requestReachesFleet(subject) {
		return c.wildcard
	}
	return c.named
}

// requestApprovers lists who may approve a request filed by requester:
// administrators only when wildcard is set, otherwise everyone the policy gives
// secret.grant hub-wide.
func (s *Server) requestApprovers(requester string, wildcard bool) []string {
	if !s.oidcEnabled() {
		return []string{"whoever holds this hub's admin token, or an API token with the maintainer or admin role"}
	}
	if !s.authzActive() {
		// Single sign-on without a role policy: every signed-in identity
		// holds every permission but executor administration.
		return []string{"anyone signed in to this hub other than you"}
	}
	need := authz.PermSecretGrant
	if wildcard {
		need = authz.PermUserManage // the admin role's own permission
	}
	if roleCarries(s.Authz.DefaultRole(), need) {
		return []string{"anyone signed in to this hub other than you"}
	}

	// Runtime denies aimed at one account, so a demoted administrator is not
	// offered. A deny aimed at a group cannot be matched to a binding naming
	// another claim, and is left to the hub to enforce when they try.
	denied := map[string]bool{}
	runtime := s.Authz.RuntimeBindings()
	for _, b := range runtime {
		if b.Deny && b.Project == "" && b.Executor == "" {
			denied[string(b.Claim)+"\x00"+strings.ToLower(b.Value)] = true
		}
	}
	type entry struct {
		label string
		admin bool
		group bool
	}
	seen := map[string]bool{}
	var out []entry
	for _, b := range append(s.Authz.ConfiguredBindings(), runtime...) {
		if b.Deny || b.Project != "" || b.Executor != "" || !roleCarries(b.Role, need) {
			continue
		}
		if denied[string(b.Claim)+"\x00"+strings.ToLower(b.Value)] {
			continue
		}
		if b.Claim == authz.ClaimEmail && requester != "" && strings.EqualFold(b.Value, requester) {
			continue
		}
		label := approverLabel(b)
		if label == "" || seen[label] {
			continue
		}
		seen[label] = true
		group := b.Claim == authz.ClaimGroup || b.Claim == authz.ClaimSCIMGroup || b.Claim == authz.ClaimRole
		out = append(out, entry{label: label, admin: b.Role == authz.RoleAdmin, group: group})
	}
	// Administrators first, and within each role the people a requester can
	// write to before the groups they would have to find a member of.
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].admin != out[j].admin {
			return out[i].admin
		}
		if out[i].group != out[j].group {
			return !out[i].group
		}
		return out[i].label < out[j].label
	})
	labels := make([]string, 0, len(out))
	for i, e := range out {
		if i == maxApprovers {
			labels = append(labels, "and "+strconv.Itoa(len(out)-maxApprovers)+" more in the hub's role mappings")
			break
		}
		role := "maintainer"
		if e.admin {
			role = "admin"
		}
		labels = append(labels, e.label+" ("+role+")")
	}
	return labels
}

// roleCarries reports whether role carries perm.
func roleCarries(role authz.Role, perm authz.Permission) bool {
	for _, p := range role.Permissions() {
		if p == perm {
			return true
		}
	}
	return false
}

// approverLabel names whom a binding points at, the way a person would go and
// find them.
func approverLabel(b authz.Binding) string {
	v := strings.TrimSpace(b.Value)
	if v == "" {
		return ""
	}
	switch b.Claim {
	case authz.ClaimEmail:
		return v
	case authz.ClaimGroup:
		return "members of group " + v
	case authz.ClaimSCIMGroup:
		return "members of the provisioned group " + v
	case authz.ClaimRole:
		return "holders of the identity provider role " + v
	case authz.ClaimUsername:
		return "user " + v
	case authz.ClaimSub:
		return "the account with subject " + v
	case authz.ClaimOID:
		return "the directory object " + v
	}
	return string(b.Claim) + " " + v
}
