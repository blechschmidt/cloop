package cmd

// How `cloop remote` reports a hub's refusal (Task 20417).
//
// The hub explains itself in structured fields: an apierror code, a message,
// and details — for a missing permission, which permission, the caller's role
// and the scope it was decided at. The dashboard turns those into a sentence;
// a terminal that printed only the message would tell a developer "your role
// does not permit this action" and leave them to guess which action needed
// what, and one that printed the body would hand them JSON. So the rendering
// here is the hub's message, its code, every detail as a readable line, and for
// a permission the one thing the details never say: how to get it.

import (
	"fmt"
	"sort"
	"strings"

	"github.com/blechschmidt/cloop/pkg/authz"
	"github.com/blechschmidt/cloop/pkg/hubclient"
)

// remoteError is a hub refusal rendered for a terminal. It unwraps to the
// *hubclient.APIError, so callers can still ask what the hub said.
type remoteError struct {
	hub string
	ae  *hubclient.APIError
}

func (e *remoteError) Unwrap() error { return e.ae }

func (e *remoteError) Error() string {
	var b strings.Builder
	b.WriteString(e.ae.Error())
	for _, line := range explainRefusal(e.hub, e.ae) {
		b.WriteString("\n  ")
		b.WriteString(line)
	}
	return b.String()
}

// explainedDetails are the detail keys explainRefusal renders in its own
// words; every other detail is listed as it came.
var explainedDetails = map[string]bool{
	"required_permission": true, "role": true, "scope": true,
	"reason": true, "claim_age_seconds": true, "max_claim_age_seconds": true, "renewable": true,
}

// explainRefusal is the lines under a refusal's message: what was needed,
// what the caller has, how to get the rest, then any other detail the hub
// gave.
func explainRefusal(hub string, ae *hubclient.APIError) []string {
	var lines []string
	perm := ae.Detail("required_permission")
	if perm == "" && ae.Status == 403 {
		perm = permissionNamedIn(ae.Message)
	}
	if perm != "" {
		scope := ae.Detail("scope")
		switch {
		case ae.Detail("reason") != "":
			// The claims behind the session are older than the hub accepts
			// for anything above operator, and a terminal cannot renew them
			// silently the way the dashboard does.
			lines = append(lines, fmt.Sprintf("needs:      %s, decided on claims your identity provider confirmed recently", perm),
				fmt.Sprintf("to get it:  sign in again — `cloop login %s` — and retry; "+
					"the session you have was approved too long ago for this", hub))
		default:
			lines = append(lines, "needs:      "+perm+describeScope(scope))
			if role := ae.Detail("role"); role != "" && role != string(authz.RoleNone) {
				lines = append(lines, "your role:  "+role+describeScope(scope))
			} else if ae.Detail("role") != "" {
				lines = append(lines, "your role:  none"+describeScope(scope))
			}
			lines = append(lines, "to get it:  "+permissionRemedy(authz.Permission(perm), scope))
		}
	}
	keys := make([]string, 0, len(ae.Details))
	for k := range ae.Details {
		if !explainedDetails[k] {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	for _, k := range keys {
		if v := ae.Detail(k); v != "" {
			lines = append(lines, strings.ReplaceAll(k, "_", " ")+": "+v)
		}
	}
	return lines
}

// describeScope renders the hub's scope label ("global", "project=api",
// "executor=edge-01") as the tail of a sentence.
func describeScope(scope string) string {
	switch {
	case scope == "":
		return ""
	case scope == "global":
		return " (hub-wide)"
	case strings.HasPrefix(scope, "project="):
		return " on project " + strings.TrimPrefix(scope, "project=")
	case strings.HasPrefix(scope, "executor="):
		return " on executor " + strings.TrimPrefix(strings.SplitN(scope, ",", 2)[0], "executor=")
	}
	return " (" + scope + ")"
}

// permissionNamedIn finds the permission a refusal names in its prose, for
// the refusals that carry no details — "this is a shared secret: granting it
// requires secret.grant".
func permissionNamedIn(message string) string {
	for _, p := range authz.AllPermissions {
		if strings.Contains(message, string(p)) {
			return string(p)
		}
	}
	return ""
}

// lowestRoleWith is the least role on the ladder that carries perm.
func lowestRoleWith(perm authz.Permission) authz.Role {
	for _, r := range authz.AllRoles {
		for _, p := range r.Permissions() {
			if p == perm {
				return r
			}
		}
	}
	return authz.RoleAdmin
}

// permissionRemedy says how a person gets perm: from whom, and in which role.
func permissionRemedy(perm authz.Permission, scope string) string {
	role := lowestRoleWith(perm)
	project := ""
	if strings.HasPrefix(scope, "project=") {
		project = strings.TrimPrefix(scope, "project=")
	}
	switch perm {
	case authz.PermExecutorManage:
		return "only an administrator binds a project to an executor — ask one to bind it, " +
			"or leave out --executor to use the hub's default"
	case authz.PermSecretGrant:
		where := "hub-wide"
		if project != "" {
			where = "on " + project
		}
		return "ask a maintainer to grant it, or file a request an approver can grant without you holding it: " +
			"`cloop remote grants request <secret> --project <project> --justification \"…\"` " +
			"(secret.grant is the maintainer role " + where + ")"
	}
	if project != "" && role != authz.RoleAdmin {
		return fmt.Sprintf("ask a maintainer of %s to share it with you as %s (Members on the project's "+
			"Overview), or an administrator to map your account to the %s role", project, role, role)
	}
	return fmt.Sprintf("ask an administrator of this hub to map your account to the %s role "+
		"(Settings → Single sign-on → role mappings)", role)
}
